"""自动巡检调度器：后台线程 + croniter 计算下次执行时间。

* 每 20 秒扫描一次启用中的调度；
* 到点后在独立线程中执行（用信号量限制并发，避免压垮生产库）；
* 支持 5/6 字段标准 cron（6 字段时首字段为秒）。
"""
from __future__ import annotations

import json
import os
import threading
import time
from datetime import datetime, timedelta

from . import store
from . import service

_POLL_SECONDS = 20


class Scheduler:
    def __init__(self):
        self._lock = threading.Lock()
        self._crons: dict[int, dict] = {}   # id -> {cron, next(datetime), running(bool)}
        self._stop = threading.Event()
        self._thread = None
        self._last_cleanup = 0.0

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="dbcheck-scheduler", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def reset(self, schedule_id: int | None = None) -> None:
        """调度变化后重置缓存，使下次 tick 重新计算。"""
        with self._lock:
            if schedule_id is None:
                self._crons.clear()
            else:
                self._crons.pop(schedule_id, None)

    # ------------------------------------------------------------------
    def _loop(self) -> None:
        from croniter import croniter

        while not self._stop.is_set():
            try:
                self._tick(croniter)
                self._maybe_cleanup()
            except Exception:
                pass
            self._stop.wait(_POLL_SECONDS)

    def _maybe_cleanup(self) -> None:
        if time.time() - self._last_cleanup < 3600:
            return
        self._last_cleanup = time.time()
        try:
            self._cleanup_reports()
        except Exception:
            pass
        try:
            self._cleanup_work_orders()
        except Exception:
            pass

    def _cleanup_work_orders(self) -> None:
        days = int(store.get_setting("work_order_retention_days", "90") or 90)
        if days <= 0:
            return
        cutoff = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")
        rows = store.query_all(
            "SELECT id FROM work_orders WHERE status='closed' AND created_at < ?", (cutoff,))
        if not rows:
            return
        ids = [r["id"] for r in rows]
        marks = ",".join("?" for _ in ids)
        store.execute(f"DELETE FROM work_orders WHERE id IN ({marks})", ids)
        store.audit(None, "system", "workorder_cleanup", f"清理过期工单 {len(ids)} 个（> {days} 天）")

    def _cleanup_reports(self) -> None:
        days = int(store.get_setting("report_retention_days", "180") or 180)
        if days <= 0:
            return
        cutoff = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")
        rows = store.query_all(
            "SELECT id, html_file, word_file FROM reports WHERE created_at < ?", (cutoff,))
        if not rows:
            return
        for r in rows:
            for f in (r["html_file"], r["word_file"]):
                if f:
                    try:
                        os.remove(os.path.join(store.REPORT_DIR, f))
                    except Exception:
                        pass
            store.execute("DELETE FROM ai_interpretations WHERE report_id=?", (r["id"],))
            store.execute("DELETE FROM reports WHERE id=?", (r["id"],))
        store.audit(None, "system", "report_cleanup", f"清理过期报告 {len(rows)} 份（> {days} 天）")

    def _tick(self, croniter) -> None:
        now = datetime.now()
        schedules = store.query_all("SELECT * FROM schedules WHERE enabled=1")
        live_ids = set()

        with self._lock:
            for sch in schedules:
                sid = sch["id"]
                live_ids.add(sid)
                entry = self._crons.get(sid)
                cron = sch.get("cron") or ""
                if not cron:
                    continue
                if entry is None or entry.get("cron") != cron:
                    try:
                        it = croniter(cron, now)
                        entry = {"cron": cron, "next": it.get_next(datetime), "running": False}
                    except Exception:
                        entry = {"cron": cron, "next": None, "running": False}
                    self._crons[sid] = entry
                if entry.get("next") and now >= entry["next"] and not entry.get("running"):
                    entry["running"] = True
                    self._spawn(sch, croniter)
                    # 计算下次
                    try:
                        it = croniter(cron, datetime.now())
                        entry["next"] = it.get_next(datetime)
                    except Exception:
                        entry["next"] = None
                    entry["running"] = False
            # 清理已删除/停用的
            for sid in list(self._crons):
                if sid not in live_ids:
                    self._crons.pop(sid, None)

    def _spawn(self, sch: dict, croniter) -> None:
        threading.Thread(target=self._run_schedule, args=(sch,), daemon=True).start()

    def _run_schedule(self, sch: dict) -> None:
        log_lines: list[str] = []

        def log(msg: str):
            log_lines.append(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")

        try:
            template = store.query_one("SELECT * FROM templates WHERE id=?", (sch["template_id"],))
            if not template:
                store.execute(
                    "UPDATE schedules SET last_run_status=?, last_run_at=? WHERE id=?",
                    ("失败：模板不存在", store.now(), sch["id"]))
                return
            items = store.query_all(
                "SELECT * FROM template_items WHERE template_id=? AND enabled=1 ORDER BY sort_order,id",
                (template["id"],))
            connections = self._resolve_connections(sch, template)
            if not connections:
                store.execute(
                    "UPDATE schedules SET last_run_status=?, last_run_at=? WHERE id=?",
                    ("失败：无匹配连接", store.now(), sch["id"]))
                return

            output_formats = json.loads(sch.get("output_formats") or '["html","word"]')
            parallel = int(store.get_setting("parallel_limit", "3") or 3)
            max_retries = int(sch.get("max_retries") or 0)
            retry_min = max(1, int(sch.get("retry_interval_min") or 10))
            sem = threading.Semaphore(max(1, parallel))

            done = 0
            first_report_id = None
            report_ids = []
            for conn in connections:
                sem.acquire()
                try:
                    pwd = store.decrypt_password(conn)
                    out = None
                    for attempt in range(max_retries + 1):
                        tag = f"（第 {attempt + 1}/{max_retries + 1} 次）" if attempt else ""
                        log(f"开始巡检 {conn['name']}（{conn['db_type']}）{tag}")
                        try:
                            out = service.run_inspection_job(
                                conn, pwd, template, items, output_formats, "auto", log_cb=log)
                            break
                        except Exception as exc:  # noqa: BLE001
                            if attempt < max_retries:
                                log(f"{conn['name']} 巡检失败：{exc}；{retry_min} 分钟后重试")
                                time.sleep(retry_min * 60)
                            else:
                                log(f"{conn['name']} 巡检失败（已重试 {max_retries} 次）：{exc}")
                                out = None
                    if out is not None:
                        if first_report_id is None:
                            first_report_id = out["report_id"]
                        report_ids.append(out["report_id"])
                        done += 1
                finally:
                    sem.release()

            status = f"成功（{done}/{len(connections)}）" if done == len(connections) else f"部分失败（{done}/{len(connections)}）"
            store.execute(
                "UPDATE schedules SET last_run_status=?, last_run_at=?, last_run_report_id=? WHERE id=?",
                (status, store.now(), first_report_id, sch["id"]))
            _record_run(sch, status, report_ids)
            store.audit(None, "system", "auto_inspect",
                        f"调度[{sch['name']}] 执行完成：{status}，共 {done} 个连接")
        except Exception as exc:  # noqa: BLE001
            store.execute(
                "UPDATE schedules SET last_run_status=?, last_run_at=? WHERE id=?",
                (f"失败：{str(exc)[:200]}", store.now(), sch["id"]))
            _record_run(sch, f"失败：{str(exc)[:200]}", [])

    def _resolve_connections(self, sch: dict, template: dict) -> list[dict]:
        try:
            ids = json.loads(sch.get("connection_ids") or "[]")
        except Exception:
            ids = []
        if ids == ["*"] or "*" in ids:
            rows = store.query_all(
                "SELECT * FROM connections WHERE enabled=1 AND db_type=?", (template["db_type"],))
        else:
            if not ids:
                return []
            marks = ",".join("?" for _ in ids)
            rows = store.query_all(
                f"SELECT * FROM connections WHERE enabled=1 AND id IN ({marks})", ids)
        return rows


def _record_run(sch: dict, status: str, report_ids: list) -> None:
    try:
        store.execute(
            "INSERT INTO schedule_runs(schedule_id,schedule_name,run_at,status,detail,report_ids,created_at) "
            "VALUES(?,?,?,?,?,?,?)",
            (sch.get("id"), sch.get("name"), store.now(), status, status,
             json.dumps(report_ids, ensure_ascii=False), store.now()))
    except Exception:
        pass


_scheduler = Scheduler()


def get_scheduler() -> Scheduler:
    return _scheduler
