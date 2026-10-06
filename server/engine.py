"""巡检引擎：按模板对目标数据库执行 SQL → 阈值判定 → 结构化结果。

结构化结果（供报告渲染、AI 解读、前端预览共用）：
{
  "connection": {...}, "template": {...},
  "started_at": "...", "duration": 42.0,
  "summary": {"total":N,"normal":N,"warn":N,"crit":N,"info":N,"error":N},
  "categories": [
    {"name":"性能指标","items":[
       {"name":"会话数使用率","status":"warn","value":"77.2%","threshold_desc":">80% 警告",
        "columns":[...],"rows":[[...]]}
    ]}
  ]
}
"""
from __future__ import annotations

import re
import time
from datetime import datetime

from . import drivers

# 默认变量（自定义模板可使用 {{top_n}}、{{days}}、{{schema}} 等占位符）
DEFAULT_VARS = {"top_n": 10, "days": 7, "schema": "", "threshold": 80}

STATUS_LABEL = {"normal": "正常", "warn": "警告", "crit": "严重", "info": "信息", "error": "错误"}


def substitute_vars(sql: str, variables: dict | None = None) -> str:
    varset = dict(DEFAULT_VARS)
    if variables:
        varset.update(variables)

    def repl(m):
        key = m.group(1).strip()
        return str(varset.get(key, m.group(0)))

    return re.sub(r"\{\{\s*([\w]+)\s*\}\}", repl, sql)


def _to_float(value) -> float | None:
    try:
        if value is None:
            return None
        if isinstance(value, bool):
            return 1.0 if value else 0.0
        return float(str(value).replace("%", "").strip())
    except Exception:
        return None


def _compare(value: float, op: str, threshold) -> bool:
    if op in ("", None) or threshold in ("", None):
        return False
    try:
        t = float(threshold)
    except Exception:
        return False
    if op == "gt":
        return value > t
    if op == "lt":
        return value < t
    if op == "ge":
        return value >= t
    if op == "le":
        return value <= t
    if op == "eq":
        return value == t
    if op == "ne":
        return value != t
    return False


def _pick_scalar(item: dict, columns: list[str], rows: list[list]) -> tuple[float | None, object]:
    metric = (item.get("metric_column") or "").strip()
    # 指定列优先
    if metric and columns:
        try:
            idx = columns.index(metric)
        except ValueError:
            idx = -1
        if idx >= 0 and rows:
            return _to_float(rows[0][idx]), rows[0][idx]
    # 自动：第一个数值列
    if rows and rows[0]:
        for i, v in enumerate(rows[0]):
            f = _to_float(v)
            if f is not None and not isinstance(v, bool):
                return f, v
    # 兜底：单行单列
    if rows and rows[0]:
        return _to_float(rows[0][0]), rows[0][0]
    return None, None


def _fmt_value(value, value_format: str) -> str:
    if value is None:
        return "—"
    if value_format == "percent":
        return f"{value}%"
    if value_format == "number":
        if isinstance(value, float):
            return f"{value:.2f}".rstrip("0").rstrip(".")
        return str(value)
    return str(value)


def evaluate_item(item: dict, columns: list[str], rows: list[list]) -> dict:
    """返回 {status, value, error}。"""
    mode = item.get("eval_mode") or "scalar"
    if mode == "info":
        if rows and rows[0]:
            scalar, raw = _pick_scalar(item, columns, rows)
            return {"status": "info", "value": str(raw) if raw is not None else f"{len(rows)} 行", "error": ""}
        return {"status": "info", "value": "无数据", "error": ""}

    if mode == "exists":
        n = len(rows)
        if n > 0:
            return {"status": "crit", "value": f"{n} 条", "error": ""}
        return {"status": "normal", "value": "0 条", "error": ""}

    if mode == "rows":
        n = len(rows)
        crit = _compare(float(n), item.get("crit_op"), item.get("crit_value"))
        warn = _compare(float(n), item.get("warn_op"), item.get("warn_value"))
        status = "crit" if crit else ("warn" if warn else "normal")
        return {"status": status, "value": f"{n} 条", "error": ""}

    # scalar
    scalar, raw = _pick_scalar(item, columns, rows)
    if scalar is None:
        return {"status": "info", "value": "无可用指标", "error": ""}
    crit = _compare(scalar, item.get("crit_op"), item.get("crit_value"))
    warn = _compare(scalar, item.get("warn_op"), item.get("warn_value"))
    status = "crit" if crit else ("warn" if warn else "normal")
    return {"status": status, "value": _fmt_value(raw, item.get("value_format") or "number"), "error": ""}


def _limit_rows(rows: list[list], columns: list[str], limit: int = 100):
    if len(rows) <= limit:
        return rows
    truncated = rows[:limit]
    return truncated


def run_inspection(conn_row: dict, password: str, template: dict, items: list[dict],
                   log_cb=None, variables: dict | None = None, row_limit: int = 100,
                   timeout: int = 300) -> dict:
    """执行一次完整巡检。log_cb(msg) 用于进度日志。"""

    def log(msg: str):
        if log_cb:
            log_cb(msg)

    started = time.time()
    started_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    conn_name = conn_row.get("name", conn_row.get("host", ""))
    log(f"连接 {conn_name}（{conn_row.get('host')}:{conn_row.get('port')}）…")
    session = drivers.open_session(conn_row, password)
    try:
        version = session.server_version()
        log(f"连接成功（{version or '未知版本'}），开始执行 {len(items)} 个巡检项 …")

        categories: list[dict] = []
        cat_index: dict[str, int] = {}
        summary = {"total": 0, "normal": 0, "warn": 0, "crit": 0, "info": 0, "error": 0}

        for it in items:
            if not it.get("enabled", 1):
                continue
            summary["total"] += 1
            cat_name = it.get("category") or "未分类"
            if cat_name not in cat_index:
                cat_index[cat_name] = len(categories)
                categories.append({"name": cat_name, "items": []})

            sql = substitute_vars(it.get("sql_text", ""), variables)
            item_name = it.get("item_name", "巡检项")
            log(f"[{cat_name}] {item_name} …")
            try:
                columns, rows = session.execute(sql)
                rows = _limit_rows(rows, columns, row_limit)
                ev = evaluate_item(it, columns, rows)
                status, value, error = ev["status"], ev["value"], ev["error"]
                summary[status] = summary.get(status, 0) + 1
                label = STATUS_LABEL.get(status, status)
                log(f"    → {label}（{value}）")
                categories[cat_index[cat_name]]["items"].append({
                    "name": item_name,
                    "status": status,
                    "value": value,
                    "threshold_desc": it.get("threshold_desc") or "",
                    "columns": columns,
                    "rows": rows,
                })
            except Exception as exc:  # noqa: BLE001
                summary["error"] = summary.get("error", 0) + 1
                msg = str(exc).strip().replace("\n", " ")[:300]
                log(f"    → 错误：{msg}")
                categories[cat_index[cat_name]]["items"].append({
                    "name": item_name,
                    "status": "error",
                    "value": "执行失败",
                    "threshold_desc": it.get("threshold_desc") or "",
                    "columns": [],
                    "rows": [],
                    "error": msg,
                })

        duration = round(time.time() - started, 1)
        log(f"巡检完成：共 {summary['total']} 项（正常 {summary['normal']} / 警告 {summary['warn']} / 严重 {summary['crit']} / 错误 {summary['error']}），耗时 {duration}s")
        return {
            "connection": {
                "name": conn_name, "host": conn_row.get("host"), "port": conn_row.get("port"),
                "db_type": conn_row.get("db_type"), "version": version,
            },
            "template": {
                "name": template.get("name"), "db_type": template.get("db_type"),
                "report_title": template.get("report_title") or "数据库巡检报告",
                "watermark": template.get("watermark") or "",
            },
            "started_at": started_at,
            "duration": duration,
            "summary": summary,
            "categories": categories,
        }
    finally:
        session.close()
