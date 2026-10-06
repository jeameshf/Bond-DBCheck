"""巡检作业编排：连接→巡检→渲染报告→落库/落盘，供手动与自动巡检复用。"""
from __future__ import annotations

import json
import os

from . import REPORT_DIR, store
from . import engine, notify, reports


def run_inspection_job(conn_row: dict, password: str, template: dict, items: list[dict],
                       output_formats: list[str], trigger_type: str, log_cb=None,
                       email_notify: bool = False) -> dict:
    """执行一次巡检并生成报告，返回 {report_id, report_no, result}。"""
    result = engine.run_inspection(conn_row, password, template, items, log_cb=log_cb)
    report_no = f"RPT-{store.now_stamp()}-{conn_row.get('name', 'db')}"
    report_name = f"{conn_row.get('name', 'db')} 巡检报告"

    trigger_label = "自动调度" if trigger_type == "auto" else "手动巡检"
    html_file = ""
    word_file = ""
    html_bytes = b""
    word_bytes = b""

    if "html" in output_formats:
        html_text = reports.render_html(result, report_no, trigger_label,
                                        abnormal_only=bool(template.get("abnormal_only")))
        html_bytes = html_text.encode("utf-8")
        html_file = report_no + ".html"
        _safe_write(os.path.join(REPORT_DIR, html_file), html_bytes)
        if log_cb:
            log_cb(f"HTML 报告已生成：{html_file}")

    if "word" in output_formats:
        word_bytes = reports.render_word(result, report_no, trigger_label,
                                         abnormal_only=bool(template.get("abnormal_only")))
        word_file = report_no + ".docx"
        _safe_write(os.path.join(REPORT_DIR, word_file), word_bytes)
        if log_cb:
            log_cb(f"Word 报告已生成：{word_file}")

    # 邮件通知（按告警触发条件，或强制发送）
    attachments: list[tuple[str, bytes]] = []
    if html_file:
        attachments.append((html_file, html_bytes))
    if word_file:
        attachments.append((word_file, word_bytes))
    try:
        notify_msg = notify.maybe_notify(result, attachments=attachments, force=email_notify)
        if log_cb:
            log_cb(notify_msg)
    except Exception as exc:  # noqa: BLE001
        if log_cb:
            log_cb(f"邮件通知异常：{exc}")

    report_id = store.execute(
        "INSERT INTO reports(report_no,name,connection_id,connection_name,db_type,template_id,template_name,"
        "trigger_type,status,duration,summary,result_json,html_file,word_file,created_at) "
        "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            report_no, report_name, conn_row.get("id"), conn_row.get("name"), conn_row.get("db_type"),
            template.get("id"), template.get("name"), trigger_type,
            "success", result.get("duration", 0),
            json.dumps(result.get("summary", {}), ensure_ascii=False),
            json.dumps(result, ensure_ascii=False),
            html_file, word_file, store.now(),
        ),
    )

    # 巡检问题自动生成工单
    _generate_work_orders(result, report_id, report_no, conn_row)

    result["report_id"] = report_id
    result["report_no"] = report_no
    return {"report_id": report_id, "report_no": report_no, "result": result}


def _generate_work_orders(result: dict, report_id: int, report_no: str, conn_row: dict) -> None:
    """对巡检异常项（警告/严重/失败）自动生成工单。"""
    try:
        for cat in result.get("categories", []):
            for it in cat.get("items", []):
                st = it.get("status")
                if st in ("warn", "crit", "error"):
                    store.execute(
                        "INSERT INTO work_orders(report_id,report_no,connection_name,db_type,category,item_name,"
                        "severity,value,threshold_desc,status,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                        (report_id, report_no, conn_row.get("name"), conn_row.get("db_type"),
                         cat.get("name"), it.get("name"), st, it.get("value"),
                         it.get("threshold_desc") or "", "open", store.now()))
    except Exception:
        pass


def _safe_write(path: str, data: bytes) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "wb") as fp:
        fp.write(data)
    os.replace(tmp, path)
