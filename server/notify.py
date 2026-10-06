"""邮件通知：用标准库 smtplib 发送告警邮件 / 巡检报告邮件。

SMTP 配置来自系统设置（settings 表）；密码使用 Fernet 加密存储。
触发规则由 maybe_notify 结合系统设置里的「告警触发条件」判断。
"""
from __future__ import annotations

import json
import smtplib
import urllib.request
from email.message import EmailMessage
from email.utils import formataddr

from . import security, store


def _smtp_config() -> dict:
    s = store.get_all_settings()
    return {
        "host": (s.get("smtp_host") or "").strip(),
        "port": int(s.get("smtp_port") or 0),
        "user": (s.get("smtp_user") or "").strip(),
        "password": security.decrypt_text(s.get("smtp_pass_enc") or ""),
        "from": (s.get("smtp_from") or "").strip(),
        "receivers": s.get("alert_receivers") or "",
    }


def _receivers() -> list[str]:
    cfg = _smtp_config()
    return [r.strip() for r in cfg["receivers"].split(",") if r.strip()]


def send_mail(subject: str, body_html: str, to_list: list[str],
              attachments: list[tuple[str, bytes]] | None = None, timeout: int = 30) -> tuple[bool, str]:
    """发送一封邮件。attachments: [(文件名, 字节)]。返回 (是否成功, 说明)。"""
    cfg = _smtp_config()
    if not cfg["host"]:
        return False, "未配置 SMTP 服务器"
    if not cfg["from"]:
        return False, "未配置发件人"
    if not to_list:
        return False, "未配置收件人"

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = formataddr(("Bond-DBCheck", cfg["from"]))
    msg["To"] = ", ".join(to_list)
    msg.set_content(body_html, subtype="html")
    for name, data in (attachments or []):
        if not data:
            continue
        msg.add_attachment(data, maintype="application", subtype="octet-stream", filename=name)

    port = cfg["port"] or 465
    server = None
    try:
        if port == 465:
            server = smtplib.SMTP_SSL(cfg["host"], port, timeout=timeout)
        else:
            server = smtplib.SMTP(cfg["host"], port, timeout=timeout)
            server.ehlo()
            if port == 587:
                server.starttls()
                server.ehlo()
        if cfg["user"]:
            server.login(cfg["user"], cfg["password"])
        server.sendmail(cfg["from"], to_list, msg.as_string())
        return True, "邮件已发送"
    except Exception as exc:  # noqa: BLE001
        return False, f"发送失败：{exc}"
    finally:
        if server is not None:
            try:
                server.quit()
            except Exception:
                pass


def _body_html(result: dict) -> str:
    from . import reports  # 复用状态样式元数据
    conn = result.get("connection", {})
    tpl = result.get("template", {})
    summary = result.get("summary", {})

    rows = []
    for cat in result.get("categories", []):
        for item in cat.get("items", []):
            status = item.get("status")
            if status in ("normal", "info"):
                continue
            label, color, _ = reports.STATUS_META.get(status, (status, "#475569", ""))
            rows.append(
                f'<tr><td style="padding:6px 10px;border:1px solid #eee">{cat.get("name")}</td>'
                f'<td style="padding:6px 10px;border:1px solid #eee">{item.get("name")}</td>'
                f'<td style="padding:6px 10px;border:1px solid #eee">{item.get("value")}</td>'
                f'<td style="padding:6px 10px;border:1px solid #eee;color:{color};font-weight:600">{label}</td></tr>'
            )
    abnormal_table = (
        '<table style="border-collapse:collapse;width:100%;font-size:13px">'
        '<tr style="background:#f1f5f9"><th style="padding:6px 10px;border:1px solid #eee;text-align:left">分类</th>'
        '<th style="padding:6px 10px;border:1px solid #eee;text-align:left">巡检项</th>'
        '<th style="padding:6px 10px;border:1px solid #eee;text-align:left">结果</th>'
        '<th style="padding:6px 10px;border:1px solid #eee;text-align:left">状态</th></tr>'
        + "".join(rows) + "</table>" if rows else '<p style="color:#059669">无异常项</p>'
    )

    return f"""<div style="font-family:-apple-system,'PingFang SC','Microsoft YaHei',sans-serif;font-size:14px;color:#111827">
  <h2 style="margin:0 0 8px">{tpl.get('report_title') or '数据库巡检报告'}</h2>
  <p style="color:#6b7280;margin:4px 0">实例：{conn.get('name')}（{conn.get('db_type')}，{conn.get('version') or ''}）</p>
  <p style="color:#6b7280;margin:4px 0">巡检时间：{result.get('started_at')} &nbsp;|&nbsp; 耗时 {result.get('duration')} 秒</p>
  <p style="margin:12px 0 6px">
    <b>巡检项总数 {summary.get('total', 0)}</b> ｜
    <span style="color:#059669">正常 {summary.get('normal', 0)}</span> ｜
    <span style="color:#d97706">警告 {summary.get('warn', 0)}</span> ｜
    <span style="color:#dc2626">严重 {summary.get('crit', 0)}</span> ｜
    <span style="color:#dc2626">错误 {summary.get('error', 0)}</span>
  </p>
  <h3 style="margin:14px 0 6px">异常项清单</h3>
  {abnormal_table}
  <p style="color:#9ca3af;font-size:12px;margin-top:16px">本邮件由 Bond-DBCheck 邦德智能巡检平台自动发送 · {tpl.get('watermark') or ''}</p>
</div>"""


def _should_notify(result: dict, force: bool = False) -> bool:
    summary = result.get("summary", {})
    crit = int(summary.get("crit", 0))
    warn = int(summary.get("warn", 0))
    error = int(summary.get("error", 0))
    s = store.get_all_settings()
    if force:
        return True
    if s.get("alert_on_fail") == "1" and error > 0:
        return True
    if s.get("alert_on_crit") == "1" and crit > 0:
        return True
    if s.get("alert_on_warn") == "1" and warn > 0:
        return True
    return False


def _markdown(result: dict) -> str:
    conn = result.get("connection", {})
    tpl = result.get("template", {})
    summary = result.get("summary", {})
    lines = [
        "### Bond-DBCheck 巡检告警",
        f"> 实例：**{conn.get('name')}**（{conn.get('db_type')}，{conn.get('version') or ''}）",
        f"> 模板：{tpl.get('name') or '-'} ｜ 时间：{result.get('started_at')} ｜ 耗时 {result.get('duration')}s",
        "",
        f"**汇总**：总数 {summary.get('total', 0)} ｜ 正常 {summary.get('normal', 0)} ｜ "
        f"警告 {summary.get('warn', 0)} ｜ 严重 {summary.get('crit', 0)} ｜ 错误 {summary.get('error', 0)}",
        "",
        "**异常项**：",
    ]
    found = False
    label = {"warn": "警告", "crit": "严重", "error": "错误"}
    for cat in result.get("categories", []):
        for item in cat.get("items", []):
            st = item.get("status")
            if st in ("normal", "info"):
                continue
            found = True
            lines.append(f"- 【{label.get(st, st)}】{cat.get('name')} · {item.get('name')}：{item.get('value')}")
    if not found:
        lines.append("- 无异常项")
    lines.append("")
    lines.append(f"> {tpl.get('watermark') or ''}")
    return "\n".join(lines)


def send_webhook(result: dict) -> tuple[bool, str]:
    """发送 Webhook 告警（企业微信 / 钉钉 / 通用）。返回 (是否发送, 说明)。"""
    s = store.get_all_settings()
    url = (s.get("webhook_url") or "").strip()
    if not url:
        return False, "未配置 Webhook 地址"
    wtype = (s.get("webhook_type") or "generic").strip()
    md = _markdown(result)
    if wtype == "wecom":
        payload = {"msgtype": "markdown", "markdown": {"content": md}}
    elif wtype == "dingtalk":
        payload = {"msgtype": "markdown", "markdown": {"title": "Bond-DBCheck 巡检告警", "text": md}}
    else:
        payload = {"text": md}
    data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            body = resp.read().decode("utf-8", "replace")
        try:
            obj = json.loads(body)
            if isinstance(obj, dict) and obj.get("errcode") not in (None, 0):
                return False, f"Webhook 返回错误：{body[:200]}"
        except Exception:
            pass
        return True, "Webhook 已发送"
    except Exception as exc:  # noqa: BLE001
        return False, f"Webhook 发送失败：{exc}"


def maybe_notify(result: dict, attachments: list[tuple[str, bytes]] | None = None,
                 force: bool = False) -> str:
    """根据系统告警触发条件判断是否发送（邮件 + Webhook），返回日志说明。"""
    if not _should_notify(result, force):
        return "未触发告警条件，不发送通知"

    conn = result.get("connection", {})
    summary = result.get("summary", {})
    crit = int(summary.get("crit", 0))
    warn = int(summary.get("warn", 0))
    error = int(summary.get("error", 0))
    if crit or warn or error:
        subject = f"[DBCheck] {conn.get('name')} 巡检：严重 {crit} / 警告 {warn} / 错误 {error}"
    else:
        subject = f"[DBCheck] {conn.get('name')} 巡检报告"

    msgs = []

    receivers = _receivers()
    if receivers:
        ok, msg = send_mail(subject, _body_html(result), receivers, attachments=attachments)
        msgs.append(f"邮件{'已发送' if ok else '失败：' + msg}")
    else:
        msgs.append("未配置告警接收人，跳过邮件")

    if (store.get_all_settings().get("webhook_url") or "").strip():
        ok, msg = send_webhook(result)
        msgs.append("Webhook" + ("已发送" if ok else ("失败：" + msg)))

    return "通知：" + "；".join(msgs)


def test_webhook() -> tuple[bool, str]:
    """发送一条测试消息到已配置的 Webhook。"""
    mock = {
        "connection": {"name": "TEST", "db_type": "mysql", "version": ""},
        "template": {"name": "测试", "watermark": ""},
        "started_at": store.now(), "duration": 0,
        "summary": {"total": 1, "normal": 1, "warn": 0, "crit": 0, "info": 0, "error": 0},
        "categories": [],
    }
    return send_webhook(mock)
