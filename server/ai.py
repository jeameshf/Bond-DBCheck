"""AI 报告解读：调用 OpenAI 兼容的 /chat/completions 接口，对巡检报告做解读与处置建议。

支持单个报告解读与批量解读。接口地址、模型、API Key 均可配置（见 ai_configs 表）。
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request

from . import security

DEFAULT_SYSTEM = (
    "你是一名资深数据库运维专家（DBA）。请根据给出的数据库巡检报告数据，"
    "用中文输出条理清晰、专业且可落地的解读，包含：1) 总体健康结论；2) 需要重点关注的问题（按严重程度排序）；"
    "3) 每类问题的处置建议。不要编造报告中没有的数据。"
)


def _mask_key(key: str) -> str:
    return (key[:4] + "****" + key[-4:]) if len(key) > 8 else "****"


def config_to_dict(cfg: dict) -> dict:
    """把数据库行转成前端安全对象（脱敏 API Key）。"""
    return {
        "id": cfg["id"],
        "name": cfg["name"],
        "provider": cfg.get("provider") or "openai",
        "base_url": cfg.get("base_url") or "",
        "api_key_masked": _mask_key(security.decrypt_text(cfg.get("api_key_enc") or "")),
        "has_key": bool(security.decrypt_text(cfg.get("api_key_enc") or "")),
        "model": cfg.get("model") or "",
        "temperature": cfg.get("temperature") if cfg.get("temperature") is not None else 0.3,
        "system_prompt": cfg.get("system_prompt") or "",
        "enabled": cfg.get("enabled", 1),
    }


def _report_to_text(result: dict, max_items: int = 60) -> str:
    conn = result.get("connection", {})
    tpl = result.get("template", {})
    summary = result.get("summary", {})
    lines = [
        f"实例：{conn.get('name')}（{conn.get('db_type')}，{conn.get('version') or ''}）",
        f"模板：{tpl.get('name')}，巡检时间：{result.get('started_at')}，耗时 {result.get('duration')}s",
        f"汇总：总数 {summary.get('total')}，正常 {summary.get('normal')}，警告 {summary.get('warn')}，"
        f"严重 {summary.get('crit')}，信息 {summary.get('info')}，错误 {summary.get('error')}",
        "",
        "巡检项明细：",
    ]
    count = 0
    for cat in result.get("categories", []):
        lines.append(f"【{cat.get('name')}】")
        for item in cat.get("items", []):
            if count >= max_items:
                lines.append("（明细过多，已截断）")
                return "\n".join(lines)
            err = item.get("error")
            extra = f" 错误信息:{err}" if err else ""
            lines.append(
                f"  - {item.get('name')}：{item.get('status')}，值={item.get('value')}，"
                f"阈值={item.get('threshold_desc') or '无'}{extra}"
            )
            count += 1
    return "\n".join(lines)


def call_chat_completions(base_url: str, api_key: str, model: str, system: str,
                          user: str, temperature: float = 0.3, timeout: int = 120) -> str:
    url = base_url.rstrip("/") + "/chat/completions"
    payload = json.dumps({
        "model": model,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        "temperature": temperature,
        "stream": False,
    }, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(url, data=payload, method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("Authorization", f"Bearer {api_key}")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        return data["choices"][0]["message"]["content"]
    except urllib.error.HTTPError as e:
        body = ""
        try:
            body = e.read().decode("utf-8", "replace")[:500]
        except Exception:
            pass
        raise RuntimeError(f"AI 接口返回 HTTP {e.code}：{body}")
    except urllib.error.URLError as e:
        raise RuntimeError(f"无法连接 AI 接口：{e.reason}")


def interpret_report(result: dict, cfg: dict) -> str:
    """单个报告解读。cfg 为 ai_configs 行。"""
    api_key = security.decrypt_text(cfg.get("api_key_enc") or "")
    if not api_key:
        raise RuntimeError("该 AI 配置未设置 API Key。")
    system = (cfg.get("system_prompt") or "").strip() or DEFAULT_SYSTEM
    report_text = _report_to_text(result)
    user = (
        "请对以下数据库巡检报告进行解读并给出处置建议：\n\n"
        + report_text
    )
    return call_chat_completions(
        cfg.get("base_url", ""), api_key, cfg.get("model", ""),
        system, user, float(cfg.get("temperature") or 0.3),
    )


def interpret_batch(results: list[dict], cfg: dict) -> str:
    """批量解读：汇总多份报告。"""
    api_key = security.decrypt_text(cfg.get("api_key_enc") or "")
    if not api_key:
        raise RuntimeError("该 AI 配置未设置 API Key。")
    system = (cfg.get("system_prompt") or "").strip() or DEFAULT_SYSTEM
    parts = []
    for i, r in enumerate(results, 1):
        parts.append(f"===== 报告 {i} =====")
        parts.append(_report_to_text(r, max_items=40))
    user = (
        f"以下是 {len(results)} 份数据库巡检报告的汇总数据。请先逐份给出结论，"
        f"再做横向对比与整体风险总结，并给出处置优先级建议：\n\n" + "\n\n".join(parts)
    )
    return call_chat_completions(
        cfg.get("base_url", ""), api_key, cfg.get("model", ""),
        system, user, float(cfg.get("temperature") or 0.3),
    )
