"""Flask Web 应用：路由、认证与基于角色的权限控制（RBAC）。

角色：viewer(只读) < dba(运维) < admin(管理员)
* admin：全部权限，含用户管理、AI 配置、系统设置
* dba ：连接/模板/任务/报告/AI 解读
* viewer：仅查看与下载
"""
from __future__ import annotations

import io
import json
import os
import time as _time
import zipfile
from datetime import datetime, timedelta
from functools import wraps

from flask import Flask, g, jsonify, request, send_from_directory, session

from . import ROLE_RANK, STATIC_DIR, store
from . import ai as ai_mod
from . import drivers, engine, notify, reports, service
from . import security
from .scheduler import get_scheduler

_SECRET_FILE = os.path.join(store.DATA_DIR, "flask_secret.key")


def _load_secret() -> str:
    if os.path.isfile(_SECRET_FILE):
        with open(_SECRET_FILE, "rb") as fp:
            return fp.read()
    key = os.urandom(32)
    os.makedirs(store.DATA_DIR, exist_ok=True)
    with open(_SECRET_FILE, "wb") as fp:
        fp.write(key)
    return key


# =====================================================================
# 应用工厂
# =====================================================================
def create_app() -> Flask:
    app = Flask(__name__, static_folder=None)
    app.secret_key = _load_secret()
    app.json.ensure_ascii = False
    app.permanent_session_lifetime = timedelta(days=7)

    register_routes(app)
    return app


# =====================================================================
# 认证 / 权限工具
# =====================================================================
def current_user() -> dict | None:
    uid = session.get("uid")
    if not uid:
        return None
    return store.query_one("SELECT * FROM users WHERE id=?", (uid,))


def _deny(message: str, code: int):
    return jsonify(ok=False, message=message), code


# ---- 登录失败锁定（内存态，进程内有效）----
_LOGIN_FAILS: dict[str, list[float]] = {}
_MAX_LOGIN_FAILS = 5
_LOCK_SECONDS = 10 * 60


def _login_lock_msg(username: str) -> str:
    fails = [t for t in _LOGIN_FAILS.get(username, []) if _time.time() - t < _LOCK_SECONDS]
    _LOGIN_FAILS[username] = fails
    if len(fails) >= _MAX_LOGIN_FAILS:
        remain = int(_LOCK_SECONDS - (_time.time() - fails[0]))
        return f"登录失败次数过多，请 {max(1, remain // 60)} 分钟后重试"
    return ""


def _record_login_fail(username: str) -> None:
    fails = [t for t in _LOGIN_FAILS.get(username, []) if _time.time() - t < _LOCK_SECONDS]
    fails.append(_time.time())
    _LOGIN_FAILS[username] = fails[-_MAX_LOGIN_FAILS:]


def _clear_login_fails(username: str) -> None:
    _LOGIN_FAILS.pop(username, None)


def require_role(min_role: str):
    def deco(fn):
        @wraps(fn)
        def wrapper(*a, **k):
            u = current_user()
            if not u:
                return _deny("未登录或会话已过期", 401)
            if not u.get("enabled"):
                return _deny("账号已停用", 403)
            if ROLE_RANK.get(u.get("role"), 0) < ROLE_RANK.get(min_role, 0):
                return _deny("权限不足", 403)
            g.user = u
            return fn(*a, **k)
        return wrapper
    return deco


def _body() -> dict:
    return request.get_json(silent=True) or {}


def _now_date() -> str:
    return datetime.now().strftime("%Y-%m-%d")


def _parse_output_formats(data: dict, default=None) -> list[str]:
    v = data.get("output_formats")
    if isinstance(v, list):
        return [x for x in v if x in ("html", "word")]
    if isinstance(v, str):
        try:
            return [x for x in json.loads(v) if x in ("html", "word")]
        except Exception:
            pass
    return default or ["html", "word"]


def _conn_public(row: dict) -> dict:
    return {
        "id": row["id"], "name": row["name"], "db_type": row["db_type"],
        "host": row["host"], "port": row["port"], "database": row["database"],
        "username": row["username"], "connect_mode": row["connect_mode"],
        "env": row.get("env") or "",
        "remark": row["remark"], "enabled": row["enabled"],
        "last_test_at": row["last_test_at"], "last_test_ok": row["last_test_ok"],
        "last_test_msg": row["last_test_msg"],
        "created_at": row["created_at"], "updated_at": row["updated_at"],
    }


# =====================================================================
# 路由注册
# =====================================================================
def register_routes(app: Flask) -> None:

    @app.get("/")
    def index():
        return send_from_directory(STATIC_DIR, "index.html")

    @app.get("/static/<path:filename>")
    def static_files(filename):
        return send_from_directory(STATIC_DIR, filename)

    # ---------------- 认证 ----------------
    @app.post("/api/login")
    def login():
        data = _body()
        username = (data.get("username") or "").strip()
        password = data.get("password") or ""
        lock_msg = _login_lock_msg(username)
        if lock_msg:
            return _deny(lock_msg, 429)
        u = store.query_one("SELECT * FROM users WHERE username=?", (username,))
        if not u or not security.verify_password(password, u["password_hash"]):
            _record_login_fail(username)
            return _deny("用户名或密码错误", 401)
        if not u.get("enabled"):
            return _deny("账号已停用", 403)
        _clear_login_fails(username)
        session["uid"] = u["id"]
        if data.get("remember"):
            session.permanent = True
        store.execute("UPDATE users SET last_login_at=? WHERE id=?", (store.now(), u["id"]))
        store.audit(u["id"], u["username"], "login", "")
        return jsonify(ok=True, user=_user_public(u))

    @app.post("/api/logout")
    def logout():
        session.clear()
        return jsonify(ok=True)

    @app.get("/api/me")
    def me():
        u = current_user()
        if not u:
            return jsonify(ok=True, user=None)
        return jsonify(ok=True, user=_user_public(u))

    # ---------------- 仪表盘 ----------------
    @app.get("/api/dashboard")
    @require_role("viewer")
    def dashboard():
        conns = store.query_all("SELECT * FROM connections")
        online = sum(1 for c in conns if c["last_test_ok"] == 1)
        abnormal_conn = sum(1 for c in conns if c["last_test_ok"] == 0)

        today = _now_date()
        today_reports = store.query_all(
            "SELECT * FROM reports WHERE substr(created_at,1,10)=? ORDER BY created_at DESC", (today,))
        auto_n = sum(1 for r in today_reports if r["trigger_type"] == "auto")
        manual_n = len(today_reports) - auto_n

        def _abn(r):
            try:
                s = json.loads(r["summary"] or "{}")
                return int(s.get("crit", 0)) + int(s.get("warn", 0))
            except Exception:
                return 0
        abnormal_items = sum(_abn(r) for r in today_reports)

        report_total = store.query_one("SELECT COUNT(*) AS n FROM reports")["n"]
        month_prefix = datetime.now().strftime("%Y-%m")
        month_new = store.query_one(
            "SELECT COUNT(*) AS n FROM reports WHERE substr(created_at,1,7)=?", (month_prefix,))["n"]

        # 类型分布
        dist = {}
        for c in conns:
            dist[c["db_type"]] = dist.get(c["db_type"], 0) + 1
        type_dist = [{"type": t, "count": n} for t, n in dist.items()]

        # 近 7 天异常项趋势
        trend = []
        for i in range(6, -1, -1):
            d = (datetime.now() - timedelta(days=i)).strftime("%Y-%m-%d")
            rs = store.query_all(
                "SELECT summary FROM reports WHERE substr(created_at,1,10)=?", (d,))
            trend.append({"date": d[5:], "count": sum(_abn(r) for r in rs)})

        recent = store.query_all(
            "SELECT id,name,connection_name,db_type,template_name,trigger_type,status,duration,summary,created_at "
            "FROM reports ORDER BY created_at DESC LIMIT 6")
        recent_out = []
        for r in recent:
            try:
                s = json.loads(r["summary"] or "{}")
            except Exception:
                s = {}
            recent_out.append({
                "id": r["id"], "name": r["name"], "connection_name": r["connection_name"],
                "db_type": r["db_type"], "template_name": r["template_name"],
                "trigger_type": r["trigger_type"], "status": r["status"],
                "duration": r["duration"], "crit": s.get("crit", 0), "warn": s.get("warn", 0),
                "created_at": r["created_at"],
            })

        wo_total = store.query_one("SELECT COUNT(*) AS n FROM work_orders")["n"]
        wo_open = store.query_one("SELECT COUNT(*) AS n FROM work_orders WHERE status='open'")["n"]
        wo_closed = store.query_one("SELECT COUNT(*) AS n FROM work_orders WHERE status='closed'")["n"]

        return jsonify(ok=True, data={
            "conn_total": len(conns), "conn_online": online, "conn_abnormal": abnormal_conn,
            "today_inspect": len(today_reports), "auto_count": auto_n, "manual_count": manual_n,
            "abnormal_items": abnormal_items,
            "report_total": report_total, "month_new": month_new,
            "type_dist": type_dist, "trend": trend, "recent": recent_out,
            "work_orders": {"total": wo_total, "open": wo_open, "closed": wo_closed},
        })

    # ---------------- 连接管理 ----------------
    @app.get("/api/connections")
    @require_role("viewer")
    def list_connections():
        rows = store.query_all("SELECT * FROM connections ORDER BY id DESC")
        return jsonify(ok=True, data=[_conn_public(r) for r in rows])

    @app.post("/api/connections")
    @require_role("dba")
    def create_connection():
        data = _body()
        if not (data.get("name") and data.get("host") and data.get("username")):
            return _deny("连接名称、主机地址、用户名均为必填项", 400)
        cid = store.execute(
            "INSERT INTO connections(name,db_type,host,port,database,username,password_enc,connect_mode,env,"
            "remark,enabled,created_by,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,1,?,?,?)",
            (data.get("name"), data.get("db_type") or "mysql", data.get("host"), int(data.get("port") or 0),
             data.get("database") or "", data.get("username"),
             security.encrypt_text(data.get("password") or ""), data.get("connect_mode") or "service",
             data.get("env") or "", data.get("remark") or "", g.user["id"], store.now(), store.now()),
        )
        store.audit(g.user["id"], g.user["username"], "conn_create", data.get("name"))
        return jsonify(ok=True, id=cid)

    @app.put("/api/connections/<int:cid>")
    @require_role("dba")
    def update_connection(cid):
        data = _body()
        row = store.query_one("SELECT * FROM connections WHERE id=?", (cid,))
        if not row:
            return _deny("连接不存在", 404)
        pwd = data.get("password")
        password_enc = security.encrypt_text(pwd) if pwd else row["password_enc"]
        store.execute(
            "UPDATE connections SET name=?,db_type=?,host=?,port=?,database=?,username=?,password_enc=?,"
            "connect_mode=?,env=?,remark=?,updated_at=? WHERE id=?",
            (data.get("name", row["name"]), data.get("db_type", row["db_type"]),
             data.get("host", row["host"]), int(data.get("port", row["port"] or 0)),
             data.get("database", row["database"]), data.get("username", row["username"]),
             password_enc, data.get("connect_mode", row["connect_mode"]),
             data.get("env", row.get("env") or ""), data.get("remark", row["remark"]), store.now(), cid),
        )
        store.audit(g.user["id"], g.user["username"], "conn_update", row["name"])
        return jsonify(ok=True)

    @app.delete("/api/connections/<int:cid>")
    @require_role("dba")
    def delete_connection(cid):
        row = store.query_one("SELECT * FROM connections WHERE id=?", (cid,))
        if not row:
            return _deny("连接不存在", 404)
        store.execute("DELETE FROM connections WHERE id=?", (cid,))
        store.audit(g.user["id"], g.user["username"], "conn_delete", row["name"])
        return jsonify(ok=True)

    @app.post("/api/connections/<int:cid>/test")
    @require_role("dba")
    def test_connection(cid):
        row = store.query_one("SELECT * FROM connections WHERE id=?", (cid,))
        if not row:
            return _deny("连接不存在", 404)
        pwd = store.decrypt_password(row)
        res = drivers.test_connection(row, pwd)
        store.execute(
            "UPDATE connections SET last_test_at=?, last_test_ok=?, last_test_msg=? WHERE id=?",
            (store.now(), 1 if res["ok"] else 0, res["message"], cid))
        return jsonify(ok=True, result=res)

    @app.post("/api/connections/test-raw")
    @require_role("dba")
    def test_raw_connection():
        data = _body()
        row = {
            "name": data.get("name") or "临时连接", "db_type": data.get("db_type") or "mysql",
            "host": data.get("host"), "port": data.get("port"), "database": data.get("database"),
            "username": data.get("username"), "connect_mode": data.get("connect_mode") or "service",
        }
        if not row["host"] or not row["username"]:
            return _deny("请填写主机地址与用户名", 400)
        res = drivers.test_connection(row, data.get("password") or "")
        return jsonify(ok=True, result=res)

    @app.post("/api/connections/batch-test")
    @require_role("dba")
    def batch_test():
        data = _body()
        ids = data.get("ids") or []
        rows = store.query_all("SELECT * FROM connections") if not ids else store.query_all(
            "SELECT * FROM connections WHERE id IN (%s)" % ",".join("?" * len(ids)), ids)
        ok_n = 0
        results = []
        for r in rows:
            pwd = store.decrypt_password(r)
            res = drivers.test_connection(r, pwd)
            if res["ok"]:
                ok_n += 1
            store.execute(
                "UPDATE connections SET last_test_at=?, last_test_ok=?, last_test_msg=? WHERE id=?",
                (store.now(), 1 if res["ok"] else 0, res["message"], r["id"]))
            results.append({"id": r["id"], "name": r["name"], "ok": res["ok"], "message": res["message"]})
        return jsonify(ok=True, ok_count=ok_n, total=len(rows), results=results)

    # ---------------- 模板管理 ----------------
    @app.get("/api/templates")
    @require_role("viewer")
    def list_templates():
        rows = store.query_all("SELECT t.*, (SELECT COUNT(*) FROM template_items i WHERE i.template_id=t.id) AS item_count "
                               "FROM templates t ORDER BY t.id DESC")
        return jsonify(ok=True, data=[_tpl_public(r) for r in rows])

    @app.get("/api/templates/<int:tid>")
    @require_role("viewer")
    def get_template(tid):
        t = store.query_one("SELECT * FROM templates WHERE id=?", (tid,))
        if not t:
            return _deny("模板不存在", 404)
        items = store.query_all(
            "SELECT * FROM template_items WHERE template_id=? ORDER BY sort_order,id", (tid,))
        return jsonify(ok=True, data={"template": _tpl_public(t), "items": [dict(i) for i in items]})

    @app.post("/api/templates")
    @require_role("dba")
    def create_template():
        data = _body()
        name = data.get("name") or ""
        if not name:
            return _deny("模板名称不能为空", 400)
        tid = store.execute(
            "INSERT INTO templates(name,db_type,description,status,report_title,watermark,output_formats,abnormal_only,email_notify,created_by,created_at,updated_at) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            (name, data.get("db_type") or "mysql", data.get("description") or "",
             data.get("status") or "enabled", data.get("report_title") or "数据库巡检报告",
             data.get("watermark") or "", json.dumps(_parse_output_formats(data), ensure_ascii=False),
             1 if data.get("abnormal_only") else 0, 1 if data.get("email_notify") else 0,
             g.user["id"], store.now(), store.now()),
        )
        store.audit(g.user["id"], g.user["username"], "tpl_create", name)
        return jsonify(ok=True, id=tid)

    @app.put("/api/templates/<int:tid>")
    @require_role("dba")
    def update_template(tid):
        data = _body()
        t = store.query_one("SELECT * FROM templates WHERE id=?", (tid,))
        if not t:
            return _deny("模板不存在", 404)
        store.execute(
            "UPDATE templates SET name=?,db_type=?,description=?,status=?,report_title=?,watermark=?,"
            "output_formats=?,abnormal_only=?,email_notify=?,updated_at=? WHERE id=?",
            (data.get("name", t["name"]), data.get("db_type", t["db_type"]),
             data.get("description", t["description"]), data.get("status", t["status"]),
             data.get("report_title", t["report_title"]), data.get("watermark", t["watermark"]),
             json.dumps(_parse_output_formats(data, json.loads(t["output_formats"] or '[]')), ensure_ascii=False),
             1 if data.get("abnormal_only") else 0, 1 if data.get("email_notify") else 0, store.now(), tid),
        )
        store.audit(g.user["id"], g.user["username"], "tpl_update", t["name"])
        return jsonify(ok=True)

    @app.delete("/api/templates/<int:tid>")
    @require_role("dba")
    def delete_template(tid):
        t = store.query_one("SELECT * FROM templates WHERE id=?", (tid,))
        if not t:
            return _deny("模板不存在", 404)
        store.execute("DELETE FROM template_items WHERE template_id=?", (tid,))
        store.execute("DELETE FROM templates WHERE id=?", (tid,))
        store.audit(g.user["id"], g.user["username"], "tpl_delete", t["name"])
        return jsonify(ok=True)

    @app.post("/api/templates/<int:tid>/copy")
    @require_role("dba")
    def copy_template(tid):
        t = store.query_one("SELECT * FROM templates WHERE id=?", (tid,))
        if not t:
            return _deny("模板不存在", 404)
        items = store.query_all("SELECT * FROM template_items WHERE template_id=? ORDER BY sort_order,id", (tid,))
        new_id = store.execute(
            "INSERT INTO templates(name,db_type,description,status,report_title,watermark,output_formats,abnormal_only,created_by,created_at,updated_at) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (t["name"] + "（副本）", t["db_type"], t["description"], t["status"], t["report_title"],
             t["watermark"], t["output_formats"], t["abnormal_only"], g.user["id"], store.now(), store.now()),
        )
        for it in items:
            store.execute(
                "INSERT INTO template_items(template_id,category,item_name,sql_text,eval_mode,metric_column,warn_op,warn_value,crit_op,crit_value,value_format,threshold_desc,sort_order,enabled) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (new_id, it["category"], it["item_name"], it["sql_text"], it["eval_mode"],
                 it["metric_column"], it["warn_op"], it["warn_value"], it["crit_op"], it["crit_value"],
                 it["value_format"], it["threshold_desc"], it["sort_order"], it["enabled"]),
            )
        store.audit(g.user["id"], g.user["username"], "tpl_copy", t["name"])
        return jsonify(ok=True, id=new_id)

    @app.put("/api/templates/<int:tid>/items")
    @require_role("dba")
    def save_template_items(tid):
        data = _body()
        t = store.query_one("SELECT * FROM templates WHERE id=?", (tid,))
        if not t:
            return _deny("模板不存在", 404)
        items = data.get("items") or []
        store.execute("DELETE FROM template_items WHERE template_id=?", (tid,))
        for i, it in enumerate(items):
            store.execute(
                "INSERT INTO template_items(template_id,category,item_name,sql_text,eval_mode,metric_column,warn_op,warn_value,crit_op,crit_value,value_format,threshold_desc,sort_order,enabled) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (tid, it.get("category") or "未分类", it.get("item_name") or "巡检项",
                 it.get("sql_text") or "", it.get("eval_mode") or "info",
                 it.get("metric_column") or "", it.get("warn_op") or "", it.get("warn_value"),
                 it.get("crit_op") or "", it.get("crit_value"), it.get("value_format") or "number",
                 it.get("threshold_desc") or "", i, 1 if it.get("enabled", 1) else 0),
            )
        store.execute("UPDATE templates SET updated_at=? WHERE id=?", (store.now(), tid))
        return jsonify(ok=True)

    @app.get("/api/templates/<int:tid>/export")
    @require_role("viewer")
    def export_template(tid):
        t = store.query_one("SELECT * FROM templates WHERE id=?", (tid,))
        if not t:
            return _deny("模板不存在", 404)
        items = store.query_all(
            "SELECT * FROM template_items WHERE template_id=? ORDER BY sort_order,id", (tid,))
        try:
            output_formats = json.loads(t.get("output_formats") or '[]')
        except Exception:
            output_formats = []
        data = {
            "name": t["name"], "db_type": t["db_type"], "description": t["description"],
            "report_title": t["report_title"], "watermark": t["watermark"],
            "output_formats": output_formats, "abnormal_only": t["abnormal_only"],
            "email_notify": t["email_notify"],
            "items": [{
                "category": i["category"], "item_name": i["item_name"], "sql_text": i["sql_text"],
                "eval_mode": i["eval_mode"], "metric_column": i["metric_column"],
                "warn_op": i["warn_op"], "warn_value": i["warn_value"],
                "crit_op": i["crit_op"], "crit_value": i["crit_value"],
                "value_format": i["value_format"], "threshold_desc": i["threshold_desc"],
                "enabled": i["enabled"],
            } for i in items],
        }
        filename = f"{t['name']}.json"
        return _send_bytes(json.dumps(data, ensure_ascii=False, indent=2).encode("utf-8"),
                           filename, "application/json")

    @app.post("/api/templates/import")
    @require_role("dba")
    def import_template():
        data = _body()
        name = (data.get("name") or "").strip()
        if not name:
            return _deny("模板数据缺少名称", 400)
        try:
            output_formats = data.get("output_formats") or ["html", "word"]
        except Exception:
            output_formats = ["html", "word"]
        tid = store.execute(
            "INSERT INTO templates(name,db_type,description,status,report_title,watermark,output_formats,abnormal_only,email_notify,created_by,created_at,updated_at) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            (name, data.get("db_type") or "mysql", data.get("description") or "", "draft",
             data.get("report_title") or "数据库巡检报告", data.get("watermark") or "",
             json.dumps(output_formats, ensure_ascii=False),
             1 if data.get("abnormal_only") else 0, 1 if data.get("email_notify") else 0,
             g.user["id"], store.now(), store.now()),
        )
        for i, it in enumerate(data.get("items") or []):
            store.execute(
                "INSERT INTO template_items(template_id,category,item_name,sql_text,eval_mode,metric_column,warn_op,warn_value,crit_op,crit_value,value_format,threshold_desc,sort_order,enabled) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (tid, it.get("category") or "未分类", it.get("item_name") or "巡检项",
                 it.get("sql_text") or "", it.get("eval_mode") or "info",
                 it.get("metric_column") or "", it.get("warn_op") or "", it.get("warn_value"),
                 it.get("crit_op") or "", it.get("crit_value"), it.get("value_format") or "number",
                 it.get("threshold_desc") or "", i, 1 if it.get("enabled", 1) else 0),
            )
        store.audit(g.user["id"], g.user["username"], "tpl_import", name)
        return jsonify(ok=True, id=tid)

    # ---------------- SQL 模板库 ----------------
    @app.get("/api/sql-templates")
    @require_role("viewer")
    def list_sql_templates():
        db_type = request.args.get("db_type", "")
        if db_type:
            rows = store.query_all("SELECT * FROM sql_templates WHERE db_type=? ORDER BY id", (db_type,))
        else:
            rows = store.query_all("SELECT * FROM sql_templates ORDER BY db_type, id")
        return jsonify(ok=True, data=[dict(r) for r in rows])

    @app.post("/api/sql-templates")
    @require_role("dba")
    def create_sql_template():
        data = _body()
        name = (data.get("name") or "").strip()
        sql = (data.get("sql_text") or "").strip()
        if not name or not sql:
            return _deny("名称与 SQL 不能为空", 400)
        tid = store.execute(
            "INSERT INTO sql_templates(db_type,name,metric,sql_text,threshold_desc,created_at) VALUES(?,?,?,?,?,?)",
            (data.get("db_type") or "mysql", name, data.get("metric") or "", sql,
             data.get("threshold_desc") or "", store.now()))
        store.audit(g.user["id"], g.user["username"], "sql_template_create", name)
        return jsonify(ok=True, id=tid)

    @app.put("/api/sql-templates/<int:tid>")
    @require_role("dba")
    def update_sql_template(tid):
        data = _body()
        t = store.query_one("SELECT * FROM sql_templates WHERE id=?", (tid,))
        if not t:
            return _deny("SQL 模板不存在", 404)
        store.execute(
            "UPDATE sql_templates SET db_type=?,name=?,metric=?,sql_text=?,threshold_desc=? WHERE id=?",
            (data.get("db_type", t["db_type"]), data.get("name", t["name"]),
             data.get("metric", t["metric"]), data.get("sql_text", t["sql_text"]),
             data.get("threshold_desc", t["threshold_desc"]), tid))
        return jsonify(ok=True)

    @app.delete("/api/sql-templates/<int:tid>")
    @require_role("dba")
    def delete_sql_template(tid):
        store.execute("DELETE FROM sql_templates WHERE id=?", (tid,))
        return jsonify(ok=True)

    @app.post("/api/sql-templates/batch-delete")
    @require_role("dba")
    def batch_delete_sql_templates():
        data = _body()
        ids = [int(x) for x in (data.get("ids") or []) if str(x).isdigit()]
        if not ids:
            return _deny("请选择要删除的模板", 400)
        store.execute(f"DELETE FROM sql_templates WHERE id IN ({','.join('?' for _ in ids)})", ids)
        store.audit(g.user["id"], g.user["username"], "sql_template_batch_delete", f"批量删除 {len(ids)} 个 SQL 模板")
        return jsonify(ok=True, message=f"已删除 {len(ids)} 个模板")

    @app.post("/api/sql-test")
    @require_role("dba")
    def sql_test():
        data = _body()
        conn_id = data.get("connection_id")
        sql = (data.get("sql") or "").strip()
        if not conn_id or not sql:
            return _deny("请选择连接并填写 SQL", 400)
        conn = store.query_one("SELECT * FROM connections WHERE id=?", (conn_id,))
        if not conn:
            return _deny("连接不存在", 404)
        try:
            session_ = drivers.open_session(conn, store.decrypt_password(conn))
            try:
                cols, rows = session_.execute(sql)
                return jsonify(ok=True, columns=cols, rows=rows[:100], total=len(rows))
            finally:
                session_.close()
        except Exception as exc:  # noqa: BLE001
            return jsonify(ok=False, message=str(exc).strip()[:400]), 200

    # ---------------- 手动巡检（异步任务） ----------------
    @app.post("/api/inspect")
    @require_role("dba")
    def start_inspect():
        data = _body()
        conn_ids = data.get("connection_ids") or []
        template_id = data.get("template_id")
        output_formats = _parse_output_formats(data)
        if not conn_ids or not template_id:
            return _deny("请选择目标数据库和巡检模板", 400)
        template = store.query_one("SELECT * FROM templates WHERE id=?", (template_id,))
        if not template:
            return _deny("模板不存在", 404)
        items = store.query_all(
            "SELECT * FROM template_items WHERE template_id=? AND enabled=1 ORDER BY sort_order,id", (template_id,))
        conns = store.query_all(
            "SELECT * FROM connections WHERE enabled=1 AND id IN (%s)" % ",".join("?" * len(conn_ids)), conn_ids)

        job_id = _new_job()
        args = dict(conns=conns, template=template, items=items,
                    output_formats=output_formats, trigger_type="manual",
                    username=g.user["username"])
        _jobs[job_id]["args"] = args
        _start_job_thread(job_id, _run_inspect_job)
        store.audit(g.user["id"], g.user["username"], "inspect_start",
                    f"模板[{template['name']}]，{len(conns)} 个连接")
        return jsonify(ok=True, job_id=job_id)

    @app.get("/api/jobs/<job_id>")
    @require_role("dba")
    def job_status(job_id):
        j = _jobs.get(job_id)
        if not j:
            return _deny("任务不存在", 404)
        return jsonify(ok=True, job={
            "id": job_id, "status": j["status"], "progress": j["progress"],
            "log": j["log"], "reports": j["reports"], "error": j.get("error"),
        })

    # ---------------- 调度（自动巡检） ----------------
    @app.get("/api/schedules")
    @require_role("viewer")
    def list_schedules():
        rows = store.query_all(
            "SELECT s.*, t.name AS template_name FROM schedules s LEFT JOIN templates t ON t.id=s.template_id ORDER BY s.id DESC")
        out = []
        for r in rows:
            try:
                r["connection_ids"] = json.loads(r["connection_ids"] or "[]")
            except Exception:
                r["connection_ids"] = []
            try:
                r["output_formats"] = json.loads(r["output_formats"] or '[]')
            except Exception:
                r["output_formats"] = []
            r["_next_run"] = _next_run_time(r["cron"])
            out.append(dict(r))
        return jsonify(ok=True, data=out)

    @app.post("/api/schedules")
    @require_role("dba")
    def create_schedule():
        data = _body()
        name = data.get("name") or ""
        if not name or not data.get("cron"):
            return _deny("调度名称与 Cron 表达式不能为空", 400)
        sid = store.execute(
            "INSERT INTO schedules(name,enabled,connection_ids,template_id,cron,output_formats,max_retries,retry_interval_min,created_by,created_at) "
            "VALUES(?,?,?,?,?,?,?,?,?,?)",
            (name, 1 if data.get("enabled", 1) else 0,
             json.dumps(data.get("connection_ids") or ["*"], ensure_ascii=False),
             data.get("template_id"), data.get("cron").strip(),
             json.dumps(_parse_output_formats(data), ensure_ascii=False),
             int(data.get("max_retries") or 0), int(data.get("retry_interval_min") or 10),
             g.user["id"], store.now()),
        )
        get_scheduler().reset(sid)
        store.audit(g.user["id"], g.user["username"], "sched_create", name)
        return jsonify(ok=True, id=sid)

    @app.put("/api/schedules/<int:sid>")
    @require_role("dba")
    def update_schedule(sid):
        data = _body()
        s = store.query_one("SELECT * FROM schedules WHERE id=?", (sid,))
        if not s:
            return _deny("调度不存在", 404)
        store.execute(
            "UPDATE schedules SET name=?,enabled=?,connection_ids=?,template_id=?,cron=?,output_formats=?,max_retries=?,retry_interval_min=? WHERE id=?",
            (data.get("name", s["name"]), 1 if data.get("enabled", 1) else 0,
             json.dumps(data.get("connection_ids", json.loads(s["connection_ids"] or '[]')), ensure_ascii=False),
             data.get("template_id", s["template_id"]), data.get("cron", s["cron"]).strip(),
             json.dumps(_parse_output_formats(data, json.loads(s["output_formats"] or '[]')), ensure_ascii=False),
             int(data.get("max_retries", s.get("max_retries") or 0)),
             int(data.get("retry_interval_min", s.get("retry_interval_min") or 10)),
             sid),
        )
        get_scheduler().reset(sid)
        return jsonify(ok=True)

    @app.delete("/api/schedules/<int:sid>")
    @require_role("dba")
    def delete_schedule(sid):
        store.execute("DELETE FROM schedules WHERE id=?", (sid,))
        get_scheduler().reset(sid)
        return jsonify(ok=True)

    @app.post("/api/schedules/<int:sid>/toggle")
    @require_role("dba")
    def toggle_schedule(sid):
        s = store.query_one("SELECT * FROM schedules WHERE id=?", (sid,))
        if not s:
            return _deny("调度不存在", 404)
        store.execute("UPDATE schedules SET enabled=? WHERE id=?", (0 if s["enabled"] else 1, sid))
        get_scheduler().reset(sid)
        return jsonify(ok=True)

    @app.post("/api/schedules/<int:sid>/run-now")
    @require_role("dba")
    def run_schedule_now(sid):
        s = store.query_one("SELECT * FROM schedules WHERE id=?", (sid,))
        if not s:
            return _deny("调度不存在", 404)
        get_scheduler().reset(sid)
        import threading
        threading.Thread(target=_run_single_schedule, args=(s,), daemon=True).start()
        return jsonify(ok=True, message="已触发立即执行")

    @app.get("/api/schedule-runs")
    @require_role("viewer")
    def list_schedule_runs():
        rows = store.query_all(
            "SELECT * FROM schedule_runs ORDER BY id DESC LIMIT 200")
        out = []
        for r in rows:
            try:
                r["report_ids"] = json.loads(r.get("report_ids") or "[]")
            except Exception:
                r["report_ids"] = []
            out.append(dict(r))
        return jsonify(ok=True, data=out)

    @app.get("/api/manual-runs")
    @require_role("viewer")
    def list_manual_runs():
        rows = store.query_all(
            "SELECT * FROM manual_runs ORDER BY id DESC LIMIT 200")
        out = []
        for r in rows:
            for f in ("connection_names", "report_ids"):
                try:
                    r[f] = json.loads(r.get(f) or "[]")
                except Exception:
                    r[f] = []
            out.append(dict(r))
        return jsonify(ok=True, data=out)

    # ---------------- 工单 ----------------
    @app.get("/api/work-orders")
    @require_role("viewer")
    def list_work_orders():
        status = request.args.get("status", "")
        sql = "SELECT * FROM work_orders"
        params = []
        if status in ("open", "closed"):
            sql += " WHERE status=?"
            params.append(status)
        sql += " ORDER BY id DESC LIMIT 500"
        rows = store.query_all(sql, params)
        return jsonify(ok=True, data=[dict(r) for r in rows])

    @app.get("/api/work-orders/stats")
    @require_role("viewer")
    def work_order_stats():
        total = store.query_one("SELECT COUNT(*) AS n FROM work_orders")["n"]
        open_n = store.query_one("SELECT COUNT(*) AS n FROM work_orders WHERE status='open'")["n"]
        closed = store.query_one("SELECT COUNT(*) AS n FROM work_orders WHERE status='closed'")["n"]
        by_db = {r["db_type"]: r["n"] for r in
                 store.query_all("SELECT db_type, COUNT(*) AS n FROM work_orders WHERE status='open' GROUP BY db_type")}
        by_sev = {r["severity"]: r["n"] for r in
                  store.query_all("SELECT severity, COUNT(*) AS n FROM work_orders WHERE status='open' GROUP BY severity")}
        return jsonify(ok=True, data={"total": total, "open": open_n, "closed": closed,
                                      "by_db": by_db, "by_severity": by_sev})

    @app.post("/api/work-orders/batch-close")
    @require_role("dba")
    def batch_close_work_orders():
        data = _body()
        ids = [int(x) for x in (data.get("ids") or []) if str(x).isdigit()]
        if not ids:
            return _deny("请选择要关闭的工单", 400)
        marks = ",".join("?" for _ in ids)
        store.execute(
            f"UPDATE work_orders SET status='closed', closed_at=?, closed_by=? WHERE status='open' AND id IN ({marks})",
            [store.now(), g.user["id"]] + ids)
        store.audit(g.user["id"], g.user["username"], "workorder_batch_close", f"批量关闭 {len(ids)} 个工单")
        return jsonify(ok=True, message=f"已关闭 {len(ids)} 个工单")

    @app.post("/api/work-orders/<int:wid>/close")
    @require_role("dba")
    def close_work_order(wid):
        wo = store.query_one("SELECT * FROM work_orders WHERE id=?", (wid,))
        if not wo:
            return _deny("工单不存在", 404)
        store.execute("UPDATE work_orders SET status='closed', closed_at=?, closed_by=? WHERE id=?",
                      (store.now(), g.user["id"], wid))
        store.audit(g.user["id"], g.user["username"], "workorder_close", f"工单 #{wid} {wo['item_name']}")
        return jsonify(ok=True)

    @app.delete("/api/work-orders/<int:wid>")
    @require_role("dba")
    def delete_work_order(wid):
        wo = store.query_one("SELECT * FROM work_orders WHERE id=?", (wid,))
        if not wo:
            return _deny("工单不存在", 404)
        store.execute("DELETE FROM work_orders WHERE id=?", (wid,))
        store.audit(g.user["id"], g.user["username"], "workorder_delete", f"工单 #{wid} {wo['item_name']}")
        return jsonify(ok=True)

    # ---------------- 报告 ----------------
    @app.get("/api/reports")
    @require_role("viewer")
    def list_reports():
        rows = store.query_all(
            "SELECT id,report_no,name,connection_name,db_type,template_name,trigger_type,status,duration,summary,html_file,word_file,created_at "
            "FROM reports ORDER BY created_at DESC LIMIT 500")
        out = []
        for r in rows:
            try:
                s = json.loads(r["summary"] or "{}")
            except Exception:
                s = {}
            out.append({
                "id": r["id"], "report_no": r["report_no"], "name": r["name"],
                "connection_name": r["connection_name"], "db_type": r["db_type"],
                "template_name": r["template_name"], "trigger_type": r["trigger_type"],
                "status": r["status"], "duration": r["duration"],
                "crit": s.get("crit", 0), "warn": s.get("warn", 0),
                "has_html": bool(r["html_file"]), "has_word": bool(r["word_file"]),
                "created_at": r["created_at"],
            })
        return jsonify(ok=True, data=out)

    @app.get("/api/reports/<int:rid>")
    @require_role("viewer")
    def get_report(rid):
        r = store.query_one("SELECT * FROM reports WHERE id=?", (rid,))
        if not r:
            return _deny("报告不存在", 404)
        try:
            result = json.loads(r["result_json"] or "{}")
        except Exception:
            result = {}
        interps = store.query_all(
            "SELECT a.id,a.content,a.created_at,c.name AS ai_name FROM ai_interpretations a "
            "LEFT JOIN ai_configs c ON c.id=a.ai_config_id WHERE a.report_id=? ORDER BY a.id DESC", (rid,))
        return jsonify(ok=True, data={
            "id": r["id"], "report_no": r["report_no"], "name": r["name"],
            "connection_name": r["connection_name"], "db_type": r["db_type"],
            "template_name": r["template_name"], "trigger_type": r["trigger_type"],
            "status": r["status"], "duration": r["duration"],
            "created_at": r["created_at"], "result": result,
            "interpretations": [dict(i) for i in interps],
        })

    @app.get("/api/reports/<int:rid>/html")
    @require_role("viewer")
    def report_html(rid):
        r = store.query_one("SELECT * FROM reports WHERE id=?", (rid,))
        if not r:
            return _deny("报告不存在", 404)
        if r["html_file"]:
            path = os.path.join(store.REPORT_DIR, r["html_file"])
            if os.path.isfile(path):
                with open(path, "r", encoding="utf-8") as fp:
                    return jsonify(ok=True, html=fp.read())
        try:
            result = json.loads(r["result_json"] or "{}")
        except Exception:
            result = {}
        html = reports.render_html(result, r["report_no"], "自动调度" if r["trigger_type"] == "auto" else "手动巡检")
        return jsonify(ok=True, html=html)

    @app.get("/api/reports/<int:rid>/download")
    @require_role("viewer")
    def download_report(rid):
        r = store.query_one("SELECT * FROM reports WHERE id=?", (rid,))
        if not r:
            return _deny("报告不存在", 404)
        fmt = request.args.get("format", "html")
        name = r["name"] or r["report_no"]
        if fmt == "word":
            if not r["word_file"]:
                result = json.loads(r["result_json"] or "{}")
                data = reports.render_word(result, r["report_no"], "自动调度" if r["trigger_type"] == "auto" else "手动巡检")
                return _send_bytes(data, name + ".docx",
                                   "application/vnd.openxmlformats-officedocument.wordprocessingml.document")
            return _send_file(r["word_file"], name + ".docx")
        if not r["html_file"]:
            result = json.loads(r["result_json"] or "{}")
            html = reports.render_html(result, r["report_no"], "自动调度" if r["trigger_type"] == "auto" else "手动巡检")
            return _send_bytes(html.encode("utf-8"), name + ".html", "text/html; charset=utf-8")
        return _send_file(r["html_file"], name + ".html")

    @app.delete("/api/reports/<int:rid>")
    @require_role("dba")
    def delete_report(rid):
        r = store.query_one("SELECT * FROM reports WHERE id=?", (rid,))
        if not r:
            return _deny("报告不存在", 404)
        for f in (r["html_file"], r["word_file"]):
            if f:
                try:
                    os.remove(os.path.join(store.REPORT_DIR, f))
                except Exception:
                    pass
        store.execute("DELETE FROM ai_interpretations WHERE report_id=?", (rid,))
        store.execute("DELETE FROM work_orders WHERE report_id=?", (rid,))
        store.execute("DELETE FROM reports WHERE id=?", (rid,))
        return jsonify(ok=True)

    @app.post("/api/reports/batch-delete")
    @require_role("dba")
    def batch_delete_reports():
        data = _body()
        ids = [int(x) for x in (data.get("ids") or []) if str(x).isdigit()]
        if not ids:
            return _deny("请选择要删除的报告", 400)
        rows = store.query_all(
            f"SELECT id, html_file, word_file FROM reports WHERE id IN ({','.join('?' for _ in ids)})", ids)
        for r in rows:
            for f in (r["html_file"], r["word_file"]):
                if f:
                    try:
                        os.remove(os.path.join(store.REPORT_DIR, f))
                    except Exception:
                        pass
            store.execute("DELETE FROM ai_interpretations WHERE report_id=?", (r["id"],))
            store.execute("DELETE FROM work_orders WHERE report_id=?", (r["id"],))
            store.execute("DELETE FROM reports WHERE id=?", (r["id"],))
        store.audit(g.user["id"], g.user["username"], "report_batch_delete", f"批量删除 {len(rows)} 份报告")
        return jsonify(ok=True, message=f"已删除 {len(rows)} 份报告")

    @app.get("/api/reports/export")
    @require_role("viewer")
    def export_reports():
        ids = [int(x) for x in request.args.get("ids", "").split(",") if x.strip().isdigit()]
        fmt = request.args.get("format", "html")
        if not ids:
            return _deny("未选择报告", 400)
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            for rid in ids:
                r = store.query_one("SELECT * FROM reports WHERE id=?", (rid,))
                if not r:
                    continue
                if fmt == "word" and r["word_file"]:
                    p = os.path.join(store.REPORT_DIR, r["word_file"])
                    if os.path.isfile(p):
                        zf.write(p, os.path.basename(p))
                elif r["html_file"]:
                    p = os.path.join(store.REPORT_DIR, r["html_file"])
                    if os.path.isfile(p):
                        zf.write(p, os.path.basename(p))
        buf.seek(0)
        return _send_bytes(buf.read(), f"dbcheck_reports_{store.now_stamp()}.zip", "application/zip")

    # ---------------- AI 配置与解读 ----------------
    @app.get("/api/ai-configs")
    @require_role("dba")
    def list_ai_configs():
        rows = store.query_all("SELECT * FROM ai_configs ORDER BY id")
        return jsonify(ok=True, data=[ai_mod.config_to_dict(r) for r in rows])

    @app.post("/api/ai-configs")
    @require_role("admin")
    def create_ai_config():
        data = _body()
        name = data.get("name") or ""
        if not name:
            return _deny("配置名称不能为空", 400)
        key = data.get("api_key") or ""
        aid = store.execute(
            "INSERT INTO ai_configs(name,provider,base_url,api_key_enc,model,temperature,system_prompt,enabled,created_at,updated_at) "
            "VALUES(?,?,?,?,?,?,?,?,?,?)",
            (name, data.get("provider") or "openai", data.get("base_url") or "",
             security.encrypt_text(key), data.get("model") or "",
             float(data.get("temperature", 0.3) or 0.3), data.get("system_prompt") or "",
             1 if data.get("enabled", 1) else 0, store.now(), store.now()),
        )
        store.audit(g.user["id"], g.user["username"], "ai_config_create", name)
        return jsonify(ok=True, id=aid)

    @app.put("/api/ai-configs/<int:aid>")
    @require_role("admin")
    def update_ai_config(aid):
        data = _body()
        row = store.query_one("SELECT * FROM ai_configs WHERE id=?", (aid,))
        if not row:
            return _deny("AI 配置不存在", 404)
        key = data.get("api_key")
        key_enc = security.encrypt_text(key) if key else row["api_key_enc"]
        store.execute(
            "UPDATE ai_configs SET name=?,provider=?,base_url=?,api_key_enc=?,model=?,temperature=?,system_prompt=?,enabled=?,updated_at=? WHERE id=?",
            (data.get("name", row["name"]), data.get("provider", row["provider"]),
             data.get("base_url", row["base_url"]), key_enc, data.get("model", row["model"]),
             float(data.get("temperature", row["temperature"] or 0.3) or 0.3),
             data.get("system_prompt", row["system_prompt"]),
             1 if data.get("enabled", 1) else 0, store.now(), aid),
        )
        return jsonify(ok=True)

    @app.delete("/api/ai-configs/<int:aid>")
    @require_role("admin")
    def delete_ai_config(aid):
        store.execute("DELETE FROM ai_configs WHERE id=?", (aid,))
        return jsonify(ok=True)

    @app.get("/api/interpretations")
    @require_role("viewer")
    def list_interpretations():
        rows = store.query_all(
            "SELECT a.id, a.report_id, a.content, a.created_at, a.ai_config_id, "
            "c.name AS ai_name, r.name AS report_name "
            "FROM ai_interpretations a LEFT JOIN ai_configs c ON c.id=a.ai_config_id "
            "LEFT JOIN reports r ON r.id=a.report_id ORDER BY a.id DESC LIMIT 100")
        return jsonify(ok=True, data=[dict(r) for r in rows])

    @app.post("/api/interpret")
    @require_role("dba")
    def interpret():
        data = _body()
        report_ids = data.get("report_ids") or []
        ai_config_id = data.get("ai_config_id")
        if not report_ids or not ai_config_id:
            return _deny("请选择报告与 AI 配置", 400)
        cfg = store.query_one("SELECT * FROM ai_configs WHERE id=?", (ai_config_id,))
        if not cfg:
            return _deny("AI 配置不存在", 404)
        reports_rows = [store.query_one("SELECT * FROM reports WHERE id=?", (rid,)) for rid in report_ids]
        reports_rows = [r for r in reports_rows if r]
        if not reports_rows:
            return _deny("未找到有效报告", 404)
        try:
            results = [json.loads(r["result_json"] or "{}") for r in reports_rows]
            if len(results) == 1:
                content = ai_mod.interpret_report(results[0], cfg)
            else:
                content = ai_mod.interpret_batch(results, cfg)
            # 保存到每份报告的解读
            for r in reports_rows:
                store.execute(
                    "INSERT INTO ai_interpretations(report_id,ai_config_id,content,created_at) VALUES(?,?,?,?)",
                    (r["id"], ai_config_id, content, store.now()))
            store.audit(g.user["id"], g.user["username"], "ai_interpret",
                        f"{len(reports_rows)} 份报告")
            return jsonify(ok=True, content=content)
        except Exception as exc:  # noqa: BLE001
            return jsonify(ok=False, message=str(exc)[:600]), 200

    # ---------------- 用户管理 ----------------
    @app.get("/api/users")
    @require_role("admin")
    def list_users():
        rows = store.query_all(
            "SELECT id,username,display_name,role,email,enabled,created_at,last_login_at FROM users ORDER BY id")
        return jsonify(ok=True, data=[dict(r) for r in rows])

    @app.post("/api/users")
    @require_role("admin")
    def create_user():
        data = _body()
        username = (data.get("username") or "").strip()
        password = data.get("password") or ""
        if not username or not password:
            return _deny("用户名与初始密码不能为空", 400)
        if len(password) < 6:
            return _deny("密码长度至少 6 位", 400)
        if store.query_one("SELECT id FROM users WHERE username=?", (username,)):
            return _deny("用户名已存在", 400)
        uid = store.execute(
            "INSERT INTO users(username,password_hash,display_name,role,email,enabled,created_at) VALUES(?,?,?,?,?,1,?)",
            (username, security.hash_password(password), data.get("display_name") or username,
             data.get("role") or "viewer", data.get("email") or "", store.now()),
        )
        store.audit(g.user["id"], g.user["username"], "user_create", username)
        return jsonify(ok=True, id=uid)

    @app.put("/api/users/<int:uid>")
    @require_role("admin")
    def update_user(uid):
        data = _body()
        u = store.query_one("SELECT * FROM users WHERE id=?", (uid,))
        if not u:
            return _deny("用户不存在", 404)
        if uid == 1 and data.get("role") not in (None, "admin"):
            return _deny("不能降级内置管理员", 400)
        pwd = data.get("password")
        if pwd and len(pwd) < 6:
            return _deny("密码长度至少 6 位", 400)
        pwd_hash = security.hash_password(pwd) if pwd else u["password_hash"]
        store.execute(
            "UPDATE users SET display_name=?,role=?,email=?,enabled=?,password_hash=? WHERE id=?",
            (data.get("display_name", u["display_name"]), data.get("role", u["role"]),
             data.get("email", u["email"]), 1 if data.get("enabled", u["enabled"]) else 0,
             pwd_hash, uid),
        )
        return jsonify(ok=True)

    @app.delete("/api/users/<int:uid>")
    @require_role("admin")
    def delete_user(uid):
        if uid == 1:
            return _deny("不能删除内置管理员", 400)
        store.execute("DELETE FROM users WHERE id=?", (uid,))
        return jsonify(ok=True)

    # ---------------- 系统设置 ----------------
    @app.get("/api/settings")
    @require_role("admin")
    def get_settings():
        data = store.get_all_settings()
        data.pop("smtp_pass_enc", None)
        return jsonify(ok=True, data=data)

    @app.put("/api/settings")
    @require_role("admin")
    def save_settings():
        data = _body()
        for k in ("smtp_host", "smtp_port", "smtp_user", "smtp_from", "alert_receivers",
                  "alert_on_crit", "alert_on_fail", "alert_on_warn", "report_retention_days",
                  "work_order_retention_days", "inspect_timeout", "parallel_limit",
                  "webhook_type", "webhook_url"):
            if k in data:
                store.set_setting(k, str(data[k]))
        if "default_output" in data:
            store.set_setting("default_output", json.dumps(data["default_output"], ensure_ascii=False))
        if data.get("smtp_pass"):
            store.set_setting("smtp_pass_enc", security.encrypt_text(data["smtp_pass"]))
        return jsonify(ok=True)

    @app.post("/api/settings/test-mail")
    @require_role("admin")
    def test_mail():
        data = _body()
        cfg = store.get_all_settings()
        to = [r.strip() for r in (data.get("to") or cfg.get("alert_receivers") or "").split(",") if r.strip()]
        if not to:
            return _deny("请填写测试收件人，或在系统设置中配置告警接收人", 400)
        ok, msg = notify.send_mail(
            "Bond-DBCheck 测试邮件",
            "<p>这是一封来自 <b>Bond-DBCheck 邦德智能巡检平台</b> 的测试邮件，收到即表示 SMTP 配置可用。</p>",
            to,
        )
        return jsonify(ok=ok, message=msg)

    @app.post("/api/settings/test-webhook")
    @require_role("admin")
    def test_webhook():
        ok, msg = notify.test_webhook()
        return jsonify(ok=ok, message=msg)


# =====================================================================
# 工具函数
# =====================================================================
def _user_public(u: dict) -> dict:
    return {
        "id": u["id"], "username": u["username"], "display_name": u["display_name"],
        "role": u["role"], "email": u["email"], "enabled": u["enabled"],
    }


def _tpl_public(t: dict) -> dict:
    try:
        output_formats = json.loads(t.get("output_formats") or '[]')
    except Exception:
        output_formats = []
    return {
        "id": t["id"], "name": t["name"], "db_type": t["db_type"],
        "description": t["description"], "status": t["status"],
        "report_title": t["report_title"], "watermark": t["watermark"],
        "output_formats": output_formats, "abnormal_only": t["abnormal_only"],
        "email_notify": t.get("email_notify", 0),
        "item_count": t.get("item_count", 0),
        "created_at": t["created_at"], "updated_at": t["updated_at"],
    }


def _send_file(filename: str, download_name: str):
    from flask import send_file
    return send_file(os.path.join(store.REPORT_DIR, filename), as_attachment=True,
                     download_name=download_name)


def _send_bytes(data: bytes, download_name: str, mimetype: str):
    from flask import Response
    return Response(data, mimetype=mimetype, headers={
        "Content-Disposition": f'attachment; filename="{download_name}"'})


def _next_run_time(cron: str) -> str:
    try:
        from croniter import croniter
        it = croniter(cron, datetime.now())
        return it.get_next(datetime).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return "—"


# =====================================================================
# 内存任务队列（手动巡检异步执行）
# =====================================================================
_jobs: dict[str, dict] = {}
import threading as _threading


def _new_job() -> str:
    job_id = f"j{int(datetime.now().timestamp() * 1000)}"
    _jobs[job_id] = {"status": "running", "progress": 0.0, "log": [], "reports": [], "error": ""}
    return job_id


def _start_job_thread(job_id: str, fn) -> None:
    _threading.Thread(target=fn, args=(job_id,), daemon=True).start()


def _run_inspect_job(job_id: str) -> None:
    j = _jobs[job_id]
    args = j["args"]

    def log(msg: str):
        j["log"].append(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")
        if len(j["log"]) > 500:
            j["log"] = j["log"][-500:]

    conns = args["conns"]
    total = len(conns)
    report_ids = []
    try:
        for i, conn in enumerate(conns):
            log(f"开始巡检 {conn['name']}（{conn['db_type']}）…")
            try:
                out = service.run_inspection_job(
                    conn, store.decrypt_password(conn), args["template"], args["items"],
                    args["output_formats"], args["trigger_type"], log_cb=log,
                    email_notify=bool(args["template"].get("email_notify")))
                report_ids.append(out["report_id"])
                j["reports"].append({
                    "report_id": out["report_id"], "report_no": out["report_no"],
                    "connection_name": conn["name"], "db_type": conn["db_type"],
                    "summary": out["result"]["summary"],
                })
            except Exception as exc:  # noqa: BLE001
                log(f"{conn['name']} 巡检失败：{exc}")
            j["progress"] = round((i + 1) / total, 3)
        j["status"] = "done"
        log("全部巡检完成。")
        _record_manual_run(args, f"成功（{len(report_ids)}/{total}）", report_ids)
    except Exception as exc:  # noqa: BLE001
        j["status"] = "error"
        j["error"] = str(exc)
        log(f"任务异常：{exc}")
        _record_manual_run(args, f"失败：{str(exc)[:200]}", report_ids)


def _record_manual_run(args: dict, status: str, report_ids: list) -> None:
    try:
        conn_names = [c.get("name") for c in args.get("conns", [])]
        store.execute(
            "INSERT INTO manual_runs(username,connection_names,template_name,status,detail,report_ids,created_at) "
            "VALUES(?,?,?,?,?,?,?)",
            (args.get("username") or "system", json.dumps(conn_names, ensure_ascii=False),
             args.get("template", {}).get("name") or "", status, status,
             json.dumps(report_ids, ensure_ascii=False), store.now()))
    except Exception:
        pass


def _run_single_schedule(sch: dict) -> None:
    get_scheduler()._run_schedule(sch)
