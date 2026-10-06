"""DBCheck 自检：无需真实数据库，跑通「建库→登录→各接口→报告渲染」全链路。

用法：python selfcheck.py
"""
from __future__ import annotations

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)
_LIBS = os.path.join(HERE, "libs")
if os.path.isdir(_LIBS) and _LIBS not in sys.path:
    sys.path.insert(0, _LIBS)

PASS = 0
FAIL = 0


def check(name, cond, extra=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  [PASS] {name}")
    else:
        FAIL += 1
        print(f"  [FAIL] {name} {extra}")


def main() -> int:
    print("== 1. 导入后端模块 ==")
    from server import store, web
    from server import reports
    check("导入 store/web/reports", True)

    print("== 2. 初始化数据库（含种子） ==")
    store.init_db(seed=True)
    check("users 表有数据", store.query_one("SELECT COUNT(*) AS n FROM users")["n"] >= 3)
    check("templates 表有数据", store.query_one("SELECT COUNT(*) AS n FROM templates")["n"] >= 4)
    check("connections 表有数据", store.query_one("SELECT COUNT(*) AS n FROM connections")["n"] >= 4)
    check("reports 表有演示数据", store.query_one("SELECT COUNT(*) AS n FROM reports")["n"] >= 1)

    print("== 3. Flask 应用与认证 ==")
    app = web.create_app()
    client = app.test_client()

    r = client.post("/api/login", json={"username": "admin", "password": "admin123"})
    check("admin 登录", r.get_json().get("ok") is True)
    r = client.post("/api/login", json={"username": "admin", "password": "wrong"})
    check("错误密码被拒绝", r.get_json().get("ok") is False)

    print("== 4. 核心接口（admin） ==")
    for path in ("/api/dashboard", "/api/connections", "/api/templates", "/api/reports",
                 "/api/schedules", "/api/users", "/api/ai-configs", "/api/settings",
                 "/api/interpretations"):
        rr = client.get(path)
        check(f"GET {path}", rr.get_json().get("ok") is True, f"-> {rr.status_code}")

    # 报告详情 + HTML 渲染
    rep = client.get("/api/reports").get_json()["data"]
    check("存在报告", len(rep) > 0)
    rid = rep[0]["id"]
    h = client.get(f"/api/reports/{rid}/html")
    check("报告 HTML 渲染", h.get_json().get("ok") is True and "<html" in h.get_json().get("html", ""))

    print("== 5. Word 报告渲染 ==")
    result = json.loads(store.query_one("SELECT result_json FROM reports WHERE id=?", (rid,))["result_json"])
    try:
        b = reports.render_word(result, "RPT-TEST", "手动巡检")
        check("Word 生成 (docx)", b[:2] == b"PK" and len(b) > 1000, f"len={len(b)}")
    except Exception as e:
        check("Word 生成 (docx)", False, str(e))

    print("== 6. 权限控制 ==")
    client2 = app.test_client()
    client2.post("/api/login", json={"username": "viewer", "password": "viewer123"})
    r = client2.get("/api/dashboard")
    check("viewer 可看仪表盘", r.get_json().get("ok") is True)
    r = client2.get("/api/users")
    check("viewer 访问用户管理被拒(403)", r.status_code == 403, f"-> {r.status_code}")
    r = client2.post("/api/connections", json={"name": "x", "host": "1.2.3.4", "username": "u"})
    check("viewer 新建连接被拒(403)", r.status_code == 403, f"-> {r.status_code}")

    client3 = app.test_client()
    client3.post("/api/login", json={"username": "dba", "password": "dba123"})
    r = client3.post("/api/connections", json={"name": "T", "host": "1.1.1.1", "username": "u", "db_type": "mysql", "port": 3306})
    check("dba 可新建连接", r.get_json().get("ok") is True)
    r = client3.get("/api/users")
    check("dba 访问用户管理被拒(403)", r.status_code == 403, f"-> {r.status_code}")

    print("== 7. 连接测试（不可达，应优雅返回） ==")
    r = client3.post("/api/connections/test-raw", json={"db_type": "mysql", "host": "127.0.0.1", "port": 1, "username": "u", "password": "p", "database": ""})
    res = r.get_json()
    check("测试连接返回结构化结果", res.get("ok") is True and isinstance(res.get("result"), dict))

    print("== 8. SQL 试运行（不可达，应返回错误信息） ==")
    conns = client.get("/api/connections").get_json()["data"]
    cid = conns[0]["id"]
    r = client3.post("/api/sql-test", json={"connection_id": cid, "sql": "SELECT 1"})
    check("sql-test 返回(ok=False 或 ok=True 均可)", r.status_code in (200,) and "ok" in r.get_json())

    print(f"\n==== 自检完成：PASS {PASS} / FAIL {FAIL} ====")
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
