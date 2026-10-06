"""统一数据库驱动：Oracle / MySQL / PostgreSQL。

对外提供统一接口，屏蔽三方驱动差异：
    session = open_session(conn_row, password)   # 建立连接
    columns, rows = session.execute(sql)         # 执行只读查询，返回列名 + 行数据
    session.server_version()                     # 数据库版本
    session.close()

所有值在 execute 时统一序列化为 JSON 友好的类型（str/int/float/None）。
"""
from __future__ import annotations

import datetime
import decimal
from typing import Any

# 驱动在 app.py 启动时通过 libs/ 提供；此处延迟 import，避免模块加载失败影响其它功能。
_ORACLE_OK = True
_MYSQL_OK = True
_PG_OK = True


def _serialize(value: Any) -> Any:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value
    if isinstance(value, decimal.Decimal):
        return float(value)
    if isinstance(value, (datetime.datetime, datetime.date, datetime.time)):
        return value.isoformat(sep=" ") if isinstance(value, datetime.datetime) else str(value)
    if isinstance(value, (bytes, bytearray, memoryview)):
        try:
            return bytes(value).decode("utf-8")
        except Exception:
            return bytes(value).hex()
    return str(value)


def _columns_from_description(desc) -> list[str]:
    return [d[0] for d in desc]


class DatabaseSession:
    """统一数据库会话。"""

    def __init__(self, db_type: str, handle, close_fn):
        self.db_type = db_type
        self._h = handle
        self._close_fn = close_fn

    def execute(self, sql: str, params=None) -> tuple[list[str], list[list]]:
        raise NotImplementedError

    def server_version(self) -> str:
        return ""

    def close(self) -> None:
        try:
            self._close_fn()
        except Exception:
            pass


# ============================= Oracle =============================
class OracleSession(DatabaseSession):
    def execute(self, sql, params=None):
        cur = self._h.cursor()
        try:
            cur.execute(sql)
            cols = _columns_from_description(cur.description) if cur.description else []
            rows = [[_serialize(v) for v in r] for r in cur.fetchall()]
            return cols, rows
        finally:
            cur.close()

    def server_version(self) -> str:
        try:
            return str(self._h.version or "")
        except Exception:
            return ""


def _open_oracle(host, port, user, password, database, connect_mode, timeout=8):
    import oracledb

    kwargs = dict(user=user, password=password, host=host, port=int(port or 1521))
    if connect_mode == "sid":
        kwargs["sid"] = database
    else:
        kwargs["service_name"] = database
    handle = oracledb.connect(**kwargs)
    return OracleSession("oracle", handle, handle.close)


# ============================= MySQL =============================
class MySQLSession(DatabaseSession):
    def execute(self, sql, params=None):
        cur = self._h.cursor()
        try:
            cur.execute(sql)
            cols = _columns_from_description(cur.description) if cur.description else []
            rows = [[_serialize(v) for v in r] for r in cur.fetchall()]
            return cols, rows
        finally:
            cur.close()

    def server_version(self) -> str:
        try:
            return str(self._h.get_server_info() or "")
        except Exception:
            return ""


def _open_mysql(host, port, user, password, database, connect_mode="", timeout=8):
    import pymysql

    handle = pymysql.connect(
        host=host, port=int(port or 3306), user=user, password=password,
        database=database or None, connect_timeout=timeout, charset="utf8mb4",
    )
    return MySQLSession("mysql", handle, handle.close)


# ============================= PostgreSQL =============================
class PGSession(DatabaseSession):
    def execute(self, sql, params=None):
        cur = self._h.cursor()
        try:
            cur.execute(sql)
            cols = _columns_from_description(cur.description) if cur.description else []
            rows = [[_serialize(v) for v in r] for r in cur.fetchall()]
            return cols, rows
        finally:
            cur.close()

    def server_version(self) -> str:
        try:
            return "PostgreSQL " + str(self._h.server_version or "")
        except Exception:
            return ""


def _open_pg(host, port, user, password, database, connect_mode="", timeout=8):
    import psycopg2

    handle = psycopg2.connect(
        host=host, port=int(port or 5432), user=user, password=password,
        dbname=database or "postgres", connect_timeout=timeout,
    )
    handle.autocommit = True
    return PGSession("pg", handle, handle.close)


_OPENERS = {
    "oracle": _open_oracle,
    "mysql": _open_mysql,
    "pg": _open_pg,
}


def driver_available(db_type: str) -> bool:
    try:
        if db_type == "oracle":
            import oracledb  # noqa: F401
        elif db_type == "mysql":
            import pymysql  # noqa: F401
        elif db_type == "pg":
            import psycopg2  # noqa: F401
        return True
    except Exception:
        return False


def open_session(conn_row: dict, password: str) -> DatabaseSession:
    db_type = conn_row["db_type"]
    opener = _OPENERS.get(db_type)
    if opener is None:
        raise ValueError(f"不支持的数据库类型：{db_type}")
    if not driver_available(db_type):
        raise RuntimeError(f"缺少 {db_type} 数据库驱动，请先运行 install_deps.py 或安装对应驱动。")
    return opener(
        conn_row.get("host", ""),
        conn_row.get("port"),
        conn_row.get("username", ""),
        password,
        conn_row.get("database", ""),
        conn_row.get("connect_mode", ""),
    )


def test_connection(conn_row: dict, password: str) -> dict:
    """测试连接，返回 {ok, message, version}。"""
    try:
        session = open_session(conn_row, password)
        try:
            version = session.server_version()
            return {"ok": True, "message": f"连接成功（{version or '未知版本'}）", "version": version}
        finally:
            session.close()
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "message": _friendly_error(conn_row["db_type"], exc), "version": ""}


def _friendly_error(db_type: str, exc: Exception) -> str:
    msg = str(exc).strip().replace("\n", " ")
    if len(msg) > 300:
        msg = msg[:300] + "…"
    return f"连接失败：{msg}"
