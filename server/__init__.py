"""DBCheck 数据库巡检平台 —— 后端包。

本包被 app.py 加载；app.py 会先把项目根目录与 libs/ 加入 sys.path，
因此这里的 import 依赖（flask / oracledb / pymysql / psycopg2 / croniter）在运行时可用。
"""
from __future__ import annotations

import os

SERVER_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(SERVER_DIR)
DATA_DIR = os.path.join(PROJECT_DIR, "data")
REPORT_DIR = os.path.join(DATA_DIR, "reports")
LIBS_DIR = os.path.join(PROJECT_DIR, "libs")
STATIC_DIR = os.path.join(PROJECT_DIR, "static")
DB_PATH = os.path.join(DATA_DIR, "dbcheck.db")

VERSION = "1.0.0"

ROLE_RANK = {"viewer": 0, "dba": 1, "admin": 2}

# 支持的数据库类型
DB_TYPES = ("oracle", "mysql", "pg")


def ensure_dirs() -> None:
    for d in (DATA_DIR, REPORT_DIR, STATIC_DIR):
        os.makedirs(d, exist_ok=True)


ensure_dirs()
