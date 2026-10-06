"""存储层：SQLite 平台数据（用户/连接/模板/巡检项/调度/报告/AI/设置/审计）。

所有函数每次打开独立连接（SQLite 打开开销极小），线程安全、无需跨请求共享游标。
密码字段只保存密文，明文由 web 层调用 security.decrypt_text 解出。
"""
from __future__ import annotations

import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime

from . import DB_PATH, DATA_DIR, REPORT_DIR, VERSION
from . import security

_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  display_name TEXT NOT NULL DEFAULT '',
  role TEXT NOT NULL DEFAULT 'viewer',
  email TEXT DEFAULT '',
  enabled INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL,
  last_login_at TEXT
);
CREATE TABLE IF NOT EXISTS connections (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  db_type TEXT NOT NULL,
  host TEXT NOT NULL,
  port INTEGER NOT NULL,
  database TEXT DEFAULT '',
  username TEXT DEFAULT '',
  password_enc TEXT DEFAULT '',
  connect_mode TEXT DEFAULT 'service',
  env TEXT DEFAULT '',
  extra TEXT DEFAULT '{}',
  remark TEXT DEFAULT '',
  enabled INTEGER NOT NULL DEFAULT 1,
  created_by INTEGER,
  created_at TEXT,
  updated_at TEXT,
  last_test_at TEXT,
  last_test_ok INTEGER,
  last_test_msg TEXT
);
CREATE TABLE IF NOT EXISTS templates (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  db_type TEXT NOT NULL,
  description TEXT DEFAULT '',
  status TEXT NOT NULL DEFAULT 'enabled',
  report_title TEXT DEFAULT '数据库巡检报告',
  watermark TEXT DEFAULT '',
  output_formats TEXT DEFAULT '["html","word"]',
  abnormal_only INTEGER NOT NULL DEFAULT 0,
  email_notify INTEGER NOT NULL DEFAULT 0,
  created_by INTEGER,
  created_at TEXT,
  updated_at TEXT
);
CREATE TABLE IF NOT EXISTS template_items (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  template_id INTEGER NOT NULL,
  category TEXT NOT NULL,
  item_name TEXT NOT NULL,
  sql_text TEXT NOT NULL,
  eval_mode TEXT NOT NULL DEFAULT 'scalar',
  metric_column TEXT DEFAULT '',
  warn_op TEXT DEFAULT '',
  warn_value REAL,
  crit_op TEXT DEFAULT '',
  crit_value REAL,
  value_format TEXT DEFAULT 'number',
  threshold_desc TEXT DEFAULT '',
  sort_order INTEGER NOT NULL DEFAULT 0,
  enabled INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS schedules (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1,
  connection_ids TEXT DEFAULT '[]',
  template_id INTEGER,
  cron TEXT NOT NULL,
  output_formats TEXT DEFAULT '["html","word"]',
  max_retries INTEGER NOT NULL DEFAULT 0,
  retry_interval_min INTEGER NOT NULL DEFAULT 10,
  created_by INTEGER,
  created_at TEXT,
  last_run_at TEXT,
  last_run_status TEXT,
  last_run_report_id INTEGER
);
CREATE TABLE IF NOT EXISTS reports (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  report_no TEXT NOT NULL,
  name TEXT NOT NULL,
  connection_id INTEGER,
  connection_name TEXT,
  db_type TEXT,
  template_id INTEGER,
  template_name TEXT,
  trigger_type TEXT NOT NULL DEFAULT 'manual',
  status TEXT NOT NULL DEFAULT 'success',
  duration REAL DEFAULT 0,
  summary TEXT DEFAULT '{}',
  result_json TEXT DEFAULT '{}',
  html_file TEXT DEFAULT '',
  word_file TEXT DEFAULT '',
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS ai_configs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  provider TEXT DEFAULT 'openai',
  base_url TEXT DEFAULT '',
  api_key_enc TEXT DEFAULT '',
  model TEXT DEFAULT '',
  temperature REAL DEFAULT 0.3,
  system_prompt TEXT DEFAULT '',
  enabled INTEGER NOT NULL DEFAULT 1,
  created_at TEXT,
  updated_at TEXT
);
CREATE TABLE IF NOT EXISTS ai_interpretations (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  report_id INTEGER NOT NULL,
  ai_config_id INTEGER,
  content TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value TEXT
);
CREATE TABLE IF NOT EXISTS audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER,
  username TEXT,
  action TEXT,
  detail TEXT,
  created_at TEXT
);
CREATE TABLE IF NOT EXISTS schedule_runs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  schedule_id INTEGER,
  schedule_name TEXT,
  run_at TEXT,
  status TEXT,
  detail TEXT,
  report_ids TEXT DEFAULT '[]',
  created_at TEXT
);
CREATE TABLE IF NOT EXISTS work_orders (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  report_id INTEGER,
  report_no TEXT,
  connection_name TEXT,
  db_type TEXT,
  category TEXT,
  item_name TEXT,
  severity TEXT,
  value TEXT,
  threshold_desc TEXT,
  status TEXT NOT NULL DEFAULT 'open',
  created_at TEXT NOT NULL,
  closed_at TEXT,
  closed_by INTEGER
);
CREATE TABLE IF NOT EXISTS manual_runs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT,
  connection_names TEXT DEFAULT '[]',
  template_name TEXT,
  status TEXT,
  detail TEXT,
  report_ids TEXT DEFAULT '[]',
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sql_templates (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  db_type TEXT NOT NULL,
  name TEXT NOT NULL,
  metric TEXT DEFAULT '',
  sql_text TEXT NOT NULL,
  threshold_desc TEXT DEFAULT '',
  created_at TEXT
);
"""


def now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def now_stamp() -> str:
    return datetime.now().strftime("%Y%m%d%H%M%S")


@contextmanager
def db():
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def query_all(sql: str, params=()) -> list[dict]:
    with db() as c:
        return [dict(r) for r in c.execute(sql, params).fetchall()]


def query_one(sql: str, params=()) -> dict | None:
    with db() as c:
        r = c.execute(sql, params).fetchone()
        return dict(r) if r else None


def execute(sql: str, params=()) -> int:
    """执行写操作，返回 lastrowid。"""
    with db() as c:
        cur = c.execute(sql, params)
        return cur.lastrowid


# =====================================================================
# 通用：连接口令解密 / 设置读写 / 审计
# =====================================================================
def decrypt_password(row: dict) -> str:
    return security.decrypt_text(row.get("password_enc") or "")


def get_setting(key: str, default: str = "") -> str:
    r = query_one("SELECT value FROM settings WHERE key=?", (key,))
    return r["value"] if r else default


def set_setting(key: str, value: str) -> None:
    execute(
        "INSERT INTO settings(key,value) VALUES(?,?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (key, value),
    )


def get_all_settings() -> dict:
    rows = query_all("SELECT key,value FROM settings")
    return {r["key"]: r["value"] for r in rows}


def audit(user_id, username, action, detail=""):
    try:
        execute(
            "INSERT INTO audit_log(user_id,username,action,detail,created_at) VALUES(?,?,?,?,?)",
            (user_id, username, action, detail[:2000], now()),
        )
    except Exception:
        pass


# =====================================================================
# 初始化：建表 + 种子
# =====================================================================
def init_db(seed: bool = True) -> None:
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    with db() as c:
        c.executescript(_SCHEMA)
    _migrate()
    if seed:
        _seed()


def _migrate() -> None:
    """对旧版本数据库做增量迁移（幂等）。"""
    def has_column(table: str, col: str) -> bool:
        cols = query_all(f"PRAGMA table_info({table})")
        return any(c["name"] == col for c in cols)

    if not has_column("templates", "email_notify"):
        try:
            execute("ALTER TABLE templates ADD COLUMN email_notify INTEGER NOT NULL DEFAULT 0")
        except Exception:
            pass

    if not has_column("schedules", "max_retries"):
        try:
            execute("ALTER TABLE schedules ADD COLUMN max_retries INTEGER NOT NULL DEFAULT 0")
        except Exception:
            pass
    if not has_column("schedules", "retry_interval_min"):
        try:
            execute("ALTER TABLE schedules ADD COLUMN retry_interval_min INTEGER NOT NULL DEFAULT 10")
        except Exception:
            pass

    # 补齐后续版本新增的默认设置
    if not query_one("SELECT key FROM settings WHERE key=?", ("work_order_retention_days",)):
        set_setting("work_order_retention_days", "90")

    # 补齐 SQL 模板库（老库迁移）
    if not query_one("SELECT id FROM sql_templates LIMIT 1"):
        _seed_sql_templates()

    if not has_column("connections", "env"):
        try:
            execute("ALTER TABLE connections ADD COLUMN env TEXT DEFAULT ''")
        except Exception:
            pass


def _seed() -> None:
    if query_one("SELECT id FROM users LIMIT 1"):
        return  # 已初始化

    # ---- 用户 ----
    users = [
        ("admin", "admin123", "系统管理员", "admin", "admin@example.com"),
        ("dba", "dba123", "数据库运维", "dba", "dba@example.com"),
        ("viewer", "viewer123", "只读访客", "viewer", "viewer@example.com"),
    ]
    for username, pwd, display, role, email in users:
        execute(
            "INSERT INTO users(username,password_hash,display_name,role,email,enabled,created_at) "
            "VALUES(?,?,?,?,?,1,?)",
            (username, security.hash_password(pwd), display, role, email, now()),
        )

    # ---- AI 配置（示例，未启用）----
    execute(
        "INSERT INTO ai_configs(name,provider,base_url,api_key_enc,model,temperature,system_prompt,enabled,created_at,updated_at) "
        "VALUES(?,?,?,?,?,?,?,0,?,?)",
        (
            "DeepSeek 示例", "openai", "https://api.deepseek.com/v1", "", "deepseek-chat", 0.3,
            "你是一名资深数据库运维专家（DBA）。请根据巡检报告数据，用中文给出专业、可执行的解读与处置建议。",
            now(), now(),
        ),
    )

    # ---- 设置 ----
    defaults = {
        "smtp_host": "smtp.company.com",
        "smtp_port": "465",
        "smtp_user": "",
        "smtp_pass_enc": "",
        "smtp_from": "dbcheck@company.com",
        "alert_receivers": "",
        "alert_on_crit": "1",
        "alert_on_fail": "1",
        "alert_on_warn": "0",
        "default_output": '["html","word"]',
        "report_retention_days": "180",
        "work_order_retention_days": "90",
        "report_dir": "",
        "inspect_timeout": "300",
        "parallel_limit": "3",
        "webhook_type": "",
        "webhook_url": "",
    }
    for k, v in defaults.items():
        set_setting(k, v)

    # ---- 连接（示例）----
    conns = [
        ("ORCL-PROD-01", "oracle", "10.20.1.11", 1521, "ORCLPDB", "inspec", "Oracle123", "service", "生产", "生产核心库"),
        ("MYSQL-ORDER-01", "mysql", "10.20.2.21", 3306, "order_db", "inspec", "Inspec123", "db", "生产", "订单库"),
        ("PG-REPORT-01", "pg", "10.20.3.31", 5432, "report_db", "inspec", "Inspec123", "db", "测试", "报表库"),
        ("PG-LOG-01", "pg", "10.20.3.32", 5432, "log_db", "inspec", "Inspec123", "db", "测试", "日志库"),
    ]
    for name, db_type, host, port, database, user, pwd, mode, env, remark in conns:
        execute(
            "INSERT INTO connections(name,db_type,host,port,database,username,password_enc,connect_mode,env,remark,enabled,created_at,updated_at) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,1,?,?)",
            (name, db_type, host, port, database, user, security.encrypt_text(pwd), mode, env, remark, now(), now()),
        )

    # ---- 模板 + 巡检项 ----
    _seed_templates()

    # ---- SQL 模板库 ----
    _seed_sql_templates()

    # ---- 调度（示例，默认停用）----
    execute(
        "INSERT INTO schedules(name,enabled,connection_ids,template_id,cron,output_formats,created_by,created_at) VALUES(?,?,?,?,?,?,?,?)",
        ("生产 Oracle 每日巡检", 0, '["*"]', 1, "0 0 8 * * *", '["html","word"]', 1, now()),
    )
    execute(
        "INSERT INTO schedules(name,enabled,connection_ids,template_id,cron,output_formats,created_by,created_at) VALUES(?,?,?,?,?,?,?,?)",
        ("MySQL 每 6 小时巡检", 0, '["*"]', 2, "0 0 */6 * * *", '["html"]', 1, now()),
    )

    # ---- 示例报告（mock 数据，便于演示仪表盘/列表/预览）----
    _seed_demo_reports()


def _seed_sql_templates() -> None:
    tpls = [
        # Oracle
        ("oracle", "数据库版本", "", "SELECT banner FROM v$version WHERE banner LIKE 'Oracle%' AND ROWNUM=1", ""),
        ("oracle", "实例启动时间", "DAYS_UP", "SELECT startup_time, ROUND((SYSDATE-startup_time),1) AS days_up FROM v$instance", "运行 > 180 天 → 提示重启"),
        ("oracle", "会话数", "SESSIONS", "SELECT COUNT(*) AS sessions FROM v$session WHERE type='USER'", ""),
        ("oracle", "缓冲区命中率", "HIT_RATIO", "SELECT ROUND((1-(phy.value/(cur.value+con.value)))*100,2) AS hit_ratio FROM v$sysstat phy, v$sysstat cur, v$sysstat con WHERE phy.name='physical reads' AND cur.name='db block gets' AND con.name='consistent gets'", "<95% 警告"),
        ("oracle", "表空间使用率", "USED_PERCENT", "SELECT tablespace_name, ROUND(used_percent,2) AS used_percent FROM dba_tablespace_usage_metrics ORDER BY used_percent DESC", ">85% 警告"),
        ("oracle", "阻塞会话", "", "SELECT blocking_session, sid, seconds_in_wait FROM v$session WHERE blocking_session IS NOT NULL", "存在即告警"),
        ("oracle", "归档日志使用率", "USED_PCT", "SELECT ROUND(space_used*100/space_limit,2) AS used_pct FROM v$recovery_file_dest WHERE space_limit > 0", ">80% 警告"),
        ("oracle", "默认口令账号", "", "SELECT username FROM dba_users_with_defpwd", "存在即严重"),
        ("oracle", "无效对象", "", "SELECT owner, object_name, object_type FROM dba_objects WHERE status='INVALID'", ""),
        ("oracle", "TOP SQL（按逻辑读）", "", "SELECT * FROM (SELECT sql_id, buffer_gets, executions FROM v$sql ORDER BY buffer_gets DESC) WHERE ROWNUM<=10", ""),
        ("oracle", "TOP 等待事件", "", "SELECT * FROM (SELECT event, total_waits, time_waited FROM v$system_event WHERE event NOT LIKE '%null%' ORDER BY time_waited DESC) WHERE ROWNUM<=5", ""),
        # MySQL
        ("mysql", "数据库版本", "", "SELECT VERSION() AS version", ""),
        ("mysql", "连接数使用率", "USED_PCT", "SELECT ROUND((SELECT VARIABLE_VALUE FROM performance_schema.global_status WHERE VARIABLE_NAME='Threads_connected')*100/@@max_connections,2) AS used_pct", ">80% 警告"),
        ("mysql", "缓冲池命中率", "HIT_RATIO", "SELECT ROUND((1 - (SELECT VARIABLE_VALUE FROM performance_schema.global_status WHERE VARIABLE_NAME='Innodb_buffer_pool_reads') / (SELECT VARIABLE_VALUE FROM performance_schema.global_status WHERE VARIABLE_NAME='Innodb_buffer_pool_read_requests'))*100, 2) AS hit_ratio", "<95% 警告"),
        ("mysql", "慢查询数量", "SLOW_QUERIES", "SELECT VARIABLE_VALUE AS slow_queries FROM performance_schema.global_status WHERE VARIABLE_NAME='Slow_queries'", ""),
        ("mysql", "锁等待", "", "SELECT * FROM information_schema.innodb_lock_waits LIMIT 50", "存在即告警"),
        ("mysql", "长事务", "SECS", "SELECT trx_id, TIMESTAMPDIFF(SECOND, trx_started, NOW()) AS secs FROM information_schema.innodb_trx WHERE TIMESTAMPDIFF(SECOND, trx_started, NOW()) > 60", "存在即告警"),
        ("mysql", "主从复制状态", "", "SHOW SLAVE STATUS", ""),
        ("mysql", "大表 TOP15", "SIZE_MB", "SELECT table_schema, table_name, ROUND((data_length+index_length)/1024/1024,2) AS size_mb FROM information_schema.tables ORDER BY size_mb DESC LIMIT 15", ""),
        # PostgreSQL
        ("pg", "数据库版本", "", "SELECT version() AS version", ""),
        ("pg", "连接数使用率", "USED_PCT", "SELECT ROUND(count(*)*100.0/current_setting('max_connections')::int,2) AS used_pct FROM pg_stat_activity", ">80% 警告"),
        ("pg", "缓存命中率", "HIT_RATIO", "SELECT ROUND((blks_hit::numeric / NULLIF(blks_hit + blks_read, 0) * 100), 2) AS hit_ratio FROM pg_stat_database WHERE datname = current_database()", "<95% 警告"),
        ("pg", "长事务", "", "SELECT pid, now() - xact_start AS duration FROM pg_stat_activity WHERE xact_start IS NOT NULL AND now() - xact_start > interval '5 minutes' ORDER BY duration DESC", "存在即告警"),
        ("pg", "死锁数量", "DEADLOCKS", "SELECT deadlocks FROM pg_stat_database WHERE datname = current_database()", ""),
        ("pg", "数据库大小", "", "SELECT datname, pg_size_pretty(pg_database_size(datname)) AS size FROM pg_database ORDER BY pg_database_size(datname) DESC", ""),
        ("pg", "复制延迟", "", "SELECT client_addr, state, write_lag FROM pg_stat_replication", ""),
        ("pg", "表膨胀 TOP15", "", "SELECT schemaname||'.'||relname AS tbl, pg_size_pretty(pg_total_relation_size(relid)) AS total_size FROM pg_stat_user_tables ORDER BY pg_total_relation_size(relid) DESC LIMIT 15", ""),
        ("pg", "未自动清理表", "", "SELECT schemaname||'.'||relname AS tbl, last_autovacuum FROM pg_stat_user_tables WHERE last_autovacuum IS NULL OR last_autovacuum < now() - interval '7 days'", "存在即告警"),
    ]
    for db_type, name, metric, sql, threshold in tpls:
        execute(
            "INSERT INTO sql_templates(db_type,name,metric,sql_text,threshold_desc,created_at) VALUES(?,?,?,?,?,?)",
            (db_type, name, metric, sql, threshold, now()))


def _seed_templates() -> None:
    tpl_specs = [
        {
            "name": "Oracle 标准巡检模板", "db_type": "oracle",
            "description": "适用于 Oracle 11g/12c/19c 单实例与 RAC 环境的标准日常巡检，覆盖基础信息、性能、空间、会话锁、备份、高可用、安全七大维度。",
            "report_title": "数据库巡检报告", "watermark": "内部资料 · 请勿外传",
            "items": [
                ("基础信息", "数据库版本", "SELECT banner FROM v$version WHERE banner LIKE 'Oracle%' AND ROWNUM=1", "info", "", "", None, "", None, "text", "仅采集展示"),
                ("基础信息", "实例名称", "SELECT instance_name, host_name, status FROM v$instance", "info", "", "", None, "", None, "text", "仅采集展示"),
                ("基础信息", "实例启动时间", "SELECT startup_time, SYSDATE, ROUND((SYSDATE-startup_time)*24*60*60/86400,1) AS days_up FROM v$instance", "scalar", "DAYS_UP", "gt", 180, "", None, "number", "运行 > 180 天 → 提示重启"),
                ("基础信息", "数据库字符集", "SELECT value FROM nls_database_parameters WHERE parameter='NLS_CHARACTERSET'", "info", "", "", None, "", None, "text", "仅采集展示"),
                ("基础信息", "归档模式", "SELECT log_mode FROM v$database", "info", "", "", None, "", None, "text", "仅采集展示"),
                ("性能指标", "会话数使用率", "SELECT ROUND(COUNT(*)*100/(SELECT value FROM v$parameter WHERE name='sessions'),2) AS used_pct FROM v$session", "scalar", "USED_PCT", "gt", 80, "gt", 95, "percent", ">80% 警告 / >95% 严重"),
                ("性能指标", "缓冲区命中率", "SELECT ROUND((1-(phy.value/(cur.value+con.value)))*100,2) AS hit_ratio FROM v$sysstat phy, v$sysstat cur, v$sysstat con WHERE phy.name='physical reads' AND cur.name='db block gets' AND con.name='consistent gets'", "scalar", "HIT_RATIO", "lt", 95, "lt", 90, "percent", "<95% 警告 / <90% 严重"),
                ("性能指标", "共享池空闲率", "SELECT ROUND(free.bytes*100/pool.bytes,2) AS free_pct FROM v$sgastat free, v$sgastat pool WHERE free.name='free memory' AND free.pool='shared pool' AND pool.name='shared pool' AND pool.pool='shared pool'", "scalar", "FREE_PCT", "lt", 10, "lt", 5, "percent", "<10% 警告 / <5% 严重"),
                ("性能指标", "TOP5 等待事件", "SELECT * FROM (SELECT event, total_waits, time_waited FROM v$system_event WHERE event NOT LIKE '%null%' ORDER BY time_waited DESC) WHERE ROWNUM<=5", "info", "", "", None, "", None, "text", "仅采集展示"),
                ("空间容量", "表空间使用率", "SELECT tablespace_name, ROUND(used_percent,2) AS used_percent FROM dba_tablespace_usage_metrics ORDER BY used_percent DESC", "scalar", "USED_PERCENT", "gt", 85, "gt", 95, "percent", ">85% 警告 / >95% 严重"),
                ("空间容量", "ASM 磁盘组容量", "SELECT name, total_mb, free_mb, ROUND(free_mb*100/total_mb,2) AS free_pct FROM v$asm_diskgroup", "scalar", "FREE_PCT", "lt", 20, "lt", 10, "percent", "剩余 <20% 警告 / <10% 严重"),
                ("会话与锁", "阻塞会话检测", "SELECT blocking_session, sid, seconds_in_wait FROM v$session WHERE blocking_session IS NOT NULL", "rows", "", "gt", 0, "gt", 5, "number", "存在阻塞即警告 / >5 个严重"),
                ("会话与锁", "长时间运行 SQL", "SELECT username, sid, ROUND(last_call_et/60,1) AS minutes FROM v$session WHERE status='ACTIVE' AND last_call_et > 3600", "rows", "", "gt", 0, "", None, "number", "存在即警告"),
                ("备份与日志", "归档日志空间使用率", "SELECT ROUND(space_used*100/space_limit,2) AS used_pct FROM v$recovery_file_dest WHERE space_limit > 0", "scalar", "USED_PCT", "gt", 80, "gt", 95, "percent", ">80% 警告 / >95% 严重"),
                ("备份与日志", "最近 RMAN 备份", "SELECT MAX(completion_time) AS last_backup FROM v$backup_set", "info", "", "", None, "", None, "text", "仅采集展示"),
                ("高可用", "DataGuard 同步延迟", "SELECT name, value, time_computed FROM v$dataguard_stats WHERE name IN ('apply lag','transport lag')", "info", "", "", None, "", None, "text", "仅采集展示"),
                ("安全配置", "默认口令账号", "SELECT username, account_status FROM dba_users_with_defpwd", "exists", "", "", None, "", None, "number", "存在即严重"),
                ("安全配置", "密码过期策略", "SELECT profile, limit FROM dba_profiles WHERE resource_name='PASSWORD_LIFE_TIME' AND profile='DEFAULT'", "info", "", "", None, "", None, "text", "仅采集展示"),
            ],
        },
        {
            "name": "MySQL 基础巡检模板", "db_type": "mysql",
            "description": "MySQL 5.7/8.0 日常基础巡检：版本、连接、缓存、复制、慢查询、空间等。",
            "report_title": "MySQL 巡检报告", "watermark": "内部资料 · 请勿外传",
            "items": [
                ("基础信息", "数据库版本", "SELECT VERSION() AS version", "info", "", "", None, "", None, "text", "仅采集展示"),
                ("基础信息", "运行时长", "SELECT VARIABLE_VALUE AS uptime_sec FROM performance_schema.global_status WHERE VARIABLE_NAME='Uptime'", "info", "", "", None, "", None, "text", "仅采集展示"),
                ("连接指标", "当前连接数", "SELECT VARIABLE_VALUE AS threads_connected FROM performance_schema.global_status WHERE VARIABLE_NAME='Threads_connected'", "info", "", "", None, "", None, "text", "仅采集展示"),
                ("连接指标", "连接数使用率", "SELECT ROUND(@@max_connections,0) AS max_conns", "info", "", "", None, "", None, "text", "仅采集展示"),
                ("缓存指标", "缓冲池命中率", "SELECT ROUND((1 - (SELECT VARIABLE_VALUE FROM performance_schema.global_status WHERE VARIABLE_NAME='Innodb_buffer_pool_reads') / (SELECT VARIABLE_VALUE FROM performance_schema.global_status WHERE VARIABLE_NAME='Innodb_buffer_pool_read_requests'))*100, 2) AS hit_ratio", "scalar", "HIT_RATIO", "lt", 95, "lt", 90, "percent", "<95% 警告 / <90% 严重"),
                ("复制状态", "主从复制状态", "SHOW SLAVE STATUS", "info", "", "", None, "", None, "text", "仅采集展示"),
                ("慢查询", "慢查询数量", "SELECT VARIABLE_VALUE AS slow_queries FROM performance_schema.global_status WHERE VARIABLE_NAME='Slow_queries'", "info", "", "", None, "", None, "text", "仅采集展示"),
                ("空间容量", "数据库大小", "SELECT table_schema AS db_name, ROUND(SUM(data_length+index_length)/1024/1024,2) AS size_mb FROM information_schema.tables GROUP BY table_schema ORDER BY size_mb DESC", "info", "", "", None, "", None, "text", "仅采集展示"),
                ("空间容量", "表空间使用率", "SELECT table_schema, table_name, ROUND((data_length+index_length)/1024/1024,2) AS size_mb FROM information_schema.tables ORDER BY size_mb DESC LIMIT 15", "info", "", "", None, "", None, "text", "TOP15 大表"),
                ("锁等待", "当前锁等待", "SELECT * FROM information_schema.innodb_lock_waits LIMIT 50", "rows", "", "gt", 0, "", None, "number", "存在即警告"),
                ("长事务", "长事务列表", "SELECT trx_id, trx_started, TIMESTAMPDIFF(SECOND, trx_started, NOW()) AS secs FROM information_schema.innodb_trx WHERE TIMESTAMPDIFF(SECOND, trx_started, NOW()) > 60", "rows", "", "gt", 0, "", None, "number", "存在即警告"),
            ],
        },
        {
            "name": "PostgreSQL 高可用巡检模板", "db_type": "pg",
            "description": "PostgreSQL 12+ 巡检：版本、连接、复制、事务、死锁、表膨胀、空间等。",
            "report_title": "PostgreSQL 巡检报告", "watermark": "内部资料 · 请勿外传",
            "items": [
                ("基础信息", "数据库版本", "SELECT version() AS version", "info", "", "", None, "", None, "text", "仅采集展示"),
                ("基础信息", "启动时间", "SELECT pg_postmaster_start_time() AS started_at, now() - pg_postmaster_start_time() AS uptime", "info", "", "", None, "", None, "text", "仅采集展示"),
                ("连接指标", "当前连接数", "SELECT count(*) AS conns FROM pg_stat_activity", "info", "", "", None, "", None, "text", "仅采集展示"),
                ("连接指标", "连接数使用率", "SELECT ROUND(count(*)*100.0/current_setting('max_connections')::int,2) AS used_pct FROM pg_stat_activity", "scalar", "USED_PCT", "gt", 80, "gt", 95, "percent", ">80% 警告 / >95% 严重"),
                ("复制状态", "复制延迟", "SELECT client_addr, state, COALESCE(write_lag, '0'::interval) AS write_lag FROM pg_stat_replication", "info", "", "", None, "", None, "text", "仅采集展示"),
                ("事务与锁", "长事务", "SELECT pid, now() - xact_start AS duration, state FROM pg_stat_activity WHERE xact_start IS NOT NULL AND now() - xact_start > interval '5 minutes' ORDER BY duration DESC", "rows", "", "gt", 0, "", None, "number", "存在即警告"),
                ("事务与锁", "死锁数量", "SELECT deadlocks AS deadlocks FROM pg_stat_database WHERE datname = current_database()", "info", "", "", None, "", None, "text", "仅采集展示"),
                ("缓存命中", "缓存命中率", "SELECT ROUND((blks_hit::numeric / NULLIF(blks_hit + blks_read, 0) * 100), 2) AS hit_ratio FROM pg_stat_database WHERE datname = current_database()", "scalar", "HIT_RATIO", "lt", 95, "lt", 90, "percent", "<95% 警告 / <90% 严重"),
                ("空间容量", "数据库大小", "SELECT pg_database.datname, pg_size_pretty(pg_database_size(pg_database.datname)) AS size FROM pg_database ORDER BY pg_database_size(pg_database.datname) DESC", "info", "", "", None, "", None, "text", "仅采集展示"),
                ("空间容量", "表膨胀 TOP", "SELECT schemaname||'.'||relname AS table_name, pg_size_pretty(pg_total_relation_size(relid)) AS total_size FROM pg_stat_user_tables ORDER BY pg_total_relation_size(relid) DESC LIMIT 15", "info", "", "", None, "", None, "text", "TOP15 大表"),
                ("自动清理", "未自动清理表", "SELECT schemaname||'.'||relname AS tbl, last_autovacuum, last_autoanalyze FROM pg_stat_user_tables WHERE last_autovacuum IS NULL OR last_autovacuum < now() - interval '7 days'", "rows", "", "gt", 0, "", None, "number", "存在即警告"),
            ],
        },
        {
            "name": "Oracle 深度性能巡检模板", "db_type": "oracle",
            "description": "面向 Oracle 深度性能诊断：AWR、SQL 性能、等待、资源使用等（草稿）。",
            "report_title": "Oracle 深度性能巡检报告", "watermark": "内部资料 · 请勿外传",
            "status": "draft",
            "items": [
                ("性能分析", "Top SQL 按逻辑读", "SELECT * FROM (SELECT sql_id, buffer_gets, executions, ROUND(buffer_gets/DECODE(executions,0,1,executions),0) AS gets_per_exec FROM v$sql ORDER BY buffer_gets DESC) WHERE ROWNUM<=10", "info", "", "", None, "", None, "text", "仅采集展示"),
                ("性能分析", "Top SQL 按 CPU", "SELECT * FROM (SELECT sql_id, cpu_time, executions FROM v$sql ORDER BY cpu_time DESC) WHERE ROWNUM<=10", "info", "", "", None, "", None, "text", "仅采集展示"),
                ("资源使用", "SGA/PGA 使用率", "SELECT ROUND((SELECT SUM(bytes) FROM v$sgastat WHERE name NOT IN ('free memory'))*100/(SELECT value FROM v$parameter WHERE name='sga_max_size'),2) AS sga_pct FROM dual", "scalar", "SGA_PCT", "gt", 90, "", None, "percent", ">90% 警告"),
            ],
        },
    ]

    for spec in tpl_specs:
        status = spec.get("status", "enabled")
        tpl_id = execute(
            "INSERT INTO templates(name,db_type,description,status,report_title,watermark,output_formats,abnormal_only,created_by,created_at,updated_at) "
            "VALUES(?,?,?,?,?,?,?,0,1,?,?)",
            (spec["name"], spec["db_type"], spec["description"], status,
             spec["report_title"], spec["watermark"], '["html","word"]', now(), now()),
        )
        for i, it in enumerate(spec["items"]):
            category, item_name, sql, eval_mode, metric, warn_op, warn_v, crit_op, crit_v, fmt, tdesc = it
            execute(
                "INSERT INTO template_items(template_id,category,item_name,sql_text,eval_mode,metric_column,warn_op,warn_value,crit_op,crit_value,value_format,threshold_desc,sort_order,enabled) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,1)",
                (tpl_id, category, item_name, sql, eval_mode, metric, warn_op, warn_v, crit_op, crit_v, fmt, tdesc, i),
            )


def _mock_result(db_type: str, db_name: str, host: str, tpl_name: str, warn: int, crit: int):
    """构造一份演示巡检结果，结构与 engine.run 输出一致。"""
    def mk_cat(cat_name, items):
        return {"name": cat_name, "items": items}

    def mk_item(name, status, value, tdesc="", columns=None, rows=None):
        return {
            "name": name, "status": status, "value": value, "threshold_desc": tdesc,
            "columns": columns or ["巡检项", "巡检结果"],
            "rows": rows or [[name, value]],
        }

    categories = [
        mk_cat("基础信息", [
            mk_item("数据库版本", "normal", f"{db_type.upper()} Enterprise Edition"),
            mk_item("实例名称", "normal", db_name),
            mk_item("启动时间", "warn" if warn else "normal", "已运行 221 天"),
            mk_item("字符集", "normal", "AL32UTF8"),
        ]),
        mk_cat("性能指标", [
            mk_item("会话数使用率", "normal", "77.2%", ">80% 警告"),
            mk_item("共享池空闲率", "warn" if warn else "normal", "8.4%", "<10% 警告"),
            mk_item("TOP1 等待事件", "normal", "db file sequential read (21.4%)"),
        ]),
        mk_cat("空间容量", [
            mk_item("表空间使用率", "crit" if crit else "normal", "96.3%", ">95% 严重",
                    ["表空间", "使用率"], [["USERS", "85.6%"], ["UNDOTBS1", "96.3%"]]),
        ]),
        mk_cat("会话与锁", [
            mk_item("阻塞会话", "crit" if crit else "normal", "1 个阻塞会话 (412s)"),
        ]),
        mk_cat("高可用与备份", [
            mk_item("DataGuard 应用延迟", "normal", "12 秒"),
            mk_item("归档日志使用率", "warn" if warn else "normal", "82.4%"),
        ]),
    ]
    total = sum(len(c["items"]) for c in categories)
    normal = total - warn - crit
    return {
        "connection": {"name": db_name, "host": host, "db_type": db_type},
        "template": {"name": tpl_name},
        "summary": {"total": total, "normal": normal, "warn": warn, "crit": crit, "info": 0, "error": 0},
        "categories": categories,
    }


def _seed_demo_reports() -> None:
    demos = [
        ("ORCL-PROD-01", "oracle", "10.20.1.11", "Oracle 标准巡检模板", 3, 2, 42),
        ("MYSQL-ORDER-01", "mysql", "10.20.2.21", "MySQL 基础巡检模板", 0, 0, 18),
        ("PG-REPORT-01", "pg", "10.20.3.31", "PostgreSQL 高可用巡检模板", 0, 2, 25),
    ]
    for name, db_type, host, tpl_name, warn, crit, dur in demos:
        result = _mock_result(db_type, name, host, tpl_name, warn, crit)
        report_no = f"RPT-{now_stamp()}-{name}"
        execute(
            "INSERT INTO reports(report_no,name,connection_name,db_type,template_name,trigger_type,status,duration,summary,result_json,created_at) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (report_no, f"{name} 巡检报告", name, db_type, tpl_name, "manual", "success", dur,
             json.dumps(result["summary"], ensure_ascii=False), json.dumps(result, ensure_ascii=False), now()),
        )
