"""DBCheck 数据库巡检平台 —— 启动入口。

用法：
    python app.py                    # 默认 http://127.0.0.1:8080
    python app.py --port 9000
    python app.py --host 0.0.0.0     # 允许局域网访问
    python app.py --no-seed          # 不注入演示数据
"""
from __future__ import annotations

import argparse
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)
_LIBS = os.path.join(_HERE, "libs")
if os.path.isdir(_LIBS) and _LIBS not in sys.path:
    sys.path.insert(0, _LIBS)

from server import VERSION, store  # noqa: E402
from server.scheduler import get_scheduler  # noqa: E402
from server.web import create_app  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="Bond-DBCheck 邦德智能巡检平台")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--no-seed", action="store_true", help="不注入演示数据")
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    store.init_db(seed=not args.no_seed)

    app = create_app()
    get_scheduler().start()

    print("=" * 68)
    print(f"  Bond-DBCheck 邦德智能巡检平台 v{VERSION}")
    print("=" * 68)
    print(f"  访问地址   : http://127.0.0.1:{args.port}")
    print(f"  默认账号   : admin / admin123（管理员）")
    print(f"              dba / dba123（运维）    viewer / viewer123（只读）")
    print(f"  数据库文件 : {store.DB_PATH}")
    print(f"  报告目录   : {store.REPORT_DIR}")
    print("  提示：内置示例连接为演示数据，请修改为真实连接后使用。")
    print("=" * 68)

    app.run(host=args.host, port=args.port, threaded=True, debug=args.debug, use_reloader=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
