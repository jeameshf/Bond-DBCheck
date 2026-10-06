"""安装/更新第三方依赖到本项目的 libs/ 目录（离线自包含部署）。

用法：
    python install_deps.py             # 依据 requirements.txt 安装到 ./libs
    python install_deps.py --offline   # 使用 ./wheels 里的离线 wheel 安装
"""
from __future__ import annotations

import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
LIBS = os.path.join(HERE, "libs")
REQ = os.path.join(HERE, "requirements.txt")


def main() -> int:
    args = [sys.executable, "-m", "pip", "install", "--target", LIBS,
            "--upgrade", "--no-warn-script-location"]
    if "--offline" in sys.argv:
        args += ["--no-index", "--find-links", os.path.join(HERE, "wheels")]
    args += ["-r", REQ]
    print(" ".join(args))
    return subprocess.call(args)


if __name__ == "__main__":
    raise SystemExit(main())
