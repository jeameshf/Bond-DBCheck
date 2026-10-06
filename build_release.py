"""打包发布脚本：生成干净的源码发布包（Zip）。

发布包只包含源码与文档，自动排除：
  - libs/、wheels/（本机 Windows 平台的二进制依赖，目标机需自行安装对应平台依赖）
  - data/（运行期数据：数据库、密钥、报告，应随部署实例单独管理）
  - __pycache__、*.pyc、.git、tmp、.pipcache 等

用法：python build_release.py
输出：dbcheck-release-v<版本>.zip
"""
from __future__ import annotations

import os
import sys
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from server import VERSION  # noqa: E402

EXCLUDE_DIRS = {"libs", "wheels", "data", "__pycache__", ".git", ".tmp", "tmp",
                ".pipcache", ".idea", ".vscode"}


def main() -> int:
    out_name = f"dbcheck-release-v{VERSION}.zip"
    out_path = os.path.join(HERE, out_name)

    count = 0
    with zipfile.ZipFile(out_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for root, dirs, files in os.walk(HERE):
            dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]
            for f in files:
                if f == out_name or f.endswith((".pyc", ".pyo")):
                    continue
                full = os.path.join(root, f)
                rel = os.path.relpath(full, HERE)
                zf.write(full, rel)
                count += 1

    size_kb = os.path.getsize(out_path) // 1024
    print("=" * 56)
    print("  Bond-DBCheck 发布包已生成")
    print("=" * 56)
    print(f"  文件   : {out_path}")
    print(f"  大小   : {size_kb} KB")
    print(f"  文件数 : {count}")
    print("=" * 56)
    print("  部署前请阅读 README.md「Linux 服务器部署」章节。")
    print("  目标机需执行 install_deps.py（或 pip install -r requirements.txt）安装依赖。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
