"""离线自包含安装依赖：用标准库 urllib 从 PyPI 下载 wheel，再用 zipfile 解压到 libs/。

不经过 pip（避免其临时目录在受限环境下的权限问题），产出的文件为普通可读文件。
用法：python fetch_deps.py
"""
from __future__ import annotations

import io
import json
import os
import platform
import sys
import time
import urllib.request
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
LIBS = os.path.join(HERE, "libs")
WHEELS = os.path.join(HERE, "wheels")

# 完整依赖闭包（Flask 及其传递依赖 + 三库驱动 + croniter 及其依赖）
PACKAGES = [
    "flask", "werkzeug", "jinja2", "itsdangerous", "click", "markupsafe", "blinker",
    "pymysql", "psycopg2-binary", "oracledb", "cryptography", "cffi", "pycparser",
    "croniter", "python-dateutil", "six", "typing_extensions",
]


def _fetch_json(url: str, retries: int = 3):
    for i in range(retries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "dbcheck-fetch/1.0"})
            with urllib.request.urlopen(req, timeout=60) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except Exception as e:  # noqa: BLE001
            if i == retries - 1:
                raise
            time.sleep(2)


def _plat_tags() -> list[str]:
    """返回当前平台的 wheel 标签片段，用于挑选二进制 wheel。"""
    if sys.platform.startswith("win"):
        return ["win_amd64", "win32", "win_arm64"]
    if sys.platform.startswith("linux"):
        m = (platform.machine() or "").lower()
        if m in ("x86_64", "amd64"):
            return ["manylinux", "linux", "musllinux"]
        if m in ("aarch64", "arm64"):
            return ["manylinux", "aarch64", "linux", "musllinux"]
        return ["manylinux", "linux", "musllinux"]
    if sys.platform == "darwin":
        return ["macosx"]
    return []


def pick_wheel(files: list[dict]) -> str | None:
    wheels = [f for f in files if f.get("filename", "").endswith(".whl")]
    pyver = f"cp{sys.version_info.major}{sys.version_info.minor}"
    plats = _plat_tags()

    def score(f):
        fn = f["filename"].lower()
        # 纯 Python wheel 优先（跨平台）
        if "py3-none-any" in fn:
            return 0
        if "py2.py3-none-any" in fn:
            return 1
        plat_match = any(t in fn for t in plats)
        ver_match = pyver in fn or "abi3" in fn
        if plat_match and ver_match:
            return 2
        if plat_match:
            return 3
        if "none-any" in fn:
            return 4
        return 100

    wheels.sort(key=score)
    return wheels[0]["url"] if wheels else None


def download(url: str, dest: str):
    req = urllib.request.Request(url, headers={"User-Agent": "dbcheck-fetch/1.0"})
    with urllib.request.urlopen(req, timeout=180) as resp:
        data = resp.read()
    with open(dest, "wb") as fp:
        fp.write(data)
    return len(data)


def extract(whl: str):
    with zipfile.ZipFile(whl) as z:
        if z.testzip() is not None:
            raise RuntimeError(f"wheel 损坏：{os.path.basename(whl)}")
        z.extractall(LIBS)


def main() -> int:
    os.makedirs(LIBS, exist_ok=True)
    os.makedirs(WHEELS, exist_ok=True)
    done = 0
    for pkg in PACKAGES:
        # 若 wheels/ 已存在同名 wheel（如离线复用），直接解压，跳过联网
        norm = pkg.lower().replace("-", "_")
        existing = [f for f in os.listdir(WHEELS) if f.lower().startswith(norm + "-") and f.endswith(".whl")]
        if existing:
            dest = os.path.join(WHEELS, existing[0])
            print(f"[复用] {pkg} -> {existing[0]}")
            extract(dest)
            done += 1
            continue

        meta = _fetch_json(f"https://pypi.org/pypi/{pkg}/json")
        ver = meta["info"]["version"]
        url = pick_wheel(meta["urls"])
        if not url:
            print(f"[跳过] {pkg}: 未找到兼容 wheel")
            continue
        fname = os.path.basename(url.split("#")[0].split("?")[0])
        dest = os.path.join(WHEELS, fname)
        if os.path.isfile(dest) and os.path.getsize(dest) > 0:
            print(f"[复用] {pkg} {ver} -> {fname}")
        else:
            print(f"[下载] {pkg} {ver} ...")
            size = download(url, dest)
            print(f"       {size // 1024} KB")
        extract(dest)
        print(f"[解压] {fname} 完成")
        done += 1

    sys.path.insert(0, LIBS)
    print("\n== 验证导入 ==")
    ok = True
    for mod in ("flask", "pymysql", "psycopg2", "oracledb", "croniter"):
        try:
            __import__(mod)
            print(f"  [OK] {mod}")
        except Exception as e:  # noqa: BLE001
            ok = False
            print(f"  [FAIL] {mod}: {e}")
    print(f"\n共处理 {done}/{len(PACKAGES)} 个包，导入验证 {'通过' if ok else '失败'}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
