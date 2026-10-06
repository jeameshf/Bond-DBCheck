"""安全工具：密码哈希 + 对称加密（用于数据库口令与 AI API Key）。

* 用户登录口令使用 PBKDF2-HMAC-SHA256 加盐哈希存储。
* 数据库连接口令、AI API Key 使用 Fernet 加密后落库；密钥保存在 data/secret.key。
"""
from __future__ import annotations

import hashlib
import hmac
import os
import secrets

from . import DATA_DIR

_SECRET_FILE = os.path.join(DATA_DIR, "secret.key")

_fernet = None


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 120_000)
    return f"pbkdf2$120000${salt.hex()}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, iters, salt_hex, hash_hex = stored.split("$")
        salt = bytes.fromhex(salt_hex)
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, int(iters))
        return hmac.compare_digest(dk.hex(), hash_hex)
    except Exception:
        return False


def _get_fernet():
    global _fernet
    if _fernet is not None:
        return _fernet
    from cryptography.fernet import Fernet

    if os.path.isfile(_SECRET_FILE):
        with open(_SECRET_FILE, "rb") as fp:
            key = fp.read().strip()
    else:
        key = Fernet.generate_key()
        os.makedirs(DATA_DIR, exist_ok=True)
        tmp = _SECRET_FILE + ".tmp"
        with open(tmp, "wb") as fp:
            fp.write(key)
        os.replace(tmp, _SECRET_FILE)
    _fernet = Fernet(key)
    return _fernet


def encrypt_text(plain: str) -> str:
    if not plain:
        return ""
    return _get_fernet().encrypt(plain.encode("utf-8")).decode("ascii")


def decrypt_text(enc: str) -> str:
    if not enc:
        return ""
    try:
        return _get_fernet().decrypt(enc.encode("ascii")).decode("utf-8")
    except Exception:
        return ""
