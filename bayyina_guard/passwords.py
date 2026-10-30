"""Part 3: scrypt password storage. The stored string is treated as attacker input."""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import os
import re
import unicodedata

_N, _R, _P = 2**14, 8, 5
_SALT_LEN, _KEY_LEN = 16, 32
_MAXMEM = 64 * 1024 * 1024
_B64_RE = re.compile(r"[A-Za-z0-9_-]*", re.ASCII)
_INT_RE = re.compile(r"[0-9]{1,10}", re.ASCII)


def _normalise(password) -> str:
    if not isinstance(password, str):
        raise TypeError("password must be a string")
    return unicodedata.normalize("NFKC", password)


def _b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64d(text: str) -> bytes | None:
    if not _B64_RE.fullmatch(text):
        return None
    try:
        return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (binascii.Error, ValueError):
        return None


def hash_password(password: str) -> str:
    pw = _normalise(password)
    if not 8 <= len(pw) <= 128:
        raise ValueError("password must be 8 to 128 characters")
    salt = os.urandom(_SALT_LEN)
    dk = hashlib.scrypt(pw.encode("utf-8"), salt=salt, n=_N, r=_R, p=_P,
                        maxmem=_MAXMEM, dklen=_KEY_LEN)
    return f"scrypt${_N}${_R}${_P}${_b64e(salt)}${_b64e(dk)}"


def _parse(stored):
    """Return (n, r, p, salt, key) or None if anything is wrong or out of bounds."""
    if not isinstance(stored, str):
        return None
    parts = stored.split("$")
    if len(parts) != 6 or parts[0] != "scrypt":
        return None
    for token in parts[1:4]:
        if not _INT_RE.fullmatch(token):
            return None
    n, r, p = int(parts[1]), int(parts[2]), int(parts[3])
    if not (2 <= n <= 2**20 and n & (n - 1) == 0):
        return None
    if not (1 <= r <= 32 and 1 <= p <= 16):
        return None
    salt, key = _b64d(parts[4]), _b64d(parts[5])
    if salt is None or key is None:
        return None
    if len(salt) < _SALT_LEN or len(key) != _KEY_LEN:  # exactly 32: never compare a prefix
        return None
    return n, r, p, salt, key


def verify_password(password: str, stored: str) -> bool:
    parsed = _parse(stored)  # all bounds checked BEFORE scrypt runs (no DoS)
    if parsed is None:
        return False
    pw = _normalise(password)
    if not 8 <= len(pw) <= 128:
        return False
    n, r, p, salt, key = parsed
    try:
        dk = hashlib.scrypt(pw.encode("utf-8"), salt=salt, n=n, r=r, p=p,
                            maxmem=_MAXMEM, dklen=_KEY_LEN)
    except (ValueError, MemoryError, OverflowError):
        return False
    return hmac.compare_digest(dk, key)


def needs_rehash(stored: str) -> bool:
    parsed = _parse(stored)
    if parsed is None:
        return True
    n, r, p, _, _ = parsed
    return n < _N or r < _R or p < _P
