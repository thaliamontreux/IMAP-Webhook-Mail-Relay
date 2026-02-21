from __future__ import annotations

import base64
import hmac
import secrets
import struct
import time
from urllib.parse import quote
from hashlib import sha1


def generate_base32_secret(*, nbytes: int = 20) -> str:
    raw = secrets.token_bytes(nbytes)
    return base64.b32encode(raw).decode("ascii").strip("=")


def _normalize_base32(secret: str) -> str:
    s = (secret or "").strip().replace(" ", "").upper()
    pad = (-len(s)) % 8
    return s + ("=" * pad)


def _hotp(*, secret: str, counter: int, digits: int = 6) -> str:
    key = base64.b32decode(_normalize_base32(secret), casefold=True)
    msg = struct.pack(">Q", int(counter))
    digest = hmac.new(key, msg, sha1).digest()
    off = digest[-1] & 0x0F
    code_int = struct.unpack(">I", digest[off:off + 4])[0] & 0x7FFFFFFF
    mod = 10**digits
    return str(code_int % mod).zfill(digits)


def totp_now(*, secret: str, step_seconds: int = 30, digits: int = 6) -> str:
    counter = int(time.time()) // int(step_seconds)
    return _hotp(secret=secret, counter=counter, digits=digits)


def verify_totp(
    *,
    secret: str,
    code: str,
    step_seconds: int = 30,
    digits: int = 6,
    window_steps: int = 1,
) -> bool:
    c = (code or "").strip().replace(" ", "")
    if len(c) != digits or not c.isdigit():
        return False

    counter = int(time.time()) // int(step_seconds)
    for delta in range(-int(window_steps), int(window_steps) + 1):
        if _hotp(secret=secret, counter=counter + delta, digits=digits) == c:
            return True
    return False


def build_provisioning_uri(*, secret: str, account: str, issuer: str) -> str:
    a = (account or "").strip()
    i = (issuer or "").strip()
    label = a
    if i:
        label = f"{i}:{a}" if a else i

    label_enc = quote(label, safe=":")
    issuer_enc = quote(i, safe="")

    qs = f"secret={secret}&algorithm=SHA1&digits=6&period=30"
    if issuer_enc:
        qs += f"&issuer={issuer_enc}"

    return f"otpauth://totp/{label_enc}?{qs}"
