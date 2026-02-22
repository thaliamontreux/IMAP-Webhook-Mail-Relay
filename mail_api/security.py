from __future__ import annotations

import hmac
import os
from datetime import datetime, timezone
from hashlib import sha256
from typing import Optional

from itsdangerous import URLSafeSerializer
from passlib.context import CryptContext

from .settings import get_or_create_session_secret


_pwd = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")


def hash_password(password: str) -> str:
    return _pwd.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return _pwd.verify(password, password_hash)
    except Exception:
        return False


def _parse_iso(ts: str) -> Optional[datetime]:
    ts = ts.strip()
    if not ts:
        return None
    if ts.endswith("Z"):
        ts = ts[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(ts)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def verify_webhook_signature(
    *,
    secret: str,
    timestamp_header: str,
    signature_header: str,
    raw_body: bytes,
    max_skew_seconds: int,
) -> bool:
    ts = _parse_iso(timestamp_header)
    if ts is None:
        return False

    now = datetime.now(timezone.utc)
    skew = abs((now - ts).total_seconds())
    if skew > max_skew_seconds:
        return False

    msg = timestamp_header.encode("utf-8") + b"." + raw_body
    expected = hmac.new(secret.encode("utf-8"), msg, sha256).hexdigest()
    return hmac.compare_digest(expected, signature_header.strip().lower())


def get_session_serializer() -> URLSafeSerializer:
    secret = os.environ.get("MAIL_API_SESSION_SECRET")
    if not secret:
        secret = get_or_create_session_secret()
    return URLSafeSerializer(secret, salt="mail_api_session")


def get_csrf_serializer() -> URLSafeSerializer:
    secret = os.environ.get("MAIL_API_SESSION_SECRET")
    if not secret:
        secret = get_or_create_session_secret()
    return URLSafeSerializer(secret, salt="mail_api_csrf")
