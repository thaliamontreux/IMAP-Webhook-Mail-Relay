from __future__ import annotations

from dataclasses import dataclass
import secrets
from typing import Optional

from .db import get_conn


@dataclass(frozen=True)
class AppSettings:
    webhook_secret: Optional[str]
    timestamp_skew_seconds: int
    allowed_sender_domain: str
    default_from_localpart: str
    allow_from_override: bool
    sendmail_path: str


DEFAULTS = {
    "webhook_secret": "",
    "timestamp_skew_seconds": "300",
    "allowed_sender_domain": "",
    "default_from_localpart": "no-reply",
    "allow_from_override": "0",
    "sendmail_path": "/usr/sbin/sendmail",
    "smtp_host": "",
    "smtp_port": "587",
    "smtp_security": "starttls",
    "smtp_ignore_certificates": "0",
    "smtp_username": "",
    "smtp_password": "",
    "smtp_timeout_seconds": "15",
    "smtp_sender_name": "",
    "receiver_bind_host": "0.0.0.0",
    "admin_bind_host": "0.0.0.0",
    "trusted_proxy_cidrs": "",
    "session_secret": "",
}


def get_setting(key: str) -> str:
    with get_conn() as conn:
        row = conn.execute("select value from settings where key = ?", (key,)).fetchone()
        if row is None:
            return DEFAULTS.get(key, "")
        return str(row["value"])


def set_setting(key: str, value: str) -> None:
    with get_conn() as conn:
        conn.execute(
            "insert into settings(key, value) values(?, ?) on conflict(key) do update set value = excluded.value",
            (key, value),
        )
        conn.commit()


def get_or_create_session_secret() -> str:
    existing = get_setting("session_secret").strip()
    if existing:
        return existing
    value = secrets.token_urlsafe(48)
    set_setting("session_secret", value)
    return value


def load_app_settings() -> AppSettings:
    secret = get_setting("webhook_secret").strip() or None
    skew_raw = get_setting("timestamp_skew_seconds").strip() or "300"
    try:
        skew = int(skew_raw)
    except ValueError:
        skew = 300

    allow_override = (
        get_setting("allow_from_override").strip().lower()
        in {
            "1",
            "true",
            "on",
            "yes",
        }
    )

    return AppSettings(
        webhook_secret=secret,
        timestamp_skew_seconds=skew,
        allowed_sender_domain=get_setting("allowed_sender_domain").strip(),
        default_from_localpart=get_setting("default_from_localpart").strip() or "no-reply",
        allow_from_override=allow_override,
        sendmail_path=get_setting("sendmail_path").strip() or "/usr/sbin/sendmail",
    )
