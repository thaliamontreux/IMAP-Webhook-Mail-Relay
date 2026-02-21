from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import secrets
from typing import Optional

from .db import get_conn


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class Webhook:
    id: int
    name: str
    relay_key: str
    is_active: bool
    sender_email: str
    webhook_secret: str
    timestamp_skew_seconds: int
    allow_from_override: bool

    smtp_host: str
    smtp_port: str
    smtp_security: str
    smtp_username: str
    smtp_password: str
    smtp_timeout_seconds: str
    smtp_ignore_certificates: str
    smtp_sender_name: str


def _row_to_webhook(r) -> Webhook:
    return Webhook(
        id=int(r["id"]),
        name=str(r["name"]),
        relay_key=str(r["relay_key"]),
        is_active=int(r["is_active"]) == 1,
        sender_email=str(r["sender_email"]),
        webhook_secret=str(r["webhook_secret"]),
        timestamp_skew_seconds=int(r["timestamp_skew_seconds"]),
        allow_from_override=int(r["allow_from_override"]) == 1,
        smtp_host=str(r["smtp_host"]),
        smtp_port=str(r["smtp_port"]),
        smtp_security=str(r["smtp_security"]),
        smtp_username=str(r["smtp_username"]),
        smtp_password=str(r["smtp_password"]),
        smtp_timeout_seconds=str(r["smtp_timeout_seconds"]),
        smtp_ignore_certificates=str(r["smtp_ignore_certificates"]),
        smtp_sender_name=str(r["smtp_sender_name"]),
    )


def ensure_default_webhook() -> None:
    with get_conn() as conn:
        row = conn.execute("select count(*) as c from webhooks").fetchone()
        if int(row["c"]) > 0:
            return

        now = _now_iso()
        relay_key = secrets.token_hex(16)
        webhook_secret = secrets.token_hex(32)

        conn.execute(
            (
                "insert into webhooks("
                "name, relay_key, is_active, sender_email, webhook_secret, "
                "timestamp_skew_seconds, allow_from_override, "
                "created_at, updated_at"
                ") values(?, ?, 0, '', ?, 300, 0, ?, ?)"
            ),
            ("Default", relay_key, webhook_secret, now, now),
        )
        conn.commit()


def list_webhooks() -> list[Webhook]:
    with get_conn() as conn:
        rows = conn.execute(
            "select * from webhooks order by created_at desc, id desc"
        ).fetchall()
        return [_row_to_webhook(r) for r in rows]


def get_webhook_by_id(webhook_id: int) -> Optional[Webhook]:
    with get_conn() as conn:
        row = conn.execute(
            "select * from webhooks where id = ?",
            (int(webhook_id),),
        ).fetchone()
        if row is None:
            return None
        return _row_to_webhook(row)


def get_webhook_by_relay_key(relay_key: str) -> Optional[Webhook]:
    key = (relay_key or "").strip()
    if not key:
        return None
    with get_conn() as conn:
        row = conn.execute(
            "select * from webhooks where relay_key = ?",
            (key,),
        ).fetchone()
        if row is None:
            return None
        return _row_to_webhook(row)


def create_webhook(*, name: str) -> int:
    now = _now_iso()
    relay_key = secrets.token_hex(16)
    webhook_secret = secrets.token_hex(32)

    with get_conn() as conn:
        cur = conn.execute(
            (
                "insert into webhooks("
                "name, relay_key, is_active, sender_email, webhook_secret, "
                "timestamp_skew_seconds, allow_from_override, "
                "created_at, updated_at"
                ") values(?, ?, 0, '', ?, 300, 0, ?, ?)"
            ),
            (name.strip() or "Webhook", relay_key, webhook_secret, now, now),
        )
        conn.commit()
        return int(cur.lastrowid)


def update_webhook(
    *,
    webhook_id: int,
    name: str,
    is_active: bool,
    sender_email: str,
    webhook_secret: str,
    timestamp_skew_seconds: int,
    allow_from_override: bool,
) -> None:
    now = _now_iso()
    with get_conn() as conn:
        conn.execute(
            (
                "update webhooks set "
                "name = ?, is_active = ?, sender_email = ?, webhook_secret = ?, "
                "timestamp_skew_seconds = ?, allow_from_override = ?, "
                "updated_at = ? "
                "where id = ?"
            ),
            (
                name.strip() or "Webhook",
                1 if is_active else 0,
                sender_email.strip(),
                webhook_secret.strip(),
                int(timestamp_skew_seconds),
                1 if allow_from_override else 0,
                now,
                int(webhook_id),
            ),
        )
        conn.commit()


def update_webhook_smtp(
    *,
    webhook_id: int,
    smtp_host: str,
    smtp_port: str,
    smtp_security: str,
    smtp_username: str,
    smtp_password: str,
    smtp_timeout_seconds: str,
    smtp_ignore_certificates: str,
    smtp_sender_name: str,
) -> None:
    now = _now_iso()
    with get_conn() as conn:
        if smtp_password.strip():
            conn.execute(
                (
                    "update webhooks set "
                    "smtp_host = ?, smtp_port = ?, smtp_security = ?, "
                    "smtp_username = ?, "
                    "smtp_password = ?, smtp_timeout_seconds = ?, "
                    "smtp_ignore_certificates = ?, "
                    "smtp_sender_name = ?, updated_at = ? "
                    "where id = ?"
                ),
                (
                    smtp_host.strip(),
                    smtp_port.strip(),
                    smtp_security.strip(),
                    smtp_username.strip(),
                    smtp_password,
                    smtp_timeout_seconds.strip() or "15",
                    smtp_ignore_certificates.strip(),
                    smtp_sender_name.strip(),
                    now,
                    int(webhook_id),
                ),
            )
        else:
            conn.execute(
                (
                    "update webhooks set "
                    "smtp_host = ?, smtp_port = ?, smtp_security = ?, "
                    "smtp_username = ?, "
                    "smtp_timeout_seconds = ?, smtp_ignore_certificates = ?, "
                    "smtp_sender_name = ?, updated_at = ? "
                    "where id = ?"
                ),
                (
                    smtp_host.strip(),
                    smtp_port.strip(),
                    smtp_security.strip(),
                    smtp_username.strip(),
                    smtp_timeout_seconds.strip() or "15",
                    smtp_ignore_certificates.strip(),
                    smtp_sender_name.strip(),
                    now,
                    int(webhook_id),
                ),
            )
        conn.commit()
