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

    smtp_envelope_from_override: str

    relay_scenario: str

    imap_host: str
    imap_port: str
    imap_security: str
    imap_username: str
    imap_password: str

    pop3_host: str
    pop3_port: str
    pop3_security: str
    pop3_username: str
    pop3_password: str


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
        smtp_envelope_from_override=str(r["smtp_envelope_from_override"]),
        relay_scenario=str(r["relay_scenario"]),
        imap_host=str(r["imap_host"]),
        imap_port=str(r["imap_port"]),
        imap_security=str(r["imap_security"]),
        imap_username=str(r["imap_username"]),
        imap_password=str(r["imap_password"]),
        pop3_host=str(r["pop3_host"]),
        pop3_port=str(r["pop3_port"]),
        pop3_security=str(r["pop3_security"]),
        pop3_username=str(r["pop3_username"]),
        pop3_password=str(r["pop3_password"]),
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
            (
                name.strip() or "Webhook",
                relay_key,
                webhook_secret,
                now,
                now,
            ),
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
                "name = ?, is_active = ?, sender_email = ?, "
                "webhook_secret = ?, "
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
    smtp_envelope_from_override: str,
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
                    "smtp_sender_name = ?, smtp_envelope_from_override = ?, "
                    "updated_at = ? "
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
                    smtp_envelope_from_override.strip(),
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
                    "smtp_sender_name = ?, smtp_envelope_from_override = ?, "
                    "updated_at = ? "
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
                    smtp_envelope_from_override.strip(),
                    now,
                    int(webhook_id),
                ),
            )
        conn.commit()


def update_webhook_relay_scenario(
    *,
    webhook_id: int,
    relay_scenario: str,
) -> None:
    scenario = (relay_scenario or "").strip().lower()
    if scenario not in {"smtp", "imap", "pop3"}:
        scenario = "smtp"
    now = _now_iso()
    with get_conn() as conn:
        conn.execute(
            "update webhooks set relay_scenario = ?, updated_at = ? "
            "where id = ?",
            (scenario, now, int(webhook_id)),
        )
        conn.commit()


def update_webhook_imap(
    *,
    webhook_id: int,
    imap_host: str,
    imap_port: str,
    imap_security: str,
    imap_username: str,
    imap_password: str,
) -> None:
    now = _now_iso()
    security = (imap_security or "").strip().lower() or "ssl"
    if security not in {"ssl", "starttls", "plain"}:
        security = "ssl"

    with get_conn() as conn:
        if imap_password.strip():
            conn.execute(
                (
                    "update webhooks set "
                    "imap_host = ?, imap_port = ?, imap_security = ?, "
                    "imap_username = ?, imap_password = ?, "
                    "updated_at = ? where id = ?"
                ),
                (
                    imap_host.strip(),
                    imap_port.strip(),
                    security,
                    imap_username.strip(),
                    imap_password,
                    now,
                    int(webhook_id),
                ),
            )
        else:
            conn.execute(
                (
                    "update webhooks set "
                    "imap_host = ?, imap_port = ?, imap_security = ?, "
                    "imap_username = ?, updated_at = ? where id = ?"
                ),
                (
                    imap_host.strip(),
                    imap_port.strip(),
                    security,
                    imap_username.strip(),
                    now,
                    int(webhook_id),
                ),
            )
        conn.commit()


def update_webhook_pop3(
    *,
    webhook_id: int,
    pop3_host: str,
    pop3_port: str,
    pop3_security: str,
    pop3_username: str,
    pop3_password: str,
) -> None:
    now = _now_iso()
    security = (pop3_security or "").strip().lower() or "ssl"
    if security not in {"ssl", "starttls", "plain"}:
        security = "ssl"

    with get_conn() as conn:
        if pop3_password.strip():
            conn.execute(
                (
                    "update webhooks set "
                    "pop3_host = ?, pop3_port = ?, pop3_security = ?, "
                    "pop3_username = ?, pop3_password = ?, "
                    "updated_at = ? where id = ?"
                ),
                (
                    pop3_host.strip(),
                    pop3_port.strip(),
                    security,
                    pop3_username.strip(),
                    pop3_password,
                    now,
                    int(webhook_id),
                ),
            )
        else:
            conn.execute(
                (
                    "update webhooks set "
                    "pop3_host = ?, pop3_port = ?, pop3_security = ?, "
                    "pop3_username = ?, updated_at = ? where id = ?"
                ),
                (
                    pop3_host.strip(),
                    pop3_port.strip(),
                    security,
                    pop3_username.strip(),
                    now,
                    int(webhook_id),
                ),
            )
        conn.commit()
