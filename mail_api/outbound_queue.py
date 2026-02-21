from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Optional

from .db import get_conn


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _now_iso() -> str:
    return _now().isoformat()


@dataclass(frozen=True)
class QueuedEmail:
    id: int
    webhook_id: int
    to_addr: str
    from_addr: str
    subject: str
    body_text: str
    message_bytes: bytes
    attempts: int


def enqueue_email(
    *,
    webhook_id: int,
    to_addr: str,
    from_addr: str,
    subject: str,
    body_text: str,
    message_bytes: bytes,
) -> int:
    now = _now_iso()
    with get_conn() as conn:
        cur = conn.execute(
            "insert into outbound_queue("
            "created_at, updated_at, status, webhook_id, to_addr, from_addr, "
            "subject, body_text, message_bytes, attempts, next_attempt_at, "
            "last_error"
            ") values(?, ?, 'pending', ?, ?, ?, ?, ?, ?, 0, ?, '')",
            (
                now,
                now,
                int(webhook_id),
                to_addr,
                from_addr,
                subject,
                body_text,
                message_bytes,
                now,
            ),
        )
        conn.commit()
        return int(cur.lastrowid)


def reserve_next_email(
    *,
    now: Optional[datetime] = None,
) -> Optional[QueuedEmail]:
    now_dt = now or _now()
    now_iso = now_dt.isoformat()
    stale_iso = (now_dt - timedelta(minutes=5)).isoformat()

    # Best-effort single-worker reservation. BEGIN IMMEDIATE prevents two
    # workers
    # from reserving the same row.
    with get_conn() as conn:
        conn.execute("begin immediate")
        conn.execute(
            "update outbound_queue set status = 'pending', updated_at = ? "
            "where status = 'sending' and updated_at < ?",
            (now_iso, stale_iso),
        )
        row = conn.execute(
            "select id, webhook_id, to_addr, from_addr, subject, body_text, "
            "message_bytes, attempts "
            "from outbound_queue "
            "where status = 'pending' and next_attempt_at <= ? "
            "order by next_attempt_at asc, id asc "
            "limit 1",
            (now_iso,),
        ).fetchone()
        if row is None:
            conn.execute("commit")
            return None

        conn.execute(
            "update outbound_queue set status = 'sending', updated_at = ? "
            "where id = ?",
            (now_iso, int(row["id"])),
        )
        conn.execute("commit")

        return QueuedEmail(
            id=int(row["id"]),
            webhook_id=int(row["webhook_id"]),
            to_addr=str(row["to_addr"]),
            from_addr=str(row["from_addr"]),
            subject=str(row["subject"]),
            body_text=str(row["body_text"]),
            message_bytes=bytes(row["message_bytes"]),
            attempts=int(row["attempts"]),
        )


def _backoff_seconds(attempts: int) -> int:
    # attempts is the number of failed attempts so far. After a failure we will
    # schedule attempt #attempts+1.
    schedule = [5, 10, 30, 60, 120, 300]
    idx = attempts if attempts < len(schedule) else (len(schedule) - 1)
    return int(schedule[idx])


def mark_failed(*, queue_id: int, previous_attempts: int, error: str) -> None:
    now_dt = _now()
    now_iso = now_dt.isoformat()
    next_dt = now_dt + timedelta(seconds=_backoff_seconds(previous_attempts))
    next_iso = next_dt.isoformat()
    err = (error or "").strip()
    if len(err) > 4000:
        err = err[:4000]

    with get_conn() as conn:
        conn.execute(
            "update outbound_queue "
            "set status = 'pending', updated_at = ?, attempts = attempts + 1, "
            "next_attempt_at = ?, last_error = ? "
            "where id = ?",
            (now_iso, next_iso, err, int(queue_id)),
        )
        conn.commit()


def delete_email(*, queue_id: int) -> None:
    with get_conn() as conn:
        conn.execute(
            "delete from outbound_queue where id = ?",
            (int(queue_id),),
        )
        conn.commit()
