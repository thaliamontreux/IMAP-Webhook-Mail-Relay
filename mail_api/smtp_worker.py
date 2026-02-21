from __future__ import annotations

import time

from .outbound_queue import delete_email, mark_failed, reserve_next_email
from .smtp_delivery import send_via_smtp
from .delivery_log import append_log_line
from .webhooks import get_webhook_by_id


def run_smtp_worker(*, poll_seconds: float = 2.0) -> None:
    while True:
        q = reserve_next_email()
        if q is None:
            time.sleep(poll_seconds)
            continue

        wh = get_webhook_by_id(q.webhook_id)
        if wh is None:
            err = f"webhook not found: {q.webhook_id}"
            append_log_line(
                f"FAIL id={q.id} wh={q.webhook_id} to={q.to_addr} err={err}"
            )
            mark_failed(
                queue_id=q.id,
                previous_attempts=q.attempts,
                error=err,
            )
            time.sleep(0.2)
            continue
        if not wh.is_active:
            err = f"webhook disabled: {q.webhook_id}"
            append_log_line(
                f"FAIL id={q.id} wh={q.webhook_id} to={q.to_addr} err={err}"
            )
            mark_failed(
                queue_id=q.id,
                previous_attempts=q.attempts,
                error=err,
            )
            time.sleep(0.2)
            continue

        try:
            send_via_smtp(
                envelope_from=q.from_addr,
                to_addr=q.to_addr,
                message_bytes=q.message_bytes,
                smtp_settings={
                    "smtp_host": wh.smtp_host,
                    "smtp_port": wh.smtp_port,
                    "smtp_security": wh.smtp_security,
                    "smtp_username": wh.smtp_username,
                    "smtp_password": wh.smtp_password,
                    "smtp_timeout_seconds": wh.smtp_timeout_seconds,
                    "smtp_ignore_certificates": wh.smtp_ignore_certificates,
                },
            )
        except Exception as e:
            err = str(e)
            msg = (
                f"FAIL id={q.id} wh={q.webhook_id} to={q.to_addr} "
                f"att={q.attempts} err={err}"
            )
            append_log_line(msg)
            mark_failed(
                queue_id=q.id,
                previous_attempts=q.attempts,
                error=err,
            )
            time.sleep(0.2)
            continue

        msg = (
            f"OK id={q.id} wh={q.webhook_id} to={q.to_addr} "
            f"att={q.attempts} subj={q.subject}"
        )
        append_log_line(msg)
        delete_email(queue_id=q.id)
