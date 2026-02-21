from __future__ import annotations

from email.parser import BytesParser
from email.policy import default
import os
import smtplib
import ssl
from typing import Union

from .settings import get_setting


def _get_smtp_password() -> str:
    value = get_setting("smtp_password").strip()
    if value:
        return value
    return os.environ.get("MAIL_API_SMTP_PASSWORD", "").strip()


def send_via_smtp(
    *,
    envelope_from: str,
    to_addr: str,
    message_bytes: bytes,
    smtp_settings: dict[str, str] | None = None,
) -> None:
    s = smtp_settings or {}
    host = (s.get("smtp_host") or get_setting("smtp_host")).strip()
    if not host:
        raise RuntimeError("smtp host not configured")

    port_setting = s.get("smtp_port") or get_setting("smtp_port")
    port_raw = (port_setting.strip() or "587")
    try:
        port = int(port_raw)
    except ValueError:
        raise RuntimeError("invalid smtp port")

    security_setting = s.get("smtp_security") or get_setting("smtp_security")
    security = (security_setting.strip().lower() or "starttls")
    timeout_raw = (
        (s.get("smtp_timeout_seconds") or get_setting("smtp_timeout_seconds"))
        .strip()
        or "15"
    )
    try:
        timeout_seconds = int(timeout_raw)
    except ValueError:
        timeout_seconds = 15

    username = (s.get("smtp_username") or get_setting("smtp_username")).strip()
    password = (s.get("smtp_password") or "").strip()
    if not password and not smtp_settings:
        password = _get_smtp_password()

    ignore_raw = (
        (
            s.get("smtp_ignore_certificates")
            or get_setting("smtp_ignore_certificates")
        )
        .strip()
        .lower()
    )
    ignore_certs = ignore_raw in {"1", "true", "on", "yes"}

    ctx = ssl.create_default_context()
    if ignore_certs:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    smtp: Union[smtplib.SMTP, smtplib.SMTP_SSL, None] = None
    try:
        if security == "ssl":
            smtp = smtplib.SMTP_SSL(
                host=host,
                port=port,
                timeout=timeout_seconds,
                context=ctx,
            )
            smtp.ehlo()
        else:
            smtp = smtplib.SMTP(host=host, port=port, timeout=timeout_seconds)
            smtp.ehlo()
            if security == "starttls":
                smtp.starttls(context=ctx)
                smtp.ehlo()

        assert smtp is not None

        if username:
            if not password:
                raise RuntimeError("smtp username set but password is empty")
            smtp.login(username, password)

        # Match behavior of common working scripts which use send_message().
        # This ensures correct message formatting and SMTP options.
        try:
            msg = BytesParser(policy=default).parsebytes(message_bytes)
            smtp.send_message(msg, from_addr=envelope_from, to_addrs=[to_addr])
        except Exception:
            smtp.sendmail(envelope_from, [to_addr], message_bytes)
    finally:
        try:
            if smtp is not None:
                smtp.quit()
        except Exception:
            pass
