from __future__ import annotations

import subprocess
from email.message import EmailMessage
from email.utils import formataddr, formatdate, make_msgid


def build_message(
    *,
    from_addr: str,
    to_addr: str,
    subject: str,
    body_text: str,
    from_name: str | None = None,
) -> bytes:
    msg = EmailMessage()
    if from_name and from_name.strip():
        msg["From"] = formataddr((from_name.strip(), from_addr))
    else:
        msg["From"] = from_addr
    msg["To"] = to_addr
    msg["Subject"] = subject
    msg["Date"] = formatdate(localtime=False)
    msg["Message-ID"] = make_msgid()
    msg.set_content(body_text)
    return msg.as_bytes()


def send_via_sendmail(
    *,
    sendmail_path: str,
    envelope_from: str,
    message_bytes: bytes,
) -> None:
    p = subprocess.run(
        [sendmail_path, "-t", "-i", "-f", envelope_from],
        input=message_bytes,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if p.returncode != 0:
        err = p.stderr.decode("utf-8", errors="replace").strip()
        raise RuntimeError(err or "sendmail failed")
