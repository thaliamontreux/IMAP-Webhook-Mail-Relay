from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Iterable


def _data_dir() -> str:
    base_dir = os.environ.get("MAIL_API_DATA_DIR")
    if not base_dir:
        base_dir = os.path.join(os.getcwd(), "data")
    os.makedirs(base_dir, exist_ok=True)
    return base_dir


def _log_path() -> str:
    p = os.path.join(_data_dir(), "delivery.log")
    return p


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _cap_file(path: str, max_bytes: int) -> None:
    try:
        size = os.path.getsize(path)
    except OSError:
        return
    if size <= max_bytes:
        return

    keep = max_bytes
    try:
        with open(path, "rb") as f:
            f.seek(-keep, os.SEEK_END)
            tail = f.read(keep)
        nl = tail.find(b"\n")
        if nl != -1 and nl + 1 < len(tail):
            tail = tail[nl + 1 :]
        with open(path, "wb") as f:
            f.write(tail)
    except OSError:
        return


def append_log_line(line: str) -> None:
    path = _log_path()
    msg = line.replace("\r", " ").replace("\n", " ").strip()
    if not msg:
        return
    out = f"{_now_iso()} {msg}\n"
    try:
        with open(path, "a", encoding="utf-8") as f:
            f.write(out)
    except OSError:
        return
    _cap_file(path, 5 * 1024 * 1024)


def iter_recent_lines(max_bytes: int = 64 * 1024) -> Iterable[str]:
    path = _log_path()
    try:
        size = os.path.getsize(path)
    except OSError:
        return []

    start = 0
    if size > max_bytes:
        start = size - max_bytes

    try:
        with open(path, "rb") as f:
            f.seek(start)
            data = f.read()
    except OSError:
        return []

    if start > 0:
        nl = data.find(b"\n")
        if nl != -1 and nl + 1 < len(data):
            data = data[nl + 1 :]

    try:
        text = data.decode("utf-8", errors="replace")
    except Exception:
        return []

    lines = [ln for ln in text.splitlines() if ln.strip()]
    return lines
