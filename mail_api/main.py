from __future__ import annotations

import multiprocessing
import sys

import uvicorn

from .db import init_db
from .settings import get_setting


def _run_receiver(host: str) -> None:
    from .receiver_app import create_receiver_app

    app = create_receiver_app()
    uvicorn.run(app, host=host, port=2555, log_level="info")


def _run_admin(host: str) -> None:
    from .admin_app import create_admin_app

    app = create_admin_app()
    uvicorn.run(app, host=host, port=2580, log_level="info")


def _run_smtp_worker() -> None:
    from .smtp_worker import run_smtp_worker

    run_smtp_worker()


def main() -> None:
    if sys.version_info < (3, 11):
        raise RuntimeError("MAIL_API requires Python 3.11+")

    init_db()

    receiver_host = get_setting("receiver_bind_host").strip() or "0.0.0.0"
    admin_host = get_setting("admin_bind_host").strip() or "0.0.0.0"

    p1 = multiprocessing.Process(target=_run_receiver, args=(receiver_host,), daemon=False)
    p2 = multiprocessing.Process(target=_run_admin, args=(admin_host,), daemon=False)
    p3 = multiprocessing.Process(target=_run_smtp_worker, args=(), daemon=False)

    p1.start()
    p2.start()
    p3.start()

    p1.join()
    p2.join()
    p3.join()


if __name__ == "__main__":
    multiprocessing.freeze_support()
    main()
