import os
import tempfile
import unittest

from mail_api.db import init_db
from mail_api.outbound_queue import enqueue_email


class TestIdempotency(unittest.TestCase):
    def test_enqueue_idempotent(self):
        old = os.environ.get("MAIL_API_DATA_DIR")
        with tempfile.TemporaryDirectory() as d:
            os.environ["MAIL_API_DATA_DIR"] = d
            init_db()

            q1 = enqueue_email(
                webhook_id=1,
                idempotency_key="k1",
                to_addr="a@example.com",
                from_addr="b@example.com",
                subject="s",
                body_text="t",
                message_bytes=b"x",
            )
            q2 = enqueue_email(
                webhook_id=1,
                idempotency_key="k1",
                to_addr="a@example.com",
                from_addr="b@example.com",
                subject="s",
                body_text="t",
                message_bytes=b"x",
            )
            self.assertEqual(q1, q2)

        if old is None:
            os.environ.pop("MAIL_API_DATA_DIR", None)
        else:
            os.environ["MAIL_API_DATA_DIR"] = old
