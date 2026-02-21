import os
import tempfile
import unittest

try:
    from mail_api.admin_app import (
        _consume_recovery_code,
        _count_unused_recovery_codes,
        _create_recovery_codes,
    )
except ModuleNotFoundError:  # pragma: no cover
    _consume_recovery_code = None
    _count_unused_recovery_codes = None
    _create_recovery_codes = None
from mail_api.db import init_db


class TestRecoveryCodes(unittest.TestCase):
    def test_create_and_consume(self):
        if _create_recovery_codes is None:
            self.skipTest("mail_api dependencies not installed")

        with tempfile.TemporaryDirectory() as d:
            os.environ["MAIL_API_DATA_DIR"] = d
            init_db()

            codes = _create_recovery_codes(username="alice", count=3)
            self.assertEqual(len(codes), 3)
            self.assertEqual(_count_unused_recovery_codes("alice"), 3)

            ok = _consume_recovery_code(username="alice", code=codes[0])
            self.assertTrue(ok)
            self.assertEqual(_count_unused_recovery_codes("alice"), 2)

            ok2 = _consume_recovery_code(username="alice", code=codes[0])
            self.assertFalse(ok2)
            self.assertEqual(_count_unused_recovery_codes("alice"), 2)
