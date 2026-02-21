import hmac
import unittest
from datetime import datetime, timezone
from hashlib import sha256

try:
    from mail_api.security import verify_webhook_signature
except ModuleNotFoundError:  # pragma: no cover
    verify_webhook_signature = None


class TestWebhookSignature(unittest.TestCase):
    def test_signature_valid(self):
        if verify_webhook_signature is None:
            self.skipTest("mail_api dependencies not installed")

        secret = "abc123"
        raw = b"{\"hello\":\"world\"}"
        ts = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        msg = ts.encode("utf-8") + b"." + raw
        sig = hmac.new(secret.encode("utf-8"), msg, sha256).hexdigest()

        self.assertTrue(
            verify_webhook_signature(
                secret=secret,
                timestamp_header=ts,
                signature_header=sig,
                raw_body=raw,
                max_skew_seconds=300,
            )
        )

    def test_signature_invalid(self):
        if verify_webhook_signature is None:
            self.skipTest("mail_api dependencies not installed")

        secret = "abc123"
        raw = b"{}"
        ts = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

        self.assertFalse(
            verify_webhook_signature(
                secret=secret,
                timestamp_header=ts,
                signature_header="deadbeef",
                raw_body=raw,
                max_skew_seconds=300,
            )
        )
