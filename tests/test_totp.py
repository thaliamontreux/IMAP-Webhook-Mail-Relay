import unittest

from mail_api.totp import generate_base32_secret, totp_now, verify_totp


class TestTotp(unittest.TestCase):
    def test_generate_secret(self):
        s = generate_base32_secret()
        self.assertTrue(isinstance(s, str))
        self.assertGreaterEqual(len(s), 20)

    def test_totp_verify_now(self):
        secret = generate_base32_secret()
        code = totp_now(secret=secret)
        self.assertTrue(verify_totp(secret=secret, code=code))

    def test_totp_verify_rejects_wrong(self):
        secret = generate_base32_secret()
        self.assertFalse(verify_totp(secret=secret, code="000000"))
