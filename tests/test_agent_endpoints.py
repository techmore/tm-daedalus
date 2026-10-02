import unittest
from unittest.mock import patch
from daedalus.agent import validate_endpoint, enroll


class AgentEndpointTests(unittest.TestCase):
    def test_portal_https_or_exact_loopback_origin(self):
        for value in ("https://cybersecuritypilot.org", "https://portal.example:8443/", "http://localhost:8000", "http://127.0.0.1:8000", "http://[::1]:8000"):
            self.assertEqual(validate_endpoint(value), value.rstrip("/"))
        for value in ("http://remote.example", "http://127.0.0.2", "http://localhost.evil.example", "https://user:secret@portal.example", "https://portal.example/path", "https://portal.example?x=1", "https://portal.example#fragment", "https://portal.example:0", " https://portal.example", "https://portal.example\\evil", "https://%70ortal.example"):
            with self.assertRaises(ValueError): validate_endpoint(value)

    def test_scanner_requires_exact_loopback(self):
        for value in ("http://127.0.0.1:9000", "https://localhost:9000", "http://[::1]:9000"):
            validate_endpoint(value, local_scanner=True)
        for value in ("https://remote.example", "http://192.168.1.1", "http://localhost.evil.example"):
            with self.assertRaises(ValueError): validate_endpoint(value, local_scanner=True)

    def test_invalid_enrollment_destination_never_sends_code(self):
        with patch("daedalus.agent.httpx.post") as request:
            with self.assertRaises(ValueError): enroll("http://remote.example", "Fixture", "secret")
            request.assert_not_called()
