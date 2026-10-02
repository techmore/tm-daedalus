import hashlib
import json
import unittest
from email.message import Message
from unittest.mock import patch

from daedalus.external_checks import (
    MAX_COOKIE_HEADERS,
    MAX_COOKIE_HEADER_BYTES,
    MAX_PAGE_BYTES,
    MAX_SECURITY_HEADER_CHARS,
    _cookie_attribute_observations,
    _header_semantic_observations,
    compare_snapshots,
    run_website_check,
)


class FixtureSocket:
    def getpeercert(self, binary_form=False):
        if binary_form:
            return b"fixture-public-certificate"
        return {
            "notBefore": "Jan  1 00:00:00 2026 GMT",
            "notAfter": "Jan  1 00:00:00 2027 GMT",
            "subjectAltName": (("DNS", "example.test"),),
        }

    def version(self):
        return "TLSv1.3"

    def cipher(self):
        return ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)


class FixtureResponse:
    def __init__(self, body=b"<html><title>Landing</title></html>", status=200, extra_headers=()):
        self.body = body
        self.status = status
        self.reason = "Fixture response"
        self.headers = Message()
        self.headers.add_header("Content-Type", "text/html; charset=utf-8")
        for key, value in extra_headers:
            self.headers.add_header(key, value)
        self.read_limits = []

    def getheader(self, name, default=None):
        return self.headers.get(name, default)

    def read(self, limit):
        self.read_limits.append(limit)
        return self.body[:limit]


class FixtureConnection:
    def __init__(self, response):
        self.sock = FixtureSocket()
        self.response = response
        self.requests = []
        self.closed = False

    def request(self, method, path, headers):
        self.requests.append((method, path, headers))

    def getresponse(self):
        return self.response

    def close(self):
        self.closed = True


class WebsitePassiveObservationTests(unittest.TestCase):
    def collect(self, response):
        connection = FixtureConnection(response)
        with patch("daedalus.external_checks._public_addresses", return_value=["8.8.8.8"]) as lookup, patch(
            "daedalus.external_checks._PinnedHTTPSConnection", return_value=connection
        ) as connect:
            result = run_website_check("example.test")
        lookup.assert_called_once_with("example.test")
        connect.assert_called_once_with("example.test", "8.8.8.8")
        self.assertEqual(len(connection.requests), 1)
        self.assertTrue(connection.closed)
        self.assertEqual(response.read_limits, [MAX_PAGE_BYTES + 1])
        return result

    def test_existing_verified_handshake_supplies_negotiated_tls_without_probes(self):
        result = self.collect(FixtureResponse())
        self.assertEqual(result["tls"]["negotiated_protocol"], "TLSv1.3")
        self.assertEqual(result["tls"]["negotiated_cipher"], "TLS_AES_256_GCM_SHA384")
        self.assertEqual(result["tls"]["cipher_secret_bits"], 256)
        self.assertIs(result["tls"]["supported_protocols_tested"], False)
        self.assertEqual(result["page_content"]["sha256"], hashlib.sha256(b"<html><title>Landing</title></html>").hexdigest())
        self.assertIs(result["page_content"]["comparison_eligible"], True)

    def test_cookie_values_and_names_never_persist_and_nonce_values_are_redacted(self):
        private = "fixture-session-value-must-not-be-saved"
        result = self.collect(FixtureResponse(extra_headers=[
            ("Set-Cookie", f"fixture-private-name={private}; Secure; HttpOnly; SameSite=Lax"),
            ("Set-Cookie", "other-private-name=other-private-value; SameSite=None"),
            ("Content-Security-Policy", "default-src 'self'; script-src 'nonce-private-nonce-value'"),
        ]))
        encoded = json.dumps(result)
        for sentinel in [private, "fixture-private-name", "other-private-name", "other-private-value", "private-nonce-value"]:
            self.assertNotIn(sentinel, encoded)
        cookies = result["cookie_observations"]
        self.assertEqual(cookies["inspected_cookie_count"], 2)
        self.assertEqual(cookies["secure_attribute_count"], 1)
        self.assertEqual(cookies["http_only_attribute_count"], 1)
        self.assertEqual(cookies["same_site_lax_count"], 1)
        self.assertEqual(cookies["same_site_none_without_secure_count"], 1)
        self.assertIn("nonce-[redacted]", result["security_headers"]["content-security-policy"])
        self.assertIs(result["header_observations"]["csp"]["nonce_source_present"], True)

    def test_cookie_ambiguity_and_limits_are_reported_without_invented_flags(self):
        cookies = _cookie_attribute_observations([
            "a=x; Secure; Secure", "combined=x, second=y; Secure", "invalid pair",
            "b=x; SameSite=Unexpected", "c=x; Expires=Wed, 01 Jan 2027 00:00:00 GMT; SameSite=Strict",
        ])
        self.assertEqual(cookies["unparsed_header_count"], 3)
        self.assertEqual(cookies["inspected_cookie_count"], 2)
        self.assertEqual(cookies["secure_attribute_count"], 0)
        self.assertEqual(cookies["same_site_unrecognized_count"], 1)
        self.assertEqual(cookies["same_site_strict_count"], 1)
        oversized = _cookie_attribute_observations(["a=" + "x" * MAX_COOKIE_HEADER_BYTES])
        self.assertIs(oversized["analysis_partial"], True)
        self.assertEqual(oversized["inspected_cookie_count"], 0)
        limited = _cookie_attribute_observations(["a=x; Secure"] * (MAX_COOKIE_HEADERS + 1))
        self.assertIs(limited["analysis_partial"], True)
        self.assertEqual(limited["inspected_cookie_count"], MAX_COOKIE_HEADERS)

    def test_semantics_are_bounded_token_observations_not_security_scores(self):
        headers = {
            "strict-transport-security": "max-age=0; includeSubDomains; preload",
            "content-security-policy": "default-src 'self'; script-src 'unsafe-inline' 'unsafe-eval'; frame-ancestors 'none'",
            "x-content-type-options": "nosniff", "x-frame-options": "SAMEORIGIN",
        }
        result = _header_semantic_observations(headers, {key: 1 for key in headers}, False)
        self.assertEqual(result["hsts"]["max_age_seconds"], 0)
        self.assertEqual(result["hsts"]["state"], "observed")
        self.assertIs(result["csp"]["unsafe_inline_token_present"], True)
        self.assertIs(result["csp"]["unsafe_eval_token_present"], True)
        self.assertIs(result["csp"]["frame_ancestors_token_present"], True)
        self.assertNotIn("score", result)
        result = _header_semantic_observations({"strict-transport-security": "max-age=300; max-age=0"}, {"strict-transport-security": 1}, False)
        self.assertEqual(result["hsts"]["state"], "ambiguous")
        self.assertIsNone(result["hsts"]["max_age_seconds"])

    def test_truncated_header_nonce_is_redacted_and_analysis_is_partial(self):
        result = self.collect(FixtureResponse(extra_headers=[
            ("Content-Security-Policy", "script-src 'nonce-" + "sensitive-token" * MAX_SECURITY_HEADER_CHARS),
        ]))
        self.assertIs(result["header_observations"]["analysis_partial"], True)
        self.assertNotIn("sensitive-token", result["security_headers"]["content-security-policy"])

    def test_only_complete_successful_same_representation_digests_are_compared(self):
        first = self.collect(FixtureResponse(body=b"<title>Landing</title><p>First</p>"))
        second = self.collect(FixtureResponse(body=b"<title>Landing</title><p>Second</p>"))
        paths = [path for path, _, _ in compare_snapshots(first, second)]
        self.assertIn("page_content.sha256", paths)
        partial = self.collect(FixtureResponse(body=b"x" * (MAX_PAGE_BYTES + 10)))
        self.assertIs(partial["page_content"]["partial"], True)
        self.assertIs(partial["page_html_truncated"], True)
        self.assertEqual(partial["page_content"]["sampled_bytes"], MAX_PAGE_BYTES)
        error = self.collect(FixtureResponse(body=b"error", status=503))
        compressed = self.collect(FixtureResponse(body=b"encoded", extra_headers=[("Content-Encoding", "gzip")]))
        ranged = self.collect(FixtureResponse(body=b"a partial response", status=206, extra_headers=[("Content-Range", "bytes 0-17/1000")]))
        short = self.collect(FixtureResponse(body=b"short", extra_headers=[("Content-Length", "1000")]))
        malformed_length = self.collect(FixtureResponse(extra_headers=[("Content-Length", "not-a-length")]))
        for uncomparable in [partial, error, compressed, ranged, short, malformed_length]:
            self.assertIs(uncomparable["page_content"]["comparison_eligible"], False)
            self.assertFalse(any(path.startswith("page_content.") for path, _, _ in compare_snapshots(first, uncomparable)))
            self.assertFalse(any(path in {"title", "external_resources", "external_host_count", "external_origin_count", "external_reference_count"} for path, _, _ in compare_snapshots(first, uncomparable)))
        different_url = {**second, "final_url": "https://example.test/another-page"}
        self.assertFalse(any(path.startswith("page_content.") for path, _, _ in compare_snapshots(first, different_url)))
        failed = {"requested_url": "https://example.test/", "destination_addresses": []}
        self.assertFalse(any(path.startswith("page_content.") for path, _, _ in compare_snapshots(first, failed)))


if __name__ == "__main__":
    unittest.main()
