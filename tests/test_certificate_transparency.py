import unittest
from unittest.mock import MagicMock, patch

from daedalus.certificate_transparency import fetch_entries, transparency_evidence, run_transparency_check, MAX_RESPONSE_BYTES, MAX_SAVED_ENTRIES


class CertificateTransparencyTests(unittest.TestCase):
    def row(self, entry_id=1):
        return {"id": entry_id, "issuer_ca_id": 2, "issuer_name": "Fixture issuer", "serial_number": "01AF",
                "name_value": "EXAMPLE.ORG\n*.example.org\napi.example.org\nother.org",
                "not_before": "2026-01-01T00:00:00", "not_after": "2027-01-01T00:00:00"}

    def test_scoped_deduplicated_observations_do_not_verify_live_tls_or_log_proofs(self):
        row = self.row()
        result = transparency_evidence("example.org", [row, row])
        self.assertEqual(len(result["entries"]), 1)
        self.assertEqual(result["entries"][0]["dns_names"], ["*.example.org", "api.example.org", "example.org"])
        self.assertFalse(result["collection_partial"])
        self.assertFalse(result["live_certificate_verified"])
        self.assertFalse(result["log_proofs_verified"])
        self.assertEqual(result["entries"][0]["serial_number"], "01af")

    def test_invalid_foreign_and_missing_rows_leave_partial_coverage(self):
        for change in ({"name_value": "other.org"}, {"not_before": "invalid"}, {"issuer_name": "x" * 257}, {"id": True}, {"serial_number": "bad-serial"}):
            result = transparency_evidence("example.org", [{**self.row(), **change}])
            self.assertTrue(result["collection_partial"])
            self.assertEqual(result["entries"], [])

    def test_conflicting_ids_are_rejected(self):
        with self.assertRaises(ValueError):
            transparency_evidence("example.org", [self.row(), {**self.row(), "serial_number": "02"}])

    def test_limits_and_order_are_explicit_and_stable(self):
        rows = [self.row(i + 1) for i in range(MAX_SAVED_ENTRIES + 1)]
        result = transparency_evidence("example.org", rows)
        self.assertTrue(result["collection_partial"])
        self.assertEqual(len(result["entries"]), MAX_SAVED_ENTRIES)
        self.assertEqual(result, transparency_evidence("example.org", list(reversed(rows))))

    def test_outage_is_unavailable_not_empty_issuance(self):
        with patch("daedalus.certificate_transparency.fetch_entries", side_effect=TimeoutError):
            result = run_transparency_check("example.org")
        self.assertEqual(result["state"], "unavailable")
        self.assertNotIn("entries", result)

    def test_subdomain_query_failure_retains_root_evidence_as_partial(self):
        with patch("daedalus.certificate_transparency._public_addresses", return_value=["8.8.8.8"]), patch(
            "daedalus.certificate_transparency._fetch_query", side_effect=[[self.row()], TimeoutError]
        ):
            result = run_transparency_check("example.org")
        self.assertEqual(result["state"], "observed")
        self.assertTrue(result["collection_partial"])
        self.assertEqual(len(result["entries"]), 1)
        self.assertEqual(result["subdomain_query_error_type"], "TimeoutError")

    def test_provider_is_fixed_pinned_bounded_and_redirects_are_not_followed(self):
        for status, body in [(200, b'[]'), (302, b''), (200, b'x' * (MAX_RESPONSE_BYTES + 1))]:
            connection = MagicMock()
            connection.getresponse.return_value.status = status
            connection.getresponse.return_value.read.return_value = body
            with patch("daedalus.certificate_transparency._public_addresses", return_value=["8.8.8.8"]) as resolve, patch("daedalus.certificate_transparency._PinnedHTTPSConnection", return_value=connection):
                if status == 200 and body == b'[]':
                    self.assertEqual(fetch_entries("example.org"), [])
                else:
                    with self.assertRaises(ValueError):
                        fetch_entries("example.org")
            resolve.assert_called_once_with("crt.sh")
            self.assertEqual(connection.request.call_args.args[:2], ("GET", "/?q=%25.example.org&output=json" if status == 200 and body == b'[]' else "/?q=example.org&output=json"))
            self.assertEqual(connection.close.call_count, 2 if status == 200 and body == b'[]' else 1)
