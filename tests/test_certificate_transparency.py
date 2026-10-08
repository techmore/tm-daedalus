import unittest
from unittest.mock import MagicMock, patch

from daedalus.certificate_transparency import fetch_entries, transparency_evidence, run_transparency_check, ProviderHTTPFailure, MAX_RESPONSE_BYTES, MAX_SAVED_ENTRIES


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

    def test_root_failure_still_collects_subdomains_as_partial(self):
        with patch("daedalus.certificate_transparency._public_addresses", return_value=["8.8.8.8"]), patch(
            "daedalus.certificate_transparency._fetch_query", side_effect=[ProviderHTTPFailure(502), [self.row()]]
        ) as query:
            result = run_transparency_check("example.org")
        self.assertEqual([call.args[0] for call in query.call_args_list], ["example.org", "%.example.org"])
        self.assertEqual(result["state"], "observed")
        self.assertTrue(result["collection_partial"])
        self.assertEqual(len(result["entries"]), 1)
        self.assertEqual(result["root_query_http_status"], 502)
        self.assertEqual(result["root_query_error_type"], "ProviderHTTPFailure")
        self.assertNotIn("subdomain_query_error_type", result)
        from daedalus.certificate_transparency import newly_observed_entries
        self.assertEqual(newly_observed_entries(transparency_evidence("example.org", []), result, "example.org"), [])

    def test_failed_root_and_empty_subdomain_response_remain_partial(self):
        with patch("daedalus.certificate_transparency._public_addresses", return_value=["8.8.8.8"]), patch(
            "daedalus.certificate_transparency._fetch_query", side_effect=[TimeoutError, []]
        ):
            result = run_transparency_check("example.org")
        self.assertEqual(result["state"], "observed")
        self.assertEqual(result["entries"], [])
        self.assertTrue(result["collection_partial"])
        self.assertEqual(result["root_query_error_type"], "TimeoutError")

    def test_both_failed_queries_are_unavailable_not_empty_issuance(self):
        with patch("daedalus.certificate_transparency._public_addresses", return_value=["8.8.8.8"]), patch(
            "daedalus.certificate_transparency._fetch_query", side_effect=[ProviderHTTPFailure(502), TimeoutError]
        ) as query:
            result = run_transparency_check("example.org")
        self.assertEqual(query.call_count, 2)
        self.assertEqual(result["state"], "unavailable")
        self.assertNotIn("entries", result)
        self.assertEqual(result["http_status"], 502)

    def test_root_access_or_rate_limit_refusal_does_not_issue_more_queries(self):
        for status in [401, 403, 429]:
            with self.subTest(status=status), patch("daedalus.certificate_transparency._public_addresses", return_value=["8.8.8.8"]), patch(
                "daedalus.certificate_transparency._fetch_query", side_effect=ProviderHTTPFailure(status)
            ) as query:
                result = run_transparency_check("example.org")
            query.assert_called_once()
            self.assertEqual(result["state"], "unavailable")
            self.assertEqual(result["http_status"], status)

    def test_provider_http_status_is_saved_without_response_body(self):
        connection = MagicMock()
        connection.getresponse.return_value.status = 502
        with patch("daedalus.certificate_transparency._public_addresses", return_value=["8.8.8.8"]), patch(
            "daedalus.certificate_transparency._PinnedHTTPSConnection", return_value=connection
        ):
            result = run_transparency_check("example.org")
        self.assertEqual(result["state"], "unavailable")
        self.assertEqual(result["http_status"], 502)
        self.assertEqual(result["error_code"], "provider_http_error")
        connection.getresponse.return_value.read.assert_not_called()
        self.assertEqual(connection.close.call_count, 2)
        with self.assertRaises(ValueError):
            ProviderHTTPFailure(900)

    def test_partial_root_observations_retain_subdomain_http_failure(self):
        with patch("daedalus.certificate_transparency._public_addresses", return_value=["8.8.8.8"]), patch(
            "daedalus.certificate_transparency._fetch_query", side_effect=[[self.row()], ProviderHTTPFailure(429)]
        ):
            result = run_transparency_check("example.org")
        self.assertEqual(result["state"], "observed")
        self.assertTrue(result["collection_partial"])
        self.assertEqual(result["subdomain_query_http_status"], 429)

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
            self.assertEqual([call.args[:2] for call in connection.request.call_args_list], [
                ("GET", "/?q=example.org&output=json"), ("GET", "/?q=%25.example.org&output=json")])
            self.assertEqual(connection.close.call_count, 2)

class CertificateTransparencyComparisonTests(unittest.TestCase):
    row = CertificateTransparencyTests.row
    def block(self, ids):
        return transparency_evidence("example.org", [self.row(i) for i in ids])

    def compare(self, before, after):
        from daedalus.external_checks import compare_snapshots
        return compare_snapshots({"domain": "example.org", "certificate_transparency": before},
                                 {"domain": "example.org", "certificate_transparency": after})

    def test_additions_are_new_observations_and_omissions_are_not_revocations(self):
        self.assertEqual(self.compare(self.block([1, 2]), self.block([1])), [])
        changes = self.compare(self.block([1, 2]), self.block([1, 3]))
        self.assertEqual(changes[0][0], "certificate_transparency.newly_observed_entries")
        self.assertEqual([entry["id"] for entry in changes[0][2]], [3])
        self.assertEqual(self.compare(self.block([1, 2]), self.block([2, 1])), [])

    def test_partial_unavailable_foreign_and_malformed_blocks_cannot_claim_additions(self):
        from copy import deepcopy
        baseline = self.block([1])
        for change in ({"collection_partial": True}, {"state": "unavailable"}, {"domain": "other.org"}, {"provider": "other"}, {"scope": "other"}, {"entries": [{"id": 3}]}):
            current = {**self.block([1, 3]), **change}
            self.assertFalse(any(path.endswith("newly_observed_entries") for path, _, _ in self.compare(baseline, current)))
        current = deepcopy(self.block([1, 3]));current["entries"][0]["dns_names"] = ["other.org"]
        self.assertFalse(any(path.endswith("newly_observed_entries") for path, _, _ in self.compare(baseline, current)))
