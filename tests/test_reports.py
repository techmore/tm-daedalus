import unittest
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import KeepTogether, LongTable

from daedalus.reports import (
    _record_value,
    _time_text,
    _tls_issuer_text,
    build_external_posture_pdf,
    build_scanner_results_pdf,
    build_meraki_security_pdf,
    scanner_result_hosts,
    scanner_phase_label,
)


class ExternalPostureReportTests(unittest.TestCase):
    def test_bounded_exposure_heading_and_complete_probe_list_stay_together(self):
        from daedalus import reports

        sample = getSampleStyleSheet()
        styles = {
            "section": sample["Heading2"],
            "subsection": sample["Heading3"],
            "body": sample["BodyText"],
            "small": sample["BodyText"],
            "cell": sample["BodyText"],
            "table_header": sample["BodyText"],
        }
        probes = [
            {"path": path, "http_status": 404, "assessment": "missing_response_observed"}
            for path in ("/.git/HEAD", "/.git/config", "/.env", "/server-status", "/phpinfo.php")
        ]
        story = []
        reports._append_active_website(story, {
            "run": {"id": 43, "status": "completed", "completed_at": "2026-10-02T15:14:42Z",
                    "snapshot": {"preset_version": "fixed-exposure-v1", "coverage_complete": True,
                                 "baseline": {"assessment": "missing_response_observed"},
                                 "probes": probes, "findings": [], "limitations": []}},
            "changes": [],
        }, styles)

        self.assertIsInstance(story[0], KeepTogether)
        grouped = story[0]._content
        self.assertEqual(grouped[0].getPlainText(), "Bounded website exposure observations")
        probe_table = next(item for item in grouped if isinstance(item, LongTable) and len(item._cellvalues) == 6)
        rendered_paths = [cell.getPlainText() for row in probe_table._cellvalues[1:] for cell in row]
        self.assertTrue(all(probe["path"] in rendered_paths for probe in probes))

    def test_posture_pdf_starts_with_coverage_cards_and_confirmed_change_count(self):
        from unittest.mock import patch
        from daedalus import reports

        snapshot = {"domain": "example.org", "checks": {
            "dns": {"run": {"id": 7, "status": "completed", "snapshot": {
                "records": {}, "resolver_errors": {},
            }}, "changes": [{"field_path": "A", "previous_value": "192.0.2.1", "current_value": "192.0.2.2"}]},
            "web": {"run": {"id": 8, "status": "completed", "snapshot": {
                "http_status": 200, "tls": {"certificate_valid": True},
            }}, "changes": []},
        }}
        with patch.object(reports, "_paragraph", wraps=reports._paragraph) as paragraphs:
            pdf = build_external_posture_pdf(snapshot)

        values = [str(call.args[0]) for call in paragraphs.call_args_list]
        self.assertTrue(pdf.startswith(b"%PDF-"))
        self.assertIn("DNS AND EMAIL", values)
        self.assertIn("CONFIRMED CHANGES", values)
        self.assertIn("1", values)
        self.assertTrue(any("does not calculate a combined security score" in value for value in values))

    def test_dns_lookup_failures_are_unknown_instead_of_absent(self):
        value, status = _record_value({}, {"www A": "SERVFAIL"}, "WWW_A")

        self.assertEqual(value, "Lookup failed: SERVFAIL")
        self.assertEqual(status, "Unknown")

    def test_dkim_report_reads_selector_from_nested_record_map(self):
        value, status = _record_value(
            {"DKIM": {"google": ["v=DKIM1; k=rsa; p=public-key"]}},
            {},
            "DKIM.google",
        )

        self.assertEqual(value, "v=DKIM1; k=rsa; p=public-key")
        self.assertEqual(status, "Published")

    def test_dns_record_sets_render_without_json_punctuation(self):
        value, status = _record_value(
            {"TXT": ["google-site-verification=token", "v=spf1 -all"]}, {}, "TXT"
        )

        self.assertEqual(value, "google-site-verification=token, v=spf1 -all")
        self.assertNotIn("[", value)
        self.assertNotIn('"', value)
        self.assertEqual(status, "Published")

    def test_report_dates_and_tls_issuer_use_readable_labels(self):
        self.assertEqual(_time_text("2026-09-29T15:00:00Z"), "Sep 29, 2026 at 15:00 UTC")
        self.assertEqual(
            _tls_issuer_text("countryName=US, organizationName=Let's Encrypt, commonName=YR1"),
            "Let's Encrypt · YR1 · US",
        )

    def test_dkim_lookup_failures_are_unknown_instead_of_absent(self):
        value, status = _record_value(
            {"DKIM": {"google": []}}, {"DKIM google": "SERVFAIL"}, "DKIM.google"
        )

        self.assertEqual(value, "Lookup failed: SERVFAIL")
        self.assertEqual(status, "Unknown")

    def test_pdf_interprets_legacy_spf_and_dmarc_records_with_clear_limits(self):
        from unittest.mock import patch
        from daedalus import reports

        snapshot = {"domain": "example.org", "checks": {"dns": {"run": {
            "id": 2, "snapshot": {
                "records": {
                    "SPF": ["v=spf1 +all"],
                    "DMARC": ["v=DMARC1; p=none"],
                },
                "resolver_errors": {},
            },
        }}}}
        with patch.object(reports, "_paragraph", wraps=reports._paragraph) as rendered:
            pdf = build_external_posture_pdf(snapshot)

        values = [str(call.args[0]) for call in rendered.call_args_list]
        self.assertTrue(pdf.startswith(b"%PDF-"))
        self.assertIn("Allows all", values)
        self.assertIn("Monitor only", values)
        self.assertTrue(any("No aggregate-report URI is configured" in value for value in values))
        self.assertTrue(any("verify actual SPF/DKIM alignment" in value for value in values))

    def test_report_identifies_newer_failed_attempt_without_discarding_saved_evidence(self):
        from unittest.mock import patch
        from daedalus import reports
        with patch.object(reports, "_paragraph", wraps=reports._paragraph) as paragraphs:
            pdf = build_external_posture_pdf({"checks": {"web": {
                "run": {"id": 10, "snapshot": {"title": "Saved successful evidence"}},
                "latest_attempt": {"id": 11, "status": "failed", "started_at": "2026-09-29T00:00:00Z", "error_summary": "HTTPS request failed (TimeoutError)."}
            }}})
        values = [str(call.args[0]) for call in paragraphs.call_args_list]
        self.assertTrue(pdf.startswith(b"%PDF"))
        self.assertTrue(any("Latest attempt #11: failed" in value for value in values))
        self.assertTrue(any("saved successful run #10" in value for value in values))
        self.assertIn("Saved successful evidence", values)
        self.assertTrue(any("TimeoutError" in value for value in values))

    def test_passive_website_report_preserves_zero_counts_and_scope(self):
        from unittest.mock import patch
        from daedalus import reports
        snapshot = {"checks": {"web": {"run": {"id": 1, "snapshot": {
            "tls": {"negotiated_protocol": "TLSv1.3", "negotiated_cipher": "Example cipher"},
            "cookie_observations": {"inspected_cookie_count": 0, "response_header_count": 0, "analysis_partial": False},
            "page_content": {"sha256": "a" * 64, "sampled_bytes": 0, "partial": True, "comparison_eligible": False},
        }}}}}
        with patch.object(reports, "_paragraph", wraps=reports._paragraph) as paragraphs:
            pdf = build_external_posture_pdf(snapshot)
        values = [call.args[0] for call in paragraphs.call_args_list]
        self.assertTrue(pdf.startswith(b"%PDF"))
        self.assertIn(0, values)
        self.assertIn("TLSv1.3 · Example cipher", values)
        self.assertTrue(any("cookie names and values are not retained" in str(value) for value in values))
        self.assertTrue(any("not evidence of defacement" in str(value) for value in values))
        self.assertTrue(any("not an enumeration" in str(value) for value in values))

    def test_builds_pdf_with_saved_dns_and_website_evidence(self):
        report = build_external_posture_pdf(
            {
                "domain": "cybersecuritypilot.org",
                "generated_at": "2026-09-29T15:00:00Z",
                "requested_by": "admin@cybersecuritypilot.org",
                "checks": {
                    "dns": {
                        "run": {
                            "id": 18,
                            "status": "completed_with_warnings",
                            "completed_at": "2026-09-29T14:50:00Z",
                            "actor": "admin@cybersecuritypilot.org",
                            "snapshot": {
                                "records": {
                                    "A": ["192.0.2.10"],
                                    "MX": ["10 mail.example.net."],
                                    "SPF": ["v=spf1 -all"],
                                    "DMARC": ["v=DMARC1; p=reject"],
                                    "DKIM": {"default": []},
                                },
                                "resolver_errors": {"www A": "SERVFAIL"},
                            },
                        },
                        "changes": [],
                    },
                    "web": {
                        "run": {
                            "id": 19,
                            "status": "completed",
                            "completed_at": "2026-09-29T14:55:00Z",
                            "actor": "admin@cybersecuritypilot.org",
                            "snapshot": {
                                "requested_url": "https://cybersecuritypilot.org/",
                                "final_url": "https://cybersecuritypilot.org/",
                                "http_status": 200,
                                "http_reason": "OK",
                                "title": "Cyber Security Pilot",
                                "tls": {"issuer": "Example CA", "valid_until": "2026-11-27T00:00:00Z"},
                                "destination_addresses": ["192.0.2.10"],
                                "security_headers": {"strict-transport-security": "max-age=31536000"},
                                "external_resources": [
                                    {
                                        "vendor": "Google Fonts",
                                        "host": "fonts.googleapis.com",
                                        "resource_types": ["Stylesheet"],
                                        "scheme": "https",
                                    }
                                ],
                            },
                        },
                        "changes": [
                            {
                                "field_path": "http_status",
                                "previous_value": 301,
                                "current_value": 200,
                            }
                        ],
                    },
                },
            }
        )

        self.assertTrue(report.startswith(b"%PDF-"))
        self.assertTrue(report.rstrip().endswith(b"%%EOF"))
        self.assertGreater(len(report), 1800)

    def test_builds_when_no_check_snapshots_exist(self):
        report = build_external_posture_pdf({"domain": "example.org", "checks": {}})

        self.assertTrue(report.startswith(b"%PDF-"))
        self.assertTrue(report.rstrip().endswith(b"%%EOF"))


if __name__ == "__main__":
    unittest.main()


class ScannerResultsReportTests(unittest.TestCase):
    def test_supports_live_and_historical_nmapui_result_shapes(self):
        hosts = [{"ip": "192.0.2.10", "ports": []}]
        self.assertEqual(scanner_result_hosts(hosts), hosts)
        self.assertEqual(scanner_result_hosts({"hosts": hosts, "is_historical": True}), hosts)
        with self.assertRaises(ValueError):
            scanner_result_hosts({"hosts_up": 2})

    def test_builds_saved_scanner_pdf_with_escaped_and_bounded_evidence(self):
        pdf = build_scanner_results_pdf({
            "domain": "example.org",
            "scanner": {"name": "Fixture scanner", "event_id": 1,
                        "event_name": "scan_results", "occurred_at": "2026-09-29T15:00:00Z",
                        "payload": [{"ip": "192.0.2.10", "hostname": "<untrusted>&host",
                                     "ports": [{"port": 22, "protocol": "tcp", "state": "open",
                                                "service": "ssh", "scripts": "<script>" + "\n" * 2000}]}]},
        })
        self.assertTrue(pdf.startswith(b"%PDF-"))
        self.assertGreater(len(pdf), 2000)


class MerakiReportLayoutTests(unittest.TestCase):
    def test_many_switch_ports_render_as_separate_table_rows(self):
        report = build_meraki_security_pdf({"domain": "example.org", "meraki": {
            "organization": {"id": "fixture-org", "name": "Fixture organization"},
            "security_controls": [{"network_id": "fixture-network", "network_name": "Fixture network",
                "control": "Switch port configuration", "status": "complete", "data": [
                    {"portId": str(port), "enabled": True, "type": "access", "vlan": 10,
                     "poeEnabled": True, "accessPolicyType": "Open"} for port in range(1,61)]}],
            "summary": {"switch_network_count": 1, "switch_device_count": 1}},
            "meraki_comparison": {"baseline": False, "previous_report_id": 1,
                "changes": [{"network_id": "fixture-network", "control": "Switch port configuration"}],
                "coverage_changes": []}})
        self.assertTrue(report.startswith(b"%PDF-"))
        self.assertGreater(len(report), 3000)


class ScannerRunReportTests(unittest.TestCase):
    def test_phase_labels_are_readable_and_unknown_phases_retained(self):
        self.assertEqual(scanner_phase_label("deep_scan_results"), "Detailed scan results")
        self.assertEqual(scanner_phase_label("new_saved_phase"), "new saved phase")

    def test_run_pdf_preserves_summary_and_result_phases(self):
        pdf = build_scanner_results_pdf({"scanner": {
            "name": "Fixture", "source_job_id": "fixture-run",
            "run": {"status": "completed"}, "events": [
                {"id": 1, "event_name": "job_status", "payload": {"status": "running"}},
                {"id": 2, "event_name": "quickscan_results", "payload": {"total_ips": 1, "hosts_up": 1, "time_taken": 0.5}},
                {"id": 3, "event_name": "deep_scan_results", "payload": [{"ip": "127.0.0.1", "ports": [{"port": 80, "protocol": "tcp", "state": "open"}]}]},
                {"id": 4, "event_name": "job_status", "payload": {"status": "completed"}},
            ]}})
        self.assertTrue(pdf.startswith(b"%PDF"))

    def test_run_without_results_generates_honest_history_report(self):
        pdf = build_scanner_results_pdf({"scanner": {"run": {"status": "interrupted"}, "events": [{"id": 1, "event_name": "job_status", "payload": {"status": "interrupted"}}]}})
        self.assertTrue(pdf.startswith(b"%PDF"))

    def test_run_report_includes_vulnerability_references_and_errors(self):
        from unittest.mock import patch
        from daedalus import reports
        snapshot = {"scanner": {"run": {"status": "completed"}, "events": [
            {"id": 1, "event_name": "cve_array", "payload": [{"reference": "CVE-fixture-123", "host": "127.0.0.1"}]},
            {"id": 2, "event_name": "deep_scan_error", "payload": {"message": "fixture incomplete service scan"}},
        ]}}
        with patch("daedalus.reports._paragraph", wraps=reports._paragraph) as rendered:
            pdf = build_scanner_results_pdf(snapshot)
        self.assertTrue(pdf.startswith(b"%PDF"))
        text = "\n".join(str(call.args[0]) for call in rendered.call_args_list)
        self.assertIn("CVE-fixture-123", text)
        self.assertIn("fixture incomplete service scan", text)
        self.assertIn("do not independently establish", text)

    def test_run_report_avoids_duplicate_host_service_info_and_empty_cve_page(self):
        from unittest.mock import patch
        from daedalus import reports
        line = "OS: Mac OS X; CPE: cpe:/o:apple:mac_os_x"
        snapshot = {"scanner": {"run": {"status": "completed"}, "events": [
            {"id": 1, "event_name": "deep_scan_results", "payload": [
                {"ip": "127.0.0.1", "service_info": [line], "cves": [], "ports": []},
            ]},
            {"id": 2, "event_name": "service_info", "payload": {"target": "127.0.0.1", "line": line}},
            {"id": 3, "event_name": "cve_array", "payload": {"target": "127.0.0.1", "cve_array": []}},
        ]}}
        with patch("daedalus.reports._paragraph", wraps=reports._paragraph) as rendered:
            pdf = build_scanner_results_pdf(snapshot)
        values = [str(call.args[0]) for call in rendered.call_args_list]
        self.assertTrue(pdf.startswith(b"%PDF"))
        self.assertEqual(sum(line in value for value in values), 1)
        self.assertNotIn("Additional scanner evidence", values)
