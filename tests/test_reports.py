import unittest
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import KeepTogether, LongTable

from daedalus.reports import (
    _change_field_label,
    _record_value,
    _time_text,
    _tls_valid_at_collection,
    _tls_issuer_text,
    build_external_posture_pdf,
    build_scanner_results_pdf,
    build_meraki_security_pdf,
    scanner_result_hosts,
    scanner_phase_label,
)


class CISEndpointSummaryTests(unittest.TestCase):
    def test_unassessed_categories_show_counts_and_coverage_instead_of_zero_percent(self):
        from unittest.mock import patch
        from daedalus import reports
        snapshot = {'cis': {'summary': {'total':4, 'pass':1, 'fail':1, 'manual':1, 'error':1, 'score':25,
            'categories': {'chrome': {'total':2, 'pass':0, 'fail':0, 'manual':1, 'error':1, 'score':0}}}, 'results':[]}}
        with patch.object(reports, '_paragraph', wraps=reports._paragraph) as paragraphs:
            pdf = reports.build_cis_endpoint_pdf(snapshot)
        values = [str(call.args[0]) for call in paragraphs.call_args_list]
        self.assertTrue(pdf.startswith(b'%PDF'))
        self.assertIn('2/4 checks have pass or fail results', values)
        self.assertIn('0 pass · 0 fail · 1 manual · 1 error', values)
        self.assertNotIn('0/2 passed · 0%', values)
        self.assertTrue(any('manual and error results in its denominator' in value for value in values))

    def test_incomplete_category_metadata_does_not_invent_zero_counts(self):
        from unittest.mock import patch
        from daedalus import reports
        with patch.object(reports, '_paragraph', wraps=reports._paragraph) as paragraphs:
            reports.build_cis_endpoint_pdf({'cis': {'summary': {'categories': {'chrome': {}}}}})
        values = [str(call.args[0]) for call in paragraphs.call_args_list]
        self.assertIn('Not reported pass · Not reported fail · Not reported manual · Not reported error', values)
        self.assertNotIn('0%', values)
        self.assertNotIn('0', values)


class ExternalPostureReportTests(unittest.TestCase):
    def test_saved_comparison_details_render_without_changing_legacy_reports(self):
        from daedalus import reports
        styles = {"small": getSampleStyleSheet()["Normal"]}
        base = {"id": 20, "check_type": "dns", "status": "completed", "change_count": 0}

        def labels(run):
            story = []
            reports._append_run_line(story, run, styles)
            return [item.getPlainText() for item in story if hasattr(item, "getPlainText")]

        self.assertEqual(len(labels(base)), 1)
        baseline = labels({**base, "comparison_context": {"schema_version": 1, "previous_run_id": None}})
        self.assertIn("baseline established", baseline[-1])
        for check_type in ("dns", "web"):
            comparison = labels({**base, "check_type": check_type,
                "comparison_context": {"schema_version": 1, "previous_run_id": 10}})
            self.assertIn("run #10", comparison[-1])
            self.assertIn("0 recorded evidence", comparison[-1])
            self.assertIn("not incident verdicts", comparison[-1])
        for context in (None, {}, {"schema_version": True, "previous_run_id": 10},
                        {"schema_version": 1, "previous_run_id": True},
                        {"schema_version": 1, "previous_run_id": 20}):
            with self.subTest(context=context):
                self.assertIn("not recorded", labels({**base, "comparison_context": context})[-1])
        for count in (None, True, -1, "0"):
            self.assertIn("Unknown count", labels({**base, "change_count": count,
                "comparison_context": {"schema_version": 1, "previous_run_id": 10}})[-1])
        for check_type in ("web-active", "nikto"):
            self.assertEqual(len(labels({**base, "check_type": check_type,
                "comparison_context": {"schema_version": 1, "previous_run_id": 10}})), 1)

    def test_domain_history_renders_saved_evidence_and_qualification(self):
        from unittest.mock import patch
        from daedalus import reports
        snapshot = {"domain": "example.org", "checks": {"dns": {"run": {"id": 1, "status": "completed", "snapshot": {
            "registration_observations": {"state": "observed", "protocol": "rdap", "collection_partial": True,
                "registrars": ["Example Registrar <review>"], "nameservers": ["ns.example.org"],
                "events": [{"action": "expiration", "date": "2027-01-01T00:00:00Z"}], "source_url": "https://rdap.example.org/domain/example.org"},
            "certificate_transparency": {"state": "observed", "provider": "crt.sh", "scope": "domain_and_subdomains",
                "collection_partial": True, "subdomain_query_error_type": "TimeoutError", "entries": [
                    {"id": 42, "issuer": "Example CA <public>", "dns_names": ["example.org", "www.example.org"],
                     "not_before": "2026-01-01T00:00:00Z", "not_after": "2027-01-01T00:00:00Z"}]},
        }}}}}
        with patch.object(reports, "_paragraph", wraps=reports._paragraph) as paragraphs:
            pdf = build_external_posture_pdf(snapshot)
        values = [str(call.args[0]) for call in paragraphs.call_args_list]
        self.assertTrue(pdf.startswith(b"%PDF-"))
        self.assertIn("Partial", values)
        self.assertIn("TimeoutError", values)
        self.assertIn("Expiration", values)
        self.assertTrue(any("42" in value and "Example CA" in value for value in values))
        self.assertTrue(any("does not verify workspace ownership" in value for value in values))
        self.assertTrue(any("did not verify certificate log proofs" in value for value in values))

    def test_unavailable_domain_history_never_claims_no_certificates_or_no_registration(self):
        from unittest.mock import patch
        from daedalus import reports
        with patch.object(reports, "_paragraph", wraps=reports._paragraph) as paragraphs:
            build_external_posture_pdf({"checks": {"dns": {"run": {"snapshot": {
                "registration_observations": {"state": "unavailable", "error_type": "TimeoutError"},
                "certificate_transparency": {"state": "unavailable", "error_code": "provider_http_error"},
            }}}}})
        values = [str(call.args[0]) for call in paragraphs.call_args_list]
        self.assertEqual(values.count("Unavailable"), 2)
        self.assertIn("provider_http_error", values)
        self.assertFalse(any("No certificate entries were retained" in value for value in values))

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
            "web": {"run": {"id": 8, "status": "completed", "completed_at": "2026-10-02T23:23:01Z", "snapshot": {
                "http_status": 200,
                "tls": {"valid_from": "2026-09-01T00:00:00Z", "valid_until": "2026-11-01T00:00:00Z"},
            }}, "changes": []},
        }}
        with patch.object(reports, "_paragraph", wraps=reports._paragraph) as paragraphs:
            pdf = build_external_posture_pdf(snapshot)

        values = [str(call.args[0]) for call in paragraphs.call_args_list]
        self.assertTrue(pdf.startswith(b"%PDF-"))
        self.assertIn("DNS AND EMAIL", values)
        self.assertIn("RECORDED DIFFERENCES", values)
        self.assertIn("1", values)
        self.assertTrue(any("TLS certificate valid at collection" in value for value in values))
        self.assertTrue(any("does not calculate a combined security score" in value for value in values))

    def test_tls_coverage_uses_collection_time_and_missing_times_stay_unknown(self):
        tls = {"valid_from": "2026-09-01T00:00:00Z", "valid_until": "2026-11-01T00:00:00Z"}
        self.assertIs(_tls_valid_at_collection(tls, {"completed_at": "2026-10-02T23:23:01Z"}), True)
        self.assertIs(_tls_valid_at_collection(tls, {"completed_at": "2026-11-02T00:00:00Z"}), False)
        self.assertIsNone(_tls_valid_at_collection(tls, {}))
        self.assertEqual(_change_field_label("page_content.sampled_bytes"), "Page content size")
        self.assertEqual(_change_field_label("records.WWW_A"), "DNS record www A")

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
    def test_scanner_pdf_uses_template_renderer_without_alternate_format(self):
        from unittest.mock import patch
        from daedalus import reports
        snapshot = {"scanner": {"original_xml": "fixture"}}
        with patch('daedalus.scanner_report_template.render_standardized_scanner_pdf', return_value=b'fixture-result') as renderer:
            self.assertEqual(build_scanner_results_pdf(snapshot), b'fixture-result')
        renderer.assert_called_once_with(snapshot)
        self.assertFalse(hasattr(reports, '_build_legacy_scanner_evidence_pdf'))

    def test_supports_live_and_historical_nmapui_result_shapes(self):
        hosts = [{"ip": "192.0.2.10", "ports": []}]
        self.assertEqual(scanner_result_hosts(hosts), hosts)
        self.assertEqual(scanner_result_hosts({"hosts": hosts, "is_historical": True}), hosts)
        with self.assertRaises(ValueError):
            scanner_result_hosts({"hosts_up": 2})


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


class VendorDecisionPDFTests(unittest.TestCase):
    def test_frozen_decisions_include_rationale_and_long_notes_render(self):
        from unittest.mock import patch
        from daedalus import reports
        review={'id':1,'origin':{'host':'cdn.example','scheme':'https','port':None},'status':'needs_action','reviewer':'Fixture reviewer','created_at':'2026-10-04T09:50:33Z','note':'<script>literal rationale</script> '+('Long review rationale. '*85)}
        snapshot={'checks':{'web':{'run':{'id':54,'status':'completed','snapshot':{'http_status':200}},'vendor_reviews':{'run_id':54,'security_assessment':False,'latest':[review],'history':[review],'history_truncated':True}}}}
        with patch.object(reports,'_paragraph',wraps=reports._paragraph) as paragraphs:
            pdf=reports.build_external_posture_pdf(snapshot)
        values=[str(call.args[0]) for call in paragraphs.call_args_list]
        self.assertTrue(pdf.startswith(b'%PDF'))
        self.assertIn(review['note'],values)
        self.assertTrue(any('not provider security assessments' in value for value in values))
        self.assertTrue(any('latest 100 decision-history entries' in value for value in values))
        self.assertIn('Fixture reviewer',values)


def test_posture_status_items_report_what_needs_attention_and_stay_quiet_when_healthy():
    from daedalus.reports import _posture_attention_items
    healthy = {"dns": {"run": {"snapshot": {"records": {
        "TXT": ["v=spf1 include:_spf.google.com -all"], "DMARC": ["v=DMARC1; p=reject; rua=mailto:a@example.test"],
        "DKIM": {"google": ["v=DKIM1; k=rsa; p=" + "A" * 400]}}, "resolver_errors": {}}}},
        "web": {"run": {"snapshot": {"http_status": 200, "tls": {}, "security_headers": {"hsts": "x"}}}}}
    assert _posture_attention_items(healthy, None) == []
    broken = {"dns": {"run": {"snapshot": {"records": {"TXT": [], "DMARC": [], "DKIM": {}},
                               "resolver_errors": {"www A": "SERVFAIL"}}}},
              "web": {"run": {"snapshot": {"http_status": 503, "security_headers": {"hsts": None}}}}}
    levels = dict((text.split(":")[0][:12], level) for level, text in _posture_attention_items(broken, None))
    texts = " ".join(text for _, text in _posture_attention_items(broken, None))
    assert "www A" in texts and "SPF" in texts and "DMARC" in texts and "503" in texts and "header" in texts
    assert any(level == "bad" for level, _ in _posture_attention_items(broken, None))
    assert _posture_attention_items({}, None)[0][0] == "warn"
