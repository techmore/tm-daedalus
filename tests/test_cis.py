import unittest

from daedalus.cis import (
    CISDataError,
    apply_profile_coverage_limits,
    bind_report_to_profile,
    load_macos26_starter_profiles,
    load_starter_profile,
    normalize_cis_report,
    profile_checksum,
    validate_profile,
)
from daedalus.reports import build_cis_endpoint_pdf


class CISProfileTests(unittest.TestCase):
    def test_approved_login_message_is_preserved_and_changes_profile_checksum(self):
        from copy import deepcopy
        profile = {'name': 'Approved message', 'version': '1', 'platform': 'macos', 'checks': [
            {'id': 'login', 'category': 'macos', 'description': 'Login message',
             'rule_id': 'system_settings_loginwindow_loginwindowtext_enable',
             'expected_login_message': '  Organization warning\nAuthorized use only  '}]}
        valid = validate_profile(profile)
        self.assertEqual(valid['checks'][0]['expected_login_message'], profile['checks'][0]['expected_login_message'])
        changed = deepcopy(valid)
        changed['checks'][0]['expected_login_message'] = 'Other approved message'
        self.assertNotEqual(profile_checksum(valid), profile_checksum(changed))
        for value in (None, False, 1, [], '', '   ', 'x\x00', 'x\x7f', '\ud800', 'é' * 1025):
            bad = deepcopy(profile)
            bad['checks'][0]['expected_login_message'] = value
            with self.subTest(value=repr(value)), self.assertRaises(CISDataError):
                validate_profile(bad)
        for field, value in (('rule_id', 'other_rule'), ('category', 'chrome')):
            bad = deepcopy(profile)
            bad['checks'][0][field] = value
            with self.assertRaises(CISDataError):
                validate_profile(bad)
        bad = deepcopy(profile)
        bad['platform'] = 'multi'
        with self.assertRaises(CISDataError):
            validate_profile(bad)

    def test_distributed_alignment_document_matches_project_copy(self):
        from pathlib import Path
        root = Path(__file__).resolve().parents[1]
        self.assertEqual((root / 'CIS-MACOS26-ALIGNMENT.md').read_bytes(),
                         (root / 'clients/csp-cis-audit/CIS-MACOS26-ALIGNMENT.md').read_bytes())

    def test_bundled_csp_starter_profile_has_all_check_categories(self):
        profile = load_starter_profile()
        categories = {category: 0 for category in ("macos", "chrome", "safari")}
        for check in profile["checks"]:
            categories[check["category"]] += 1

        self.assertEqual(profile["name"], "CSP macOS & Browser Baseline")
        self.assertEqual(categories, {"macos": 98, "chrome": 33, "safari": 23})
        self.assertEqual(len(profile_checksum(profile)), 64)

    def test_bundled_macos26_profiles_keep_references_and_leave_rules_without_local_checks_manual(self):
        level1, level2 = load_macos26_starter_profiles()

        self.assertEqual([len(level1["checks"]), len(level2["checks"])], [100, 119])
        from scripts.build_cis_macos26_profiles import SUPPORTED_RULE_IDS
        audit_evidence_rules = {
            "audit_files_owner_configure", "audit_files_group_configure", "audit_files_mode_configure",
            "audit_folder_owner_configure", "audit_folder_group_configure", "audit_folders_mode_configure",
            "audit_acls_files_configure", "audit_acls_folders_configure", "audit_control_acls_configure",
        }
        for profile, supported, manual in ((level1, 91, 9), (level2, 105, 14)):
            self.assertEqual(sum(check["rule_id"] in SUPPORTED_RULE_IDS for check in profile["checks"]), supported)
            self.assertEqual(len(profile["checks"]) - supported, manual)
            profile_rule_ids = {check["rule_id"] for check in profile["checks"]}
            self.assertTrue(audit_evidence_rules.issubset(profile_rule_ids))
            self.assertIn("Check coverage depends on the client build", profile["description"])
            self.assertEqual(profile["version"], "1.1.0-r2")
        self.assertTrue(audit_evidence_rules.issubset(SUPPORTED_RULE_IDS))
        managed_safari_rules = {
            "os_safari_advertising_privacy_protection_enable",
            "os_safari_open_safe_downloads_disable",
            "os_safari_prevent_cross-site_tracking_enable",
            "os_safari_show_full_website_address_enable",
            "os_safari_show_status_bar_enabled",
            "os_safari_warn_fraudulent_website_enable",
            "system_settings_guest_access_smb_disable",
        }
        self.assertTrue(managed_safari_rules.issubset(SUPPORTED_RULE_IDS))
        self.assertEqual(len(SUPPORTED_RULE_IDS), 107)
        self.assertEqual(level1["benchmark"]["version"], "1.1.0")
        self.assertEqual(level1["benchmark"]["level"], "1")
        self.assertEqual(level2["benchmark"]["level"], "2")
        self.assertEqual(level1["benchmark"]["source_commit"], level2["benchmark"]["source_commit"])
        self.assertTrue(all(check["rule_id"] == check["id"] for check in level1["checks"] + level2["checks"]))
        self.assertTrue(all(check["category"] == "macos" for check in level1["checks"] + level2["checks"]))
        self.assertTrue(any(check["benchmark_ids"] for check in level1["checks"]))
        self.assertTrue(all("check" not in check for check in level1["checks"] + level2["checks"]))
        self.assertTrue(any(not check["benchmark_ids"] for check in level1["checks"]))

    def test_profile_rejects_duplicate_ids_and_unsupported_categories(self):
        profile = {
            "name": "Small profile",
            "version": "1.0",
            "platform": "macos",
            "checks": [
                {"id": "macos_1", "category": "macos", "description": "Check one"},
                {"id": "macos_1", "category": "unsupported", "description": "Check two"},
            ],
        }

        with self.assertRaises(CISDataError):
            validate_profile(profile)

    def test_profile_preserves_optional_rule_and_benchmark_metadata(self):
        profile = validate_profile({
            "name": "Tahoe subset",
            "version": "1.1.0",
            "platform": "macos",
            "benchmark": {"name": "CIS Tahoe", "version": "1.1.0", "level": "1"},
            "checks": [{
                "id": "system_settings_firewall_enable",
                "rule_id": "system_settings_firewall_enable",
                "benchmark_ids": ["2.2.1"],
                "category": "macos",
                "description": "Enable Application Firewall",
            }],
        })

        self.assertEqual(profile["benchmark"]["level"], "1")
        self.assertEqual(profile["checks"][0]["rule_id"], "system_settings_firewall_enable")
        self.assertEqual(profile["checks"][0]["benchmark_ids"], ["2.2.1"])


class CISReportNormalizationTests(unittest.TestCase):
    def test_filevault_pass_is_manual_until_tahoe_coverage_includes_connected_volumes(self):
        profile = {
            "benchmark": {
                "name": "CIS Apple macOS 26.0 Tahoe Benchmark",
                "version": "1.1.0",
            },
            "checks": [
                {"id": "filevault", "rule_id": "system_settings_filevault_enforce", "category": "macos", "description": "FileVault"},
                {"id": "firewall", "rule_id": "system_settings_firewall_enable", "category": "macos", "description": "Firewall"},
            ],
        }
        report = normalize_cis_report({
            "timestamp": "2026-10-02T10:00:00Z",
            "device_uuid": "coverage-guard",
            "results": [
                {"id": "filevault", "category": "macos", "description": "FileVault", "status": "pass", "details": "FileVault is On."},
                {"id": "firewall", "category": "macos", "description": "Firewall", "status": "pass", "details": "Enabled."},
            ],
        })

        bind_report_to_profile(report, profile)
        apply_profile_coverage_limits(report, profile)

        filevault = next(result for result in report["results"] if result["id"] == "filevault")
        self.assertEqual(filevault["status"], "manual")
        self.assertIn("connected drives and volumes", filevault["details"])
        self.assertEqual(report["summary"]["pass"], 1)
        self.assertEqual(report["summary"]["manual"], 1)
        self.assertEqual(report["summary"]["score"], 50.0)
        self.assertEqual(report["summary"]["assessment_coverage"], 50.0)

    def test_filevault_coverage_guard_does_not_change_other_benchmarks_or_failures(self):
        result = {"rule_id": "system_settings_filevault_enforce", "status": "fail", "details": "FileVault is Off."}
        report = {
            "results": [result],
            "summary": {"score": 0.0, "fail": 1, "pass": 0, "manual": 0, "error": 0, "total": 1},
        }
        apply_profile_coverage_limits(report, {"benchmark": {"name": "Other Benchmark", "version": "1.1.0"}})
        self.assertEqual(result["status"], "fail")
        self.assertEqual(report["summary"]["fail"], 1)

    def test_assessment_coverage_does_not_treat_manual_or_error_as_assessed(self):
        report = normalize_cis_report({
            "device_uuid": "coverage-fixture",
            "report_info": {"timestamp": "2026-09-29T10:00:00Z"},
            "summary": {"score": 100, "assessment_coverage": 100},
            "results": [
                {"id": str(index), "category": "macos", "description": status,
                 "status": status, "details": "fixture"}
                for index, status in enumerate(("pass", "fail", "manual", "error"))
            ],
        })
        self.assertEqual(report["summary"]["assessed"], 2)
        self.assertEqual(report["summary"]["assessment_coverage"], 50.0)
        self.assertEqual(report["summary"]["score"], 25.0)

    def test_accepts_existing_csp_payload_and_minimizes_sensitive_device_fields(self):
        normalized = normalize_cis_report(
            {
                "api_key": "body-key-must-not-be-persisted",
                "domain": "spoofed.example",
                "device_uuid": "SERIAL-PRIVATE-1234",
                "report_id": "SERIAL-PRIVATE-1234-2026-09-29T10:00:00Z",
                "report_info": {
                    "timestamp": "2026-09-29T10:00:00Z",
                    "cis_benchmark_version": "1.0.0",
                },
                "system_info": {
                    "hostname": "CSP-Mac",
                    "serial_number": "SERIAL-PRIVATE-1234",
                    "os_version": "macOS 15",
                    "ip_addresses": ["10.20.30.40"],
                },
                "results": [
                    {
                        "id": "macos_1",
                        "rule_id": "system_settings_firewall_enable",
                        "benchmark_ids": ["2.2.1"],
                        "category": "macos",
                        "description": "Ensure firewall is enabled",
                        "status": "pass",
                        "details": "Path /Users/Alice/Library; ip=10.20.30.40; api_key=hidden-value",
                    },
                    {
                        "id": "chrome_1",
                        "category": "chrome",
                        "description": "Ensure updates are enabled",
                        "status": "fail",
                        "details": "Setting is disabled",
                    },
                ],
            },
            api_key="hidden-value",
        )

        self.assertEqual(normalized["device_name"], "CSP-Mac")
        self.assertNotIn("serial_number", normalized)
        self.assertNotIn("ip_addresses", normalized)
        self.assertEqual(normalized["summary"]["score"], 50.0)
        self.assertEqual(normalized["summary"]["categories"]["macos"]["pass"], 1)
        details = normalized["results"][0]["details"]
        self.assertNotIn("Alice", details)
        self.assertNotIn("10.20.30.40", details)
        self.assertNotIn("hidden-value", details)
        self.assertEqual(normalized["profile_version"], "1.0.0")
        self.assertEqual(normalized["results"][0]["rule_id"], "system_settings_firewall_enable")
        self.assertEqual(normalized["results"][0]["benchmark_ids"], ["2.2.1"])

    def test_accepts_nested_swift_report_result_shape(self):
        normalized = normalize_cis_report({
            "timestamp": "2026-09-29T10:00:00Z",
            "systemInfo": {"serialNumber": "private-serial", "hostname": "Mac", "osVersion": "15.0"},
            "summary": {"complianceScore": 100},
            "results": [
                {
                    "check": {"id": "safari_1", "category": "safari", "description": "A Safari check"},
                    "status": "manual",
                    "details": "Review required",
                }
            ],
        })

        self.assertEqual(normalized["device_identifier"], "private-serial")
        self.assertEqual(normalized["platform"], "browser")
        self.assertEqual(normalized["summary"]["manual"], 1)


class CISReportPDFTests(unittest.TestCase):
    def test_builds_workspace_themed_pdf_with_snapshot_and_status_changes(self):
        report = build_cis_endpoint_pdf({
            "domain": "example.org",
            "organization_name": "Example Workspace",
            "requested_by": "admin@example.org",
            "cis": {
                "device_name": "CSP-Mac",
                "platform": "macos",
                "os_version": "macOS 15",
                "profile_name": "CSP baseline",
                "profile_version": "1.0.0",
                "collected_at": "2026-09-29T12:00:00Z",
                "summary": {
                    "total": 2, "pass": 1, "fail": 1, "manual": 0, "error": 0,
                    "score": 50.0,
                    "categories": {"macos": {"total": 2, "pass": 1, "fail": 1, "manual": 0, "error": 0, "score": 50.0}},
                },
                "results": [
                    {"id": "macos_1", "category": "macos", "description": "Firewall enabled", "status": "pass", "details": "Enabled"},
                    {"id": "macos_2", "category": "macos", "description": "Automatic updates", "status": "fail", "details": "Disabled"},
                ],
                "changes": [{
                    "check_id": "macos_2", "previous_status": "pass", "current_status": "fail",
                    "detected_at": "2026-09-29T12:00:00Z",
                }],
            },
        })

        self.assertTrue(report.startswith(b"%PDF-"))
        self.assertTrue(report.rstrip().endswith(b"%%EOF"))
        self.assertGreater(len(report), 1_800)


if __name__ == "__main__":
    unittest.main()
