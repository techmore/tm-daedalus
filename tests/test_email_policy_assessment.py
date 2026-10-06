import unittest

from daedalus.email_policy import analyze_email_auth


class EmailPolicyAssessmentTests(unittest.TestCase):
    def test_malformed_error_collection_cannot_establish_policy(self):
        records = {"SPF": ["v=spf1 -all"], "DMARC": ["v=DMARC1; p=reject"]}
        for errors in ([], ["TXT"], "SERVFAIL", 0, False):
            with self.subTest(errors=errors):
                result = analyze_email_auth(records, errors)
                for protocol in ("spf", "dmarc"):
                    self.assertEqual(result[protocol]["status"], "evidence_unavailable")
                    self.assertIsNone(result[protocol]["policy"])
                    self.assertIsNone(result[protocol]["record_count"])

    def test_malformed_saved_evidence_is_unknown_not_absent_or_protected(self):
        for key, protocol, record in (
            ("SPF", "spf", "v=spf1 -all"),
            ("TXT", "spf", "v=spf1 -all"),
            ("DMARC", "dmarc", "v=DMARC1; p=reject"),
        ):
            for value in (None, 0, False, {}, [None], [record, None]):
                with self.subTest(key=key, value=value):
                    assessment = analyze_email_auth({key: value})[protocol]
                    self.assertEqual(assessment["status"], "evidence_unavailable")
                    self.assertIsNone(assessment["record_count"])
                    self.assertIsNone(assessment["policy"])
                    self.assertEqual(assessment["tone"], "neutral")

    def test_string_legacy_evidence_remains_supported(self):
        assessment = analyze_email_auth({"SPF": "v=spf1 -all", "DMARC": "v=DMARC1; p=reject"})
        self.assertEqual(assessment["spf"]["policy"], "hard_fail")
        self.assertEqual(assessment["dmarc"]["effective_policy"], "reject")

    def test_spf_interprets_only_the_first_effective_all_qualifier(self):
        cases = {
            "-all": "hard_fail",
            "~all": "soft_fail",
            "?all": "neutral",
            "+all": "pass_all",
            "all": "pass_all",
        }
        for terminal, expected in cases.items():
            with self.subTest(terminal=terminal):
                result = analyze_email_auth({"SPF": ["v=spf1 include:mail.example " + terminal]}, {})["spf"]
                self.assertEqual(result["status"], "published")
                self.assertEqual(result["policy"], expected)

        ignored_tail = analyze_email_auth({"SPF": ["v=spf1 -all redirect=mail.example"]}, {})["spf"]
        self.assertEqual(ignored_tail["policy"], "hard_fail")

    def test_spf_distinguishes_absent_failed_duplicate_and_delegated_records(self):
        absent = analyze_email_auth({"SPF": [], "TXT": []}, {})["spf"]
        self.assertEqual(absent["status"], "not_published")
        failed = analyze_email_auth({}, {"TXT": "SERVFAIL"})["spf"]
        self.assertEqual(failed["status"], "lookup_failed")
        duplicated = analyze_email_auth({"SPF": ["v=spf1 -all", "v=spf1 ~all"]}, {})["spf"]
        self.assertEqual(duplicated["status"], "multiple_records")
        redirect = analyze_email_auth({"SPF": ["v=spf1 include:mail.example redirect=spf.example"]}, {})["spf"]
        self.assertEqual(redirect["policy"], "redirect_unresolved")
        malformed = analyze_email_auth({"SPF": ["v=spf2 -all"]}, {})["spf"]
        self.assertEqual(malformed["status"], "invalid_record")

    def test_spf_derives_from_legacy_root_txt_records(self):
        assessment = analyze_email_auth({"TXT": ["google-site-verification=x", "v=spf1 -all"]}, {})
        self.assertEqual(assessment["spf"]["policy"], "hard_fail")

    def test_spf_looking_txt_with_leading_space_is_reported_malformed(self):
        assessment = analyze_email_auth({"TXT": [" v=spf1 -all"]}, {})
        self.assertEqual(assessment["spf"]["status"], "invalid_record")
        self.assertEqual(assessment["spf"]["label"], "Malformed record")

    def test_dmarc_interprets_policies_alignment_subdomains_and_reporting(self):
        assessment = analyze_email_auth({"DMARC": [
            "v=DMARC1; p=reject; sp=quarantine; np=none; aspf=s; adkim=r; rua=mailto:dmarc@example.test"
        ]}, {})["dmarc"]
        self.assertEqual(assessment["status"], "published")
        self.assertEqual(assessment["policy"], "reject")
        self.assertEqual(assessment["effective_policy"], "reject")
        self.assertEqual(assessment["effective_subdomain_policy"], "quarantine")
        self.assertEqual(assessment["effective_nonexistent_subdomain_policy"], "none")
        self.assertEqual(assessment["alignment"], {"aspf": "strict", "adkim": "relaxed"})
        self.assertTrue(assessment["aggregate_reporting_configured"])
        self.assertFalse(assessment["test_mode"])

        with_unrelated_txt = analyze_email_auth({"DMARC": [
            "verification=fixture", "v=DMARC1; p=reject"
        ]}, {})["dmarc"]
        self.assertEqual(with_unrelated_txt["status"], "published")
        self.assertEqual(with_unrelated_txt["policy"], "reject")

    def test_dmarc_monitoring_defaults_and_test_mode_reduction(self):
        no_policy = analyze_email_auth({"DMARC": ["v=DMARC1; rua=mailto:dmarc@example.test"]}, {})["dmarc"]
        self.assertEqual(no_policy["policy"], "none")
        self.assertEqual(no_policy["effective_policy"], "none")
        self.assertTrue(no_policy["aggregate_reporting_configured"])

        reject_test = analyze_email_auth({"DMARC": ["v=DMARC1; p=reject; t=y"]}, {})["dmarc"]
        self.assertEqual(reject_test["effective_policy"], "quarantine")
        self.assertEqual(reject_test["effective_subdomain_policy"], "quarantine")
        self.assertIn("Test mode lowers", reject_test["summary"])

        quarantine_test = analyze_email_auth({"DMARC": ["v=DMARC1; p=quarantine; t=y"]}, {})["dmarc"]
        self.assertEqual(quarantine_test["effective_policy"], "none")

    def test_dmarc_distinguishes_absence_failure_multiple_and_malformed(self):
        absent = analyze_email_auth({"DMARC": []}, {})["dmarc"]
        self.assertEqual(absent["status"], "not_published")
        failed = analyze_email_auth({}, {"DMARC": "SERVFAIL"})["dmarc"]
        self.assertEqual(failed["status"], "lookup_failed")
        multiple = analyze_email_auth({"DMARC": ["v=DMARC1; p=none", "v=DMARC1; p=reject"]}, {})["dmarc"]
        self.assertEqual(multiple["status"], "multiple_records")
        malformed = analyze_email_auth({"DMARC": ["p=reject; v=DMARC1"]}, {})["dmarc"]
        self.assertEqual(malformed["status"], "invalid_record")

    def test_removed_legacy_pct_tag_is_disclosed_not_applied(self):
        assessment = analyze_email_auth({"DMARC": ["v=DMARC1; p=reject; pct=0"]}, {})["dmarc"]
        self.assertTrue(assessment["legacy_pct_present"])
        self.assertEqual(assessment["effective_policy"], "reject")
        self.assertIn("legacy pct tag is not applied", assessment["summary"])


if __name__ == "__main__":
    unittest.main()
