import unittest

from daedalus.email_policy import analyze_email_auth
from daedalus.external_checks import compare_snapshots


class DNSComparisonTests(unittest.TestCase):
    def test_failed_lookup_reports_resolver_change_without_record_removal(self):
        previous = {"records": {"WWW_A": ["203.0.113.7"]}, "resolver_errors": {}}
        current = {"records": {"WWW_A": []}, "resolver_errors": {"www A": "SERVFAIL"}}
        self.assertEqual(compare_snapshots(previous, current), [("resolver_errors.www A", None, "unavailable")])

    def test_recovered_lookup_does_not_claim_unobserved_record_change(self):
        previous = {"records": {"WWW_A": []}, "resolver_errors": {"www A": "SERVFAIL"}}
        current = {"records": {"WWW_A": ["203.0.113.7"]}, "resolver_errors": {}}
        self.assertEqual(compare_snapshots(previous, current), [("resolver_errors.www A", "unavailable", None)])

    def test_resolver_error_class_changes_do_not_look_like_dns_changes(self):
        previous = {"records": {"WWW_A": []}, "resolver_errors": {"www A": "SERVFAIL"}}
        current = {"records": {"WWW_A": []}, "resolver_errors": {"www A": "LifetimeTimeout"}}
        self.assertEqual(compare_snapshots(previous, current), [])

    def test_confirmed_empty_answer_is_a_record_removal(self):
        previous = {"records": {"WWW_A": ["203.0.113.7"]}, "resolver_errors": {}}
        current = {"records": {"WWW_A": []}, "resolver_errors": {}}
        self.assertEqual(compare_snapshots(previous, current), [("records.WWW_A", ["203.0.113.7"], [])])

    def test_email_policy_changes_are_saved_and_reported(self):
        previous = {
            "records": {"SPF": ["v=spf1 ~all"], "DMARC": ["v=DMARC1; p=none"]},
            "resolver_errors": {},
        }
        previous["email_authentication_assessment"] = analyze_email_auth(previous["records"], {})
        current = {
            "records": {"SPF": ["v=spf1 -all"], "DMARC": ["v=DMARC1; p=reject"]},
            "resolver_errors": {},
        }
        current["email_authentication_assessment"] = analyze_email_auth(current["records"], {})

        paths = {path for path, _old, _new in compare_snapshots(previous, current)}

        self.assertIn("email_authentication_assessment.spf.policy", paths)
        self.assertIn("email_authentication_assessment.dmarc.effective_policy", paths)
        self.assertIn("records.SPF", paths)
        self.assertIn("records.DMARC", paths)

    def test_first_policy_annotation_does_not_alert_against_legacy_baseline(self):
        records = {"SPF": ["v=spf1 -all"], "DMARC": ["v=DMARC1; p=reject"]}
        previous = {"records": records, "resolver_errors": {}}
        current = {
            **previous,
            "email_authentication_assessment": analyze_email_auth(records, {}),
        }

        self.assertEqual(compare_snapshots(previous, current), [])

    def test_failed_email_lookup_suppresses_policy_removal_churn(self):
        records = {"SPF": ["v=spf1 -all"], "DMARC": ["v=DMARC1; p=reject"]}
        previous = {
            "records": records,
            "resolver_errors": {},
            "email_authentication_assessment": analyze_email_auth(records, {}),
        }
        current_records = {"SPF": [], "DMARC": ["v=DMARC1; p=reject"]}
        current_errors = {"TXT": "SERVFAIL"}
        current = {
            "records": current_records,
            "resolver_errors": current_errors,
            "email_authentication_assessment": analyze_email_auth(current_records, current_errors),
        }

        self.assertEqual(
            compare_snapshots(previous, current),
            [("resolver_errors.TXT", None, "unavailable")],
        )


if __name__ == "__main__":
    unittest.main()
