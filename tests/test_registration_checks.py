import unittest
from unittest.mock import patch

from daedalus.registration_checks import registration_url, registration_evidence, run_registration_check, fetch_json, MAX_JSON_BYTES


class RegistrationChecksTests(unittest.TestCase):
    def document(self):
        return {"objectClassName": "domain", "ldhName": "EXAMPLE.ORG", "nameservers": [{"ldhName": "NS1.EXAMPLE.ORG."}],
                "events": [{"eventAction": "expiration", "eventDate": "2027-01-01T00:00:00Z"}],
                "entities": [{"roles": ["registrar"], "vcardArray": ["vcard", [["fn", {}, "text", "Fixture registrar"], ["email", {}, "text", "private@example.org"]]]},
                             {"roles": ["registrant"], "vcardArray": ["vcard", [["fn", {}, "text", "Private contact"]]]}]}

    def test_bootstrap_selects_longest_matching_suffix_and_https(self):
        data = {"services": [[["org"], ["http://invalid.example/", "https://registry.example/rdap/"]], [["example.org"], ["https://specific.example/"]]]}
        self.assertEqual(registration_url("example.org", data), "https://specific.example/domain/example.org")
        self.assertEqual(registration_url("other.org", data), "https://registry.example/rdap/domain/other.org")
        with self.assertRaises(ValueError):
            registration_url("example.net", data)

    def test_unsafe_bootstrap_urls_are_rejected(self):
        for url in ["http://registry.example/", "https://u:p@registry.example/", "https://registry.example:9000/", "https://registry.example/?x=1", "https://registry.example/#x", "https://registry.example/\\path"]:
            with self.subTest(url=url), self.assertRaises(ValueError):
                registration_url("example.org", {"services": [[["org"], [url]]]})

    def test_evidence_retains_registration_metadata_without_contact_data(self):
        result = registration_evidence("example.org", self.document())
        self.assertEqual(result["nameservers"], ["ns1.example.org"])
        self.assertEqual(result["registrars"], ["Fixture registrar"])
        self.assertNotIn("private@example.org", str(result))
        self.assertNotIn("Private contact", str(result))
        self.assertFalse(result["registration_owner_verified"])
        self.assertFalse(result["collection_partial"])

    def test_wrong_domain_or_malformed_collections_cannot_be_observed(self):
        for change in [{"ldhName": "other.org"}, {"objectClassName": "entity"}, {"events": {}}]:
            with self.subTest(change=change), self.assertRaises(ValueError):
                registration_evidence("example.org", {**self.document(), **change})

    def test_collection_limit_is_explicit(self):
        document = self.document()
        document["events"] *= 101
        self.assertTrue(registration_evidence("example.org", document)["collection_partial"])

    def test_missing_and_unreadable_metadata_is_partial_not_confirmed_removal(self):
        from copy import deepcopy
        from daedalus.external_checks import compare_snapshots
        baseline = registration_evidence("example.org", self.document())
        baseline["source_url"] = "https://registry.example/domain/example.org"
        for change in ({"nameservers": [{}]}, {"events": [{"eventAction": "expiration", "eventDate": "invalid"}]},
                       {"entities": [{"roles": ["registrar"], "vcardArray": []}]}, {"entities": []}):
            with self.subTest(change=change):
                current = registration_evidence("example.org", {**self.document(), **change})
                self.assertTrue(current["collection_partial"])
                current["source_url"] = baseline["source_url"]
                paths = [path for path, _, _ in compare_snapshots(
                    {"domain": "example.org", "registration_observations": baseline},
                    {"domain": "example.org", "registration_observations": current})]
                self.assertFalse(set(paths) & {"registration_observations.registrars", "registration_observations.nameservers", "registration_observations.events"})
        document = deepcopy(self.document())
        del document["nameservers"]
        self.assertTrue(registration_evidence("example.org", document)["collection_partial"])

    def test_repeated_events_are_canonicalized(self):
        document = self.document()
        document["events"] *= 2
        self.assertEqual(len(registration_evidence("example.org", document)["events"]), 1)

    def test_failure_is_unavailable_not_empty_registration(self):
        with patch("daedalus.registration_checks.fetch_json", side_effect=TimeoutError):
            result = run_registration_check("example.org")
        self.assertEqual(result["state"], "unavailable")
        self.assertNotIn("registrars", result)

    def test_complete_collection_uses_only_bootstrap_and_domain_service(self):
        with patch("daedalus.registration_checks.fetch_json", side_effect=[{"services": [[["org"], ["https://registry.example/rdap/"]]]}, self.document()]) as fetch:
            result = run_registration_check("example.org")
        self.assertEqual(result["state"], "observed")
        self.assertEqual(fetch.call_count, 2)
        self.assertEqual(result["source_url"], "https://registry.example/rdap/domain/example.org")

    def test_redirect_and_oversize_response_close_connection(self):
        from unittest.mock import MagicMock
        for status, body in [(302, b''), (200, b'x' * (MAX_JSON_BYTES + 1))]:
            connection = MagicMock()
            connection.getresponse.return_value.status = status
            connection.getresponse.return_value.read.return_value = body
            with self.subTest(status=status), patch("daedalus.registration_checks._public_addresses", return_value=["8.8.8.8"]), patch("daedalus.registration_checks._PinnedHTTPSConnection", return_value=connection):
                with self.assertRaises(ValueError):
                    fetch_json("https://registry.example/")
            connection.close.assert_called_once()

class RegistrationComparisonTests(unittest.TestCase):
    def test_event_comparison_uses_instants_and_preserves_saved_values(self):
        from copy import deepcopy
        from daedalus.external_checks import compare_snapshots
        previous = self.snapshot()
        previous["registration_observations"]["events"] = [{"action": "expiration", "date": "2027-01-01T00:00:00Z"}]
        current = deepcopy(previous)
        current["registration_observations"]["events"] = [{"action": "expiration", "date": "2026-12-31T19:00:00-05:00"}] * 2
        self.assertEqual(compare_snapshots(previous, current), [])
        self.assertEqual(previous["registration_observations"]["events"][0]["date"], "2027-01-01T00:00:00Z")
        current["registration_observations"]["events"] = [{"action": "expiration", "date": "2027-01-02T00:00:00Z"}]
        self.assertEqual(compare_snapshots(previous, current)[0][0], "registration_observations.events")
        for date in ("invalid", "2027-01-01T00:00:00"):
            current["registration_observations"]["events"][0]["date"] = date
            self.assertEqual(compare_snapshots(previous, current), [])

    def snapshot(self, registrar="First"):
        return {"domain": "example.org", "records": {}, "registration_observations": {
            "domain": "example.org", "protocol": "rdap", "state": "observed", "collection_partial": False,
            "source_url": "https://registry.example/domain/example.org", "registrars": [registrar], "nameservers": [], "events": []}}

    def test_complete_same_provider_registration_changes_are_compared(self):
        from daedalus.external_checks import compare_snapshots
        self.assertEqual(compare_snapshots(self.snapshot(), self.snapshot("Second")),
                         [("registration_observations.registrars", ["First"], ["Second"])])

    def test_unavailable_partial_foreign_and_different_provider_do_not_claim_registration_removal(self):
        from copy import deepcopy
        from daedalus.external_checks import compare_snapshots
        baseline = self.snapshot()
        for change in [{"state": "unavailable", "registrars": []}, {"collection_partial": True, "registrars": []},
                       {"domain": "other.org", "registrars": []}, {"source_url": "https://other.example/domain/example.org", "registrars": []}]:
            current = deepcopy(baseline)
            current["registration_observations"].update(change)
            with self.subTest(change=change):
                paths = [path for path, _, _ in compare_snapshots(baseline, current)]
                self.assertNotIn("registration_observations.registrars", paths)
                self.assertNotIn("registration_observations.source_url", paths)

    def test_dns_registration_collection_is_explicit_and_stored_in_snapshot(self):
        from daedalus.external_checks import run_dns_check
        from test_dns_collector_observations import FixtureResolver
        with patch("daedalus.external_checks.dns.resolver.Resolver", return_value=FixtureResolver()), patch(
            "daedalus.registration_checks.run_registration_check", return_value=self.snapshot()["registration_observations"]
        ) as registration:
            snapshot = run_dns_check("example.org", include_registration=True)
        registration.assert_called_once_with("example.org")
        self.assertEqual(snapshot["registration_observations"]["registrars"], ["First"])
