import unittest
from unittest.mock import patch

import dns.flags
import dns.message
import dns.name
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.resolver
import dns.rrset

from daedalus.external_checks import compare_snapshots, run_dns_check
from daedalus.dns_settings import parse_audit_nameservers


class FixtureResolver:
    def __init__(self, answers=None, failures=None):
        self.answers = answers or {}
        self.failures = failures or {}
        self.calls = []
        self.edns = None

    def use_edns(self, **kwargs):
        self.edns = kwargs

    def resolve(self, name, record_type, *, search):
        self.calls.append((name, record_type, search))
        key = (name.rstrip("."), record_type)
        if key in self.failures:
            raise self.failures[key]
        if key not in self.answers:
            response = dns.message.make_response(dns.message.make_query(name, record_type))
            raise dns.resolver.NoAnswer(response=response)
        values, ttl, authenticated = self.answers[key]
        response = dns.message.make_response(dns.message.make_query(name, record_type))
        if authenticated:
            response.flags |= dns.flags.AD
        response.answer.append(dns.rrset.from_text(name, ttl, "IN", record_type, *values))
        response.index = None  # The synthetic answer was appended after make_response.
        return dns.resolver.Answer(dns.name.from_text(name), dns.rdatatype.from_text(record_type), dns.rdataclass.IN, response)


class DNSCollectorObservationTests(unittest.TestCase):
    def test_nameserver_configuration_is_bounded_and_literal(self):
        self.assertEqual(parse_audit_nameservers('1.1.1.1, 2606:4700:4700::1111 1.1.1.1'), ('1.1.1.1', '2606:4700:4700::1111'))
        self.assertEqual(parse_audit_nameservers(''), ())
        for invalid in ('https://dns.example', 'resolver.example', '0.0.0.0', '224.0.0.1', 'fe80::1%en0', '1.1.1.1 2.2.2.2 3.3.3.3 4.4.4.4'):
            with self.subTest(value=invalid), self.assertRaises(ValueError):
                parse_audit_nameservers(invalid)

    def test_explicit_resolver_is_saved_without_fallback(self):
        resolver = FixtureResolver(failures={('example.test', 'DS'): dns.resolver.NoNameservers()})
        with patch('daedalus.external_checks.dns.resolver.Resolver', return_value=resolver) as factory:
            result = run_dns_check('example.test', nameservers=('1.1.1.1',))
        factory.assert_called_once_with(configure=True)
        self.assertEqual(resolver.nameservers, ['1.1.1.1'])
        self.assertEqual(result['resolver_context'], {'mode': 'explicit', 'nameservers': ['1.1.1.1']})
        self.assertIn('DS', result['resolver_errors'])
        self.assertIsNone(result['dnssec_observations']['delegation_ds_present'])

    def test_resolver_metadata_is_not_a_domain_change(self):
        old = {'records': {'A': ['203.0.113.7']}, 'resolver_context': {'mode': 'system', 'nameservers': ['127.0.0.53']}}
        new = {'records': {'A': ['203.0.113.7']}, 'resolver_context': {'mode': 'explicit', 'nameservers': ['1.1.1.1']}}
        self.assertEqual(compare_snapshots(old, new), [])
        new['records']['A'] = ['203.0.113.8']
        self.assertEqual(compare_snapshots(old, new), [('records.A', ['203.0.113.7'], ['203.0.113.8'])])

    def collect(self, resolver):
        with patch("daedalus.external_checks.dns.resolver.Resolver", return_value=resolver) as factory:
            result = run_dns_check("example.test")
        factory.assert_called_once_with(configure=True)
        return result

    def test_collects_authority_dnssec_and_ttl_without_claiming_local_validation(self):
        resolver = FixtureResolver({
            ("example.test", "A"): (["203.0.113.7"], 120, True),
            ("example.test", "SOA"): (["ns.example.test. admin.example.test. 2026092901 3600 600 86400 300"], 300, True),
            ("example.test", "DS"): (["12345 8 2 " + "AB" * 32], 86400, True),
            ("example.test", "DNSKEY"): (["257 3 8 AQIDBA=="], 3600, True),
        })
        result = self.collect(resolver)
        self.assertEqual(resolver.edns, {"edns": 0, "ednsflags": dns.flags.DO, "payload": 1232})
        self.assertTrue(all(name.endswith(".") and search is False for name, _, search in resolver.calls))
        self.assertIn("2026092901", result["records"]["SOA"][0])
        self.assertEqual(result["query_observations"]["A"]["observed_ttl_seconds"], 120)
        self.assertEqual(result["query_observations"]["A"]["canonical_name"], "example.test")
        self.assertEqual(result["query_observations"]["DS"]["record_count"], 1)
        security = result["dnssec_observations"]
        self.assertEqual(security["assessment"], "records_observed")
        self.assertIs(security["delegation_ds_present"], True)
        self.assertIs(security["zone_dnskey_present"], True)
        self.assertEqual(security["resolver_ad_by_query"], {"DS": True, "DNSKEY": True})
        self.assertIs(security["local_chain_validation_performed"], False)
        self.assertNotIn("validated", security["assessment"])

    def test_confirmed_absence_differs_from_dnssec_lookup_error(self):
        absent = self.collect(FixtureResolver())
        self.assertEqual(absent["dnssec_observations"]["assessment"], "no_records_observed")
        self.assertIs(absent["dnssec_observations"]["delegation_ds_present"], False)
        failed = self.collect(FixtureResolver(failures={
            ("example.test", "DS"): dns.resolver.LifetimeTimeout(timeout=5, errors=[]),
        }))
        self.assertEqual(failed["dnssec_observations"]["assessment"], "lookup_incomplete")
        self.assertIsNone(failed["dnssec_observations"]["delegation_ds_present"])
        self.assertEqual(failed["query_observations"]["DS"]["status"], "error")
        self.assertIsNone(failed["query_observations"]["DS"]["record_count"])
        self.assertIn("DS", failed["resolver_errors"])

    def test_ad_assertion_is_not_inferred_from_dnskey_presence(self):
        result = self.collect(FixtureResolver({
            ("example.test", "DNSKEY"): (["257 3 8 AQIDBA=="], 300, False),
        }))
        self.assertEqual(result["dnssec_observations"]["assessment"], "records_observed")
        self.assertIs(result["dnssec_observations"]["resolver_ad_by_query"]["DNSKEY"], False)
        self.assertIs(result["dnssec_observations"]["local_chain_validation_performed"], False)

    def test_dns_snapshot_includes_email_policy_interpretation(self):
        resolver = FixtureResolver({
            ("example.test", "TXT"): (["\"v=spf1 -all\""], 300, False),
            ("_dmarc.example.test", "TXT"): (["\"v=DMARC1; p=reject; rua=mailto:dmarc@example.test\""], 300, False),
        })

        result = self.collect(resolver)

        self.assertEqual(result["email_authentication_assessment"]["spf"]["policy"], "hard_fail")
        dmarc = result["email_authentication_assessment"]["dmarc"]
        self.assertEqual(dmarc["effective_policy"], "reject")
        self.assertTrue(dmarc["aggregate_reporting_configured"])

    def test_query_metadata_preserves_negative_and_error_states(self):
        response = dns.message.make_response(dns.message.make_query("example.test", "AAAA"))
        response.flags |= dns.flags.AD
        result = self.collect(FixtureResolver(failures={
            ("example.test", "AAAA"): dns.resolver.NoAnswer(response=response),
            ("www.example.test", "A"): dns.resolver.NXDOMAIN(),
        }))
        self.assertEqual(result["query_observations"]["AAAA"]["status"], "no_answer")
        self.assertIs(result["query_observations"]["AAAA"]["resolver_ad"], True)
        self.assertEqual(result["query_observations"]["www A"]["status"], "nxdomain")
        self.assertNotIn("AAAA", result["resolver_errors"])

    def test_cached_ttl_changes_do_not_create_domain_change_alerts(self):
        first = self.collect(FixtureResolver({("example.test", "A"): (["203.0.113.7"], 300, False)}))
        second = self.collect(FixtureResolver({("example.test", "A"): (["203.0.113.7"], 120, False)}))
        self.assertEqual(compare_snapshots(first, second), [])
        third = self.collect(FixtureResolver({("example.test", "A"): (["203.0.113.8"], 120, False)}))
        self.assertIn(("records.A", ["203.0.113.7"], ["203.0.113.8"]), compare_snapshots(second, third))

    def test_soa_serial_change_remains_a_reported_change(self):
        values = ["ns.example.test. admin.example.test. 2026092901 3600 600 86400 300"]
        first = self.collect(FixtureResolver({("example.test", "SOA"): (values, 300, False)}))
        values = ["ns.example.test. admin.example.test. 2026092902 3600 600 86400 300"]
        second = self.collect(FixtureResolver({("example.test", "SOA"): (values, 299, False)}))
        changes = compare_snapshots(first, second)
        self.assertEqual([path for path, _, _ in changes], ["records.SOA"])

    def test_dnssec_timeout_and_recovery_only_report_lookup_availability(self):
        first = self.collect(FixtureResolver({
            ("example.test", "DS"): (["12345 8 2 " + "AB" * 32], 300, True),
        }))
        failed = self.collect(FixtureResolver(failures={
            ("example.test", "DS"): dns.resolver.LifetimeTimeout(timeout=5, errors=[]),
        }))
        self.assertEqual(compare_snapshots(first, failed),
                         [("resolver_errors.DS", None, "unavailable")])
        self.assertEqual(compare_snapshots(failed, first),
                         [("resolver_errors.DS", "unavailable", None)])

    def test_dnssec_failure_does_not_hide_independent_dnskey_removal(self):
        first = self.collect(FixtureResolver({
            ("example.test", "DNSKEY"): (["257 3 8 AQIDBA=="], 300, False),
        }))
        second = self.collect(FixtureResolver(failures={
            ("example.test", "DS"): dns.resolver.LifetimeTimeout(timeout=5, errors=[]),
        }))
        paths = {path for path, _, _ in compare_snapshots(first, second)}
        self.assertIn("records.DNSKEY", paths)
        self.assertIn("dnssec_observations.zone_dnskey_present", paths)
        self.assertNotIn("dnssec_observations.assessment", paths)


if __name__ == "__main__":
    unittest.main()
