import unittest
from unittest.mock import patch
import dns.resolver
from daedalus.domain_verification import has_matching_txt


class DomainVerificationDNSTests(unittest.TestCase):
    def test_absent_records_are_distinct_from_resolver_failures(self):
        for failure in (dns.resolver.NXDOMAIN(), dns.resolver.NoAnswer()):
            with self.subTest(failure=type(failure).__name__), patch('daedalus.domain_verification.dns.resolver.resolve', side_effect=failure):
                self.assertFalse(has_matching_txt('example.org', {'expected'}, lambda token: token))
        for failure in (dns.resolver.NoNameservers(), dns.resolver.LifetimeTimeout()):
            with self.subTest(failure=type(failure).__name__), patch('daedalus.domain_verification.dns.resolver.resolve', side_effect=failure):
                with self.assertRaisesRegex(RuntimeError, 'DNS lookup failed'):
                    has_matching_txt('example.org', {'expected'}, lambda token: token)
