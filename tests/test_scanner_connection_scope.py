import unittest
from types import SimpleNamespace
from unittest.mock import patch

from daedalus import server


class ScannerConnectionScopeTests(unittest.TestCase):
    def test_scope_comparison_uses_subnets_and_union_without_granting_permission(self):
        cases = [
            (["192.168.222.0/24"], ["10.20.0.0/24"], "outside"),
            (["10.20.0.0/24"], ["10.20.0.0/16"], "covered"),
            (["10.20.0.0/24"], ["10.20.0.0/25"], "partial"),
            (["10.20.0.0/24"], ["10.20.0.0/25", "10.20.0.128/25"], "covered"),
            (["10.20.0.0/24", "192.168.222.0/24"], ["10.20.0.0/24"], "partial"),
            (["fd00::/64"], ["fd00::/48", "10.20.0.0/24"], "covered"),
            (["fd00::/64"], ["10.20.0.0/24"], "outside"),
            ([], ["10.20.0.0/24"], "unknown"),
            (["10.20.0.0/24"], [], "unassigned"),
            (["invalid"], ["10.20.0.0/24"], "unknown"),
            (["10.20.0.0/24"], ["invalid"], "unknown"),
        ]
        with patch.object(server, "agent_bridge_online", return_value=True):
            for detected, approved, expected in cases:
                with self.subTest(detected=detected, approved=approved):
                    agent = SimpleNamespace(enabled=True, detected_networks=detected[:], authorized_networks=approved[:])
                    self.assertEqual(server.scanner_connection_scope(agent), expected)
                    self.assertEqual(agent.authorized_networks, approved)

    def test_stale_or_revoked_connection_is_unknown(self):
        agent = SimpleNamespace(enabled=True, detected_networks=["10.20.0.0/24"], authorized_networks=["10.20.0.0/24"])
        with patch.object(server, "agent_bridge_online", return_value=False):
            self.assertEqual(server.scanner_connection_scope(agent), "unknown")
        agent.enabled = False
        with patch.object(server, "agent_bridge_online", return_value=True):
            self.assertEqual(server.scanner_connection_scope(agent), "unknown")
