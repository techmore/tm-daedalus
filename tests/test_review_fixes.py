"""Regression tests for the 2026-10-19 full-repo review (docs/CODE-REVIEW-20261019.md)."""
import unittest
from unittest.mock import Mock, patch

import httpx
from sqlalchemy import func, select

from daedalus import server
from daedalus.agent import local_scan_target_refusal, parse_authorized_networks
from daedalus.models import Agent, EnrollmentToken

try:
    from . import test_agent_bridge as bridge_fixtures
    from . import test_cis_pdf_flow as fixtures
except ImportError:
    import test_agent_bridge as bridge_fixtures
    import test_cis_pdf_flow as fixtures


class LocalScanTargetTests(unittest.TestCase):
    def test_private_targets_are_accepted(self):
        for target in ("10.1.2.3", "192.168.1.0/24", "172.16.0.0/16", "127.0.0.1", "fd00::/112"):
            self.assertIsNone(local_scan_target_refusal(target, parse_authorized_networks([target])), target)

    def test_public_hostname_and_oversized_targets_are_refused(self):
        for target in ("8.8.8.8", "example.com", "10.0.0.0/7", "0.0.0.0/0", "10.0.0.1,8.8.8.8", "2001:db8::/32", "10.0.0.0/8"):
            self.assertIsNotNone(local_scan_target_refusal(target), target)


class BridgeRefusesPublicScanTests(unittest.TestCase):
    setUp = bridge_fixtures.NmapUIBridgeTelemetryTests.setUp
    make_bridge = bridge_fixtures.NmapUIBridgeTelemetryTests.make_bridge

    def test_public_target_is_never_forwarded_to_nmapui(self):
        bridge = self.make_bridge()
        bridge.nmapui_connected.set()
        request = httpx.Request("GET", "https://fixture.example.org/next")
        bridge._request = Mock(return_value=httpx.Response(200, request=request, json={
            "command": {"id": 41, "action": "start_scan", "target": "8.8.8.8"}}))
        bridge.sio.emit = Mock()
        bridge._send_command_result = Mock()
        bridge._run_one_command()
        bridge.sio.emit.assert_not_called()
        self.assertEqual(bridge._send_command_result.call_args.args[:2], (41, "failed"))


class EnrollmentAndUploadLimitTests(unittest.TestCase):
    setUp = fixtures.CISReportPDFFlowTests.setUp
    tearDown = fixtures.CISReportPDFFlowTests.tearDown

    def test_concurrent_enrollment_cannot_reuse_a_single_use_code(self):
        code = self.client.post("/api/enrollment-tokens").json()["code"]
        original = server.workspace_controls_available

        def claim_elsewhere(db, organization):
            # A competing enrollment wins between the used_at check and the claim.
            with self.session_factory() as other:
                token = other.scalar(select(EnrollmentToken))
                token.used_at = server.utcnow()
                other.commit()
            return original(db, organization)

        with patch.object(server, "workspace_controls_available", side_effect=claim_elsewhere):
            response = self.client.post("/api/agents/enroll", json={"code": code, "name": "Race scanner"})
        self.assertEqual(response.status_code, 401, response.text)
        with self.session_factory() as db:
            self.assertEqual(db.scalar(select(func.count(Agent.id)).where(Agent.name == "Race scanner")), 0)

    def test_chunked_cis_upload_is_bounded_without_content_length(self):
        key = self.client.post("/api/cis/api-key").json()["api_key"]

        def body():
            for _ in range(6):
                yield b" " * (1024 * 1024)

        response = self.client.post("/api/cis/report", headers={"X-API-Key": key, "Content-Type": "application/json"}, content=body())
        self.assertEqual(response.status_code, 413, response.text)


if __name__ == "__main__":
    unittest.main()
