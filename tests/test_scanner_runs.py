import json
import unittest
import hashlib
import socket
import threading
import time
import httpx
import uvicorn
from uuid import uuid4
from sqlalchemy import inspect, text
from daedalus import server
from daedalus.models import ScanEvent, ReportJob, AuditLog
from sqlalchemy import select
from unittest.mock import patch
try:
    from . import test_cis_pdf_flow as fixtures
except ImportError:
    import test_cis_pdf_flow as fixtures


class ScannerRunTests(unittest.TestCase):
    setUp = fixtures.CISReportPDFFlowTests.setUp
    tearDown = fixtures.CISReportPDFFlowTests.tearDown
    create_scanner = fixtures.CISReportPDFFlowTests.create_scanner

    def setup_scanner(self):
        self.agent, _ = self.create_scanner()
        self.headers = {"Authorization": "Bearer test-scanner-token"}
        self.job_id = str(uuid4())

    def envelope(self, name="scan_results", payload=None):
        return {"event_name": name, "payload": [] if payload is None else payload,
                "client_event_id": str(uuid4()), "occurred_at": "2026-09-29T14:00:00Z",
                "source_job_id": self.job_id, "source_job_type": "scan"}

    def send(self, envelope):
        return self.client.post(f"/api/agents/{self.agent}/events", headers=self.headers, json=envelope)

    def test_device_status_uses_only_its_enrollment_and_never_returns_token(self):
        self.setup_scanner()
        self.send(self.envelope("job_status", {"status": "completed", "job_type": "scan"}))
        path = f"/api/agents/{self.agent}/client-status"
        response = self.client.get(path, headers=self.headers)
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.headers["cache-control"], "no-store")
        self.assertEqual(response.json()["recent_runs"][0]["source_job_id"], self.job_id)
        self.assertNotIn("test-scanner-token", response.text)
        self.assertNotEqual(self.client.get(path).status_code, 200)
        self.assertNotEqual(self.client.get(f"/api/agents/{self.agent + 999}/client-status", headers=self.headers).status_code, 200)

    def test_device_pdf_access_is_scoped_to_its_scanner_and_workspace(self):
        self.setup_scanner()
        self.send(self.envelope("job_status", {"status": "completed", "job_type": "scan"}))
        xml = b'<nmaprun><runstats><finished elapsed="1"/><hosts up="0" down="0" total="0"/></runstats></nmaprun>'
        self.send(self.envelope("scan_xml_chunk", {"target": "192.168.1.1", "sha256": hashlib.sha256(xml).hexdigest(), "byte_count": len(xml), "chunk_count": 1, "chunk_index": 0, "xml": xml.decode()}))
        with patch.object(server, "generate_report_job"):
            report_id = self.client.post(f"/api/agents/{self.agent}/runs/{self.job_id}/pdf").json()["id"]
        status = self.client.get(f"/api/agents/{self.agent}/client-status", headers=self.headers).json()
        self.assertEqual(status["hosted_reports"][0]["id"], report_id)
        path = f"/api/agents/{self.agent}/reports/{report_id}/download"
        self.assertEqual(self.client.get(path, headers=self.headers).status_code, 409)
        self.assertNotEqual(self.client.get(path).status_code, 200)
        artifact = self.root / "device-report.pdf"
        artifact.write_bytes(b"%PDF-1.4\nfixture")
        with self.session_factory() as db:
            job = db.get(ReportJob, report_id)
            job.status = "completed"; job.artifact_path = str(artifact)
            db.commit()
        with patch.object(server, "report_artifact", return_value=artifact):
            response = self.client.get(path, headers=self.headers)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["cache-control"], "no-store")
        self.assertTrue(response.content.startswith(b"%PDF-"))
        with artifact.open("ab") as stream:
            stream.truncate(64 * 1024 * 1024 + 1)
        with patch.object(server, "report_artifact", return_value=artifact):
            self.assertEqual(self.client.get(path, headers=self.headers).status_code, 413)
        artifact.write_bytes(b"%PDF-1.4\nfixture")
        with patch.object(server, "report_artifact", side_effect=ValueError("unavailable")):
            self.assertEqual(self.client.get(path, headers=self.headers).status_code, 404)
        with self.session_factory() as db:
            job = db.get(ReportJob, report_id)
            job.report_snapshot = {"scanner": {"agent_id": self.agent + 999}}
            db.commit()
        self.assertEqual(self.client.get(path, headers=self.headers).status_code, 404)
        self.assertEqual(self.client.get(f"/api/agents/{self.agent}/client-status", headers=self.headers).json()["hosted_reports"], [])
        with self.session_factory() as db:
            job = db.get(ReportJob, report_id)
            job.report_snapshot = {"scanner": {"agent_id": self.agent}}
            job.organization_id += 999
            db.commit()
        self.assertEqual(self.client.get(path, headers=self.headers).status_code, 404)

    def test_latest_assessment_keeps_observations_separate_from_completion(self):
        self.setup_scanner()
        path = f"/api/agents/{self.agent}/assessment"
        self.assertEqual(self.client.get(path).json()["state"], "not_assessed")
        event = self.send(self.envelope("deep_scan_results", {"hosts": [{"ip": "127.0.0.1", "ports": [{"port": 22, "protocol": "tcp", "state": "open"}, {"port": 443, "protocol": "tcp"}]}], "covered_targets": ["127.0.0.1/32"]})).json()
        data = self.client.get(path).json()
        self.assertEqual(data["state"], "attention")
        self.assertEqual(data["observations"]["host_count"], 1)
        self.assertEqual(data["observations"]["open_port_count"], 1)
        self.assertEqual(data["observations"]["unknown_port_state_count"], 1)
        self.assertEqual(data["observations"]["result_event_id"], event["event_id"])
        self.assertFalse(data["observations"]["coverage_complete"])
        self.send(self.envelope("job_status", {"status": "completed", "job_type": "scan"}))
        self.assertEqual(self.client.get(path).json()["state"], "recorded")
        self.send(self.envelope("deep_scan_results", {"hosts": "malformed"}))
        invalid = self.client.get(path).json()
        self.assertIsNone(invalid["observations"])
        self.assertIn("earlier results were not substituted", invalid["reason"])
        self.assertEqual(self.client.get('/api/agents/999999/assessment').status_code, 404)

    def test_assessment_combines_hosts_and_replaces_repeated_host_snapshots(self):
        self.setup_scanner()
        self.send(self.envelope("deep_scan_results", [{"ip": "10.20.0.1", "ports": [{"port": 22, "protocol": "tcp", "state": "open"}]}]))
        self.send(self.envelope("deep_scan_results", [{"ip": "10.20.0.2", "ports": [{"port": 443, "protocol": "tcp", "state": "open"}]}]))
        self.send(self.envelope("deep_scan_results", [{"ip": "10.20.0.1", "ports": []}]))
        data = self.client.get(f"/api/agents/{self.agent}/assessment").json()["observations"]
        self.assertEqual(data["host_count"], 2)
        self.assertEqual(data["open_port_count"], 1)
        self.assertEqual(data["result_event_count"], 3)
        self.assertIsNone(data["covered_targets"])
        self.assertFalse(data["coverage_complete"])

    def test_assessment_does_not_replace_failed_latest_scan_with_old_success(self):
        self.setup_scanner()
        path = f"/api/agents/{self.agent}/assessment"
        self.send(self.envelope("deep_scan_results", {"hosts": [{"ip": "127.0.0.1", "ports": []}]}))
        self.send(self.envelope("job_status", {"status": "completed", "job_type": "scan"}))
        self.job_id = str(uuid4())
        self.send(self.envelope("job_status", {"status": "failed", "job_type": "scan"}))
        data = self.client.get(path).json()
        self.assertEqual(data["run"]["source_job_id"], self.job_id)
        self.assertEqual(data["run"]["status"], "failed")
        self.assertEqual(data["state"], "attention")
        self.assertIsNone(data["observations"])

    def test_assessment_bounds_artifacts_before_read_and_rejects_corruption(self):
        self.setup_scanner()
        path = f"/api/agents/{self.agent}/assessment"
        payload = self.envelope("deep_scan_results", {"hosts": [{"ip": "127.0.0.1", "ports": []}]})
        uploaded = self.client.post(f"/api/agents/{self.agent}/event-artifacts", headers=self.headers, content=json.dumps(payload))
        self.assertEqual(uploaded.status_code, 200)
        with self.session_factory() as db:
            event = db.get(ScanEvent, uploaded.json()["event_id"])
            original_size = event.artifact_size_bytes
            event.artifact_size_bytes = 8 * 1024 * 1024 + 1
            db.commit()
        with patch.object(server, "load_scanner_event_payload", side_effect=AssertionError("Oversized evidence must not be read")):
            data = self.client.get(path).json()
        self.assertIsNone(data["observations"])
        self.assertIn("size limit", data["reason"])
        with self.session_factory() as db:
            event = db.get(ScanEvent, uploaded.json()["event_id"])
            event.artifact_size_bytes = original_size
            db.commit()
            server.scanner_artifact_path(event).write_text("corrupted")
        response = self.client.get(path)
        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.json()["detail"], "Saved scanner evidence is missing or has changed.")

    def test_assessment_metadata_conflict_never_reports_observation_counts(self):
        self.setup_scanner()
        self.send(self.envelope("deep_scan_results", {"hosts": [{"ip": "127.0.0.1", "ports": []}]}))
        with self.session_factory() as db:
            agent = db.get(server.Agent, self.agent)
            db.add(ScanEvent(organization_id=agent.organization_id, agent_id=agent.id,
                source_job_id=self.job_id, source_job_type="report", event_name="report_complete",
                payload={}, created_at=server.utcnow()))
            db.commit()
        data = self.client.get(f"/api/agents/{self.agent}/assessment").json()
        self.assertTrue(data["run"]["group_metadata_conflict"])
        self.assertIsNone(data["observations"])
        self.assertEqual(data["state"], "attention")

    def test_explicit_grouping_legacy_unknown_and_terminal_evidence(self):
        self.setup_scanner()
        self.assertEqual(self.send(self.envelope()).status_code, 200)
        self.send(self.envelope("quick_scan_complete"))
        self.send({"event_name": "scan_results", "payload": []})
        listing = self.client.get(f"/api/agents/{self.agent}/runs").json()
        self.assertEqual(listing["total_runs"], 1)
        self.assertEqual(listing["runs"][0]["event_count"], 2)
        self.assertEqual(listing["runs"][0]["result_count"], 1)
        self.assertEqual(listing["runs"][0]["status"], "unknown")
        event = self.send(self.envelope("job_status", {"status": "completed", "job_type": "scan"})).json()
        detail = self.client.get(f"/api/agents/{self.agent}/runs/{self.job_id}").json()
        self.assertEqual(detail["run"]["status"], "completed")
        self.assertEqual(detail["run"]["status_evidence_event_id"], event["event_id"])
        self.assertEqual(len(detail["events"]), 3)
        self.assertTrue(all(row["source_job_id"] == self.job_id for row in detail["events"]))
        self.send(self.envelope("job_status", {"status": "interrupted", "job_type": "scan"}))
        self.assertEqual(self.client.get(f"/api/agents/{self.agent}/runs/{self.job_id}").json()["run"]["status"], "interrupted")

    def test_grouping_identity_conflicts_and_validation(self):
        self.setup_scanner()
        envelope = self.envelope()
        self.assertEqual(self.send(envelope).status_code, 200)
        self.assertTrue(self.send(envelope).json()["duplicate"])
        self.assertEqual(self.send({**envelope, "source_job_id": str(uuid4())}).status_code, 409)
        self.assertEqual(self.send({**envelope, "source_job_type": "report"}).status_code, 409)
        del envelope["source_job_type"]
        self.assertEqual(self.send(envelope).status_code, 422)
        self.assertEqual(self.send({**envelope, "source_job_id": "not-uuid", "source_job_type": "scan"}).status_code, 422)

    def test_artifact_metadata_dedup_and_scope(self):
        self.setup_scanner()
        envelope = self.envelope(payload=[{"ip": "192.168.1.1", "text": "x" * 520000}])
        endpoint = f"/api/agents/{self.agent}/event-artifacts"
        first = self.client.post(endpoint, headers=self.headers, content=json.dumps(envelope))
        self.assertEqual(first.status_code, 200, first.text)
        self.assertTrue(self.client.post(endpoint, headers=self.headers, content=json.dumps(envelope)).json()["duplicate"])
        changed = self.client.post(endpoint, headers=self.headers, content=json.dumps({**envelope, "source_job_type": "report"}))
        self.assertEqual(changed.status_code, 409)
        detail = self.client.get(f"/api/agents/{self.agent}/runs/{self.job_id}").json()
        self.assertTrue(detail["events"][0]["artifact_download_url"])
        self.client.post("/api/workspaces", json={"name": "Other", "domain": "other-scan-fixture.example"})
        self.assertEqual(self.client.get(f"/api/agents/{self.agent}/assessment").status_code, 404)
        self.assertEqual(self.client.get(f"/api/agents/{self.agent}/runs").status_code, 404)
        self.assertEqual(self.client.get(f"/api/agents/{self.agent}/runs/{self.job_id}").status_code, 404)

    def test_detail_and_list_truncation_do_not_imply_completion(self):
        self.setup_scanner()
        with self.session_factory() as db:
            agent = db.get(server.Agent, self.agent)
            for index in range(205):
                db.add(ScanEvent(organization_id=agent.organization_id, agent_id=agent.id,
                    source_job_id=self.job_id, source_job_type="scan", event_name="scan_feedback",
                    payload={"index": index}, created_at=server.utcnow()))
            for _ in range(21):
                db.add(ScanEvent(organization_id=agent.organization_id, agent_id=agent.id,
                    source_job_id=str(uuid4()), source_job_type="report", event_name="report_complete",
                    payload={}, created_at=server.utcnow()))
            db.commit()
        listing = self.client.get(f"/api/agents/{self.agent}/runs").json()
        self.assertTrue(listing["truncated"])
        self.assertEqual(len(listing["runs"]), 20)
        detail = self.client.get(f"/api/agents/{self.agent}/runs/{self.job_id}").json()
        self.assertTrue(detail["truncated"])
        self.assertEqual(detail["returned_event_count"], 200)
        self.assertEqual(detail["run"]["event_count"], 205)
        self.assertEqual(detail["run"]["status"], "unknown")
        self.assertEqual(detail["events"][0]["payload"]["index"], 5)

    def test_migration_is_additive_repeatable(self):
        with self.engine.begin() as connection:
            connection.execute(text("DROP TABLE scan_events"))
            connection.execute(text("CREATE TABLE scan_events (id INTEGER PRIMARY KEY, agent_id INTEGER, organization_id INTEGER)"))
            server.ensure_scanner_event_columns(connection)
            server.ensure_scanner_event_columns(connection)
            columns = {column["name"] for column in inspect(connection).get_columns("scan_events")}
            self.assertTrue({"source_job_id", "source_job_type"}.issubset(columns))

    def test_malformed_or_conflicting_job_evidence_is_unknown(self):
        self.setup_scanner()
        self.send(self.envelope("job_status", {"status": ["completed"], "job_type": "scan"}))
        self.assertEqual(self.client.get(f"/api/agents/{self.agent}/runs").json()["runs"][0]["status"], "unknown")
        self.send(self.envelope("job_status", {"status": "completed", "job_type": "report"}))
        self.assertEqual(self.client.get(f"/api/agents/{self.agent}/runs").json()["runs"][0]["status"], "unknown")
        self.send({**self.envelope("job_status", {"status": "completed"}), "source_job_type": "report"})
        run = self.client.get(f"/api/agents/{self.agent}/runs").json()["runs"][0]
        self.assertTrue(run["group_metadata_conflict"])
        self.assertEqual(run["status"], "unknown")

    def test_detail_payload_bytes_are_bounded_with_explicit_truncation(self):
        self.setup_scanner()
        with self.session_factory() as db:
            agent = db.get(server.Agent, self.agent)
            for _ in range(10):
                db.add(ScanEvent(organization_id=agent.organization_id, agent_id=agent.id,
                    source_job_id=self.job_id, source_job_type="scan", event_name="scan_results",
                    payload="x" * 500000, created_at=server.utcnow()))
            db.commit()
        detail = self.client.get(f"/api/agents/{self.agent}/runs/{self.job_id}").json()
        self.assertTrue(detail["truncated"])
        self.assertLess(detail["returned_event_count"], 10)
        self.assertLessEqual(len(json.dumps(detail["events"]).encode()), detail["event_byte_limit"])

    def test_run_pdf_freezes_all_phases_summary_results_and_verified_artifact(self):
        self.setup_scanner()
        self.send(self.envelope("quick_scan_start", "started"))
        self.send(self.envelope("quickscan_results", {"total_ips": 2, "hosts_up": 1, "time_taken": 0.4}))
        artifact = self.envelope("deep_scan_results", [{"ip": "192.168.1.1", "evidence": "x" * 520000}])
        response = self.client.post(f"/api/agents/{self.agent}/event-artifacts", headers=self.headers, content=json.dumps(artifact))
        self.assertEqual(response.status_code, 200, response.text)
        self.send(self.envelope("job_status", {"status": "completed", "job_type": "scan"}))
        xml = b'<nmaprun scanner="nmap" args="nmap -sV 192.168.1.1" version="7.98"><host><status state="up"/><address addr="192.168.1.1" addrtype="ipv4"/></host><runstats><finished elapsed="1"/><hosts up="1" down="0" total="1"/></runstats></nmaprun>'
        self.send(self.envelope("scan_xml_chunk", {"target": "192.168.1.1", "sha256": hashlib.sha256(xml).hexdigest(), "byte_count": len(xml), "chunk_count": 1, "chunk_index": 0, "xml": xml.decode()}))
        with patch.object(server, "generate_report_job"):
            queued = self.client.post(f"/api/agents/{self.agent}/runs/{self.job_id}/pdf")
        self.assertEqual(queued.status_code, 200, queued.text)
        self.send(self.envelope("scan_feedback", "later evidence"))
        with self.session_factory() as db:
            job = db.get(ReportJob, queued.json()["id"])
            snapshot = job.report_snapshot["scanner"]
            self.assertEqual(snapshot["run"]["event_count"], 5)
            self.assertEqual(snapshot["run"]["status"], "completed")
            self.assertFalse(snapshot["run"]["truncated"])
            self.assertEqual(snapshot["events"][2]["payload"], artifact["payload"])
            self.assertTrue(snapshot["events"][2]["artifact_sha256"])
            self.assertEqual(len(snapshot["events"]), 5)
            self.assertEqual(job.report_type, "scanner_results")
            self.assertEqual(job.report_snapshot["scanner_report_template"]["stylesheet_sha256"],
                             "687e6ff1522e99a77ba03ddfe367fd098c7eb0c57eb231f3aa370fcf5ad31537")
            from daedalus.scanner_report_template import REPORT_ASSET_SHA256
            self.assertEqual(job.report_snapshot["scanner_report_template"]["asset_sha256"], REPORT_ASSET_SHA256)
            logs = db.scalars(select(AuditLog).where(AuditLog.action == "report.requested")).all()
            self.assertEqual(logs[-1].details["source_job_id"], self.job_id)
            self.assertEqual(logs[-1].details["template_asset_sha256"], REPORT_ASSET_SHA256)

    def test_run_pdf_limits_and_malformed_result_create_no_partial_job(self):
        self.setup_scanner()
        self.send(self.envelope("scan_feedback", "evidence"))
        endpoint = f"/api/agents/{self.agent}/runs/{self.job_id}/pdf"
        with patch.object(server, "MAX_SCANNER_RUN_PDF_EVENTS", 0):
            self.assertEqual(self.client.post(endpoint).status_code, 413)
        with patch.object(server, "MAX_SCANNER_RUN_PDF_BYTES", 1):
            self.assertEqual(self.client.post(endpoint).status_code, 413)
        self.send(self.envelope("scan_results", {"hosts": ["invalid host"]}))
        self.assertEqual(self.client.post(endpoint).status_code, 422)
        with self.session_factory() as db:
            self.assertEqual(db.scalars(select(ReportJob)).all(), [])

    def test_completed_run_without_xml_rejects_pdf_before_queueing(self):
        self.setup_scanner()
        self.send(self.envelope("job_status", {"status": "completed", "job_type": "scan"}))
        response = self.client.post(f"/api/agents/{self.agent}/runs/{self.job_id}/pdf")
        self.assertEqual(response.status_code, 422, response.text)
        self.assertIn("original Nmap XML", response.json()["detail"])
        with self.session_factory() as db:
            self.assertEqual(db.scalars(select(ReportJob)).all(), [])
            self.assertEqual(db.scalars(select(AuditLog).where(AuditLog.action == "report.requested")).all(), [])

    def test_run_pdf_zero_results_scope_and_saved_artifact_corruption(self):
        self.setup_scanner()
        self.send(self.envelope("job_status", {"status": "interrupted", "job_type": "scan"}))
        endpoint = f"/api/agents/{self.agent}/runs/{self.job_id}/pdf"
        with patch.object(server, "generate_report_job"):
            zero = self.client.post(endpoint)
        self.assertEqual(zero.status_code, 422, zero.text)
        with self.session_factory() as db:
            self.assertEqual(db.scalars(select(ReportJob)).all(), [])
        artifact = self.envelope("scan_results", [{"ip": "192.168.1.1"}])
        uploaded = self.client.post(f"/api/agents/{self.agent}/event-artifacts", headers=self.headers, content=json.dumps(artifact))
        with self.session_factory() as db:
            event = db.get(ScanEvent, uploaded.json()["event_id"])
            server.scanner_artifact_path(event).write_text("corrupted")
        self.assertEqual(self.client.post(endpoint).status_code, 409)
        self.client.post("/api/workspaces", json={"name": "Other", "domain": "other-runpdf-fixture.example"})
        self.assertEqual(self.client.post(endpoint).status_code, 404)

    def test_real_http_artifact_run_pdf_roundtrip(self):
        """Use a real ephemeral loopback listener; startup never touches the demo DB."""
        self.setup_scanner()
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        address = listener.getsockname()
        runtime = uvicorn.Server(uvicorn.Config(server.app, host="127.0.0.1",
            port=address[1], lifespan="off", log_level="error", access_log=False))
        thread = threading.Thread(target=runtime.run, kwargs={"sockets": [listener]}, daemon=True)
        thread.start()
        try:
            ready_deadline = time.monotonic() + 5
            while not runtime.started and thread.is_alive() and time.monotonic() < ready_deadline:
                time.sleep(0.01)
            self.assertTrue(runtime.started, "Isolated HTTP listener did not start")
            with httpx.Client(base_url=f"http://127.0.0.1:{address[1]}", timeout=10) as http:
                self.assertEqual(http.post("/dev/login").status_code, 303)
                payload = [{"ip": "192.168.1.1", "ports": [{"port": "443", "protocol": "tcp",
                    "state": "open", "service": "https"}], "evidence": "fixture evidence " * 40000}]
                envelope = self.envelope("deep_scan_results", payload)
                artifact_route = f"/api/agents/{self.agent}/event-artifacts"
                first = http.post(artifact_route, headers=self.headers, json=envelope)
                self.assertEqual(first.status_code, 200, first.text)
                event_id = first.json()["event_id"]
                retry = http.post(artifact_route, headers=self.headers, json=envelope)
                self.assertTrue(retry.json()["duplicate"])
                self.assertEqual(retry.json()["event_id"], event_id)
                conflict = http.post(artifact_route, headers=self.headers,
                    json={**envelope, "source_job_id": str(uuid4())})
                self.assertEqual(conflict.status_code, 409)
                conflict = http.post(artifact_route, headers=self.headers,
                    json={**envelope, "payload": [{"ip": "192.168.1.2"}]})
                self.assertEqual(conflict.status_code, 409)
                status = http.post(f"/api/agents/{self.agent}/events", headers=self.headers,
                    json=self.envelope("job_status", {"status": "completed", "job_type": "scan"}))
                self.assertEqual(status.status_code, 200, status.text)
                runs = http.get(f"/api/agents/{self.agent}/runs").json()
                self.assertEqual(runs["total_runs"], 1)
                self.assertEqual(runs["runs"][0]["source_job_id"], self.job_id)
                self.assertEqual(runs["runs"][0]["source_job_type"], "scan")
                self.assertEqual(runs["runs"][0]["event_count"], 2)
                self.assertEqual(runs["runs"][0]["status"], "completed")
                assessment_response = http.get(f"/api/agents/{self.agent}/assessment")
                self.assertEqual(assessment_response.status_code, 200)
                assessment = assessment_response.json()
                self.assertEqual(assessment["state"], "recorded")
                self.assertEqual(assessment["observations"]["host_count"], 1)
                self.assertEqual(assessment["observations"]["open_port_count"], 1)
                self.assertEqual(assessment["observations"]["result_event_id"], event_id)
                self.assertIsNone(assessment["observations"]["covered_targets"])
                self.assertFalse(assessment["observations"]["coverage_complete"])
                detail = http.get(f"/api/agents/{self.agent}/runs/{self.job_id}").json()
                saved = detail["events"][0]
                canonical = json.dumps(payload, sort_keys=True, ensure_ascii=False,
                    separators=(",", ":"), allow_nan=False).encode()
                digest = hashlib.sha256(canonical).hexdigest()
                self.assertEqual(saved["artifact_sha256"], digest)
                download = http.get(saved["artifact_download_url"])
                self.assertEqual(download.status_code, 200)
                self.assertEqual(hashlib.sha256(download.content).hexdigest(), digest)
                self.assertEqual(download.json(), payload)
                xml = b'<nmaprun scanner="nmap" args="nmap -sV 192.168.1.1" version="7.98"><host><status state="up"/><address addr="192.168.1.1" addrtype="ipv4"/><ports><port portid="443" protocol="tcp"><state state="open"/><service name="https"/></port></ports></host><runstats><finished elapsed="1"/><hosts up="1" down="0" total="1"/></runstats></nmaprun>'
                xml_upload = http.post(f"/api/agents/{self.agent}/events", headers=self.headers,
                    json=self.envelope("scan_xml_chunk", {"target": "192.168.1.1", "sha256": hashlib.sha256(xml).hexdigest(),
                        "byte_count": len(xml), "chunk_count": 1, "chunk_index": 0, "xml": xml.decode()}))
                self.assertEqual(xml_upload.status_code, 200, xml_upload.text)
                queued = http.post(f"/api/agents/{self.agent}/runs/{self.job_id}/pdf")
                self.assertEqual(queued.status_code, 200, queued.text)
                report_id = queued.json()["id"]
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    with self.session_factory() as db:
                        job = db.get(ReportJob, report_id)
                        job_status, job_error = job.status, job.error_summary
                    if job_status in {"completed", "failed"}:
                        break
                    time.sleep(0.02)
                self.assertEqual(job_status, "completed", job_error)
                pdf = http.get(f"/api/reports/{report_id}/download")
                self.assertEqual(pdf.status_code, 200)
                self.assertTrue(pdf.content.startswith(b"%PDF-"))
                with self.session_factory() as db:
                    stored = db.get(ScanEvent, event_id)
                    self.assertEqual(stored.source_job_id, self.job_id)
                    self.assertEqual(stored.source_job_type, "scan")
                    self.assertEqual(hashlib.sha256(server.scanner_artifact_path(stored).read_bytes()).hexdigest(), digest)
                    job = db.get(ReportJob, report_id)
                    frozen = job.report_snapshot["scanner"]
                    self.assertEqual(frozen["events"][0]["payload"], payload)
                    self.assertEqual(frozen["events"][0]["artifact_sha256"], digest)
                    self.assertEqual(frozen["run"]["event_count"], 3)
                    self.assertEqual(job.progress, 100)
        finally:
            runtime.should_exit = True
            thread.join(timeout=5)
            if thread.is_alive():
                runtime.force_exit = True
                thread.join(timeout=2)
            listener.close()
            self.assertFalse(thread.is_alive(), "Isolated HTTP server did not exit")
