"""Operational activity fixtures; no live scanner, target or service action."""
import copy
from datetime import timedelta
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

import httpx
from sqlalchemy import create_engine, inspect
from daedalus import server
from daedalus.agent import NmapUIBridge
from daedalus.models import Agent
from daedalus.scanner_activity import activity_from_runtime, validated_activity, unknown_activity
try:
    from . import test_cis_pdf_flow as fixtures
except ImportError:
    import test_cis_pdf_flow as fixtures


def runtime_job(progress=42, target="127.0.0.1"):
    return {"sid": "private-session", "job_type": "scan", "status": "running",
            "started_at": "not-a-verified-UTC-date", "details": {"target": target, "progress": progress,
            "command": "private command", "password": "private password"}}


def running_activity():
    return activity_from_runtime({"has_active_jobs": True, "active_jobs": [runtime_job()]})


class ActivityContractTests(unittest.TestCase):
    def test_idle_running_report_and_maintenance_are_independent_observations(self):
        for paused, state in [(False, "idle"), (True, "maintenance")]:
            value = activity_from_runtime({"has_active_jobs": False, "active_jobs": [], "maintenance_active": paused})
            self.assertEqual(value["state"], state)
            self.assertEqual(validated_activity(value), value)
        job = runtime_job()
        job.update(job_type="report", status="cancelling")
        value = activity_from_runtime({"has_active_jobs": True, "active_jobs": [job], "active_job_types": ["report"]})
        self.assertEqual(value["jobs"], [{"job_type": "report", "status": "cancelling", "target": "127.0.0.1", "progress": 42}])
        self.assertNotIn("private", json.dumps(value))
        self.assertNotIn("started_at", json.dumps(value))

    def test_incoherent_missing_and_malformed_runtime_never_establishes_idle(self):
        for body in [None, [], {}, {"active_jobs": []}, {"has_active_jobs": 0, "active_jobs": []},
                     {"has_active_jobs": True, "active_jobs": []}, {"has_active_jobs": False, "active_jobs": [runtime_job()]},
                     {"has_active_jobs": True, "active_jobs": [runtime_job()], "maintenance_active": True},
                     {"has_active_jobs": False, "active_jobs": [], "maintenance_active": []},
                     {"has_active_jobs": True, "active_jobs": [runtime_job()], "active_job_types": ["report"]},
                     {"has_active_jobs": True, "active_jobs": [{**runtime_job(), "status": []}]},
                     {"has_active_jobs": True, "active_jobs": [runtime_job()] * 129}]:
            with self.subTest(body=body):
                self.assertEqual(activity_from_runtime(body), unknown_activity())

    def test_bounded_jobs_and_unsafe_optional_fields_remain_unknown(self):
        value = activity_from_runtime({"has_active_jobs": True, "active_jobs": [runtime_job()] * 9})
        self.assertEqual(value["active_job_count"], 9)
        self.assertEqual(len(value["jobs"]), 8)
        self.assertTrue(value["truncated"])
        self.assertEqual(validated_activity(value), value)
        for progress in [True, -1, 101, float("nan"), float("inf"), "42", 2**5000]:
            self.assertIsNone(activity_from_runtime({"has_active_jobs": True, "active_jobs": [runtime_job(progress)]})["jobs"][0]["progress"])
        for target in ["x" * 256, "bad\nrecord", {"unexpected": "value"}, ""]:
            self.assertIsNone(activity_from_runtime({"has_active_jobs": True, "active_jobs": [runtime_job(target=target)]})["jobs"][0]["target"])

    def test_normalized_telemetry_rejects_coercion_inconsistency_and_extra_fields(self):
        valid = running_activity()
        mutations = [{"schema_version": True}, {"state": []}, {"active_job_count": True}, {"active_job_count": 0},
                     {"truncated": True}, {"jobs": []}, {"extra": "private"}]
        for fields in mutations:
            with self.subTest(fields=fields):
                self.assertIsNone(validated_activity({**valid, **fields}))
        for fields in [{"job_type": []}, {"status": []}, {"target": "bad\rvalue"}, {"progress": True}, {"progress": 2**5000}]:
            self.assertIsNone(validated_activity({**valid, "jobs": [{**valid["jobs"][0], **fields}]}))
        cloned = validated_activity(valid)
        cloned["jobs"][0]["target"] = "changed"
        self.assertEqual(valid["jobs"][0]["target"], "127.0.0.1")


class ActivityProbeTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.bridge = NmapUIBridge({"agent_id": 7, "server": "https://fixture.invalid", "agent_token": "synthetic"},
                                   "http://127.0.0.1:9000", spool_dir=Path(temporary.name))
        self.addCleanup(self.bridge.http.close)

    def test_runtime_read_is_bounded_and_does_not_forward_private_details(self):
        requests = []
        def handle(request):
            requests.append(request)
            return httpx.Response(200, stream=httpx.ByteStream(json.dumps({"has_active_jobs": True, "active_jobs": [runtime_job()]}).encode()))
        actual_client = httpx.Client
        def factory(**kwargs):
            self.assertFalse(kwargs["trust_env"])
            self.assertFalse(kwargs["follow_redirects"])
            return actual_client(transport=httpx.MockTransport(handle), **kwargs)
        with patch("daedalus.agent.httpx.Client", side_effect=factory):
            value = self.bridge._read_nmapui_activity()
        self.assertEqual(value, running_activity())
        self.assertEqual(str(requests[0].url), "http://127.0.0.1:9000/api/runtime/status")
        self.assertEqual(requests[0].method, "GET")

    def test_oversized_redirect_invalid_json_or_unreachable_is_unknown(self):
        responses = [httpx.Response(200, stream=httpx.ByteStream(b" " * (64 * 1024 + 1))), httpx.Response(302, headers={"location": "https://other.invalid"}),
                     httpx.Response(200, stream=httpx.ByteStream(b"[]")), httpx.Response(200, stream=httpx.ByteStream(b"\xff")), httpx.Response(404),
                     httpx.Response(200, stream=httpx.ByteStream(b"unused"), headers={"content-encoding": "gzip"})]
        actual_client = httpx.Client
        for response in responses:
            with self.subTest(code=response.status_code), patch("daedalus.agent.httpx.Client", side_effect=lambda **kw: actual_client(transport=httpx.MockTransport(lambda _: response), **kw)):
                self.assertEqual(self.bridge._read_nmapui_activity(), unknown_activity())
        with patch("daedalus.agent.httpx.Client", side_effect=httpx.ConnectError("fixture")):
            self.assertEqual(self.bridge._read_nmapui_activity(), unknown_activity())

    def test_small_drip_transport_fragments_are_checked_against_total_deadline(self):
        chunks = []
        class Drip(httpx.SyncByteStream):
            def __iter__(self):
                for _ in range(100):
                    chunks.append(b" ")
                    yield b" "
        actual_client = httpx.Client
        with patch("daedalus.agent.httpx.Client", side_effect=lambda **kw: actual_client(transport=httpx.MockTransport(lambda _: httpx.Response(200, stream=Drip())), **kw)), \
                patch("daedalus.agent.time.monotonic", side_effect=[0, 1, 2, 3, 4]):
            self.assertEqual(self.bridge._read_nmapui_activity(), unknown_activity())
        self.assertEqual(len(chunks), 3)

    def test_heartbeat_carries_runtime_observation_without_commands_or_scope_changes(self):
        self.bridge._read_nmapui_health = Mock(return_value={"nmapui_ready": True})
        self.bridge._read_nmapui_activity = Mock(return_value=running_activity())
        self.bridge._request = Mock(return_value=httpx.Response(200, request=httpx.Request("POST", "https://fixture.invalid")))
        with patch("daedalus.agent.discover_connected_networks", return_value=["10.0.0.0/24"]):
            self.bridge._heartbeat()
        payload = self.bridge._request.call_args.kwargs["json"]
        self.assertEqual(payload["nmapui_activity"], running_activity())
        self.assertNotIn("authorized_networks", payload)


class ActivityAPITests(unittest.TestCase):
    setUp = fixtures.CISReportPDFFlowTests.setUp
    tearDown = fixtures.CISReportPDFFlowTests.tearDown
    create_scanner = fixtures.CISReportPDFFlowTests.create_scanner

    def test_current_projection_older_heartbeat_and_scope_preservation(self):
        agent_id, _ = self.create_scanner()
        with self.session_factory() as db:
            approved = list(db.get(Agent, agent_id).authorized_networks)
        path = f"/api/agents/{agent_id}/heartbeat"
        headers = {"Authorization": "Bearer test-scanner-token"}
        response = self.client.post(path, headers=headers, json={"nmapui_connected": True, "nmapui_activity": running_activity()})
        self.assertEqual(response.status_code, 200, response.text)
        row = next(a for a in self.client.get("/api/dashboard").json()["agents"] if a["id"] == agent_id)
        self.assertEqual(row["nmapui_activity"]["state"], "running")
        self.assertEqual(row["nmapui_activity"]["jobs"][0]["progress"], 42)
        self.assertIsNotNone(row["nmapui_activity"]["observed_at"])
        self.assertEqual(row["authorized_networks"], approved)
        self.client.post(path, headers=headers, json={"nmapui_connected": True})
        row = next(a for a in self.client.get("/api/dashboard").json()["agents"] if a["id"] == agent_id)
        self.assertEqual(row["nmapui_activity"], {**unknown_activity(), "observed_at": None})

    def test_stale_disabled_future_and_corrupt_saved_observations_are_unknown(self):
        agent_id, _ = self.create_scanner()
        with self.session_factory() as db:
            agent = db.get(Agent, agent_id)
            agent.nmapui_activity = running_activity()
            now = server.utcnow()
            agent.last_seen_at = now
            agent.nmapui_activity_at = now
            self.assertEqual(server.scanner_activity_projection(agent, now=now)["state"], "running")
            for seen, activity_at, enabled, value in [(now - timedelta(seconds=46), now, True, running_activity()),
                    (now, now - timedelta(seconds=46), True, running_activity()), (now, now + timedelta(seconds=1), True, running_activity()),
                    (now, now, False, running_activity()), (now, now, True, {"state": "idle"}),
                    (now + timedelta(seconds=1), now, True, running_activity())]:
                agent.last_seen_at, agent.nmapui_activity_at, agent.enabled, agent.nmapui_activity = seen, activity_at, enabled, value
                self.assertEqual(server.scanner_activity_projection(agent, now=now)["state"], "unknown")
            agent.last_seen_at, agent.nmapui_activity_at, agent.enabled, agent.nmapui_activity = now, now, True, running_activity()
            agent.nmapui_ready = False
            self.assertEqual(server.scanner_activity_projection(agent, now=now)["state"], "unknown")
            agent.nmapui_ready = True
            agent.nmapui_connected = False
            self.assertEqual(server.scanner_activity_projection(agent, now=now)["state"], "running")

    def test_malformed_heartbeat_is_rejected_without_refreshing_old_activity(self):
        agent_id, _ = self.create_scanner()
        path = f"/api/agents/{agent_id}/heartbeat"
        headers = {"Authorization": "Bearer test-scanner-token"}
        self.client.post(path, headers=headers, json={"nmapui_activity": running_activity()})
        with self.session_factory() as db:
            before = db.get(Agent, agent_id).nmapui_activity_at
        response = self.client.post(path, headers=headers, json={"nmapui_activity": {**running_activity(), "active_job_count": True}})
        self.assertEqual(response.status_code, 422)
        with self.session_factory() as db:
            self.assertEqual(db.get(Agent, agent_id).nmapui_activity_at, before)

    def test_nullable_migration_preserves_legacy_rows_and_is_idempotent(self):
        engine = create_engine("sqlite:///:memory:")
        try:
            with engine.begin() as connection:
                connection.exec_driver_sql("CREATE TABLE agents (id INTEGER PRIMARY KEY)")
                connection.exec_driver_sql("INSERT INTO agents (id) VALUES (1)")
                server.ensure_agent_telemetry_columns(connection)
                server.ensure_agent_telemetry_columns(connection)
                self.assertEqual(connection.exec_driver_sql("SELECT nmapui_activity, nmapui_activity_at FROM agents").one(), (None, None))
                self.assertTrue({"nmapui_activity", "nmapui_activity_at"}.issubset({c["name"] for c in inspect(connection).get_columns("agents")}))
        finally:
            engine.dispose()


class ActivityUIContracts(unittest.TestCase):
    @unittest.skipUnless(shutil.which("node"), "Node required")
    def test_live_activity_progress_and_unknown_are_separate_from_saved_results(self):
        source = (Path(__file__).parents[1] / "src/daedalus/static/js/dashboard.js").read_text()
        helper = source[source.index("  function appendScannerActivity("):source.index("  function makeEventRow(")]
        script = """const assert=require('node:assert/strict');
class Node {constructor(tag){this.tag=tag;this.children=[];this.style={};this.attributes={};this.dataset={};}append(...nodes){for(const n of nodes){if(n.parent)n.parent.children=n.parent.children.filter(x=>x!==n);n.parent=this;this.children.push(n);}}setAttribute(k,v){this.attributes[k]=v;}querySelector(selector){return this.children.find(x=>'.'+x.className===selector);}replaceWith(other){const parent=this.parent;parent.children=parent.children.filter(x=>x!==other);const i=parent.children.indexOf(this);parent.children.splice(i,1,other);other.parent=parent;}}
let agentList=null;
const document={createElement:tag=>new Node(tag),getElementById:id=>id==='agent-list'?agentList:null};
function flatten(n){return [n,...n.children.flatMap(flatten)];}
function card(activity,extra={}){let node=new Node('article');node.dataset.agentId='2';appendScannerActivity(node,{id:2,enabled:true,status:'online',bridge_online:true,nmapui_activity:activity,...extra});return node;}
function texts(node){return flatten(node).map(x=>x.textContent||'').join(' ');}
""" + helper + """
const idle={schema_version:1,state:'idle',active_job_count:0,jobs:[],truncated:false,observed_at:new Date().toISOString()};
assert.ok(texts(card(idle)).includes('Idle · no active jobs observed'));
assert.ok(texts(card({...idle,state:'maintenance'})).includes('new scans and reports are paused'));
const job={job_type:'scan',status:'running',target:'<script>literal</script>',progress:42};
const running={...idle,state:'running',active_job_count:1,jobs:[job]};
let view=card(running);assert.ok(texts(view).includes('Scan · Running · <script>literal</script> · 42% reported'));
let bar=flatten(view).find(x=>x.attributes.role==='progressbar');assert.equal(bar.attributes['aria-valuenow'],'42');
assert.equal(flatten(view).find(x=>x.className==='report-progress-bar').style.width,'42%');
assert.ok(texts(view).includes('idle observation does not confirm that an earlier scan completed'));
assert.ok(texts(card({...running,jobs:[{...job,status:'cancelling',progress:null}]})).includes('Cancellation requested'));
for (const activity of [undefined,{...idle,observed_at:new Date(Date.now()-46000).toISOString()},{...running,active_job_count:0},{...running,jobs:[{...job,progress:true}]},{...running,jobs:[{...job,target:'bad\\nrecord'}]}]) {
 assert.ok(texts(card(activity)).includes('Current activity unknown'));assert.equal(flatten(card(activity)).some(x=>x.attributes.role==='progressbar'),false);
}
assert.ok(texts(card(running,{bridge_online:false,status:'offline'})).includes('scanner bridge offline'));
assert.ok(texts(card(running,{enabled:false,status:'disabled'})).includes('scanner access revoked'));
assert.ok(texts(card(running,{nmapui_ready:false})).includes('Current activity unknown'));
assert.ok(texts(card({...running,active_job_count:9,jobs:Array(8).fill(job),truncated:true})).includes('Showing 8 of 9 active jobs'));
// Editing and a failed refresh preserve the card and control values while old
// runtime observations expire; a new observation updates only that section.
agentList=new Node('div');const editCard=card(running);const input=new Node('input');input.value='10.0.0.111';editCard.append(input);agentList.append(editCard);
editCard.scannerActivityAgent.nmapui_activity={...running,observed_at:new Date(Date.now()-46000).toISOString()};
refreshScannerActivities();assert.ok(texts(editCard).includes('Current activity unknown'));assert.equal(input.value,'10.0.0.111');assert.ok(editCard.children.includes(input));
refreshScannerActivities([{id:2,enabled:true,status:'online',bridge_online:true,nmapui_activity:idle}]);
assert.ok(texts(editCard).includes('Idle · no active jobs observed'));assert.equal(editCard.children.filter(x=>x.className==='scanner-current-activity').length,1);assert.ok(editCard.children.includes(input));
"""
        response = subprocess.run(["node", "-e", script], capture_output=True, text=True)
        self.assertEqual(response.returncode, 0, response.stderr)
        refresh = source[source.index("  function refresh(force)"):source.index("  var addScanner")]
        self.assertLess(refresh.index("refreshScannerActivities();"), refresh.index("fetch(\"/api/dashboard\""))
        self.assertLess(refresh.index("refreshScannerActivities(data.agents);"), refresh.index('document.querySelector(".inline-confirmation")'))
