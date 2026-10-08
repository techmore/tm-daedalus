#!/usr/bin/env python3
"""Opt-in real packaged scanner smoke; loopback only, no live workspace.

Managed mode installs real user services; use a disposable Linux user only.

The test toolchain executes real Nmap with a single ephemeral listener port,
no DNS/NSE/privilege escalation, and a 15-second host deadline. This validates
transport/lifecycle/evidence rather than the default scan's port coverage.
"""
from __future__ import annotations
import argparse
import hashlib
import io
import json
import os
import re
from pathlib import Path
import secrets
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import zipfile
import xml.etree.ElementTree as ET
from contextlib import closing
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx

REPO = Path(__file__).resolve().parents[1]


def port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def wait_for(predicate, timeout=45, process=None):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process is not None and process.poll() is not None:
            raise RuntimeError("Owned validation process exited before readiness")
        try:
            result = predicate()
            if result:
                return result
        except (httpx.HTTPError, OSError, ValueError, KeyError):
            pass
        time.sleep(.3)
    raise RuntimeError("Timed out waiting for isolated scanner evidence")


def validate_host_evidence(payload, listener_port):
    hosts = payload if isinstance(payload, list) else payload.get("hosts", [])
    matched = [h for h in hosts if h.get("ip") == "127.0.0.1"]
    open_ports = [p for h in matched for p in h.get("ports", [])]
    if not any(str(p.get("port")) == str(listener_port) and p.get("protocol") == "tcp" and p.get("state") == "open" for p in open_ports):
        raise RuntimeError("Persisted actual scan evidence is missing the loopback listener port")
    return matched, open_ports


def validate_run_evidence(detail, event):
    run_id = event.get("source_job_id")
    events = detail.get("events", [])
    run = detail.get("run", {})
    if not run_id or event.get("source_job_type") != "scan" or run.get("source_job_id") != run_id:
        raise RuntimeError("Scanner run identity is missing or inconsistent")
    if detail.get("truncated") or run.get("event_count") != len(events):
        raise RuntimeError("Run history is incomplete")
    if run.get("status") != "completed" or run.get("group_metadata_conflict"):
        raise RuntimeError("Run completion is not confirmed")
    if not any(e.get("id") == event["id"] for e in events) or any(e.get("source_job_id") != run_id for e in events):
        raise RuntimeError("Run history mixed or omitted result evidence")
    evidence = next((e for e in events if e.get("id") == run.get("status_evidence_event_id")), None)
    if not evidence or evidence.get("event_name") != "job_status" or evidence.get("payload", {}).get("status") != "completed":
        raise RuntimeError("Run status lacks saved completion evidence")


def validate_xml_evidence(xml, listener_port):
    document = ET.fromstring(xml)
    for host in document.findall("host"):
        if host.find("status").get("state") != "up":
            continue
        if not any(a.get("addr") == "127.0.0.1" for a in host.findall("address")):
            continue
        if any(p.get("portid") == str(listener_port) and p.get("protocol") == "tcp" and p.find("state").get("state") == "open" for p in host.findall("ports/port")):
            return
    raise RuntimeError("Actual Nmap XML is missing the open loopback listener")


def validate_loopback_comparison_coverage(comparison):
    coverage = comparison.get("coverage", {})
    if coverage.get("comparable") is not True or coverage.get("reasons"):
        raise RuntimeError("Repeated loopback coverage is not confirmed")
    for field in ("previous_targets", "current_targets"):
        if coverage.get(field) != ["127.0.0.1/32"]:
            raise RuntimeError("Comparison coverage extends beyond the loopback command")
    for field in ("previous_run", "current_run"):
        if comparison.get(field, {}).get("covered_targets_source") != "successful_daedalus_single_ip_command":
            raise RuntimeError("Comparison is missing successful single-IP command provenance")


def validate_listener_change(comparison, listener_port):
    """Require the one controlled observation change and exact XML port coverage."""
    validate_loopback_comparison_coverage(comparison)
    expected = {"hosts_added": 0, "hosts_removed": 0, "hosts_not_observed": 0,
                "port_changes": 1, "newly_observed_ports": 0,
                "reported_port_changes": 1, "confirmed_removed_ports": 0}
    if comparison.get("available") is not True or comparison.get("truncated") or comparison.get("counts") != expected:
        raise RuntimeError("Controlled listener change lacks one confirmed open-to-closed observation")
    rows = comparison.get("port_changes", [])
    if (len(rows) != 1 or rows[0].get("host") != "127.0.0.1"
            or rows[0].get("protocol") != "tcp" or str(rows[0].get("port")) != str(listener_port)
            or rows[0].get("change") != "state_service_changed" or rows[0].get("confirmed") is not True
            or rows[0].get("before", {}).get("state") != "open" or rows[0].get("after", {}).get("state") != "closed"):
        raise RuntimeError("Controlled comparison changed another observation")


def validate_closed_listener_xml(xml, listener_port):
    document = ET.fromstring(xml)
    hosts = document.findall("host")
    if len(hosts) != 1 or hosts[0].find("status").get("state") != "up" or not any(
            a.get("addr") == "127.0.0.1" for a in hosts[0].findall("address")):
        raise RuntimeError("Closed-listener scan lacks exact live loopback host evidence")
    scaninfo = document.findall("scaninfo")
    if len(scaninfo) != 1 or scaninfo[0].get("protocol") != "tcp" or scaninfo[0].get("numservices") != "1" or scaninfo[0].get("services") != str(listener_port):
        raise RuntimeError("Closed-listener XML does not prove the exact tested port")
    ports = hosts[0].findall("ports/port")
    extra = hosts[0].findall("ports/extraports")
    explicit = (len(ports) == 1 and not extra and ports[0].get("portid") == str(listener_port)
                and ports[0].get("protocol") == "tcp" and ports[0].find("state").get("state") == "closed")
    aggregate = not ports and len(extra) == 1 and extra[0].get("state") == "closed" and extra[0].get("count") == "1"
    if not (explicit or aggregate) or document.find("runstats/finished").get("exit") != "success":
        raise RuntimeError("Controlled closed-listener XML is incomplete or not closed")


class FixtureHTTPServer(ThreadingHTTPServer):
    def handle_error(self, request, client_address):
        if isinstance(sys.exc_info()[1], (ConnectionResetError, BrokenPipeError)):
            return
        super().handle_error(request, client_address)


class Listener(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"Daedalus loopback fixture\n")
    def log_message(self, *args):
        pass


class BridgeTransport(BaseHTTPRequestHandler):
    """Loopback fixture transport; holds only uploads, never changes product state."""
    def do_GET(self):
        self.forward()

    def do_POST(self):
        self.forward()

    def forward(self):
        if not self.path.startswith('/api/agents/'):
            self.send_error(403)
            return
        upload = self.command == 'POST' and self.path.rsplit('/', 1)[-1] in {'events', 'event-artifacts', 'result'}
        length = int(self.headers.get('Content-Length', '0'))
        if length > 4 * 1024 * 1024:
            self.send_error(413)
            return
        body = self.rfile.read(length)
        if upload and not self.server.uploads_allowed.is_set():
            status, content = 503, b'{"fixture_upload_hold":true}'
        else:
            try:
                response = httpx.request(self.command, self.server.portal + self.path, content=body, headers={key: value for key, value in self.headers.items() if key.lower() not in {'host', 'content-length', 'connection'}}, timeout=10, follow_redirects=False)
                status, content = response.status_code, response.content
            except httpx.HTTPError:
                status, content = 503, b'{}'
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def log_message(self, *args):
        pass


def validate_recovery_evidence(pending, history, run_id, invocations, listener_port):
    if not pending or not any(event.get('source_job_id') == run_id for event in pending) or any(event.get('source_job_id') not in {None, run_id} for event in pending):
        raise RuntimeError('Interrupted bridge spool lacks consistent original run identity')
    saved = {event.get('client_event_id'): event for event in history}
    def instant(value):
        value = datetime.fromisoformat(value.replace('Z', '+00:00'))
        return value.replace(tzinfo=value.tzinfo or timezone.utc).astimezone(timezone.utc)
    for event in pending:
        matches = [item for item in history if item.get('client_event_id') == event['client_event_id']]
        if len(matches) != 1 or any(saved[event['client_event_id']].get(key) != event.get(key) for key in ('source_job_id', 'source_job_type', 'event_name')) or instant(saved[event['client_event_id']]['occurred_at']) != instant(event['occurred_at']):
            raise RuntimeError('Recovered event identity or original timestamp changed or duplicated')
    deep = [args for args in invocations if '-sT' in args]
    if len(deep) != 1 or str(listener_port) not in deep[0]:
        raise RuntimeError('Bridge recovery repeated or changed the scan side effect')
    return {'pending_events_recovered': len(pending), 'original_event_ids': [event['client_event_id'] for event in pending], 'original_occurred_at': [event['occurred_at'] for event in pending], 'source_job_id': run_id, 'deep_nmap_invocations': 1, 'event_identity_unchanged': True}


def validate(nmap_python: Path, receipt_path: Path, repeat_scan: bool = False, interrupt_bridge: bool = False, skip_host_discovery: bool = True, managed_linux: bool = False, close_listener: bool = False) -> dict:
    if close_listener and (not repeat_scan or interrupt_bridge or managed_linux):
        raise RuntimeError("Listener-change validation requires the ordinary repeated loopback workflow")
    nmap = shutil.which("nmap")
    if not nmap:
        raise RuntimeError("nmap is unavailable on PATH")
    if not nmap_python.is_file():
        raise RuntimeError("Provide Python with shipped NmapUI runtime dependencies")
    if managed_linux:
        if not sys.platform.startswith('linux') or os.getuid() == 0 or interrupt_bridge or repeat_scan:
            raise RuntimeError('Managed validation requires a disposable non-root Linux user and one uninterrupted scan.')
        config_home = Path.home() / '.config'
        data_home = Path.home() / '.local/share'
        managed_config = config_home / 'daedalus'
        managed_data = data_home / 'daedalus'
        units = config_home / 'systemd/user'
        for path in (managed_config, managed_data, units / 'daedalus-nmapui.service', units / 'daedalus-scanner-bridge.service'):
            if path.exists() or path.is_symlink():
                raise RuntimeError('Existing Daedalus installation found; refusing managed validation.')
        manager_env = subprocess.run(['systemctl', '--user', 'show-environment'], check=True, capture_output=True, text=True, timeout=10).stdout
        original_manager_path = next((line[5:] for line in manager_env.splitlines() if line.startswith('PATH=')), None)
    managed_attempted = False
    manager_path_changed = False
    managed_proof = None
    processes = []
    live = []
    with tempfile.TemporaryDirectory(prefix="daedalus-real-scanner-", dir=Path.home() if managed_linux else None) as temporary:
        root = Path(temporary)
        root.chmod(0o700)
        portal_port, scanner_port = port(), port()
        portal = f"http://127.0.0.1:{portal_port}"
        scanner = f"http://127.0.0.1:{scanner_port}"
        environment = {key: os.environ[key] for key in ("PATH", "HOME", "TMPDIR", "LANG") if key in os.environ}
        portal_data = root / 'portal-data'
        portal_data.mkdir(mode=0o700)
        portal_database = portal_data / 'daedalus.db'
        environment.update(PYTHON_DOTENV_DISABLED="1", DAEDALUS_DATABASE_URL=f"sqlite:///{portal_database}", DAEDALUS_DATA_DIR=str(portal_data), DAEDALUS_REPORTS_DIR=str(portal_data / "reports"), DAEDALUS_SESSION_SECRET=secrets.token_urlsafe(48), DAEDALUS_ENV="development", DAEDALUS_DEMO_MODE="true", DAEDALUS_BASE_URL=portal, PYTHONPATH=str(REPO / "src"))
        if managed_linux:
            environment.update({key: os.environ[key] for key in ('XDG_RUNTIME_DIR', 'DBUS_SESSION_BUS_ADDRESS') if key in os.environ})
            environment.update(XDG_CONFIG_HOME=str(config_home), XDG_DATA_HOME=str(data_home))
        managed_cleaned = False
        def cleanup_managed():
            nonlocal managed_cleaned
            if not managed_linux or managed_cleaned:
                return
            if managed_attempted and (managed_config / '.daedalus-scanner-services.json').exists():
                cleanup = subprocess.run(['/bin/sh', str(kit / 'manage-service-linux.sh'), 'uninstall'], env=environment, capture_output=True, timeout=90)
                if cleanup.returncode:
                    raise RuntimeError('Managed cleanup failed; recovery files remain in the disposable user home.')
            if any((units / name).exists() for name in ('daedalus-nmapui.service', 'daedalus-scanner-bridge.service')):
                raise RuntimeError('Managed cleanup left a service descriptor; retained recovery data.')
            if manager_path_changed:
                argv = ['systemctl', '--user', 'unset-environment', 'PATH'] if original_manager_path is None else ['systemctl', '--user', 'set-environment', 'PATH=' + original_manager_path]
                subprocess.run(argv, check=True, capture_output=True, timeout=10)
            shutil.rmtree(managed_config, ignore_errors=True)
            shutil.rmtree(managed_data, ignore_errors=True)
            if managed_config.exists() or managed_data.exists():
                raise RuntimeError('Disposable enrollment or scanner data cleanup is incomplete.')
            managed_cleaned = True

        def launch(name, argv, env, cwd):
            log = (root / f"{name}.log").open("wb")
            process = subprocess.Popen(argv, env=env, cwd=cwd, stdout=log, stderr=subprocess.STDOUT)
            processes.append((process, log))
            print(json.dumps({"process": name, "pid": process.pid, "portal_port": portal_port, "scanner_port": scanner_port}), flush=True)
            return process
        try:
            bundled = subprocess.run([sys.executable, "-c", "from daedalus.server import build_agent_bundle; import sys;sys.stdout.buffer.write(build_agent_bundle())"], env=environment, cwd=root, capture_output=True, check=True, timeout=20).stdout
            with zipfile.ZipFile(io.BytesIO(bundled)) as archive:
                archive.extractall(root)
            kit = root / "daedalus-scanner-kit"
            with zipfile.ZipFile(kit / "nmapui-source.zip") as archive:
                archive.extractall(root / "scanner-source")
            source = root / "scanner-source" / "daedalus-nmapui-source"
            # Guard the executable boundary while running the actual Nmap binary.
            listener = FixtureHTTPServer(("127.0.0.1", 0), Listener)
            threading.Thread(target=listener.serve_forever, daemon=True).start()
            listener_port = listener.server_address[1]
            guard_dir = root / "toolchain"
            guard_dir.mkdir()
            wrapper = guard_dir / "nmap"
            wrapper.write_text(f'''#!{nmap_python.absolute()}
import sys, subprocess, json, time, os, tempfile
from pathlib import Path
args=sys.argv[1:]
if args == ["--version"]:
    raise SystemExit(subprocess.run([{nmap!r}, "--version"]).returncode)
xml_destination=None
normalized=list(args)
if "-oX" in normalized:
    index=normalized.index("-oX")
    if index+1 >= len(normalized): raise SystemExit("Missing scanner XML path")
    xml_destination=Path(normalized[index+1])
    parent=xml_destination.parent
    if (not xml_destination.is_absolute() or xml_destination.name != "scan.xml"
        or not parent.name.startswith("nmapui-evidence-") or parent.is_symlink()
        or parent.parent.resolve() != Path(tempfile.gettempdir()).resolve()
        or parent.stat().st_uid != os.getuid() or xml_destination.exists() or xml_destination.is_symlink()):
        raise SystemExit("Loopback harness rejected unexpected XML destination")
    del normalized[index:index+2]
if not normalized or normalized[-1] != "127.0.0.1" or normalized[:-1] not in (["-sn", "-Pn"], ["-T3", "-sV", "-Pn"]):
    raise SystemExit("Loopback harness rejected unexpected scanner arguments")
cmd=[{nmap!r}, "-n", "--host-timeout", "15s"]
if "-sn" in args:
    cmd += ["-sn", "-Pn", "127.0.0.1"]
else:
    cmd += ["-sT", "-Pn", "-sV", "--version-light", "-p", {str(listener_port)!r}, "-oA", {str(root / 'actual-scan')!r}, "127.0.0.1"]
with open({str(root / 'invocations.jsonl')!r}, "a") as out: out.write(json.dumps(cmd)+"\\n")
child=subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
if {interrupt_bridge!r} and "-sn" not in args:
    Path({str(root / 'deep-in-flight.json')!r}).write_text(json.dumps({{"nmap_pid": child.pid}}))
try:
    stdout,stderr=child.communicate(timeout=25)
except subprocess.TimeoutExpired:
    child.kill();child.communicate(timeout=5)
    raise SystemExit("Harness Nmap deadline exceeded")
completed=subprocess.CompletedProcess(cmd,child.returncode,stdout,stderr)
if xml_destination is not None and completed.returncode == 0:
    with xml_destination.open("xb") as output:
        output.write(Path({str(root / 'actual-scan.xml')!r}).read_bytes())
if {interrupt_bridge!r} and "-sn" not in args:
    deadline=time.monotonic()+45
    while not Path({str(root / 'release-deep-result')!r}).exists():
        if time.monotonic()>deadline: raise SystemExit("Harness result gate expired")
        time.sleep(.05)
with open({str(root / 'nmap-results.jsonl')!r}, "a") as out: out.write(json.dumps({{"returncode": completed.returncode, "stdout": completed.stdout, "stderr": completed.stderr}})+"\\n")
sys.stdout.write(completed.stdout)
sys.stderr.write(completed.stderr)
raise SystemExit(completed.returncode)
''')
            wrapper.chmod(0o700)
            data = managed_data / "nmapui-data" if managed_linux else root / "scanner-data"
            data.mkdir(parents=True)
            (data / "settings.json").write_text(json.dumps({"schema_version": 1, "scan_rules": {"scan_only_mode": True, "skip_host_discovery": True, "excluded_targets": [], "max_scan_minutes": 1}, "reports": {"save_to_desktop": False}}))
            scanner_env = dict(environment, PYTHONPATH=str(source), NMAPUI_HOST="127.0.0.1", NMAPUI_PORT=str(scanner_port), NMAPUI_DATA_DIR=str(data), NMAPUI_LOG_DIR=str(root / "scanner-logs"), NMAPUI_SKIP_LEGACY_MIGRATION="1", NMAPUI_STARTUP_TRACEROUTE="false", NMAPUI_ALLOW_UNSAFE_WERKZEUG="true", NMAPUI_ENABLE_UPDATE_CHECK="false", NMAPUI_ENABLE_VULNERS="false", NMAPUI_TRUST_LOCAL_UI="false", NMAPUI_USERNAME="isolated-fixture", NMAPUI_PASSWORD=secrets.token_urlsafe(40), PATH=str(guard_dir)+os.pathsep+environment.get("PATH", ""))
            portal_argv = [sys.executable, "-m", "uvicorn", "daedalus.server:app", "--host", "127.0.0.1", "--port", str(portal_port)]
            portal_process = launch("portal", portal_argv, environment, root)
            if not managed_linux:
                nmapui_process = launch("nmapui", [str(nmap_python.absolute()), str(source / "app.py")], scanner_env, source)
            with httpx.Client(base_url=portal, timeout=10, follow_redirects=True) as client:
                wait_for(lambda: client.get("/healthz").status_code == 200, process=portal_process)
                client.post("/dev/login").raise_for_status()
                if not managed_linux:
                    wait_for(lambda: httpx.get(scanner + "/api/health/ready", auth=(scanner_env["NMAPUI_USERNAME"], scanner_env["NMAPUI_PASSWORD"]), timeout=2).json().get("ready"), process=nmapui_process)
                code = client.post("/api/enrollment-tokens").json()["code"]
                if managed_linux:
                    # The user manager inherits the guard only for this disposable validation.
                    subprocess.run(['systemctl', '--user', 'set-environment', 'PATH=' + scanner_env['PATH']], check=True, capture_output=True, timeout=10)
                    manager_path_changed = True
                    install_env = dict(scanner_env, PYTHON_BIN=sys.executable, NMAPUI_PORT=str(scanner_port))
                    managed_attempted = True
                    install_log = root / 'managed-install.log'
                    with install_log.open('wb') as log:
                        installed = subprocess.run(['/bin/sh', str(kit / 'install-service-linux.sh'), portal, 'Isolated managed Linux scanner'],
                            input=(code + '\n').encode(), env=install_env, cwd=kit, stdout=log, stderr=subprocess.STDOUT, timeout=900)
                    if installed.returncode:
                        raise RuntimeError('Managed Linux installer failed; private log retained until cleanup.')
                    config = json.loads((managed_config / 'managed-agent.json').read_text())
                    config['organization_id'] = client.get('/api/dashboard').json()['organization']['id']
                    managed_proof = {'fresh_installer_completed': True, 'enrollment_config_mode': oct((managed_config / 'managed-agent.json').stat().st_mode & 0o777)}
                else:
                    enrollment = client.post("/api/agents/enroll", json={"code": code, "name": "Isolated real loopback scanner"})
                    enrollment.raise_for_status()
                    config = dict(enrollment.json(), server=portal)
                    if interrupt_bridge:
                        transport = FixtureHTTPServer(('127.0.0.1', 0), BridgeTransport)
                        transport.portal = portal
                        transport.uploads_allowed = threading.Event()
                        threading.Thread(target=transport.serve_forever, daemon=True).start()
                        config['server'] = f'http://127.0.0.1:{transport.server_address[1]}'
                    secret_file = root / "bridge-credentials.json"
                    secret_file.write_text(json.dumps(config))
                    secret_file.chmod(0o600)
                    bridge_env = dict(scanner_env, PYTHONPATH=str(kit / "src"))
                    bridge_code = "import json,pathlib,sys;from daedalus.agent import NmapUIBridge;NmapUIBridge(json.loads(pathlib.Path(sys.argv[1]).read_text()),sys.argv[2],spool_dir=pathlib.Path(sys.argv[3])).run()"
                    bridge_argv = [sys.executable, "-c", bridge_code, str(secret_file), scanner, str(root / "spool")]
                    bridge_process = launch("bridge", bridge_argv, bridge_env, root)
                agent_id = config["agent_id"]
                def online():
                    return next((a for a in client.get("/api/dashboard").json()["agents"] if a["id"] == agent_id and a["status"] == "online" and a["nmapui_ready"] is True and a["command_protocol_version"] >= 2), None)
                agent = wait_for(online)
                approved_scope = client.put(f"/api/agents/{agent_id}/network-scope", json={'authorized_networks': ['127.0.0.1/32']})
                approved_scope.raise_for_status()
                # Observe real portal websocket broadcasts as well as persisted REST history.
                import websocket
                cookie = "; ".join(f"{key}={value}" for key, value in client.cookies.items())
                socket_live = websocket.create_connection(portal.replace("http:", "ws:") + f"/ws/live?organization_id={config['organization_id']}", cookie=cookie, timeout=1)
                def receive():
                    while True:
                        try: live.append(json.loads(socket_live.recv()))
                        except websocket.WebSocketTimeoutException: continue
                        except Exception: return
                threading.Thread(target=receive, daemon=True).start()
                queued = client.post(f"/api/agents/{agent_id}/commands", json={"action": "start_scan", "target": "127.0.0.1", "skip_host_discovery": skip_host_discovery})
                queued.raise_for_status()
                command_id = queued.json()["id"]
                recovery_pending = None
                recovery_claim = None
                if interrupt_bridge:
                    wait_for(lambda: (root / 'deep-in-flight.json').exists())
                    def pending_source_events():
                        pending = [json.loads(path.read_text()) for path in (root / 'spool').glob('*.json')]
                        return [event for event in pending if event.get('source_job_id')] or None
                    recovery_pending = wait_for(pending_source_events)
                    if len({event['source_job_id'] for event in recovery_pending}) != 1:
                        raise RuntimeError('Interrupted source events mixed run identity')
                    claims = list((root / 'spool').glob(f'commands-*/claim-{command_id}.json'))
                    if len(claims) != 1:
                        raise RuntimeError('Command claim was not durable before interruption')
                    recovery_claim = json.loads(claims[0].read_text())
                    bridge_process.kill()
                    bridge_process.wait(timeout=10)
                    recovery_pending = [json.loads(path.read_text()) for path in (root / 'spool').glob('*.json')]
                    print(json.dumps({'stage': 'owned_bridge_interrupted', 'pid': bridge_process.pid, 'exit_code': bridge_process.returncode, 'pending_source_events': len(recovery_pending)}), flush=True)
                    (root / 'release-deep-result').touch()
                    # Source persists its command/run receipts while the bridge is absent.
                    def source_completed():
                        with closing(sqlite3.connect(data / 'runtime.sqlite3')) as db:
                            return bool(db.execute("SELECT 1 FROM jobs WHERE status='completed' LIMIT 1").fetchone())
                    wait_for(source_completed)
                    transport.uploads_allowed.set()
                    bridge_process = launch('bridge-restarted', bridge_argv, bridge_env, root)
                    wait_for(online)
                def finished():
                    command = next(c for c in client.get(f"/api/agents/{agent_id}/commands").json()["commands"] if c["id"] == command_id)
                    return command if command["status"] in {"succeeded", "failed", "timed_out"} else None
                command = wait_for(finished, 90)
                if command["status"] != "succeeded": raise RuntimeError("Real loopback scan did not succeed: " + command["status"])
                events = wait_for(lambda: [e for e in client.get("/api/events?limit=200").json()["events"] if e["agent_id"] == agent_id and e["event_name"] == "deep_scan_results"])
                event = events[0]
                payload = event["payload"]
                if event.get("artifact_download_url"):
                    artifact = client.get(event["artifact_download_url"])
                    artifact.raise_for_status()
                    if hashlib.sha256(artifact.content).hexdigest() != event["artifact_sha256"]:
                        raise RuntimeError("Persisted scanner artifact hash mismatch")
                    payload = artifact.json()
                matched, open_ports = validate_host_evidence(payload, listener_port)
                run_id = event.get("source_job_id")
                if not run_id or event.get("source_job_type") != "scan":
                    raise RuntimeError("Packaged scanner did not preserve explicit scan run metadata")
                def saved_run():
                    response = client.get(f"/api/agents/{agent_id}/runs/{run_id}")
                    response.raise_for_status()
                    detail = response.json()
                    return detail if detail["run"]["status"] == "completed" else None
                run_detail = wait_for(saved_run)
                validate_run_evidence(run_detail, event)
                job_response = client.post(f"/api/agents/{agent_id}/runs/{run_id}/pdf")
                job_response.raise_for_status()
                job_id = job_response.json()["id"]
                def pdf_ready():
                    return next((j for j in client.get("/api/reports").json()["reports"] if j["id"] == job_id and j["status"] in {"completed", "failed"}), None)
                report = wait_for(pdf_ready, 90)
                pdf_response = client.get(report["download_url"]) if report["status"] == "completed" else None
                if pdf_response is None or not pdf_response.content.startswith(b"%PDF-"): raise RuntimeError("Observed scan evidence PDF did not complete")
                pdf = pdf_response.content
                comparison_proof = None
                if repeat_scan:
                    if close_listener:
                        listener.shutdown()
                        listener.server_close()
                        print(json.dumps({"stage": "controlled_loopback_listener_closed"}), flush=True)
                    # Keep the shipped five-minute scanner cooldown intact.
                    # The isolated services stay live; health checks observe them while waiting.
                    print(json.dumps({"stage": "waiting_for_product_scan_cooldown", "seconds": 300}), flush=True)
                    cooldown_deadline = time.monotonic() + 300
                    while time.monotonic() < cooldown_deadline:
                        client.get("/healthz").raise_for_status()
                        if any(process.poll() is not None for process, _log in processes):
                            raise RuntimeError("Isolated scanner service stopped during cooldown")
                        time.sleep(min(30, max(0, cooldown_deadline - time.monotonic())))
                        print(json.dumps({"stage": "product_scan_cooldown", "remaining_seconds": max(0, round(cooldown_deadline - time.monotonic()))}), flush=True)
                    second = client.post(f"/api/agents/{agent_id}/commands", json={"action": "start_scan", "target": "127.0.0.1", "skip_host_discovery": skip_host_discovery})
                    second.raise_for_status()
                    command_id = second.json()["id"]
                    second_command = wait_for(finished, 90)
                    if second_command["status"] != "succeeded": raise RuntimeError("Second loopback scan did not succeed")
                    def second_run_detail():
                        summaries = client.get(f"/api/agents/{agent_id}/runs?limit=10").json()["runs"]
                        candidate = next((r for r in summaries if r["source_job_id"] != run_id and r["status"] == "completed"), None)
                        if not candidate:
                            return None
                        response = client.get(f"/api/agents/{agent_id}/runs/{candidate['source_job_id']}")
                        response.raise_for_status()
                        detail = response.json()
                        return detail if detail["run"]["status"] == "completed" else None
                    second_detail = wait_for(second_run_detail)
                    second_id = second_detail["run"]["source_job_id"]
                    second_event = next((e for e in second_detail["events"] if e["event_name"] == "deep_scan_results"), None)
                    if second_event is None:
                        second_event = next((e for e in second_detail["events"] if e["event_name"] == "scan_results"), None)
                    if not second_event:
                        raise RuntimeError("Repeated scan has no host-result event for comparison")
                    validate_run_evidence(second_detail, second_event)
                    if close_listener:
                        hosts = second_event["payload"] if isinstance(second_event["payload"], list) else second_event["payload"].get("hosts", [])
                        if len(hosts) != 1 or hosts[0].get("ip") != "127.0.0.1" or any(
                                str(p.get("port")) == str(listener_port) and p.get("state") == "open" for p in hosts[0].get("ports", [])):
                            raise RuntimeError("Closed listener remained open or host evidence was lost")
                        validate_closed_listener_xml((root / "actual-scan.xml").read_bytes(), listener_port)
                    else:
                        validate_host_evidence(second_event["payload"], listener_port)
                    comparison_response = client.get(f"/api/agents/{agent_id}/runs/{second_id}/comparison", params={"previous_run_id": run_id})
                    comparison_response.raise_for_status()
                    comparison = comparison_response.json()
                    if not close_listener and (not comparison.get("available") or any(comparison.get(key) for key in ("hosts_added", "hosts_removed", "hosts_not_observed", "port_changes"))):
                        raise RuntimeError("Identical repeated loopback observations did not compare cleanly")
                    validate_loopback_comparison_coverage(comparison)
                    if close_listener:
                        validate_listener_change(comparison, listener_port)
                        def saved_change():
                            saved = client.get(f"/api/agents/{agent_id}/run-comparisons").json()["comparisons"]
                            return next((row for row in saved if row["previous_run_id"] == run_id and row["current_run_id"] == second_id and row["comparison"]["counts"].get("reported_port_changes") == 1), None)
                        saved = wait_for(saved_change)
                        notices = client.get("/api/notifications").json()["notifications"]
                        notices = [n for n in notices if n["source_type"] == "scanner_comparison" and n["source_id"] == saved["id"]]
                        if len(notices) != 1 or notices[0]["reason"] != "changes" or notices[0]["tab"] != "scanners" or saved["meaningful_change_count"] != 1:
                            raise RuntimeError("Controlled listener change did not persist one scoped inbox notice")
                        # Reads must preserve saved evidence and avoid duplicate notices.
                        before = json.dumps(saved, sort_keys=True)
                        client.get(f"/api/agents/{agent_id}/runs/{second_id}/comparison", params={"previous_run_id": run_id}).raise_for_status()
                        if json.dumps(saved_change(), sort_keys=True) != before or len([n for n in client.get("/api/notifications").json()["notifications"] if n["source_type"] == "scanner_comparison" and n["source_id"] == saved["id"]]) != 1:
                            raise RuntimeError("Comparison read altered history or duplicated its notice")
                    comparison_proof = {"previous_run_id": run_id, "current_run_id": second_id, "second_run_event_count": second_detail["run"]["event_count"], "counts": comparison["counts"], "coverage_comparable": True, "covered_targets": comparison["coverage"]["current_targets"], "coverage_source": "successful_daedalus_single_ip_command", "coverage_reasons": comparison["coverage"]["reasons"]}
                socket_live.close()
                with sqlite3.connect(portal_database) as db:
                    acknowledgements = [json.loads(row[0]).get("status") for row in db.execute("SELECT details FROM audit_logs WHERE action='scanner.command_result_reported'")]
                if acknowledgements != ["accepted", "succeeded"] * (2 if repeat_scan else 1):
                    raise RuntimeError("Expected persisted accepted and succeeded command acknowledgements")
                if not any(message.get("type") == "scan_event" for message in live):
                    raise RuntimeError("No real portal scan event websocket broadcast was observed")
                xml = (root / "actual-scan.xml").read_bytes()
                if close_listener:
                    validate_closed_listener_xml(xml, listener_port)
                    comparison_proof.update(controlled_listener_closed=True, persisted_change_notice=True, notice_deduplicated=True, immutable_history_on_read=True)
                else:
                    validate_xml_evidence(xml, listener_port)
                history = client.get("/api/events?limit=200").json()["events"]
                invocations = [json.loads(line) for line in (root / "invocations.jsonl").read_text().splitlines()]
                recovery_proof = None
                if interrupt_bridge:
                    with closing(sqlite3.connect(portal_database)) as db:
                        source_history = [dict(zip(['client_event_id', 'occurred_at', 'source_job_id', 'source_job_type', 'event_name'], row)) for row in db.execute('SELECT client_event_id,occurred_at,source_job_id,source_job_type,event_name FROM scan_events WHERE agent_id=?', (agent_id,))]
                    recovery_proof = validate_recovery_evidence(recovery_pending, source_history, run_id, invocations, listener_port)
                    claim = json.loads(claims[0].read_text())
                    if claim.get('fingerprint') != recovery_claim.get('fingerprint') or claim.get('claimed_at') != recovery_claim.get('claimed_at') or claim.get('terminal_result', {}).get('status') != 'succeeded':
                        raise RuntimeError('Original command claim or recovered terminal acknowledgement changed')
                    if list((root / 'spool').glob('*.json')) or list((root / 'spool').rglob('*.rejected')) or list((root / 'spool').glob('commands-*/result-*.json')):
                        raise RuntimeError('Recovery queues did not drain cleanly')
                    recovery_proof.update(command_claim_unchanged=True, terminal_acknowledged=True, own_bridge_interruption='SIGKILL', source_process_restarted=False, pending_queues_drained=True, upload_hold='loopback transport shim returned 503', interruption_scope='owned bridge killed while source workflow awaited guarded real Nmap output')
                receipt = {"validated_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "kind": "real-managed-linux-loopback-scanner" if managed_linux else "real-packaged-loopback-scanner", "target": "127.0.0.1", "scanner_bundle_sha256": hashlib.sha256(bundled).hexdigest(), "source_tree_sha256": json.loads((source / "manifest.json").read_text())["source_tree_sha256"], "bridge_protocol": agent["command_protocol_version"], "product_skip_host_discovery": True, "per_scan_skip_host_discovery": skip_host_discovery, "command_acknowledgement_states": acknowledgements, "command_status": command["status"], "command_completed_at": command["completed_at"], "host_count": len(matched), "open_port_count": len(open_ports), "loopback_listener_port": listener_port, "observed_port_protocol": "tcp", "persisted_json_artifact_downloaded": bool(event.get("artifact_download_url")), "saved_event_names": sorted({e["event_name"] for e in history if e["agent_id"] == agent_id}), "realtime_messages": len(live), "realtime_types": sorted({str(m.get("type", "")) for m in live}), "nmap_invocations": [[Path(v).name if i == 0 else "<isolated-output>" if 'actual-scan' in v else v for i,v in enumerate(argv)] for argv in invocations], "nmap_xml_sha256": hashlib.sha256(xml).hexdigest(), "source_job_id": run_id, "grouped_run_status": run_detail["run"]["status"], "grouped_run_event_count": run_detail["run"]["event_count"], "pdf_scope": "explicit-run-snapshot", "pdf_status": report["status"], "pdf_bytes": len(pdf), "pdf_sha256": hashlib.sha256(pdf).hexdigest(), "limits": ["Single ephemeral loopback listener port; PATHguard executes real Nmap with bounded options", "No default scan coverage, service install, external targets, persistence soak, or production readiness claimed", "Ephemeral credentials/database/logs/spool removed; only sanitized receipt and PDF retained"]}
                if managed_linux:
                    def service_pid():
                        return int(subprocess.run(['systemctl', '--user', 'show', '--property=MainPID', '--value', 'daedalus-nmapui.service'], check=True, capture_output=True, text=True, timeout=10).stdout.strip())
                    old_pid = service_pid()
                    restart = client.post(f"/api/agents/{agent_id}/commands", json={'action': 'restart_nmapui'})
                    restart.raise_for_status()
                    restart_id = restart.json()['id']
                    def restarted():
                        item = next(c for c in client.get(f"/api/agents/{agent_id}/commands").json()['commands'] if c['id'] == restart_id)
                        return item if item['status'] in {'succeeded', 'failed', 'timed_out'} else None
                    restart_result = wait_for(restarted, 90)
                    if restart_result['status'] != 'succeeded':
                        raise RuntimeError('Managed Linux remote restart failed.')
                    created = restart_result['created_at']
                    def online_after_restart():
                        observed = online()
                        return observed if observed and observed['last_seen_at'] > created else None
                    wait_for(online_after_restart)
                    wait_for(lambda: httpx.get(scanner + '/api/health/ready', auth=(scanner_env['NMAPUI_USERNAME'], scanner_env['NMAPUI_PASSWORD']), timeout=2).json().get('ready'))
                    new_pid = service_pid()
                    if old_pid <= 0 or new_pid <= 0 or old_pid == new_pid:
                        raise RuntimeError('Remote restart did not produce a different live NmapUI process.')
                    managed_proof.update(remote_restart_status='succeeded', nmapui_pid_changed=True, portal_readiness_recovered=True)
                    # Exercise the shipped local upgrade command on the live managed installation.
                    kit_zip = root / 'upgrade-kit.zip'
                    kit_zip.write_bytes(bundled)
                    retained_paths = (managed_config / 'managed-agent.json', managed_config / 'daedalus-nmapui.env', data / 'settings.json')
                    retained_bytes = {path: path.read_bytes() for path in retained_paths}
                    before_upgrade_pid = service_pid()
                    protected = (*retained_paths, units / 'daedalus-nmapui.service',
                                 units / 'daedalus-scanner-bridge.service',
                                 managed_config / '.daedalus-scanner-services.json')
                    protected_bytes = {path: path.read_bytes() for path in protected}
                    maintenance = httpx.post(scanner + '/api/runtime/maintenance', json={},
                        auth=(scanner_env['NMAPUI_USERNAME'], scanner_env['NMAPUI_PASSWORD']), timeout=3)
                    maintenance.raise_for_status()
                    maintenance_token = maintenance.json()['token']
                    try:
                        refused = subprocess.run(['/bin/sh', str(kit / 'manage-service-linux.sh'), 'upgrade', str(kit_zip)],
                                                 env=environment, capture_output=True, text=True, timeout=900)
                        if (refused.returncode == 0 or 'upgrade deferred' not in refused.stderr
                                or service_pid() != before_upgrade_pid
                                or any(path.read_bytes() != contents for path, contents in protected_bytes.items())):
                            raise RuntimeError('Managed Linux maintenance refusal changed the installed service.')
                        managed_proof['maintenance_claim_refuses_upgrade_without_service_change'] = True
                    finally:
                        released = httpx.request('DELETE', scanner + '/api/runtime/maintenance',
                                json={'token': maintenance_token},
                                auth=(scanner_env['NMAPUI_USERNAME'], scanner_env['NMAPUI_PASSWORD']), timeout=3)
                        released.raise_for_status()
                        if released.json().get('maintenance_active') is not False:
                            raise RuntimeError('Managed Linux maintenance release was not confirmed.')
                    upgrade_started_at = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
                    upgraded = subprocess.run(['/bin/sh', str(kit / 'manage-service-linux.sh'), 'upgrade', str(kit_zip)], env=environment, capture_output=True, text=True, timeout=900)
                    if upgraded.returncode or not json.loads(upgraded.stdout).get('upgraded'):
                        raise RuntimeError('Managed Linux local upgrade failed.')
                    def online_after_upgrade():
                        observed = online()
                        return observed if observed and observed['last_seen_at'] > upgrade_started_at else None
                    wait_for(online_after_upgrade)
                    wait_for(lambda: httpx.get(scanner + '/api/health/ready', auth=(scanner_env['NMAPUI_USERNAME'], scanner_env['NMAPUI_PASSWORD']), timeout=2).json().get('ready'))
                    if service_pid() == before_upgrade_pid or any(path.read_bytes() != contents for path, contents in retained_bytes.items()):
                        raise RuntimeError('Upgrade did not change the process or preserve enrollment/settings.')
                    after_upgrade = client.get(f"/api/agents/{agent_id}/runs/{run_id}")
                    after_upgrade.raise_for_status()
                    validate_run_evidence(after_upgrade.json(), event)
                    if after_upgrade.json()['events'] != run_detail['events']:
                        raise RuntimeError('Saved scan history changed during upgrade.')
                    again = subprocess.run(['/bin/sh', str(kit / 'manage-service-linux.sh'), 'upgrade', str(kit_zip)], env=environment, capture_output=True, text=True, timeout=120)
                    if again.returncode or not json.loads(again.stdout).get('already_current'):
                        raise RuntimeError('Repeated kit upgrade was not a no-op.')
                    managed_proof.update(local_upgrade_completed=True, enrollment_settings_preserved=True, saved_run_unchanged=True, repeated_upgrade_noop=True)
                    before_local_restart_pid = service_pid()
                    local_restart_at = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
                    local_restart = subprocess.run(['/bin/sh', str(kit / 'manage-service-linux.sh'), 'restart'], env=environment, capture_output=True, text=True, timeout=120)
                    if local_restart.returncode or json.loads(local_restart.stdout).get('action') != 'restart':
                        raise RuntimeError('Managed Linux local restart failed.')
                    def online_after_local_restart():
                        observed = online()
                        return observed if observed and observed['last_seen_at'] > local_restart_at else None
                    wait_for(online_after_local_restart)
                    wait_for(lambda: httpx.get(scanner + '/api/health/ready', auth=(scanner_env['NMAPUI_USERNAME'], scanner_env['NMAPUI_PASSWORD']), timeout=2).json().get('ready'))
                    if service_pid() == before_local_restart_pid or any(path.read_bytes() != contents for path, contents in retained_bytes.items()):
                        raise RuntimeError('Local restart did not replace NmapUI or retain enrollment/settings.')
                    managed_proof.update(local_restart_completed=True, local_restart_pid_changed=True, local_restart_heartbeat_recovered=True)
                    # Rehearse point-in-time recovery on this owned isolated portal.
                    backup_response = subprocess.run([sys.executable, str(REPO / 'scripts/backup_data.py')], env=environment, capture_output=True, text=True, check=True, timeout=60)
                    backup_name = backup_response.stdout.strip()
                    if not re.fullmatch(r'daedalus-data-\d{8}T\d{6}Z\.tar\.gz', backup_name):
                        raise RuntimeError('Recovery backup returned an unexpected filename.')
                    backup = portal_data / 'backups' / backup_name
                    restored_data = root / 'portal-data-restored'
                    subprocess.run([sys.executable, str(REPO / 'scripts/restore_data.py'), str(backup), '--destination', str(restored_data)], env=environment, capture_output=True, text=True, check=True, timeout=120)
                    expected_name = next(a['name'] for a in client.get('/api/dashboard').json()['agents'] if a['id'] == agent_id)
                    with sqlite3.connect(portal_database) as db:
                        db.execute('UPDATE agents SET name=? WHERE id=?', ('post-backup recovery fixture', agent_id))
                    changed = next(a for a in client.get('/api/dashboard').json()['agents'] if a['id'] == agent_id)
                    if changed['name'] != 'post-backup recovery fixture':
                        raise RuntimeError('Recovery marker was not visible before cutover.')
                    portal_process.terminate()
                    portal_process.wait(timeout=20)
                    previous_data = root / 'portal-data-before-recovery'
                    portal_data.rename(previous_data)
                    restored_data.rename(portal_data)
                    recovery_started_at = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
                    recovered_portal = launch('portal-recovered', portal_argv, environment, root)
                    wait_for(lambda: client.get('/readyz').status_code == 200)
                    def online_after_recovery():
                        observed = online()
                        return observed if observed and observed['last_seen_at'] > recovery_started_at else None
                    recovered_agent = wait_for(online_after_recovery)
                    if recovered_agent['name'] != expected_name or recovered_portal.pid == portal_process.pid:
                        raise RuntimeError('Recovered portal did not restore the backup state.')
                    recovered_run = client.get(f'/api/agents/{agent_id}/runs/{run_id}')
                    recovered_run.raise_for_status()
                    if recovered_run.json()['events'] != run_detail['events']:
                        raise RuntimeError('Recovered scan events differ from the saved backup.')
                    recovered_pdf = client.get(report['download_url'])
                    recovered_pdf.raise_for_status()
                    if hashlib.sha256(recovered_pdf.content).digest() != hashlib.sha256(pdf).digest():
                        raise RuntimeError('Recovered PDF bytes differ from the saved report.')
                    artifact_restored = False
                    if event.get('artifact_download_url'):
                        recovered_artifact = client.get(event['artifact_download_url'])
                        recovered_artifact.raise_for_status()
                        if hashlib.sha256(recovered_artifact.content).hexdigest() != event['artifact_sha256']:
                            raise RuntimeError('Recovered scanner artifact differs from its saved digest.')
                        artifact_restored = True
                    managed_proof.update(portal_recovery_completed=True, point_in_time_state_restored=True, recovered_run_unchanged=True, recovered_pdf_unchanged=True, recovered_artifact_verified=artifact_restored, scanner_heartbeat_after_recovery=True)
                    receipt['managed_linux'] = managed_proof
                    receipt['limits'][1] = 'No default scan coverage, external targets, persistence soak, or production readiness claimed'
                receipt["repeated_scan_comparison"] = comparison_proof
                receipt['bridge_interruption_recovery'] = recovery_proof
                if managed_linux:
                    cleanup_managed()
                    receipt['managed_linux']['cleanup_completed'] = True
                receipt_path.parent.mkdir(parents=True, exist_ok=True)
                receipt_path.write_text(json.dumps(receipt, indent=2)+"\n")
                receipt_path.with_suffix(".pdf").write_bytes(pdf)
                return receipt
        except Exception as exc:
            failure = {"validated_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "kind": "real-managed-linux-loopback-scanner" if managed_linux else "real-packaged-loopback-scanner", "result": "incomplete", "error_type": type(exc).__name__, "target": "127.0.0.1", "realtime_messages": len(live), "own_processes": [{"name": log.name.rsplit("/", 1)[-1], "pid": process.pid, "exit_code_before_cleanup": process.poll()} for process, log in processes], "limits": ["No full scan success claimed; isolated temporary data/credentials removed after own-process cleanup"]}
            if managed_linux:
                service_diagnostics = {}
                for name in ('daedalus-nmapui.service', 'daedalus-scanner-bridge.service'):
                    state = subprocess.run(['systemctl', '--user', 'show', '--property=ActiveState,SubState,MainPID,ExecMainStatus', name], capture_output=True, text=True, timeout=10)
                    journal = subprocess.run(['journalctl', '--user', '--unit=' + name, '--no-pager', '-n', '100'], capture_output=True, text=True, timeout=10)
                    text = journal.stdout
                    categories = [category for category in ('PermissionError', 'ModuleNotFoundError', 'FileNotFoundError', 'ConnectionError', 'ConnectError', 'ImportError', 'RuntimeError') if category in text]
                    service_diagnostics[name] = {'manager_state': state.stdout.splitlines(), 'journal_error_categories': categories}
                failure['managed_service_diagnostics'] = service_diagnostics
                # Only fixed state fields and exception categories reach CI logs.
                print(json.dumps({'managed_failure_diagnostics': service_diagnostics}), flush=True)
            result_file = root / "nmap-results.jsonl"
            if result_file.exists(): failure["actual_nmap_results"] = [json.loads(line) for line in result_file.read_text().splitlines()]
            if portal_database.exists():
                with sqlite3.connect(portal_database) as db:
                    failure["command_states"] = [dict(zip(["action", "status", "delivered_at", "completed_at"], row)) for row in db.execute("SELECT action,status,delivered_at,completed_at FROM agent_commands")]
                    safe_reasons = {"The scan request was rate limited.", "A scan job is already running for this client", "Invalid scan target.", "Missing scan target.", "NmapUI restarted before this command completed.", "The Linux systemd user service could not restart NmapUI.", "Managed Linux service verification failed; refusing to restart NmapUI."}
                    failure["command_failure_reasons"] = [result if result in safe_reasons else "Other command failure (details withheld)" for (result,) in db.execute("SELECT result FROM agent_commands WHERE status='failed'")]
                    failure["saved_event_names"] = [row[0] for row in db.execute("SELECT event_name FROM scan_events")]
                    failure["command_acknowledgement_states"] = [json.loads(row[0]).get("status") for row in db.execute("SELECT details FROM audit_logs WHERE action='scanner.command_result_reported'")]
            receipt_path.parent.mkdir(parents=True, exist_ok=True)
            receipt_path.write_text(json.dumps(failure, indent=2)+"\n")
            raise
        finally:
            cleanup_failure = None
            try:
                cleanup_managed()
            except Exception as exc:
                cleanup_failure = exc
            for process, log in reversed(processes):
                if process.poll() is None:
                    process.terminate()
                    try: process.wait(timeout=10)
                    except subprocess.TimeoutExpired: process.kill(); process.wait(timeout=5)
                log.close()
            if 'listener' in locals(): listener.shutdown(); listener.server_close()
            if 'transport' in locals(): transport.shutdown(); transport.server_close()
            if cleanup_failure:
                raise cleanup_failure


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-loopback", action="store_true", help="Explicitly opt into real loopback-only Nmap")
    parser.add_argument("--nmapui-python", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--close-listener", action="store_true", help="With --repeat-scan, close the owned listener and validate an exact-port state change, saved history and inbox notice")
    parser.add_argument("--repeat-scan", action="store_true", help="Repeat the bounded scan and validate distinct run IDs and comparison")
    parser.add_argument('--interrupt-bridge', action='store_true', help='Interrupt only the owned bridge during one in-flight loopback job, then validate durable recovery')
    parser.add_argument('--allow-host-discovery', action='store_true', help='Use normal host discovery for the loopback target instead of the default per-scan -Pn override')
    parser.add_argument("--managed-linux", action="store_true", help="Run the real managed installer and portal restart as a disposable Linux user")
    args = parser.parse_args()
    if not args.run_loopback: parser.error("--run-loopback is required")
    if args.interrupt_bridge and args.repeat_scan: parser.error('Select either repeat comparison or bridge interruption for one bounded validation')
    if args.close_listener and (not args.repeat_scan or args.interrupt_bridge or args.managed_linux): parser.error("--close-listener requires --repeat-scan without interruption/managed mode")
    print(json.dumps(validate(args.nmapui_python, args.receipt, args.repeat_scan, args.interrupt_bridge, not args.allow_host_discovery, args.managed_linux, args.close_listener), indent=2))

if __name__ == "__main__": main()
