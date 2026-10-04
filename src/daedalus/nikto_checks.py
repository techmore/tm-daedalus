"""Nikto collection through a domain-scoped, public-address-pinned TLS proxy.

The caller must enforce current workspace authorization before invocation.
Options/schema reference: https://github.com/sullo/nikto/tree/main/program
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import select
import socket
import socketserver
import subprocess
import tempfile
import threading
import time
from urllib.parse import urlsplit

from daedalus.domain_verification import normalize_domain
from daedalus.external_checks import ExternalCheckFailure, _public_addresses

PRESET_VERSION = "nikto-nondos-v1"
MAX_OUTPUT = 4 * 1024 * 1024
MAX_FINDINGS = 2000
SCAN_SECONDS = 600


class ScopedProxy(socketserver.ThreadingTCPServer):
    allow_reuse_address = False
    daemon_threads = True
    block_on_close = False

    def __init__(self, domain: str, addresses: list[str], *, deadline: float):
        self.domain = normalize_domain(domain)
        self.addresses = tuple(addresses)
        if not self.addresses or any(not ipaddress.ip_address(value).is_global for value in self.addresses):
            raise ValueError("Nikto requires pinned public target addresses.")
        self.deadline = deadline
        self.denied = 0
        self.connected = 0
        self.state_lock = threading.Lock()
        super().__init__(("127.0.0.1", 0), Tunnel)

    def handle_error(self, request, client_address):
        # Never print tunnel contents or customer paths.
        pass


class Tunnel(socketserver.BaseRequestHandler):
    def handle(self):
        upstream = None
        try:
            self.request.settimeout(5)
            data = b""
            while b"\r\n\r\n" not in data:
                part = self.request.recv(4096)
                if not part or len(data) + len(part) > 32768:
                    return
                data += part
            header, trailing = data.split(b"\r\n\r\n", 1)
            first = header.split(b"\r\n", 1)[0].decode("ascii")
            parts = first.split(" ")
            authority = parts[1] if len(parts) == 3 else ""
            allowed = {self.server.domain + ":443"}
            allowed.update(("[" + value + "]" if ":" in value else value) + ":443" for value in self.server.addresses)
            if len(parts) != 3 or parts[0] != "CONNECT" or authority not in allowed or parts[2] not in {"HTTP/1.0", "HTTP/1.1"} or time.monotonic() >= self.server.deadline:
                with self.server.state_lock:
                    self.server.denied += 1
                self.request.sendall(b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
                return
            for address in self.server.addresses:
                try:
                    upstream = socket.create_connection((address, 443), timeout=5)
                    break
                except OSError:
                    continue
            if upstream is None:
                return
            with self.server.state_lock:
                self.server.connected += 1
            self.request.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
            if trailing:
                upstream.sendall(trailing)
            while time.monotonic() < self.server.deadline:
                readable, _, _ = select.select([self.request, upstream], [], [], min(1, max(0, self.server.deadline - time.monotonic())))
                for source in readable:
                    chunk = source.recv(65536)
                    if not chunk:
                        return
                    (upstream if source is self.request else self.request).sendall(chunk)
        except (OSError, UnicodeError, ValueError):
            return
        finally:
            if upstream is not None:
                upstream.close()


def parse_report(content: bytes, domain: str) -> dict:
    """Retain stable finding metadata, excluding banners and response contents."""
    if len(content) > MAX_OUTPUT:
        raise ValueError("Nikto output exceeds the collection limit.")
    report = json.loads(content)
    hosts = report if isinstance(report, list) else [report]
    if len(hosts) != 1 or not isinstance(hosts[0], dict):
        raise ValueError("Nikto must report exactly one authorized host.")
    host = hosts[0]
    if str(host.get("host", "")).rstrip(".").lower() != normalize_domain(domain) or str(host.get("port")) != "443":
        raise ValueError("Nikto reported an unexpected host or port.")
    rows = host.get("vulnerabilities")
    if not isinstance(rows, list) or len(rows) > MAX_FINDINGS:
        raise ValueError("Nikto finding count is invalid or exceeds the limit.")
    findings = {}
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError("Nikto finding metadata is invalid.")
        identifier = str(row.get("id", ""))
        method = str(row.get("method", ""))
        path = str(row.get("url", ""))
        parsed = urlsplit(path)
        if parsed.scheme or parsed.netloc or not path.startswith("/") or len(path) > 2048 or any(ord(c) < 32 for c in path):
            raise ValueError("Nikto reported an invalid finding path.")
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,80}", identifier) or not re.fullmatch(r"[A-Z]{1,16}", method):
            raise ValueError("Nikto finding identifiers are invalid.")
        # Queries can contain injected payloads or reflected values. Retain a
        # digest for stable comparison, not the raw query or response message.
        query_digest = hashlib.sha256(parsed.query.encode()).hexdigest() if parsed.query else None
        signature = "nikto_" + identifier + "_" + method
        if query_digest:
            signature += "_" + query_digest[:16]
        description = row.get("msg", "")
        if not isinstance(description, str):
            raise ValueError("Nikto finding description is invalid.")
        description = re.sub(r"(?i)(password|secret|token|api[_-]?key)\s*[:=]\s*\S+", r"\1=[redacted]", description[:2048])
        description = re.sub(r"\?[^\s]+", "?[query redacted]", description)
        description = " ".join(description.split())
        item = {"signature_id": signature, "test_id": identifier, "method": method, "path": parsed.path, "query_sha256": query_digest, "http_status": None, "description": description}
        findings[(signature, parsed.path, query_digest or "")] = item
    return {"findings": [findings[key] for key in sorted(findings)], "engine_report_ended": bool(host.get("end_time"))}


def run_nikto_check(domain: str, executable: Path | None = None) -> dict:
    domain = normalize_domain(domain)
    preset = {"domain": domain, "preset_version": PRESET_VERSION, "engine": "nikto", "coverage_complete": False, "findings": [], "port": 443, "excluded_test_categories": ["denial_of_service"], "max_seconds": SCAN_SECONDS}
    executable = executable or Path(os.environ.get("DAEDALUS_NIKTO_EXECUTABLE", "/opt/daedalus/nikto/program/nikto.pl"))
    if not executable.is_absolute() or executable.is_symlink() or not executable.is_file():
        return dict(preset, error_code="nikto_runtime_unavailable")
    try:
        addresses = _public_addresses(domain)
    except (OSError, ValueError, ExternalCheckFailure):
        return dict(preset, error_code="public_target_unavailable")
    deadline = time.monotonic() + SCAN_SECONDS + 15
    with tempfile.TemporaryDirectory(prefix="daedalus-nikto-") as temporary, ScopedProxy(domain, addresses, deadline=deadline) as proxy:
        worker = threading.Thread(target=proxy.serve_forever, daemon=True)
        worker.start()
        output = Path(temporary) / "report.json"
        command = ["/usr/bin/perl", str(executable), "-host", "https://" + domain, "-port", "443", "-vhost", domain, "-useproxy", "http://127.0.0.1:" + str(proxy.server_address[1]), "-Tuning", "x6", "-maxtime", str(SCAN_SECONDS) + "s", "-timeout", "5", "-Pause", "0.2", "-ask", "no", "-nocheck", "-nointeractive", "-Format", "json", "-output", str(output)]
        environment = {key: os.environ[key] for key in ("PATH", "LANG") if key in os.environ}
        environment.update(HOME=temporary, TMPDIR=temporary)
        timed_out = False
        try:
            try:
                result = subprocess.run(command, env=environment, cwd=executable.parent, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=SCAN_SECONDS + 15, check=False)
                returncode = result.returncode
            except subprocess.TimeoutExpired:
                timed_out = True
                returncode = None
            if not output.is_file() or output.is_symlink() or output.stat().st_size > MAX_OUTPUT:
                return dict(preset, error_code="nikto_report_unavailable", timed_out=timed_out)
            with output.open("rb") as report:
                parsed = parse_report(report.read(MAX_OUTPUT + 1), domain)
            process_completed = returncode == 0 and not timed_out and parsed["engine_report_ended"] and proxy.denied == 0 and proxy.connected > 0
            # Nikto writes end_time even after its own maximum-time cutoff.
            # A valid report therefore cannot prove every test was exhausted.
            return dict(preset, **parsed, engine_process_completed=process_completed, coverage_reason="test_exhaustion_not_reported", timed_out=timed_out, proxy_denied_connections=proxy.denied, proxy_connected_tunnels=proxy.connected)
        except (OSError, ValueError, json.JSONDecodeError):
            return dict(preset, error_code="nikto_report_invalid")
        finally:
            proxy.shutdown()
            worker.join(timeout=2)
