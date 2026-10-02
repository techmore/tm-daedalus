"""Authorized, fixed-path exposure probes. Response bodies never leave this module.

The caller must enforce workspace authorization; this collector is not an API.
An absent signature is an observation, never a vulnerability-free assessment.
"""
from __future__ import annotations

import hashlib
import http.client
import re
import secrets
import socket
import ssl
import threading
import time
from typing import Any

from daedalus.domain_verification import normalize_domain
from daedalus.external_checks import ExternalCheckFailure, _PinnedHTTPSConnection, _public_addresses

PROBE_PATHS = ("/.git/HEAD", "/.git/config", "/.env", "/server-status", "/phpinfo.php")
MAX_PROBE_BYTES = 32 * 1024
REQUEST_DEADLINE_SECONDS = 5.0
OVERALL_DEADLINE_SECONDS = 40.0
PRESET_VERSION = "fixed-exposure-v1"


class _ExposureHTTPSConnection(_PinnedHTTPSConnection):
    """Expose the pending TLS socket so the deadline can abort its handshake."""

    def connect(self) -> None:
        if self.deadline_expired.is_set():
            raise TimeoutError("Request deadline elapsed")
        raw_socket = socket.create_connection((self.connect_ip, self.port), self.timeout)
        self.sock = raw_socket
        try:
            if self.deadline_expired.is_set():
                raise TimeoutError("Request deadline elapsed")
            tls_socket = self._context.wrap_socket(raw_socket, server_hostname=self.host, do_handshake_on_connect=False)
            self.sock = tls_socket
            if self.deadline_expired.is_set():
                raise TimeoutError("Request deadline elapsed")
            tls_socket.do_handshake()
        except Exception:
            raw_socket.close()
            self.close()
            raise


def _signature(path: str, body: bytes) -> str | None:
    text = body.decode("utf-8", errors="replace")
    if path == "/.git/HEAD" and re.fullmatch(r"\s*(?:ref: refs/(?:heads|tags)/[^\s<>]+|[0-9a-fA-F]{40}|[0-9a-fA-F]{64})\s*", text):
        return "exposed_git_head"
    if path == "/.git/config" and re.search(r"(?m)^\s*\[core\]\s*$", text) and re.search(r"(?m)^\s*(?:repositoryformatversion|bare)\s*=", text):
        return "exposed_git_config"
    if path == "/.env" and "<html" not in text.lower() and "<!doctype" not in text.lower():
        assignments = re.findall(r"(?m)^\s*(?:export\s+)?([A-Z][A-Z0-9_]{2,80})\s*=\s*[^\r\n]+", text)
        if len(assignments) >= 2 and any(re.search(r"(?:PASSWORD|SECRET|TOKEN|API_KEY|DATABASE_URL|DB_PASS)", key) for key in assignments):
            return "exposed_environment_config"
    if path == "/server-status" and "Apache Server Status for" in text and ("Server Version:" in text or "Total accesses:" in text):
        return "exposed_apache_status"
    if path == "/phpinfo.php" and "PHP Version" in text and ("phpinfo()" in text or "PHP Variables" in text) and "Configuration" in text:
        return "exposed_phpinfo"
    return None


def _fetch(host: str, address: str, path: str, remaining: float) -> tuple[dict[str, Any], bytes]:
    evidence: dict[str, Any] = {"path": path, "http_status": None, "assessment": "unassessed", "error_code": None}
    if remaining <= 0:
        evidence["error_code"] = "overall_deadline"
        return evidence, b""
    limit = min(REQUEST_DEADLINE_SECONDS, remaining)
    connection = _ExposureHTTPSConnection(host, address, timeout=limit)
    expired = threading.Event()
    connection.deadline_expired = expired

    def abort() -> None:
        expired.set()
        sock = connection.sock
        if sock is not None:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        connection.close()

    timer = threading.Timer(limit, abort)
    timer.daemon = True
    timer.start()
    try:
        if expired.is_set():
            raise TimeoutError("Request deadline elapsed")
        connection.request("GET", path, headers={"User-Agent": "Daedalus-Authorized-Exposure-Audit/1.0", "Accept-Encoding": "identity", "Connection": "close"})
        response = connection.getresponse()
        evidence["http_status"] = response.status
        if 300 <= response.status < 400:
            evidence["error_code"] = "redirect_not_followed"
            return evidence, b""
        if response.status not in (200, 404, 410):
            evidence["error_code"] = "http_unassessed"
            return evidence, b""
        if (response.getheader("Content-Encoding") or "identity").lower().strip() != "identity":
            evidence["error_code"] = "encoded_response"
            return evidence, b""
        body = response.read(MAX_PROBE_BYTES + 1)
        if expired.is_set():
            evidence["error_code"] = "request_deadline"
            return evidence, b""
        length = response.getheader("Content-Length")
        if len(body) > MAX_PROBE_BYTES or response.getheader("Content-Range") or (length is not None and (not re.fullmatch(r"[0-9]{1,12}", length.strip()) or int(length.strip()) != len(body))):
            evidence["error_code"] = "incomplete_response"
            return evidence, b""
        evidence["assessment"] = "response_observed"
        return evidence, body
    except (OSError, ssl.SSLError, http.client.HTTPException):
        evidence["error_code"] = "request_deadline" if expired.is_set() else "transport_error"
        return evidence, b""
    finally:
        timer.cancel()
        connection.close()


def run_active_website_check(domain: str) -> dict[str, Any]:
    host = normalize_domain(domain)
    deadline = time.monotonic() + OVERALL_DEADLINE_SECONDS
    result: dict[str, Any] = {
        "domain": host, "preset_version": PRESET_VERSION, "coverage_complete": False,
        "baseline": None, "probes": [], "findings": [], "error_code": None,
        "limits": {"request_seconds": REQUEST_DEADLINE_SECONDS, "overall_seconds": OVERALL_DEADLINE_SECONDS, "response_bytes": MAX_PROBE_BYTES, "requests": 6},
        "limitations": ["Five fixed paths only; no crawling or Nikto execution.", "Signature observations require review and do not establish exploitability.", "No response bodies, configuration values, or response headers are retained.", "Absence of a signature is not a vulnerability-free assessment."],
    }
    try:
        address = _public_addresses(host)[0]
    except ExternalCheckFailure:
        result["error_code"] = "public_address_validation_failed"
        return result
    baseline_path = "/.daedalus-missing-" + secrets.token_hex(16)
    baseline, baseline_body = _fetch(host, address, baseline_path, deadline - time.monotonic())
    # The random baseline path is not useful history and need not be persisted.
    baseline["path"] = "random_nonexistent_path"
    baseline_ok = baseline["assessment"] == "response_observed" and baseline["http_status"] in (404, 410)
    baseline["assessment"] = "missing_response_observed" if baseline_ok else "soft_404_unknown"
    result["baseline"] = baseline
    baseline_digest = hashlib.sha256(baseline_body).digest() if baseline_ok else None
    for path in PROBE_PATHS:
        probe, body = _fetch(host, address, path, deadline - time.monotonic())
        if probe["assessment"] == "response_observed":
            if not baseline_ok:
                probe["assessment"] = "soft_404_unknown"
            elif probe["http_status"] in (404, 410):
                probe["assessment"] = "missing_response_observed"
            elif baseline_digest is not None and hashlib.sha256(body).digest() == baseline_digest:
                probe["assessment"] = "baseline_matching_response"
            else:
                signature = _signature(path, body)
                probe["assessment"] = "signature_observed" if signature else "no_signature_observed"
                if signature:
                    result["findings"].append({"signature_id": signature, "path": path, "http_status": probe["http_status"], "evidence_confidence": "signature_match_requires_review"})
        result["probes"].append(probe)
    result["coverage_complete"] = baseline_ok and all(probe["assessment"] not in ("unassessed", "soft_404_unknown", "baseline_matching_response") for probe in result["probes"])
    return result
