#!/usr/bin/env python3
"""Wait for deployment containers without exposing configuration or logs."""
from __future__ import annotations

import http.client
import ipaddress
import json
import re
import socket
import ssl
import subprocess
import sys
import time


def container_ready(container: dict, *, require_health: bool) -> tuple[bool, bool]:
    state = container.get("State", {})
    status = state.get("Status")
    if status in {"exited", "dead", "removing"}:
        return False, True
    health = state.get("Health", {}).get("Status")
    return status == "running" and (health == "healthy" if require_health else health in {None, "healthy"}), False


def validate_caddy_config(container_id: str) -> bool:
    """Validate the mounted Caddyfile in the running Caddy container."""
    try:
        result = subprocess.run(
            [
                "docker", "exec", container_id, "caddy", "validate",
                "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile",
            ],
            capture_output=True, text=True, timeout=15, check=False,
        )
    except (subprocess.SubprocessError, OSError):
        return False
    return result.returncode == 0


def _caddy_probe_targets(container: dict) -> tuple[str, list[str]]:
    """Return Caddy's private network address and validated served hostnames."""
    config = container.get("Config", {})
    environment = {}
    for item in config.get("Env", []):
        name, separator, value = item.partition("=")
        if separator:
            environment[name] = value

    hosts = []
    for host in re.split(r"[,\s]+", environment.get("DAEDALUS_HOSTNAMES", "")):
        host = host.strip().lower().rstrip(".")
        if not host:
            continue
        labels = host.split(".")
        label_pattern = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
        if len(host) <= 253 and len(labels) > 1 and all(label_pattern.fullmatch(label) for label in labels):
            hosts.append(host)

    networks = container.get("NetworkSettings", {}).get("Networks", {})
    for network in networks.values():
        address = network.get("IPAddress", "")
        if address:
            try:
                return str(ipaddress.ip_address(address)), list(dict.fromkeys(hosts))
            except ValueError:
                continue
    return "", list(dict.fromkeys(hosts))


class _SNIHTTPSConnection(http.client.HTTPSConnection):
    """Connect to Caddy's container IP while selecting a configured TLS site."""

    def __init__(self, address: str, server_hostname: str, *, timeout: float):
        super().__init__(address, port=443, timeout=timeout, context=ssl._create_unverified_context())
        self.server_hostname = server_hostname

    def connect(self) -> None:
        raw_socket = socket.create_connection((self.host, self.port), self.timeout)
        self.sock = self._context.wrap_socket(raw_socket, server_hostname=self.server_hostname)


def caddy_proxy_healthy(container: dict) -> bool:
    """Request /healthz through Caddy and verify the Daedalus health payload."""
    address, hosts = _caddy_probe_targets(container)
    if not address or not hosts:
        return False

    for host in hosts:
        connection = _SNIHTTPSConnection(address, host, timeout=5)
        try:
            connection.request(
                "GET", "/healthz",
                headers={"Host": host, "Connection": "close"},
            )
            response = connection.getresponse()
            payload = json.loads(response.read(4096))
            if (
                response.status == 200
                and isinstance(payload, dict)
                and payload.get("status") == "ok"
                and payload.get("app") == "daedalus"
            ):
                return True
        except (OSError, ssl.SSLError, http.client.HTTPException, ValueError):
            continue
        finally:
            connection.close()
    return False


def main() -> int:
    if len(sys.argv) != 3:
        print("Provide the Daedalus and Caddy container IDs.", file=sys.stderr)
        return 2
    deadline = time.monotonic() + 180
    caddy_validated = False
    while time.monotonic() < deadline:
        try:
            result = subprocess.run(
                ["docker", "inspect", *sys.argv[1:]], capture_output=True,
                text=True, timeout=10, check=True,
            )
            containers = json.loads(result.stdout)
            if len(containers) != 2:
                raise ValueError("Missing container")
            states = [container_ready(container, require_health=index == 0)
                      for index, container in enumerate(containers)]
            if any(terminal for _, terminal in states):
                print("Deployment failed: a service stopped. Inspect its logs locally.", file=sys.stderr)
                return 1
            if all(ready for ready, _ in states):
                if not caddy_validated:
                    if not validate_caddy_config(sys.argv[2]):
                        print("Deployment failed: Caddy configuration validation failed.", file=sys.stderr)
                        return 1
                    caddy_validated = True
                if caddy_proxy_healthy(containers[1]):
                    print("Daedalus is healthy, Caddy configuration is valid, and the HTTPS proxy returns app health. Verify public certificate trust and Google login before accepting deployment.")
                    return 0
        except (subprocess.SubprocessError, ValueError, OSError):
            # Inspection failure does not establish that either service stopped.
            # Keep observing the same IDs until authoritative state or deadline.
            pass
        time.sleep(2)
    print("Deployment readiness timed out after 180 seconds. Inspect service status and logs locally.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
