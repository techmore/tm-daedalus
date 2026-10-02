#!/usr/bin/env python3
"""Verify public DNS, trusted TLS, and the Daedalus health endpoint."""
from __future__ import annotations

import http.client
import json
import socket
import ssl
import sys
from pathlib import Path

from scripts.check_production_env import read_env, validate


def check_public_host(hostname: str, *, timeout: float = 8) -> tuple[bool, str]:
    """Check that a public hostname resolves and serves Daedalus over trusted TLS."""
    try:
        socket.getaddrinfo(hostname, 443, type=socket.SOCK_STREAM)
    except OSError:
        return False, "DNS lookup failed"

    connection = http.client.HTTPSConnection(
        hostname, 443, timeout=timeout, context=ssl.create_default_context()
    )
    try:
        connection.request("GET", "/healthz", headers={"Host": hostname, "Connection": "close"})
        response = connection.getresponse()
        payload = json.loads(response.read(4096))
        if (response.status == 200 and isinstance(payload, dict)
                and payload.get("status") == "ok" and payload.get("app") == "daedalus"):
            return True, "DNS, trusted HTTPS, and Daedalus health passed"
        return False, "HTTPS endpoint did not return the Daedalus health response"
    except ssl.SSLCertVerificationError:
        return False, "TLS certificate trust or hostname verification failed"
    except (OSError, ssl.SSLError, http.client.HTTPException, ValueError):
        return False, "HTTPS health request failed"
    finally:
        connection.close()


def main() -> int:
    env_path = Path(sys.argv[1]) if len(sys.argv) == 2 else Path(".env.production")
    if len(sys.argv) > 2:
        print("Usage: check_public_deployment.py [production-env-file]", file=sys.stderr)
        return 2
    try:
        values = read_env(env_path)
    except (OSError, ValueError) as exc:
        print(f"Cannot read production configuration: {exc}", file=sys.stderr)
        return 1
    errors = validate(values)
    if errors:
        print("Production configuration is invalid; run check_production_env.py first.", file=sys.stderr)
        return 1

    hosts = list(dict.fromkeys(host.rstrip(".").lower() for host in values["DAEDALUS_HOSTNAMES"].replace(",", " ").split()))
    failed = False
    for hostname in hosts:
        success, message = check_public_host(hostname)
        print(f"{hostname}: {message}")
        failed |= not success
    if failed:
        print("Public deployment verification failed. Confirm DNS points to this Droplet and Caddy has issued trusted certificates.", file=sys.stderr)
        return 1
    print("All configured public Daedalus hostnames passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
