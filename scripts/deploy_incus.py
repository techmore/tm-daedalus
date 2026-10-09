#!/usr/bin/env python3
"""Build, back up, deploy, health-check, and roll back Daedalus on Incus."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shlex
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from urllib.error import URLError
from urllib.request import Request, urlopen

if __package__:
    from .package_release import build_bundle, verify_bundle
else:
    from package_release import build_bundle, verify_bundle


ROOT = Path(__file__).resolve().parents[1]
INSTANCE_DEFAULT = "daedalus-prod"
HEALTH_URL_DEFAULT = "https://daedalus.cybersecuritypilot.org/readyz"
SSH_CONNECTION_OPTIONS = ["-o", "ConnectTimeout=10", "-o", "ConnectionAttempts=1"]


class DeployError(RuntimeError):
    pass


def _run(arguments: list[str], *, input_text: str | None = None) -> str:
    result = subprocess.run(
        arguments,
        input=input_text,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode:
        detail = result.stderr.strip() or result.stdout.strip()
        raise DeployError(f"Command failed ({result.returncode}): {detail}")
    return result.stdout.strip()


def _run_streaming_ssh(arguments: list[str], *, allow_access_check: bool = True, timeout: float | None = None) -> str:
    """Expose only SSH access-check prompts while retaining normal output."""
    process = subprocess.Popen(arguments, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    assert process.stdout is not None and process.stderr is not None
    errors: list[str] = []
    timed_out = threading.Event()

    def stop_after_deadline() -> None:
        timed_out.set()
        try:
            process.kill()
        except ProcessLookupError:
            pass

    timer = threading.Timer(timeout, stop_after_deadline) if timeout is not None else None
    if timer is not None:
        timer.daemon = True
        timer.start()

    def read_errors() -> None:
        for line in process.stderr:
            errors.append(line)
            message = line.strip()
            if message == "# Tailscale SSH requires an additional check." or re.fullmatch(
                r"# To authenticate, visit: https://login\.tailscale\.com/a/[A-Za-z0-9_-]{8,128}", message
            ):
                if allow_access_check:
                    print(message, file=sys.stderr, flush=True)
                else:
                    try:
                        process.terminate()
                    except ProcessLookupError:
                        pass

    reader = threading.Thread(target=read_errors, daemon=True)
    reader.start()
    try:
        output = process.stdout.read()
        status = process.wait()
        reader.join()
    finally:
        if timer is not None:
            timer.cancel()
        process.stdout.close()
        process.stderr.close()
    if timed_out.is_set():
        raise DeployError("Optional SSH cleanup exceeded its deadline; temporary files may remain.")
    if status:
        detail = "".join(errors).strip() or output.strip()
        raise DeployError(f"Command failed ({status}): {detail}")
    return output.strip()


def _ssh(host: str, command: list[str], *, optional_cleanup: bool = False) -> str:
    arguments = ["ssh", *SSH_CONNECTION_OPTIONS, host, shlex.join(command)]
    if optional_cleanup:
        return _run_streaming_ssh(arguments, allow_access_check=False, timeout=20)
    return _run_streaming_ssh(arguments)


def _validate(host: str, instance: str, *, require_clean: bool = True) -> None:
    if not re.fullmatch(r"[A-Za-z0-9_.@-]{1,255}", host):
        raise DeployError("Incus SSH host must be a simple user@host or host value.")
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", instance):
        raise DeployError("Invalid Incus instance name.")
    status = _run(["git", "-C", str(ROOT), "status", "--porcelain"])
    if require_clean and status:
        raise DeployError("Commit and push the working tree before deploying it.")
    branch = _run(["git", "-C", str(ROOT), "branch", "--show-current"])
    if branch != "main":
        raise DeployError("Production deployments must come from the main branch.")
    if require_clean:
        local_commit = _run(["git", "-C", str(ROOT), "rev-parse", "HEAD"])
        remote_head = _run([
            "git", "-C", str(ROOT), "ls-remote", "--exit-code", "origin", "refs/heads/main"
        ])
        remote_fields = remote_head.split()
        if (
            len(remote_fields) != 2
            or remote_fields[1] != "refs/heads/main"
            or remote_fields[0] != local_commit
        ):
            raise DeployError(
                "Production deploy requires HEAD to match the current origin/main commit."
            )


def _public_health(url: str) -> bool:
    try:
        request = Request(url, headers={"Accept": "application/json", "Connection": "close"})
        with urlopen(request, timeout=8) as response:
            payload = json.loads(response.read(4096))
            return (
                response.status == 200
                and isinstance(payload, dict)
                and payload.get("status") == "ready"
                and payload.get("app") == "daedalus"
            )
    except (OSError, URLError, ValueError):
        return False


def _wait_for_health(host: str, instance: str, health_url: str, timeout: int = 120) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            _ssh(host, [
                "incus", "exec", instance, "--", "bash", "-lc",
                "systemctl is-active --quiet daedalus && "
                "curl -fsS -H 'Host: daedalus.cybersecuritypilot.org' "
                "http://127.0.0.1:8000/readyz >/dev/null",
            ])
            if _public_health(health_url):
                return True
        except DeployError:
            pass
        time.sleep(3)
    return False


def deploy(host: str, instance: str, health_url: str, *, plan_only: bool = False) -> int:
    _validate(host, instance, require_clean=not plan_only)
    commit = _run(["git", "-C", str(ROOT), "rev-parse", "HEAD"])
    print(f"Release commit: {commit}")
    print(f"Incus target: {host}/{instance}")
    print(f"Health URL: {health_url}")
    with tempfile.TemporaryDirectory(prefix="daedalus-deploy-") as directory:
        archive = Path(directory) / "daedalus-release.tar.gz"
        bundle = build_bundle(ROOT, archive)
        verify_bundle(archive)
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        print(f"Verified release archive: {bundle['file_count']} files, sha256 {digest}")
        if plan_only:
            print("Plan: off-host data backup → staged Python 3.12 venv → Incus restart → internal/public health check → automatic rollback if unhealthy")
            return 0

        environment = os.environ.copy()
        environment["DAEDALUS_INCUS_HOST"] = host
        environment["DAEDALUS_INCUS_INSTANCE"] = instance
        backup = subprocess.run(["sh", str(ROOT / "scripts/backup_incus.sh")], cwd=ROOT, env=environment, check=False)
        if backup.returncode:
            raise DeployError("The off-host data backup failed; deployment was not started.")

        archive_name = f"daedalus-{digest}.tar.gz"
        remote_archive = f"/tmp/{archive_name}"
        remote_script = "/tmp/daedalus-deploy-remote.sh"
        script = ROOT / "scripts/deploy_incus_remote.sh"
        retain_remote_recovery = False
        try:
            _run(["scp", *SSH_CONNECTION_OPTIONS, str(archive), f"{host}:{remote_archive}"])
            _run(["scp", *SSH_CONNECTION_OPTIONS, str(script), f"{host}:{remote_script}"])
            _ssh(host, ["incus", "file", "push", remote_archive, f"{instance}{remote_archive}"])
            _ssh(host, ["incus", "file", "push", remote_script, f"{instance}{remote_script}"])

            def remote_phase(phase: str) -> None:
                _ssh(host, [
                    "incus", "exec", instance, "--", "bash", remote_script,
                    phase, digest, instance,
                ])

            remote_phase("prepare")
            try:
                remote_phase("activate")
                _ssh(host, ["incus", "restart", "--timeout", "120", instance])
                if _wait_for_health(host, instance, health_url):
                    print("Release is active; internal and public health checks passed.")
                    return 0
                raise DeployError("The new release did not pass internal and public health checks.")
            except Exception as failure:
                print("Deployment failed after staging. Restoring the previous source release.", file=sys.stderr)
                try:
                    remote_phase("rollback")
                    _ssh(host, ["incus", "restart", "--timeout", "120", instance])
                    if not _wait_for_health(host, instance, health_url):
                        raise DeployError("The restored service did not pass health checks.")
                except Exception as rollback_failure:
                    retain_remote_recovery = True
                    raise DeployError(
                        f"Deployment failed ({failure}); automatic rollback could not be verified ({rollback_failure})."
                    ) from failure
                raise DeployError(f"Deployment failed ({failure}); previous release was restored and is healthy.") from failure
        finally:
            if not retain_remote_recovery:
                try:
                    _ssh(host, [
                        "incus", "exec", instance, "--", "bash", remote_script,
                        "cleanup", digest, instance,
                    ], optional_cleanup=True)
                except DeployError:
                    print("Optional container cleanup was skipped; temporary staging files may remain.", file=sys.stderr)
            try:
                host_cleanup = ["rm", "-f", remote_archive]
                if not retain_remote_recovery:
                    host_cleanup.append(remote_script)
                _ssh(host, host_cleanup, optional_cleanup=True)
            except DeployError:
                print("Optional host cleanup was skipped; temporary archives may remain.", file=sys.stderr)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default=os.environ.get("DAEDALUS_INCUS_HOST"))
    parser.add_argument("--instance", default=os.environ.get("DAEDALUS_INCUS_INSTANCE", INSTANCE_DEFAULT))
    parser.add_argument("--health-url", default=os.environ.get("DAEDALUS_HEALTH_URL", HEALTH_URL_DEFAULT))
    parser.add_argument("--plan", action="store_true", help="validate the checkout and show the deployment plan")
    args = parser.parse_args(argv)
    if not args.host:
        parser.error("set --host or DAEDALUS_INCUS_HOST")
    try:
        return deploy(args.host, args.instance, args.health_url, plan_only=args.plan)
    except (DeployError, OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
