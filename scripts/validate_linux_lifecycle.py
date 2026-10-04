#!/usr/bin/env python3
"""Opt-in real systemd lifecycle check with inert processes, not network scans.

Run as a disposable non-root Linux user with an active systemd user manager.
Refuses existing Daedalus service files. Enrollment/evidence are synthetic.
This validates service removal/recovery, not the NmapUI engine or portal.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from urllib.request import urlopen


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--helper', type=Path, default=Path(__file__).resolve().parents[1] / 'src/daedalus/agent_bundle/systemd_service.py')
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    if not sys.platform.startswith('linux') or os.getuid() == 0:
        raise SystemExit('Use a disposable non-root Linux user with an active systemd user manager.')
    spec = importlib.util.spec_from_file_location('lifecycle_helper', args.helper)
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    config_home = Path(os.environ.get('XDG_CONFIG_HOME', str(Path.home() / '.config')))
    unit_dir, config_dir = config_home / 'systemd/user', config_home / 'daedalus'
    for path in (unit_dir / helper.NMAPUI_UNIT, unit_dir / helper.BRIDGE_UNIT, config_dir / helper.ENV_FILE, config_dir / helper.STATE_FILE, config_dir / helper.RESUME_FILE, config_dir / helper.LOCK_FILE, config_dir / 'managed-agent.json'):
        if path.exists() or path.is_symlink():
            raise SystemExit('Existing scanner installation found; refusing to modify it.')
    subprocess.run([helper.SYSTEMCTL, '--user', 'show-environment'], check=True, capture_output=True, timeout=10)
    workspace = Path(tempfile.mkdtemp(prefix='daedalus-lifecycle-', dir=Path.home()))
    report = {'scope': 'real systemd user lifecycle with inert fixture processes', 'nmapui_engine_validated': False, 'portal_checkin_validated': False, 'network_scan_issued': False, 'helper_sha256': hashlib.sha256(args.helper.read_bytes()).hexdigest()}
    installed = False
    owned_enrollment = False
    cleanup_error = None

    def require(condition: bool, message: str) -> None:
        if not condition:
            raise RuntimeError(message)

    def lifecycle(action: str) -> dict:
        response = subprocess.run(
            [sys.executable, str(args.helper), action, '--unit-dir', str(unit_dir), '--config-dir', str(config_dir)],
            capture_output=True, text=True, timeout=90,
        )
        if response.returncode:
            raise helper.ServiceError(response.stderr.strip() or 'Lifecycle command failed.')
        return json.loads(response.stdout)
    try:
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            port = listener.getsockname()[1]
        app_dir = workspace / 'fixture-nmapui'
        app_dir.mkdir()
        (app_dir / 'app.py').write_text('from http.server import BaseHTTPRequestHandler,HTTPServer\nimport os\nclass Handler(BaseHTTPRequestHandler):\n def do_GET(self):\n  self.send_response(200);self.end_headers();self.wfile.write(b"lifecycle fixture")\n def log_message(self,*args): pass\nHTTPServer(("127.0.0.1",int(os.environ["NMAPUI_PORT"])),Handler).serve_forever()\n')
        bridge = workspace / 'fixture-bridge'
        bridge.write_text('#!/usr/bin/python3\nimport time\nwhile True: time.sleep(1)\n')
        bridge.chmod(0o700)
        config_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        enrollment = config_dir / 'managed-agent.json'
        helper._write_exclusive(enrollment, b'synthetic enrollment: no portal credential\n')
        owned_enrollment = True
        evidence = workspace / 'scanner-evidence.json'
        evidence.write_bytes(b'synthetic saved evidence\n')
        namespace = argparse.Namespace(unit_dir=str(unit_dir), config_dir=str(config_dir), nmapui_python='/usr/bin/python3', nmapui_app_dir=str(app_dir), nmapui_data_dir=str(workspace / 'scanner-data'), browser_dir=str(workspace / 'browsers'), agent_executable=str(bridge), bridge_working_dir=str(workspace), agent_config=str(enrollment), port=port)
        helper.install(namespace)
        installed = True
        units = {name: (unit_dir / name).read_bytes() for name in (helper.NMAPUI_UNIT, helper.BRIDGE_UNIT)}
        retained = {path: path.read_bytes() for path in (enrollment, evidence, config_dir / helper.ENV_FILE, config_dir / helper.STATE_FILE)}

        def ready() -> bool:
            try:
                with urlopen(f'http://127.0.0.1:{port}/', timeout=1) as response:
                    return response.read() == b'lifecycle fixture'
            except OSError:
                return False

        def await_listener() -> None:
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                if ready():
                    return
                time.sleep(.1)
            raise RuntimeError('Fixture process did not begin listening.')

        subprocess.run([helper.SYSTEMCTL, '--user', 'daemon-reload'], check=True, capture_output=True, timeout=10)
        subprocess.run([helper.SYSTEMCTL, '--user', 'enable', '--now', helper.NMAPUI_UNIT, helper.BRIDGE_UNIT], check=True, capture_output=True, timeout=20)
        await_listener()
        removed = lifecycle('uninstall')
        require(not ready() and all(not (unit_dir / name).exists() for name in units), 'Uninstall left the listener or a unit present.')
        require(all(path.read_bytes() == contents for path, contents in retained.items()), 'Uninstall changed enrollment or saved evidence.')
        report['uninstall'] = removed['services']
        report['enrollment_and_evidence_preserved'] = True
        restored = lifecycle('restore')
        await_listener()
        require(all((unit_dir / name).read_bytes() == contents for name, contents in units.items()), 'Restore changed a service descriptor.')
        require(all(path.read_bytes() == contents for path, contents in retained.items()), 'Restore changed enrollment or saved evidence.')
        report['restore'] = restored['services']
        report['exact_descriptors_restored'] = True

        unit = unit_dir / helper.BRIDGE_UNIT
        unit.write_bytes(units[helper.BRIDGE_UNIT] + b'# fixture tamper\n')
        try:
            lifecycle('uninstall')
        except helper.ServiceError:
            report['tampered_descriptor_refused'] = True
        else:
            raise RuntimeError('Tampered descriptor was accepted.')
        finally:
            unit.write_bytes(units[helper.BRIDGE_UNIT])
        require(ready(), 'Refused uninstall unexpectedly stopped the listener.')
        lifecycle('uninstall')
        require(not ready(), 'Final uninstall left the listener running.')
        report['systemd_version'] = subprocess.run([helper.SYSTEMCTL, '--version'], check=True, capture_output=True, text=True, timeout=10).stdout.splitlines()[0]
    finally:
        if installed:
            try:
                lifecycle('uninstall')
            except Exception as exc:
                cleanup_error = type(exc).__name__
        if cleanup_error is None:
            if installed:
                for name in ('managed-agent.json', helper.ENV_FILE, helper.STATE_FILE, helper.RESUME_FILE, helper.LOCK_FILE):
                    (config_dir / name).unlink(missing_ok=True)
            elif owned_enrollment:
                enrollment.unlink(missing_ok=True)
            shutil.rmtree(workspace)
        report['cleanup_completed'] = cleanup_error is None
    if cleanup_error:
        raise SystemExit('Cleanup is incomplete; retained the private recovery files.')
    encoded = json.dumps(report, sort_keys=True, indent=2) + '\n'
    if args.output:
        args.output.write_text(encoded)
    print(encoded, end='')


if __name__ == '__main__':
    main()
