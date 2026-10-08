#!/usr/bin/env python3
"""Explicit local Linux scanner upgrade with recoverable descriptor cutover."""
from __future__ import annotations
import argparse
import base64
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import stat
import subprocess
import time
from urllib.request import Request
try:
    from . import systemd_service as service, upgrade_service as shared
except ImportError:
    import systemd_service as service
    import upgrade_service as shared

PENDING = service.UPGRADE_FILE
NAMES = (service.NMAPUI_UNIT, service.BRIDGE_UNIT, service.STATE_FILE)
urlopen = shared.urlopen  # Local credentials must never follow redirects or proxies.


def digest(data):
    return hashlib.sha256(data).hexdigest()


def paths(unit_dir, config_dir):
    return {name: (config_dir if name == service.STATE_FILE else unit_dir) / name for name in NAMES}


def check_path(path, root):
    shared.macos_service._check_managed_path(path, root)


def environment_value(unit, key):
    prefix = 'Environment=' + key + '='
    found = [line[len(prefix):] for line in unit.decode().splitlines() if line.startswith(prefix)]
    if len(found) != 1:
        raise service.ServiceError('Managed unit environment is ambiguous.')
    values = shlex.split(found[0])
    if len(values) != 1:
        raise service.ServiceError('Managed unit environment is invalid.')
    return values[0].replace('%%', '%')


def credentials(contents):
    result = {}
    for line in contents.decode().splitlines():
        key, separator, raw = line.partition('=')
        if not separator or key not in {'NMAPUI_USERNAME', 'NMAPUI_PASSWORD'} or key in result or not raw.startswith('"') or not raw.endswith('"'):
            raise service.ServiceError('Managed credential environment is invalid.')
        value = re.sub(r'\\([\\"$`])', r'\1', raw[1:-1])
        if service._env_file_quote(value, key) != raw:
            raise service.ServiceError('Managed credential escaping is invalid.')
        result[key] = value
    if set(result) != {'NMAPUI_USERNAME', 'NMAPUI_PASSWORD'} or bool(result['NMAPUI_USERNAME']) != bool(result['NMAPUI_PASSWORD']):
        raise service.ServiceError('Managed credential environment is incomplete.')
    return result


def ready(port, auth, timeout=60):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        request = Request(f'http://127.0.0.1:{port}/api/health/ready')
        if auth['NMAPUI_USERNAME']:
            token = base64.b64encode((auth['NMAPUI_USERNAME'] + ':' + auth['NMAPUI_PASSWORD']).encode()).decode()
            request.add_header('Authorization', 'Basic ' + token)
        try:
            with urlopen(request, timeout=3) as response:
                payload = json.load(response)
            if payload.get('ready') is True and payload.get('status') == 'ready':
                return True
        except (OSError, ValueError):
            pass
        time.sleep(.5)
    return False


def replace_field(contents, prefix, replacement):
    lines = contents.decode().splitlines()
    indexes = [i for i, line in enumerate(lines) if line.startswith(prefix)]
    if len(indexes) != 1:
        raise service.ServiceError('Managed service descriptor has ambiguous upgrade fields.')
    lines[indexes[0]] = replacement
    return ('\n'.join(lines) + '\n').encode()


def read_pending(unit_dir, config_dir):
    if not (config_dir / PENDING).exists() and not (config_dir / PENDING).is_symlink():
        raise service.ServiceError('No interrupted upgrade transaction exists to recover.')
    try:
        record = json.loads(service._private_bytes(config_dir / PENDING))
        if record['format'] != 1 or record['unit_dir'] != str(unit_dir) or record['config_dir'] != str(config_dir):
            raise ValueError()
        token = record.get('maintenance_token')
        if token is not None and (not isinstance(token, str) or len(token) != 32
                or any(c not in '0123456789abcdef' for c in token)):
            raise ValueError()
        for group in ('old', 'candidate'):
            if set(record[group]) != set(NAMES) or any(not isinstance(value, str) for value in record[group].values()):
                raise ValueError()
            state = json.loads(record[group][service.STATE_FILE])
            if state.get('format') != 1 or state.get('unit_dir') != str(unit_dir) or set(state.get('files', {})) != {service.ENV_FILE, service.NMAPUI_UNIT, service.BRIDGE_UNIT}:
                raise ValueError()
            if state['files'][service.ENV_FILE] != record['environment_sha256'] or any(state['files'][name] != digest(record[group][name].encode()) for name in (service.NMAPUI_UNIT, service.BRIDGE_UNIT)):
                raise ValueError()
        for name, path in paths(unit_dir, config_dir).items():
            if service._private_bytes(path) not in {record['old'][name].encode(), record['candidate'][name].encode()}:
                raise ValueError()
        if digest(service._private_bytes(config_dir / service.ENV_FILE)) != record['environment_sha256'] or digest(service._private_bytes(config_dir / 'managed-agent.json')) != record['enrollment_sha256']:
            raise ValueError()
        return record
    except (KeyError, TypeError, OSError, ValueError) as exc:
        raise service.ServiceError('Upgrade recovery files changed or are invalid; refusing to overwrite them.') from exc


def operate(action, bundle, unit_dir, config_dir, data_home, *, executor=None, prepare=None, wait_ready=None):
    executor = executor or subprocess.run
    wait_ready = wait_ready or ready
    unit_dir, config_dir, data_home = map(lambda p: Path(p).absolute(), (unit_dir, config_dir, data_home))
    if action not in {'upgrade', 'upgrade-offline', 'upgrade-rollback'}:
        raise service.ServiceError('Unsupported upgrade action.')
    # Shared lifecycle lock prevents overlap with removal/recovery.
    service._ownership(unit_dir, config_dir)
    lock = os.open(config_dir / service.LOCK_FILE, os.O_RDWR | os.O_CREAT | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    maintenance_token = maintenance_payload = None
    try:
        info = os.fstat(lock)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600:
            raise service.ServiceError('Upgrade lock is unsafe.')
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise service.ServiceError('Another scanner lifecycle action is running.') from exc
        pending_path = config_dir / PENDING
        record = None
        def validate_current():
            if record is None:
                service.verify(unit_dir, config_dir)
            else:
                read_pending(unit_dir, config_dir)
        def run(*args):
            validate_current()
            try:
                result = executor([service.SYSTEMCTL, '--user', *args], capture_output=True, text=True, timeout=30)
            except (OSError, subprocess.SubprocessError) as exc:
                raise service.ServiceError('Upgrade service operation failed; private recovery files were retained.') from exc
            if result.returncode:
                raise service.ServiceError('Upgrade service operation failed; private recovery files were retained.')
            return result
        def observe(name):
            response = run('show', '--property=LoadState,ActiveState,MainPID,FragmentPath,DropInPaths,UnitFileState', name)
            values = {}
            for line in response.stdout.splitlines():
                key, sep, value = line.partition('=')
                if not sep or key in values:
                    raise service.ServiceError('Service state is ambiguous.')
                values[key] = value
            if set(values) != {'LoadState', 'ActiveState', 'MainPID', 'FragmentPath', 'DropInPaths', 'UnitFileState'} or values['LoadState'] != 'loaded' or values['FragmentPath'] != str(unit_dir / name) or values['DropInPaths'] or not values['MainPID'].isdigit():
                raise service.ServiceError('Unexpected loaded service or override; refusing upgrade.')
            return values
        def stop():
            for name in (service.BRIDGE_UNIT, service.NMAPUI_UNIT):
                observe(name)
                run('stop', name)
                state = observe(name)
                if state['MainPID'] != '0' or state['ActiveState'] not in {'inactive', 'failed'}:
                    raise service.ServiceError('Service stop is unconfirmed; descriptors were retained.')
        def start(port, auth):
            run('daemon-reload')
            run('start', service.NMAPUI_UNIT)
            if not wait_ready(port, auth):
                raise service.ServiceError('Upgraded NmapUI did not become ready.')
            run('start', service.BRIDGE_UNIT)
            for name in (service.NMAPUI_UNIT, service.BRIDGE_UNIT):
                state = observe(name)
                if state['ActiveState'] != 'active' or state['MainPID'] == '0' or state['UnitFileState'] != 'enabled':
                    raise service.ServiceError('Upgraded service startup is unconfirmed.')
        def write(group):
            for name, path in paths(unit_dir, config_dir).items():
                validate_current()
                shared._atomic_plist(path, record[group][name].encode())
        auth = credentials(service._private_bytes(config_dir / service.ENV_FILE))
        def claim(port, previous_token=None):
            nonlocal maintenance_payload, maintenance_token
            maintenance_payload = {'EnvironmentVariables': {**auth, 'NMAPUI_PORT': str(port)}}
            try:
                maintenance_token = shared._acquire_scanner_maintenance(maintenance_payload, previous_token)
            except RuntimeError as exc:
                raise service.ServiceError(str(exc)) from exc
        def require_closed_listener(payload):
            try:
                shared._require_scanner_offline(payload)
            except RuntimeError as exc:
                raise service.ServiceError(str(exc)) from exc
        if action == 'upgrade-rollback':
            record = read_pending(unit_dir, config_dir)
            port = int(environment_value(record['old'][service.NMAPUI_UNIT].encode(), 'NMAPUI_PORT'))
            if not 1 <= port <= 65535:
                raise service.ServiceError('Managed scanner port is invalid.')
            engine = observe(service.NMAPUI_UNIT)
            if engine['ActiveState'] == 'active' and engine['MainPID'] != '0':
                claim(port, record.get('maintenance_token'))
                # A restarted engine may issue a fresh token. Persist it before
                # any stop so another interrupted recovery can reassert ownership.
                record['maintenance_token'] = maintenance_token
                shared._atomic_plist(pending_path, (json.dumps(record, sort_keys=True, indent=2) + '\n').encode())
            elif engine['MainPID'] != '0' or engine['ActiveState'] not in {'inactive', 'failed'}:
                raise service.ServiceError('Scanner activity is unknown; recovery deferred.')
            stop()
            write('old')
            start(port, auth)
            pending_path.unlink()
            return {'rolled_back': True, 'data_preserved': True}
        if pending_path.exists() or pending_path.is_symlink():
            raise service.ServiceError('An interrupted upgrade needs upgrade-rollback before another upgrade.')
        service.verify(unit_dir, config_dir)
        resume_path = config_dir / service.RESUME_FILE
        resume_original = None
        if resume_path.exists() or resume_path.is_symlink():
            service._resume(unit_dir, config_dir)
            resume_original = service._private_bytes(resume_path)
        def require_offline_services():
            for name in (service.NMAPUI_UNIT, service.BRIDGE_UNIT):
                state = observe(name)
                if state['ActiveState'] not in {'inactive', 'failed'} or state['MainPID'] != '0' or state['UnitFileState'] != 'enabled':
                    raise service.ServiceError('Offline upgrade requires both managed services stopped and enabled.')
        if action == 'upgrade-offline':
            require_offline_services()
        for name in (() if action == 'upgrade-offline' else (service.NMAPUI_UNIT, service.BRIDGE_UNIT)):
            state = observe(name)
            if state['ActiveState'] != 'active' or state['MainPID'] == '0' or state['UnitFileState'] != 'enabled':
                raise service.ServiceError('Upgrade requires both managed services active and enabled.')
        old = {name: service._private_bytes(path) for name, path in paths(unit_dir, config_dir).items()}
        environment = service._private_bytes(config_dir / service.ENV_FILE)
        enrollment = service._private_bytes(config_dir / 'managed-agent.json')
        port = int(environment_value(old[service.NMAPUI_UNIT], 'NMAPUI_PORT'))
        if not 1 <= port <= 65535:
            raise service.ServiceError('Managed scanner port is invalid.')
        offline_payload = {'EnvironmentVariables': {**auth, 'NMAPUI_PORT': str(port)}}
        if action == 'upgrade-offline':
            require_closed_listener(offline_payload)
        files, kit_digest = shared._read_kit(Path(bundle).absolute())
        support = data_home / 'daedalus'
        for path in (support, support / 'nmapui/releases', support / 'scanner-bridge/releases'):
            check_path(path, data_home)
        nmap_release, bridge_release = (prepare or shared.prepare_releases)(files, support)
        nmap_hash = digest(files['nmapui-source.zip'])
        bridge_hash = digest(b''.join(files[key] for key in sorted(shared.REQUIRED_KIT_FILES - {'nmapui-source.zip'})))
        if Path(nmap_release) != support / 'nmapui/releases' / nmap_hash or Path(bridge_release) != support / 'scanner-bridge/releases' / bridge_hash:
            raise service.ServiceError('Prepared release paths do not match content fingerprints.')
        for path in (nmap_release / '.venv/bin', bridge_release / '.venv/bin', nmap_release / 'daedalus-nmapui-source/app.py'):
            check_path(path, data_home)
        if not os.access(nmap_release / '.venv/bin/python', os.X_OK) or not os.access(bridge_release / '.venv/bin/daedalus-agent', os.X_OK) or not (nmap_release / 'daedalus-nmapui-source/app.py').is_file():
            raise service.ServiceError('Prepared runtimes are incomplete.')
        service.verify(unit_dir, config_dir)
        if environment != service._private_bytes(config_dir / service.ENV_FILE) or enrollment != service._private_bytes(config_dir / 'managed-agent.json'):
            raise service.ServiceError('Enrollment or credentials changed while preparing the upgrade.')
        nmap = replace_field(old[service.NMAPUI_UNIT], 'WorkingDirectory=', 'WorkingDirectory=' + service._unit_path(str(nmap_release / 'daedalus-nmapui-source'), 'application'))
        nmap = replace_field(nmap, 'ExecStart=', 'ExecStart=' + service._exec_quote(str(nmap_release / '.venv/bin/python'), 'python') + ' ' + service._exec_quote(str(nmap_release / 'daedalus-nmapui-source/app.py'), 'application'))
        nmap = replace_field(nmap, 'Environment=PLAYWRIGHT_BROWSERS_PATH=', 'Environment=PLAYWRIGHT_BROWSERS_PATH=' + service._environment_quote(str(nmap_release / 'playwright-browsers'), 'browsers'))
        bridge = replace_field(old[service.BRIDGE_UNIT], 'WorkingDirectory=', 'WorkingDirectory=' + service._unit_path(str(bridge_release), 'bridge'))
        bridge = replace_field(bridge, 'ExecStart=', 'ExecStart=' + service._exec_quote(str(bridge_release / '.venv/bin/daedalus-agent'), 'bridge') + ' --config ' + service._exec_quote(str(config_dir / 'managed-agent.json'), 'enrollment'))
        enrolled = json.loads(enrollment)
        portal = service.management_portal_url(enrolled.get('server') if isinstance(enrolled, dict) else None)
        lines = [line for line in nmap.decode().splitlines() if not line.startswith('Environment=NMAPUI_MANAGEMENT_PORTAL_URL=')]
        if portal:
            lines.insert(lines.index('[Service]') + 1, 'Environment=NMAPUI_MANAGEMENT_PORTAL_URL=' + service._environment_quote(portal, 'portal URL'))
        nmap = ('\n'.join(lines) + '\n').encode()
        state = json.loads(old[service.STATE_FILE])
        state['files'][service.NMAPUI_UNIT], state['files'][service.BRIDGE_UNIT] = digest(nmap), digest(bridge)
        candidate = {service.NMAPUI_UNIT: nmap, service.BRIDGE_UNIT: bridge, service.STATE_FILE: (json.dumps(state, sort_keys=True, indent=2) + '\n').encode()}
        if candidate == old:
            return {'upgraded': False, 'already_current': True, 'kit_sha256': kit_digest, 'data_preserved': True}
        if action == 'upgrade-offline':
            require_offline_services()
            require_closed_listener(offline_payload)
        record = {'format': 1, 'unit_dir': str(unit_dir), 'config_dir': str(config_dir), 'kit_sha256': kit_digest, 'environment_sha256': digest(environment), 'enrollment_sha256': digest(enrollment), 'old': {key: value.decode() for key, value in old.items()}, 'candidate': {key: value.decode() for key, value in candidate.items()}}
        old_digest = digest(b''.join(old[name] for name in sorted(old)))
        backup_root = support / 'service-upgrades' / kit_digest / old_digest
        for directory in (support / 'service-upgrades', support / 'service-upgrades' / kit_digest, backup_root):
            check_path(directory, data_home)
            directory.mkdir(mode=0o700, parents=True, exist_ok=True)
            info = directory.stat()
            if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
                raise service.ServiceError('Upgrade backup directories must be private and owned by this user.')
        backup_file = backup_root / 'transaction.json'
        if action != 'upgrade-offline':
            claim(port)
        record['maintenance_token'] = maintenance_token
        record_bytes = (json.dumps(record, sort_keys=True, indent=2) + '\n').encode()
        if backup_file.exists() or backup_file.is_symlink():
            # A retry obtains a fresh token; the immutable descriptor backup
            # may retain its previous token while pending owns the new claim.
            saved = json.loads(service._private_bytes(backup_file))
            comparable = dict(record)
            saved.pop('maintenance_token', None)
            comparable.pop('maintenance_token', None)
            if saved != comparable:
                raise service.ServiceError('Existing upgrade backup does not match this transaction.')
        else:
            service._write_exclusive(backup_file, record_bytes)
        service._write_exclusive(pending_path, record_bytes)
        if action == 'upgrade-offline':
            require_offline_services()
            require_closed_listener(offline_payload)
        try:
            stop()
            write('candidate')
            start(port, auth)
        except BaseException as exc:
            try:
                stop()
                write('old')
                start(port, auth)
                pending_path.unlink()
            except BaseException:
                raise service.ServiceError('Upgrade failed and rollback is incomplete; run upgrade-rollback using this kit.') from exc
            raise service.ServiceError('Upgrade failed; previous services were restored and data retained.') from exc
        # A previous uninstall snapshot describes old units and must not survive a successful upgrade.
        resume = config_dir / service.RESUME_FILE
        if resume_original is not None:
            if service._private_bytes(resume) != resume_original:
                raise service.ServiceError('Previous recovery record changed; upgrade rollback remains available.')
            resume.unlink()
        pending_path.unlink()
        return {'upgraded': True, 'kit_sha256': kit_digest, 'data_preserved': True, 'backup_file': str(backup_file)}
    finally:
        if maintenance_token is not None:
            try:
                shared._release_scanner_maintenance(maintenance_payload, maintenance_token)
            except Exception:
                # A stopped engine drops its gate; restarted engines reject
                # tokens owned by the old process. Pending recovery stays private.
                pass
        os.close(lock)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('upgrade', 'upgrade-offline', 'upgrade-rollback'))
    parser.add_argument('--bundle', type=Path)
    parser.add_argument('--unit-dir', type=Path, required=True)
    parser.add_argument('--config-dir', type=Path, required=True)
    parser.add_argument('--data-home', type=Path, required=True)
    args = parser.parse_args()
    if args.action in {'upgrade', 'upgrade-offline'} and args.bundle is None:
        parser.error('upgrade requires --bundle')
    try:
        print(json.dumps(operate(args.action, args.bundle, args.unit_dir, args.config_dir, args.data_home), sort_keys=True))
    except (ValueError, OSError, subprocess.SubprocessError) as exc:
        parser.exit(1, str(exc) + '\n')


if __name__ == '__main__':
    main()
