"""Offline Linux upgrade transactions; no real installs or service operations."""
from argparse import Namespace
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from daedalus.agent_bundle import linux_upgrade as upgrade, systemd_service as service
from test_managed_scanner_upgrade import make_bundle


class LinuxUpgradeTests(unittest.TestCase):
    def test_missing_recovery_transaction_has_clear_message(self):
        with self.assertRaisesRegex(service.ServiceError, 'No interrupted upgrade transaction'):
            upgrade.read_pending(self.unit_dir, self.config)

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='daedalus-linux-upgrade-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.unit_dir = self.root / 'config with spaces/systemd/user'
        self.config = self.root / 'config with spaces/daedalus'
        self.data_home = self.root / 'data with spaces'
        self.support = self.data_home / 'daedalus'
        self.config.mkdir(parents=True, mode=0o700)
        self.enrollment = self.config / 'managed-agent.json'
        self.enrollment.write_text('{"agent_id":7,"agent_token":"synthetic-enrollment"}')
        self.enrollment.chmod(0o600)
        self.evidence = self.support / 'nmapui-data/evidence.json'
        self.evidence.parent.mkdir(parents=True)
        self.evidence.write_text('retain scan evidence')
        self.password = 'fixture$`password\\"'
        args = Namespace(unit_dir=str(self.unit_dir), config_dir=str(self.config), nmapui_python=str(self.support / 'nmapui/releases/old/.venv/bin/python'), nmapui_app_dir=str(self.support / 'nmapui/releases/old/daedalus-nmapui-source'), nmapui_data_dir=str(self.evidence.parent), browser_dir=str(self.support / 'nmapui/releases/old/playwright-browsers'), agent_executable=str(self.support / 'scanner-bridge/.venv/bin/daedalus-agent'), bridge_working_dir=str(self.support / 'scanner-bridge'), agent_config=str(self.enrollment), port=9137)
        with patch.dict(os.environ, {'NMAPUI_USERNAME': 'fixture user', 'NMAPUI_PASSWORD': self.password}):
            service.install(args)
        self.original = {path: path.read_bytes() for path in [*upgrade.paths(self.unit_dir, self.config).values(), self.config / service.ENV_FILE, self.enrollment, self.evidence]}
        self.bundle = self.root / 'kit.zip'
        make_bundle(self.bundle)
        self.calls = []
        self.states = {name: {'LoadState':'loaded', 'ActiveState':'active', 'MainPID':'123', 'FragmentPath':str(self.unit_dir / name), 'DropInPaths':'', 'UnitFileState':'enabled'} for name in (service.NMAPUI_UNIT, service.BRIDGE_UNIT)}
        self.pid = 123
        self.readiness = []

    def prepare(self, files, support):
        nmap_hash = upgrade.digest(files['nmapui-source.zip'])
        bridge_hash = upgrade.digest(b''.join(files[k] for k in sorted(upgrade.shared.REQUIRED_KIT_FILES - {'nmapui-source.zip'})))
        nmap = support / 'nmapui/releases' / nmap_hash
        bridge = support / 'scanner-bridge/releases' / bridge_hash
        for path in (nmap / '.venv/bin/python', bridge / '.venv/bin/daedalus-agent', nmap / 'daedalus-nmapui-source/app.py'):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('fixture executable not launched')
            path.chmod(0o700)
        return nmap, bridge

    def execute(self, argv, **kwargs):
        self.calls.append(argv)
        self.assertEqual(argv[:2], [service.SYSTEMCTL, '--user'])
        self.assertEqual(kwargs['timeout'], 30)
        action = argv[2]
        if action == 'show':
            return subprocess.CompletedProcess(argv, 0, '\n'.join(key+'='+value for key,value in self.states[argv[-1]].items()), '')
        if action == 'stop':
            self.states[argv[-1]].update(ActiveState='inactive', MainPID='0')
        elif action == 'start':
            self.pid += 1
            self.states[argv[-1]].update(ActiveState='active', MainPID=str(self.pid))
        elif action != 'daemon-reload':
            raise AssertionError('Unexpected manager action')
        return subprocess.CompletedProcess(argv, 0, '', '')

    def ready(self, port, auth):
        self.readiness.append((port, auth))
        return True

    def operate(self, action='upgrade', **kwargs):
        return upgrade.operate(action, self.bundle, self.unit_dir, self.config, self.data_home, executor=kwargs.pop('executor', self.execute), prepare=kwargs.pop('prepare', self.prepare), wait_ready=kwargs.pop('wait_ready', self.ready), **kwargs)

    def assert_retained(self):
        for path in (self.enrollment, self.evidence, self.config / service.ENV_FILE):
            self.assertEqual(path.read_bytes(), self.original[path])

    def test_upgrade_preserves_enrollment_evidence_auth_and_updates_fingerprints(self):
        result = self.operate()
        self.assertTrue(result['upgraded'])
        backup = Path(result['backup_file'])
        self.assertEqual(backup.stat().st_mode & 0o777, 0o600)
        saved = json.loads(backup.read_text())
        self.assertEqual(saved['old'][service.NMAPUI_UNIT].encode(), self.original[self.unit_dir / service.NMAPUI_UNIT])
        self.assert_retained()
        service.verify(self.unit_dir, self.config)
        self.assertEqual(self.readiness, [(9137, {'NMAPUI_USERNAME':'fixture user', 'NMAPUI_PASSWORD':self.password})])
        self.assertFalse((self.config / upgrade.PENDING).exists())
        self.assertEqual([call[-1] for call in self.calls if call[2] == 'stop'], [service.BRIDGE_UNIT, service.NMAPUI_UNIT])
        self.assertEqual([call[-1] for call in self.calls if call[2] == 'start'], [service.NMAPUI_UNIT, service.BRIDGE_UNIT])
        self.assertNotIn('synthetic-enrollment', json.dumps(result))

    def test_failed_candidate_readiness_restores_exact_old_descriptors(self):
        answers = iter((False, True))
        with self.assertRaisesRegex(ValueError, 'previous services were restored'):
            self.operate(wait_ready=lambda *_: next(answers))
        for path, contents in self.original.items():
            self.assertEqual(path.read_bytes(), contents)
        self.assertFalse((self.config / upgrade.PENDING).exists())
        service.verify(self.unit_dir, self.config)

    def test_incomplete_rollback_can_be_resumed_explicitly(self):
        with self.assertRaisesRegex(ValueError, 'rollback is incomplete'):
            self.operate(wait_ready=lambda *_: False)
        self.assertTrue((self.config / upgrade.PENDING).exists())
        with self.assertRaisesRegex(ValueError, 'interrupted upgrade'):
            self.operate()
        result = self.operate('upgrade-rollback')
        self.assertTrue(result['rolled_back'])
        for path, contents in self.original.items():
            self.assertEqual(path.read_bytes(), contents)
        self.assertFalse((self.config / upgrade.PENDING).exists())

    def test_interrupted_partial_descriptor_write_is_recoverable(self):
        with self.assertRaises(ValueError):
            self.operate(wait_ready=lambda *_: False)
        record = json.loads((self.config / upgrade.PENDING).read_text())
        (self.unit_dir / service.NMAPUI_UNIT).write_text(record['candidate'][service.NMAPUI_UNIT])
        self.operate('upgrade-rollback')
        for path, contents in self.original.items():
            self.assertEqual(path.read_bytes(), contents)

    def test_lifecycle_lock_refuses_overlapping_upgrade(self):
        import fcntl
        lock = self.config / service.LOCK_FILE
        with lock.open('w') as stream:
            lock.chmod(0o600)
            fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaisesRegex(ValueError, 'lifecycle action is running'):
                self.operate()
        self.assertFalse(self.calls)
        self.assert_retained()

    def test_failed_stop_does_not_switch_descriptors(self):
        failed = False
        def fail_once(argv, **kwargs):
            nonlocal failed
            if argv[2] == 'stop' and not failed:
                failed = True
                return subprocess.CompletedProcess(argv, 1, 'withheld', '')
            return self.execute(argv, **kwargs)
        with self.assertRaisesRegex(ValueError, 'previous services were restored'):
            self.operate(executor=fail_once)
        for path, contents in self.original.items():
            self.assertEqual(path.read_bytes(), contents)

    def test_recovery_refuses_tampered_backup_before_operations(self):
        with self.assertRaises(ValueError):
            self.operate(wait_ready=lambda *_: False)
        path = self.config / upgrade.PENDING
        record = json.loads(path.read_text())
        record['old'][service.BRIDGE_UNIT] += '# tampered\n'
        path.write_text(json.dumps(record))
        calls = len(self.calls)
        with self.assertRaisesRegex(ValueError, 'recovery files changed'):
            self.operate('upgrade-rollback')
        self.assertEqual(len(self.calls), calls)
        self.assert_retained()

    def test_loaded_dropin_refused_before_preparing(self):
        self.states[service.BRIDGE_UNIT]['DropInPaths'] = '/unknown/override.conf'
        with self.assertRaisesRegex(ValueError, 'override'):
            self.operate(prepare=lambda *_: self.fail('Prepared unexpected services'))
        self.assertFalse(any(call[2] == 'stop' for call in self.calls))
        self.assert_retained()

    def test_enrollment_change_during_preparation_refused_before_stop(self):
        def change(files, support):
            releases = self.prepare(files, support)
            self.enrollment.write_text('changed enrollment')
            return releases
        with self.assertRaisesRegex(ValueError, 'changed while preparing'):
            self.operate(prepare=change)
        self.assertFalse(any(call[2] == 'stop' for call in self.calls))

    def test_same_kit_is_a_noop_after_first_upgrade(self):
        self.operate()
        self.calls.clear()
        result = self.operate()
        self.assertTrue(result['already_current'])
        self.assertFalse(result['upgraded'])
        self.assertFalse(any(call[2] in {'stop', 'start'} for call in self.calls))
        self.assert_retained()

    def test_pending_upgrade_blocks_uninstall_and_restore(self):
        with self.assertRaises(ValueError):
            self.operate(wait_ready=lambda *_: False)
        for action in ('uninstall', 'restore'):
            with self.assertRaisesRegex(ValueError, 'pending upgrade'):
                service.manage(action, self.unit_dir, self.config, executor=lambda *_a, **_k: self.fail('Unexpected lifecycle operation'))

    def test_changed_current_descriptor_refused_before_prepare(self):
        (self.unit_dir / service.NMAPUI_UNIT).write_text('unknown unit')
        with self.assertRaisesRegex(ValueError, 'changed after installation'):
            self.operate(prepare=lambda *_: self.fail('Prepared changed installation'))
        self.assertFalse(self.calls)
