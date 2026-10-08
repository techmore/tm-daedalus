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
    def stopped(self):
        for state in self.states.values():
            state.update(ActiveState='inactive', MainPID='0')

    def test_explicit_offline_upgrade_starts_new_services_without_http_maintenance(self):
        self.stopped()
        with patch.object(upgrade.shared, '_require_scanner_offline') as offline:
            result = self.operate('upgrade-offline')
        self.assertTrue(result['upgraded'])
        self.assertEqual(offline.call_count, 3)
        self.claim.assert_not_called()
        self.release.assert_not_called()
        self.assertEqual(self.enrollment.read_bytes(), self.original[self.enrollment])
        self.assertEqual(self.evidence.read_bytes(), self.original[self.evidence])

    def test_offline_upgrade_refuses_either_running_service(self):
        for name in self.states:
            with self.subTest(name=name):
                self.stopped(); self.states[name].update(ActiveState='active', MainPID='123')
                self.calls.clear()
                with self.assertRaisesRegex(ValueError, 'both managed services stopped'):
                    self.operate('upgrade-offline')
                self.assertFalse(any(c[2] in {'stop', 'start'} for c in self.calls))
        self.claim.assert_not_called()

    def test_offline_upgrade_refuses_open_or_unknown_listener_without_cutover(self):
        self.stopped()
        with patch.object(upgrade.shared, '_require_scanner_offline', side_effect=RuntimeError('Scanner offline state is unknown')):
            with self.assertRaisesRegex(ValueError, 'offline state is unknown'):
                self.operate('upgrade-offline')
        self.assertFalse((self.config / upgrade.PENDING).exists())
        self.assertFalse(any(c[2] in {'stop', 'start'} for c in self.calls))
        for path, raw in self.original.items():
            self.assertEqual(path.read_bytes(), raw)

    def test_offline_upgrade_rechecks_services_after_preparing(self):
        self.stopped()
        def prepare(files, support):
            result = self.prepare(files, support)
            self.states[service.NMAPUI_UNIT].update(ActiveState='active', MainPID='321')
            return result
        with patch.object(upgrade.shared, '_require_scanner_offline'):
            with self.assertRaisesRegex(ValueError, 'both managed services stopped'):
                self.operate('upgrade-offline', prepare=prepare)
        self.assertFalse((self.config / upgrade.PENDING).exists())
        self.assertFalse(any(c[2] in {'stop', 'start'} for c in self.calls))

    def test_offline_upgrade_late_listener_reappearance_keeps_recovery_without_stopping(self):
        self.stopped()
        with patch.object(upgrade.shared, '_require_scanner_offline', side_effect=[None, None, RuntimeError('listener reopened')]):
            with self.assertRaisesRegex(ValueError, 'listener reopened'):
                self.operate('upgrade-offline')
        self.assertTrue((self.config / upgrade.PENDING).exists())
        self.assertFalse(any(c[2] in {'stop', 'start'} for c in self.calls))
        for path, raw in self.original.items():
            self.assertEqual(path.read_bytes(), raw)

    def test_offline_failed_readiness_restores_old_descriptors(self):
        self.stopped()
        readiness = iter([False, True])
        with patch.object(upgrade.shared, '_require_scanner_offline'):
            with self.assertRaisesRegex(ValueError, 'previous services were restored'):
                self.operate('upgrade-offline', wait_ready=lambda *_: next(readiness))
        for path, raw in self.original.items():
            self.assertEqual(path.read_bytes(), raw)
        self.assertFalse((self.config / upgrade.PENDING).exists())

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
        self.enrollment.write_text('{"server":"https://portal.example","agent_id":7,"agent_token":"synthetic-enrollment"}')
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
        claim_patch = patch.object(upgrade.shared, '_acquire_scanner_maintenance', return_value='a' * 32)
        self.claim = claim_patch.start()
        self.addCleanup(claim_patch.stop)
        release_patch = patch.object(upgrade.shared, '_release_scanner_maintenance')
        self.release = release_patch.start()
        self.addCleanup(release_patch.stop)

    def test_busy_or_unsupported_engine_defers_before_stop_or_pending(self):
        self.claim.side_effect = RuntimeError('Scanner maintenance could not be acquired; upgrade deferred')
        with self.assertRaisesRegex(ValueError, 'upgrade deferred'):
            self.operate()
        self.assertFalse(any(c[2] == 'stop' for c in self.calls))
        self.assertFalse((self.config / upgrade.PENDING).exists())
        self.release.assert_not_called()
        for path, raw in self.original.items():
            self.assertEqual(path.read_bytes(), raw)

    def test_claim_precedes_stop_and_owner_is_released(self):
        events = []
        self.claim.side_effect = lambda *_: events.append('claim') or 'a' * 32
        self.release.side_effect = lambda *_: events.append('release')
        def executor(argv, **kwargs):
            if argv[2] in {'stop', 'start'}:
                events.append(argv[2])
            return self.execute(argv, **kwargs)
        result = self.operate(executor=executor)
        self.assertEqual(events, ['claim', 'stop', 'stop', 'start', 'start', 'release'])
        record = json.loads(Path(result['backup_file']).read_text())
        self.assertEqual(record['maintenance_token'], 'a' * 32)
        self.assertNotIn('a' * 32, json.dumps(result))

    def test_recovery_reclaims_persisted_owner_before_stopping_active_engine(self):
        with self.assertRaisesRegex(ValueError, 'rollback is incomplete'):
            self.operate(wait_ready=lambda *_: False)
        self.claim.reset_mock()
        self.operate('upgrade-rollback')
        self.assertEqual(self.claim.call_args.args[1], 'a' * 32)

    def test_busy_recovery_keeps_pending_and_services_untouched(self):
        with self.assertRaises(ValueError):
            self.operate(wait_ready=lambda *_: False)
        self.calls.clear()
        self.claim.side_effect = RuntimeError('Scanner is busy; upgrade deferred')
        with self.assertRaisesRegex(ValueError, 'upgrade deferred'):
            self.operate('upgrade-rollback')
        self.assertFalse(any(c[2] in {'stop', 'start'} for c in self.calls))
        self.assertTrue((self.config / upgrade.PENDING).exists())

    def test_recovery_persists_fresh_owner_before_service_operation(self):
        with self.assertRaises(ValueError):
            self.operate(wait_ready=lambda *_: False)
        self.claim.return_value = 'b' * 32
        def interrupt_stop(argv, **kwargs):
            if argv[2] == 'stop':
                record = json.loads((self.config / upgrade.PENDING).read_text())
                self.assertEqual(record['maintenance_token'], 'b' * 32)
                raise OSError('fixture interruption')
            return self.execute(argv, **kwargs)
        with self.assertRaisesRegex(ValueError, 'service operation failed'):
            self.operate('upgrade-rollback', executor=interrupt_stop)
        self.assertEqual(json.loads((self.config / upgrade.PENDING).read_text())['maintenance_token'], 'b' * 32)

    def test_recovery_of_stopped_engine_does_not_require_http(self):
        with self.assertRaises(ValueError):
            self.operate(wait_ready=lambda *_: False)
        self.states[service.NMAPUI_UNIT].update(ActiveState='inactive', MainPID='0')
        self.claim.reset_mock()
        self.operate('upgrade-rollback')
        self.claim.assert_not_called()

    def test_recovery_rejects_ambiguous_engine_state(self):
        with self.assertRaises(ValueError):
            self.operate(wait_ready=lambda *_: False)
        self.states[service.NMAPUI_UNIT].update(ActiveState='activating', MainPID='0')
        self.calls.clear()
        with self.assertRaisesRegex(ValueError, 'activity is unknown'):
            self.operate('upgrade-rollback')
        self.assertFalse(any(c[2] == 'stop' for c in self.calls))

    def test_invalid_pending_owner_is_refused_before_service_operations(self):
        with self.assertRaises(ValueError):
            self.operate(wait_ready=lambda *_: False)
        path = self.config / upgrade.PENDING
        record = json.loads(path.read_text()); record['maintenance_token'] = 'invalid'
        path.write_text(json.dumps(record))
        self.calls.clear()
        with self.assertRaisesRegex(ValueError, 'recovery files changed'):
            self.operate('upgrade-rollback')
        self.assertFalse(self.calls)

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
        unit = (self.unit_dir / service.NMAPUI_UNIT).read_text()
        self.assertIn('NMAPUI_MANAGEMENT_PORTAL_URL=', unit)
        self.assertIn('https://portal.example', unit)
        self.assertNotIn('synthetic-enrollment', unit)
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
