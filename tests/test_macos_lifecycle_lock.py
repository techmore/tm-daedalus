"""The standalone helper and deployed bridge share one lifecycle lock."""
import os
import tempfile
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from daedalus.agent import NmapUIBridge
from daedalus.agent_bundle import macos_service


class MacLifecycleLockTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.support = self.root / 'Library/Application Support/Daedalus'
        self.support.mkdir(parents=True)
        self.path = self.support / macos_service.LIFECYCLE_LOCK_FILE
        self.bridge = NmapUIBridge.__new__(NmapUIBridge)
        self.bridge.config = {'nmapui_service_label': 'org.daedalus.nmapui'}
        home = patch('daedalus.agent.Path.home', return_value=self.root)
        platform = patch('daedalus.agent.sys.platform', 'darwin')
        home.start()
        platform.start()
        self.addCleanup(home.stop)
        self.addCleanup(platform.stop)

    def test_helper_excludes_remote_restart_without_service_changes(self):
        with macos_service.lifecycle_lock(self.root), patch.object(self.bridge, '_restart_managed_nmapui_locked') as restart:
            with self.assertRaisesRegex(RuntimeError, 'lifecycle'):
                self.bridge._restart_managed_nmapui()
            restart.assert_not_called()
        with self.bridge._managed_restart_lock():
            pass

    def test_remote_restart_excludes_local_mutations(self):
        with self.bridge._managed_restart_lock():
            for action in ('restart', 'uninstall', 'restore'):
                executor = Mock()
                with self.subTest(action=action), self.assertRaisesRegex(RuntimeError, 'lifecycle'):
                    macos_service.manage_services(action, user_root=self.root, executor=executor)
                executor.assert_not_called()
            with self.assertRaisesRegex(RuntimeError, 'lifecycle'):
                with macos_service.lifecycle_lock(self.root):
                    self.fail('second action admitted')

    def test_exception_releases_lock_and_preserves_inode(self):
        with self.assertRaisesRegex(RuntimeError, 'fixture'):
            with macos_service.lifecycle_lock(self.root):
                inode = self.path.stat().st_ino
                raise RuntimeError('fixture')
        with self.bridge._managed_restart_lock():
            self.assertEqual(self.path.stat().st_ino, inode)
            self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)

    def test_separate_process_cannot_enter_held_helper_lock(self):
        code = '''
import sys
from pathlib import Path
from daedalus.agent_bundle.macos_service import lifecycle_lock
try:
    with lifecycle_lock(Path(sys.argv[1])):
        raise SystemExit(2)
except RuntimeError:
    print("lifecycle action deferred")
'''
        environment = {**os.environ, 'PYTHONPATH': str(Path(__file__).resolve().parents[1] / 'src')}
        with self.bridge._managed_restart_lock():
            result = subprocess.run([sys.executable, '-c', code, str(self.root)],
                                    capture_output=True, text=True, timeout=10, env=environment)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), 'lifecycle action deferred')

    def assert_both_refuse(self):
        for context in (macos_service.lifecycle_lock(self.root), self.bridge._managed_restart_lock()):
            with self.assertRaises((ValueError, RuntimeError, OSError)):
                with context:
                    self.fail('unsafe lock admitted')

    def test_symlink_fifo_and_public_lock_refused(self):
        outside = self.root / 'outside'
        outside.write_bytes(b'unchanged')
        self.path.symlink_to(outside)
        self.assert_both_refuse()
        self.assertEqual(outside.read_bytes(), b'unchanged')
        self.path.unlink()
        os.mkfifo(self.path, 0o600)
        self.assert_both_refuse()
        self.path.unlink()
        self.path.write_bytes(b'')
        self.path.chmod(0o644)
        self.assert_both_refuse()

    def test_hard_link_wrong_owner_and_writable_directory_refused(self):
        self.path.write_bytes(b'')
        self.path.chmod(0o600)
        os.link(self.path, self.root / 'second-link')
        self.assert_both_refuse()
        (self.root / 'second-link').unlink()
        self.support.chmod(0o777)
        self.assert_both_refuse()
        self.support.chmod(0o755)
        with patch('os.getuid', return_value=os.getuid() + 1):
            self.assert_both_refuse()

    def test_symlink_directory_refused(self):
        self.support.rmdir()
        outside = self.root / 'outside'
        outside.mkdir()
        self.support.symlink_to(outside, target_is_directory=True)
        self.assert_both_refuse()
        self.assertFalse((outside / macos_service.LIFECYCLE_LOCK_FILE).exists())

    def test_missing_installation_remote_restart_returns_bounded_failure(self):
        self.support.rmdir()
        with patch.object(self.bridge, '_restart_managed_nmapui_locked') as restart:
            with self.assertRaisesRegex(RuntimeError, 'verification failed'):
                self.bridge._restart_managed_nmapui()
            restart.assert_not_called()
