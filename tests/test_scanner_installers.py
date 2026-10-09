"""Offline installer/lifecycle fixtures; no real pip, enrollment or launchctl."""
import importlib.util
import fcntl
import json
import os
from argparse import Namespace
from pathlib import Path
import plistlib
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
BUNDLE = ROOT / 'src/daedalus/agent_bundle'
spec = importlib.util.spec_from_file_location('installer_macos_service', BUNDLE / 'macos_service.py')
service = importlib.util.module_from_spec(spec)
spec.loader.exec_module(service)
systemd_spec = importlib.util.spec_from_file_location('installer_systemd_service', BUNDLE / 'systemd_service.py')
systemd_service = importlib.util.module_from_spec(systemd_spec)
systemd_spec.loader.exec_module(systemd_service)


class ScannerInstallerFixtures(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='daedalus-installer-fixture-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def foreground_fixture(self):
        kit = self.root / 'kit'
        (kit / 'src/daedalus').mkdir(parents=True)
        for name in ['install.sh', 'pyproject.toml']:
            shutil.copyfile(BUNDLE / name, kit / name)
        for name in ['__init__.py', 'agent.py', 'command_journal.py', 'scanner_activity.py', 'scanner_delivery.py']:
            shutil.copyfile(ROOT / 'src/daedalus' / name, kit / 'src/daedalus' / name)
        tools = self.root / 'tools'
        tools.mkdir()
        (tools / 'uname').write_text("#!/bin/sh\nprintf '%s\\n' Linux\n")
        (tools / 'uname').chmod(0o700)
        recorder = self.root / 'argv.json'
        python_stub = tools / 'python-fixture'
        python_stub.write_text(f'''#!{sys.executable}
import json,os,pathlib,shutil,subprocess,sys
args=sys.argv[1:]
if pathlib.Path(sys.argv[0]).name == "daedalus-agent":
 pathlib.Path({str(recorder)!r}).write_text(json.dumps(args));raise SystemExit(0)
if args[:1] == ["-c"]: raise SystemExit(0)
if args[:2] == ["-m","venv"]:
 out=pathlib.Path(args[2])/"bin";out.mkdir(parents=True,exist_ok=True)
 for name in ["python","daedalus-agent"]:
  shutil.copyfile({str(python_stub)!r},out/name);(out/name).chmod(0o700)
 raise SystemExit(0)
if args[:3] == ["-m","pip","install"]:
 source=pathlib.Path(args[-1])/"src"
 code="import sys,pathlib;sys.path.insert(0,"+repr(str(source))+");import daedalus.agent,daedalus.command_journal;assert pathlib.Path(daedalus.agent.__file__).resolve().is_relative_to(pathlib.Path("+repr(str(source))+").resolve())"
 raise SystemExit(subprocess.run([{sys.executable!r},"-c",code],cwd=source.parent,env={{**os.environ,"PYTHONPATH":str(source)}}).returncode)
raise SystemExit("Unexpected fixture Python invocation")
''')
        python_stub.chmod(0o700)
        environment = {'PATH': str(tools)+os.pathsep+os.environ['PATH'], 'HOME': os.environ['HOME'], 'XDG_DATA_HOME': str(self.root / 'data-home'), 'PYTHON_BIN': str(python_stub), 'NMAPUI_URL': 'http://127.0.0.1:9000'}
        return kit, environment, recorder

    def test_fresh_linux_bridge_installer_copies_required_runtime_and_uses_xdg(self):
        kit, environment, recorder = self.foreground_fixture()
        response = subprocess.run(['/bin/sh', str(kit / 'install.sh'), 'https://fixture.invalid', 'Fixture scanner'], env=environment, capture_output=True, text=True, timeout=15)
        self.assertEqual(response.returncode, 0, response.stderr)
        installed = self.root / 'data-home/daedalus/scanner-bridge'
        self.assertTrue((installed / 'src/daedalus/command_journal.py').is_file())
        self.assertTrue((installed / 'src/daedalus/scanner_activity.py').is_file())
        self.assertTrue((installed / 'src/daedalus/scanner_delivery.py').is_file())
        self.assertEqual(installed.stat().st_mode & 0o777, 0o700)
        self.assertEqual(json.loads(recorder.read_text()), ['--server', 'https://fixture.invalid', '--nmapui-url', 'http://127.0.0.1:9000', '--name', 'Fixture scanner'])

    def linux_managed_install(self, fail_unit=None, fail_stop_unit=None):
        kit = self.root / 'linux-kit'
        (kit / 'src/daedalus').mkdir(parents=True)
        for name in ['install-service-linux.sh', 'manage-service-linux.sh', 'install-nmapui.sh', 'systemd_service.py', 'pyproject.toml']:
            shutil.copyfile(BUNDLE / name, kit / name)
        for name in ['__init__.py', 'agent.py', 'command_journal.py', 'scanner_activity.py', 'scanner_delivery.py']:
            shutil.copyfile(ROOT / 'src/daedalus' / name, kit / 'src/daedalus' / name)
        with zipfile.ZipFile(kit / 'nmapui-source.zip', 'w') as source:
            source.writestr('daedalus-nmapui-source/app.py', '# fixture only\n')
            source.writestr('daedalus-nmapui-source/requirements.txt', '')
        tools = self.root / 'linux-tools'
        tools.mkdir()
        recorder = self.root / 'linux-installer-records.json'
        python_stub = tools / 'python-fixture'
        python_stub.write_text(f'''#!{sys.executable}
import hashlib,json,os,pathlib,shutil,subprocess,sys,zipfile
args=sys.argv[1:]
if args[:1] == ["-c"]: raise SystemExit(0)
if args[:2] == ["-m","venv"]:
 out=pathlib.Path(args[2]) / "bin";out.mkdir(parents=True,exist_ok=True)
 for name in ["python","daedalus-agent"]: shutil.copyfile({str(python_stub)!r},out/name);(out/name).chmod(0o700)
 raise SystemExit(0)
if args[:3] == ["-m","pip","install"] or args[:3] == ["-m","playwright","install"]: raise SystemExit(0)
if args and args[0].endswith("systemd_service.py"):
 raise SystemExit(subprocess.run([{sys.executable!r},*args],env=os.environ).returncode)
if pathlib.Path(sys.argv[0]).name == "daedalus-agent":
 pathlib.Path({str(recorder)!r}).write_text(json.dumps(args))
 config=pathlib.Path(args[args.index("--config-path")+1]);config.parent.mkdir(parents=True,exist_ok=True)
 config.write_text(json.dumps({{"server":"https://fixture.invalid","agent_id":7,"agent_name":"fixture","organization":"fixture.invalid","agent_token":"synthetic-token","nmapui_url":"http://127.0.0.1:9000"}}));config.chmod(0o600)
 raise SystemExit(0)
if args[:1] == ["-"]:
 if len(args)>1 and args[1].startswith("http://"):
  marker=pathlib.Path({str(self.root/'readiness-count')!r});count=int(marker.read_text()) if marker.exists() else 0;marker.write_text(str(count+1));raise SystemExit(1 if count==0 else 0)
 if len(args)>1 and args[1].isdigit(): raise SystemExit(1)
 if len(args)>1:
  print(hashlib.sha256(pathlib.Path(args[1]).read_bytes()).hexdigest());raise SystemExit(0)
 raise SystemExit(0)
raise SystemExit("Unexpected fixture Python invocation: "+repr(args))
''')
        python_stub.chmod(0o700)
        for name, body in {
            'uname': '#!/bin/sh\nprintf "%s\\n" Linux\n',
            'nmap': '#!/bin/sh\nexit 0\n',
            'systemctl': f'''#!/bin/sh
printf '%s\\n' "$*" >> {str(recorder)!r}.systemctl
case "$*" in *"is-active"*|*"is-enabled"*) exit 0;; esac
if [ "$*" = "--user enable --now $FIXTURE_FAIL_UNIT" ] || [ "$*" = "--user stop $FIXTURE_FAIL_STOP_UNIT" ]; then exit 1; fi
exit 0
''',
        }.items():
            path=tools/name;path.write_text(body);path.chmod(0o700)
        environment = {
            'PATH': str(tools)+os.pathsep+os.environ['PATH'],
            'HOME': str(self.root/'home'),
            'XDG_DATA_HOME': str(self.root/'data-home'),
            'XDG_CONFIG_HOME': str(self.root/'config-home'),
            'PYTHON_BIN': str(python_stub),
            'FIXTURE_FAIL_UNIT': fail_unit or '',
            'FIXTURE_FAIL_STOP_UNIT': fail_stop_unit or '',
            'NMAPUI_USERNAME': 'scanner user',
            'NMAPUI_PASSWORD': 'fixture"secret\\$value',
        }
        response = subprocess.run(['/bin/sh', str(kit/'install-service-linux.sh'), 'https://fixture.invalid', 'CSP VLAN 10'], env=environment, capture_output=True, text=True, timeout=20)
        return response, recorder, environment

    def test_linux_managed_installer_prepares_enrolls_and_starts_fixed_services(self):
        response, recorder, environment = self.linux_managed_install()
        self.assertEqual(response.returncode, 0, response.stderr+response.stdout)
        config = self.root/'config-home/daedalus/managed-agent.json'
        unit_dir = self.root/'config-home/systemd/user'
        units = [unit_dir/'daedalus-nmapui.service',unit_dir/'daedalus-scanner-bridge.service']
        self.assertTrue(config.is_file())
        self.assertFalse((self.root / 'data-home/nmapui').exists())
        self.assertTrue((self.root / 'data-home/daedalus/nmapui-data/logs').is_dir())
        self.assertEqual(config.stat().st_mode & 0o777, 0o600)
        self.assertTrue(all(unit.is_file() for unit in units))
        self.assertIn('NMAPUI_TRUST_LOCAL_UI="false"', units[0].read_text())
        self.assertIn('Environment=XDG_CONFIG_HOME=' + systemd_service._environment_quote(str(config.parent.parent), 'fixture'), units[1].read_text())
        self.assertIn(f'Environment=XDG_RUNTIME_DIR="/run/user/{os.getuid()}"', units[1].read_text())
        self.assertIn(f'Environment=DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/{os.getuid()}/bus"', units[1].read_text())
        self.assertNotIn(environment['NMAPUI_PASSWORD'], ''.join(unit.read_text() for unit in units))
        self.assertIn('loginctl enable-linger', response.stdout)
        commands=(Path(str(recorder)+'.systemctl')).read_text().splitlines()
        self.assertLess(commands.index('--user enable --now daedalus-nmapui.service'),commands.index('--user enable --now daedalus-scanner-bridge.service'))
        enrollment_args = json.loads(recorder.read_text())
        for flag, value in (
            ('--nmapui-systemd-unit-dir', str(unit_dir)),
            ('--nmapui-systemd-config-dir', str(self.root/'config-home/daedalus')),
        ):
            self.assertEqual(enrollment_args[enrollment_args.index(flag)+1], value)

    def check_linux_partial_start_failure(self, unit, expected_stops):
        response, recorder, _ = self.linux_managed_install(fail_unit=unit)
        self.assertNotEqual(response.returncode, 0)
        self.assertIn('Service startup failed', response.stderr)
        commands = Path(str(recorder) + '.systemctl').read_text().splitlines()
        stops = [command for command in commands if command.startswith('--user stop ')]
        self.assertEqual(stops, ['--user stop ' + name for name in expected_stops])
        config = self.root / 'config-home/daedalus'
        self.assertTrue((config / 'managed-agent.json').is_file())
        self.assertTrue((config / systemd_service.STATE_FILE).is_file())
        systemd_service.verify(self.root / 'config-home/systemd/user', config)

    def test_linux_partial_nmapui_start_is_stopped_and_enrollment_retained(self):
        self.check_linux_partial_start_failure(systemd_service.NMAPUI_UNIT, [systemd_service.NMAPUI_UNIT])

    def test_linux_partial_bridge_start_stops_both_services_and_retains_enrollment(self):
        self.check_linux_partial_start_failure(systemd_service.BRIDGE_UNIT, [systemd_service.BRIDGE_UNIT, systemd_service.NMAPUI_UNIT])

    def test_linux_failed_cleanup_reports_running_risk_and_attempts_other_stop(self):
        response, recorder, _ = self.linux_managed_install(
            fail_unit=systemd_service.BRIDGE_UNIT, fail_stop_unit=systemd_service.BRIDGE_UNIT,
        )
        self.assertNotEqual(response.returncode, 0)
        self.assertIn('Could not stop daedalus-scanner-bridge.service', response.stderr)
        self.assertIn('may still be running', response.stderr)
        commands = Path(str(recorder) + '.systemctl').read_text().splitlines()
        self.assertIn('--user stop daedalus-nmapui.service', commands)
        self.assertTrue((self.root / 'config-home/daedalus/managed-agent.json').is_file())

    def test_nested_bridge_module_symlink_is_rejected_before_overwrite(self):
        kit, environment, recorder = self.foreground_fixture()
        destination = self.root / 'data-home/daedalus/scanner-bridge/src/daedalus'
        destination.mkdir(parents=True)
        outside = self.root / 'untouched.txt'
        outside.write_text('keep fixture evidence')
        (destination / 'command_journal.py').symlink_to(outside)
        response = subprocess.run(['/bin/sh', str(kit / 'install.sh'), 'https://fixture.invalid', 'Fixture'], env=environment, capture_output=True, text=True, timeout=5)
        self.assertNotEqual(response.returncode, 0)
        self.assertIn('symbolic link', response.stderr)
        self.assertEqual(outside.read_text(), 'keep fixture evidence')
        self.assertFalse(recorder.exists())

    def test_managed_rollback_removes_only_recorded_created_files(self):
        source = (BUNDLE / 'install-service-macos.sh').read_text()
        function = source.split('rollback_failed_install() {', 1)[1].split('\ntrap rollback_failed_install EXIT', 1)[0]
        files = [self.root / name for name in ['config.json', 'nmapui.plist', 'bridge.plist']]
        for created in [0, 1]:
            for path in files: path.write_text('retained fixture')
            script = 'rollback_failed_install() {' + function + '\ntrap rollback_failed_install EXIT\nexit 1\n'
            environment = {'PATH': os.environ['PATH'], 'PYTHON_BIN': sys.executable, 'CONFIG_PATH': str(files[0]), 'NMAPUI_PLIST': str(files[1]), 'BRIDGE_PLIST': str(files[2]), 'CONFIG_CREATED': str(created), 'NMAPUI_PLIST_CREATED': '0', 'BRIDGE_PLIST_CREATED': '0', 'BRIDGE_LOADED': '0', 'NMAPUI_LOADED': '0'}
            response = subprocess.run(['/bin/sh'], input=script, env=environment, capture_output=True, text=True, timeout=5)
            self.assertEqual(response.returncode, 1)
            self.assertEqual(files[0].exists(), created == 0)
            self.assertTrue(files[1].exists() and files[2].exists())

    def test_managed_installer_includes_journal_and_exclusive_plists(self):
        source = (BUNDLE / 'install-service-macos.sh').read_text()
        self.assertIn('"$SCRIPT_DIR/src/daedalus/command_journal.py" "$BRIDGE_SOURCE/command_journal.py"', source)
        self.assertIn('--output "$NMAPUI_PLIST" --exclusive', source)
        self.assertIn('--output "$BRIDGE_PLIST" --exclusive', source)
        self.assertIn('NMAPUI_DATA_ROOT="$APP_SUPPORT/nmapui-data"', source)
        self.assertIn('DAEDALUS_NMAPUI_DATA_ROOT="$NMAPUI_DATA_ROOT"', source)
        nmapui_source = (BUNDLE / 'install-nmapui.sh').read_text()
        self.assertIn('DATA_ROOT=${DAEDALUS_NMAPUI_DATA_ROOT:-"$APP_SUPPORT/nmapui-data"}', nmapui_source)


class ManagedLifecycleFixtures(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='daedalus-service-fixture-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.support = self.root / 'Library/Application Support/Daedalus'
        self.bridge = self.support / 'scanner-bridge'
        self.data = self.support / 'nmapui-data'
        self.release = self.support / 'nmapui/releases' / ('a' * 64)
        self.plists = self.root / 'Library/LaunchAgents'
        with patch.dict(os.environ, {'NMAPUI_USERNAME': '', 'NMAPUI_PASSWORD': '', 'NMAPUI_TRUST_LOCAL_UI': 'false', 'NMAPUI_COOKIE_SECURE': 'false'}):
            nmapui = service.build_nmapui_plist(python=str(self.release / '.venv/bin/python'), app_dir=str(self.release / 'daedalus-nmapui-source'), data_dir=str(self.data), log_dir=str(self.data / 'logs'), browser_dir=str(self.release / 'browsers'), port=9000)
            bridge = service.build_bridge_plist(agent_executable=str(self.bridge / '.venv/bin/daedalus-agent'), config_path=str(self.support / 'managed-agent.json'), install_dir=str(self.bridge), log_dir=str(self.support / 'logs'))
        for label, payload in [(service.NMAPUI_LABEL, nmapui), (service.BRIDGE_LABEL, bridge)]:
            service.write_plist(self.plists / (label+'.plist'), payload)
        self.support.mkdir(parents=True, exist_ok=True)
        self.retained = [self.support / 'managed-agent.json', self.support / 'saved-evidence.json']
        for path in self.retained: path.write_text('synthetic retained fixture')
        self.retained[0].write_text(json.dumps({'server': 'https://fixture.invalid', 'agent_id': 1, 'organization': 'fixture.invalid', 'agent_token': 'synthetic-not-a-real-token'}))
        self.retained[0].chmod(0o600)
        self.original_retained = [path.read_bytes() for path in self.retained]
        for executable in [self.bridge / '.venv/bin/daedalus-agent', self.release / '.venv/bin/python']:
            executable.parent.mkdir(parents=True, exist_ok=True)
            executable.write_text('fixture executable never launched')
            executable.chmod(0o700)
        app = self.release / 'daedalus-nmapui-source/app.py'
        app.parent.mkdir(parents=True, exist_ok=True)
        app.write_text('fixture source never launched')

    def test_status_never_changes_services_or_exposes_plist_credentials(self):
        executor = Mock(return_value=subprocess.CompletedProcess([], 0, 'private process environment', ''))
        result = service.manage_services('status', user_root=self.root, executor=executor)
        self.assertEqual(len(result['services']), 2)
        self.assertTrue(all(call.args[0][1] == 'print' for call in executor.call_args_list))
        self.assertNotIn('private', json.dumps(result))
        self.assertTrue(all(path.exists() for path in self.retained))

    def test_status_distinguishes_loaded_crash_loop_from_running_service(self):
        executor = Mock(return_value=subprocess.CompletedProcess([], 0, 'state = spawn scheduled\nlast exit code = 126\n', ''))
        result = service.manage_services('status', user_root=self.root, executor=executor)
        self.assertEqual({item['state'] for item in result['services']}, {'loaded_not_running'})

    def test_managed_lifecycle_accepts_legacy_path_but_rejects_foreign_data_root(self):
        path = self.plists / (service.NMAPUI_LABEL + '.plist')
        payload = plistlib.loads(path.read_bytes())
        environment = payload['EnvironmentVariables']
        legacy = self.root / 'Library/Application Support/NmapUI'
        environment['NMAPUI_DATA_DIR'] = str(legacy / 'data')
        environment['NMAPUI_LOG_DIR'] = str(legacy / 'logs')
        service.write_plist(path, payload)
        executor = Mock(return_value=subprocess.CompletedProcess([], 0, '', ''))
        service.manage_services('status', user_root=self.root, executor=executor)
        self.assertEqual(len(executor.call_args_list), 2)

        environment['NMAPUI_DATA_DIR'] = str(self.root / 'other/data')
        environment['NMAPUI_LOG_DIR'] = str(self.root / 'other/logs')
        service.write_plist(path, payload)
        executor = Mock()
        with self.assertRaisesRegex(ValueError, 'unrecognized NmapUI configuration'):
            service.manage_services('status', user_root=self.root, executor=executor)
        executor.assert_not_called()

    def test_restart_requests_only_fixed_owned_labels_and_does_not_claim_readiness(self):
        executor = Mock(return_value=subprocess.CompletedProcess([], 0, '', ''))
        result = service.manage_services('restart', user_root=self.root, executor=executor)
        commands = [call.args[0] for call in executor.call_args_list]
        self.assertEqual(commands[1], ['/bin/launchctl', 'kickstart', '-k', f'gui/{os.getuid()}/{service.NMAPUI_LABEL}'])
        self.assertEqual(commands[3][-1], f'gui/{os.getuid()}/{service.BRIDGE_LABEL}')
        self.assertEqual({item['state'] for item in result['services']}, {'restart_requested'})

    def test_uninstall_removes_only_known_plists_and_keeps_all_configuration_evidence(self):
        executor = Mock(return_value=subprocess.CompletedProcess([], 0, '', ''))
        result = service.manage_services('uninstall', user_root=self.root, executor=executor)
        self.assertTrue(result['data_preserved'])
        self.assertFalse(list(self.plists.glob('*.plist')))
        self.assertEqual([path.read_bytes() for path in self.retained], self.original_retained)
        self.assertEqual([call.args[0][1] for call in executor.call_args_list], ['print', 'bootout', 'print', 'bootout'])

    def test_unknown_or_readable_service_descriptor_is_refused_before_commands(self):
        path = self.plists / (service.BRIDGE_LABEL+'.plist')
        payload = plistlib.loads(path.read_bytes())
        payload['ProgramArguments'] = ['/unrelated/app']
        service.write_plist(path, payload)
        executor = Mock()
        with self.assertRaisesRegex(ValueError, 'unrecognized bridge'):
            service.manage_services('uninstall', user_root=self.root, executor=executor)
        executor.assert_not_called()
        path.chmod(0o644)
        with self.assertRaisesRegex(ValueError, 'private'):
            service.manage_services('uninstall', user_root=self.root, executor=executor)

    def test_failed_bootout_keeps_descriptor_and_data(self):
        executor = Mock(side_effect=[subprocess.CompletedProcess([], 0, '', ''), subprocess.CompletedProcess([], 1, '', 'failure')])
        with self.assertRaisesRegex(RuntimeError, 'retained'):
            service.manage_services('uninstall', user_root=self.root, executor=executor)
        self.assertEqual(len(list(self.plists.glob('*.plist'))), 2)
        self.assertTrue(all(path.exists() for path in self.retained))

    def test_unknown_print_failure_is_not_treated_as_unloaded(self):
        executor = Mock(return_value=subprocess.CompletedProcess([], 1, '', 'permission denied'))
        with self.assertRaisesRegex(RuntimeError, 'determine'):
            service.manage_services('uninstall', user_root=self.root, executor=executor)
        self.assertEqual(executor.call_count, 1)
        self.assertEqual(len(list(self.plists.glob('*.plist'))), 2)

    def test_unloaded_restart_bootstraps_only_known_descriptors(self):
        executor = Mock(side_effect=[subprocess.CompletedProcess([], 1, '', 'Could not find service'), subprocess.CompletedProcess([], 0, '', '')] * 2)
        service.manage_services('restart', user_root=self.root, executor=executor)
        actions = [call.args[0] for call in executor.call_args_list]
        self.assertEqual([action[1] for action in actions], ['print', 'bootstrap', 'print', 'bootstrap'])
        self.assertEqual(actions[1][-1], str(self.plists / (service.NMAPUI_LABEL+'.plist')))

    def test_descriptor_changed_during_probe_is_retained(self):
        path = self.plists / (service.BRIDGE_LABEL+'.plist')
        def probe(*args, **kwargs):
            path.chmod(0o644)
            return subprocess.CompletedProcess([], 0, '', '')
        executor = Mock(side_effect=probe)
        with self.assertRaisesRegex(ValueError, 'changed'):
            service.manage_services('uninstall', user_root=self.root, executor=executor)
        self.assertEqual(executor.call_count, 1)
        self.assertTrue(path.exists())

    def test_symlink_descriptor_refused_before_commands(self):
        path = self.plists / (service.BRIDGE_LABEL+'.plist')
        outside = self.root / 'untouched.plist'
        path.rename(outside)
        path.symlink_to(outside)
        executor = Mock()
        with self.assertRaisesRegex(ValueError, 'symbolic link'):
            service.manage_services('uninstall', user_root=self.root, executor=executor)
        executor.assert_not_called()
        self.assertTrue(outside.exists())

    def test_exclusive_plist_write_keeps_existing_file(self):
        path = self.plists / (service.BRIDGE_LABEL+'.plist')
        original = path.read_bytes()
        with self.assertRaises(FileExistsError):
            service.write_plist(path, {'Label': service.BRIDGE_LABEL}, exclusive=True)
        self.assertEqual(path.read_bytes(), original)

    def test_uninstall_then_restore_preserves_enrollment_and_evidence(self):
        original = {path.name: path.read_bytes() for path in self.plists.glob('*.plist')}
        service.manage_services('uninstall', user_root=self.root, executor=Mock(return_value=subprocess.CompletedProcess([], 0, '', '')))
        executor = Mock(side_effect=[subprocess.CompletedProcess([], 1, '', 'Could not find service'), subprocess.CompletedProcess([], 0, '', '')] * 2)
        result = service.manage_services('restore', user_root=self.root, executor=executor)
        self.assertEqual({path.name: path.read_bytes() for path in self.plists.glob('*.plist')}, original)
        self.assertEqual([path.read_bytes() for path in self.retained], self.original_retained)
        self.assertEqual([call.args[0][1] for call in executor.call_args_list], ['print', 'bootstrap', 'print', 'bootstrap'])
        self.assertTrue(result['data_preserved'])
        self.assertNotIn('synthetic-not-a-real-token', json.dumps(result))
        service.manage_services('uninstall', user_root=self.root, executor=Mock(return_value=subprocess.CompletedProcess([], 0, '', '')))

    def test_restore_refuses_changed_enrollment_or_unknown_existing_descriptor(self):
        service.manage_services('uninstall', user_root=self.root, executor=Mock(return_value=subprocess.CompletedProcess([], 0, '', '')))
        self.retained[0].write_bytes(self.original_retained[0] + b' ')
        executor = Mock()
        with self.assertRaisesRegex(ValueError, 'identity changed'):
            service.manage_services('restore', user_root=self.root, executor=executor)
        executor.assert_not_called()
        self.retained[0].write_bytes(self.original_retained[0])
        service.write_plist(self.plists / (service.BRIDGE_LABEL+'.plist'), {'Label': service.BRIDGE_LABEL})
        with self.assertRaisesRegex(ValueError, 'existing service'):
            service.manage_services('restore', user_root=self.root, executor=executor)
        executor.assert_not_called()

    def test_restore_refuses_tampered_backup_and_missing_executable(self):
        service.manage_services('uninstall', user_root=self.root, executor=Mock(return_value=subprocess.CompletedProcess([], 0, '', '')))
        directory = service._resume_directory(self.root)
        backup = directory / (service.NMAPUI_LABEL+'.plist')
        original = backup.read_bytes()
        backup.write_bytes(original + b'\n')
        executor = Mock()
        with self.assertRaisesRegex(ValueError, 'changed'):
            service.manage_services('restore', user_root=self.root, executor=executor)
        backup.write_bytes(original)
        (self.bridge / '.venv/bin/daedalus-agent').unlink()
        with self.assertRaisesRegex(ValueError, 'unavailable'):
            service.manage_services('restore', user_root=self.root, executor=executor)
        executor.assert_not_called()
        self.assertFalse(list(self.plists.glob('*.plist')))

    def test_restore_refuses_foreign_uid_and_public_resume_directory(self):
        service.manage_services('uninstall', user_root=self.root, executor=Mock(return_value=subprocess.CompletedProcess([], 0, '', '')))
        directory = service._resume_directory(self.root)
        receipt_path = directory / 'receipt.json'
        receipt = json.loads(receipt_path.read_bytes())
        receipt['uid'] = os.getuid() + 1
        receipt_path.write_text(json.dumps(receipt))
        executor = Mock()
        with self.assertRaisesRegex(ValueError, 'identity changed'):
            service.manage_services('restore', user_root=self.root, executor=executor)
        directory.chmod(0o755)
        with self.assertRaisesRegex(ValueError, 'directory must be private'):
            service.manage_services('restore', user_root=self.root, executor=executor)
        executor.assert_not_called()

    def test_restore_preserves_binary_descriptor_bytes(self):
        path = self.plists / (service.BRIDGE_LABEL+'.plist')
        binary = plistlib.dumps(plistlib.loads(path.read_bytes()), fmt=plistlib.FMT_BINARY)
        path.write_bytes(binary)
        service.manage_services('uninstall', user_root=self.root, executor=Mock(return_value=subprocess.CompletedProcess([], 0, '', '')))
        service.manage_services('restore', user_root=self.root, executor=Mock(return_value=subprocess.CompletedProcess([], 0, '', '')))
        self.assertEqual(path.read_bytes(), binary)

    def test_strict_auth_flags_are_preserved_and_malformed_values_rejected(self):
        payload = plistlib.loads((self.plists / (service.NMAPUI_LABEL+'.plist')).read_bytes())
        self.assertEqual(payload['EnvironmentVariables']['NMAPUI_TRUST_LOCAL_UI'], 'false')
        with patch.dict(os.environ, {'NMAPUI_TRUST_LOCAL_UI': 'malformed'}):
            with self.assertRaisesRegex(ValueError, 'must be true or false'): service._auth_environment()


class LinuxSystemdUnitFixtures(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='daedalus-systemd-fixture-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.unit_dir = self.root / 'config with spaces/systemd/user'
        self.config_dir = self.root / 'config with spaces/daedalus'
        self.nmapui_release = self.root / 'data with spaces/daedalus/nmapui/release'
        self.bridge_root = self.root / 'data with spaces/daedalus/scanner-bridge'
        for path in [self.nmapui_release / '.venv/bin/python', self.nmapui_release / 'daedalus-nmapui-source/app.py', self.nmapui_release / 'playwright-browsers', self.bridge_root / '.venv/bin/daedalus-agent', self.config_dir / 'managed-agent.json']:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('fixture path')
        self.args = Namespace(
            unit_dir=str(self.unit_dir), config_dir=str(self.config_dir),
            nmapui_python=str(self.nmapui_release / '.venv/bin/python'),
            nmapui_app_dir=str(self.nmapui_release / 'daedalus-nmapui-source'),
            nmapui_data_dir=str(self.root / 'data with spaces/daedalus/nmapui-data'),
            browser_dir=str(self.nmapui_release / 'playwright-browsers'),
            agent_executable=str(self.bridge_root / '.venv/bin/daedalus-agent'),
            bridge_working_dir=str(self.bridge_root),
            agent_config=str(self.config_dir / 'managed-agent.json'), port=9000,
        )

    def lifecycle_executor(self):
        states = {name: {'LoadState': 'loaded', 'ActiveState': 'active', 'UnitFileState': 'enabled', 'MainPID': '123', 'FragmentPath': str(self.unit_dir / name), 'DropInPaths': ''}
                  for name in (systemd_service.NMAPUI_UNIT, systemd_service.BRIDGE_UNIT)}
        calls = []

        def execute(argv, **kwargs):
            calls.append(argv)
            self.assertEqual(argv[:2], [systemd_service.SYSTEMCTL, '--user'])
            self.assertEqual(kwargs['timeout'], 30)
            action = argv[2]
            if action == 'daemon-reload':
                for name, state in states.items():
                    state['LoadState'] = 'loaded' if (self.unit_dir / name).exists() else 'not-found'
                    if state['LoadState'] == 'not-found':
                        state['UnitFileState'] = ''
                        state['FragmentPath'] = ''
            elif action == 'disable':
                states[argv[-1]].update(ActiveState='inactive', UnitFileState='disabled', MainPID='0')
            elif action == 'enable':
                states[argv[-1]].update(LoadState='loaded', ActiveState='active', UnitFileState='enabled', MainPID='123', FragmentPath=str(self.unit_dir / argv[-1]))
            output = '\n'.join(f'{key}={value}' for key, value in states[argv[-1]].items()) if action == 'show' else ''
            return subprocess.CompletedProcess(argv, 0, output, '')

        return execute, calls, states

    def install_lifecycle_fixture(self):
        with patch.dict(os.environ, {'NMAPUI_USERNAME': 'synthetic-user', 'NMAPUI_PASSWORD': 'synthetic-secret'}):
            systemd_service.install(self.args)
        enrollment = self.config_dir / 'managed-agent.json'
        enrollment.write_bytes(b'private enrollment fixture')
        enrollment.chmod(0o600)
        spool = self.root / 'data with spaces/daedalus/scanner-bridge/spool/event.json'
        spool.parent.mkdir(parents=True)
        spool.write_bytes(b'saved scanner evidence')
        unrelated = self.unit_dir / 'unrelated.service'
        unrelated.write_bytes(b'unrelated unit')
        return {path: path.read_bytes() for path in (enrollment, spool, unrelated, self.config_dir / systemd_service.ENV_FILE, self.config_dir / systemd_service.STATE_FILE)}

    def test_restart_preserves_files_and_orders_only_fixed_units(self):
        original = self.install_lifecycle_fixture()
        execute, calls, states = self.lifecycle_executor()
        result = systemd_service.manage('restart', self.unit_dir, self.config_dir, executor=execute)
        self.assertTrue(result['data_preserved'])
        self.assertEqual([argv[-1] for argv in calls if argv[2] == 'restart'], [systemd_service.NMAPUI_UNIT, systemd_service.BRIDGE_UNIT])
        for path, contents in original.items():
            self.assertEqual(path.read_bytes(), contents)
        self.assertFalse((self.config_dir / systemd_service.RESUME_FILE).exists())

    def test_restart_refuses_pending_upgrade_without_manager_calls(self):
        self.install_lifecycle_fixture()
        (self.config_dir / systemd_service.UPGRADE_FILE).write_text('{}')
        execute, calls, _ = self.lifecycle_executor()
        with self.assertRaisesRegex(systemd_service.ServiceError, 'pending upgrade'):
            systemd_service.manage('restart', self.unit_dir, self.config_dir, executor=execute)
        self.assertEqual(calls, [])

    def test_restart_refuses_concurrent_lifecycle_without_manager_calls(self):
        self.install_lifecycle_fixture()
        lock = os.open(self.config_dir / systemd_service.LOCK_FILE, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            execute, calls, _ = self.lifecycle_executor()
            with self.assertRaisesRegex(systemd_service.ServiceError, 'Another scanner lifecycle'):
                systemd_service.manage('restart', self.unit_dir, self.config_dir, executor=execute)
            self.assertEqual(calls, [])
        finally:
            os.close(lock)

    def test_restart_refuses_loaded_override_before_mutation(self):
        self.install_lifecycle_fixture()
        execute, calls, states = self.lifecycle_executor()
        states[systemd_service.BRIDGE_UNIT]['DropInPaths'] = '/fixture/foreign.conf'
        with self.assertRaisesRegex(systemd_service.ServiceError, 'unexpected unit or override'):
            systemd_service.manage('restart', self.unit_dir, self.config_dir, executor=execute)
        self.assertFalse(any(argv[2] == 'restart' for argv in calls))

    def test_restart_refuses_unconfirmed_start_and_hides_manager_output(self):
        self.install_lifecycle_fixture()
        execute, calls, states = self.lifecycle_executor()
        states[systemd_service.NMAPUI_UNIT].update(ActiveState='failed', MainPID='0')
        with self.assertRaisesRegex(systemd_service.ServiceError, 'startup is unconfirmed'):
            systemd_service.manage('restart', self.unit_dir, self.config_dir, executor=execute)
        self.assertEqual([argv[-1] for argv in calls if argv[2] == 'restart'], [systemd_service.NMAPUI_UNIT])

    def test_uninstall_restore_preserves_enrollment_evidence_and_exact_private_units(self):
        retained = self.install_lifecycle_fixture()
        units = {name: (self.unit_dir / name).read_bytes() for name in (systemd_service.NMAPUI_UNIT, systemd_service.BRIDGE_UNIT)}
        execute, calls, states = self.lifecycle_executor()
        removed = systemd_service.manage('uninstall', self.unit_dir, self.config_dir, executor=execute)
        self.assertTrue(removed['data_preserved'])
        self.assertFalse(any((self.unit_dir / name).exists() for name in units))
        self.assertEqual([argv[-1] for argv in calls if argv[2] == 'disable'], [systemd_service.BRIDGE_UNIT, systemd_service.NMAPUI_UNIT])
        backup = self.config_dir / systemd_service.RESUME_FILE
        self.assertEqual(backup.stat().st_mode & 0o777, 0o600)
        self.assertNotIn('synthetic-secret', backup.read_text())
        self.assertNotIn('private enrollment', backup.read_text())
        restored = systemd_service.manage('restore', self.unit_dir, self.config_dir, executor=execute)
        self.assertEqual([argv[-1] for argv in calls if argv[2] == 'enable'], [systemd_service.NMAPUI_UNIT, systemd_service.BRIDGE_UNIT])
        self.assertTrue(all(row['active_state'] == 'active' for row in restored['services']))
        for name, contents in units.items():
            path = self.unit_dir / name
            self.assertEqual(path.read_bytes(), contents)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        for path, contents in retained.items():
            self.assertEqual(path.read_bytes(), contents)
        self.assertTrue(systemd_service.verify(self.unit_dir, self.config_dir)['verified'])

    def test_failed_disable_retains_descriptors_and_retry_completes(self):
        retained = self.install_lifecycle_fixture()
        execute, calls, states = self.lifecycle_executor()

        def fail_second_disable(argv, **kwargs):
            if argv[2] == 'disable' and argv[-1] == systemd_service.NMAPUI_UNIT:
                return subprocess.CompletedProcess(argv, 1, '', 'synthetic-secret')
            return execute(argv, **kwargs)

        with self.assertRaisesRegex(ValueError, 'action failed') as raised:
            systemd_service.manage('uninstall', self.unit_dir, self.config_dir, executor=fail_second_disable)
        self.assertNotIn('synthetic-secret', str(raised.exception))
        self.assertTrue(all((self.unit_dir / name).exists() for name in states))
        self.assertTrue((self.config_dir / systemd_service.RESUME_FILE).exists())
        systemd_service.manage('uninstall', self.unit_dir, self.config_dir, executor=execute)
        for path, contents in retained.items():
            self.assertEqual(path.read_bytes(), contents)

    def test_overlapping_lifecycle_action_is_refused_before_manager_operations(self):
        self.install_lifecycle_fixture()
        execute, calls, states = self.lifecycle_executor()
        overlaps = []

        def overlapping(argv, **kwargs):
            if argv[2] == 'disable':
                inner = Mock()
                with self.assertRaisesRegex(ValueError, 'Another scanner lifecycle action'):
                    systemd_service.manage('restore', self.unit_dir, self.config_dir, executor=inner)
                inner.assert_not_called()
                overlaps.append(argv[-1])
            return execute(argv, **kwargs)

        systemd_service.manage('uninstall', self.unit_dir, self.config_dir, executor=overlapping)
        self.assertEqual(len(overlaps), 2)
        systemd_service.manage('restore', self.unit_dir, self.config_dir, executor=execute)

    def test_unconfirmed_stop_or_disable_does_not_remove_units(self):
        self.install_lifecycle_fixture()
        for field, value in [('ActiveState', 'deactivating'), ('MainPID', '123'), ('UnitFileState', 'enabled')]:
            with self.subTest(field=field):
                execute, calls, states = self.lifecycle_executor()

                def unconfirmed(argv, **kwargs):
                    result = execute(argv, **kwargs)
                    if argv[2] == 'disable':
                        states[argv[-1]][field] = value
                    return result

                with self.assertRaisesRegex(ValueError, 'stop/disable is unconfirmed'):
                    systemd_service.manage('uninstall', self.unit_dir, self.config_dir, executor=unconfirmed)
                self.assertTrue(all((self.unit_dir / name).exists() for name in states))

    def test_interrupted_descriptor_removal_can_resume_without_new_enrollment(self):
        retained = self.install_lifecycle_fixture()
        execute, calls, states = self.lifecycle_executor()
        original_unlink = Path.unlink
        nmapui = self.unit_dir / systemd_service.NMAPUI_UNIT

        def interrupt(path, *args, **kwargs):
            if path == nmapui:
                raise OSError('fixture disk error')
            return original_unlink(path, *args, **kwargs)

        with patch.object(Path, 'unlink', interrupt):
            with self.assertRaisesRegex(OSError, 'fixture disk error'):
                systemd_service.manage('uninstall', self.unit_dir, self.config_dir, executor=execute)
        self.assertFalse((self.unit_dir / systemd_service.BRIDGE_UNIT).exists())
        self.assertTrue(nmapui.exists())
        systemd_service.manage('uninstall', self.unit_dir, self.config_dir, executor=execute)
        systemd_service.manage('restore', self.unit_dir, self.config_dir, executor=execute)
        for path, contents in retained.items():
            self.assertEqual(path.read_bytes(), contents)

    def test_tampering_during_manager_action_prevents_descriptor_removal(self):
        self.install_lifecycle_fixture()
        execute, calls, states = self.lifecycle_executor()
        unit = self.unit_dir / systemd_service.NMAPUI_UNIT

        def mutate(argv, **kwargs):
            result = execute(argv, **kwargs)
            if argv[2] == 'disable':
                unit.write_text(unit.read_text() + '# changed after preflight\n')
            return result

        with self.assertRaisesRegex(ValueError, 'changed during this action'):
            systemd_service.manage('uninstall', self.unit_dir, self.config_dir, executor=mutate)
        self.assertTrue(all((self.unit_dir / name).exists() for name in states))

    def test_uninstall_refuses_loaded_replacement_unit_or_dropins(self):
        self.install_lifecycle_fixture()
        for field, value in [('FragmentPath', '/run/user/1000/systemd/transient/foreign.service'), ('DropInPaths', '/tmp/unexpected.conf')]:
            with self.subTest(field=field):
                execute, calls, states = self.lifecycle_executor()
                states[systemd_service.BRIDGE_UNIT][field] = value
                with self.assertRaisesRegex(ValueError, 'unexpected unit or override'):
                    systemd_service.manage('uninstall', self.unit_dir, self.config_dir, executor=execute)
                self.assertFalse(any(argv[2] == 'disable' for argv in calls))
                self.assertTrue(all((self.unit_dir / name).exists() for name in states))

    def test_restore_refuses_replacement_symlinks_environment_and_recovery_corruption(self):
        self.install_lifecycle_fixture()
        execute, calls, states = self.lifecycle_executor()
        systemd_service.manage('uninstall', self.unit_dir, self.config_dir, executor=execute)
        backup = self.config_dir / systemd_service.RESUME_FILE
        original = backup.read_bytes()
        env = self.config_dir / systemd_service.ENV_FILE
        environment = env.read_bytes()
        unit = self.unit_dir / systemd_service.BRIDGE_UNIT
        for mutation in ['symlink', 'replacement', 'environment', 'backup', 'permissions', 'owner']:
            with self.subTest(mutation=mutation):
                backup.write_bytes(original); backup.chmod(0o600)
                env.write_bytes(environment)
                if unit.exists() or unit.is_symlink():
                    unit.unlink()
                calls.clear()
                if mutation == 'symlink':
                    unit.symlink_to(self.root / 'unrelated')
                elif mutation == 'replacement':
                    unit.write_text('unrelated replacement'); unit.chmod(0o600)
                elif mutation == 'environment':
                    env.write_bytes(b'changed secret')
                elif mutation == 'backup':
                    body = json.loads(original); body['units'][systemd_service.BRIDGE_UNIT] += '# changed\n'
                    backup.write_text(json.dumps(body))
                elif mutation == 'permissions':
                    backup.chmod(0o644)
                with patch.object(systemd_service.os, 'getuid', return_value=os.getuid() + 1) if mutation == 'owner' else patch.dict(os.environ, {}):
                    with self.assertRaises(ValueError):
                        systemd_service.manage('restore', self.unit_dir, self.config_dir, executor=execute)
                self.assertEqual(calls, [])

    def test_failed_restore_keeps_recovery_and_can_retry(self):
        retained = self.install_lifecycle_fixture()
        execute, calls, states = self.lifecycle_executor()
        systemd_service.manage('uninstall', self.unit_dir, self.config_dir, executor=execute)

        def fail_bridge(argv, **kwargs):
            if argv[2] == 'enable' and argv[-1] == systemd_service.BRIDGE_UNIT:
                raise subprocess.TimeoutExpired(argv, 30)
            return execute(argv, **kwargs)

        with self.assertRaisesRegex(ValueError, 'timed out'):
            systemd_service.manage('restore', self.unit_dir, self.config_dir, executor=fail_bridge)
        self.assertTrue(all((self.unit_dir / name).exists() for name in states))
        self.assertTrue((self.config_dir / systemd_service.RESUME_FILE).exists())
        systemd_service.manage('restore', self.unit_dir, self.config_dir, executor=execute)
        for path, contents in retained.items():
            self.assertEqual(path.read_bytes(), contents)

    def test_invalid_ownership_json_is_a_controlled_refusal(self):
        self.install_lifecycle_fixture()
        state_file = self.config_dir / systemd_service.STATE_FILE
        state = state_file.read_bytes()
        for body in [[], {'format': 1, 'unit_dir': str(self.unit_dir), 'files': []}, {'format': 1, 'unit_dir': str(self.unit_dir), 'files': {name: 9 for name in (systemd_service.NMAPUI_UNIT, systemd_service.BRIDGE_UNIT, systemd_service.ENV_FILE)}}]:
            with self.subTest(body=body):
                state_file.write_text(json.dumps(body))
                with self.assertRaises(ValueError):
                    systemd_service.verify(self.unit_dir, self.config_dir)
        state_file.write_bytes(state)

    def test_units_are_fixed_private_and_keep_credentials_out_of_unit_text(self):
        secret = 'pass\\word"$value'
        with patch.dict(os.environ, {'NMAPUI_USERNAME': 'scanner-user', 'NMAPUI_PASSWORD': secret}):
            result = systemd_service.install(self.args)
        self.assertTrue(result['installed'])
        checked = systemd_service.verify(self.unit_dir, self.config_dir)
        self.assertTrue(checked['verified'])
        nmapui = (self.unit_dir / systemd_service.NMAPUI_UNIT).read_text()
        bridge = (self.unit_dir / systemd_service.BRIDGE_UNIT).read_text()
        self.assertIn('127.0.0.1', nmapui)
        self.assertIn('NMAPUI_ENABLE_VULNERS="false"', nmapui)
        self.assertIn('NMAPUI_TRUST_LOCAL_UI="false"', nmapui)
        self.assertIn('NMAPUI_COOKIE_SECURE="false"', nmapui)
        self.assertIn('Restart=on-failure', nmapui)
        self.assertIn('Restart=always', bridge)
        self.assertIn('--config "' + str(self.config_dir / 'managed-agent.json') + '"', bridge)
        self.assertNotIn(secret, nmapui + bridge)
        encoded_password = systemd_service._env_file_quote(secret, 'NMAPUI_PASSWORD')
        self.assertIn('NMAPUI_PASSWORD=' + encoded_password, (self.config_dir / systemd_service.ENV_FILE).read_text())
        for path in [self.unit_dir, self.config_dir]:
            self.assertEqual(path.stat().st_mode & 0o777, 0o700)
        for path in [self.unit_dir / systemd_service.NMAPUI_UNIT, self.unit_dir / systemd_service.BRIDGE_UNIT, self.config_dir / systemd_service.ENV_FILE, self.config_dir / systemd_service.STATE_FILE]:
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_tampered_or_symlink_unit_is_refused(self):
        with patch.dict(os.environ, {'NMAPUI_USERNAME': '', 'NMAPUI_PASSWORD': ''}):
            systemd_service.install(self.args)
        path = self.unit_dir / systemd_service.NMAPUI_UNIT
        path.write_text(path.read_text() + '# changed\n')
        with self.assertRaisesRegex(ValueError, 'changed after installation'):
            systemd_service.verify(self.unit_dir, self.config_dir)
        path.unlink()
        path.symlink_to(self.root / 'outside')
        with self.assertRaisesRegex(ValueError, 'unsafe'):
            systemd_service.verify(self.unit_dir, self.config_dir)

    def test_install_rejects_newline_credentials_and_does_not_leave_files(self):
        with patch.dict(os.environ, {'NMAPUI_USERNAME': 'user', 'NMAPUI_PASSWORD': 'bad\nvalue'}):
            with self.assertRaisesRegex(ValueError, 'control characters'):
                systemd_service.install(self.args)
        self.assertFalse(self.unit_dir.exists())

    def test_install_does_not_overwrite_any_existing_unit(self):
        self.unit_dir.mkdir(parents=True)
        existing = self.unit_dir / systemd_service.NMAPUI_UNIT
        existing.write_text('user unit')
        with patch.dict(os.environ, {'NMAPUI_USERNAME': '', 'NMAPUI_PASSWORD': ''}):
            with self.assertRaises(FileExistsError):
                systemd_service.install(self.args)
        self.assertEqual(existing.read_text(), 'user unit')

    def test_linux_manager_operates_only_verified_fixed_unit_names(self):
        with patch.dict(os.environ, {'NMAPUI_USERNAME': '', 'NMAPUI_PASSWORD': ''}):
            systemd_service.install(self.args)
        tools = self.root / 'tools'
        tools.mkdir()
        log = self.root / 'systemctl.log'
        uname = tools / 'uname'
        uname.write_text('#!/bin/sh\nprintf "%s\\n" Linux\n')
        uname.chmod(0o700)
        systemctl = tools / 'systemctl'
        systemctl.write_text('''#!/bin/sh
printf '%s\\n' "$*" >> "$SYSTEMCTL_LOG"
case "$*" in *"is-active"*|*"is-enabled"*) exit 0;; esac
exit 0
''')
        systemctl.chmod(0o700)
        environment = {
            'PATH': str(tools) + os.pathsep + os.environ['PATH'],
            'HOME': str(self.root),
            'XDG_CONFIG_HOME': str(self.root / 'config with spaces'),
            'SYSTEMCTL_LOG': str(log),
        }
        script = BUNDLE / 'manage-service-linux.sh'
        status = subprocess.run(['/bin/sh', str(script), 'status'], env=environment, capture_output=True, text=True, timeout=5)
        self.assertEqual(status.returncode, 0, status.stderr)
        commands = log.read_text().splitlines()
        self.assertEqual(commands[0], '--user show-environment')
        self.assertIn('--user is-active --quiet daedalus-nmapui.service', commands)
        self.assertIn('--user is-enabled --quiet daedalus-scanner-bridge.service', commands)
        self.assertIn('daedalus-nmapui.service: active, enabled', status.stdout)

        log.write_text('')
        unit = self.unit_dir / systemd_service.BRIDGE_UNIT
        unit.write_text(unit.read_text() + '# tampered\n')
        refused = subprocess.run(['/bin/sh', str(script), 'restart'], env=environment, capture_output=True, text=True, timeout=5)
        self.assertNotEqual(refused.returncode, 0)
        self.assertEqual(log.read_text().splitlines(), ['--user show-environment'])
