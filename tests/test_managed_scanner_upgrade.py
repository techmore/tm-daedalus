import hashlib
import io
import os
import plistlib
import tempfile
import unittest
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from daedalus.agent_bundle import macos_service, upgrade_service


def make_bundle(path: Path) -> None:
    inner = io.BytesIO()
    with zipfile.ZipFile(inner, "w") as archive:
        archive.writestr("daedalus-nmapui-source/app.py", "app = True")
        archive.writestr("daedalus-nmapui-source/requirements.txt", "flask\n")
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("daedalus-scanner-kit/nmapui-source.zip", inner.getvalue())
        archive.writestr("daedalus-scanner-kit/pyproject.toml", "[project]\nname='daedalus-bridge'\n")
        archive.writestr("daedalus-scanner-kit/src/daedalus/__init__.py", "__version__='test'\n")
        archive.writestr("daedalus-scanner-kit/src/daedalus/agent.py", "pass\n")
        archive.writestr("daedalus-scanner-kit/src/daedalus/command_journal.py", "pass\n")
        archive.writestr("daedalus-scanner-kit/src/daedalus/scanner_activity.py", "pass\n")
        archive.writestr("daedalus-scanner-kit/src/daedalus/scanner_delivery.py", "pass\n")


class ManagedScannerUpgradeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.support = self.root / "Library/Application Support/Daedalus"
        self.launch_agents = self.root / "Library/LaunchAgents"
        self.nmap_release = self.support / "nmapui/releases" / ("a" * 64)
        self.bridge_install = self.support / "scanner-bridge"
        self.bridge_release = self.bridge_install / "releases" / ("b" * 64)
        self.data = self.support / "nmapui-data"
        for path in (self.nmap_release / ".venv/bin", self.nmap_release / "daedalus-nmapui-source",
                     self.bridge_install / ".venv/bin", self.data / "data", self.data / "logs",
                     self.support / "event-spool", self.support / "command-journal", self.launch_agents):
            path.mkdir(parents=True, exist_ok=True)
        (self.nmap_release / "daedalus-nmapui-source/app.py").write_text("old")
        (self.nmap_release / ".venv/bin/python").write_text("python")
        (self.nmap_release / ".venv/bin/python").chmod(0o700)
        (self.bridge_install / ".venv/bin/daedalus-agent").write_text("bridge")
        (self.bridge_install / ".venv/bin/daedalus-agent").chmod(0o700)
        config = self.support / "managed-agent.json"
        config.write_text('{"server":"https://portal.example","agent_id":7,"agent_token":"private-fixture-token","organization":"Fixture"}')
        config.chmod(0o600)
        self.state_files = {
            self.data / "data/settings.json": b'{"theme":"saved","scanner":true}',
            self.data / "data/scans.db": b"scanner-data-bytes",
            self.support / "event-spool/event.json": b"event-spool-bytes",
            self.support / "command-journal/journal.db": b"command-journal-bytes",
            self.support / "managed-agent.json": config.read_bytes(),
        }
        for path, contents in self.state_files.items():
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(contents)
        (self.data / "data").chmod(0o700)
        old_nmap = macos_service.build_nmapui_plist(
            python=str(self.nmap_release / ".venv/bin/python"), app_dir=str(self.nmap_release / "daedalus-nmapui-source"),
            data_dir=str(self.data), log_dir=str(self.data / "logs"), browser_dir=str(self.nmap_release / "browsers"), port=9137)
        old_nmap["EnvironmentVariables"].update({"CUSTOM_SETTING": "keep-me", "NMAPUI_USERNAME": "fixture-user", "NMAPUI_PASSWORD": "fixture-password"})
        old_bridge = macos_service.build_bridge_plist(
            agent_executable=str(self.bridge_install / ".venv/bin/daedalus-agent"),
            config_path=str(self.support / "managed-agent.json"), install_dir=str(self.bridge_install), log_dir=str(self.support / "logs"))
        old_bridge["EnvironmentVariables"]["BRIDGE_CUSTOM"] = "keep-bridge"
        self.old_bytes = {}
        for label, payload in ((macos_service.NMAPUI_LABEL, old_nmap), (macos_service.BRIDGE_LABEL, old_bridge)):
            path = self.launch_agents / f"{label}.plist"
            macos_service.write_plist(path, payload)
            self.old_bytes[label] = path.read_bytes()
        self.bundle = self.root / "kit.zip"
        make_bundle(self.bundle)
        self.executor_calls = []
        self.loaded = {macos_service.NMAPUI_LABEL, macos_service.BRIDGE_LABEL}
        self.idle_patch = patch.object(upgrade_service, "_require_scanner_idle")
        self.idle_probe = self.idle_patch.start()
        self.addCleanup(self.idle_patch.stop)
        self.claim_patch = patch.object(upgrade_service, "_acquire_scanner_maintenance", return_value="a" * 32)
        self.claim = self.claim_patch.start()
        self.addCleanup(self.claim_patch.stop)
        self.release_patch = patch.object(upgrade_service, "_release_scanner_maintenance")
        self.release = self.release_patch.start()
        self.addCleanup(self.release_patch.stop)

    def tearDown(self):
        self.temp.cleanup()

    def test_upgrade_defers_before_any_probe_or_staging_when_lifecycle_locked(self):
        with macos_service.lifecycle_lock(self.root):
            with self.assertRaisesRegex(RuntimeError, "lifecycle"):
                upgrade_service.upgrade_managed_scanner(self.bundle, self.root, self.executor, self.prepare, lambda _: True)
        self.assertEqual(self.executor_calls, [])
        self.claim.assert_not_called()

    def test_upgrade_holds_lifecycle_lock_through_readiness(self):
        def ready(payload):
            with self.assertRaisesRegex(RuntimeError, "lifecycle"):
                macos_service.manage_services("restart", user_root=self.root, executor=self.executor)
            return True
        upgrade_service.upgrade_managed_scanner(self.bundle, self.root, self.executor, self.prepare, ready)
        with macos_service.lifecycle_lock(self.root):
            pass  # Successful cutover releases the lock.

    def offline_executor(self, args, **kwargs):
        response = self.executor(args, **kwargs)
        if args[1] == "print" and response.returncode:
            response.stderr = "Could not find service"
        return response

    def test_offline_upgrade_requires_unloaded_services_and_preserves_data(self):
        self.loaded.clear()
        with patch.object(upgrade_service, "_require_scanner_offline") as offline:
            result = upgrade_service.upgrade_managed_scanner(self.bundle, self.root, self.offline_executor,
                                                            self.prepare, lambda _: True, offline=True)
        self.assertTrue(result["offline_upgrade"])
        self.assertEqual(offline.call_count, 2)
        self.claim.assert_not_called()
        self.idle_probe.assert_not_called()
        self.release.assert_not_called()
        self.assertFalse(any(c[1] == "bootout" for c in self.executor_calls))
        self.assertEqual(self.loaded, {macos_service.NMAPUI_LABEL, macos_service.BRIDGE_LABEL})
        for path, data in self.state_files.items():
            self.assertEqual(path.read_bytes(), data)

    def test_offline_upgrade_refuses_loaded_and_ambiguous_services(self):
        for executor in (self.executor, lambda *a, **k: SimpleNamespace(returncode=1, stdout="", stderr="Permission denied")):
            with self.subTest(executor=executor), self.assertRaisesRegex(ValueError, "unloaded"):
                upgrade_service.upgrade_managed_scanner(self.bundle, self.root, executor, self.prepare, lambda _: True, offline=True)
        self.assertFalse(any(c[1] in {"bootout", "bootstrap"} for c in self.executor_calls))

    def test_offline_upgrade_refuses_service_or_listener_reappearing_during_staging(self):
        for restart_service in (False, True):
            self.loaded.clear()
            self.executor_calls.clear()
            def prepare(files, root, digest):
                result = self.prepare(files, root, digest)
                if restart_service:
                    self.loaded.add(macos_service.NMAPUI_LABEL)
                return result
            guard = [None, None] if restart_service else [None, RuntimeError("listener appeared")]
            with patch.object(upgrade_service, "_require_scanner_offline", side_effect=guard):
                with self.assertRaises(RuntimeError):
                    upgrade_service.upgrade_managed_scanner(self.bundle, self.root, self.offline_executor, prepare, lambda _: True, offline=True)
            self.assertFalse(any(c[1] in {"bootout", "bootstrap"} for c in self.executor_calls))
            for label, contents in self.old_bytes.items():
                self.assertEqual((self.launch_agents / (label + ".plist")).read_bytes(), contents)

    def test_offline_candidate_failure_restores_original_services_and_descriptors(self):
        self.loaded.clear()
        readiness = iter([False, True])
        with patch.object(upgrade_service, "_require_scanner_offline"), self.assertRaisesRegex(RuntimeError, "ready"):
            upgrade_service.upgrade_managed_scanner(self.bundle, self.root, self.offline_executor, self.prepare,
                                                  lambda _: next(readiness), offline=True)
        for label, contents in self.old_bytes.items():
            self.assertEqual((self.launch_agents / (label + ".plist")).read_bytes(), contents)
        self.assertEqual(self.loaded, {macos_service.NMAPUI_LABEL, macos_service.BRIDGE_LABEL})

    def test_offline_probe_requires_connection_refusal(self):
        payload = {"EnvironmentVariables": {"NMAPUI_PORT": "9137"}}
        with patch.object(upgrade_service.socket, "create_connection", side_effect=ConnectionRefusedError()):
            upgrade_service._require_scanner_offline(payload)
        for failure in (TimeoutError(), OSError("fixture")):
            with patch.object(upgrade_service.socket, "create_connection", side_effect=failure), self.assertRaisesRegex(RuntimeError, "unknown"):
                upgrade_service._require_scanner_offline(payload)
        with patch.object(upgrade_service.socket, "create_connection"), self.assertRaisesRegex(RuntimeError, "still running"):
            upgrade_service._require_scanner_offline(payload)

    def test_maintenance_refusal_defers_without_service_changes(self):
        self.claim.side_effect = RuntimeError("Scanner maintenance could not be acquired")
        with self.assertRaisesRegex(RuntimeError, "maintenance"):
            upgrade_service.upgrade_managed_scanner(self.bundle, self.root, self.executor, self.prepare, lambda _: True)
        self.assertFalse(any(c[1] in {"bootout", "bootstrap"} for c in self.executor_calls))
        self.release.assert_not_called()
        for label, raw in self.old_bytes.items():
            self.assertEqual((self.launch_agents / (label + ".plist")).read_bytes(), raw)

    def test_admission_is_claimed_before_service_stop_and_released_after(self):
        events = []
        self.claim.side_effect = lambda _: events.append("claim") or "a" * 32
        self.release.side_effect = lambda _, token: events.append("release")
        def executor(args, **kwargs):
            if args[1] in {"bootout", "bootstrap"}:
                events.append(args[1])
            return self.executor(args, **kwargs)
        result = upgrade_service.upgrade_managed_scanner(self.bundle, self.root, executor, self.prepare, lambda _: True)
        self.assertTrue(result["upgraded"])
        self.assertEqual(events, ["claim", "bootout", "bootout", "bootstrap", "bootstrap", "release"])
        self.release.assert_called_once_with(unittest.mock.ANY, "a" * 32)

    def test_failed_candidate_rolls_back_and_releases_admission(self):
        with self.assertRaisesRegex(RuntimeError, "did not become ready"):
            upgrade_service.upgrade_managed_scanner(self.bundle, self.root, self.executor, self.prepare,
                                                    lambda p: p["WorkingDirectory"] == str(self.nmap_release / "daedalus-nmapui-source"))
        self.release.assert_called_once_with(unittest.mock.ANY, "a" * 32)
        for label, raw in self.old_bytes.items():
            self.assertEqual((self.launch_agents / (label + ".plist")).read_bytes(), raw)

    def test_busy_engine_defers_before_staging_or_service_changes(self):
        self.idle_probe.side_effect = RuntimeError("Scanner is busy")
        with patch.object(self, "prepare") as prepare:
            with self.assertRaisesRegex(RuntimeError, "busy"):
                upgrade_service.upgrade_managed_scanner(self.bundle, self.root, self.executor, prepare, lambda _: True)
            prepare.assert_not_called()
        self.assertEqual(self.loaded, {macos_service.NMAPUI_LABEL, macos_service.BRIDGE_LABEL})
        self.assertFalse(any(c[1] in {"bootout", "bootstrap"} for c in self.executor_calls))
        for label, raw in self.old_bytes.items():
            self.assertEqual((self.launch_agents / (label + ".plist")).read_bytes(), raw)

    def test_engine_becoming_busy_during_staging_defers_cutover(self):
        self.idle_probe.side_effect = [None, RuntimeError("Scanner is busy")]
        with self.assertRaisesRegex(RuntimeError, "busy"):
            upgrade_service.upgrade_managed_scanner(self.bundle, self.root, self.executor, self.prepare, lambda _: True)
        self.assertEqual(self.idle_probe.call_count, 2)
        self.assertFalse(any(c[1] in {"bootout", "bootstrap"} for c in self.executor_calls))
        for label, raw in self.old_bytes.items():
            self.assertEqual((self.launch_agents / (label + ".plist")).read_bytes(), raw)

    def test_kit_hash_and_members_use_same_snapshot_when_path_is_replaced(self):
        original = self.bundle.read_bytes()
        replacement = self.root / "replacement.zip"
        make_bundle(replacement)
        with zipfile.ZipFile(replacement, "a") as archive:
            archive.writestr("daedalus-scanner-kit/replaced.txt", "different kit")
        real_zip = zipfile.ZipFile
        opened = 0
        def replace_before_parse(source, *args, **kwargs):
            nonlocal opened
            opened += 1
            if opened == 1:
                os.replace(replacement, self.bundle)
            return real_zip(source, *args, **kwargs)
        with patch.object(upgrade_service.zipfile, "ZipFile", side_effect=replace_before_parse):
            files, digest = upgrade_service._read_kit(self.bundle)
        self.assertEqual(digest, hashlib.sha256(original).hexdigest())
        self.assertNotIn("replaced.txt", files)
        self.assertNotEqual(self.bundle.read_bytes(), original)

    def test_oversized_kit_is_refused_before_zip_parsing(self):
        with patch.object(upgrade_service, "MAX_KIT_BYTES", 8), patch.object(upgrade_service.zipfile, "ZipFile") as reader:
            with self.assertRaisesRegex(ValueError, "too large"):
                upgrade_service._read_kit(self.bundle)
            reader.assert_not_called()

    def test_non_regular_kit_is_refused_without_waiting_for_a_writer(self):
        fifo = self.root / "kit-fifo"
        os.mkfifo(fifo)
        with self.assertRaisesRegex(ValueError, "unsafe"):
            upgrade_service._read_kit(fifo)

    def test_growth_after_size_check_is_bounded_and_refused(self):
        info = self.bundle.stat()
        with patch.object(upgrade_service, "MAX_KIT_BYTES", 8), patch.object(upgrade_service.os, "fstat", return_value=SimpleNamespace(st_mode=info.st_mode, st_size=1)), patch.object(upgrade_service.zipfile, "ZipFile") as reader:
            with self.assertRaisesRegex(ValueError, "allowed size"):
                upgrade_service._read_kit(self.bundle)
            reader.assert_not_called()

    def test_bridge_launcher_is_rebased_before_versioned_stage_is_renamed(self):
        stage = self.root / "releases/.stage-fixture/.venv/bin"
        release = self.root / "releases" / ("c" * 64)
        stage.mkdir(parents=True)
        launcher = stage / "daedalus-agent"
        launcher.write_text(f'#!/bin/sh\nexec "{stage / "python"}" "$0" "$@"\n')
        launcher.chmod(0o700)
        upgrade_service._rebase_bridge_launcher(launcher, stage / "python", release / ".venv/bin/python")
        self.assertIn(str(release / ".venv/bin/python"), launcher.read_text())
        self.assertNotIn(".stage-fixture", launcher.read_text())
        self.assertEqual(launcher.stat().st_mode & 0o777, 0o700)

    def executor(self, args, **kwargs):
        self.executor_calls.append(args)
        if args[1] == "print":
            loaded = args[-1].split("/")[-1] in self.loaded
            return SimpleNamespace(returncode=0 if loaded else 113, stderr="", stdout="state = running\npid = 123\n" if loaded else "")
        if args[1] == "bootout":
            self.loaded.discard(Path(args[-1]).stem)
        elif args[1] == "bootstrap":
            self.loaded.add(Path(args[-1]).stem)
        return SimpleNamespace(returncode=0, stderr="", stdout="state = running\npid = 123\n")

    def prepare(self, files, root, kit_digest):
        nmap = self.support / "nmapui/releases" / hashlib.sha256(files["nmapui-source.zip"]).hexdigest()
        bridge_digest = hashlib.sha256(b"".join(files[k] for k in sorted(upgrade_service.REQUIRED_KIT_FILES - {"nmapui-source.zip"}))).hexdigest()
        bridge = self.support / "scanner-bridge/releases" / bridge_digest
        for release in (nmap, bridge):
            (release / ".venv/bin").mkdir(parents=True, exist_ok=True)
        (nmap / ".venv/bin/python").write_text("python-fixture")
        (nmap / ".venv/bin/python").chmod(0o700)
        (nmap / "daedalus-nmapui-source").mkdir(exist_ok=True)
        (nmap / "daedalus-nmapui-source/app.py").write_text("new")
        (bridge / ".venv/bin/daedalus-agent").write_text("bridge-fixture")
        (bridge / ".venv/bin/daedalus-agent").chmod(0o700)
        return nmap, bridge

    def assert_state_unchanged(self):
        for path, contents in self.state_files.items():
            self.assertEqual(path.read_bytes(), contents, path.name)

    def test_success_preserves_data_and_configuration_and_updates_only_browser_path(self):
        with patch.object(macos_service, "managed_artifacts", wraps=macos_service.managed_artifacts):
            result = upgrade_service.upgrade_managed_scanner(self.bundle, self.root, self.executor, self.prepare, lambda payload: True)
        self.assertTrue(result["upgraded"])
        self.assert_state_unchanged()
        nmap = plistlib.loads((self.launch_agents / f"{macos_service.NMAPUI_LABEL}.plist").read_bytes())
        bridge = plistlib.loads((self.launch_agents / f"{macos_service.BRIDGE_LABEL}.plist").read_bytes())
        old_nmap = plistlib.loads(self.old_bytes[macos_service.NMAPUI_LABEL])
        old_bridge = plistlib.loads(self.old_bytes[macos_service.BRIDGE_LABEL])
        env = nmap["EnvironmentVariables"]
        self.assertEqual(env["NMAPUI_MANAGEMENT_PORTAL_URL"], "https://portal.example")
        self.assertNotIn("private-fixture-token", str(env))
        for key, value in old_nmap["EnvironmentVariables"].items():
            if key != "PLAYWRIGHT_BROWSERS_PATH":
                self.assertEqual(env[key], value)
        self.assertNotEqual(env["PLAYWRIGHT_BROWSERS_PATH"], old_nmap["EnvironmentVariables"]["PLAYWRIGHT_BROWSERS_PATH"])
        self.assertEqual(bridge["EnvironmentVariables"], old_bridge["EnvironmentVariables"])
        self.assertEqual(nmap["EnvironmentVariables"]["NMAPUI_PORT"], "9137")
        self.assertEqual(nmap["EnvironmentVariables"]["NMAPUI_DATA_DIR"], old_nmap["EnvironmentVariables"]["NMAPUI_DATA_DIR"])
        for label, old in self.old_bytes.items():
            backup = Path(result["backups"][label])
            self.assertEqual(backup.read_bytes(), old)
            self.assertEqual(backup.stat().st_mode & 0o777, 0o600)
        self.assertIn("bootstrap", [call[1] for call in self.executor_calls])

    def test_readiness_failure_restores_exact_descriptors_and_preserves_scanner_state(self):
        readiness = iter((False, True))
        with self.assertRaisesRegex(RuntimeError, "did not become ready"):
            upgrade_service.upgrade_managed_scanner(self.bundle, self.root, self.executor, self.prepare, lambda payload: next(readiness))
        for label, contents in self.old_bytes.items():
            self.assertEqual((self.launch_agents / f"{label}.plist").read_bytes(), contents)
        self.assert_state_unchanged()
        self.assertEqual(self.loaded, {macos_service.NMAPUI_LABEL, macos_service.BRIDGE_LABEL})

    def test_cutover_failure_restores_original_services_and_identical_retry_is_noop(self):
        failed = False

        def fail_candidate_bootstrap(args, **kwargs):
            nonlocal failed
            if args[1] == "bootstrap" and not failed:
                failed = True
                self.executor_calls.append(args)
                return SimpleNamespace(returncode=1, stderr="fixture failure", stdout="")
            return self.executor(args, **kwargs)

        with self.assertRaisesRegex(RuntimeError, "service operation failed"):
            upgrade_service.upgrade_managed_scanner(self.bundle, self.root, fail_candidate_bootstrap, self.prepare, lambda payload: True)
        for label, contents in self.old_bytes.items():
            self.assertEqual((self.launch_agents / f"{label}.plist").read_bytes(), contents)
        self.assert_state_unchanged()
        self.assertEqual(self.loaded, {macos_service.NMAPUI_LABEL, macos_service.BRIDGE_LABEL})
        self.executor_calls.clear()
        result = upgrade_service.upgrade_managed_scanner(self.bundle, self.root, self.executor, self.prepare, lambda payload: True)
        self.assertTrue(result["upgraded"])
        self.executor_calls.clear()
        result = upgrade_service.upgrade_managed_scanner(self.bundle, self.root, self.executor, self.prepare, lambda payload: True)
        self.assertFalse(result["upgraded"])
        self.assertTrue(result["already_current"])
        self.assertFalse(any(call[1] in {"bootout", "bootstrap"} for call in self.executor_calls))

    def test_malformed_kit_and_missing_managed_service_do_not_bootout_services(self):
        bad = self.root / "bad.zip"
        with zipfile.ZipFile(bad, "w") as archive:
            archive.writestr("outside.txt", "bad")
        with self.assertRaises(ValueError):
            upgrade_service.upgrade_managed_scanner(bad, self.root, self.executor, self.prepare, lambda _: True)
        self.assertFalse(any(call[1] in {"bootout", "bootstrap"} for call in self.executor_calls))
        self.executor_calls.clear()
        (self.launch_agents / f"{macos_service.BRIDGE_LABEL}.plist").unlink()
        with self.assertRaises(ValueError):
            upgrade_service.upgrade_managed_scanner(self.bundle, self.root, self.executor, self.prepare, lambda _: True)
        self.assertEqual(self.executor_calls, [])

    def test_archive_path_aliases_are_rejected_before_extracting_or_cutover(self):
        bad = self.root / "aliased.zip"
        with zipfile.ZipFile(bad, "w") as archive:
            archive.writestr("daedalus-scanner-kit/nmapui-source.zip", b"stub")
            archive.writestr("daedalus-scanner-kit/./pyproject.toml", "alias")
            archive.writestr("daedalus-scanner-kit/src/daedalus/__init__.py", "")
            archive.writestr("daedalus-scanner-kit/src/daedalus/agent.py", "")
            archive.writestr("daedalus-scanner-kit/src/daedalus/command_journal.py", "")
        with self.assertRaisesRegex(ValueError, "unsafe|duplicate"):
            upgrade_service.upgrade_managed_scanner(bad, self.root, self.executor, self.prepare, lambda _: True)
        self.assertFalse(any(call[1] in {"bootout", "bootstrap"} for call in self.executor_calls))

    def test_incomplete_prepared_release_is_rejected_before_cutover(self):
        def incomplete(files, root, digest):
            nmap, bridge = self.prepare(files, root, digest)
            (bridge / ".venv/bin/daedalus-agent").unlink()
            return nmap, bridge
        with self.assertRaisesRegex(ValueError, "unavailable executable"):
            upgrade_service.upgrade_managed_scanner(self.bundle, self.root, self.executor, incomplete, lambda _: True)
        self.assertFalse(any(call[1] in {"bootout", "bootstrap"} for call in self.executor_calls))

    def test_public_upgrade_backup_directory_is_refused_before_cutover(self):
        files, kit_digest = upgrade_service._read_kit(self.bundle)
        old_set_digest = hashlib.sha256(b"".join(self.old_bytes[label] for label in sorted(self.old_bytes))).hexdigest()
        backup_root = self.support / "service-upgrades" / kit_digest / old_set_digest
        backup_root.mkdir(mode=0o700, parents=True)
        backup_root.chmod(0o755)
        with self.assertRaisesRegex(ValueError, "private"):
            upgrade_service.upgrade_managed_scanner(self.bundle, self.root, self.executor, self.prepare, lambda _: True)
        self.assertFalse(any(call[1] in {"bootout", "bootstrap"} for call in self.executor_calls))

    def test_preflight_refuses_a_loaded_but_not_running_service(self):
        def scheduled(args, **kwargs):
            if args[1] == "print" and args[-1].endswith(macos_service.NMAPUI_LABEL):
                self.executor_calls.append(args)
                return SimpleNamespace(returncode=0, stderr="", stdout="state = spawn scheduled\n")
            return self.executor(args, **kwargs)
        with self.assertRaisesRegex(ValueError, "must be loaded"):
            upgrade_service.upgrade_managed_scanner(self.bundle, self.root, scheduled, self.prepare, lambda _: True)
        self.assertFalse(any(call[1] in {"bootout", "bootstrap"} for call in self.executor_calls))


class ScannerIdleProbeTests(unittest.TestCase):
    def test_only_explicit_coherent_idle_status_is_accepted(self):
        import json
        payload = {"EnvironmentVariables": {"NMAPUI_PORT": "9001"}}
        for status, accepted in [
            ({"has_active_jobs": False, "active_jobs": [], "active_job_types": []}, True),
            ({"has_active_jobs": True, "active_jobs": [{}], "active_job_types": ["scan"]}, False),
            ({"has_active_jobs": False, "active_jobs": [{}], "active_job_types": []}, False),
            ({"has_active_jobs": False}, False), ([], False),
        ]:
            with self.subTest(status=status), patch.object(upgrade_service, "urlopen", return_value=io.BytesIO(json.dumps(status).encode())):
                if accepted:
                    upgrade_service._require_scanner_idle(payload)
                else:
                    with self.assertRaises(RuntimeError):
                        upgrade_service._require_scanner_idle(payload)

    def test_unavailable_malformed_and_oversized_status_defer(self):
        payload = {"EnvironmentVariables": {"NMAPUI_PORT": "9001"}}
        for body in [b"not JSON", b"x" * 65537]:
            with patch.object(upgrade_service, "urlopen", return_value=io.BytesIO(body)), self.assertRaises(RuntimeError):
                upgrade_service._require_scanner_idle(payload)
        with patch.object(upgrade_service, "urlopen", side_effect=TimeoutError()), self.assertRaises(RuntimeError):
            upgrade_service._require_scanner_idle(payload)

    def test_local_activity_probe_refuses_redirects(self):
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        import threading
        paths = []
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                paths.append(self.path)
                self.send_response(302)
                self.send_header('Location', '/redirected')
                self.end_headers()
            def log_message(self, *_):
                pass
        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': 0.01}, daemon=True)
        thread.start()
        try:
            payload = {'EnvironmentVariables': {'NMAPUI_PORT': str(server.server_port), 'NMAPUI_USERNAME': 'fixture-user', 'NMAPUI_PASSWORD': 'fixture-password'}}
            with self.assertRaises(RuntimeError):
                upgrade_service._require_scanner_idle(payload)
            self.assertEqual(paths, ['/api/runtime/status'])
        finally:
            server.shutdown();server.server_close();thread.join(timeout=1)


class ScannerMaintenanceTransportTests(unittest.TestCase):
    payload = {"EnvironmentVariables": {"NMAPUI_PORT": "9001", "NMAPUI_USERNAME": "fixture-user", "NMAPUI_PASSWORD": "fixture-password"}}

    def test_claim_and_owner_release_use_authenticated_local_methods(self):
        import json
        for token, method, reply in [(None, "POST", {"maintenance_active": True, "token": "a" * 32}),
                                     ("a" * 32, "DELETE", {"maintenance_active": False})]:
            with patch.object(upgrade_service, "urlopen", return_value=io.BytesIO(json.dumps(reply).encode())) as transport:
                if token is None:
                    self.assertEqual(upgrade_service._acquire_scanner_maintenance(self.payload), "a" * 32)
                else:
                    upgrade_service._release_scanner_maintenance(self.payload, token)
                req = transport.call_args.args[0]
                self.assertEqual(req.full_url, "http://127.0.0.1:9001/api/runtime/maintenance")
                self.assertEqual(req.get_method(), method)
                self.assertEqual(json.loads(req.data), {} if token is None else {"token": token})
                self.assertTrue(req.get_header("Authorization").startswith("Basic "))
                self.assertEqual(transport.call_args.kwargs["timeout"], 3)

    def test_invalid_claims_defer(self):
        import json
        replies = [[], {}, {"maintenance_active": False, "token": "a" * 32},
                   {"maintenance_active": True, "token": "g" * 32},
                   {"maintenance_active": True, "token": "a" * 31}]
        for raw in [json.dumps(p).encode() for p in replies] + [b"bad JSON", b"x" * 65537]:
            with self.subTest(raw_size=len(raw)), patch.object(upgrade_service, "urlopen", return_value=io.BytesIO(raw)):
                with self.assertRaisesRegex(RuntimeError, "upgrade deferred"):
                    upgrade_service._acquire_scanner_maintenance(self.payload)

    def test_unsupported_or_busy_engine_defers(self):
        from urllib.error import HTTPError
        for code in [404, 409, 401, 503]:
            with self.subTest(code=code), patch.object(upgrade_service, "urlopen", side_effect=HTTPError("http://127.0.0.1", code, "fixture", {}, None)):
                with self.assertRaisesRegex(RuntimeError, "upgrade deferred"):
                    upgrade_service._acquire_scanner_maintenance(self.payload)

    def test_maintenance_redirect_never_forwards_credentials_or_owner_token(self):
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        from threading import Thread
        paths = []
        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                paths.append(self.path)
                self.send_response(307)
                self.send_header("Location", "/credential-trap")
                self.end_headers()
            do_DELETE = do_POST
            def log_message(self, *args):
                pass
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = Thread(target=server.serve_forever, daemon=True); thread.start()
        payload = {"EnvironmentVariables": {**self.payload["EnvironmentVariables"], "NMAPUI_PORT": str(server.server_port)}}
        try:
            with self.assertRaises(RuntimeError):
                upgrade_service._acquire_scanner_maintenance(payload)
            with self.assertRaises(Exception):
                upgrade_service._release_scanner_maintenance(payload, "a" * 32)
            self.assertEqual(paths, ["/api/runtime/maintenance", "/api/runtime/maintenance"])
        finally:
            server.shutdown(); server.server_close(); thread.join(timeout=1)
