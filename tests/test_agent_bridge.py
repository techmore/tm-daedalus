import os
import json
import hashlib
import tempfile
import sys
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import httpx
from sqlalchemy import create_engine, inspect

from daedalus.agent import COMMAND_PROTOCOL_VERSION, FORWARDED_EVENTS, NmapUIBridge, load_config
from daedalus import server


class NmapUIBridgeTelemetryTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="daedalus-agent-fixture-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        location = patch("daedalus.agent.default_config_dir", return_value=self.root)
        location.start()
        self.addCleanup(location.stop)

    def make_bridge(self):
        bridge = NmapUIBridge(
            {
                "agent_id": 7,
                "server": "https://daedalus.example.org",
                "agent_token": "local-test-token",
            },
            "http://127.0.0.1:9000",
        )
        self.addCleanup(bridge.http.close)
        return bridge

    def test_linux_managed_service_config_requires_fixed_unit_and_absolute_paths(self):
        path = self.root / "agent.json"
        config = {
            "server": "https://daedalus.example.org",
            "agent_id": 7,
            "agent_token": "local-test-token",
            "nmapui_service_manager": "systemd-user",
            "nmapui_service_label": "daedalus-nmapui.service",
            "nmapui_systemd_unit_dir": str(self.root / "config/systemd/user"),
            "nmapui_systemd_config_dir": str(self.root / "config/daedalus"),
        }
        path.write_text(json.dumps(config))
        self.assertEqual(load_config(path)["nmapui_service_manager"], "systemd-user")

        config["nmapui_systemd_config_dir"] = "relative/config"
        path.write_text(json.dumps(config))
        with self.assertRaisesRegex(RuntimeError, "invalid managed Linux service settings"):
            load_config(path)

    @unittest.skipUnless(sys.platform == "linux" and Path("/usr/bin/apt").is_file(), "Requires a real Linux APT host")
    def test_actual_linux_cached_index_has_a_parseable_scoped_result(self):
        from datetime import datetime, UTC
        bridge = self.make_bridge()
        result = bridge._check_linux_updates(datetime.now(UTC).isoformat())
        self.assertIn(result["status"], {"updates_available", "no_updates"}, result)
        self.assertEqual(result["source"], "existing_apt_index")
        self.assertFalse(result["catalog_refreshed"])
        self.assertGreaterEqual(result["update_count"], 0)
        self.assertLessEqual(len(result["updates"]), 5)

    def test_linux_update_check_reads_cached_index_without_refresh_or_install(self):
        bridge = self.make_bridge()
        output = "Listing...\n" + "\n".join(f"package-{i}/stable 2.0 amd64 [upgradable from: 1.0]" for i in range(7))
        with patch("daedalus.agent.platform.system", return_value="Linux"), patch(
            "daedalus.agent.Path.is_file", return_value=True
        ), patch("daedalus.agent.subprocess.run", return_value=Mock(returncode=0, stdout=output)) as run:
            result = bridge._check_os_updates()
        self.assertEqual(result["status"], "updates_available")
        self.assertEqual(result["update_count"], 7)
        self.assertEqual(len(result["updates"]), 5)
        self.assertTrue(result["truncated"])
        self.assertEqual(result["source"], "existing_apt_index")
        self.assertFalse(result["catalog_refreshed"])
        self.assertEqual(run.call_args.args[0], ["/usr/bin/apt", "list", "--upgradable"])
        self.assertEqual(run.call_args.kwargs["env"]["LC_ALL"], "C")
        self.assertEqual(run.call_args.kwargs["timeout"], 30)

    def test_linux_empty_and_unparseable_index_results_are_distinct(self):
        bridge = self.make_bridge()
        for output, expected in (("Listing...\n", "no_updates"), ("", "unknown"),
                                 ("Listing...\nunparseable package\n", "unknown"),
                                 ("Listing...\n" + "x" * (128 * 1024), "unknown")):
            with self.subTest(expected=expected, length=len(output)), patch(
                "daedalus.agent.Path.is_file", return_value=True
            ), patch("daedalus.agent.subprocess.run", return_value=Mock(returncode=0, stdout=output)):
                result = bridge._check_linux_updates("2026-10-05T00:00:00Z")
                self.assertEqual(result["status"], expected)
                self.assertFalse(result["catalog_refreshed"])

    def test_linux_update_check_preserves_failure_states(self):
        import subprocess
        bridge = self.make_bridge()
        for failure, status in ((OSError("unavailable"), "unavailable"),
                                (subprocess.TimeoutExpired("apt", 30), "timed_out")):
            with self.subTest(status=status), patch("daedalus.agent.Path.is_file", return_value=True), patch(
                "daedalus.agent.subprocess.run", side_effect=failure
            ):
                self.assertEqual(bridge._check_linux_updates("now")["status"], status)
        with patch("daedalus.agent.Path.is_file", return_value=False), patch("daedalus.agent.subprocess.run") as run:
            self.assertEqual(bridge._check_linux_updates("now")["status"], "unavailable")
            run.assert_not_called()
        with patch("daedalus.agent.Path.is_file", return_value=True), patch(
            "daedalus.agent.subprocess.run", return_value=Mock(returncode=1, stdout="Listing...\n")
        ):
            self.assertEqual(bridge._check_linux_updates("now")["status"], "error")

    def test_macos_update_check_parses_bounded_read_only_catalog(self):
        bridge = self.make_bridge()
        completed = Mock(returncode=0, stdout=(
            "Software Update found the following new or updated software:\n"
            "* Label: macOS Tahoe 26.1-25B83\n    Title: macOS Tahoe 26.1, Version: 26.1\n"
            "* Label: Safari-26.1\n    Title: Safari, Version: 26.1\n"
        ))
        with patch("daedalus.agent.platform.system", return_value="Darwin"), patch(
            "daedalus.agent.Path.is_file", return_value=True
        ), patch("daedalus.agent.subprocess.run", return_value=completed) as run:
            result = bridge._check_os_updates()
        self.assertEqual(result["status"], "updates_available")
        self.assertEqual(result["update_count"], 2)
        self.assertEqual(result["updates"][0]["label"], "macOS Tahoe 26.1-25B83")
        run.assert_called_once_with(
            ["/usr/sbin/softwareupdate", "--list"],
            capture_output=True, text=True, timeout=120, check=False,
        )

    def test_macos_update_check_handles_no_updates_unknown_and_timeout(self):
        bridge = self.make_bridge()
        with patch("daedalus.agent.platform.system", return_value="Darwin"), patch(
            "daedalus.agent.Path.is_file", return_value=True
        ), patch("daedalus.agent.subprocess.run", return_value=Mock(
            returncode=0, stdout="No new software available.\n"
        )):
            self.assertEqual(bridge._check_os_updates()["status"], "no_updates")
        with patch("daedalus.agent.platform.system", return_value="Darwin"), patch(
            "daedalus.agent.Path.is_file", return_value=True
        ), patch("daedalus.agent.subprocess.run", return_value=Mock(returncode=0, stdout="unrecognized output")):
            self.assertEqual(bridge._check_os_updates()["status"], "unknown")
        with patch("daedalus.agent.platform.system", return_value="Darwin"), patch(
            "daedalus.agent.Path.is_file", return_value=True
        ), patch("daedalus.agent.subprocess.run", side_effect=__import__("subprocess").TimeoutExpired("softwareupdate", 120)):
            self.assertEqual(bridge._check_os_updates()["status"], "timed_out")

    def test_macos_no_updates_message_on_stderr(self):
        bridge = self.make_bridge()
        with patch("daedalus.agent.platform.system", return_value="Darwin"), patch(
            "daedalus.agent.Path.is_file", return_value=True
        ), patch("daedalus.agent.subprocess.run", return_value=Mock(
            returncode=0, stdout="Software Update Tool\nFinding available software\n",
            stderr="No new software available.\n"
        )):
            result = bridge._check_os_updates()
        self.assertEqual(result["status"], "no_updates")
        self.assertEqual(result["update_count"], 0)
        self.assertNotIn("stderr", result)

    def test_unsupported_update_command_is_local_only_and_protocol_is_four(self):
        self.assertEqual(COMMAND_PROTOCOL_VERSION, 4)
        bridge = self.make_bridge()
        response = Mock()
        response.json.return_value = {"command": {"id": 31, "action": "check_os_updates"}}
        bridge._request = Mock(return_value=response)
        bridge._send_command_result = Mock()
        with patch("daedalus.agent.platform.system", return_value="Windows"), patch(
            "daedalus.agent.subprocess.run"
        ) as run:
            bridge._run_one_command()
        run.assert_not_called()
        args = bridge._send_command_result.call_args.args
        self.assertEqual(args[:2], (31, "succeeded"))
        self.assertEqual(json.loads(args[2])["status"], "unsupported")

    def test_long_update_command_result_retains_valid_json_and_total(self):
        bridge = self.make_bridge()
        response = Mock()
        response.json.return_value = {"command": {"id": 32, "action": "check_os_updates"}}
        bridge._request = Mock(return_value=response)
        bridge._send_command_result = Mock()
        evidence = {"schema_version": 1, "observed_at": "2026-10-05T12:00:00Z", "status": "updates_available",
                    "platform": "Darwin", "update_count": 5, "truncated": False,
                    "updates": [{"label": '"' * 200, "title": '\\' * 160} for _ in range(5)]}
        with patch.object(bridge, "_check_os_updates", return_value=evidence):
            bridge._run_one_command()
        result = bridge._send_command_result.call_args.args[2]
        self.assertLessEqual(len(result), 1000)
        decoded = json.loads(result)
        self.assertEqual(decoded["update_count"], 5)
        self.assertTrue(decoded["truncated"])
        self.assertLess(len(decoded["updates"]), 5)
        self.assertEqual(len(evidence["updates"]), 5)
        self.assertFalse(evidence["truncated"])
        self.assertEqual(decoded["status"], "updates_available")

    def test_reads_only_readiness_and_app_version_from_nmapui(self):
        bridge = self.make_bridge()
        response = Mock()
        response.json.return_value = {
            "status": "ready",
            "ready": True,
            "app_version": "v2026.3.14.00_10",
            "default_interface": "private-interface-name",
            "tool_versions": {"nmap": "nmap 7.x"},
        }

        with patch("daedalus.agent.httpx.get", return_value=response) as get:
            status = bridge._read_nmapui_health()

        self.assertEqual(
            status,
            {"nmapui_version": "v2026.3.14.00_10", "nmapui_ready": True},
        )
        self.assertNotIn("default_interface", status)
        self.assertNotIn("tool_versions", status)
        get.assert_called_once_with(
            "http://127.0.0.1:9000/api/health/ready",
            auth=None,
            timeout=4,
        )

    def test_scan_command_forwards_only_an_explicit_known_target_override(self):
        bridge = self.make_bridge()
        bridge.nmapui_connected.set()
        bridge.command_completion_supported = True
        bridge._send_command_result = Mock()
        bridge.sio.emit = Mock()
        for option, expected in ((False, {"target": "127.0.0.1", "skip_host_discovery": False, "daedalus_command_id": 12, "daedalus_command_namespace": bridge.command_namespace}),
                                 (True, {"target": "127.0.0.1", "skip_host_discovery": True, "daedalus_command_id": 13, "daedalus_command_namespace": bridge.command_namespace})):
            bridge._request = Mock(return_value=httpx.Response(
                200,
                request=httpx.Request("GET", "https://fixture.example.org/next"),
                json={"command": {"id": 12 if not option else 13, "action": "start_scan", "target": "127.0.0.1", "skip_host_discovery": option}},
            ))
            bridge._run_one_command()
            bridge.sio.emit.assert_called_with("start_scan", expected)
        bridge._request = Mock(return_value=httpx.Response(
            200,
            request=httpx.Request("GET", "https://fixture.example.org/next"),
            json={"command": {"id": 14, "action": "start_scan", "target": "127.0.0.1"}},
        ))
        bridge._run_one_command()
        self.assertNotIn("skip_host_discovery", bridge.sio.emit.call_args.args[1])

    def test_events_survive_network_failure_process_restart_and_keep_order(self):
        bridge = self.make_bridge()
        bridge._request = Mock(side_effect=httpx.ConnectError("offline"))
        bridge._forward_event("scan_results", {"hosts": ["fixture-host"]})
        bridge._forward_event("scan_complete_summary", {"count": 1})
        paths = sorted(bridge.spool_dir.glob("*.json"))
        original = [json.loads(path.read_text()) for path in paths]
        self.assertEqual(len(paths), 2)
        self.assertEqual(bridge.spool_dir.stat().st_mode & 0o777, 0o700)
        self.assertEqual(paths[0].stat().st_mode & 0o777, 0o600)
        bridge._flush_events()
        self.assertEqual(len(list(bridge.spool_dir.glob("*.json"))), 2)
        bridge._flush_events()
        self.assertEqual(bridge._request.call_count, 1)  # Backoff prevents busy retries.
        restarted = self.make_bridge()
        restarted._request = Mock(return_value=httpx.Response(200, json={"ok": True, "event_id": 1}))
        restarted._flush_events()
        delivered = [call.kwargs["json"] for call in restarted._request.call_args_list]
        self.assertEqual(delivered, original)
        self.assertEqual(list(restarted.spool_dir.glob("*.json")), [])

    def test_permanent_rejection_retains_evidence_and_does_not_block_next_event(self):
        bridge = self.make_bridge()
        bridge._forward_event("scan_results", {"oversize": "fixture"})
        bridge._forward_event("scan_complete_summary", {"count": 1})
        bridge._request = Mock(side_effect=[httpx.Response(413), httpx.Response(200, json={"ok": True, "event_id": 1})])
        bridge._flush_events()
        self.assertEqual(len(list(bridge.spool_dir.glob("*.rejected"))), 1)
        self.assertEqual(list(bridge.spool_dir.glob("*.json")), [])

    def test_auth_and_transient_errors_keep_pending_events(self):
        bridge = self.make_bridge()
        bridge._forward_event("scan_results", {"fixture": True})
        for code in (401, 403, 408, 429, 503):
            with self.subTest(code=code):
                bridge.next_upload_at = 0
                bridge._request = Mock(return_value=httpx.Response(code))
                bridge._flush_events()
                self.assertEqual(len(list(bridge.spool_dir.glob("*.json"))), 1)
                self.assertEqual(list(bridge.spool_dir.glob("*.rejected")), [])

    def test_success_without_durable_acknowledgement_keeps_evidence(self):
        bridge = self.make_bridge()
        bridge._forward_event("scan_results", {"fixture": True})
        for response in (httpx.Response(200, text="<html>proxy</html>"), httpx.Response(202, json={"ok": True})):
            bridge.next_upload_at = 0
            bridge._request = Mock(return_value=response)
            bridge._flush_events()
            self.assertEqual(len(list(bridge.spool_dir.glob("*.json"))), 1)
            self.assertEqual(list(bridge.spool_dir.glob("*.rejected")), [])

    def test_large_scan_result_uses_artifact_endpoint_and_same_event_identity(self):
        bridge = self.make_bridge()
        bridge._forward_event("scan_results", {"padding": "x" * 600_000})
        original = json.loads(next(bridge.spool_dir.glob("*.json")).read_text())
        bridge._request = Mock(return_value=httpx.Response(200, json={"ok": True, "event_id": 4}))
        bridge._flush_events()
        bridge._request.assert_called_once_with("POST", "/api/agents/7/event-artifacts", json=original)
        self.assertEqual(list(bridge.spool_dir.glob("*.json")), [])

    def test_source_replay_keeps_uuid_time_and_avoids_duplicate_pending_raw_events(self):
        bridge = self.make_bridge()
        receive = bridge.sio.handlers["/"]["*"]
        source = {"client_event_id": "c6e06e90-ab69-4b6f-9e9e-d0600470c164",
                  "occurred_at": "2026-09-28T12:00:00+00:00", "event_name": "scan_results", "payload": [{"ip": "fixture-host"}]}
        receive("daedalus_protocol", {"version": 1})
        receive("daedalus_event", source)
        receive("daedalus_event", source)
        receive("scan_results", source["payload"])
        pending = list(bridge.spool_dir.glob("*.json"))
        self.assertEqual(len(pending), 1)
        self.assertEqual(json.loads(pending[0].read_text()), source)

    def test_authenticated_socket_connect_announces_bridge_protocol(self):
        bridge = self.make_bridge()
        bridge.sio.connect = Mock()
        response = Mock()
        response.json.return_value = {"token": "fixture-socket-token"}
        with patch.dict(os.environ, {"NMAPUI_USERNAME": "fixture", "NMAPUI_PASSWORD": "fixture-password"}), patch("daedalus.agent.httpx.get", return_value=response):
            bridge._connect_nmapui()
        kwargs = bridge.sio.connect.call_args.kwargs
        self.assertEqual(kwargs["auth"], {"token": "fixture-socket-token", "daedalus_bridge": True, "command_namespace": bridge.command_namespace})
        self.assertTrue(kwargs["headers"]["Authorization"].startswith("Basic "))

    def test_disconnect_resets_negotiation_for_legacy_runtime_reconnect(self):
        bridge = self.make_bridge()
        receive = bridge.sio.handlers["/"]["*"]
        receive("daedalus_protocol", {"version": 1})
        self.assertTrue(bridge.source_protocol)
        bridge.sio.handlers["/"]["disconnect"]("fixture reconnect")
        self.assertFalse(bridge.source_protocol)
        receive("scan_results", [{"ip": "legacy-fixture"}])
        pending = list(bridge.spool_dir.glob("*.json"))
        self.assertEqual(len(pending), 1)
        self.assertEqual(json.loads(pending[0].read_text())["payload"], [{"ip": "legacy-fixture"}])

    def test_unavailable_nmapui_health_is_reported_as_not_ready(self):
        bridge = self.make_bridge()

        with patch(
            "daedalus.agent.httpx.get",
            side_effect=httpx.TimeoutException("offline"),
        ):
            status = bridge._read_nmapui_health()

        self.assertEqual(status, {"nmapui_version": None, "nmapui_ready": False})

    def test_update_check_is_a_structured_socket_command(self):
        bridge = self.make_bridge()
        bridge.nmapui_connected.set()
        response = Mock()
        response.json.return_value = {
            "command": {"id": 19, "action": "check_nmapui_updates", "target": None}
        }
        bridge._request = Mock(return_value=response)
        bridge.sio.emit = Mock()
        bridge._send_command_result = Mock()

        bridge._run_one_command()

        bridge.sio.emit.assert_called_once_with("check_app_updates")
        bridge._send_command_result.assert_called_once_with(
            19,
            "accepted",
            "NmapUI was asked to check its release channel.",
        )
        self.assertIn("app_update_available", FORWARDED_EVENTS)
        self.assertIn("deep_scan_results", FORWARDED_EVENTS)
        self.assertIn("cve_array", FORWARDED_EVENTS)

    def test_managed_nmapui_restart_runs_while_the_socket_is_offline(self):
        (self.root / "Library/Application Support/Daedalus").mkdir(parents=True)
        bridge = NmapUIBridge(
            {
                "agent_id": 7,
                "server": "https://daedalus.example.org",
                "agent_token": "local-test-token",
                "nmapui_service_label": "org.daedalus.nmapui",
            },
            "http://127.0.0.1:9000",
        )
        self.addCleanup(bridge.http.close)
        response = Mock()
        response.json.return_value = {
            "command": {"id": 23, "action": "restart_nmapui", "target": None}
        }
        bridge._request = Mock(return_value=response)
        bridge._send_command_result = Mock()

        with patch("daedalus.agent.Path.home", return_value=self.root), patch("daedalus.agent.sys.platform", "darwin"), patch(
            "daedalus.agent.subprocess.run"
        ) as run:
            bridge._run_one_command()

        run.assert_called_once_with(
            ["/bin/launchctl", "kickstart", "-k", f"gui/{os.getuid()}/org.daedalus.nmapui"],
            check=True,
            timeout=20,
            capture_output=True,
            text=True,
        )
        bridge._send_command_result.assert_called_once_with(
            23,
            "accepted",
            "Restart requested for the managed NmapUI service.",
        )

    def make_linux_managed_bridge(self, label="first"):
        unit_dir = self.root / label / "config/systemd/user"
        config_dir = self.root / label / "config/daedalus"
        unit_dir.mkdir(parents=True)
        config_dir.mkdir(parents=True)
        files = {
            "daedalus-nmapui.env": config_dir / "daedalus-nmapui.env",
            "daedalus-nmapui.service": unit_dir / "daedalus-nmapui.service",
            "daedalus-scanner-bridge.service": unit_dir / "daedalus-scanner-bridge.service",
        }
        for name, path in files.items():
            path.write_text(f"managed fixture {name}")
            path.chmod(0o600)
        ownership = {
            "format": 1,
            "unit_dir": str(unit_dir),
            "files": {name: hashlib.sha256(path.read_bytes()).hexdigest() for name, path in files.items()},
        }
        ownership_path = config_dir / ".daedalus-scanner-services.json"
        ownership_path.write_text(json.dumps(ownership))
        ownership_path.chmod(0o600)
        unit_dir.chmod(0o700)
        config_dir.chmod(0o700)
        bridge = NmapUIBridge(
            {
                "agent_id": 7,
                "server": "https://daedalus.example.org",
                "agent_token": "local-test-token",
                "nmapui_service_manager": "systemd-user",
                "nmapui_service_label": "daedalus-nmapui.service",
                "nmapui_systemd_unit_dir": str(unit_dir),
                "nmapui_systemd_config_dir": str(config_dir),
            },
            "http://127.0.0.1:9000",
        )
        self.addCleanup(bridge.http.close)
        return bridge, unit_dir, config_dir

    def test_managed_linux_nmapui_restart_verifies_then_restarts_fixed_unit(self):
        bridge, _unit_dir, _config_dir = self.make_linux_managed_bridge()
        with patch("daedalus.agent.sys.platform", "linux"), patch(
            "daedalus.agent.subprocess.run"
        ) as run:
            self.assertTrue(bridge._nmapui_restart_supported())
            bridge._restart_managed_nmapui()

        run.assert_called_once_with(
            ["systemctl", "--user", "restart", "daedalus-nmapui.service"],
            check=True, timeout=20, capture_output=True, text=True,
        )

    def test_linux_remote_restart_refuses_pending_upgrade(self):
        bridge, _, config_dir = self.make_linux_managed_bridge()
        (config_dir / '.daedalus-scanner-upgrade.json').write_text('{}')
        with patch('daedalus.agent.sys.platform', 'linux'), patch('daedalus.agent.subprocess.run') as run:
            with self.assertRaisesRegex(RuntimeError, 'pending local upgrade'):
                bridge._restart_managed_nmapui()
        run.assert_not_called()

    def test_linux_remote_restart_refuses_concurrent_lifecycle(self):
        import fcntl
        bridge, _, config_dir = self.make_linux_managed_bridge()
        lock = os.open(config_dir / '.daedalus-scanner-services.lock', os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with patch('daedalus.agent.sys.platform', 'linux'), patch('daedalus.agent.subprocess.run') as run:
                with self.assertRaisesRegex(RuntimeError, 'lifecycle action is running'):
                    bridge._restart_managed_nmapui()
            run.assert_not_called()
        finally:
            os.close(lock)

    def test_linux_nmapui_restart_refuses_missing_or_tampered_managed_install(self):
        bridge, _unit_dir, _config_dir = self.make_linux_managed_bridge()
        with patch("daedalus.agent.sys.platform", "linux"):
            bridge.config["nmapui_systemd_config_dir"] = str(self.root / "missing-config")
            self.assertFalse(bridge._nmapui_restart_supported())
            with self.assertRaisesRegex(RuntimeError, "not configured for managed"):
                bridge._restart_managed_nmapui()

            bridge, unit_dir, _config_dir = self.make_linux_managed_bridge("second")
            (unit_dir / "daedalus-nmapui.service").write_text("tampered unit")
            with patch("daedalus.agent.subprocess.run") as run:
                with self.assertRaisesRegex(RuntimeError, "verification failed"):
                    bridge._restart_managed_nmapui()
            run.assert_not_called()

    def test_unmanaged_scanner_cannot_claim_service_restart_support(self):
        bridge = self.make_bridge()
        with patch("daedalus.agent.sys.platform", "darwin"):
            self.assertFalse(bridge._nmapui_restart_supported())

    def test_live_socket_commands_fail_cleanly_when_nmapui_is_offline(self):
        bridge = self.make_bridge()
        response = Mock()
        response.json.return_value = {
            "command": {"id": 24, "action": "start_scan", "target": "127.0.0.1"}
        }
        bridge._request = Mock(return_value=response)
        bridge.sio.emit = Mock()
        bridge._send_command_result = Mock()

        bridge._run_one_command()

        bridge.sio.emit.assert_not_called()
        bridge._send_command_result.assert_called_once_with(
            24,
            "failed",
            "NmapUI is offline and this command requires its live service.",
        )


class AgentSchemaUpgradeTests(unittest.TestCase):
    def test_adds_event_identity_columns_to_existing_table_idempotently(self):
        engine = create_engine("sqlite:///:memory:")
        try:
            with engine.begin() as connection:
                connection.exec_driver_sql("CREATE TABLE scan_events (id INTEGER PRIMARY KEY, agent_id INTEGER)")
                server.ensure_scanner_event_columns(connection)
                server.ensure_scanner_event_columns(connection)
                columns = {c["name"] for c in inspect(connection).get_columns("scan_events")}
            self.assertTrue({"client_event_id", "occurred_at"}.issubset(columns))
        finally:
            engine.dispose()

    def test_adds_scanner_telemetry_columns_to_existing_agent_table(self):
        engine = create_engine("sqlite:///:memory:")
        try:
            with engine.begin() as connection:
                connection.exec_driver_sql("CREATE TABLE agents (id INTEGER PRIMARY KEY)")
                server.ensure_agent_telemetry_columns(connection)
                server.ensure_agent_telemetry_columns(connection)
                columns = {column["name"] for column in inspect(connection).get_columns("agents")}
            self.assertTrue(
                {
                    "bridge_version",
                    "host_platform",
                    "nmapui_version",
                    "nmapui_ready",
                    "nmapui_restart_supported",
                    "authorized_networks",
                }.issubset(columns)
            )
        finally:
            engine.dispose()

    def test_adds_agent_network_scope_to_existing_enrollment_tables(self):
        engine = create_engine("sqlite:///:memory:")
        try:
            with engine.begin() as connection:
                connection.exec_driver_sql("CREATE TABLE agents (id INTEGER PRIMARY KEY)")
                connection.exec_driver_sql("CREATE TABLE enrollment_tokens (id INTEGER PRIMARY KEY)")
                server.ensure_agent_telemetry_columns(connection)
                server.ensure_enrollment_scope_columns(connection)
                server.ensure_agent_telemetry_columns(connection)
                server.ensure_enrollment_scope_columns(connection)
                agent_columns = {column["name"] for column in inspect(connection).get_columns("agents")}
                token_columns = {column["name"] for column in inspect(connection).get_columns("enrollment_tokens")}
            self.assertIn("authorized_networks", agent_columns)
            self.assertTrue({"scanner_name", "authorized_networks"}.issubset(token_columns))
        finally:
            engine.dispose()


if __name__ == "__main__":
    unittest.main()
