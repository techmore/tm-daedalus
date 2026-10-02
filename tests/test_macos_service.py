import os
import plistlib
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


AGENT_BUNDLE = Path(__file__).resolve().parents[1] / "src" / "daedalus" / "agent_bundle"
sys.path.insert(0, str(AGENT_BUNDLE))
import macos_service


class ManagedMacOSServiceTests(unittest.TestCase):
    def test_nmapui_launchagent_is_loopback_only_and_restarts_on_exit(self):
        with patch.dict(os.environ, {"NMAPUI_USERNAME": "", "NMAPUI_PASSWORD": ""}):
            payload = macos_service.build_nmapui_plist(
                python="/Users/operator/Daedalus/.venv/bin/python",
                app_dir="/Users/operator/Daedalus/release",
                data_dir="/Users/operator/Library/Application Support/Daedalus/nmapui-data",
                log_dir="/Users/operator/Library/Application Support/Daedalus/nmapui-data/logs",
                browser_dir="/Users/operator/Daedalus/browsers",
                port=9000,
            )

        environment = payload["EnvironmentVariables"]
        self.assertEqual(payload["Label"], "org.daedalus.nmapui")
        self.assertEqual(payload["ProgramArguments"], ["/Users/operator/Daedalus/.venv/bin/python", "app.py"])
        self.assertTrue(payload["KeepAlive"])
        self.assertTrue(payload["RunAtLoad"])
        self.assertEqual(environment["NMAPUI_HOST"], "127.0.0.1")
        self.assertEqual(environment["NMAPUI_PORT"], "9000")
        self.assertEqual(environment["NMAPUI_DATA_DIR"], "/Users/operator/Library/Application Support/Daedalus/nmapui-data/data")
        self.assertEqual(environment["NMAPUI_LOG_DIR"], "/Users/operator/Library/Application Support/Daedalus/nmapui-data/logs")
        self.assertEqual(environment["NMAPUI_ENABLE_NETWORK_FINGERPRINT"], "false")
        self.assertEqual(environment["NMAPUI_ENABLE_UPDATE_CHECK"], "false")
        self.assertNotIn("NMAPUI_USERNAME", environment)
        self.assertNotIn("shell", payload)

    def test_bridge_launchagent_reads_private_config_without_secret_arguments(self):
        with patch.dict(
            os.environ,
            {"NMAPUI_USERNAME": "scanner", "NMAPUI_PASSWORD": "sample-password"},
        ):
            payload = macos_service.build_bridge_plist(
                agent_executable="/Users/operator/Daedalus/.venv/bin/daedalus-agent",
                config_path="/Users/operator/Daedalus/managed-agent.json",
                install_dir="/Users/operator/Daedalus",
                log_dir="/Users/operator/Daedalus/logs",
            )

        self.assertEqual(payload["Label"], "org.daedalus.scanner-bridge")
        self.assertEqual(
            payload["ProgramArguments"],
            [
                "/Users/operator/Daedalus/.venv/bin/daedalus-agent",
                "--config",
                "/Users/operator/Daedalus/managed-agent.json",
            ],
        )
        self.assertNotIn("sample-password", payload["ProgramArguments"])
        self.assertEqual(
            payload["EnvironmentVariables"]["NMAPUI_PASSWORD"], "sample-password"
        )

    def test_service_configuration_rejects_bad_auth_pairs_ports_and_labels(self):
        with patch.dict(os.environ, {"NMAPUI_USERNAME": "scanner", "NMAPUI_PASSWORD": ""}):
            with self.assertRaisesRegex(ValueError, "must be set together"):
                macos_service.build_bridge_plist(
                    agent_executable="/agent",
                    config_path="/config.json",
                    install_dir="/install",
                    log_dir="/logs",
                )

        with patch.dict(os.environ, {"NMAPUI_USERNAME": "", "NMAPUI_PASSWORD": ""}):
            with self.assertRaisesRegex(ValueError, "port must be between"):
                macos_service.build_nmapui_plist(
                    python="/python",
                    app_dir="/app",
                    data_dir="/data",
                    log_dir="/logs",
                    browser_dir="/browser",
                    port=70000,
                )
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "service.plist"
            with self.assertRaisesRegex(ValueError, "unexpected Daedalus service label"):
                macos_service.write_plist(output, {"Label": "com.other.service"})

    def test_plist_write_is_owner_only_and_round_trips(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "LaunchAgents" / "nmapui.plist"
            payload = {"Label": macos_service.NMAPUI_LABEL, "RunAtLoad": True}
            macos_service.write_plist(output, payload)
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
            with output.open("rb") as stream:
                self.assertEqual(plistlib.load(stream), payload)

            link = output.parent / "linked.plist"
            link.symlink_to(output)
            with self.assertRaisesRegex(ValueError, "symbolic link"):
                macos_service.write_plist(link, payload)


if __name__ == "__main__":
    unittest.main()
