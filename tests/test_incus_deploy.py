from __future__ import annotations

import contextlib
import io
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.deploy_incus import DeployError, _validate, deploy, _run_streaming_ssh


ROOT = Path(__file__).parents[1]


class IncusDeployTests(unittest.TestCase):
    def test_ssh_access_prompts_are_visible_without_streaming_other_output(self):
        script = "import sys; print('# Tailscale SSH requires an additional check.',file=sys.stderr); print('# To authenticate, visit: https://login.tailscale.com/a/test12345678',file=sys.stderr); print('private diagnostic',file=sys.stderr); print('ready')"
        output = io.StringIO()
        with contextlib.redirect_stderr(output):
            result = _run_streaming_ssh([sys.executable, '-c', script])
        self.assertEqual(result, 'ready')
        self.assertIn('Tailscale SSH requires an additional check', output.getvalue())
        self.assertIn('https://login.tailscale.com/a/test12345678', output.getvalue())
        self.assertNotIn('private diagnostic', output.getvalue())

    def test_streaming_ssh_retains_exit_failure(self):
        with self.assertRaisesRegex(DeployError, r'Command failed \(7\): fixture failure'):
            _run_streaming_ssh([sys.executable, '-c', "import sys; print('fixture failure',file=sys.stderr); sys.exit(7)"])

    def _deploy_with_mocked_release(self, ssh_side_effect, health_results):
        temporary_directory = tempfile.TemporaryDirectory(prefix="daedalus-deploy-test-")
        self.addCleanup(temporary_directory.cleanup)

        def create_bundle(_root, archive):
            Path(archive).write_bytes(b"verified release fixture")
            return {"file_count": 52}

        output = io.StringIO()
        errors = io.StringIO()
        with (
            patch("scripts.deploy_incus._validate"),
            patch("scripts.deploy_incus._run", side_effect=["a" * 40, "", ""]),
            patch("scripts.deploy_incus.build_bundle", side_effect=create_bundle),
            patch("scripts.deploy_incus.verify_bundle"),
            patch("scripts.deploy_incus.subprocess.run", return_value=subprocess.CompletedProcess([], 0)),
            patch("scripts.deploy_incus._ssh", side_effect=ssh_side_effect) as ssh,
            patch("scripts.deploy_incus._wait_for_health", side_effect=health_results),
            contextlib.redirect_stdout(output),
            contextlib.redirect_stderr(errors),
        ):
            with self.assertRaises(DeployError) as failure:
                deploy("operator@incus-host", "daedalus-prod", "https://portal.example/readyz")
        return failure.exception, ssh.call_args_list, output.getvalue(), errors.getvalue()

    def test_plan_builds_a_verified_release_without_remote_commands(self):
        output = io.StringIO()
        with patch("scripts.deploy_incus._run", side_effect=["", "main", "a" * 40]) as command:
            with contextlib.redirect_stdout(output):
                result = deploy("operator@incus-host", "daedalus-prod", "https://portal.example/readyz", plan_only=True)

        self.assertEqual(result, 0)
        self.assertIn("Verified release archive:", output.getvalue())
        self.assertIn("automatic rollback", output.getvalue())
        self.assertEqual(command.call_count, 3)

    def test_production_deploy_rejects_uncommitted_changes(self):
        with patch("scripts.deploy_incus._run", side_effect=[" M README.md"]):
            with self.assertRaisesRegex(DeployError, "Commit and push"):
                deploy("operator@incus-host", "daedalus-prod", "https://portal.example/readyz")

    def test_production_validation_rejects_local_commit_not_pushed_to_origin_main(self):
        local_commit = "a" * 40
        remote_commit = "b" * 40
        with patch(
            "scripts.deploy_incus._run",
            side_effect=[
                "",
                "main",
                local_commit,
                f"{remote_commit}\trefs/heads/main",
            ],
        ) as command:
            with self.assertRaisesRegex(DeployError, "match the current origin/main"):
                _validate("operator@incus-host", "daedalus-prod")
        self.assertEqual(command.call_count, 4)

    def test_production_validation_accepts_exact_pushed_origin_main_commit(self):
        local_commit = "a" * 40
        with patch(
            "scripts.deploy_incus._run",
            side_effect=["", "main", local_commit, f"{local_commit}\trefs/heads/main"],
        ) as command:
            _validate("operator@incus-host", "daedalus-prod")
        remote_lookup = command.call_args_list[-1].args[0]
        self.assertIn("ls-remote", remote_lookup)
        self.assertIn("origin", remote_lookup)

    def test_failed_release_health_check_restores_previous_release_and_cleans_staging(self):
        failure, calls, output, errors = self._deploy_with_mocked_release(
            ssh_side_effect=None,
            health_results=[False, True],
        )

        self.assertIn("previous release was restored and is healthy", str(failure))
        self.assertIn("Restoring the previous source release", errors)
        remote_phases = [call.args[1][6] for call in calls if len(call.args[1]) > 6 and call.args[1][0] == "incus" and call.args[1][5].endswith("deploy-remote.sh")]
        self.assertEqual(remote_phases, ["prepare", "activate", "rollback", "cleanup"])
        self.assertIn("Verified release archive: 52 files", output)

    def test_failed_rollback_retains_remote_recovery_files(self):
        def fail_rollback(_host, command):
            if "rollback" in command:
                raise DeployError("rollback command failed")
            return ""

        failure, calls, _output, errors = self._deploy_with_mocked_release(
            ssh_side_effect=fail_rollback,
            health_results=[False],
        )

        self.assertIn("automatic rollback could not be verified", str(failure))
        self.assertIn("Restoring the previous source release", errors)
        remote_phases = [call.args[1][6] for call in calls if len(call.args[1]) > 6 and call.args[1][0] == "incus" and call.args[1][5].endswith("deploy-remote.sh")]
        self.assertEqual(remote_phases, ["prepare", "activate", "rollback"])
        host_cleanup = calls[-1].args[1]
        self.assertEqual(host_cleanup[0], "rm")
        self.assertNotIn("/tmp/daedalus-deploy-remote.sh", host_cleanup)

    def test_pdf_browser_install_avoids_protected_home_cache(self):
        script = (ROOT / "scripts/deploy_incus_remote.sh").read_text()
        self.assertIn("PLAYWRIGHT_BROWSERS_PATH=/opt/daedalus/browser-runtime", script)
        self.assertIn("install -d -o daedalus -g daedalus -m 0755 /opt/daedalus/browser-runtime", script)

    def test_remote_helper_has_valid_bash_syntax(self):
        result = subprocess.run(
            ["bash", "-n", str(ROOT / "scripts/deploy_incus_remote.sh")],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
