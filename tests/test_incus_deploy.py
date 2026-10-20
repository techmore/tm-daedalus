from __future__ import annotations

import contextlib
import io
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.deploy_incus import DeployError, _validate, deploy, _run_streaming_ssh, _ssh


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

    def test_ssh_bounds_connection_without_limiting_remote_work(self):
        with patch("scripts.deploy_incus._run_streaming_ssh", return_value="ready") as command:
            self.assertEqual(_ssh("operator@incus-host", ["incus", "exec", "daedalus-prod", "--", "echo", "a b"]), "ready")
        self.assertEqual(command.call_args.args[0], [
            "ssh", "-o", "ConnectTimeout=10", "-o", "ConnectionAttempts=1",
            "operator@incus-host", "incus exec daedalus-prod -- echo 'a b'",
        ])

    def test_backup_connection_failure_leaves_no_published_archive(self):
        import os
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            executable = root / "ssh"
            arguments = root / "arguments"
            executable.write_text("#!/bin/sh\nprintf '%s\n' \"$@\" > \"$QA_SSH_ARGUMENTS\"\nexit 7\n")
            executable.chmod(0o700)
            environment = dict(os.environ, PATH=str(root) + os.pathsep + os.environ["PATH"],
                DAEDALUS_INCUS_HOST="operator@fixture-host", DAEDALUS_BACKUP_DIR=str(root / "backups"),
                QA_SSH_ARGUMENTS=str(arguments))
            result = subprocess.run(["sh", str(ROOT / "scripts/backup_incus.sh")], env=environment, capture_output=True)
            self.assertEqual(result.returncode, 7)
            self.assertEqual(arguments.read_text().splitlines()[:5],
                ["-o", "ConnectTimeout=10", "-o", "ConnectionAttempts=1", "operator@fixture-host"])
            self.assertEqual(list((root / "backups").iterdir()), [])

    def test_streaming_ssh_retains_exit_failure(self):
        with self.assertRaisesRegex(DeployError, r'Command failed \(7\): fixture failure'):
            _run_streaming_ssh([sys.executable, '-c', "import sys; print('fixture failure',file=sys.stderr); sys.exit(7)"])

    def test_optional_cleanup_does_not_request_another_identity_check(self):
        script = "import sys,time; print('# Tailscale SSH requires an additional check.',file=sys.stderr,flush=True); print('# To authenticate, visit: https://login.tailscale.com/a/test12345678',file=sys.stderr,flush=True); time.sleep(5)"
        output = io.StringIO()
        with contextlib.redirect_stderr(output), self.assertRaises(DeployError):
            _run_streaming_ssh([sys.executable, '-c', script], allow_access_check=False, timeout=1)
        self.assertEqual(output.getvalue(), '')

    def test_optional_cleanup_has_a_bounded_process_deadline(self):
        with self.assertRaisesRegex(DeployError, 'exceeded its deadline'):
            _run_streaming_ssh([sys.executable, '-c', 'import time; time.sleep(5)'], allow_access_check=False, timeout=0.1)

    def test_only_optional_cleanup_changes_access_check_and_work_deadline(self):
        with patch('scripts.deploy_incus._run_streaming_ssh', return_value='') as command:
            _ssh('operator@incus-host', ['rm', '-f', '/tmp/fixture.tar.gz'], optional_cleanup=True)
        self.assertEqual(command.call_args.kwargs, {'allow_access_check': False, 'timeout': 20})
        with patch('scripts.deploy_incus._run_streaming_ssh', return_value='') as command:
            _ssh('operator@incus-host', ['incus', 'exec', 'daedalus-prod', '--', 'rollback'])
        self.assertEqual(command.call_args.kwargs, {})

    def _deploy_with_mocked_release(self, ssh_side_effect, health_results, expected_error=DeployError):
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
            with self.assertRaises(expected_error) as failure:
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
        self.assertTrue(calls[-1].kwargs["optional_cleanup"])
        self.assertTrue(calls[-2].kwargs["optional_cleanup"])
        self.assertTrue(all(not call.kwargs.get("optional_cleanup") for call in calls[:-2]))
        self.assertIn("Verified release archive: 52 files", output)

    def test_failed_rollback_retains_remote_recovery_files(self):
        def fail_rollback(_host, command, **_kwargs):
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
        self.assertFalse(any(call.kwargs.get("optional_cleanup") for call in calls))
        self.assertIn("Recovery staging retained", str(failure))

    def test_staging_is_private_unique_and_root_owned_before_upload(self):
        _failure, calls, _output, _errors = self._deploy_with_mocked_release(None, [False, True])
        commands = [call.args[1] for call in calls]
        host_directory = commands[0][-1]
        self.assertRegex(host_directory, r'^/tmp/daedalus-deploy-[0-9a-f]{32}$')
        self.assertEqual(commands[0][:4], ['mkdir', '-m', '0700', '--'])
        self.assertIn('mkdir -m 0700', commands[1][-3])
        pushes = [command for command in commands if command[:3] == ['incus', 'file', 'push']]
        self.assertEqual(len(pushes), 2)
        for command in pushes:
            self.assertEqual(command[3:9], ['--uid', '0', '--gid', '0', '--mode', '0600'])
            self.assertRegex(command[-1], r'^daedalus-prod/opt/daedalus/\.deploy-[0-9a-f]{32}/')
        phases = [command for command in commands if len(command) > 6 and command[5].endswith('deploy-remote.sh')]
        self.assertTrue(all(command[9] == phases[0][9] for command in phases))
        self.assertEqual(commands[-1], ['rm', '-rf', '--', host_directory])

    def test_failed_helper_upload_cleans_private_attempt_without_executing_partial_helper(self):
        def upload_fails(_host, command, **_kwargs):
            if command[:3] == ['incus', 'file', 'push'] and command[-1].endswith('deploy-remote.sh'):
                raise DeployError('interrupted helper upload')
            return ''
        failure, calls, _output, _errors = self._deploy_with_mocked_release(upload_fails, [])
        self.assertIn('interrupted helper upload', str(failure))
        cleanup = [call.args[1] for call in calls if call.kwargs.get('optional_cleanup')]
        self.assertEqual(len(cleanup), 2)
        self.assertEqual(cleanup[0][:7], ['incus', 'exec', 'daedalus-prod', '--', 'rm', '-rf', '--'])
        self.assertFalse(any('prepare' in call.args[1] for call in calls))

    def test_interrupted_or_uncertain_remote_work_retains_recovery(self):
        for phase in ('prepare', 'activate', 'rollback'):
            for error in (KeyboardInterrupt, DeployError):
                with self.subTest(phase=phase, error=error):
                    def interrupt(_host, command, **_kwargs):
                        if phase in command:
                            raise error('interrupted remote operation')
                        return ''
                    # Activation DeployError is recovered normally; rollback is then proven safe.
                    if phase == 'activate' and error == DeployError:
                        continue
                    _failure, calls, _output, errors = self._deploy_with_mocked_release(interrupt, [False], expected_error=error)
                    self.assertFalse(any(call.kwargs.get('optional_cleanup') for call in calls))
                    self.assertIn('Recovery staging retained', errors)

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
