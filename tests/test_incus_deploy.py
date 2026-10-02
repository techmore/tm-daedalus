from __future__ import annotations

import contextlib
import io
import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.deploy_incus import DeployError, deploy


ROOT = Path(__file__).parents[1]


class IncusDeployTests(unittest.TestCase):
    def test_plan_builds_a_verified_release_without_remote_commands(self):
        output = io.StringIO()
        with patch("scripts.deploy_incus._run", side_effect=["", "main", "a" * 40]) as command:
            with contextlib.redirect_stdout(output):
                result = deploy("operator@incus-host", "daedalus-prod", "https://portal.example/healthz", plan_only=True)

        self.assertEqual(result, 0)
        self.assertIn("Verified release archive:", output.getvalue())
        self.assertIn("automatic rollback", output.getvalue())
        self.assertEqual(command.call_count, 3)

    def test_production_deploy_rejects_uncommitted_changes(self):
        with patch("scripts.deploy_incus._run", side_effect=[" M README.md"]):
            with self.assertRaisesRegex(DeployError, "Commit and push"):
                deploy("operator@incus-host", "daedalus-prod", "https://portal.example/healthz")

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
