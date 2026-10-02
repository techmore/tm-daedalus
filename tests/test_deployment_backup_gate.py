"""Shell deployment gate fixtures; no Docker daemon or real config is used."""
import json
import hashlib
import io
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tarfile
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class DeploymentBackupGateTests(unittest.TestCase):
    def make_valid_backup(self, root):
        database = root / "daedalus.db"
        with sqlite3.connect(database) as db:
            db.execute("CREATE TABLE evidence (value TEXT)")
            db.execute("INSERT INTO evidence VALUES ('deployment fixture')")
        database_bytes = database.read_bytes()
        manifest = json.dumps({"version": 1, "files": [{
            "path": "daedalus.db",
            "size_bytes": len(database_bytes),
            "sha256": hashlib.sha256(database_bytes).hexdigest(),
        }]}).encode()
        source = root / "source-backup.tar.gz"
        with tarfile.open(source, "w:gz") as archive:
            for name, contents in (("daedalus.db", database_bytes), ("manifest.json", manifest)):
                entry = tarfile.TarInfo(name)
                entry.size = len(contents)
                archive.addfile(entry, io.BytesIO(contents))
        return source

    def run_deployment(self, scenario, *, persistent_backups=False):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            backup_source = self.make_valid_backup(root)
            (root / "scripts").mkdir()
            (root / "bin").mkdir()
            for name in ("deploy_digitalocean.sh", "backup_digitalocean.sh"):
                shutil.copyfile(ROOT / "scripts" / name, root / "scripts" / name)
            env_file = root / ".env.production"
            env_file.write_text("fixture only\n")
            env_file.chmod(0o644 if scenario == "insecure_env" else 0o600)
            fake = root / "bin" / "docker"
            fake.write_text(f"#!{sys.executable}\n" + r'''
import json, os, pathlib, sys
args = sys.argv[1:]
with open(os.environ["CALL_LOG"], "a") as stream:
    stream.write(json.dumps(args) + "\n")
scenario = os.environ["SCENARIO"]
if args[:2] == ["compose", "version"]:
    assert os.environ.get("COMPOSE_PROJECT_NAME") == "daedalus"
    raise SystemExit(0)
if args and args[0] == "compose":
    assert os.environ.get("COMPOSE_PROJECT_NAME") == "daedalus"
if args[0] == "inspect":
    if scenario == "inspect_failure":
        raise SystemExit(1)
    print("false" if scenario == "stopped" else "true")
    raise SystemExit(0)
assert args[:3] == ["compose", "--env-file", ".env.production"], args
command = args[3:]
if command == ["ps", "-a", "-q", "daedalus"]:
    if scenario == "list_failure":
        raise SystemExit(1)
    if scenario != "first":
        print("old-id\nsecond-id" if scenario == "multiple" else "old-id")
elif command[:2] == ["exec", "-T"]:
    if scenario == "backup_failure":
        raise SystemExit(1)
    print("fixture-backup.tar.gz")
elif command[0] == "cp":
    if scenario == "copy_failure":
        raise SystemExit(1)
    if scenario == "invalid_copy":
        pathlib.Path(command[-1]).write_bytes(b"invalid archive")
    else:
        import shutil
        shutil.copyfile(os.environ["BACKUP_SOURCE"], command[-1])
elif command == ["ps", "-q", "daedalus"]:
    print("new-id")
elif command == ["ps", "-q", "caddy"]:
    print("caddy-id")
''')
            fake.chmod(0o755)
            python = root / "bin" / "python3"
            python.write_text(f"#!{sys.executable}\n" + r'''
import json, os, runpy, sys
args = sys.argv[1:]
with open(os.environ["CALL_LOG"], "a") as stream:
    stream.write(json.dumps(["python3", *args]) + "\n")
if args and args[0] in {"scripts/check_production_env.py", "scripts/wait_deployment.py", "scripts/check_public_deployment.py"}:
    if args[0] == "scripts/check_production_env.py" and os.environ["SCENARIO"] == "insecure_env":
        script = os.path.join(os.environ["SOURCE_ROOT"], args[0])
        sys.argv = [script, *args[1:]]
        runpy.run_path(script, run_name="__main__")
    if args[0] == "scripts/check_public_deployment.py" and os.environ["SCENARIO"] == "public_failure":
        raise SystemExit(1)
    raise SystemExit(0)
if len(args) >= 2 and args[0] == "scripts/restore_data.py":
    script = os.path.join(os.environ["SOURCE_ROOT"], args[0])
    sys.argv = [script, *args[1:]]
    runpy.run_path(script, run_name="__main__")
raise SystemExit("Unexpected Python command in deployment fixture")
''')
            python.chmod(0o755)
            log = root / "calls.jsonl"
            persistent_backup_dir = root / "shared-backups"
            env = dict(os.environ, PATH=str(root / "bin") + os.pathsep + os.environ["PATH"],
                       CALL_LOG=str(log), SCENARIO=scenario, BACKUP_SOURCE=str(backup_source),
                       SOURCE_ROOT=str(ROOT))
            if persistent_backups:
                env["DAEDALUS_BACKUP_DIR"] = str(persistent_backup_dir)
            result = subprocess.run(["sh", "scripts/deploy_digitalocean.sh"], cwd=root,
                                    env=env, capture_output=True, text=True, timeout=10)
            calls = [json.loads(line) for line in log.read_text().splitlines()]
            backup = (persistent_backup_dir if persistent_backups else root / "backups") / "fixture-backup.tar.gz"
            mode = backup.stat().st_mode & 0o777 if backup.exists() else None
            directory_mode = backup.parent.stat().st_mode & 0o777 if backup.exists() else None
            return result, calls, mode, directory_mode

    def test_first_deployment_skips_backup(self):
        result, calls, _, _ = self.run_deployment("first")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(any("exec" in call or "inspect" in call for call in calls))
        self.assertTrue(any("build" in call for call in calls))
        self.assertIn("first deployment", result.stdout)

    def test_deployment_rejects_permissive_secrets_before_compose_uses_them(self):
        result, calls, _, _ = self.run_deployment("insecure_env")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("permission mode 0600", result.stderr)
        self.assertFalse(any(call[:3] == ["compose", "--env-file", ".env.production"] for call in calls))
        self.assertFalse(any("build" in call or "up" in call for call in calls))

    def test_update_backups_before_build_and_up(self):
        result, calls, mode, directory_mode = self.run_deployment("running")
        self.assertEqual(result.returncode, 0, result.stderr)
        operations = [call[3] for call in calls if call[:3] == ["compose", "--env-file", ".env.production"]]
        verify_position = next(
            index for index, call in enumerate(calls)
            if call[:2] == ["python3", "scripts/restore_data.py"] and "--verify-only" in call
        )
        copy_position = next(index for index, call in enumerate(calls) if call[:3] == ["compose", "--env-file", ".env.production"] and call[3] == "cp")
        build_position = next(index for index, call in enumerate(calls) if call[:4] == ["compose", "--env-file", ".env.production", "build"])
        self.assertLess(operations.index("exec"), operations.index("cp"))
        self.assertLess(operations.index("cp"), operations.index("build"))
        self.assertLess(operations.index("build"), operations.index("up"))
        self.assertLess(copy_position, verify_position)
        self.assertLess(verify_position, build_position)
        self.assertEqual(mode, 0o600)
        self.assertEqual(directory_mode, 0o700)
        public_check = next(index for index, call in enumerate(calls) if call[:2] == ["python3", "scripts/check_public_deployment.py"])
        status = next(index for index, call in enumerate(calls) if call == ["compose", "--env-file", ".env.production", "ps"])
        self.assertLess(public_check, status)

    def test_failed_public_dns_or_tls_verification_fails_deployment(self):
        result, calls, _, _ = self.run_deployment("public_failure")
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(any(call[:2] == ["python3", "scripts/check_public_deployment.py"] for call in calls))
        self.assertFalse(any(call == ["compose", "--env-file", ".env.production", "ps"] for call in calls))

    def test_update_can_keep_verified_backups_outside_a_release_directory(self):
        result, calls, mode, directory_mode = self.run_deployment("running", persistent_backups=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(mode, 0o600)
        self.assertEqual(directory_mode, 0o700)
        self.assertIn("shared-backups/fixture-backup.tar.gz", result.stdout)
        copied = next(call for call in calls if call[:3] == ["compose", "--env-file", ".env.production"] and call[3] == "cp")
        self.assertIn("shared-backups/fixture-backup.tar.gz", copied[-1])

    def test_unavailable_or_failed_backup_never_updates(self):
        for scenario in ("stopped", "inspect_failure", "list_failure", "multiple", "backup_failure", "copy_failure", "invalid_copy"):
            with self.subTest(scenario=scenario):
                result, calls, _, _ = self.run_deployment(scenario)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(any("build" in call or "up" in call for call in calls))
                self.assertIn("Update refused", result.stderr)
                if scenario in ("stopped", "inspect_failure", "list_failure", "multiple"):
                    self.assertFalse(any("exec" in call for call in calls))


if __name__ == "__main__":
    unittest.main()
