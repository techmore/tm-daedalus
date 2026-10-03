import io
import json
import hashlib
import os
import sqlite3
import stat
import subprocess
import sys
import ssl
import tarfile
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from cryptography.fernet import Fernet

from scripts import backup_data
from scripts.restore_data import RestoreError, restore_archive, verify_archive
from scripts.check_production_env import (
    UnsafeEnvironmentFile,
    main as validate_production_env,
    read_env,
    validate,
)
from scripts import check_public_deployment


def valid_production_values():
    return {
        "DAEDALUS_ENV": "production",
        "DAEDALUS_DEMO_MODE": "false",
        "DAEDALUS_BASE_URL": "https://app.example.org",
        "DAEDALUS_HOSTNAMES": "app.example.org,app.bfs.org",
        "DAEDALUS_ALLOWED_HOSTS": "app.example.org,app.bfs.org",
        "DAEDALUS_SESSION_SECRET": "s" * 48,
        "GOOGLE_CLIENT_ID": "client.apps.googleusercontent.com",
        "GOOGLE_CLIENT_SECRET": "oauth-secret-for-tests",
        "DAEDALUS_ENCRYPTION_KEY": Fernet.generate_key().decode("ascii"),
    }


class ProductionEnvironmentTests(unittest.TestCase):
    def test_public_host_check_requires_resolvable_host_and_valid_health_payload(self):
        test_case = self
        class Response:
            status = 200

            @staticmethod
            def read(limit):
                self.assertLessEqual(limit, 4096)
                return b'{"status":"ready","app":"daedalus"}'

        class Connection:
            def __init__(self, hostname, port, *, timeout, context):
                test_case.assertEqual((hostname, port), ("app.example.org", 443))
                test_case.assertIs(context, ssl_context)

            def request(self, method, path, *, headers):
                test_case.assertEqual((method, path), ("GET", "/readyz"))
                test_case.assertEqual(headers["Host"], "app.example.org")

            @staticmethod
            def getresponse():
                return Response()

            @staticmethod
            def close():
                pass

        ssl_context = object()
        with patch.object(check_public_deployment.socket, "getaddrinfo", return_value=[("ok",)]), patch.object(check_public_deployment.ssl, "create_default_context", return_value=ssl_context), patch.object(check_public_deployment.http.client, "HTTPSConnection", Connection):
            self.assertEqual(check_public_deployment.check_public_host("app.example.org"), (True, "DNS, trusted HTTPS, and Daedalus readiness passed"))

    def test_public_host_check_fails_for_dns_tls_or_wrong_health_payload(self):
        with patch.object(check_public_deployment.socket, "getaddrinfo", side_effect=OSError):
            self.assertEqual(check_public_deployment.check_public_host("app.example.org"), (False, "DNS lookup failed"))

        class BadTLS:
            def __init__(self, *args, **kwargs):
                pass

            def request(self, *args, **kwargs):
                raise ssl.SSLCertVerificationError("untrusted")

            def close(self):
                pass

        with patch.object(check_public_deployment.socket, "getaddrinfo", return_value=[("ok",)]), patch.object(check_public_deployment.http.client, "HTTPSConnection", BadTLS):
            result = check_public_deployment.check_public_host("app.example.org")
        self.assertEqual(result, (False, "TLS certificate trust or hostname verification failed"))

    def test_public_verification_checks_each_configured_hostname_and_fails_closed(self):
        values = valid_production_values()
        with tempfile.TemporaryDirectory() as directory:
            env_file = Path(directory) / ".env.production"
            env_file.write_text("".join(f"{key}={value}\n" for key, value in values.items()), encoding="utf-8")
            env_file.chmod(0o600)
            with patch.object(sys, "argv", ["check_public_deployment.py", str(env_file)]), patch.object(check_public_deployment, "check_public_host", side_effect=[(True, "ok"), (False, "bad")]) as check, redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                self.assertEqual(check_public_deployment.main(), 1)
            self.assertEqual([call.args[0] for call in check.call_args_list], ["app.example.org", "app.bfs.org"])

    def test_production_env_requires_owner_only_0600_permissions(self):
        with tempfile.TemporaryDirectory() as directory:
            env_file = Path(directory) / ".env.production"
            env_file.write_text("DAEDALUS_ENV=production\n", encoding="utf-8")

            env_file.chmod(0o600)
            self.assertEqual(read_env(env_file), {"DAEDALUS_ENV": "production"})

            for mode in (0o640, 0o644, 0o660, 0o666):
                with self.subTest(mode=oct(mode)):
                    env_file.chmod(mode)
                    with self.assertRaisesRegex(UnsafeEnvironmentFile, "mode 0600"):
                        read_env(env_file)

    def test_production_env_permission_check_follows_symlink_target(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "shared-env"
            link = root / ".env.production"
            target.write_text("DAEDALUS_ENV=production\n", encoding="utf-8")
            target.chmod(0o644)
            link.symlink_to(target)

            with self.assertRaisesRegex(UnsafeEnvironmentFile, "found 0644"):
                read_env(link)

            target.chmod(0o600)
            self.assertEqual(read_env(link), {"DAEDALUS_ENV": "production"})

    def test_production_env_cli_blocks_readable_secrets_before_parsing(self):
        values = valid_production_values()
        secret = values["GOOGLE_CLIENT_SECRET"]
        with tempfile.TemporaryDirectory() as directory:
            env_file = Path(directory) / ".env.production"
            env_file.write_text(
                "".join(f"{name}={value}\n" for name, value in values.items()),
                encoding="utf-8",
            )
            env_file.chmod(0o644)

            error = io.StringIO()
            with patch.object(sys, "argv", ["check_production_env.py", str(env_file)]), redirect_stderr(error):
                self.assertEqual(validate_production_env(), 1)
            self.assertIn("permission mode 0600", error.getvalue())
            self.assertNotIn(secret, error.getvalue())

            env_file.chmod(0o600)
            output = io.StringIO()
            with patch.object(sys, "argv", ["check_production_env.py", str(env_file)]), redirect_stdout(output):
                self.assertEqual(validate_production_env(), 0)
            self.assertIn("Production environment is valid", output.getvalue())

    def test_public_hostnames_include_the_canonical_portal(self):
        values = valid_production_values()
        values["DAEDALUS_HOSTNAMES"] = "app.bfs.org"
        self.assertIn("DAEDALUS_HOSTNAMES must include the DAEDALUS_BASE_URL hostname", validate(values))

    def test_rejects_non_origin_and_unserved_port_urls(self):
        for suffix in ("/portal", "?key=fixture", "#portal", ":8443", ":invalid"):
            with self.subTest(suffix=suffix):
                values = valid_production_values()
                values["DAEDALUS_BASE_URL"] = "https://app.example.org" + suffix
                self.assertTrue(validate(values))
        values = valid_production_values()
        values["DAEDALUS_BASE_URL"] = "https://fixture:fixture@app.example.org"
        self.assertIn("DAEDALUS_BASE_URL must be an origin without credentials, path, query or fragment", validate(values))

    def test_accepts_https_multi_domain_configuration(self):
        self.assertEqual(validate(valid_production_values()), [])

    def test_requires_every_public_hostname_in_host_allowlist(self):
        values = valid_production_values()
        values["DAEDALUS_ALLOWED_HOSTS"] = "app.example.org"

        errors = validate(values)

        self.assertIn(
            "DAEDALUS_ALLOWED_HOSTS must include every DAEDALUS_HOSTNAMES entry",
            errors,
        )

    def test_rejects_wildcard_and_malformed_allowed_hosts_entries(self):
        invalid_entries = (
            "*.example.org",
            "https://unexpected.example.org",
            "unexpected.example.org:8443",
            "unexpected.example.org/path",
            "not_a_hostname",
        )
        for invalid_entry in invalid_entries:
            with self.subTest(invalid_entry=invalid_entry):
                values = valid_production_values()
                values["DAEDALUS_ALLOWED_HOSTS"] += "," + invalid_entry

                errors = validate(values)

                self.assertIn(
                    "DAEDALUS_ALLOWED_HOSTS must contain DNS hostnames only",
                    errors,
                )

    def test_rejects_allowed_host_not_configured_as_public_hostname(self):
        values = valid_production_values()
        values["DAEDALUS_ALLOWED_HOSTS"] += ",other.example.net"

        errors = validate(values)

        self.assertIn(
            "DAEDALUS_ALLOWED_HOSTS must not contain hostnames outside DAEDALUS_HOSTNAMES",
            errors,
        )

    def test_rejects_http_url_placeholders_and_invalid_encryption_key(self):
        values = valid_production_values()
        values.update(
            {
                "DAEDALUS_BASE_URL": "http://app.example.org",
                "GOOGLE_CLIENT_SECRET": "replace-with-google-oauth-client-secret",
                "DAEDALUS_ENCRYPTION_KEY": "invalid-key",
            }
        )

        errors = validate(values)

        self.assertIn(
            "DAEDALUS_BASE_URL must be an HTTPS URL with a hostname", errors
        )
        self.assertIn("GOOGLE_CLIENT_SECRET must be set to a real value", errors)
        self.assertIn(
            "DAEDALUS_ENCRYPTION_KEY must be a valid Fernet key", errors
        )




class ProductionConfigStartupTests(unittest.TestCase):
    def run_config_import(self, extra_values: dict[str, str]):
        environment = os.environ.copy()
        for name in (
            "DAEDALUS_ENV",
            "DAEDALUS_DEMO_MODE",
            "DAEDALUS_SESSION_SECRET",
            "DAEDALUS_BASE_URL",
            "DAEDALUS_ALLOWED_HOSTS",
            "GOOGLE_CLIENT_ID",
            "GOOGLE_CLIENT_SECRET",
            "DAEDALUS_ENCRYPTION_KEY",
        ):
            environment.pop(name, None)
        environment.update(
            {
                "DAEDALUS_ENV": "production",
                "DAEDALUS_DEMO_MODE": "false",
                "DAEDALUS_SESSION_SECRET": "production-session-secret-" + "s" * 32,
                "DAEDALUS_BASE_URL": "https://portal.example.org",
                "DAEDALUS_ALLOWED_HOSTS": "portal.example.org,app.bfs.org",
                "PYTHONPATH": str(Path(__file__).resolve().parents[1] / "src"),
                **extra_values,
            }
        )
        return subprocess.run(
            [
                sys.executable,
                "-c",
                "from daedalus.config import ALLOWED_HOSTS; print(','.join(ALLOWED_HOSTS))",
            ],
            capture_output=True,
            check=False,
            env=environment,
            text=True,
        )

    def test_production_refuses_to_start_without_google_oauth(self):
        result = self.run_config_import({})

        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "Set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET in production",
            result.stderr,
        )

    def test_production_refuses_to_start_without_valid_encryption_key(self):
        result = self.run_config_import(
            {
                "GOOGLE_CLIENT_ID": "client.apps.googleusercontent.com",
                "GOOGLE_CLIENT_SECRET": "test-oauth-secret",
                "DAEDALUS_ENCRYPTION_KEY": "invalid-key",
            }
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "DAEDALUS_ENCRYPTION_KEY must be a valid Fernet key in production",
            result.stderr,
        )

    def test_production_accepts_valid_credentials_and_allowed_hosts(self):
        result = self.run_config_import(
            {
                "GOOGLE_CLIENT_ID": "client.apps.googleusercontent.com",
                "GOOGLE_CLIENT_SECRET": "test-oauth-secret",
                "DAEDALUS_ENCRYPTION_KEY": Fernet.generate_key().decode("ascii"),
            }
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            result.stdout.strip(),
            "portal.example.org,app.bfs.org",
        )


class ProductionBackupTests(unittest.TestCase):
    def test_archive_contains_consistent_database_and_report_files(self):
        with tempfile.TemporaryDirectory(prefix="daedalus-backup-") as directory:
            root = Path(directory)
            data = root / "data"
            backup_dir = data / "backups"
            database = data / "daedalus.db"
            reports = data / "reports"
            reports.mkdir(parents=True)
            with sqlite3.connect(database) as db:
                db.execute("CREATE TABLE evidence (id INTEGER PRIMARY KEY, value TEXT)")
                db.execute("INSERT INTO evidence (value) VALUES ('saved')")
            (reports / "report.pdf").write_bytes(b"%PDF-test")
            artifacts = data / "scanner-artifacts" / "1" / "7"
            artifacts.mkdir(parents=True)
            (artifacts / "fixture.json").write_text('{"hosts": []}')

            output = io.StringIO()
            with (
                patch.object(backup_data, "DATA_DIR", data),
                patch.object(backup_data, "BACKUP_DIR", backup_dir),
                patch.object(backup_data, "DATABASE", database),
                patch.object(backup_data, "REPORTS", reports),
                redirect_stdout(output),
            ):
                backup_data.main()

            archive_path = backup_dir / output.getvalue().strip()
            self.assertTrue(archive_path.is_file())
            self.assertEqual(stat.S_IMODE(archive_path.stat().st_mode), 0o600)
            verify_archive(archive_path)
            with tarfile.open(archive_path, "r:gz") as archive:
                names = set(archive.getnames())
                self.assertTrue({"daedalus.db", "reports/report.pdf", "scanner-artifacts/1/7/fixture.json", "manifest.json"}.issubset(names))
                manifest = json.loads(archive.extractfile("manifest.json").read())
                for item in manifest["files"]:
                    content = archive.extractfile(item["path"]).read()
                    self.assertEqual(len(content), item["size_bytes"])
                    self.assertEqual(hashlib.sha256(content).hexdigest(), item["sha256"])
                restored = root / "restored.db"
                restored.write_bytes(archive.extractfile("daedalus.db").read())
            with sqlite3.connect(restored) as db:
                self.assertEqual(
                    db.execute("SELECT value FROM evidence").fetchone()[0], "saved"
                )
            destination = root / "verified-data"
            restore_archive(archive_path, destination)
            self.assertEqual((destination / "reports/report.pdf").read_bytes(), b"%PDF-test")
            self.assertEqual((destination / "scanner-artifacts/1/7/fixture.json").read_text(), '{"hosts": []}')
            self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE((destination / "daedalus.db").stat().st_mode), 0o600)
            with sqlite3.connect(destination / "daedalus.db") as db:
                self.assertEqual(db.execute("SELECT value FROM evidence").fetchone()[0], "saved")


class ProductionRestoreTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="daedalus-restore-fixture-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        database = self.root / "fixture.db"
        with sqlite3.connect(database) as db:
            db.execute("CREATE TABLE evidence (value TEXT)")
            db.execute("INSERT INTO evidence VALUES ('fixture')")
        self.database_bytes = database.read_bytes()

    def archive(self, *, files=None, manifest_files=None, extra=None, manifest=True):
        files = files or {"daedalus.db": self.database_bytes, "reports/fixture.pdf": b"%PDF-fixture"}
        expected = manifest_files or files
        path = self.root / "fixture.tar.gz"
        with tarfile.open(path, "w:gz") as archive:
            for name, contents in files.items():
                entry = tarfile.TarInfo(name)
                entry.size = len(contents)
                archive.addfile(entry, io.BytesIO(contents))
            if extra:
                archive.addfile(extra)
            if manifest:
                encoded = json.dumps({"version": 1, "files": [
                    {"path": name, "size_bytes": len(contents), "sha256": hashlib.sha256(contents).hexdigest()}
                    for name, contents in expected.items()
                ]}).encode()
                entry = tarfile.TarInfo("manifest.json")
                entry.size = len(encoded)
                archive.addfile(entry, io.BytesIO(encoded))
        return path

    def refuse(self, archive, *, destination=None, **kwargs):
        destination = destination or self.root / "restored"
        with self.assertRaises(RestoreError):
            restore_archive(archive, destination, **kwargs)
        self.assertEqual(list(self.root.glob(".daedalus-restore-*")), [])

    def refuse_verification(self, archive, **kwargs):
        with self.assertRaises(RestoreError):
            verify_archive(archive, **kwargs)
        self.assertEqual(list(self.root.glob(".daedalus-backup-verify-*")), [])

    def test_verify_only_checks_manifest_digests_and_sqlite_integrity(self):
        valid = self.archive()
        self.assertIsNone(verify_archive(valid))

        original = {"daedalus.db": self.database_bytes, "reports/fixture.pdf": b"original"}
        tampered = {**original, "reports/fixture.pdf": b"modified"}
        self.refuse_verification(self.archive(files=tampered, manifest_files=original))
        self.refuse_verification(self.archive(files={"daedalus.db": b"not sqlite"}))
        self.refuse_verification(self.archive(manifest=False))
        self.refuse_verification(valid, max_bytes=10)

    def test_refuses_occupied_destination_without_changing_it(self):
        destination = self.root / "occupied"
        destination.mkdir()
        marker = destination / "keep.txt"
        marker.write_text("existing data")
        self.refuse(self.archive(), destination=destination)
        self.assertEqual(marker.read_text(), "existing data")

    def test_refuses_corrupted_digest_and_unmanifested_file(self):
        original = {"daedalus.db": self.database_bytes, "reports/fixture.pdf": b"original"}
        changed = {**original, "reports/fixture.pdf": b"modified"}
        self.refuse(self.archive(files=changed, manifest_files=original))
        self.assertFalse((self.root / "restored").exists())
        self.refuse(self.archive(files={**original, "reports/extra.pdf": b"extra"}, manifest_files=original))

    def test_refuses_traversal_absolute_links_special_files_and_duplicate_names(self):
        for name in ("../escape", "/absolute", "reports/../../escape", "reports\\escape", "./reports/fixture"):
            with self.subTest(name=name):
                entry = tarfile.TarInfo(name)
                entry.type = tarfile.DIRTYPE
                self.refuse(self.archive(extra=entry))
        for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.FIFOTYPE, tarfile.CHRTYPE):
            with self.subTest(kind=kind):
                entry = tarfile.TarInfo("reports/linked")
                entry.type = kind
                entry.linkname = "../../escape"
                self.refuse(self.archive(extra=entry))
        duplicate = tarfile.TarInfo("reports/fixture.pdf")
        self.refuse(self.archive(extra=duplicate))
        self.assertFalse((self.root.parent / "escape").exists())

    def test_refuses_invalid_sqlite_missing_manifest_and_extracted_limit(self):
        self.refuse(self.archive(files={"daedalus.db": b"not a SQLite database"}))
        self.refuse(self.archive(manifest=False))
        self.refuse(self.archive(), max_bytes=10)

    def test_empty_destination_is_atomically_replaced_and_symlink_is_refused(self):
        destination = self.root / "empty"
        destination.mkdir()
        restored = restore_archive(self.archive(), destination)
        self.assertEqual(restored, destination.resolve())
        target = self.root / "target"
        target.mkdir()
        link = self.root / "link"
        link.symlink_to(target, target_is_directory=True)
        self.refuse(self.archive(), destination=link)
        self.assertEqual(list(target.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
