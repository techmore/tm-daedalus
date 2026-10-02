from __future__ import annotations

import hashlib
import io
import json
import tarfile
import tempfile
import unittest
from pathlib import Path

from scripts.package_digitalocean import (
    BundleError,
    build_bundle,
    extract_bundle,
    verify_bundle,
)


PROJECT_ROOT = Path(__file__).parents[1]


class DigitalOceanBundleTests(unittest.TestCase):
    def test_current_project_bundle_is_secret_free_deterministic_and_verifiable(self):
        with tempfile.TemporaryDirectory(prefix="daedalus-package-") as directory:
            first = Path(directory) / "first.tar.gz"
            second = Path(directory) / "second.tar.gz"
            build_bundle(PROJECT_ROOT, first)
            build_bundle(PROJECT_ROOT, second)
            self.assertEqual(first.read_bytes(), second.read_bytes())
            result = verify_bundle(first)
            self.assertTrue(result["manifest_verified"])
            self.assertGreater(result["file_count"], 20)
            with tarfile.open(first, "r:gz") as archive:
                names = archive.getnames()
            self.assertIn("daedalus/compose.yaml", names)
            self.assertIn("daedalus/DAEDALUS-PROJECT-REPORT.md", names)
            self.assertIn("daedalus/src/daedalus/server.py", names)
            self.assertIn("daedalus/src/daedalus/client_bundle/manifest.json", names)
            self.assertNotIn("daedalus/.env.production", names)
            self.assertFalse(any("/config.yaml" in name or "daedalus.db" in name or ".venv/" in name for name in names))

    def test_verify_rejects_modified_payload_and_extract_refuses_existing_destination(self):
        with tempfile.TemporaryDirectory(prefix="daedalus-package-") as directory:
            root = Path(directory)
            archive_path = root / "bundle.tar.gz"
            build_bundle(PROJECT_ROOT, archive_path)
            self.assertTrue(verify_bundle(archive_path)["manifest_verified"])
            destination = root / "release"
            extracted = extract_bundle(archive_path, destination)
            self.assertTrue((extracted / "compose.yaml").is_file())
            with self.assertRaises(BundleError):
                extract_bundle(archive_path, destination)

    def test_verify_rejects_path_traversal_even_with_a_matching_manifest(self):
        content = b"not a config"
        digest = hashlib.sha256(content).hexdigest()
        manifest = json.dumps({
            "format": 1,
            "project": "Daedalus",
            "files": [{"path": "../.env.production", "size_bytes": len(content), "sha256": digest}],
        }).encode()
        with tempfile.TemporaryDirectory(prefix="daedalus-malicious-package-") as directory:
            archive_path = Path(directory) / "unsafe.tar.gz"
            with tarfile.open(archive_path, "w:gz") as archive:
                for name, payload in (
                    ("daedalus/../.env.production", content),
                    ("daedalus/MANIFEST.json", manifest),
                ):
                    info = tarfile.TarInfo(name)
                    info.size = len(payload)
                    archive.addfile(info, io.BytesIO(payload))
            with self.assertRaises(BundleError):
                verify_bundle(archive_path)

    def test_build_never_follows_private_data_outside_allowlist(self):
        with tempfile.TemporaryDirectory(prefix="daedalus-package-fixture-") as directory:
            root = Path(directory)
            for name in (
                ".dockerignore", "Caddyfile", "DAEDALUS-PROJECT-REPORT.md", "Dockerfile", "INCUS-DEPLOYMENT.md", "README.md", "PROJECT-STATUS.md",
                "CIS-MACOS26-ALIGNMENT.md", "INTEGRATION-READINESS.md",
                "REMOTE-MANAGEMENT-ALIGNMENT.md", "compose.yaml", "pyproject.toml",
                "uv.lock", ".env.production.example",
            ):
                (root / name).write_text("fixture", encoding="utf-8")
            (root / "scripts").mkdir()
            for name in ("__init__.py", "backup_data.py", "backup_digitalocean.sh", "backup_incus.sh", "check_production_env.py", "check_public_deployment.py", "deploy_digitalocean.sh", "package_digitalocean.py", "restore_data.py", "wait_deployment.py"):
                (root / "scripts" / name).write_text("fixture", encoding="utf-8")
            source = root / "src" / "daedalus"
            source.mkdir(parents=True)
            (source / "server.py").write_text("server", encoding="utf-8")
            (source / "config.yaml").write_text("secret", encoding="utf-8")
            (root / ".env.production").write_text("secret", encoding="utf-8")
            (root / "data").mkdir()
            (root / "data" / "daedalus.db").write_bytes(b"private")
            archive_path = root / "bundle.tar.gz"
            build_bundle(root, archive_path)
            with tarfile.open(archive_path, "r:gz") as archive:
                names = archive.getnames()
            self.assertIn("daedalus/src/daedalus/server.py", names)
            self.assertNotIn("daedalus/src/daedalus/config.yaml", names)
            self.assertNotIn("daedalus/.env.production", names)
            self.assertFalse(any("daedalus.db" in name for name in names))


if __name__ == "__main__":
    unittest.main()
