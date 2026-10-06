import io
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
import zipfile
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from daedalus.db import Base, get_db
from daedalus.models import (
    Agent,
    AuditLog,
    CISAPIKey,
    CISDevice,
    ExternalCheckRun,
    ExternalCheckSchedule,
    Membership,
    Organization,
    ReportJob,
    User,
)
from daedalus import server
from daedalus.cis import CISDataError, validate_report_target_os


class CISReportPDFFlowTests(unittest.TestCase):
    def test_pdf_without_recorded_changes_does_not_claim_unchanged_settings(self):
        from daedalus import reports
        with patch.object(reports, "_paragraph", wraps=reports._paragraph) as paragraphs:
            data = reports.build_cis_endpoint_pdf({"domain":"example.test","cis":{"changes":[]}})
        self.assertTrue(data.startswith(b"%PDF"))
        text = " ".join(str(call.args[0]) for call in paragraphs.call_args_list)
        self.assertIn("does not establish that settings were unchanged", text)
        self.assertNotIn("No check status changes were detected since the previous report", text)

    def test_cis_profile_report_requires_matching_target_os_major_version(self):
        profile = server.load_macos26_starter_profiles()[0]
        for os_version in ("macOS 26.0.1", "26.4"):
            with self.subTest(os_version=os_version):
                validate_report_target_os({"os_version": os_version}, profile)
        for os_version in ("macOS 15", "", "unknown"):
            with self.subTest(os_version=os_version):
                with self.assertRaises(CISDataError):
                    validate_report_target_os({"os_version": os_version}, profile)

    def test_demo_cis_client_download_requires_workspace_login(self):
        self.client.cookies.clear()
        self.assertEqual(self.client.get("/api/cis/client-package/download").status_code, 401)

    def test_demo_cis_client_download_is_verified_audited_and_disabled_in_production(self):
        package_dir = self.root / "client_bundle"
        package_dir.mkdir()
        contents_buffer = io.BytesIO()
        with zipfile.ZipFile(contents_buffer, "w", compression=zipfile.ZIP_DEFLATED) as package:
            package.writestr("CSP-CIS_Audit.app/Contents/Info.plist", "fixture package")
        contents = contents_buffer.getvalue()
        filename = "CSP-CIS_Audit-local-unsigned.zip"
        (package_dir / filename).write_bytes(contents)
        (package_dir / "manifest.json").write_text(json.dumps({
            "filename": filename,
            "sha256": hashlib.sha256(contents).hexdigest(),
            "architecture": "arm64",
            "signing": "unsigned",
            "build": "test-fixture",
        }))
        with patch.object(server, "PACKAGE_DIR", self.root):
            response = self.client.get("/api/cis/client-package/download")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["cache-control"], "no-store")
        self.assertEqual(response.headers["x-content-sha256"], hashlib.sha256(response.content).hexdigest())
        with zipfile.ZipFile(io.BytesIO(response.content)) as package:
            self.assertIsNone(package.testzip())
            self.assertFalse(any(Path(name).name.lower() in {"config.yaml", "cis-client.yaml", "cis-client.yml"} for name in package.namelist()))
        with self.session_factory() as db:
            self.assertIsNotNone(db.scalar(select(AuditLog).where(AuditLog.action == "cis.client_package.downloaded")))
        with patch.object(server, "APP_ENV", "production"):
            self.assertEqual(self.client.get("/api/cis/client-package/download").status_code, 404)
        with patch.object(server, "DEMO_MODE", False):
            self.assertEqual(self.client.get("/api/cis/client-package/download").status_code, 404)

    def test_demo_cis_client_refuses_corrupt_package_without_download_audit(self):
        package_dir = self.root / "client_bundle"
        package_dir.mkdir()
        (package_dir / "manifest.json").write_text(json.dumps({"filename": "CSP-CIS_Audit-local-unsigned.zip", "sha256": "wrong", "architecture": "arm64", "signing": "unsigned"}))
        (package_dir / "CSP-CIS_Audit-local-unsigned.zip").write_bytes(b"corrupt")
        with patch.object(server, "PACKAGE_DIR", self.root):
            self.assertEqual(self.client.get("/api/cis/client-package/download").status_code, 503)
        with self.session_factory() as db:
            self.assertIsNone(db.scalar(select(AuditLog).where(AuditLog.action == "cis.client_package.downloaded")))

    def test_extracted_scanner_kit_imports_its_runtime_dependencies(self):
        with tempfile.TemporaryDirectory(prefix="daedalus-kit-import-") as directory:
            root = Path(directory)
            with zipfile.ZipFile(io.BytesIO(server.build_agent_bundle())) as bundle:
                for name in bundle.namelist():
                    if name.startswith("daedalus-scanner-kit/src/"):
                        bundle.extract(name, root)
            source = root / "daedalus-scanner-kit" / "src"
            result = subprocess.run(
                [sys.executable, "-c", "import pathlib,daedalus.agent,daedalus.command_journal; print(pathlib.Path(daedalus.agent.__file__).resolve())"],
                env={**os.environ, "PYTHONPATH": str(source)}, cwd=root,
                capture_output=True, text=True, timeout=15,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.strip(), str((source / "daedalus" / "agent.py").resolve()))

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory(prefix="daedalus-cis-flow-")
        self.root = Path(self.temp_dir.name)
        self.engine = create_engine(
            f"sqlite:///{self.root / 'test.db'}",
            connect_args={"check_same_thread": False},
        )
        Base.metadata.create_all(self.engine)
        self.session_factory = sessionmaker(
            bind=self.engine,
            autoflush=False,
            expire_on_commit=False,
        )

        def override_get_db():
            db = self.session_factory()
            try:
                yield db
            finally:
                db.close()

        self.dependency_overrides = server.app.dependency_overrides.copy()
        server.app.dependency_overrides[get_db] = override_get_db
        self.session_local_patch = patch.object(server, "SessionLocal", self.session_factory)
        self.reports_dir_patch = patch.object(server, "REPORTS_DIR", self.root / "reports")
        self.data_dir_patch = patch.object(server, "DATA_DIR", self.root / "data")
        self.session_local_patch.start()
        self.reports_dir_patch.start()
        self.data_dir_patch.start()
        server.seed_demo_workspace()
        self.client = TestClient(server.app)
        login = self.client.post("/dev/login", follow_redirects=False)
        self.assertEqual(login.status_code, 303)

    def tearDown(self):
        self.client.close()
        server.app.dependency_overrides.clear()
        server.app.dependency_overrides.update(self.dependency_overrides)
        self.reports_dir_patch.stop()
        self.data_dir_patch.stop()
        self.session_local_patch.stop()
        self.engine.dispose()
        self.temp_dir.cleanup()

    def test_migrated_pdf_download_uses_current_workspace_storage(self):
        with self.session_factory() as db:
            org = db.scalar(select(Organization))
            now = server.utcnow()
            job = ReportJob(organization_id=org.id, report_type="external_posture", domain=org.domain,
                status="completed", progress=100, stage="Completed", file_name="migration.pdf",
                artifact_path="/old-machine/reports/1/migration.pdf", size_bytes=12,
                report_snapshot={}, created_at=now, updated_at=now, completed_at=now)
            db.add(job); db.commit(); report_id = job.id; org_id = org.id
        directory = self.root / "reports" / str(org_id)
        directory.mkdir(parents=True, exist_ok=True)
        artifact = directory / "migration.pdf"; artifact.write_bytes(b"%PDF-fixture")
        response = self.client.get(f"/api/reports/{report_id}/download")
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.content, b"%PDF-fixture")
        self.assertEqual(response.headers["cache-control"], "no-store")
        artifact.unlink()
        other = self.root / "reports" / str(org_id + 1)
        other.mkdir(); (other / "migration.pdf").write_bytes(b"other-workspace")
        artifact.symlink_to(other / "migration.pdf")
        self.assertEqual(self.client.get(f"/api/reports/{report_id}/download").status_code, 404)

    def test_dashboard_route_supports_direct_reload_of_a_selected_tab(self):
        response = self.client.get("/dashboard")

        self.assertEqual(response.status_code, 200)
        self.assertIn('id="tab-meraki"', response.text)
        self.assertIn('id="tab-dns"', response.text)
        self.assertIn('id="tab-notifications"', response.text)
        self.assertIn('id="notification-badge"', response.text)
        self.assertIn('data-organization-slug="csp"', response.text)
        self.assertIn('href="/api/agents/bridge/download"', response.text)
        self.assertIn('id="enrollment-platform"', response.text)
        self.assertIn("Download NmapUI + Daedalus kit", response.text)
        self.assertIn('id="enrollment-scanner-name"', response.text)
        self.assertIn('id="enrollment-network-scopes"', response.text)
        self.assertIn("dashboard.js?v=daedalus-20261006-122", response.text)
        self.assertIn('data-load-older-checks="dns"', response.text)
        self.assertIn('data-load-older-checks="web"', response.text)
        self.assertIn('data-load-older-active="changes"', response.text)
        self.assertIn('id="cis-install-macos26"', response.text)
        self.assertIn('id="cis-device-list"', response.text)
        self.assertIn('src="/static/js/dashboard.js?', response.text)

        script = self.client.get("/static/js/dashboard.js")
        self.assertEqual(script.status_code, 200)
        self.assertIn('window.location.hash.replace(/^#/, "")', script.text)
        self.assertIn("activateTab(tabFromLocation(), false);", script.text)
        self.assertIn('install-service-macos.sh', script.text)
        self.assertIn('install-service-linux.sh', script.text)
        self.assertIn('enrollmentPlatform.value', script.text)
        self.assertIn('var selectedPlatform = document.getElementById("enrollment-platform").value', script.text)
        self.assertIn('restart_nmapui', script.text)
        self.assertIn('skip_host_discovery: action === "start_scan"', script.text)
        self.assertIn('scan-skip-discovery', script.text)
        self.assertIn('data-save-scanner-scope', script.text)
        self.assertIn('/network-scope', script.text)
        self.assertIn('authorized_networks: authorizedNetworks', script.text)
        self.assertIn('var preserveScannerEdit = agentList.contains(activeScannerField)', script.text)
        self.assertNotIn("window.confirm(", script.text)
        self.assertIn("function requestInlineConfirmation", script.text)
        self.assertIn("className = \"inline-confirmation\"", script.text)
        self.assertIn('button.setAttribute("aria-controls", panel.id)', script.text)
        self.assertIn('data-membership-revoke', script.text)
        self.assertIn('/revoke', script.text)
        self.assertIn('profiles_endpoint: ', script.text)

    def test_scanner_kit_download_is_workspace_admin_only_and_secret_free(self):
        enrollment = self.client.post("/api/enrollment-tokens")
        self.assertEqual(enrollment.status_code, 200, enrollment.text)
        one_time_code = enrollment.json()["code"]

        response = self.client.get("/api/agents/bridge/download")
        self.assertEqual(response.status_code, 200, response.text[:300])
        self.assertEqual(response.headers["content-type"], "application/zip")
        self.assertIn("no-store", response.headers["cache-control"])
        self.assertIn("daedalus-scanner-kit.zip", response.headers["content-disposition"])

        with zipfile.ZipFile(io.BytesIO(response.content)) as bundle:
            names = set(bundle.namelist())
            prefix = "daedalus-scanner-kit/"
            expected = {
                prefix + "README.md",
                prefix + "install.sh",
                prefix + "install-nmapui.sh",
                prefix + "install-service-macos.sh",
                prefix + "manage-service-macos.sh",
                prefix + "install-service-linux.sh",
                prefix + "manage-service-linux.sh",
                prefix + "macos_service.py",
                prefix + "ScannerStatus.swift",
                prefix + "install-status-macos.sh",
                prefix + "systemd_service.py",
                prefix + "upgrade_service.py",
                prefix + "linux_upgrade.py",
                prefix + "nmapui-source.zip",
                prefix + "pyproject.toml",
                prefix + "src/daedalus/__init__.py",
                prefix + "src/daedalus/agent.py",
                prefix + "src/daedalus/command_journal.py",
            }
            self.assertEqual(names, expected)
            project = bundle.read(prefix + "pyproject.toml").decode()
            install_script = bundle.read(prefix + "install.sh").decode()
            install_nmapui_script = bundle.read(prefix + "install-nmapui.sh").decode()
            install_service_script = bundle.read(prefix + "install-service-macos.sh").decode()
            install_linux_service_script = bundle.read(prefix + "install-service-linux.sh").decode()
            manage_linux_service_script = bundle.read(prefix + "manage-service-linux.sh").decode()
            systemd_service = bundle.read(prefix + "systemd_service.py").decode()
            macos_service = bundle.read(prefix + "macos_service.py").decode()
            agent = bundle.read(prefix + "src/daedalus/agent.py").decode()
            readme = bundle.read(prefix + "README.md").decode()
            contents = "\n".join(
                bundle.read(name).decode(errors="replace")
                for name in names
                if name != prefix + "nmapui-source.zip"
            )
            source_bytes = bundle.read(prefix + "nmapui-source.zip")
        with zipfile.ZipFile(io.BytesIO(source_bytes)) as source_bundle:
            source_names = set(source_bundle.namelist())
            source_prefix = "daedalus-nmapui-source/"
            source_manifest = json.loads(
                source_bundle.read(source_prefix + "manifest.json")
            )
            source_digest = hashlib.sha256()
            for name in sorted(source_names - {source_prefix + "manifest.json"}):
                relative_name = name.removeprefix(source_prefix)
                source_digest.update(relative_name.encode("utf-8"))
                source_digest.update(b"\0")
                source_digest.update(source_bundle.read(name))
                source_digest.update(b"\0")
        self.assertIn('version = "0.1.0"', project)
        self.assertNotIn("__DAEDALUS_VERSION__", project)
        self.assertIn("daedalus-agent", install_script)
        self.assertIn("--enroll-only", install_service_script)
        self.assertIn("launchctl bootstrap", install_service_script)
        self.assertIn("systemctl --user enable --now", install_linux_service_script)
        self.assertIn("systemd_service.py", manage_linux_service_script)
        self.assertIn("NoNewPrivileges=true", systemd_service)
        self.assertIn("PrivateTmp=true", systemd_service)
        self.assertIn("org.daedalus.nmapui", macos_service)
        self.assertIn('"restart_nmapui"', agent)
        self.assertIn('"/bin/launchctl", "kickstart", "-k"', agent)
        self.assertIn("NmapUI", readme)
        self.assertIn("loopback", install_nmapui_script)
        self.assertIn(source_prefix + "app.py", source_names)
        self.assertIn(source_prefix + "nmapui/app_composition.py", source_names)
        self.assertIn(source_prefix + "templates/index.html", source_names)
        self.assertIn(source_prefix + "static/css/tailwind.css", source_names)
        self.assertNotIn(source_prefix + "config/customers.yaml", source_names)
        self.assertFalse(any("/data/" in name or "/node_modules/" in name for name in source_names))
        self.assertFalse(any(name.endswith("/.env") or "/.env." in name for name in source_names))
        self.assertEqual(source_manifest["source_tree_sha256"], source_digest.hexdigest())
        self.assertNotIn(one_time_code, contents)
        self.assertNotIn(one_time_code.encode(), response.content)

        with self.session_factory() as db:
            audit_entry = db.scalar(
                select(AuditLog).where(
                    AuditLog.action == "scanner.bridge_bundle_downloaded"
                )
            )
        self.assertIsNotNone(audit_entry)
        self.assertEqual(audit_entry.details["nmapui_version"], source_manifest["version"])
        self.assertEqual(
            audit_entry.details["bundle_sha256"],
            hashlib.sha256(response.content).hexdigest(),
        )

        with self.session_factory() as db:
            admin = db.scalar(
                select(User).where(User.google_subject == "daedalus-local-demo-admin")
            )
            membership = db.scalar(
                select(Membership).where(Membership.user_id == admin.id)
            )
            membership.role = "user"
            db.commit()
        forbidden = self.client.get("/api/agents/bridge/download")
        self.assertEqual(forbidden.status_code, 403)

    def test_cis_client_profile_catalog_requires_workspace_key(self):
        key_response = self.client.post("/api/cis/api-key")
        self.assertEqual(key_response.status_code, 200, key_response.text)
        api_key = key_response.json()["api_key"]
        profile = server.load_starter_profile()
        published = self.client.post("/api/cis/profiles", json=profile)
        self.assertEqual(published.status_code, 200, published.text)

        unauthorized = self.client.get("/api/cis/client/profiles")
        self.assertEqual(unauthorized.status_code, 401)
        catalog = self.client.get(
            "/api/cis/client/profiles",
            headers={"X-API-Key": api_key},
        )
        self.assertEqual(catalog.status_code, 200, catalog.text)
        body = catalog.json()
        self.assertEqual(body["domain"], "cybersecuritypilot.org")
        self.assertEqual(len(body["profiles"]), 1)
        self.assertEqual(body["profiles"][0]["slug"], profile["slug"])
        self.assertEqual(body["profiles"][0]["version"], profile["version"])
        self.assertEqual(body["profiles"][0]["checks"], profile["checks"])

    def test_macos26_revision_publication_preserves_old_versions(self):
        from copy import deepcopy
        old_profiles = deepcopy(server.load_macos26_starter_profiles())
        for profile in old_profiles:
            profile["version"] = "1.1.0"
            profile["description"] = "Previously published fixture description"
        with patch.object(server, "load_macos26_starter_profiles", return_value=old_profiles):
            old = self.client.post("/api/cis/profiles/install-macos26").json()["profiles"]
        old_downloads = {profile["download_url"]: self.client.get(profile["download_url"]).json() for profile in old}
        revised = self.client.post("/api/cis/profiles/install-macos26")
        self.assertEqual(revised.status_code, 200, revised.text)
        self.assertEqual(revised.json()["installed_count"], 2)
        self.assertEqual({profile["version"] for profile in revised.json()["profiles"]}, {"1.1.0-r2"})
        for url, content in old_downloads.items():
            self.assertEqual(self.client.get(url).json(), content)

    def test_macos26_level_profiles_install_as_immutable_client_profiles(self):
        installed = self.client.post("/api/cis/profiles/install-macos26")
        self.assertEqual(installed.status_code, 200, installed.text)
        body = installed.json()
        self.assertEqual(body["installed_count"], 2)
        self.assertEqual(
            {profile["benchmark"]["level"] for profile in body["profiles"]},
            {"1", "2"},
        )
        self.assertEqual(
            {profile["check_count"] for profile in body["profiles"]},
            {100, 119},
        )
        self.assertTrue(all(profile["yaml_download_url"] is None for profile in body["profiles"]))
        level_one_download = next(
            profile["download_url"] for profile in body["profiles"]
            if profile["benchmark"]["level"] == "1"
        )
        self.assertEqual(
            self.client.get(level_one_download + "?format=checklist-yaml").status_code,
            409,
        )

        repeated = self.client.post("/api/cis/profiles/install-macos26")
        self.assertEqual(repeated.status_code, 200, repeated.text)
        self.assertEqual(repeated.json()["installed_count"], 0)
        self.assertEqual(len(repeated.json()["already_present"]), 2)

        key_response = self.client.post("/api/cis/api-key")
        catalog = self.client.get(
            "/api/cis/client/profiles",
            headers={"X-API-Key": key_response.json()["api_key"]},
        )
        self.assertEqual(catalog.status_code, 200, catalog.text)
        profiles = catalog.json()["profiles"]
        self.assertEqual({profile["benchmark"]["level"] for profile in profiles}, {"1", "2"})
        level_one = next(profile for profile in profiles if profile["benchmark"]["level"] == "1")
        self.assertEqual(level_one["checks"][0]["rule_id"], level_one["checks"][0]["id"])
        self.assertIn("benchmark_ids", level_one["checks"][0])

    def create_scanner(self):
        now = server.utcnow()
        with self.session_factory() as db:
            organization = db.scalar(
                select(Organization).where(Organization.slug == "csp")
            )
            admin = db.scalar(
                select(User).where(User.google_subject == "daedalus-local-demo-admin")
            )
            agent = Agent(
                organization_id=organization.id,
                name="Test Mac scanner",
                authorized_networks=["127.0.0.1/32", "192.168.1.0/24"],
                token_hash=server.token_digest("test-scanner-token"),
                enabled=True,
                nmapui_connected=False,
                created_at=now,
            )
            db.add(agent)
            db.commit()
            db.refresh(agent)
            return agent.id, admin.id

    def test_cis_profiles_history_and_retries_preserve_evidence(self):
        profile = {
            "name": "Fixture profile", "slug": "fixture", "version": "1",
            "platform": "macos", "checks": [
                {"id": "check_one", "category": "macos", "description": "Published title"},
                {"id": "check_two", "category": "macos", "description": "Second check"},
            ],
        }
        self.assertEqual(self.client.post("/api/cis/profiles", json=profile).status_code, 200)
        key = self.client.post("/api/cis/api-key").json()["api_key"]
        headers = {"X-API-Key": key}
        payload = {
            "device_uuid": "fixture-device", "report_id": "run-1",
            "timestamp": "2026-09-28T12:00:00Z",
            "profile_slug": "fixture", "profile_version": "1",
            "system_info": {"hostname": "Old name", "os_version": "26.0"},
            "results": [{**check, "status": "pass"} for check in profile["checks"]],
        }
        unknown = self.client.post("/api/cis/report", headers=headers, json={**payload, "profile_version": "unknown"})
        self.assertEqual(unknown.status_code, 422)
        partial = self.client.post("/api/cis/report", headers=headers, json={**payload, "results": payload["results"][:1]})
        self.assertEqual(partial.status_code, 422)
        wrong_category = self.client.post("/api/cis/report", headers=headers, json={
            **payload, "results": [{**row, "category": "safari"} for row in payload["results"]],
        })
        self.assertEqual(wrong_category.status_code, 422)
        first = self.client.post("/api/cis/report", headers=headers, json=payload)
        self.assertEqual(first.status_code, 200, first.text)
        first_id = first.json()["report_id"]
        duplicate = self.client.post("/api/cis/report", headers=headers, json=payload)
        self.assertTrue(duplicate.json()["duplicate"])
        conflict = self.client.post("/api/cis/report", headers=headers, json={
            **payload, "results": [{**check, "status": "fail"} for check in profile["checks"]],
        })
        self.assertEqual(conflict.status_code, 409)
        different_device = self.client.post("/api/cis/report", headers=headers, json={**payload, "device_uuid": "other-device"})
        self.assertFalse(different_device.json()["duplicate"])

        changed = {**payload, "report_id": "run-2", "timestamp": "2026-09-29T12:00:00Z",
                   "system_info": {"hostname": "New name", "os_version": "26.1"},
                   "results": [{**check, "status": "fail", "description": "Untrusted title"} for check in profile["checks"]]}
        second = self.client.post("/api/cis/report", headers=headers, json=changed)
        self.assertEqual(second.json()["changed_check_count"], 2)
        detail = self.client.get(f"/api/cis/reports/{first_id}").json()
        self.assertEqual(detail["device_name"], "Old name")
        self.assertEqual(detail["os_version"], "26.0")
        second_detail = self.client.get(f"/api/cis/reports/{second.json()['report_id']}").json()
        self.assertEqual(second_detail["results"][0]["description"], "Published title")
        self.assertEqual(len(second_detail["summary"]["profile_checksum"]), 64)
        self.assertTrue(second_detail["summary"]["profile_verified"])
        late = self.client.post("/api/cis/report", headers=headers, json={**payload, "report_id": "late", "timestamp": "2026-09-28T15:00:00Z"})
        self.assertEqual(late.json()["changed_check_count"], 0)
        self.assertEqual(next(d for d in self.client.get("/api/cis/status").json()["devices"] if d["name"] == "New name")["os_version"], "26.1")

        version_two = {**profile, "version": "2"}
        self.assertEqual(self.client.post("/api/cis/profiles", json=version_two).status_code, 200)
        new_profile = self.client.post("/api/cis/report", headers=headers, json={**payload, "report_id": "run-3", "timestamp": "2026-09-29T13:00:00Z", "profile_version": "2"})
        self.assertEqual(new_profile.json()["changed_check_count"], 0)
        with patch.object(server, "generate_report_job"):
            pdf = self.client.post(f"/api/cis/reports/{first_id}/pdf")
        with self.session_factory() as db:
            snapshot = db.get(ReportJob, pdf.json()["id"]).report_snapshot["cis"]
            self.assertEqual(snapshot["device_name"], "Old name")
            self.assertEqual(snapshot["os_version"], "26.0")

    def test_scanner_heartbeat_reports_health_version_and_platform(self):
        agent_id, _admin_id = self.create_scanner()
        heartbeat = self.client.post(
            f"/api/agents/{agent_id}/heartbeat",
            headers={"Authorization": "Bearer test-scanner-token"},
            json={
                "nmapui_connected": True,
                "version": "Daedalus bridge 0.1.0",
                "platform": "macOS",
                "nmapui_version": "v2026.3.14.00_10",
                "nmapui_ready": True,
                "nmapui_restart_supported": True,
            },
        )

        self.assertEqual(heartbeat.status_code, 200, heartbeat.text)
        dashboard = self.client.get("/api/dashboard").json()
        scanner = next(row for row in dashboard["agents"] if row["id"] == agent_id)
        self.assertEqual(scanner["status"], "online")
        self.assertEqual(scanner["platform"], "macOS")
        self.assertEqual(scanner["bridge_version"], "Daedalus bridge 0.1.0")
        self.assertEqual(scanner["nmapui_version"], "v2026.3.14.00_10")
        self.assertIs(scanner["nmapui_ready"], True)
        self.assertIs(scanner["bridge_online"], True)
        self.assertIs(scanner["nmapui_restart_supported"], True)
        dashboard_page = self.client.get("/dashboard")
        self.assertEqual(dashboard_page.status_code, 200, dashboard_page.text[:500])
        self.assertIn("NmapUI v2026.3.14.00_10", dashboard_page.text)
        self.assertIn("NmapUI ready", dashboard_page.text)

    def test_scanner_event_replay_is_idempotent_and_preserves_collection_time(self):
        agent_id, _ = self.create_scanner()
        headers = {"Authorization": "Bearer test-scanner-token"}
        event = {
            "client_event_id": "b2fe24d8-914a-40eb-9feb-31259d0181dd",
            "occurred_at": "2026-09-28T12:00:00Z",
            "event_name": "scan_complete_summary", "payload": {"fixture_count": 1},
        }
        endpoint = f"/api/agents/{agent_id}/events"
        first = self.client.post(endpoint, headers=headers, json=event)
        self.assertEqual(first.status_code, 200, first.text)
        replay = self.client.post(endpoint, headers=headers, json=event)
        self.assertTrue(replay.json()["duplicate"])
        self.assertEqual(replay.json()["event_id"], first.json()["event_id"])
        conflict = self.client.post(endpoint, headers=headers, json={**event, "payload": {"fixture_count": 2}})
        self.assertEqual(conflict.status_code, 409)
        records = self.client.get("/api/events").json()["events"]
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["occurred_at"], event["occurred_at"])
        with self.session_factory() as db:
            self.assertIsNone(db.get(Agent, agent_id).last_seen_at)
        legacy = self.client.post(endpoint, headers=headers, json={"event_name": "scan_feedback", "payload": "fixture"})
        self.assertEqual(legacy.status_code, 200)

    def test_scanner_large_artifact_is_private_immutable_downloadable_and_bounded(self):
        agent_id, _ = self.create_scanner()
        headers = {"Authorization": "Bearer test-scanner-token"}
        payload = [{"address": "192.168.1.2", "hostname": "Fixture host", "padding": "x" * 600_000}]
        event = {"client_event_id": "ade0d772-adab-4d9c-af6e-e5e2cd9d6834", "occurred_at": "2026-09-28T12:00:00Z", "event_name": "deep_scan_results", "payload": payload}
        endpoint = f"/api/agents/{agent_id}/event-artifacts"
        denied = self.client.post(endpoint, json=event)
        self.assertEqual(denied.status_code, 401)
        first = self.client.post(endpoint, headers=headers, json=event)
        self.assertEqual(first.status_code, 200, first.text)
        event_id = first.json()["event_id"]
        duplicate = self.client.post(endpoint, headers=headers, json=event)
        self.assertTrue(duplicate.json()["duplicate"])
        conflicting = self.client.post(endpoint, headers=headers, json={**event, "payload": []})
        self.assertEqual(conflicting.status_code, 409)
        evidence = self.client.get("/api/events").json()["events"][0]
        self.assertNotIn("padding", str(evidence["payload"]))
        self.assertGreater(evidence["artifact_size_bytes"], 512_000)
        downloaded = self.client.get(evidence["artifact_download_url"])
        self.assertEqual(downloaded.status_code, 200, downloaded.text[:200])
        self.assertEqual(downloaded.json(), payload)
        self.assertEqual(hashlib.sha256(downloaded.content).hexdigest(), evidence["artifact_sha256"])
        self.assertEqual(downloaded.headers["cache-control"], "no-store")
        pdf = self.client.post(f"/api/agents/events/{event_id}/pdf")
        self.assertEqual(pdf.status_code, 422, pdf.text)
        self.assertIn("original Nmap XML", pdf.json()["detail"])
        with self.session_factory() as db:
            stored = db.get(server.ScanEvent, event_id)
            artifact = server.scanner_artifact_path(stored)
            self.assertEqual(artifact.stat().st_mode & 0o777, 0o600)
        too_large = self.client.post(endpoint, headers={**headers, "Content-Length": str(33 * 1024 * 1024)}, content=b"{}")
        self.assertEqual(too_large.status_code, 413)
        with patch.object(server, "MAX_SCANNER_ARTIFACT_BYTES", 100):
            streaming = self.client.post(endpoint, headers=headers, content=(block for block in [b'{"padding":"', b"x" * 101, b'"}']))
            self.assertEqual(streaming.status_code, 413)
        other = self.client.post("/api/workspaces", json={"name": "Other fixture", "domain": "other-fixture.example"})
        self.assertEqual(other.status_code, 200)
        hidden = self.client.get(evidence["artifact_download_url"])
        self.assertEqual(hidden.status_code, 404)
        hidden_pdf = self.client.post(f"/api/agents/events/{event_id}/pdf")
        self.assertEqual(hidden_pdf.status_code, 404)

    def test_update_check_requires_online_scanner_and_stale_commands_expire(self):
        agent_id, _admin_id = self.create_scanner()
        headers = {"Authorization": "Bearer test-scanner-token"}
        payload = {"action": "check_nmapui_updates"}

        offline = self.client.post(f"/api/agents/{agent_id}/commands", json=payload)
        self.assertEqual(offline.status_code, 409)

        heartbeat = self.client.post(
            f"/api/agents/{agent_id}/heartbeat",
            headers=headers,
            json={"nmapui_connected": True},
        )
        self.assertEqual(heartbeat.status_code, 200, heartbeat.text)
        queued = self.client.post(f"/api/agents/{agent_id}/commands", json=payload)
        self.assertEqual(queued.status_code, 200, queued.text)
        command_id = queued.json()["id"]

        with self.session_factory() as db:
            command = db.get(server.AgentCommand, command_id)
            command.created_at = server.utcnow() - server.timedelta(minutes=6)
            db.commit()

        next_command = self.client.get(
            f"/api/agents/{agent_id}/commands/next", headers=headers
        )
        self.assertEqual(next_command.status_code, 200, next_command.text)
        self.assertIsNone(next_command.json()["command"])
        with self.session_factory() as db:
            self.assertEqual(db.get(server.AgentCommand, command_id).status, "expired")
        audit_actions = [row["action"] for row in self.client.get("/api/audit-log").json()["events"]]
        self.assertIn("scanner.command_queued", audit_actions)
        self.assertIn("scanner.command_expired", audit_actions)

    def test_managed_nmapui_restart_works_when_service_is_offline_and_is_audited(self):
        agent_id, _admin_id = self.create_scanner()
        headers = {"Authorization": "Bearer test-scanner-token"}
        payload = {"action": "restart_nmapui"}

        unsupported = self.client.post(f"/api/agents/{agent_id}/commands", json=payload)
        self.assertEqual(unsupported.status_code, 409)

        heartbeat = self.client.post(
            f"/api/agents/{agent_id}/heartbeat",
            headers=headers,
            json={"nmapui_connected": False, "nmapui_restart_supported": True},
        )
        self.assertEqual(heartbeat.status_code, 200, heartbeat.text)
        dashboard = self.client.get("/api/dashboard").json()
        scanner = next(row for row in dashboard["agents"] if row["id"] == agent_id)
        self.assertEqual(scanner["status"], "NmapUI offline")
        self.assertTrue(scanner["bridge_online"])

        with self.session_factory() as db:
            agent = db.get(Agent, agent_id)
            agent.last_seen_at = server.utcnow() - server.timedelta(seconds=60)
            db.commit()
        stale_bridge = self.client.post(f"/api/agents/{agent_id}/commands", json=payload)
        self.assertEqual(stale_bridge.status_code, 409)

        heartbeat = self.client.post(
            f"/api/agents/{agent_id}/heartbeat",
            headers=headers,
            json={"nmapui_connected": False, "nmapui_restart_supported": True},
        )
        self.assertEqual(heartbeat.status_code, 200, heartbeat.text)
        queued = self.client.post(f"/api/agents/{agent_id}/commands", json=payload)
        self.assertEqual(queued.status_code, 200, queued.text)
        command_id = queued.json()["id"]

        delivered = self.client.get(
            f"/api/agents/{agent_id}/commands/next", headers=headers
        )
        self.assertEqual(delivered.json()["command"]["id"], command_id)
        self.assertEqual(delivered.json()["command"]["action"], "restart_nmapui")
        result = self.client.post(
            f"/api/agents/{agent_id}/commands/{command_id}/result",
            headers=headers,
            json={"status": "accepted", "result": "restart requested"},
        )
        self.assertEqual(result.status_code, 200, result.text)
        with self.session_factory() as db:
            command = db.get(server.AgentCommand, command_id)
            self.assertEqual(command.status, "accepted")
            audit_actions = [row.action for row in db.scalars(select(AuditLog)).all()]
        self.assertIn("scanner.command_queued", audit_actions)
        self.assertIn("scanner.command_result_reported", audit_actions)

    def test_cis_report_pdf_request_progress_download_and_audit(self):
        profiles = self.client.post("/api/cis/profiles/install-macos26").json()["profiles"]
        level_one_slug = next(
            profile["slug"] for profile in profiles if profile["benchmark"]["level"] == "1"
        )
        key_response = self.client.post("/api/cis/api-key")
        self.assertEqual(key_response.status_code, 200, key_response.text)
        api_key = key_response.json()["api_key"]
        self.assertEqual(
            key_response.json()["profiles_endpoint"],
            server.BASE_URL + "/api/cis/client/profiles",
        )

        report_headers = {
            "X-API-Key": api_key,
            "X-Device-UUID": "TEST-PRIVATE-SERIAL-1234",
            "X-Report-ID": "TEST-PRIVATE-SERIAL-1234-run-001",
        }
        report_payload = {
            "api_key": api_key,
            "domain": "untrusted.invalid",
            "device_uuid": "TEST-PRIVATE-SERIAL-1234",
            "report_id": "TEST-PRIVATE-SERIAL-1234-run-001",
            "report_info": {
                "timestamp": "2026-09-29T12:00:00Z",
                "cis_benchmark_version": "1.0",
            },
            "profile_slug": level_one_slug,
            "profile_version": "1.1.0-r2",
            "system_info": {
                "hostname": "Demo Mac",
                "serial_number": "TEST-PRIVATE-SERIAL-1234",
                "os_version": "macOS 15",
                "ip_addresses": ["10.0.0.5"],
            },
            "results": [
                {**check, "status": "fail" if check["id"] == "system_settings_firewall_stealth_mode_enable" else "manual",
                 "details": "Fixture evidence"}
                for check in server.load_macos26_starter_profiles()[0]["checks"]
            ],
        }
        incompatible = self.client.post(
            "/api/cis/report", headers=report_headers, json=report_payload
        )
        self.assertEqual(incompatible.status_code, 422, incompatible.text)
        self.assertIn("OS major version", incompatible.json()["detail"])
        report_payload["system_info"]["os_version"] = "macOS 26.0.1"
        received = self.client.post(
            "/api/cis/report", headers=report_headers, json=report_payload
        )
        self.assertEqual(received.status_code, 200, received.text)
        cis_report_id = received.json()["report_id"]
        checkin = self.client.get("/api/cis/status").json()
        self.assertEqual(checkin["online_device_count"], 1)
        self.assertEqual(checkin["devices"][0]["state"], "online")
        with self.session_factory() as db:
            device = db.scalar(select(CISDevice))
            device.last_seen_at = server.utcnow() - timedelta(days=2)
            db.commit()
        offline = self.client.get("/api/cis/status").json()
        self.assertEqual(offline["offline_device_count"], 1)
        self.assertEqual(offline["devices"][0]["state"], "offline")

        requested = self.client.post(f"/api/cis/reports/{cis_report_id}/pdf")
        self.assertEqual(requested.status_code, 200, requested.text)
        job_id = requested.json()["id"]
        jobs = self.client.get("/api/reports").json()["reports"]
        job = next(row for row in jobs if row["id"] == job_id)
        self.assertEqual(job["report_type"], "cis_endpoint")
        self.assertEqual(job["status"], "completed")
        self.assertEqual(job["progress"], 100)

        downloaded = self.client.get(f"/api/reports/{job_id}/download")
        self.assertEqual(downloaded.status_code, 200, downloaded.text[:300])
        self.assertTrue(downloaded.content.startswith(b"%PDF-"))

        report_detail = self.client.get(f"/api/cis/reports/{cis_report_id}").json()
        self.assertNotIn("TEST-PRIVATE-SERIAL-1234", str(report_detail))
        self.assertNotIn("10.0.0.5", str(report_detail))
        self.assertEqual(report_detail["profile_slug"], level_one_slug)
        self.assertEqual(report_detail["profile_version"], "1.1.0-r2")
        firewall_result = next(
            row for row in report_detail["results"] if row["id"] == "system_settings_firewall_enable"
        )
        self.assertEqual(firewall_result["benchmark_ids"], ["2.2.1"])

        with self.session_factory() as db:
            stored_key = db.scalar(select(CISAPIKey))
            stored_job = db.get(ReportJob, job_id)
            self.assertNotEqual(stored_key.token_hash, api_key)
            self.assertNotIn(api_key, str(stored_job.report_snapshot))
            self.assertNotIn("TEST-PRIVATE-SERIAL-1234", str(stored_job.report_snapshot))
            self.assertEqual(stored_job.report_snapshot["cis"]["benchmark"]["level"], "1")

        audit = self.client.get("/api/audit-log").json()["events"]
        self.assertIn("report.requested", [row["action"] for row in audit])
        self.assertIn("report.generated", [row["action"] for row in audit])

    def test_dns_history_detects_changes_and_generates_saved_evidence_pdf(self):
        first_snapshot = {
            "domain": "cybersecuritypilot.org",
            "records": {
                "A": ["198.51.100.10"],
                "MX": ["10 mail.example.net."],
                "SPF": ["v=spf1 -all"],
                "DMARC": ["v=DMARC1; p=reject"],
                "DKIM": {"selector1": ["v=DKIM1; k=rsa; p=publickey"]},
            },
            "resolver_errors": {},
        }
        second_snapshot = {
            **first_snapshot,
            "records": {
                **first_snapshot["records"],
                "A": ["198.51.100.11"],
            },
        }
        with patch.object(
            server,
            "run_dns_check",
            side_effect=[first_snapshot, second_snapshot],
        ):
            first = self.client.post("/api/external-checks/dns/run")
            self.assertEqual(first.status_code, 200, first.text)
            self.assertEqual(first.json()["status"], "completed")
            self.assertEqual(first.json()["change_count"], 0)

            second = self.client.post("/api/external-checks/dns/run")
            self.assertEqual(second.status_code, 200, second.text)
            self.assertEqual(second.json()["status"], "completed")
            self.assertEqual(second.json()["change_count"], 1)
            self.assertEqual(second.json()["changed_fields"], ["records.A"])

        history = self.client.get("/api/external-checks/dns")
        self.assertEqual(history.status_code, 200, history.text)
        self.assertEqual(len(history.json()["runs"]), 2)
        self.assertEqual(history.json()["changes"][0]["previous_value"], ["198.51.100.10"])
        self.assertEqual(history.json()["changes"][0]["current_value"], ["198.51.100.11"])
        assessment = history.json()["latest_snapshot"]["email_authentication_assessment"]
        self.assertEqual(assessment["spf"]["policy"], "hard_fail")
        self.assertEqual(assessment["dmarc"]["effective_policy"], "reject")
        with self.session_factory() as db:
            saved_runs = db.scalars(select(ExternalCheckRun).order_by(ExternalCheckRun.id)).all()
            self.assertNotIn("email_authentication_assessment", saved_runs[0].snapshot)

        requested = self.client.post("/api/reports/external-posture")
        self.assertEqual(requested.status_code, 200, requested.text)
        job_id = requested.json()["id"]
        jobs = self.client.get("/api/reports").json()["reports"]
        job = next(row for row in jobs if row["id"] == job_id)
        self.assertEqual(job["status"], "completed")
        self.assertEqual(job["progress"], 100)
        downloaded = self.client.get(f"/api/reports/{job_id}/download")
        self.assertEqual(downloaded.status_code, 200, downloaded.text[:300])
        self.assertTrue(downloaded.content.startswith(b"%PDF-"))
        with self.session_factory() as db:
            report_job = db.get(ReportJob, job_id)
            report_assessment = report_job.report_snapshot["checks"]["dns"]["run"]["snapshot"]["email_authentication_assessment"]
            self.assertEqual(report_assessment["dmarc"]["policy"], "reject")

    def test_external_check_schedules_are_admin_controlled_and_verified_only(self):
        initial = self.client.get("/api/external-checks/dns")
        self.assertEqual(initial.status_code, 200, initial.text)
        self.assertFalse(initial.json()["schedule"]["enabled"])

        enabled = self.client.put(
            "/api/external-checks/dns/schedule",
            json={"enabled": True, "interval_hours": 24},
        )
        self.assertEqual(enabled.status_code, 200, enabled.text)
        self.assertTrue(enabled.json()["enabled"])
        self.assertEqual(enabled.json()["interval_hours"], 24)
        self.assertIsNotNone(enabled.json()["next_run_at"])

        with self.session_factory() as db:
            organization = db.scalar(
                select(Organization).where(Organization.slug == "csp")
            )
            organization.verification_status = "pending"
            db.commit()
        denied = self.client.put(
            "/api/external-checks/web/schedule",
            json={"enabled": True, "interval_hours": 168},
        )
        self.assertEqual(denied.status_code, 403, denied.text)

        disabled = self.client.put(
            "/api/external-checks/dns/schedule",
            json={"enabled": False, "interval_hours": 24},
        )
        self.assertEqual(disabled.status_code, 200, disabled.text)
        self.assertFalse(disabled.json()["enabled"])
        self.assertIsNone(disabled.json()["next_run_at"])

        audit_actions = self.client.get("/api/audit-log").json()["events"]
        self.assertIn("external_check.schedule_updated", [row["action"] for row in audit_actions])

    def test_due_schedule_claim_is_atomic_and_scheduled_runs_enter_shared_history(self):
        enabled = self.client.put(
            "/api/external-checks/dns/schedule",
            json={"enabled": True, "interval_hours": 24},
        )
        self.assertEqual(enabled.status_code, 200, enabled.text)
        with self.session_factory() as db:
            schedule = db.scalar(select(ExternalCheckSchedule))
            schedule.next_run_at = server.utcnow()
            db.commit()

        claimed = server.claim_due_external_check_schedules()
        self.assertEqual(len(claimed), 1)
        self.assertEqual(claimed[0]["check_type"], "dns")
        self.assertEqual(server.claim_due_external_check_schedules(), [])

        snapshot = {
            "domain": "cybersecuritypilot.org",
            "records": {"A": ["198.51.100.20"]},
            "resolver_errors": {},
        }
        organization_id = claimed[0]["organization_id"]
        with patch.object(server, "run_dns_check", return_value=snapshot):
            result = server.execute_external_check(
                organization_id,
                None,
                "dns",
                "schedule",
            )
        server.finish_external_check_schedule(claimed[0]["schedule_id"], result["status"])
        self.assertEqual(result["source"], "schedule")
        self.assertEqual(result["actor"], "Scheduled check")
        self.assertEqual(result["status"], "completed")

        with self.session_factory() as db:
            run = db.get(ExternalCheckRun, result["id"])
            self.assertEqual(run.trigger_source, "schedule")
            schedule = db.get(ExternalCheckSchedule, claimed[0]["schedule_id"])
            self.assertEqual(schedule.last_run_status, "completed")
            completed = db.scalar(
                select(AuditLog).where(
                    AuditLog.organization_id == organization_id,
                    AuditLog.action == "external_check.completed",
                ).order_by(AuditLog.id.desc())
            )
            self.assertIsNone(completed.actor_user_id)
            self.assertEqual(completed.details["source"], "schedule")

        history = self.client.get("/api/external-checks/dns").json()
        latest = next(row for row in history["runs"] if row["id"] == result["id"])
        self.assertEqual(latest["actor"], "Scheduled check")

    def test_schedule_recovery_requeues_claim_when_process_stopped_before_run_creation(self):
        enabled = self.client.put(
            "/api/external-checks/dns/schedule",
            json={"enabled": True, "interval_hours": 24},
        )
        self.assertEqual(enabled.status_code, 200, enabled.text)
        with self.session_factory() as db:
            schedule = db.scalar(select(ExternalCheckSchedule))
            schedule.next_run_at = server.utcnow() - timedelta(minutes=1)
            db.commit()

        claimed = server.claim_due_external_check_schedules()
        self.assertEqual(len(claimed), 1)
        self.assertEqual(server.recover_interrupted_external_check_schedules(), 1)
        with self.session_factory() as db:
            schedule = db.get(ExternalCheckSchedule, claimed[0]["schedule_id"])
            self.assertEqual(schedule.last_run_status, "failed")
            self.assertLessEqual(schedule.next_run_at, server.utcnow())
            self.assertIsNotNone(schedule.last_completed_at)
            self.assertIsNone(db.scalar(select(ExternalCheckRun)))
            event = db.scalar(
                select(AuditLog).where(
                    AuditLog.action == "external_check.schedule_recovered"
                )
            )
            self.assertEqual(event.details["outcome"], "claim_requeued")
        # The normal claim path can immediately take the recovered schedule.
        self.assertEqual(len(server.claim_due_external_check_schedules()), 1)

    def test_schedule_recovery_reconciles_saved_run_without_duplicate_retry(self):
        enabled = self.client.put(
            "/api/external-checks/dns/schedule",
            json={"enabled": True, "interval_hours": 24},
        )
        self.assertEqual(enabled.status_code, 200, enabled.text)
        with self.session_factory() as db:
            schedule = db.scalar(select(ExternalCheckSchedule))
            schedule.last_started_at = server.utcnow() - timedelta(seconds=3)
            schedule.last_run_status = "running"
            schedule.next_run_at = server.utcnow() + timedelta(hours=24)
            organization = db.get(Organization, schedule.organization_id)
            db.add(ExternalCheckRun(
                organization_id=organization.id,
                check_type="dns",
                domain=organization.domain,
                status="completed",
                trigger_source="schedule",
                started_at=schedule.last_started_at + timedelta(seconds=1),
                completed_at=server.utcnow() - timedelta(seconds=1),
                duration_ms=100,
                snapshot={"records": {}},
                change_count=0,
            ))
            db.commit()

        self.assertEqual(server.recover_interrupted_external_check_schedules(), 1)
        with self.session_factory() as db:
            schedule = db.scalar(select(ExternalCheckSchedule))
            self.assertEqual(schedule.last_run_status, "completed")
            self.assertGreater(schedule.next_run_at, server.utcnow())
        self.assertEqual(server.claim_due_external_check_schedules(), [])

    def test_schedule_recovery_cancels_disabled_stale_claim(self):
        enabled = self.client.put(
            "/api/external-checks/dns/schedule",
            json={"enabled": True, "interval_hours": 24},
        )
        self.assertEqual(enabled.status_code, 200, enabled.text)
        with self.session_factory() as db:
            schedule = db.scalar(select(ExternalCheckSchedule))
            schedule.last_started_at = server.utcnow() - timedelta(minutes=2)
            schedule.last_run_status = "running"
            schedule.enabled = False
            schedule.next_run_at = None
            db.commit()

        self.assertEqual(server.recover_interrupted_external_check_schedules(), 1)
        with self.session_factory() as db:
            schedule = db.scalar(select(ExternalCheckSchedule))
            self.assertEqual(schedule.last_run_status, "cancelled")
            self.assertIsNone(schedule.next_run_at)
        self.assertEqual(server.claim_due_external_check_schedules(), [])


if __name__ == "__main__":
    unittest.main()
