import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from daedalus.db import Base
from daedalus.models import Organization, User, ExternalCheckRun, ExternalCheckChange
from daedalus.server import capture_external_report_snapshot


class ExternalReportFreshnessTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.engine = create_engine(f"sqlite:///{Path(self.directory.name) / 'fixture.db'}")
        Base.metadata.create_all(self.engine)
        self.db = Session(self.engine)
        self.now = datetime(2026, 9, 29, 12)
        self.organization = Organization(name="Fixture", slug="fixture", domain="fixture.example", created_at=self.now)
        self.foreign = Organization(name="Other", slug="other", domain="other.example", created_at=self.now)
        self.user = User(google_subject="fixture-user", email="admin@fixture.example", created_at=self.now)
        self.db.add_all([self.organization, self.foreign, self.user])
        self.db.commit()

    def tearDown(self):
        self.db.close()
        self.engine.dispose()
        self.directory.cleanup()

    def add_run(self, status, check_type="dns", organization=None):
        organization = organization or self.organization
        run = ExternalCheckRun(organization_id=organization.id, domain=organization.domain,
            check_type=check_type, status=status, started_at=self.now,
            completed_at=None if status in ("running", "queued") else self.now + timedelta(seconds=2),
            error_summary="fixture failure" if status == "failed" else None,
            snapshot={"records": {"A": ["192.0.2.1"]}} if status.startswith("completed") else {"partial": "must not duplicate"})
        self.db.add(run)
        self.db.commit()
        return run

    def capture(self):
        return capture_external_report_snapshot(self.db, self.organization, self.user)

    def test_successful_evidence_and_changes_preserved_with_newer_failure_or_running(self):
        baseline = self.add_run("completed_with_warnings")
        self.db.add(ExternalCheckChange(organization_id=self.organization.id,
            run_id=baseline.id, check_type="dns", field_path="records.A",
            previous_value=[], current_value=["192.0.2.1"], detected_at=self.now))
        self.db.commit()
        for status in ("failed", "running", "queued", "cancelled"):
            with self.subTest(status=status):
                latest = self.add_run(status)
                check = self.capture()["checks"]["dns"]
                self.assertEqual(check["run"]["id"], baseline.id)
                self.assertEqual(check["run"]["snapshot"], baseline.snapshot)
                self.assertEqual(check["changes"][0]["field_path"], "records.A")
                self.assertEqual(check["latest_attempt"], {
                    "id": latest.id, "status": status, "started_at": "2026-09-29T12:00:00Z",
                    "queued_at": None, "collection_started_at": None,
                    "completed_at": None if status in ("running", "queued") else "2026-09-29T12:00:02Z",
                    "error_summary": "fixture failure" if status == "failed" else None})

    def test_latest_attempt_without_successful_baseline_and_empty_type(self):
        latest = self.add_run("failed")
        checks = self.capture()["checks"]
        self.assertIsNone(checks["dns"]["run"])
        self.assertEqual(checks["dns"]["changes"], [])
        self.assertEqual(checks["dns"]["latest_attempt"]["id"], latest.id)
        self.assertEqual(checks["web"], {"run": None, "changes": [], "latest_attempt": None})

    def test_foreign_workspace_and_other_check_type_do_not_replace_latest(self):
        baseline = self.add_run("completed")
        web = self.add_run("running", "web")
        self.add_run("failed", organization=self.foreign)
        self.add_run("completed", "web", self.foreign)
        checks = self.capture()["checks"]
        self.assertEqual(checks["dns"]["run"]["id"], baseline.id)
        self.assertEqual(checks["dns"]["latest_attempt"]["id"], baseline.id)
        self.assertEqual(checks["web"]["latest_attempt"]["id"], web.id)
        self.assertIsNone(checks["web"]["run"])

    def test_captured_attempt_is_frozen_after_database_changes(self):
        latest = self.add_run("running")
        captured = self.capture()
        latest.status = "failed"
        latest.error_summary = "later error"
        self.db.commit()
        self.assertEqual(captured["checks"]["dns"]["latest_attempt"]["status"], "running")
        self.assertIsNone(captured["checks"]["dns"]["latest_attempt"]["error_summary"])


if __name__ == "__main__":
    unittest.main()
