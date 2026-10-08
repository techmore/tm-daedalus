"""Allowlisted operational observations; never a scan completion receipt."""
from __future__ import annotations

import math
from typing import Any

MAX_RUNTIME_BYTES = 64 * 1024
MAX_RUNTIME_JOBS = 128
MAX_DISPLAY_JOBS = 8


def unknown_activity() -> dict[str, Any]:
    return {"schema_version": 1, "state": "unknown", "active_job_count": None,
            "jobs": [], "truncated": False}


def _text(value: Any, limit: int) -> str | None:
    return value if isinstance(value, str) and 0 < len(value) <= limit and all(ord(c) >= 32 and ord(c) != 127 for c in value) else None


def _progress(value: Any) -> int | float | None:
    return value if type(value) in {int, float} and 0 <= value <= 100 and math.isfinite(value) else None


def activity_from_runtime(body: Any) -> dict[str, Any]:
    """Use the same coherent active-job invariant as the native Mac companion.

    Only operational fields are copied. Omitted or malformed observations never
    establish idle, completion, or an approved target scope.
    """
    if not isinstance(body, dict):
        return unknown_activity()
    jobs, active = body.get("active_jobs"), body.get("has_active_jobs")
    maintenance = body.get("maintenance_active", False)
    if (not isinstance(jobs, list) or len(jobs) > MAX_RUNTIME_JOBS
            or type(active) is not bool or active != bool(jobs)
            or type(maintenance) is not bool or maintenance and active):
        return unknown_activity()
    parsed = []
    types = set()
    for job in jobs:
        if not isinstance(job, dict) or not _text(job.get("job_type"), 80) or not isinstance(job.get("status"), str) or job["status"] not in {"running", "cancelling"}:
            return unknown_activity()
        types.add(job["job_type"])
        details = job.get("details")
        if details is None:
            details = {}
        if not isinstance(details, dict):
            return unknown_activity()
        if len(parsed) < MAX_DISPLAY_JOBS:
            parsed.append({"job_type": job["job_type"] if job["job_type"] in {"scan", "report"} else "other",
                           "status": job["status"], "target": _text(details.get("target"), 255),
                           "progress": _progress(details.get("progress"))})
    if "active_job_types" in body:
        declared = body["active_job_types"]
        if not isinstance(declared, list) or len(declared) > MAX_RUNTIME_JOBS or any(not _text(item, 80) for item in declared) or set(declared) != types:
            return unknown_activity()
    return {"schema_version": 1, "state": "maintenance" if maintenance else "running" if active else "idle",
            "active_job_count": len(jobs), "jobs": parsed, "truncated": len(jobs) > MAX_DISPLAY_JOBS}


def validated_activity(value: Any) -> dict[str, Any] | None:
    """Validate a normalized heartbeat or stored row without coercing types."""
    if (not isinstance(value, dict) or set(value) != {"schema_version", "state", "active_job_count", "jobs", "truncated"}
            or type(value["schema_version"]) is not int or value["schema_version"] != 1
            or not isinstance(value["state"], str) or value["state"] not in {"unknown", "idle", "maintenance", "running"}
            or type(value["truncated"]) is not bool or not isinstance(value["jobs"], list)):
        return None
    if value["state"] == "unknown":
        return unknown_activity() if value == unknown_activity() else None
    count, jobs = value["active_job_count"], value["jobs"]
    if (type(count) is not int or not 0 <= count <= MAX_RUNTIME_JOBS
            or len(jobs) != min(count, MAX_DISPLAY_JOBS)
            or value["truncated"] != (count > MAX_DISPLAY_JOBS)
            or (value["state"] == "running") != (count > 0)):
        return None
    parsed = []
    for job in jobs:
        if (not isinstance(job, dict) or set(job) != {"job_type", "status", "target", "progress"}
                or not isinstance(job["job_type"], str) or job["job_type"] not in {"scan", "report", "other"}
                or not isinstance(job["status"], str) or job["status"] not in {"running", "cancelling"}
                or job["target"] is not None and _text(job["target"], 255) is None
                or job["progress"] is not None and _progress(job["progress"]) is None):
            return None
        parsed.append(dict(job))
    return {**value, "jobs": parsed}
