from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


MAX_PROFILE_CHECKS = 2_000
MAX_REPORT_RESULTS = 2_000
ALLOWED_CATEGORIES = {"macos", "chrome", "safari"}
ALLOWED_STATUSES = {"pass", "fail", "manual", "error"}
PROFILE_PLATFORMS = {"macos", "windows", "linux", "browser", "multi"}
PROFILE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,119}$")
BENCHMARK_ID = re.compile(r"^[0-9]+(?:\.[0-9]+){0,6}$")
IPV4_TEXT = re.compile(r"(?<![\w])(?:\d{1,3}\.){3}\d{1,3}(?![\w])")
MAC_TEXT = re.compile(r"(?i)(?<![\w])(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}(?![\w])")
USER_PATH = re.compile(r"(?i)(/Users/|/home/)[^/\s]+")
SECRET_ASSIGNMENT = re.compile(
    r"(?i)\b(api[_-]?key|token|password|passphrase|secret)\s*[:=]\s*[^\s,;]+"
)


class CISDataError(ValueError):
    pass


def _safe_text(value: Any, *, maximum: int) -> str:
    if value is None:
        return ""
    text = str(value)
    text = "".join(character for character in text if character in "\n\t" or ord(character) >= 32)
    return text.strip()[:maximum]


def _scrub_details(value: Any) -> str:
    details = _safe_text(value, maximum=2_000)
    details = SECRET_ASSIGNMENT.sub(lambda match: match.group(1) + "=[redacted]", details)
    details = IPV4_TEXT.sub("[address]", details)
    details = MAC_TEXT.sub("[device identifier]", details)
    details = USER_PATH.sub(lambda match: match.group(1) + "[user]", details)
    return details


def validate_profile(profile: Any) -> dict[str, Any]:
    if not isinstance(profile, dict):
        raise CISDataError("A profile must be a JSON object.")
    name = _safe_text(profile.get("name"), maximum=200)
    version = _safe_text(profile.get("version"), maximum=32)
    platform = _safe_text(profile.get("platform") or "multi", maximum=32).casefold()
    description = _safe_text(profile.get("description"), maximum=1_000)
    checks = profile.get("checks")
    if not name or not version or platform not in PROFILE_PLATFORMS:
        raise CISDataError("A profile needs a name, version, and supported platform.")
    if not isinstance(checks, list) or not checks or len(checks) > MAX_PROFILE_CHECKS:
        raise CISDataError(f"A profile must contain 1–{MAX_PROFILE_CHECKS} checks.")

    normalized: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    for row in checks:
        if not isinstance(row, dict):
            raise CISDataError("Every profile check must be an object.")
        check_id = _safe_text(row.get("id"), maximum=120)
        category = _safe_text(row.get("category"), maximum=32).casefold()
        check_description = _safe_text(row.get("description"), maximum=500)
        if (
            not PROFILE_ID.fullmatch(check_id)
            or check_id in seen_ids
            or category not in ALLOWED_CATEGORIES
            or not check_description
        ):
            raise CISDataError("Each check needs a unique ID, a supported category, and a description.")
        seen_ids.add(check_id)
        normalized_check: dict[str, Any] = {
            "id": check_id,
            "category": category,
            "description": check_description,
        }
        rule_id = _safe_text(row.get("rule_id"), maximum=120)
        if rule_id:
            if not PROFILE_ID.fullmatch(rule_id):
                raise CISDataError("A check rule ID contains unsupported characters.")
            normalized_check["rule_id"] = rule_id
        benchmark_ids = row.get("benchmark_ids")
        if benchmark_ids is not None:
            if (
                not isinstance(benchmark_ids, list)
                or len(benchmark_ids) > 8
                or any(not isinstance(item, str) or not BENCHMARK_ID.fullmatch(item) for item in benchmark_ids)
            ):
                raise CISDataError("Benchmark recommendation IDs must be a list of valid numeric IDs.")
            normalized_check["benchmark_ids"] = list(dict.fromkeys(benchmark_ids))
        normalized.append(normalized_check)
    slug = _safe_text(profile.get("slug"), maximum=100).casefold()
    if not slug:
        slug = re.sub(r"[^a-z0-9]+", "-", name.casefold()).strip("-")[:100]
    if not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", slug):
        raise CISDataError("The profile slug contains unsupported characters.")
    benchmark: dict[str, str] | None = None
    raw_benchmark = profile.get("benchmark")
    if raw_benchmark is not None:
        if not isinstance(raw_benchmark, dict):
            raise CISDataError("Benchmark metadata must be an object.")
        benchmark_fields = (
            "name", "version", "level", "os_version", "source", "source_release",
            "source_commit", "source_url", "license", "attribution", "disclaimer",
        )
        benchmark = {
            key: _safe_text(raw_benchmark.get(key), maximum=1_000 if key in {"attribution", "disclaimer"} else 300)
            for key in benchmark_fields
            if raw_benchmark.get(key) is not None
        }
        if "source_url" in benchmark and not benchmark["source_url"].startswith("https://"):
            raise CISDataError("Benchmark source URLs must use HTTPS.")
    normalized_profile: dict[str, Any] = {
        "slug": slug,
        "name": name,
        "version": version,
        "platform": platform,
        "description": description,
        "checks": normalized,
    }
    if benchmark:
        normalized_profile["benchmark"] = benchmark
    return normalized_profile


def profile_checksum(profile: dict[str, Any]) -> str:
    serialized = json.dumps(profile, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def bind_report_to_profile(report: dict[str, Any], profile: dict[str, Any]) -> None:
    """Require complete evidence and take check identity from the published profile."""
    expected = {check["id"]: check for check in profile["checks"]}
    received = {result["id"]: result for result in report["results"]}
    if expected.keys() != received.keys():
        raise CISDataError("The report must contain exactly one result for every published profile check.")
    for check_id, result in received.items():
        check = expected[check_id]
        if result["category"] != check["category"]:
            raise CISDataError("A result category does not match its published profile check.")
        if "rule_id" in result and result["rule_id"] != check.get("rule_id"):
            raise CISDataError("A result rule ID does not match its published profile check.")
        # Titles and recommendation references are server-owned, immutable metadata.
        for field in ("description", "rule_id", "benchmark_ids"):
            result.pop(field, None)
            if field in check:
                result[field] = check[field]
    report["summary"]["profile_checksum"] = profile_checksum(profile)
    report["summary"]["profile_verified"] = True


def load_starter_profile() -> dict[str, Any]:
    profile_path = Path(__file__).resolve().parent / "profiles" / "csp-macos-browser-baseline-v1.json"
    try:
        profile = json.loads(profile_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CISDataError("The bundled CSP starter profile could not be loaded.") from exc
    return validate_profile(profile)


def load_macos26_starter_profiles() -> list[dict[str, Any]]:
    profiles_dir = Path(__file__).resolve().parent / "profiles"
    profiles: list[dict[str, Any]] = []
    for level in (1, 2):
        profile_path = profiles_dir / f"cis-macos-26-tahoe-level-{level}.json"
        try:
            profile = json.loads(profile_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise CISDataError(f"The macOS 26 Level {level} CIS profile could not be loaded.") from exc
        profiles.append(validate_profile(profile))
    return profiles


def _parse_datetime(value: Any) -> datetime:
    if not isinstance(value, str) or len(value) > 80:
        raise CISDataError("The report must include an ISO 8601 collection timestamp.")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise CISDataError("The report collection timestamp is invalid.") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC).replace(tzinfo=None)


def normalize_cis_report(payload: Any, *, api_key: str | None = None) -> dict[str, Any]:
    """Accept the existing CSP client shapes and retain only report evidence."""
    if not isinstance(payload, dict):
        raise CISDataError("The CIS report must be a JSON object.")

    def safe_report_text(value: Any, maximum: int) -> str:
        cleaned = _scrub_details(value)[:maximum]
        return cleaned.replace(api_key, "[redacted]") if api_key else cleaned

    system_info = payload.get("system_info")
    if not isinstance(system_info, dict):
        system_info = payload.get("systemInfo")
    if not isinstance(system_info, dict):
        system_info = {}

    report_info = payload.get("report_info")
    if not isinstance(report_info, dict):
        report_info = {}
    collected_raw = payload.get("timestamp") or report_info.get("timestamp")
    collected_at = _parse_datetime(collected_raw)

    device_identifier = (
        payload.get("device_uuid")
        or payload.get("deviceUUID")
        or system_info.get("serial_number")
        or system_info.get("serialNumber")
    )
    if not isinstance(device_identifier, str) or not device_identifier.strip() or len(device_identifier) > 256:
        raise CISDataError("The report must include a device identifier.")
    client_report_id = payload.get("report_id") or payload.get("reportID")
    if client_report_id is not None:
        client_report_id = _safe_text(client_report_id, maximum=256)
        if not client_report_id:
            client_report_id = None

    source_results = payload.get("results")
    if not isinstance(source_results, list) or not source_results or len(source_results) > MAX_REPORT_RESULTS:
        raise CISDataError(f"The report must contain 1–{MAX_REPORT_RESULTS} check results.")

    results: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    for index, row in enumerate(source_results, start=1):
        if not isinstance(row, dict):
            raise CISDataError("Each CIS result must be an object.")
        check = row.get("check")
        check = check if isinstance(check, dict) else row
        check_id = safe_report_text(check.get("id") or f"check_{index}", maximum=120)
        category = _safe_text(check.get("category"), maximum=32).casefold()
        status = _safe_text(row.get("status"), maximum=24).casefold()
        description = safe_report_text(check.get("description"), maximum=500)
        if (
            not PROFILE_ID.fullmatch(check_id)
            or check_id in seen_ids
            or category not in ALLOWED_CATEGORIES
            or status not in ALLOWED_STATUSES
            or not description
        ):
            raise CISDataError("A CIS result has an invalid ID, category, status, or description.")
        seen_ids.add(check_id)
        normalized_result: dict[str, Any] = {
            "id": check_id,
            "category": category,
            "description": description,
            "status": status,
            "details": safe_report_text(row.get("details"), maximum=2_000),
        }
        rule_id = _safe_text(check.get("rule_id"), maximum=120)
        if rule_id and not PROFILE_ID.fullmatch(rule_id):
            raise CISDataError("A result rule ID contains unsupported characters.")
        if rule_id:
            normalized_result["rule_id"] = rule_id
        benchmark_ids = check.get("benchmark_ids")
        if benchmark_ids is not None:
            if (
                not isinstance(benchmark_ids, list)
                or len(benchmark_ids) > 8
                or not all(isinstance(item, str) and BENCHMARK_ID.fullmatch(item) for item in benchmark_ids)
            ):
                raise CISDataError("Result recommendation IDs must be valid numeric IDs.")
            normalized_result["benchmark_ids"] = list(dict.fromkeys(benchmark_ids))
        results.append(normalized_result)

    counts = {status: 0 for status in ALLOWED_STATUSES}
    categories: dict[str, dict[str, int]] = {}
    for result in results:
        counts[result["status"]] += 1
        category_summary = categories.setdefault(
            result["category"], {"total": 0, **{status: 0 for status in ALLOWED_STATUSES}}
        )
        category_summary["total"] += 1
        category_summary[result["status"]] += 1
    for category_summary in categories.values():
        category_summary["score"] = round(
            category_summary["pass"] / category_summary["total"] * 100, 2
        ) if category_summary["total"] else 0.0
    summary = {
        "total": len(results),
        **counts,
        "score": round(counts["pass"] / len(results) * 100, 2),
        "categories": categories,
        "profile_verified": False,
        "assessed": counts["pass"] + counts["fail"],
        "assessment_coverage": round((counts["pass"] + counts["fail"]) / len(results) * 100, 2),
    }

    platform = "macos" if any(row["category"] == "macos" for row in results) else "browser"
    profile = payload.get("profile")
    if not isinstance(profile, dict):
        profile = {}
    profile_slug = safe_report_text(
        profile.get("slug") or payload.get("profile_slug"), maximum=100
    ).casefold()
    profile_version = safe_report_text(
        profile.get("version")
        or payload.get("profile_version")
        or report_info.get("cis_benchmark_version"),
        32,
    )
    return {
        "device_identifier": device_identifier.strip(),
        "client_report_id": client_report_id,
        "collected_at": collected_at,
        "device_name": safe_report_text(
            system_info.get("hostname") or system_info.get("computer_name") or "CIS endpoint",
            120,
        ) or "CIS endpoint",
        "platform": platform,
        "os_version": safe_report_text(
            system_info.get("os_version") or system_info.get("osVersion"), 120
        ),
        "profile_slug": profile_slug,
        "profile_version": profile_version,
        "summary": summary,
        "results": results,
    }
