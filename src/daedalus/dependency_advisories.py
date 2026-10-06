"""Bounded OSV evidence for URL-declared npm versions, not executed-code verdicts."""

from datetime import datetime, timezone
import json
import re
import time

import httpx


OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
MAX_RESPONSE_BYTES = 512 * 1024
MAX_PACKAGES = 100


def query_declared_package_advisories(metadata: dict, *, client=None) -> dict:
    result = {
        "schema_version": 1, "provider": "OSV", "source_url": OSV_BATCH_URL,
        "observed_at": datetime.now(timezone.utc).isoformat(),
        "scope": "advisory_matches_for_url_declared_versions",
        "package_bytes_verified": False, "execution_verified": False,
        "state": "not_assessed", "packages": [],
    }
    packages = metadata.get("packages")
    if metadata.get("schema_version") != 1 or not isinstance(packages, list):
        return result
    if not packages:
        result["reason"] = "No supported exact package versions were identified."
        return result
    if len(packages) > MAX_PACKAGES or not all(
        isinstance(p, dict) and p.get("ecosystem") == "npm"
        and isinstance(p.get("name"), str) and len(p["name"]) <= 214
        and re.fullmatch(r"(?:@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*", p["name"])
        and isinstance(p.get("version"), str) and len(p["version"]) <= 64
        and re.fullmatch(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)", p["version"])
        for p in packages
    ):
        result["reason"] = "Package declaration metadata is invalid or exceeds collection limits."
        return result
    queries = [{"package": {"ecosystem": "npm", "name": p["name"]}, "version": p["version"]} for p in packages]
    owned_client = client is None
    if owned_client:
        client = httpx.Client(timeout=httpx.Timeout(3, read=2), follow_redirects=False, trust_env=False)
    try:
        deadline = time.monotonic() + 10
        with client.stream("POST", OSV_BATCH_URL, json={"queries": queries}, follow_redirects=False) as response:
            if response.status_code != 200:
                result.update(state="unavailable", http_status=response.status_code, error_type="ProviderHTTPFailure")
                return result
            body = bytearray()
            for chunk in response.iter_bytes():
                if time.monotonic() > deadline:
                    raise TimeoutError("Advisory collection deadline exceeded")
                body.extend(chunk)
                if len(body) > MAX_RESPONSE_BYTES:
                    raise ValueError("Advisory response exceeds collection limits")
        decoded = json.loads(body)
        responses = decoded.get("results") if isinstance(decoded, dict) else None
        if not isinstance(responses, list) or len(responses) != len(packages):
            raise ValueError("Advisory response does not match queried packages")
        collected = []
        for package, response in zip(packages, responses):
            if not isinstance(response, dict):
                raise ValueError("Invalid package advisory response")
            advisories = response.get("vulns", [])
            if not isinstance(advisories, list) or len(advisories) > 1000:
                raise ValueError("Invalid advisory list")
            if not all(isinstance(v, dict) and isinstance(v.get("id"), str)
                       and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", v["id"]) for v in advisories):
                raise ValueError("Invalid advisory identifier")
            ids = sorted({v["id"] for v in advisories})
            collected.append({"ecosystem": "npm", "name": package["name"], "version": package["version"],
                              "state": "partial" if response.get("next_page_token") else "observed",
                              "advisory_ids": ids})
        result.update(packages=collected, state="partial" if metadata.get("truncated") or any(p["state"] == "partial" for p in collected) else "observed")
    except (httpx.HTTPError, TimeoutError, ValueError, UnicodeError) as exc:
        result.update(state="unavailable", error_type=type(exc).__name__, packages=[])
    finally:
        if owned_client:
            client.close()
    return result
