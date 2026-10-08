"""Passive crt.sh observations; no live certificate or log-proof validation."""
from __future__ import annotations

import http.client
import json
import re
from datetime import datetime, timezone
from urllib.parse import urlencode

from .domain_verification import normalize_domain
from .external_checks import _PinnedHTTPSConnection, _public_addresses

MAX_RESPONSE_BYTES = 512 * 1024
MAX_SOURCE_ROWS = 1000
MAX_SAVED_ENTRIES = 100


class PartialTransparencyFailure(RuntimeError):
    def __init__(self, rows: list, error_type: str, http_status: int | None = None, query: str = "subdomain"):
        super().__init__("Certificate history query unavailable")
        if query not in {"root", "subdomain"}:
            raise ValueError("Invalid certificate history query scope")
        self.rows = rows
        self.error_type = error_type
        self.http_status = http_status
        self.query = query


class ProviderHTTPFailure(ValueError):
    def __init__(self, status: int):
        if type(status) is not int or not 100 <= status <= 599:
            raise ValueError("Invalid provider HTTP status")
        super().__init__("Certificate transparency provider returned an HTTP error")
        self.http_status = status


def _fetch_query(query: str, address: str) -> list:
    connection = _PinnedHTTPSConnection("crt.sh", address, timeout=8)
    try:
        connection.request("GET", "/?" + urlencode({"q": query, "output": "json"}), headers={
            "Accept": "application/json", "User-Agent": "Daedalus-Passive-Health-Check/1.0", "Connection": "close"})
        response = connection.getresponse()
        if response.status != 200:
            raise ProviderHTTPFailure(response.status)
        body = response.read(MAX_RESPONSE_BYTES + 1)
        if len(body) > MAX_RESPONSE_BYTES:
            raise ValueError("Certificate transparency response exceeds evidence limit")
        result = json.loads(body)
        if not isinstance(result, list):
            raise ValueError("Certificate transparency response is not a list")
        return result
    finally:
        connection.close()


def fetch_entries(domain: str) -> list:
    domain = normalize_domain(domain)
    addresses = _public_addresses("crt.sh")
    # Preserve root coverage as well as the legacy wildcard subdomain query.
    rows, failures = [], []
    for scope, query in (("root", domain), ("subdomain", "%." + domain)):
        try:
            rows.extend(_fetch_query(query, addresses[0]))
        except (OSError, ValueError, RuntimeError, http.client.HTTPException) as exc:
            if scope == "root" and isinstance(exc, ProviderHTTPFailure) and exc.http_status in {401, 403, 429}:
                raise  # Do not make another query after access or rate-limit refusal.
            failures.append((scope, exc))
    if len(failures) == 2:
        raise failures[0][1]
    if failures:
        scope, exc = failures[0]
        raise PartialTransparencyFailure(rows, type(exc).__name__, getattr(exc, "http_status", None), scope) from exc
    return rows


def _date(value: object) -> str:
    if not isinstance(value, str) or len(value) > 64:
        raise ValueError("Invalid certificate date")
    date = datetime.fromisoformat(value.replace("Z", "+00:00"))
    # crt.sh's SQL timestamps are represented in UTC without a suffix.
    if date.tzinfo is None:
        date = date.replace(tzinfo=timezone.utc)
    return date.astimezone(timezone.utc).isoformat()


def transparency_evidence(domain: str, rows: list) -> dict:
    domain = normalize_domain(domain)
    if not isinstance(rows, list):
        raise ValueError("Invalid certificate transparency collection")
    partial = len(rows) > MAX_SOURCE_ROWS
    entries = {}
    for row in rows[:MAX_SOURCE_ROWS]:
        try:
            if not isinstance(row, dict):
                raise ValueError("Invalid certificate observation")
            entry_id, issuer_id = row.get("id"), row.get("issuer_ca_id")
            if any(type(value) is not int or not 0 < value < 2**63 for value in (entry_id, issuer_id)):
                raise ValueError("Invalid certificate observation identity")
            serial, issuer, name_value = row.get("serial_number"), row.get("issuer_name"), row.get("name_value")
            if not isinstance(serial, str) or not re.fullmatch(r"[0-9a-fA-F]{1,128}", serial):
                raise ValueError("Invalid certificate serial")
            if not isinstance(issuer, str) or not issuer or len(issuer) > 256 or not isinstance(name_value, str) or len(name_value) > 8192:
                raise ValueError("Invalid certificate metadata")
            names = set()
            for name in name_value.splitlines():
                wildcard = name.startswith("*.")
                normalized = normalize_domain(name.removeprefix("*."))
                if normalized == domain or normalized.endswith("." + domain):
                    names.add(("*." if wildcard else "") + normalized)
            if not names:
                raise ValueError("Certificate observation is outside the requested domain")
            entry = {"id": entry_id, "issuer_ca_id": issuer_id, "issuer": issuer,
                     "serial_number": serial.lower(), "dns_names": sorted(names),
                     "not_before": _date(row.get("not_before")), "not_after": _date(row.get("not_after"))}
            if entry["not_after"] < entry["not_before"]:
                raise ValueError("Invalid certificate validity interval")
        except (ValueError, TypeError):
            partial = True
            continue
        if entry_id in entries and entries[entry_id] != entry:
            raise ValueError("Conflicting certificate observation identities")
        entries[entry_id] = entry
    ordered = sorted(entries.values(), key=lambda item: (item["not_before"], item["id"]), reverse=True)
    partial = partial or len(ordered) > MAX_SAVED_ENTRIES
    return {"domain": domain, "state": "observed", "provider": "crt.sh", "scope": "domain_and_subdomains",
            "collection_partial": partial, "source_row_count": len(rows),
            "entries": ordered[:MAX_SAVED_ENTRIES], "log_proofs_verified": False,
            "live_certificate_verified": False}


def run_transparency_check(domain: str) -> dict:
    domain = normalize_domain(domain)
    try:
        return transparency_evidence(domain, fetch_entries(domain))
    except PartialTransparencyFailure as exc:
        try:
            result = transparency_evidence(domain, exc.rows)
        except ValueError:
            return {"domain": domain, "state": "unavailable", "provider": "crt.sh", "scope": "domain_and_subdomains",
                    "error_type": "ValueError", "log_proofs_verified": False, "live_certificate_verified": False}
        result["collection_partial"] = True
        result[exc.query + "_query_error_type"] = exc.error_type
        if exc.http_status is not None:
            result[exc.query + "_query_http_status"] = exc.http_status
        return result
    except (OSError, ValueError, RuntimeError, http.client.HTTPException) as exc:
        result = {"domain": domain, "state": "unavailable", "provider": "crt.sh", "scope": "domain_and_subdomains",
                  "error_type": type(exc).__name__, "log_proofs_verified": False, "live_certificate_verified": False}
        if isinstance(exc, ProviderHTTPFailure):
            result.update(error_code="provider_http_error", http_status=exc.http_status)
        else:
            result["error_code"] = "timeout" if isinstance(exc, TimeoutError) else "invalid_response" if isinstance(exc, ValueError) else "lookup_failed"
        return result


def newly_observed_entries(previous: object, current: object, domain: str) -> list:
    """Compare complete matching provider observations; never infer removals."""
    try:
        domain = normalize_domain(domain)
        for block in (previous, current):
            if (not isinstance(block, dict) or block.get("domain") != domain or block.get("provider") != "crt.sh"
                    or block.get("scope") != "domain_and_subdomains" or block.get("state") != "observed"
                    or block.get("collection_partial") is not False or not isinstance(block.get("entries"), list)
                    or len(block["entries"]) > MAX_SAVED_ENTRIES):
                return []
            ids = set()
            for entry in block["entries"]:
                if not isinstance(entry, dict) or type(entry.get("id")) is not int or not 0 < entry["id"] < 2**63 or entry["id"] in ids:
                    return []
                ids.add(entry["id"])
                if not isinstance(entry.get("dns_names"), list) or not entry["dns_names"]:
                    return []
                for name in entry["dns_names"]:
                    normalized = normalize_domain(name.removeprefix("*."))
                    if normalized != domain and not normalized.endswith("." + domain):
                        return []
                if (_date(entry.get("not_after")) < _date(entry.get("not_before"))
                        or type(entry.get("issuer_ca_id")) is not int or not 0 < entry["issuer_ca_id"] < 2**63
                        or not isinstance(entry.get("issuer"), str) or not 0 < len(entry["issuer"]) <= 256
                        or not isinstance(entry.get("serial_number"), str)
                        or not re.fullmatch(r"[0-9a-fA-F]{1,128}", entry["serial_number"])):
                    return []
        previous_ids = {entry["id"] for entry in previous["entries"]}
        return sorted([entry for entry in current["entries"] if entry["id"] not in previous_ids], key=lambda entry: entry["id"])
    except (ValueError, TypeError, AttributeError):
        return []


def retained_entry_ids(block: object, domain: str) -> set[int]:
    """Valid saved rows remain previously observed even in a partial collection."""
    if not isinstance(block, dict):
        return set()
    empty = {"domain": domain, "provider": "crt.sh", "scope": "domain_and_subdomains",
             "state": "observed", "collection_partial": False, "entries": []}
    # This copy relaxes collection completeness only for validating retained
    # rows. It does not alter the stored coverage or qualify new comparisons.
    candidate = {**block, "collection_partial": False}
    return {entry["id"] for entry in newly_observed_entries(empty, candidate, domain)}
