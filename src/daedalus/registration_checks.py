"""Bounded public RDAP evidence; callers retain unavailable results separately."""
from __future__ import annotations

import json
import http.client
from datetime import datetime, timezone
from urllib.parse import urlsplit

from .domain_verification import normalize_domain
from .external_checks import _PinnedHTTPSConnection, _public_addresses

BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
MAX_JSON_BYTES = 512 * 1024


def canonical_registration_events(events: list) -> list:
    """Compare event instants without changing retained provider evidence."""
    if not isinstance(events, list) or len(events) > 100:
        raise ValueError("Invalid registration events")
    values = set()
    for event in events:
        if not isinstance(event, dict) or not isinstance(event.get("action"), str) or event["action"] not in {"registration", "expiration", "last changed"}:
            raise ValueError("Invalid registration event")
        value = event.get("date")
        if not isinstance(value, str) or len(value) > 64:
            raise ValueError("Invalid registration event date")
        instant = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if instant.tzinfo is None:
            raise ValueError("Registration event requires a timezone")
        values.add((event["action"], instant.astimezone(timezone.utc).isoformat()))
    return [{"action": action, "date": date} for action, date in sorted(values)]


def _https_url(value: str) -> str:
    if not isinstance(value, str) or any(ord(c) < 33 for c in value) or "\\" in value:
        raise ValueError("Invalid RDAP service URL")
    parsed = urlsplit(value)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password
            or parsed.port not in (None, 443) or parsed.query or parsed.fragment):
        raise ValueError("RDAP requires a public HTTPS service URL")
    return value


def fetch_json(url: str) -> dict:
    parsed = urlsplit(_https_url(url))
    addresses = _public_addresses(parsed.hostname)
    connection = _PinnedHTTPSConnection(parsed.hostname, addresses[0], timeout=8)
    try:
        connection.request("GET", parsed.path or "/", headers={
            "Accept": "application/rdap+json, application/json",
            "User-Agent": "Daedalus-Passive-Health-Check/1.0", "Connection": "close",
        })
        response = connection.getresponse()
        if response.status != 200:
            raise ValueError(f"RDAP HTTP {response.status}")
        body = response.read(MAX_JSON_BYTES + 1)
        if len(body) > MAX_JSON_BYTES:
            raise ValueError("RDAP response exceeds the evidence limit")
        result = json.loads(body)
        if not isinstance(result, dict):
            raise ValueError("RDAP response is not an object")
        return result
    finally:
        connection.close()


def registration_url(domain: str, bootstrap: dict) -> str:
    domain = normalize_domain(domain)
    services = bootstrap.get("services")
    if not isinstance(services, list):
        raise ValueError("RDAP bootstrap services unavailable")
    matches = []
    for service in services:
        if not isinstance(service, list) or len(service) != 2:
            continue
        suffixes, urls = service
        if not isinstance(suffixes, list) or not isinstance(urls, list):
            continue
        for suffix in suffixes:
            if isinstance(suffix, str) and (domain == suffix or domain.endswith("." + suffix)):
                for url in urls:
                    try:
                        safe_url = _https_url(url)
                    except (ValueError, TypeError):
                        continue
                    matches.append((len(suffix), safe_url))
    if not matches:
        raise ValueError("No HTTPS RDAP service is published for this domain")
    base = sorted(matches, key=lambda item: (-item[0], item[1]))[0][1]
    return base.rstrip("/") + "/domain/" + domain


def registration_evidence(domain: str, document: dict) -> dict:
    domain = normalize_domain(domain)
    if document.get("objectClassName") != "domain" or str(document.get("ldhName", "")).lower().rstrip(".") != domain:
        raise ValueError("RDAP domain identity does not match the requested domain")
    nameservers = document.get("nameservers", [])
    events = document.get("events", [])
    entities = document.get("entities", [])
    if any(not isinstance(value, list) for value in (nameservers, events, entities)):
        raise ValueError("Malformed RDAP evidence collections")
    partial = any(key not in document for key in ("nameservers", "events", "entities"))
    partial = partial or any(len(value) > 100 for value in (nameservers, events, entities))
    names = set()
    for item in nameservers[:100]:
        if isinstance(item, dict) and isinstance(item.get("ldhName"), str):
            try:
                names.add(normalize_domain(item["ldhName"]))
            except ValueError:
                partial = True
        else:
            partial = True
    dates = set()
    for item in events[:100]:
        if not isinstance(item, dict):
            partial = True
            continue
        action = item.get("eventAction")
        if not isinstance(action, str):
            partial = True
            continue
        if action in {"registration", "expiration", "last changed"}:
            value = item.get("eventDate")
            try:
                if not isinstance(value, str) or len(value) > 64 or datetime.fromisoformat(value.replace("Z", "+00:00")).tzinfo is None:
                    raise ValueError("Invalid registration event date")
            except ValueError:
                partial = True
                continue
            dates.add((item["eventAction"], value))
    registrars = set()
    for entity in entities[:100]:
        if not isinstance(entity, dict):
            partial = True
            continue
        roles = entity.get("roles")
        if not isinstance(roles, list):
            partial = True
            continue
        if "registrar" not in roles:
            continue
        card = entity.get("vcardArray")
        if not isinstance(card, list) or len(card) != 2 or not isinstance(card[1], list):
            partial = True
            continue
        partial = partial or len(card[1]) > 100
        found_name = False
        for field in card[1][:100]:
            if isinstance(field, list) and len(field) == 4 and field[0] == "fn" and isinstance(field[3], str) and field[3].strip():
                registrars.add(field[3][:256])
                partial = partial or len(field[3]) > 256
                found_name = True
        partial = partial or not found_name
    return {"domain": domain, "state": "observed", "protocol": "rdap",
            "nameservers": sorted(names), "registrars": sorted(registrars),
            "events": [{"action": action, "date": date} for action, date in sorted(dates)],
            "collection_partial": partial or not registrars,
            "registration_owner_verified": False}


def run_registration_check(domain: str) -> dict:
    domain = normalize_domain(domain)
    try:
        url = registration_url(domain, fetch_json(BOOTSTRAP_URL))
        result = registration_evidence(domain, fetch_json(url))
        result["source_url"] = url
        return result
    except (OSError, ValueError, RuntimeError, http.client.HTTPException) as exc:
        return {"domain": domain, "state": "unavailable", "protocol": "rdap",
                "error_type": type(exc).__name__, "registration_owner_verified": False}
