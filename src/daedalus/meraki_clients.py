"""Wireless client distributions; individual client records are never persisted."""
from collections import Counter
from typing import Any

TIMESPAN = 3600
MAX_CLIENTS = 50_000
DIMENSIONS = ("ssid", "os", "vlan", "status")
SCOPE = ("Wireless client records returned for the prior one-hour request, grouped by last reported "
         "SSID, OS/device-type prediction, VLAN and status. Counts are observations, not concurrent "
         "connections, distinct people, OS attestation or VLAN isolation proof. Individual client "
         "identities are not saved. RSSI is not provided by this collection endpoint.")


def summarize_wireless_clients(raw: Any) -> dict:
    if not isinstance(raw, list) or len(raw) > MAX_CLIENTS:
        raise ValueError("Invalid wireless client collection")
    seen = set()
    counts = {key: Counter() for key in DIMENSIONS}
    unknown = {key: 0 for key in DIMENSIONS}
    wireless = excluded = 0
    for client in raw:
        identifier = client.get("id") if isinstance(client, dict) else None
        if not isinstance(identifier, str) or not identifier or len(identifier) > 256 or identifier in seen:
            raise ValueError("Invalid or duplicate client identity")
        seen.add(identifier)
        if client.get("recentDeviceConnection") != "Wireless":
            excluded += 1
            continue
        wireless += 1
        for key in DIMENSIONS:
            label = client.get(key)
            if key == "os" and (not isinstance(label, str) or not label.strip()):
                label = client.get("deviceTypePrediction")
            if key == "status" and label not in ("Online", "Offline"):
                label = None
            if key == "vlan" and type(label) is int and 1 <= label <= 4094:
                label = str(label)
            if not isinstance(label, str) or not label.strip() or len(label) > 200:
                unknown[key] += 1
            else:
                counts[key][label] += 1
    return {"schema_version": 1, "requested_timespan_seconds": TIMESPAN,
            "wireless_client_count": wireless, "excluded_connection_count": excluded,
            "returned_record_count": len(raw), "scope": SCOPE,
            "rssi_status": "not_provided",
            "distributions": {key: {"unknown_count": unknown[key], "rows": [
                {"label": label, "count": count} for label, count in sorted(
                    counts[key].items(), key=lambda item: (-item[1], item[0]))]}
                for key in DIMENSIONS}}


def project_wireless_clients(value: Any, *, limit: int = 10) -> dict | None:
    """Allowlisted bounded projection of saved distributions, including legacy guards."""
    if not isinstance(value, dict) or type(value.get("schema_version")) is not int or value["schema_version"] != 1:
        return None
    def count(number):
        return number if type(number) is int and 0 <= number <= MAX_CLIENTS else None
    total = count(value.get("wireless_client_count"))
    raw = value.get("distributions")
    distributions = {}
    for key in DIMENSIONS:
        group = raw.get(key) if isinstance(raw, dict) else None
        rows = group.get("rows") if isinstance(group, dict) else None
        unknown = count(group.get("unknown_count")) if isinstance(group, dict) else None
        clean, seen = [], set()
        valid = isinstance(rows, list) and len(rows) <= MAX_CLIENTS and unknown is not None and total is not None
        if valid:
            for row in rows:
                label = row.get("label") if isinstance(row, dict) else None
                n = count(row.get("count")) if isinstance(row, dict) else None
                if not isinstance(label, str) or not label.strip() or len(label) > 200 or label in seen or n is None or n == 0:
                    valid = False
                    break
                seen.add(label)
                clean.append({"label": label, "count": n})
            valid = valid and sum(row["count"] for row in clean) + unknown == total
        if not valid:
            distributions[key] = {"status": "invalid_evidence", "rows": [], "unknown_count": None,
                                  "additional_group_count": 0, "additional_client_count": None}
            continue
        clean.sort(key=lambda row: (-row["count"], row["label"]))
        distributions[key] = {"status": "complete", "rows": clean[:limit], "unknown_count": unknown,
                              "additional_group_count": max(0, len(clean) - limit),
                              "additional_client_count": sum(row["count"] for row in clean[limit:])}
    return {"schema_version": 1, "requested_timespan_seconds": TIMESPAN, "scope": SCOPE,
            "wireless_client_count": total, "returned_record_count": count(value.get("returned_record_count")),
            "excluded_connection_count": count(value.get("excluded_connection_count")),
            "rssi_status": "not_provided", "distributions": distributions}
