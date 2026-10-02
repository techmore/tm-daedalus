"""Stable Meraki inventory history, separate from collection coverage gaps."""
from __future__ import annotations
from typing import Any
from .meraki_api import redact_meraki_data

_FIELDS = {
    "networks": ("name", "productTypes", "tags", "timeZone"),
    "devices": ("name", "model", "networkId", "productType", "firmware", "lanIp", "status"),
}
_IDS = {"networks": "id", "devices": "serial"}


def compare_meraki_inventory(previous: dict[str, Any], current: dict[str, Any]) -> dict[str, Any]:
    organization = str((current.get("organization") or {}).get("id") or "")
    if not organization or organization != str((previous.get("organization") or {}).get("id") or ""):
        raise ValueError("Inventory comparisons require the same Cisco organization.")

    def collection(snapshot, name):
        source = snapshot.get(name)
        if not isinstance(source, list):
            return "not_collected", {}
        indexed = {}
        for row in source:
            if not isinstance(row, dict) or not isinstance(row.get(_IDS[name]), str) or not row[_IDS[name]]:
                return "invalid_evidence", {}
            identifier = row[_IDS[name]]
            if identifier in indexed:
                return "invalid_evidence", {}
            safe = redact_meraki_data({key: row[key] for key in _FIELDS[name] if key in row})
            for key in ("tags", "productTypes"):
                if isinstance(safe.get(key), list):
                    safe[key] = sorted(safe[key], key=str)
            indexed[identifier] = safe
        return "complete", indexed

    changes, coverage = [], []
    for name in _FIELDS:
        old_status, before = collection(previous, name)
        new_status, after = collection(current, name)
        if old_status != "complete" or new_status != "complete":
            if old_status != new_status:
                coverage.append({"collection": name, "previous_status": old_status, "current_status": new_status})
            continue
        for identifier in sorted(before.keys() | after.keys()):
            old, new = before.get(identifier), after.get(identifier)
            if old is None or new is None:
                changes.append({"collection": name, "identifier": identifier,
                    "kind": "added" if old is None else "removed", "previous": old, "current": new})
                continue
            different = []
            for field in _FIELDS[name]:
                # Absent/null/unknown availability is incomplete evidence, not a
                # transition to an offline device or a removed configuration.
                old_known = field in old and old[field] is not None and (field != "status" or str(old[field]).lower() != "unknown")
                new_known = field in new and new[field] is not None and (field != "status" or str(new[field]).lower() != "unknown")
                if not old_known or not new_known:
                    if old_known != new_known:
                        coverage.append({"collection": name, "identifier": identifier, "field": field,
                            "previous_status": "observed" if old_known else "unknown",
                            "current_status": "observed" if new_known else "unknown"})
                    continue
                if old[field] != new[field]:
                    different.append(field)
            if different:
                changes.append({"collection": name, "identifier": identifier, "kind": "updated",
                                "changed_fields": different,
                                "previous": {field: old[field] for field in different},
                                "current": {field: new[field] for field in different}})
    return {"inventory_changes": changes, "inventory_change_count": len(changes),
            "inventory_coverage_changes": coverage, "inventory_coverage_change_count": len(coverage)}
