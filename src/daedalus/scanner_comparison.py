"""Compare explicit saved observations without treating absence as closure."""
from __future__ import annotations

import ipaddress
import json
import re
from typing import Any

MAX_HOSTS = 10000
MAX_PORTS = 50000
MAX_CHANGES = 1000


def normalize_snapshot(payload: Any) -> dict[str, Any]:
    hosts = payload.get("hosts") if isinstance(payload, dict) else payload
    if not isinstance(hosts, list) or len(hosts) > MAX_HOSTS:
        raise ValueError("Deep results must contain a bounded host list.")
    observed = {}
    port_count = 0
    for host in hosts:
        if not isinstance(host, dict):
            raise ValueError("Host results must be objects.")
        address = host.get("ip") or host.get("address")
        if not isinstance(address, str):
            raise ValueError("A host address is required.")
        try:
            address = str(ipaddress.ip_address(address.strip()))
        except ValueError as exc:
            raise ValueError("Host identities must be explicit IP addresses.") from exc
        if address in observed:
            raise ValueError("Duplicate host identities are ambiguous.")
        ports = host.get("ports")
        if ports is None:
            ports = []
        if not isinstance(ports, list):
            raise ValueError("Port observations must be a list.")
        entries = {}
        for port in ports:
            port_count += 1
            if port_count > MAX_PORTS or not isinstance(port, dict):
                raise ValueError("Port observations exceed bounds or have an invalid shape.")
            number = port.get("port", port.get("portid", port.get("number")))
            protocol = port.get("protocol")
            if isinstance(number, str) and "/" in number:
                number, embedded_protocol = number.split("/", 1)
                if protocol is not None and protocol != embedded_protocol:
                    raise ValueError("Port protocol evidence conflicts.")
                protocol = embedded_protocol
            if isinstance(number, str) and re.fullmatch(r"[0-9]{1,5}", number):
                number = int(number)
            if type(number) is not int or not 1 <= number <= 65535 or protocol not in {"tcp", "udp", "sctp"}:
                raise ValueError("Each port requires an explicit supported protocol and number.")
            identity = (protocol, number)
            if identity in entries:
                raise ValueError("Duplicate port identities are ambiguous.")
            state = port.get("state")
            if state is not None and (not isinstance(state, str) or len(state) > 80):
                raise ValueError("Port state evidence is invalid.")
            service = port.get("service")
            if service is not None and not isinstance(service, (str, dict)):
                raise ValueError("Service evidence must be text or an object.")
            if len(json.dumps(service, allow_nan=False)) > 8000:
                raise ValueError("Service evidence exceeds comparison bounds.")
            extras = {}
            for field in ("product", "version"):
                value = port.get(field)
                if value is not None and (not isinstance(value, str) or len(value) > 2000):
                    raise ValueError(f"Port {field} evidence exceeds bounds or has an invalid shape.")
                extras[field] = value
            entries[identity] = {"state": state, "service": service, **extras}
        observed[address] = {"ports": entries, "ports_complete": host.get("ports_complete") is True}
    targets = payload.get("covered_targets") if isinstance(payload, dict) else None
    coverage = None
    if isinstance(targets, list) and 0 < len(targets) <= 256 and all(isinstance(t, str) and 0 < len(t.strip()) <= 255 for t in targets):
        try:
            networks = [ipaddress.ip_network(target.strip(), strict=False) for target in targets]
            if all(any(ipaddress.ip_address(address) in network for network in networks) for address in observed):
                coverage = sorted({str(network) for network in networks})
        except ValueError:
            pass  # Invalid or descriptive scopes cannot confirm network absence.
    return {"hosts": observed, "covered_targets": coverage}


def port_was_scanned(host, protocol, number):
    coverage = host.get("scanned_ports")
    if not isinstance(coverage, dict):
        return False
    ranges = coverage.get(protocol)
    return isinstance(ranges, list) and any(
        isinstance(row, list) and len(row) == 2 and all(type(x) is int for x in row)
        and 1 <= row[0] <= number <= row[1] <= 65535 for row in ranges)


def compare_snapshots(previous: dict, current: dict, *, previous_status: str, current_status: str,
                      selection_complete: bool = True) -> dict:
    before, after = previous["hosts"], current["hosts"]
    reasons = []
    if previous_status != "completed" or current_status != "completed":
        reasons.append("Both runs must have explicit completed job-status evidence before absence can be confirmed.")
    old_targets, new_targets = previous["covered_targets"], current["covered_targets"]
    if old_targets is None or new_targets is None:
        reasons.append("Covered targets were not explicitly reported by both selected result snapshots.")
    elif old_targets != new_targets:
        reasons.append("Selected snapshots report different covered targets.")
    if not selection_complete:
        reasons.append("Malformed or bounded-out newer result evidence prevents complete snapshot selection.")
    comparable = not reasons
    added = sorted(set(after) - set(before))
    absent = sorted(set(before) - set(after))
    changes = []
    for host in sorted(set(before) & set(after)):
        old, new = before[host]["ports"], after[host]["ports"]
        full_ports = before[host]["ports_complete"] and after[host]["ports_complete"]
        for protocol, number in sorted(set(old) | set(new)):
            identity = (protocol, number)
            complete_ports = comparable and (full_ports or (port_was_scanned(before[host], protocol, number)
                                                           and port_was_scanned(after[host], protocol, number)))
            old_value, new_value = old.get(identity), new.get(identity)
            if old_value == new_value:
                continue
            if old_value is None:
                kind, confirmed = "newly_observed", False
            elif new_value is None:
                kind, confirmed = ("removed", True) if complete_ports else ("not_observed", False)
            else:
                known_changes = [field for field in ("state", "product", "version")
                                 if old_value[field] is not None and new_value[field] is not None
                                 and old_value[field] != new_value[field]]
                old_service, new_service = old_value["service"], new_value["service"]
                if isinstance(old_service, str) and isinstance(new_service, str) and old_service != new_service:
                    known_changes.append("service")
                elif isinstance(old_service, dict) and isinstance(new_service, dict):
                    if any(old_service[field] is not None and new_service[field] is not None
                           and old_service[field] != new_service[field] for field in old_service.keys() & new_service.keys()):
                        known_changes.append("service")
                kind, confirmed = ("state_service_changed", True) if known_changes else ("evidence_changed", False)
            changes.append({"host": host, "protocol": protocol, "port": number, "change": kind,
                            "confirmed": confirmed, "before": old_value, "after": new_value})
    return {"available": True, "coverage": {"comparable": comparable, "previous_targets": old_targets,
                "current_targets": new_targets, "reasons": reasons},
            "hosts_added": added[:MAX_CHANGES], "hosts_removed": absent[:MAX_CHANGES] if comparable else [],
            "hosts_not_observed": absent[:MAX_CHANGES] if not comparable else [],
            "port_changes": changes[:MAX_CHANGES],
            "counts": {"hosts_added": len(added), "hosts_removed": len(absent) if comparable else 0,
                       "hosts_not_observed": len(absent) if not comparable else 0, "port_changes": len(changes),
                       "newly_observed_ports": sum(row["change"] == "newly_observed" for row in changes),
                       "reported_port_changes": sum(row["change"] == "state_service_changed" for row in changes),
                       "confirmed_removed_ports": sum(row["change"] == "removed" and row["confirmed"] is True for row in changes)},
            "truncated": max(len(added), len(absent), len(changes)) > MAX_CHANGES,
            "limitations": ["Only the latest valid deep-scan result event from each run is compared; phases are never merged.",
                "Added hosts and ports are newly observed, not proof they are newly deployed.",
                "Absent ports require explicit complete port coverage in both snapshots; absence does not prove a port is closed.",
                "Coverage and completion are scanner-reported evidence, not independent network attestation."]}
