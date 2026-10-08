"""Scoped managed LLDP/CDP neighbors; raw discovery identities are discarded."""
import re
from typing import Any

MAX_PORTS = 1024
PORT = re.compile(r"[A-Za-z0-9_./ -]{1,64}")
SCOPE = ("LLDP/CDP observations keyed by local switch port, matched only to assigned devices in the "
         "same saved network. Discovery can be stale or incomplete; it does not verify cabling, "
         "traffic direction, link capacity or a complete topology. Unmatched/ambiguous identities "
         "and raw discovery names, addresses and descriptions are not saved.")


def _identity(value: Any) -> list[str]:
    if not isinstance(value, str) or not value or len(value) > 128:
        return []
    result = []
    if re.fullmatch(r"[A-Za-z0-9_-]{1,128}", value):
        result.append("serial:" + value.casefold())
    if re.fullmatch(r"(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}|[0-9a-fA-F]{12}", value):
        result.append("mac:" + value.replace(":", "").replace("-", "").casefold())
    return result


def inventory_lookup(devices: list, network_id: str) -> dict[str, str | None]:
    lookup = {}
    if not isinstance(network_id, str) or not network_id:
        return lookup
    for device in devices:
        if not isinstance(device, dict) or device.get("networkId") != network_id or not isinstance(device.get("serial"), str):
            continue
        serial = device["serial"]
        for value in (serial, device.get("mac")):
            for identity in _identity(value):
                if identity in lookup and lookup[identity] != serial:
                    lookup[identity] = None
                else:
                    lookup[identity] = serial
    return lookup


def summarize_neighbors(raw: Any, lookup: dict, local_serial: str) -> dict:
    ports = raw.get("ports") if isinstance(raw, dict) else None
    if not isinstance(ports, dict) or len(ports) > MAX_PORTS:
        raise ValueError("Invalid LLDP/CDP port map")
    rows = []
    for port, discovery in sorted(ports.items(), key=lambda item: str(item[0])):
        if not isinstance(port, str) or not port.strip() or not PORT.fullmatch(port) or not isinstance(discovery, dict):
            raise ValueError("Invalid LLDP/CDP port record")
        candidates, protocols, remote_ports = set(), set(), set()
        ambiguous = False
        def match(value, protocol, remote_port=None):
            nonlocal ambiguous
            for identity in _identity(value):
                if identity not in lookup:
                    continue
                serial = lookup[identity]
                if serial is None or serial == local_serial:
                    ambiguous = True
                    continue
                candidates.add(serial); protocols.add(protocol)
                if isinstance(remote_port, str) and remote_port.strip() and PORT.fullmatch(remote_port):
                    remote_ports.add(remote_port)
        match(discovery.get("deviceMac"), "deviceMac")
        for protocol, field in (("lldp", "chassisId"), ("cdp", "deviceId")):
            details = discovery.get(protocol)
            if details is None:
                continue
            if not isinstance(details, dict):
                raise ValueError("Invalid LLDP/CDP protocol record")
            match(details.get(field), protocol, details.get("portId"))
        status = "ambiguous" if ambiguous or len(candidates) > 1 else "matched" if candidates else "unmatched"
        rows.append({"local_port": port, "status": status,
            "neighbor_serial": next(iter(candidates)) if status == "matched" else None,
            "neighbor_port": next(iter(remote_ports)) if status == "matched" and len(remote_ports) == 1 else None,
            "remote_port_conflict": status == "matched" and len(remote_ports) > 1,
            "protocols": sorted(protocols) if status == "matched" else []})
    return {"schema_version": 1, "scope": SCOPE, "reported_port_count": len(rows),
            **{key + "_port_count": sum(row["status"] == key for row in rows) for key in ("matched", "unmatched", "ambiguous")},
            "rows": rows}


def project_neighbors(snapshot: dict, *, complete: bool = False) -> dict:
    devices = snapshot.get("devices") if isinstance(snapshot.get("devices"), list) else []
    by_id = {d['serial']: d for d in devices if isinstance(d, dict) and isinstance(d.get('serial'), str)}
    observations = snapshot.get("switch_neighbors") if isinstance(snapshot.get("switch_neighbors"), list) else []
    results = []
    for observation in observations[:1000 if complete else 20]:
        if not isinstance(observation, dict):
            continue
        local_id = observation.get("device_serial")
        local = by_id.get(local_id, {}) if isinstance(local_id, str) else {}
        network_id = observation.get("network_id")
        scoped = bool(local and isinstance(network_id, str) and network_id and local.get("networkId") == network_id and (local.get("productType") == "switch" or str(local.get("model", "")).startswith("MS")))
        def text(value): return value[:200] if isinstance(value, str) else ""
        result = {"device_name": text(local.get("name")) or text(local.get("model")),
            "network_name": text(observation.get("network_name")), "status": text(observation.get("status")), "data": None}
        data = observation.get("data")
        if result["status"] == "complete" and isinstance(data, dict) and type(data.get("schema_version")) is int and data["schema_version"] == 1:
            raw_rows = data.get("rows")
            rows, seen, invalid = [], set(), not scoped or not isinstance(raw_rows, list) or len(raw_rows) > MAX_PORTS
            for row in raw_rows if not invalid else []:
                port = row.get("local_port") if isinstance(row, dict) else None
                if not isinstance(port, str) or not port.strip() or not PORT.fullmatch(port) or port in seen or row.get("status") not in ("matched", "unmatched", "ambiguous"):
                    invalid = True; break
                seen.add(port)
                neighbor_id = row.get("neighbor_serial")
                neighbor = by_id.get(neighbor_id, {}) if isinstance(neighbor_id, str) else {}
                matched = row["status"] == "matched" and neighbor and local and neighbor.get("networkId") == local.get("networkId") == observation.get("network_id") and neighbor.get("serial") != local.get("serial")
                if row["status"] == "matched" and not matched:
                    invalid = True; break
                remote = row.get("neighbor_port")
                rows.append({"local_port": port, "status": row["status"],
                    "neighbor_name": (text(neighbor.get("name")) or text(neighbor.get("model"))) if matched else None,
                    "neighbor_model": text(neighbor.get("model")) if matched else None,
                    "neighbor_port": remote if matched and isinstance(remote, str) and PORT.fullmatch(remote) else None,
                    "remote_port_conflict": row.get("remote_port_conflict") is True if matched else False,
                    "protocols": [p for p in ("lldp", "cdp", "deviceMac") if p in row["protocols"]] if matched and isinstance(row.get("protocols"), list) else []})
            if invalid:
                result["status"] = "invalid_evidence"
            else:
                limit = MAX_PORTS if complete else 50
                result["data"] = {"rows": rows[:limit], "additional_rows": max(0, len(rows) - limit), "reported_port_count": len(rows),
                    **{key + "_port_count": sum(row["status"] == key for row in rows) for key in ("matched", "unmatched", "ambiguous")}}
        results.append(result)
    return {"scope": SCOPE, "switches": results, "additional_switches": max(0, len(observations) - len(results))}
