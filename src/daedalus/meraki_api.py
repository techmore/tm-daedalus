from __future__ import annotations

import json
import math
import re
import time
from collections import Counter
from datetime import UTC, datetime
from typing import Any, Callable
from urllib.parse import urlsplit

import httpx


MERAKI_API_BASE = "https://api.meraki.com/api/v1"
MERAKI_API_HOST = "api.meraki.com"
MERAKI_PAGE_SIZE = 1000
MAX_PAGINATION_PAGES = 500
MAX_NETWORKS_PER_REPORT = 500
MAX_SWITCHES_PER_REPORT = 1000
MAX_ACCESS_POINTS_PER_REPORT = 1000
MAX_TOPOLOGY_NODES = 5000
MAX_TOPOLOGY_LINKS = 10000
CLIENT_USAGE_TIMESPAN = 86400
SWITCH_POWER_TIMESPAN = 86400
MAX_COLLECTION_ITEMS = 50_000
SENSITIVE_KEYS = {
    "access_token",
    "api_key",
    "apikey",
    "authorization",
    "client_secret",
    "password",
    "passphrase",
    "private_key",
    "psk",
    "radius_secret",
    "secret",
    "shared_secret",
    "token",
    "wpa_psk",
}


class MerakiAPIError(RuntimeError):
    def __init__(self, message: str, status_code: int | None = None):
        super().__init__(message)
        self.status_code = status_code


MAX_APPLIANCES_PER_REPORT = 1000


def summarize_wan_uplinks(raw: Any, managed_networks: dict[str, str]) -> dict[str, Any]:
    """Documented link states only; omit addresses and do not infer circuit capacity."""
    if not isinstance(raw, list) or len(raw) > MAX_APPLIANCES_PER_REPORT:
        raise MerakiAPIError("WAN uplink evidence exceeds its supported array shape or limit.")
    seen, rows, omitted = set(), [], 0
    states = {"active", "connecting", "failed", "not connected", "ready"}
    for item in raw:
        serial = item.get("serial") if isinstance(item, dict) else None
        if (not isinstance(serial, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", serial)
                or serial in seen):
            raise MerakiAPIError("WAN uplink evidence requires unique device identifiers.")
        seen.add(serial)
        if serial not in managed_networks:
            omitted += 1
            continue
        if item.get("networkId") != managed_networks[serial]:
            raise MerakiAPIError("WAN uplink evidence does not match assigned network inventory.")
        uplinks = item.get("uplinks")
        if not isinstance(uplinks, list) or len(uplinks) > 4:
            raise MerakiAPIError("WAN uplink evidence returned an unsupported interface array.")
        reported_at = item.get("lastReportedAt")
        try:
            if (not isinstance(reported_at, str) or len(reported_at) > 64
                    or datetime.fromisoformat(reported_at.replace("Z", "+00:00")).tzinfo is None):
                reported_at = None
        except ValueError:
            reported_at = None
        interfaces = set()
        for uplink in uplinks:
            interface = uplink.get("interface") if isinstance(uplink, dict) else None
            if interface not in {"wan1", "wan2", "wan3", "cellular"} or interface in interfaces:
                raise MerakiAPIError("WAN uplink evidence requires unique supported interfaces.")
            interfaces.add(interface)
            state = uplink.get("status")
            rows.append({"device_serial": serial, "network_id": managed_networks[serial],
                         "interface": interface, "state": state if isinstance(state, str) and state in states else "unknown",
                         "last_reported_at": reported_at})
    rows.sort(key=lambda row: (row["device_serial"], row["interface"]))
    return {"rows": rows, "reported_device_count": len(managed_networks.keys() & seen),
            "expected_device_count": len(managed_networks),
            "missing_device_count": len(managed_networks.keys() - seen),
            "omitted_device_count": omitted, "interface_count": len(rows),
            "state_counts": dict(sorted(Counter(row["state"] for row in rows).items())),
            "scope": "Current reported interface states; no circuit capacity, throughput or outage determination."}


WIRELESS_CONNECTION_TIMESPAN = 86400


def summarize_wireless_connections(raw: Any, managed_serials: set[str]) -> dict[str, Any]:
    """Retain documented per-AP counters, without inventing a total/success rate."""
    if not isinstance(raw, list) or len(raw) > MAX_ACCESS_POINTS_PER_REPORT:
        raise MerakiAPIError("Wireless connection evidence exceeds its supported array shape or limit.")
    fields = ("assoc", "auth", "dhcp", "dns", "success")
    seen, rows, omitted = set(), [], 0
    for item in raw:
        serial = item.get("serial") if isinstance(item, dict) else None
        if (not isinstance(serial, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", serial)
                or serial in seen):
            raise MerakiAPIError("Wireless connection evidence requires unique device identifiers.")
        seen.add(serial)
        if serial not in managed_serials:
            omitted += 1
            continue
        source = item.get("connectionStats")
        if not isinstance(source, dict):
            source = {}
        counters = {key: value for key in fields
                    if type(value := source.get(key)) is int and 0 <= value <= 1_000_000_000_000}
        rows.append({"device_serial": serial, "counters": counters,
                     "counter_coverage": "complete" if len(counters) == len(fields) else "partial"})
    rows.sort(key=lambda row: row["device_serial"])
    totals = {key: sum(row["counters"][key] for row in rows if key in row["counters"])
              for key in fields if any(key in row["counters"] for row in rows)}
    return {"requested_timespan_seconds": WIRELESS_CONNECTION_TIMESPAN,
            "devices": rows, "reported_device_count": len(rows),
            "expected_device_count": len(managed_serials),
            "missing_device_count": len(managed_serials - seen),
            "omitted_device_count": omitted, "observed_counter_totals": totals,
            "counter_coverage": "complete" if rows and managed_serials <= seen
                and all(row["counter_coverage"] == "complete" for row in rows) else "partial"}


def summarize_channel_utilization(raw: Any, managed_networks: dict[str, str]) -> dict[str, Any]:
    """Keep documented per-band averages, not legacy flattened fields."""
    if not isinstance(raw, list) or len(raw) > MAX_ACCESS_POINTS_PER_REPORT:
        raise MerakiAPIError("Channel utilization exceeds its supported array shape or limit.")
    seen, rows, omitted = set(), [], 0
    for item in raw:
        serial = item.get("serial") if isinstance(item, dict) else None
        if (not isinstance(serial, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", serial) or serial in seen):
            raise MerakiAPIError("Channel utilization requires unique device identifiers.")
        seen.add(serial)
        if serial not in managed_networks:
            omitted += 1
            continue
        network = item.get("network")
        if not isinstance(network, dict) or network.get("id") != managed_networks[serial]:
            raise MerakiAPIError("Channel utilization does not match assigned network inventory.")
        bands = item.get("byBand")
        if not isinstance(bands, list) or len(bands) > 3:
            raise MerakiAPIError("Channel utilization returned an unsupported band array.")
        band_names = set()
        for band in bands:
            name = band.get("band") if isinstance(band, dict) else None
            if name not in ("2.4", "5", "6") or name in band_names:
                raise MerakiAPIError("Channel utilization requires unique supported bands.")
            band_names.add(name)
            values = {}
            for field in ("wifi", "nonWifi", "total"):
                data = band.get(field)
                value = data.get("percentage") if isinstance(data, dict) else None
                if type(value) in (int, float) and math.isfinite(value) and 0 <= value <= 100:
                    values[field] = value
            rows.append({"device_serial": serial, "network_id": managed_networks[serial], "band": name,
                "percentages": values, "measurement_coverage": "complete" if len(values) == 3 else "partial",
                "review_threshold_met": values.get("total", -1) >= 50 or values.get("nonWifi", -1) >= 20})
    rows.sort(key=lambda row: (not row["review_threshold_met"], row["device_serial"], row["band"]))
    return {"requested_timespan_seconds": 86400, "rows": rows,
            "reported_device_count": len({row["device_serial"] for row in rows}),
            "expected_device_count": len(managed_networks),
            "missing_device_count": len(set(managed_networks) - {row["device_serial"] for row in rows}),
            "omitted_device_count": omitted, "measured_band_count": sum(bool(row["percentages"]) for row in rows),
            "review_band_count": sum(row["review_threshold_met"] for row in rows),
            "review_thresholds_percent": {"total": 50, "nonWifi": 20}}


def summarize_switch_power(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Aggregate allowlisted energy, without inferring missing measurements."""
    identities = set()
    energy = []
    allocated = 0
    for row in rows:
        identifier = row.get("portId")
        if not isinstance(identifier, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", identifier) or identifier in identities:
            raise MerakiAPIError("Switch power observations require unique port identifiers.")
        identities.add(identifier)
        value = row.get("powerUsageInWh")
        if type(value) in (int, float) and 0 <= value <= 1_000_000_000_000 and math.isfinite(value):
            energy.append(value)
        poe = row.get("poe")
        if isinstance(poe, dict) and poe.get("isAllocated") is True:
            allocated += 1
    total = round(sum(energy), 3) if energy else None
    return {"port_count": len(rows), "measured_port_count": len(energy),
            "unmeasured_port_count": len(rows) - len(energy),
            "allocated_port_count": allocated,
            "measured_energy_wh": total,
            "measured_average_watts": round(total / 24, 3) if total is not None else None,
            "energy_coverage": "complete" if rows and len(energy) == len(rows) else "partial" if energy else "unavailable",
            "requested_timespan_seconds": SWITCH_POWER_TIMESPAN}


def redact_meraki_data(value: Any) -> Any:
    """Remove credentials from arbitrarily nested API data before it is saved."""
    if isinstance(value, dict):
        clean: dict[str, Any] = {}
        for key, item in value.items():
            normalized = re.sub(r"[^a-z0-9]+", "_", str(key).casefold()).strip("_")
            compact = normalized.replace("_", "")
            if normalized in SENSITIVE_KEYS or compact in {
                "apikey",
                "accesstoken",
                "clientsecret",
                "privatekey",
                "sharedsecret",
                "radiussecret",
                "wpasseskey",
            }:
                continue
            clean[str(key)] = redact_meraki_data(item)
        return clean
    if isinstance(value, list):
        return [redact_meraki_data(item) for item in value]
    return value



# Fields follow the public Meraki OpenAPI schemas, not arbitrary cached payloads:
# https://github.com/meraki/openapi/blob/master/openapi/spec3.json
RF_BAND_FIELDS = {key: None for key in ("maxPower", "minPower", "minBitrate", "validAutoChannels", "channelWidth", "rxsop", "axEnabled")}
RF_BAND_FIELDS["dot11ax"] = {"enabled": None}
RF_SSID_FIELDS = {key: None for key in ("name", "minBitrate", "bandOperationMode", "bandSteeringEnabled")}
RF_SSID_FIELDS["bands"] = {"enabled": None}
RF_PROFILE_FIELDS = {key: None for key in ("id", "networkId", "name", "clientBalancingEnabled", "minBitrateType", "bandSelectionType", "isIndoorDefault", "isOutdoorDefault")}
RF_PROFILE_FIELDS.update({
    "twoFourGhzSettings": RF_BAND_FIELDS, "fiveGhzSettings": RF_BAND_FIELDS,
    "sixGhzSettings": RF_BAND_FIELDS,
    "apBandSettings": {"bandOperationMode": None, "bandSteeringEnabled": None, "bands": {"enabled": None}},
    "transmission": {"enabled": None}, "dot11be": {"enabled": None},
    "perSsidSettings": {str(index): RF_SSID_FIELDS for index in range(15)},
})
RF_ASSIGNMENT_FIELDS = {"rfProfileId": None, "twoFourGhzSettings": {"channel": None, "targetPower": None}, "fiveGhzSettings": {"channel": None, "channelWidth": None, "targetPower": None}}
LICENSE_FIELDS = {"status": None, "expirationDate": None, "licenseCount": None,
    "states": {state: {"count": None} for state in ("active", "expired", "expiring", "recentlyQueued", "unused", "unusedActive")},
    "systemsManager": {"counts": {key: None for key in ("totalSeats", "activeSeats", "unassignedSeats", "orgwideEnrolledDevices")}},
}


def _known_fields(value: dict[str, Any], fields: dict[str, Any]) -> dict[str, Any]:
    """Retain schema-known primitives only; never preserve unknown nested fields."""
    result = {}
    for key, schema in fields.items():
        if key not in value:
            continue
        item = value[key]
        if schema is not None:
            if isinstance(item, dict):
                result[key] = _known_fields(item, schema)
        elif item is None or isinstance(item, (str, bool, int, float)):
            result[key] = item
        elif isinstance(item, list) and all(entry is None or isinstance(entry, (str, bool, int, float)) for entry in item):
            result[key] = item
    return redact_meraki_data(result)


def _managed_topology(raw: Any, serials: set[str]) -> dict[str, Any]:
    """Drop discovered/client identities; join graph nodes to assigned inventory only."""
    if not isinstance(raw, dict) or not isinstance(raw.get("nodes"), list) or not isinstance(raw.get("links"), list):
        raise MerakiAPIError("The Meraki API returned an unexpected topology shape.")
    if len(raw["nodes"]) > MAX_TOPOLOGY_NODES or len(raw["links"]) > MAX_TOPOLOGY_LINKS:
        raise MerakiAPIError("The topology exceeded this report's node/link limits.")
    node_ids: dict[str, str] = {}
    nodes: dict[str, dict[str, Any]] = {}
    for node in raw["nodes"]:
        if not isinstance(node, dict):
            continue
        device = node.get("device")
        serial = device.get("serial") if isinstance(device, dict) else None
        if not isinstance(serial, str) or serial not in serials:
            continue
        node_id = node.get("derivedId")
        if isinstance(node_id, str):
            node_ids[node_id] = serial
        nodes[serial] = {"device_serial": serial, "root": node.get("root") is True}
    pairs: Counter[tuple[str, str]] = Counter()
    retained_links = 0
    for link in raw["links"]:
        ends = link.get("ends") if isinstance(link, dict) else None
        if not isinstance(ends, list) or len(ends) != 2:
            continue
        endpoints = []
        for end in ends:
            if not isinstance(end, dict):
                break
            device, node = end.get("device"), end.get("node")
            serial = device.get("serial") if isinstance(device, dict) else None
            if not isinstance(serial, str) or serial not in nodes:
                reference = node.get("derivedId") if isinstance(node, dict) else None
                serial = node_ids.get(reference) if isinstance(reference, str) else None
            if serial not in nodes:
                break
            endpoints.append(serial)
        if len(endpoints) == 2 and endpoints[0] != endpoints[1]:
            pairs[tuple(sorted(endpoints))] += 1
            retained_links += 1
    return {
        "nodes": [nodes[key] for key in sorted(nodes)],
        "links": [{"device_serials": list(pair), "link_count": count} for pair, count in sorted(pairs.items())],
        "omitted_node_count": len(raw["nodes"]) - len(nodes),
        "omitted_link_count": len(raw["links"]) - retained_links,
        "reported_error_count": len(raw["errors"]) if isinstance(raw.get("errors"), list) else 0,
        "scope": "Assigned managed devices only; discovered nodes and client identities are omitted.",
    }


def _aggregate_client_usage(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise MerakiAPIError("The Meraki API returned an unexpected client usage shape.")
    counts, usage = raw.get("counts"), raw.get("usage")
    total = counts.get("total") if isinstance(counts, dict) else None
    overall = usage.get("overall") if isinstance(usage, dict) else None
    if not isinstance(total, int) or isinstance(total, bool) or total < 0 or not isinstance(overall, dict):
        raise MerakiAPIError("Aggregate client counts or usage totals are missing.")
    clean_usage = {}
    for key in ("total", "downstream", "upstream"):
        value = overall.get(key)
        if not isinstance(value, (int, float)) or isinstance(value, bool) or not math.isfinite(value) or value < 0:
            raise MerakiAPIError("Aggregate client usage has an unsupported numeric value.")
        clean_usage[key] = value
    return {"clients_with_usage_count": total, "usage": clean_usage, "usage_unit": "kb (Meraki API)", "requested_timespan_seconds": CLIENT_USAGE_TIMESPAN}

def _safe_meraki_next_url(current_url: httpx.URL, next_url: str) -> str:
    candidate = current_url.join(next_url)
    path = candidate.path
    if (
        candidate.scheme != "https"
        or candidate.host != MERAKI_API_HOST
        or candidate.port not in (None, 443)
        or not path.startswith("/api/v1/") and path != "/api/v1"
    ):
        raise MerakiAPIError("The Meraki API returned an unsafe pagination link.")
    return str(candidate)


class MerakiClient:
    """Small, read-only Cisco Meraki Dashboard API v1 client."""

    def __init__(
        self,
        api_key: str,
        *,
        transport: httpx.BaseTransport | None = None,
        request_interval: float = 0.12,
    ) -> None:
        if not api_key or len(api_key) > 256:
            raise MerakiAPIError("Enter a valid Meraki API key.")
        self._http = httpx.Client(
            base_url=MERAKI_API_BASE.rstrip("/") + "/",
            headers={
                "Accept": "application/json",
                "X-Cisco-Meraki-API-Key": api_key,
                "User-Agent": "Daedalus-CSP/0.1",
            },
            timeout=httpx.Timeout(25.0, connect=10.0),
            follow_redirects=False,
            transport=transport,
        )
        self._request_interval = max(0.0, request_interval)
        self._last_request_at = 0.0

    def close(self) -> None:
        self._http.close()

    def __enter__(self) -> "MerakiClient":
        return self

    def __exit__(self, *_args: Any) -> None:
        self.close()

    def _get(self, path_or_url: str, params: dict[str, Any] | None = None) -> httpx.Response:
        url = path_or_url
        if urlsplit(url).scheme:
            parsed = httpx.URL(url)
            if (
                parsed.scheme != "https"
                or parsed.host != MERAKI_API_HOST
                or parsed.port not in (None, 443)
                or not parsed.path.startswith("/api/v1/") and parsed.path != "/api/v1"
            ):
                raise MerakiAPIError("A request outside the Meraki API host was blocked.")
        else:
            url = url.lstrip("/")

        attempts = 0
        while True:
            delay = self._request_interval - (time.monotonic() - self._last_request_at)
            if delay > 0:
                time.sleep(delay)
            try:
                response = self._http.get(url, params=params)
            except httpx.TimeoutException as exc:
                raise MerakiAPIError("The Meraki API request timed out.") from exc
            except httpx.HTTPError as exc:
                raise MerakiAPIError("Could not connect to the Meraki Dashboard API.") from exc
            self._last_request_at = time.monotonic()
            if response.status_code == 429 and attempts < 1:
                retry_after = response.headers.get("Retry-After", "1")
                try:
                    pause = min(3.0, max(0.0, float(retry_after)))
                except ValueError:
                    pause = 1.0
                attempts += 1
                time.sleep(pause)
                continue
            if 300 <= response.status_code < 400:
                raise MerakiAPIError("The Meraki API returned an unexpected redirect.", response.status_code)
            if response.status_code >= 400:
                if response.status_code in (401, 403):
                    message = "The Meraki key was rejected or lacks the required read permission."
                elif response.status_code == 404:
                    message = "The Meraki resource is not available for this organization or product."
                elif response.status_code == 429:
                    message = "The Meraki API rate limit was reached. Retry after a short pause."
                elif response.status_code >= 500:
                    message = "The Meraki Dashboard API is temporarily unavailable."
                else:
                    message = f"The Meraki Dashboard API request failed (HTTP {response.status_code})."
                raise MerakiAPIError(message, response.status_code)
            return response

    @staticmethod
    def _json(response: httpx.Response) -> Any:
        try:
            return response.json()
        except ValueError as exc:
            raise MerakiAPIError("The Meraki API returned an invalid JSON response.") from exc

    def get_json(self, path: str, *, params: dict[str, Any] | None = None) -> Any:
        return self._json(self._get(path, params=params))

    def get_collection(self, path: str, *, params: dict[str, Any] | None = None) -> list[Any]:
        next_url = path
        query = {"perPage": MERAKI_PAGE_SIZE}
        if params:
            query.update(params)
        items: list[Any] = []
        seen: set[str] = set()
        for _page in range(MAX_PAGINATION_PAGES):
            response = self._get(next_url, params=query if next_url == path else None)
            payload = self._json(response)
            if isinstance(payload, list):
                items.extend(payload)
            elif isinstance(payload, dict) and isinstance(payload.get("items"), list):
                items.extend(payload["items"])
            else:
                raise MerakiAPIError("The Meraki API returned an unexpected collection shape.")
            if len(items) > MAX_COLLECTION_ITEMS:
                raise MerakiAPIError(
                    f"This report is limited to {MAX_COLLECTION_ITEMS} items per collection."
                )
            link = response.links.get("next")
            href = link.get("url") if link else None
            if not href:
                return items
            next_url = _safe_meraki_next_url(response.url, str(href))
            if next_url in seen:
                raise MerakiAPIError("The Meraki API returned a repeated pagination link.")
            seen.add(next_url)
        raise MerakiAPIError("The Meraki API exceeded the page limit for this request.")

    def list_organizations(self) -> list[dict[str, Any]]:
        rows = self.get_collection("/organizations")
        organizations: list[dict[str, Any]] = []
        for row in rows:
            if (
                not isinstance(row, dict)
                or not row.get("id")
                or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", str(row["id"]))
            ):
                continue
            organizations.append(
                {
                    "id": str(row["id"]),
                    "name": str(row.get("name") or row["id"])[:200],
                }
            )
        return organizations

    @staticmethod
    def _require_unique_inventory(rows: list[Any], identifier: str, collection: str) -> None:
        """Reject incomplete identities before inventory drives comparisons or budgets."""
        seen: set[str] = set()
        for row in rows:
            value = row.get(identifier) if isinstance(row, dict) else None
            if (not isinstance(value, str)
                    or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", value)
                    or value in seen):
                raise MerakiAPIError(
                    f"The Meraki {collection} inventory contains missing, invalid or duplicate identities; "
                    "no complete audit was saved."
                )
            seen.add(value)

    def collect_security_report(
        self,
        organization_id: str,
        *,
        progress: Callable[[int, str], None] | None = None,
    ) -> dict[str, Any]:
        report_orgs = self.list_organizations()
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", str(organization_id)):
            raise MerakiAPIError("Select a valid Meraki organization.")
        organization = next(
            (row for row in report_orgs if row["id"] == str(organization_id)),
            None,
        )
        if organization is None:
            raise MerakiAPIError("The selected Meraki organization is not accessible by this key.", 403)

        if progress:
            progress(16, "Reading organization networks")
        networks_raw = self.get_collection(f"/organizations/{organization_id}/networks")
        self._require_unique_inventory(networks_raw, "id", "network")
        networks = [self._safe_network(row) for row in networks_raw]
        if len(networks) > MAX_NETWORKS_PER_REPORT:
            raise MerakiAPIError(
                f"This report is limited to {MAX_NETWORKS_PER_REPORT} networks per run."
            )

        if progress:
            progress(28, "Reading assigned device inventory")
        devices_raw = self.get_collection(f"/organizations/{organization_id}/devices")
        self._require_unique_inventory(devices_raw, "serial", "device")

        if progress:
            progress(38, "Reading current device availability")
        availability_raw = self.get_collection(
            f"/organizations/{organization_id}/devices/availabilities"
        )
        availability = {
            str(row.get("serial")): row
            for row in availability_raw
            if isinstance(row, dict) and row.get("serial")
        }

        device_fields = (
            "name", "serial", "model", "networkId", "productType", "firmware", "lanIp"
        )
        devices: list[dict[str, Any]] = []
        for raw in devices_raw:
            if not isinstance(raw, dict):
                continue
            item = {key: raw[key] for key in device_fields if key in raw}
            status = availability.get(str(raw.get("serial")), {})
            if status.get("status") is not None:
                item["status"] = status["status"]
            if status.get("lastReportedAt") is not None:
                item["lastReportedAt"] = status["lastReportedAt"]
            devices.append(item)

        appliance_networks = [
            network for network in networks
            if "appliance" in network.get("productTypes", [])
        ]
        endpoint_specs = (
            ("L3 firewall rules", "firewall/l3FirewallRules"),
            ("L7 firewall rules", "firewall/l7FirewallRules"),
            ("Inbound firewall rules", "firewall/inboundFirewallRules"),
            ("Content filtering", "contentFiltering"),
            ("Intrusion protection", "security/intrusion"),
            ("Malware protection", "security/malware"),
        )
        security: list[dict[str, Any]] = []
        warnings: list[str] = []
        total = max(1, len(appliance_networks))
        for index, network in enumerate(appliance_networks, start=1):
            network_id = str(network["id"])
            network_name = network.get("name") or network_id
            if progress:
                percent = 42 + int(index / total * 42)
                progress(percent, f"Checking appliance network {index}/{total}: {network_name}")
            for title, suffix in endpoint_specs:
                path = f"/networks/{network_id}/appliance/{suffix}"
                try:
                    payload = redact_meraki_data(self.get_json(path))
                    status = "complete"
                except MerakiAPIError as exc:
                    status = "unsupported" if exc.status_code == 404 else "unavailable"
                    payload = None
                    if status == "unavailable":
                        warnings.append(
                            f"{network_name}: {title} could not be read ({exc.status_code or 'connection error'})."
                        )
                security.append(
                    {
                        "network_id": network_id,
                        "network_name": network_name,
                        "control": title,
                        "status": status,
                        "data": payload,
                    }
                )

        wireless_networks = [network for network in networks if "wireless" in network["productTypes"]]
        switch_networks = [network for network in networks if "switch" in network["productTypes"]]
        switches = [device for device in devices if device.get("productType") == "switch" or str(device.get("model", "")).startswith("MS")]
        if len(switches) > MAX_SWITCHES_PER_REPORT:
            raise MerakiAPIError(f"This report is limited to {MAX_SWITCHES_PER_REPORT} switches per run.")

        # The SSID, switch-port and access-policy endpoints return JSON arrays;
        # unlike organization inventory they do not expose page-token parameters.
        # All reads still use the same protected host, rate limit and retry path.
        switch_power = []
        def collect_array(path: str, title: str, network: dict[str, Any], fields: tuple[str, ...], *, serial: str | None = None, schema: dict[str, Any] | None = None, power: bool = False) -> None:
            power_data = None
            try:
                raw = self.get_json(path, params={"timespan": SWITCH_POWER_TIMESPAN}) if power else self.get_json(path)
                if not isinstance(raw, list) or any(not isinstance(row, dict) for row in raw):
                    raise MerakiAPIError("The Meraki API returned an unexpected configuration array.")
                if title == "Wireless RF profiles" and any(not isinstance(row.get("id"), str) or not row["id"] for row in raw):
                    raise MerakiAPIError("The Meraki API returned an RF profile without a stable identifier.")
                if len(raw) > MAX_COLLECTION_ITEMS:
                    raise MerakiAPIError("The Meraki configuration array exceeded the collection limit.")
                payload = [_known_fields(row, schema) if schema is not None else redact_meraki_data({key: row[key] for key in fields if key in row}) for row in raw]
                if power:
                    try:
                        power_data = summarize_switch_power(raw)
                    except MerakiAPIError:
                        power_data = {"energy_coverage": "invalid_evidence", "requested_timespan_seconds": SWITCH_POWER_TIMESPAN}
                status = "complete"
            except MerakiAPIError as exc:
                status = "unsupported" if exc.status_code == 404 else "unavailable"
                payload = None
                if status == "unavailable":
                    warnings.append(f"{network['name']}: {title} could not be read ({exc.status_code or 'response error'}).")
            security.append({
                "network_id": network["id"], "network_name": network["name"],
                "control": title, "status": status, "data": payload,
                **({"device_serial": serial} if serial else {}),
            })
            if power:
                switch_power.append({"device_serial": serial, "network_name": network["name"],
                                     "status": status, "data": power_data})

        def collect_object(path: str, title: str, network: dict[str, Any], schema: dict[str, Any], *, serial: str | None = None) -> dict[str, Any]:
            try:
                raw = self.get_json(path)
                if not isinstance(raw, dict):
                    raise MerakiAPIError("The Meraki API returned an unexpected configuration object.")
                if title == "Wireless RF assignment" and ("rfProfileId" not in raw or raw["rfProfileId"] is not None and not isinstance(raw["rfProfileId"], str)):
                    raise MerakiAPIError("The Meraki API returned an RF assignment without a profile reference.")
                if title == "Licensing overview" and not any(key in raw for key in ("status", "licenseCount", "licensedDeviceCounts", "states", "systemsManager")):
                    raise MerakiAPIError("The Meraki API returned a licensing object without summary evidence.")
                payload = _known_fields(raw, schema)
                if title == "Licensing overview" and isinstance(raw.get("licensedDeviceCounts"), dict):
                    payload["licensedDeviceCounts"] = {str(model): count for model, count in raw["licensedDeviceCounts"].items() if re.fullmatch(r"[A-Za-z0-9_-]{1,64}", str(model)) and isinstance(count, int) and not isinstance(count, bool) and count >= 0}
                status = "complete"
            except MerakiAPIError as exc:
                payload = None
                status = "unsupported" if exc.status_code == 404 else "unavailable"
                if status == "unavailable":
                    warnings.append(f"{network['name']}: {title} could not be read ({exc.status_code or 'response error'}).")
            control = {"network_id": network["id"], "network_name": network["name"], "control": title, "status": status, "data": payload, **({"device_serial": serial} if serial else {})}
            security.append(control)
            return control

        licensing = collect_object(f"/organizations/{organization_id}/licenses/overview", "Licensing overview", {"id": "", "name": organization["name"]}, LICENSE_FIELDS)
        if progress:
            progress(85, "Reading wireless security and switch ports")
        for network in wireless_networks:
            collect_array(f"/networks/{network['id']}/wireless/ssids", "Wireless SSID security", network, (
                "number", "name", "enabled", "authMode", "encryptionMode", "wpaEncryptionMode",
                "wpa3TransitionMode", "ipAssignmentMode", "useVlanTagging", "defaultVlanId", "visible",
            ))
            collect_array(f"/networks/{network['id']}/wireless/rfProfiles", "Wireless RF profiles", network, (), schema=RF_PROFILE_FIELDS)
        for network in switch_networks:
            collect_array(f"/networks/{network['id']}/switch/accessPolicies", "Switch access policies", network, (
                "accessPolicyNumber", "name", "accessPolicyType", "hostMode", "radiusTestingEnabled",
                "radiusCoaSupportEnabled", "guestVlanId", "voiceVlanClients",
            ))
        network_by_id = {network["id"]: network for network in networks}
        for device in switches:
            serial = str(device.get("serial") or "")
            if not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", serial):
                raise MerakiAPIError("The Meraki API returned an invalid switch identifier.")
            network = network_by_id.get(str(device.get("networkId")))
            if not network:
                warnings.append("A switch could not be matched to an assigned network; its ports were not collected.")
                continue
            collect_array(f"/devices/{serial}/switch/ports", "Switch port configuration", network, (
                "portId", "name", "enabled", "type", "vlan", "voiceVlan", "allowedVlans",
                "poeEnabled", "isolationEnabled", "rstpEnabled", "stpGuard", "linkNegotiation",
                "udld", "accessPolicyType", "accessPolicyNumber", "portScheduleId",
            ), serial=serial)
            collect_array(f"/devices/{serial}/switch/ports/statuses", "Switch port status", network, (
                "portId", "enabled", "status", "isUplink", "speed", "duplex",
            ), serial=serial, power=True)

        access_points = [device for device in devices if device.get("productType") == "wireless" or str(device.get("model", "")).startswith(("MR", "CW"))]
        if len(access_points) > MAX_ACCESS_POINTS_PER_REPORT:
            raise MerakiAPIError(f"This report is limited to {MAX_ACCESS_POINTS_PER_REPORT} wireless access points per run.")
        for device in access_points:
            serial = str(device.get("serial") or "")
            if not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", serial):
                raise MerakiAPIError("The Meraki API returned an invalid wireless identifier.")
            network = network_by_id.get(str(device.get("networkId")))
            if not network:
                warnings.append("An access point could not be matched to an assigned network; its RF assignment was not collected.")
                continue
            collect_object(f"/devices/{serial}/wireless/radio/settings", "Wireless RF assignment", network, RF_ASSIGNMENT_FIELDS, serial=serial)

        # The organization aggregate endpoint avoids fetching individual client
        # records, MACs, IPs, names and user identities even transiently.
        observational: list[dict[str, Any]] = []
        def collect_observation(path: str, title: str, network: dict[str, Any], transform: Callable[[Any], dict[str, Any]], *, params: dict[str, Any] | None = None, collection: bool = False) -> dict[str, Any]:
            try:
                data = transform(self.get_collection(path, params=params) if collection else self._json(self._get(path, params=params)))
                status = "complete"
            except MerakiAPIError as exc:
                data = None
                status = "unsupported" if exc.status_code == 404 else "unavailable"
                if status == "unavailable":
                    warnings.append(f"{network['name']}: {title} could not be read ({exc.status_code or 'response error'}).")
            control = {"network_id": network["id"], "network_name": network["name"], "control": title, "status": status, "data": data, "evidence_type": "observation"}
            security.append(control)
            observational.append(control)
            return control

        for network in wireless_networks:
            managed_serials = {str(device["serial"]) for device in access_points
                               if device.get("networkId") == network["id"]}
            collect_observation(f"/networks/{network['id']}/wireless/devices/connectionStats",
                "Wireless connection outcomes", network,
                lambda raw, serials=managed_serials: summarize_wireless_connections(raw, serials),
                params={"timespan": WIRELESS_CONNECTION_TIMESPAN})

        channel_utilization = collect_observation(
            f"/organizations/{organization_id}/wireless/devices/channelUtilization/byDevice",
            "Wireless channel utilization", {"id": "", "name": organization["name"]},
            lambda raw: summarize_channel_utilization(raw, {str(device["serial"]): str(device["networkId"])
                for device in access_points if device.get("networkId") in network_by_id}),
            params={"timespan": 86400}, collection=True) if access_points else None

        appliances = [device for device in devices if device.get("productType") == "appliance"
                      or str(device.get("model", "")).startswith(("MX", "Z"))]
        if len(appliances) > MAX_APPLIANCES_PER_REPORT:
            raise MerakiAPIError(f"This report is limited to {MAX_APPLIANCES_PER_REPORT} appliances per run.")
        wan_uplinks = collect_observation(
            f"/organizations/{organization_id}/appliance/uplink/statuses",
            "WAN uplink states", {"id": "", "name": organization["name"]},
            lambda raw: summarize_wan_uplinks(raw, {str(device["serial"]): str(device["networkId"])
                for device in appliances if device.get("networkId") in network_by_id}),
            collection=True) if appliances else None

        if wan_uplinks and isinstance(wan_uplinks.get("data"), dict):
            appliance_by_serial = {device["serial"]: device for device in appliances}
            for row in wan_uplinks["data"]["rows"]:
                device_name = appliance_by_serial[row["device_serial"]].get("name")
                network_name = network_by_id[row["network_id"]].get("name")
                row["device_name"] = device_name[:200] if isinstance(device_name, str) and device_name else row["device_serial"]
                row["network_name"] = network_name[:200] if isinstance(network_name, str) and network_name else row["network_id"]

        client_usage = collect_observation(f"/organizations/{organization_id}/clients/overview", "Aggregate client usage", {"id": "", "name": organization["name"]}, _aggregate_client_usage, params={"timespan": CLIENT_USAGE_TIMESPAN})
        for index, network in enumerate(networks, start=1):
            if progress:
                progress(86 + int(index / max(1, len(networks))), f"Reading managed topology {index}/{len(networks)}: {network['name']}")
            managed_serials = {str(device["serial"]) for device in devices if device.get("networkId") == network["id"] and device.get("serial")}
            collect_observation(f"/networks/{network['id']}/topology/linkLayer", "Managed link-layer topology", network, lambda raw, serials=managed_serials: _managed_topology(raw, serials))

        devices = [redact_meraki_data(device) for device in devices]
        status_counts = Counter(
            str(device.get("status") or "unknown").casefold() for device in devices
        )
        offline_count = status_counts.get("offline", 0)
        findings: list[dict[str, str]] = []
        if offline_count:
            findings.append(
                {
                    "status": "Review",
                    "title": f"{offline_count} device(s) report offline",
                    "detail": "Confirm the device state and recent connectivity in Meraki Dashboard.",
                }
            )
        for item in security:
            data = item.get("data")
            if item["control"] == "Wireless SSID security" and isinstance(data, list):
                for ssid in data:
                    if ssid.get("enabled") is True and str(ssid.get("authMode", "")).casefold() == "open":
                        findings.append({"status": "Review", "title": f"Open SSID on {item['network_name']}: {ssid.get('name') or ssid.get('number')}", "detail": "Confirm the guest network isolation, captive portal and approved wireless access policy."})
                    if ssid.get("enabled") is True and str(ssid.get("encryptionMode", "")).casefold() == "wep":
                        findings.append({"status": "Review", "title": f"Legacy WEP encryption on {item['network_name']}", "detail": "Replace WEP with a supported wireless authentication and encryption policy."})
            if not isinstance(data, dict):
                continue
            if item["control"] == "Intrusion protection" and str(data.get("mode", "")).casefold() == "disabled":
                findings.append(
                    {
                        "status": "Review",
                        "title": f"Intrusion protection is disabled on {item['network_name']}",
                        "detail": "Confirm this network's IDS/IPS mode against the organization's approved policy.",
                    }
                )
            if item["control"] == "Malware protection" and str(data.get("mode", "")).casefold() == "disabled":
                findings.append(
                    {
                        "status": "Review",
                        "title": f"Malware protection is disabled on {item['network_name']}",
                        "detail": "Confirm malware protection settings and licensing for this network.",
                    }
                )
        license_data = licensing.get("data")
        if isinstance(license_data, dict) and any(word in str(license_data.get("status", "")).casefold() for word in ("expire", "warning", "grace")):
            findings.append({"status": "Review", "title": "Meraki licensing needs review", "detail": "Review the reported license status and expiration in Meraki Dashboard; product entitlement and subscription modes may require separate licensing views."})
        if warnings:
            findings.append(
                {
                    "status": "Coverage warning",
                    "title": f"{len(warnings)} configuration request(s) could not be completed",
                    "detail": "Unavailable controls are listed with the report and are not treated as disabled.",
                }
            )

        if progress:
            progress(88, "Preparing the security report")
        return {
            "organization": organization,
            "collected_at": datetime.now(UTC).isoformat(),
            "summary": {
                "network_count": len(networks),
                "device_count": len(devices),
                "appliance_network_count": len(appliance_networks),
                "wireless_network_count": len(wireless_networks),
                "switch_network_count": len(switch_networks),
                "switch_device_count": len(switches),
                "wireless_device_count": len(access_points),
                "rf_profile_count": sum(len(row["data"]) for row in security if row["control"] == "Wireless RF profiles" and row["status"] == "complete"),
                "rf_assignments_collected": sum(row["control"] == "Wireless RF assignment" and row["status"] == "complete" for row in security),
                "licensing_status": licensing["status"],
                "client_usage_status": client_usage["status"],
                "topology_networks_collected": sum(row["control"] == "Managed link-layer topology" and row["status"] == "complete" for row in observational),
                "security_controls_unsupported": sum(row["status"] == "unsupported" for row in security),
                "device_status_counts": dict(sorted(status_counts.items())),
                "security_controls_collected": sum(
                    row["status"] == "complete" for row in security
                ),
                "security_controls_unavailable": sum(
                    row["status"] == "unavailable" for row in security
                ),
            },
            "networks": networks,
            "devices": devices,
            "security_controls": security,
            "licensing": {"status": licensing["status"], "data": licensing["data"], "endpoint": "licenses/overview"},
            "client_usage": {"status": client_usage["status"], "data": client_usage["data"]},
            "channel_utilization": channel_utilization,
            "wan_uplinks": wan_uplinks,
            "wireless_connections": [row for row in observational if row["control"] == "Wireless connection outcomes"],
            "topology": [row for row in observational if row["control"] == "Managed link-layer topology"],
            "switch_power": switch_power,
            "findings": findings,
            "warnings": warnings,
        }

    @staticmethod
    def _safe_network(row: dict[str, Any]) -> dict[str, Any]:
        fields = ("id", "name", "productTypes", "tags", "timeZone")
        safe = {key: row[key] for key in fields if key in row}
        safe["id"] = str(safe.get("id") or "")
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", safe["id"]):
            raise MerakiAPIError("The Meraki API returned an invalid network identifier.")
        safe["name"] = str(safe.get("name") or safe["id"])[:200]
        product_types = safe.get("productTypes")
        safe["productTypes"] = product_types if isinstance(product_types, list) else []
        safe["tags"] = safe.get("tags") if isinstance(safe.get("tags"), list) else []
        return redact_meraki_data(safe)


def compare_meraki_snapshots(previous: dict[str, Any], current: dict[str, Any]) -> dict[str, Any]:
    """Compare same-organization evidence without treating unreadable controls as removals.

    Array order changes are ignored for keyed SSID/port/access-policy arrays;
    firewall rule order remains significant. Rolling client-usage telemetry is
    excluded from configuration changes. Never includes secret fields.
    """
    previous_org = str((previous.get("organization") or {}).get("id") or "")
    current_org = str((current.get("organization") or {}).get("id") or "")
    if not previous_org or previous_org != current_org:
        raise ValueError("Meraki snapshots must belong to the same organization.")

    def index(snapshot: dict[str, Any]) -> dict[tuple[str, str, str], dict[str, Any]]:
        indexed = {}
        for row in snapshot.get("security_controls", []):
            if not isinstance(row, dict) or row.get("control") in {"Aggregate client usage", "Wireless connection outcomes", "Wireless channel utilization", "WAN uplink states"}:
                continue
            key = (str(row.get("network_id") or ""), str(row.get("device_serial") or ""), str(row.get("control") or ""))
            if key in indexed:
                raise ValueError("Meraki snapshot contains duplicate control identities.")
            indexed[key] = redact_meraki_data(row)
        return indexed

    def normalized(row: dict[str, Any]) -> Any:
        data = row.get("data")
        field = {"Wireless SSID security": "number", "Wireless RF profiles": "id", "Switch access policies": "accessPolicyNumber", "Switch port configuration": "portId", "Switch port status": "portId"}.get(row.get("control"))
        if field and isinstance(data, list) and all(isinstance(item, dict) and field in item for item in data):
            return sorted(data, key=lambda item: str(item[field]))
        return data

    before, after = index(previous), index(current)
    changes, coverage = [], []
    for key in sorted(before.keys() | after.keys()):
        old, new = before.get(key), after.get(key)
        identity = {"network_id": key[0], "device_serial": key[1], "control": key[2]}
        if not old or not new or old.get("status") != "complete" or new.get("status") != "complete":
            old_status = old.get("status") if old else "not_collected"
            new_status = new.get("status") if new else "not_collected"
            if old_status != new_status:
                coverage.append({**identity, "previous_status": old_status, "current_status": new_status})
            continue
        if json.dumps(normalized(old), sort_keys=True) != json.dumps(normalized(new), sort_keys=True):
            changes.append({**identity, "previous": normalized(old), "current": normalized(new)})
    return {"organization_id": current_org, "changes": changes, "coverage_changes": coverage, "changed_control_count": len(changes)}
