"""Bounded interval byte evidence; rates are interval averages, not circuit capacity."""
from datetime import UTC, datetime
import re
from typing import Any

WAN_USAGE_TIMESPAN = 604800
WAN_USAGE_RESOLUTION = 3600
MAX_WAN_INTERVALS = 1000
MAX_WAN_INTERFACES = 32
MAX_INTERVAL_BYTES = 1_000_000_000_000


def summarize_wan_usage(raw: Any) -> dict[str, Any]:
    # Import here to keep the collector's exception and protected request path shared.
    from .meraki_api import MerakiAPIError

    def invalid():
        raise MerakiAPIError("WAN usage returned invalid or overlapping interval evidence.")

    def timestamp(value):
        if not isinstance(value, str) or len(value) > 64:
            invalid()
        try:
            result = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if result.tzinfo is None:
                invalid()
            return result.astimezone(UTC)
        except (ValueError, OverflowError):
            invalid()

    if not isinstance(raw, list) or len(raw) > MAX_WAN_INTERVALS:
        invalid()
    intervals = []
    for item in raw:
        if not isinstance(item, dict):
            invalid()
        start, end = timestamp(item.get("startTime")), timestamp(item.get("endTime"))
        duration = (end - start).total_seconds()
        if not 1 <= duration <= WAN_USAGE_RESOLUTION:
            invalid()
        values = item.get("byInterface")
        if not isinstance(values, list) or len(values) > MAX_WAN_INTERFACES:
            invalid()
        names, counters = set(), []
        for value in values:
            name = value.get("interface") if isinstance(value, dict) else None
            if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,32}", name) or name in names:
                invalid()
            names.add(name)
            selected = {key: count for key in ("sent", "received")
                        if type(count := value.get(key)) is int and 0 <= count <= MAX_INTERVAL_BYTES}
            counters.append({"interface": name, "bytes": selected})
        intervals.append((start, end, duration, counters))
    intervals.sort(key=lambda row: row[0])
    if intervals and (intervals[-1][1] - intervals[0][0]).total_seconds() > WAN_USAGE_TIMESPAN + WAN_USAGE_RESOLUTION:
        invalid()
    for previous, current in zip(intervals, intervals[1:]):
        if current[0] < previous[1]:
            invalid()
    summaries, evidence = {}, []
    for start, end, duration, counters in intervals:
        for counter in counters:
            name = counter["interface"]
            if name not in summaries:
                if len(summaries) >= MAX_WAN_INTERFACES:
                    invalid()
                summaries[name] = {"interface": name, "reported_interval_count": 0, "directions": {}}
            summary = summaries[name]
            summary["reported_interval_count"] += 1
            for field, count in counter["bytes"].items():
                direction = summary["directions"].setdefault(field, {"observed_bytes": 0, "observed_seconds": 0,
                    "measured_interval_count": 0, "peak_interval_average_mbps": 0})
                direction["observed_bytes"] += count
                direction["observed_seconds"] += duration
                direction["measured_interval_count"] += 1
                direction["peak_interval_average_mbps"] = max(direction["peak_interval_average_mbps"], count * 8 / duration / 1_000_000)
            evidence.append({"start_time": start.isoformat(), "end_time": end.isoformat(),
                "duration_seconds": duration, "interface": name, "bytes": counter["bytes"],
                "counter_coverage": "complete" if len(counter["bytes"]) == 2 else "partial"})
    for summary in summaries.values():
        for direction in summary["directions"].values():
            direction["average_mbps"] = direction["observed_bytes"] * 8 / direction["observed_seconds"] / 1_000_000
    return {"requested_timespan_seconds": WAN_USAGE_TIMESPAN, "requested_resolution_seconds": WAN_USAGE_RESOLUTION,
            "interval_count": len(intervals), "interface_count": len(summaries),
            "first_interval_start": intervals[0][0].isoformat() if intervals else None,
            "last_interval_end": intervals[-1][1].isoformat() if intervals else None,
            "interfaces": [summaries[key] for key in sorted(summaries)], "intervals": evidence,
            "scope": "Observed interval byte counters. Averages cover measured seconds only; peak means highest interval average. Full-window coverage, instantaneous peaks and subscribed circuit capacity are not inferred."}


def project_wan_usage(data: Any) -> dict[str, Any] | None:
    """Bounded summary projection; complete intervals remain in saved evidence."""
    import math
    if not isinstance(data, dict):
        return None
    def number(value):
        return value if type(value) in (int, float) and math.isfinite(value) and 0 <= value <= 1_000_000_000_000_000 else None
    result = {key: number(data.get(key)) for key in ('requested_timespan_seconds', 'requested_resolution_seconds', 'interval_count', 'interface_count')}
    for key in ('first_interval_start', 'last_interval_end', 'scope'):
        value = data.get(key)
        result[key] = value[:400 if key == 'scope' else 64] if isinstance(value, str) else None
    interfaces = data.get('interfaces') if isinstance(data.get('interfaces'), list) else []
    result['additional_interfaces'] = max(0, len(interfaces) - MAX_WAN_INTERFACES)
    result['interfaces'] = []
    for item in interfaces[:MAX_WAN_INTERFACES]:
        if not isinstance(item, dict):
            continue
        name = item.get('interface')
        directions = item.get('directions') if isinstance(item.get('directions'), dict) else {}
        projected = {'interface': name[:32] if isinstance(name, str) else 'Unknown interface',
            'reported_interval_count': number(item.get('reported_interval_count')), 'directions': {}}
        for field in ('sent', 'received'):
            values = directions.get(field)
            if isinstance(values, dict):
                projected['directions'][field] = {key: number(values.get(key)) for key in ('observed_bytes', 'observed_seconds',
                    'measured_interval_count', 'average_mbps', 'peak_interval_average_mbps')}
        result['interfaces'].append(projected)
    return result
