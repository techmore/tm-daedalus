"""Bounded switch port observations from the existing read-only status request."""
import math
import re
from typing import Any

MAX_PORTS = 1024
TIMESPAN = 86400
SPEEDS = {'10 Mbps', '100 Mbps', '1 Gbps', '2.5 Gbps', '5 Gbps', '10 Gbps', '20 Gbps', '25 Gbps', '40 Gbps', '50 Gbps', '100 Gbps', '400 Gbps'}


def _number(value: Any) -> int | float | None:
    return value if type(value) in (int, float) and 0 <= value <= 10**15 and math.isfinite(value) else None


def _index(rows: Any) -> dict[str, dict]:
    if not isinstance(rows, list) or len(rows) > MAX_PORTS:
        raise ValueError('Invalid switch port array')
    result = {}
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError('Invalid switch port record')
        port = row.get('portId')
        if not isinstance(port, str) or not re.fullmatch(r'[A-Za-z0-9_./-]{1,64}', port) or port in result:
            raise ValueError('Invalid or duplicate switch port identifier')
        result[port] = row
    return result


def summarize_switch_ports(statuses: Any, configurations: Any = None) -> dict:
    status = _index(statuses)
    config = _index(configurations) if configurations is not None else {}
    rows = []
    for port, raw in sorted(status.items(), key=lambda item: (not item[0].isdigit(), int(item[0]) if item[0].isdigit() else 0, item[0])):
        cfg = config.get(port, {})
        state = raw.get('status')
        state = state.casefold() if isinstance(state, str) and state.casefold() in {'connected', 'disabled', 'disconnected'} else None
        enabled = raw.get('enabled') if type(raw.get('enabled')) is bool else None
        uplink = raw.get('isUplink') if type(raw.get('isUplink')) is bool else None
        speed = raw.get('speed') if isinstance(raw.get('speed'), str) and raw['speed'] in SPEEDS else None
        duplex = raw.get('duplex') if raw.get('duplex') in ('full', 'half') else None
        def diagnostics(key):
            value = raw.get(key)
            if not isinstance(value, list) or len(value) > 100 or any(not isinstance(v, str) for v in value):
                return None, None
            # Expected idle/disabled access-port messages are retained in counts,
            # but do not become fault prompts, matching the original audit.
            actionable = [v for v in value if not (uplink is False and v.casefold() in {'port disconnected', 'port disabled'})]
            return len(value), len(actionable)
        errors, actionable_errors = diagnostics('errors')
        warnings, actionable_warnings = diagnostics('warnings')
        prompts = []
        if uplink is True and enabled is True and state == 'disconnected': prompts.append('Enabled uplink disconnected')
        if uplink is True and state == 'connected' and speed in {'10 Mbps', '100 Mbps'}: prompts.append('Uplink negotiated at 10/100 Mbps')
        if state == 'connected' and duplex == 'half': prompts.append('Connected port reports half duplex')
        if actionable_errors: prompts.append('Reported port errors')
        if actionable_warnings: prompts.append('Reported port warnings')
        usage = raw.get('usageInKb') if isinstance(raw.get('usageInKb'), dict) else {}
        traffic = raw.get('trafficInKbps') if isinstance(raw.get('trafficInKbps'), dict) else {}
        vlan = cfg.get('vlan')
        row = {'port_id': port, 'configured': port in config if configurations is not None else None, 'enabled': enabled, 'state': state,
               'is_uplink': uplink, 'speed': speed, 'duplex': duplex,
               'mode': cfg.get('type') if cfg.get('type') in ('access', 'trunk') else None,
               'vlan': vlan if type(vlan) is int and 1 <= vlan <= 4094 else None,
               'error_count': errors, 'warning_count': warnings, 'review_prompts': prompts,
               'usage_kb': {key: _number(usage.get(key)) for key in ('total', 'sent', 'recv')},
               'traffic_kbps': {key: _number(traffic.get(key)) for key in ('total', 'sent', 'recv')},
               'power_usage_wh': _number(raw.get('powerUsageInWh'))}
        rows.append(row)
    return {'requested_timespan_seconds': TIMESPAN, 'reported_port_count': len(rows),
            'configured_port_count': len(config) if configurations is not None else None,
            'missing_status_port_count': len(config.keys() - status.keys()) if configurations is not None else None,
            'unmatched_status_port_count': len(status.keys() - config.keys()) if configurations is not None else None,
            'connected_port_count': sum(row['state'] == 'connected' for row in rows),
            'unknown_state_port_count': sum(row['state'] is None for row in rows),
            'uplink_port_count': sum(row['is_uplink'] is True for row in rows),
            'unknown_uplink_port_count': sum(row['is_uplink'] is None for row in rows),
            'review_port_count': sum(bool(row['review_prompts']) for row in rows),
            'diagnostic_coverage_port_count': sum(row['error_count'] is not None and row['warning_count'] is not None for row in rows),
            'rows': rows,
            'scope': 'Reported port state and prior 24-hour counters. Unknown fields remain unavailable. Review prompts do not establish a fault, bottleneck, peak load or replacement capacity. Neighbor/client identities and diagnostic message text are omitted.'}


def project_switch_ports(observations: Any) -> dict:
    observations = observations if isinstance(observations, list) else []
    shown = []
    for observation in observations[:20]:
        if not isinstance(observation, dict): continue
        data = observation.get('data')
        data = {key: data.get(key) for key in ('requested_timespan_seconds', 'reported_port_count', 'configured_port_count', 'missing_status_port_count', 'unmatched_status_port_count', 'connected_port_count', 'unknown_state_port_count', 'uplink_port_count', 'unknown_uplink_port_count', 'review_port_count', 'diagnostic_coverage_port_count', 'scope', 'rows')} if isinstance(data, dict) else None
        if data is not None:
            rows = [row for row in data['rows'] if isinstance(row, dict)] if isinstance(data.get('rows'), list) else []
            # Put actionable ports first, without changing saved physical ordering.
            ordered = sorted(rows, key=lambda row: not bool(row.get('review_prompts')))
            data['rows'] = []
            for row in ordered[:50]:
                clean = {key: row.get(key) if type(row.get(key)) is bool else None for key in ('configured', 'enabled', 'is_uplink')}
                clean['port_id'] = row.get('port_id', '')[:64] if isinstance(row.get('port_id'), str) else ''
                for key, allowed in [('state', ('connected', 'disabled', 'disconnected')), ('mode', ('access', 'trunk')), ('duplex', ('full', 'half'))]:
                    clean[key] = row.get(key) if row.get(key) in allowed else None
                clean['speed'] = row.get('speed') if isinstance(row.get('speed'), str) and row['speed'] in SPEEDS else None
                for key in ('vlan', 'error_count', 'warning_count', 'power_usage_wh'): clean[key] = _number(row.get(key))
                for key in ('usage_kb', 'traffic_kbps'):
                    values = row.get(key) if isinstance(row.get(key), dict) else {}
                    clean[key] = {field: _number(values.get(field)) for field in ('total', 'sent', 'recv')}
                prompts = row.get('review_prompts') if isinstance(row.get('review_prompts'), list) else []
                clean['review_prompts'] = [v[:160] for v in prompts[:5] if isinstance(v, str)]
                data['rows'].append(clean)
            for key in list(data):
                if key not in ('rows', 'scope'): data[key] = _number(data[key])
            data['scope'] = data['scope'][:500] if isinstance(data.get('scope'), str) else ''
            data['additional_rows'] = max(0, len(rows) - 50)
        shown.append({key: observation[key][:240] if isinstance(observation.get(key), str) else '' for key in ('device_serial', 'device_name', 'network_name', 'status', 'configuration_status')} | {'data': data})
    return {'switches': shown, 'additional_switches': max(0, len(observations) - 20)}
