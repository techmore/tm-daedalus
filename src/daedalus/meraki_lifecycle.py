"""Frozen official lifecycle notices joined to exact assigned inventory models."""
import copy
import re
from collections import Counter
from datetime import date, datetime, UTC
from typing import Any

INDEX = 'https://documentation.meraki.com/Platform_Management/Product_Information/End-of-Life_(EOL)_Products_and_Dates'
INDOOR = 'https://www.cisco.com/c/en/us/products/collateral/wireless/catalyst-9100ax-access-points/meraki-wi-fi-6-indoor-access-points-eol.html'
OBSERVED_ON = '2026-10-08'
# Version 1 is immutable: update vendor evidence under a new version, never
# reinterpret dates in an already saved report using a future catalog.
NOTICES_V1 = {
    'MX100': ('2021-08-10', '2022-02-01', '2027-02-01', INDEX),
    'MS120-24P': ('2024-03-28', '2025-03-28', '2030-03-28', INDEX),
    'MS120-48FP': ('2024-03-28', '2025-03-28', '2030-03-28', INDEX),
    'MR44': ('2026-03-30', '2026-12-31', '2031-12-31', INDOOR),
}
SCOPE = ('Official notices observed October 8, 2026, matched to exact assigned hardware models. '
         'Support milestones are vendor dates, not proof of an active support contract, warranty, '
         'equipment failure or a required purchase. End of sale is separate from end of support. '
         'No published date in this catalog means unknown, not indefinite support. Review dates '
         'with the vendor before approving the migration. Dates come from published notices; account-specific support records are not included.')


def _day(value):
    if not isinstance(value, str) or len(value) > 80:
        return None
    try:
        if re.fullmatch(r'\d{4}-\d{2}-\d{2}', value): return date.fromisoformat(value)
        dt = datetime.fromisoformat(value.replace('Z', '+00:00'))
        if dt.tzinfo is None: return None
        return dt.astimezone(UTC).date()
    except ValueError:
        return None


def _result(status, as_of=None, rows=None):
    rows = rows or []
    return {'schema_version': 1, 'status': status, 'scope': SCOPE,
            'notice_observed_on': OBSERVED_ON, 'as_of': as_of,
            'rows': rows, 'summary': {key: sum(r['quantity'] for r in rows if r['support_status'] == key)
             for key in ('date_passed', 'within_180_days', 'later', 'unknown')}}


def build_lifecycle(snapshot: dict[str, Any]) -> dict:
    as_of = _day(snapshot.get('collected_at'))
    # No invented inventory or date for legacy / incomplete snapshots.
    if not isinstance(snapshot.get('networks'), list) or not isinstance(snapshot.get('devices'), list):
        return _result('unavailable', as_of.isoformat() if as_of else None)
    networks, seen, counts = {}, set(), Counter()
    try:
        if len(snapshot['networks']) > 500 or len(snapshot['devices']) > 50_000:
            raise ValueError()
        for n in snapshot['networks']:
            identity = n.get('id') if isinstance(n, dict) else None
            if not isinstance(identity, str) or not 1 <= len(identity) <= 128 or identity in networks: raise ValueError()
            networks[identity] = n.get('name')[:240] if isinstance(n.get('name'), str) else identity
        for d in snapshot['devices']:
            if not isinstance(d, dict): raise ValueError()
            serial, network, model = d.get('serial'), d.get('networkId'), d.get('model')
            if not isinstance(serial, str) or not 1 <= len(serial) <= 128 or serial.casefold() in seen: raise ValueError()
            seen.add(serial.casefold())
            if network is None: continue
            if not isinstance(network, str): raise ValueError()
            if network not in networks: continue
            if not isinstance(model, str) or not 1 <= len(model) <= 128: raise ValueError()
            counts[(network, model.upper())] += 1
    except (ValueError, TypeError):
        return _result('invalid_evidence', as_of.isoformat() if as_of else None)
    rows = []
    for (network, model), count in sorted(counts.items()):
        notice = NOTICES_V1.get(model)
        announcement, sale, support, source = notice if notice else (None, None, None, INDEX)
        days = (date.fromisoformat(support) - as_of).days if support and as_of else None
        status = 'unknown' if days is None else 'date_passed' if days < 0 else 'within_180_days' if days <= 180 else 'later'
        rows.append({'network_id': network, 'network_name': networks[network], 'model': model,
            'quantity': count, 'announcement_date': announcement, 'end_of_sale_date': sale,
            'end_of_support_date': support, 'days_until_support_date': days, 'support_status': status,
            'sale_date_passed': as_of > date.fromisoformat(sale) if sale and as_of else None,
            'notice_status': 'published' if notice else 'not_in_dated_catalog', 'source_url': source,
            'note': 'MR76 is explicitly excluded from the indoor AP notice; no MR76 date was found in the vendor index on the observation date.' if model == 'MR76' else 'Exact model is absent from this dated catalog; review the vendor index.' if not notice else 'Support entitlement requires separate verification.'})
    priority = {'date_passed': 0, 'within_180_days': 1, 'later': 2, 'unknown': 3}
    rows.sort(key=lambda r: (priority[r['support_status']], r['end_of_support_date'] or '9999', r['network_id'], r['model']))
    return _result('available', as_of.isoformat() if as_of else None, rows)


def project_lifecycle(saved: Any, *, complete: bool = False) -> dict | None:
    if saved is None: return None
    invalid = _result('invalid_evidence') | {'additional_rows': 0}
    if not isinstance(saved, dict) or type(saved.get('schema_version')) is not int or saved['schema_version'] != 1:
        return invalid
    if saved.get('status') not in ('available', 'unavailable', 'invalid_evidence'):
        return invalid
    rows = saved.get('rows'); day = saved.get('as_of')
    if not isinstance(rows, list) or len(rows) > 50_000 or (day is not None and (not isinstance(day, str) or not re.fullmatch(r'\d{4}-\d{2}-\d{2}', day) or _day(day) is None)):
        return invalid
    # Reconstruct only the allowlisted grouped evidence; catalog v1 is immutable.
    devices, networks, seen = [], {}, set()
    for r in rows:
        if not isinstance(r, dict): return invalid
        network, model, quantity = r.get('network_id'), r.get('model'), r.get('quantity')
        if not isinstance(network, str) or not isinstance(model, str) or not isinstance(r.get('network_name'), str) or len(r['network_name']) > 240 or type(quantity) is not int or not 1 <= quantity <= 50_000:
            return invalid
        if (network, model) in seen or (network in networks and networks[network] != r['network_name']): return invalid
        seen.add((network, model)); networks[network] = r['network_name']
        if len(devices) + quantity > 50_000: return invalid
        start = len(devices)
        devices.extend([{'serial': str(start + i), 'networkId': network, 'model': model} for i in range(quantity)])
    rebuilt = build_lifecycle({'collected_at': day, 'networks': [{'id': k, 'name': v} for k, v in networks.items()], 'devices': devices})
    if saved['status'] != 'available':
        rebuilt = _result(saved['status'], day)
    if saved != rebuilt: return invalid
    result = copy.deepcopy(rebuilt)
    limit = len(rows) if complete else 100
    result['rows'] = result['rows'][:limit]
    result['additional_rows'] = len(rows) - len(result['rows'])
    return result
