"""Allowlisted assigned-inventory EOX evidence, separate from frozen notice catalogs."""
import copy
import json
import re
from collections import Counter
from datetime import datetime, UTC
from .meraki_lifecycle import _day, NOTICES_V1

SOURCE = 'https://developer.cisco.com/meraki/api-v1/get-organization-inventory-devices/'
STATUSES = ('endOfSupport', 'nearEndOfSupport', 'endOfSale', 'unknown')
SCOPE = ('Meraki inventory API milestones for exact assigned devices. Blank status and missing dates remain unknown; '
         'they do not establish ongoing support. Provider status is separate from published vendor notices, '
         'support contracts and warranty entitlement. Date differences require vendor verification. '
         'The published-notice comparison covers only the immutable version-1 catalog; other models have no notice cross-check here.')


def _identity(value):
    return isinstance(value, str) and re.fullmatch(r'[A-Za-z0-9_-]{1,128}', value) is not None


def _provider_day(value):
    # API specifies date-time, so a bare date or naive timestamp is not accepted.
    if not isinstance(value, str) or len(value) > 80:
        return None
    try:
        dt = datetime.fromisoformat(value.replace('Z', '+00:00'))
        return dt.astimezone(UTC).date().isoformat() if dt.tzinfo is not None else None
    except ValueError:
        return None


def assigned_index(devices, network_ids):
    if not isinstance(devices, list) or len(devices) > 50_000:
        raise ValueError('Assigned inventory has an invalid shape or limit.')
    result, seen = {}, set()
    for device in devices:
        if not isinstance(device, dict) or not _identity(device.get('serial')):
            raise ValueError('Assigned inventory requires valid serial identifiers.')
        serial = device['serial']
        if serial.casefold() in seen:
            raise ValueError('Assigned inventory contains duplicate identifiers.')
        seen.add(serial.casefold())
        network = device.get('networkId')
        if network not in network_ids:
            continue
        model = device.get('model')
        if not isinstance(model, str) or not 1 <= len(model) <= 128:
            raise ValueError('Assigned inventory requires exact model identities.')
        result[serial] = (network, model)
    return result


def summarize_inventory_eox(raw, assigned):
    """Discard unassigned inventory and private fields before anything is saved."""
    if not isinstance(raw, list) or len(raw) > 50_000:
        raise ValueError('Inventory lifecycle evidence has an invalid shape or limit.')
    seen, rows = set(), []
    for item in raw:
        if not isinstance(item, dict) or not _identity(item.get('serial')):
            raise ValueError('Inventory lifecycle evidence requires valid identifiers.')
        serial = item['serial']
        if serial.casefold() in seen:
            raise ValueError('Inventory lifecycle evidence contains duplicate identifiers.')
        seen.add(serial.casefold())
        if serial not in assigned:
            continue
        network, model = assigned[serial]
        if item.get('networkId') != network or item.get('model') != model:
            raise ValueError('Inventory lifecycle identity differs from assigned inventory.')
        eox = item.get('eox') if isinstance(item.get('eox'), dict) else {}
        status = eox.get('status')
        rows.append({'device_serial': serial, 'network_id': network, 'model': model,
                     'provider_status': status if status in STATUSES[:-1] else 'unknown',
                     'end_of_sale_date': _provider_day(eox.get('endOfSaleAt')),
                     'end_of_support_date': _provider_day(eox.get('endOfSupportAt'))})
    rows.sort(key=lambda r: r['device_serial'])
    return {'schema_version': 1, 'rows': rows, 'expected_device_count': len(assigned),
            'reported_device_count': len(rows), 'missing_device_count': len(assigned) - len(rows)}


def _validate_observation(data, assigned):
    if not isinstance(data, dict) or type(data.get('schema_version')) is not int or data['schema_version'] != 1:
        raise ValueError('Invalid lifecycle observation version.')
    rows = data.get('rows')
    if not isinstance(rows, list) or len(rows) > 50_000:
        raise ValueError('Invalid lifecycle rows.')
    raw = []
    for row in rows:
        if not isinstance(row, dict) or row.get('provider_status') not in STATUSES:
            raise ValueError('Invalid lifecycle row.')
        dates = {}
        for key, field in [('end_of_sale_date', 'endOfSaleAt'), ('end_of_support_date', 'endOfSupportAt')]:
            value = row.get(key)
            if value is not None and (not isinstance(value, str) or not re.fullmatch(r'\d{4}-\d{2}-\d{2}', value) or _day(value) is None):
                raise ValueError('Invalid lifecycle date.')
            dates[field] = value + 'T00:00:00Z' if value is not None else None
        raw.append({'serial': row.get('device_serial'), 'networkId': row.get('network_id'), 'model': row.get('model'),
                    'eox': {'status': row['provider_status'], **dates}})
    rebuilt = summarize_inventory_eox(raw, assigned)
    if json.dumps(rebuilt, sort_keys=True) != json.dumps(data, sort_keys=True):
        raise ValueError('Lifecycle observation differs from its allowlisted evidence.')
    return rows


def build_provider_lifecycle(snapshot):
    observation = snapshot.get('inventory_eox')
    if observation is None:
        return None  # Never synthesize a new section in a historical snapshot.
    result = {'schema_version': 1, 'status': 'invalid_evidence', 'source_url': SOURCE,
              'scope': SCOPE, 'as_of': None, 'rows': [], 'summary': {}}
    try:
        day = _day(snapshot.get('collected_at'))
        result['as_of'] = day.isoformat() if day else None
        networks = snapshot['networks']
        if not isinstance(networks, list) or len(networks) > 500:
            raise ValueError()
        names = {}
        for network in networks:
            if not isinstance(network, dict) or not _identity(network.get('id')) or network['id'] in names:
                raise ValueError()
            name = network.get('name')
            names[network['id']] = name[:240] if isinstance(name, str) else network['id']
        assigned = assigned_index(snapshot['devices'], names)
        if not isinstance(observation, dict) or observation.get('status') not in ('complete', 'unsupported', 'unavailable'):
            raise ValueError()
        if observation['status'] != 'complete':
            result['status'] = 'unavailable'
            return result
        source_rows = _validate_observation(observation.get('data'), assigned)
        seen = {r['device_serial'] for r in source_rows}
        grouped = Counter((r['network_id'], r['model'].upper(), r['provider_status'], r['end_of_sale_date'], r['end_of_support_date'], True) for r in source_rows)
        grouped.update((n, m.upper(), 'unknown', None, None, False) for s, (n,m) in assigned.items() if s not in seen)
        rows = []
        for (network, model, status, sale, support, reported), count in grouped.items():
            notice = NOTICES_V1.get(model)
            conflicts = [key for key, value, published in [('end_of_sale_date', sale, notice[1] if notice else None),
                        ('end_of_support_date', support, notice[2] if notice else None)] if value and published and value != published]
            days = (_day(support) - day).days if support and day else None
            rows.append({'network_id': network, 'network_name': names[network], 'model': model, 'quantity': count,
                         'provider_status': status, 'reported': reported, 'end_of_sale_date': sale,
                         'end_of_support_date': support, 'days_until_support_date': days,
                         'published_end_of_sale_date': notice[1] if notice else None,
                         'published_end_of_support_date': notice[2] if notice else None,
                         'date_conflicts': conflicts})
        rows.sort(key=lambda r: (STATUSES.index(r['provider_status']), r['network_id'], r['model'], r['end_of_support_date'] or '', r['end_of_sale_date'] or '', r['reported']))
        result.update(status='available', rows=rows, summary={
            'assigned_devices': len(assigned), 'reported_devices': len(source_rows), 'missing_devices': len(assigned)-len(source_rows),
            'provider_end_of_support': sum(r['quantity'] for r in rows if r['provider_status']=='endOfSupport'),
            'provider_near_end_of_support': sum(r['quantity'] for r in rows if r['provider_status']=='nearEndOfSupport'),
            'unknown_status': sum(r['quantity'] for r in rows if r['provider_status']=='unknown'),
            'unknown_support_date': sum(r['quantity'] for r in rows if r['end_of_support_date'] is None),
            'no_notice_cross_check': sum(r['quantity'] for r in rows if r['published_end_of_support_date'] is None),
            'date_conflicts': sum(r['quantity'] for r in rows if r['date_conflicts'])})
    except (ValueError, TypeError, KeyError):
        pass
    return result


def project_provider_lifecycle(saved, *, complete=False):
    """Validate grouped snapshot evidence and derived counters without exposing serials."""
    if saved is None:
        return None
    invalid = {'schema_version': 1, 'status': 'invalid_evidence', 'scope': SCOPE, 'source_url': SOURCE,
               'as_of': None, 'rows': [], 'summary': {}, 'additional_rows': 0}
    if not isinstance(saved, dict) or type(saved.get('schema_version')) is not int or saved['schema_version'] != 1:
        return invalid
    if saved.get('status') in ('unavailable', 'invalid_evidence'):
        expected = {k:v for k,v in invalid.items() if k != 'additional_rows'}
        expected.update(status=saved['status'], as_of=saved.get('as_of'))
        if saved.get('as_of') is not None and (not isinstance(saved['as_of'], str) or not re.fullmatch(r'\d{4}-\d{2}-\d{2}', saved['as_of']) or _day(saved['as_of']) is None):
            return invalid
        return (copy.deepcopy(expected) | {'additional_rows': 0}) if saved == expected else invalid
    rows = saved.get('rows')
    if not isinstance(rows, list) or len(rows)>50_000:
        return invalid
    networks, devices, source_rows = {}, [], []
    try:
        for row in rows:
            if not isinstance(row, dict) or type(row.get('quantity')) is not int or not 1 <= row['quantity'] <= 50_000 or type(row.get('reported')) is not bool:
                raise ValueError()
            network, name, model = row['network_id'], row['network_name'], row['model']
            if not isinstance(name, str) or len(name)>240 or network in networks and networks[network] != name:
                raise ValueError()
            networks[network] = name
            if len(devices) + row['quantity'] > 50_000:
                raise ValueError()
            for _ in range(row['quantity']):
                serial = str(len(devices))
                devices.append({'serial':serial,'networkId':network,'model':model})
                if row['reported']:
                    source_rows.append({'device_serial':serial,'network_id':network,'model':model,'provider_status':row['provider_status'],
                                        'end_of_sale_date':row['end_of_sale_date'],'end_of_support_date':row['end_of_support_date']})
        source_rows.sort(key=lambda r:r['device_serial'])
        rebuilt = build_provider_lifecycle({'collected_at':saved.get('as_of'), 'networks':[{'id':k,'name':v} for k,v in networks.items()],
            'devices':devices, 'inventory_eox':{'status':'complete','data':{'schema_version':1,'rows':source_rows,'expected_device_count':len(devices),
             'reported_device_count':len(source_rows),'missing_device_count':len(devices)-len(source_rows)}}})
        if json.dumps(saved, sort_keys=True) != json.dumps(rebuilt, sort_keys=True):
            return invalid
    except (ValueError, TypeError, KeyError):
        return invalid
    result = copy.deepcopy(saved)
    result['rows'] = result['rows'][:len(rows) if complete else 100]
    result['additional_rows'] = len(rows)-len(result['rows'])
    return result


def compare_eox_evidence(before, after):
    """Missing records/fields change coverage, never imply a removed milestone."""
    if not isinstance(before, dict) or not isinstance(after, dict):
        return [], [{'evidence_dimension': 'inventory_eox', 'previous_status': 'invalid_evidence' if not isinstance(before, dict) else 'observed', 'current_status': 'invalid_evidence' if not isinstance(after, dict) else 'observed'}]
    def index(data):
        rows = data.get('rows')
        if not isinstance(rows, list): raise ValueError('Invalid lifecycle comparison rows.')
        result = {}
        for row in rows:
            if not isinstance(row, dict) or not _identity(row.get('device_serial')) or row['device_serial'] in result:
                raise ValueError('Invalid lifecycle comparison identity.')
            result[row['device_serial']] = row
        return result
    old, new = index(before), index(after)
    changes, coverage = [], []
    for serial in sorted(old.keys() | new.keys()):
        a, b = old.get(serial), new.get(serial)
        identity = {'device_serial':serial}
        if a is None or b is None:
            coverage.append({**identity, 'evidence_dimension':'inventory_eox_record', 'previous_status':'observed' if a else 'missing', 'current_status':'observed' if b else 'missing'})
            continue
        if (a.get('network_id'), a.get('model')) != (b.get('network_id'), b.get('model')):
            coverage.append({**identity, 'evidence_dimension':'inventory_eox_assignment', 'previous_status':'previous_assignment', 'current_status':'different_assignment'})
            continue
        changed = []
        for field in ('provider_status', 'end_of_sale_date', 'end_of_support_date'):
            previous, current = a.get(field), b.get(field)
            known_a = previous is not None and previous != 'unknown'
            known_b = current is not None and current != 'unknown'
            if known_a != known_b:
                coverage.append({**identity, 'evidence_dimension':field, 'previous_status':'observed' if known_a else 'unknown', 'current_status':'observed' if known_b else 'unknown'})
            elif known_a and previous != current:
                changed.append(field)
        if changed:
            changes.append({**identity, 'previous':{f:a[f] for f in changed}, 'current':{f:b[f] for f in changed}})
    return changes, coverage
