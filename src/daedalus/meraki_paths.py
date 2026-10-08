"""Versioned network-layer review from immutable, inventory-scoped audit evidence."""
import copy
import math
from typing import Any
from .meraki_neighbors import project_neighbors
from .meraki_switch import SPEEDS

SCOPE = ("Saved WAN, switch and AP observations grouped by assigned network and unambiguous "
         "LLDP/CDP port mapping. This is a layer review, not packet-flow capture or proof of "
         "Internet reachability, bottlenecks, peak load, PoE capacity or physical cabling. "
         "Wireless counters and channel percentages cover their requested observation windows; "
         "missing measurements remain unavailable. RSSI and end-to-end flow evidence are not collected.")


def _text(value):
    return value[:200] if isinstance(value, str) else ''


def _number(value, maximum=10**15, *, integer=False):
    return value if type(value) in ((int,) if integer else (int, float)) and 0 <= value <= maximum and math.isfinite(value) else None


def _rows(value):
    return [row for row in value if isinstance(row, dict)] if isinstance(value, list) else []


def _data(observation):
    return observation['data'] if isinstance(observation,dict) and observation.get('status') == 'complete' and isinstance(observation.get('data'),dict) else {}


def _unique(rows, key):
    result = {}
    for row in rows:
        identity = row.get(key)
        if not isinstance(identity, str) or not identity or len(identity) > 128 or identity in result:
            raise ValueError('Invalid or duplicate evidence identity')
        result[identity] = row
    return result


def _kind(device):
    model, product = str(device.get('model') or ''), device.get('productType')
    if product == 'switch' or model.startswith('MS'): return 'switch'
    if product == 'wireless' or model.startswith('MR'): return 'ap'
    if product == 'appliance' or model.startswith(('MX', 'Z')): return 'edge'
    return 'other'


def _device(device):
    status = device.get('status')
    return {'device_serial': device['serial'], 'name': _text(device.get('name')) or _text(device.get('model')),
            'model': _text(device.get('model')), 'status': status if status in ('online', 'offline', 'alerting', 'dormant') else 'unknown'}


def build_path_analysis(snapshot: dict[str, Any]) -> dict:
    """Capture the original report's layer grouping without guessing traffic paths."""
    try:
        if any(not isinstance(snapshot.get(key),list) or any(not isinstance(row,dict) for row in snapshot[key]) for key in ('networks','devices')):
            raise ValueError('Invalid inventory array')
        networks = _unique(_rows(snapshot.get('networks')), 'id')
        devices = _unique(_rows(snapshot.get('devices')), 'serial')
        if len(networks) > 500 or len(devices) > 50_000:
            raise ValueError('Inventory exceeds the supported report limits')
        if any(d.get('networkId') is not None and not isinstance(d['networkId'],str) for d in devices.values()):
            raise ValueError('Invalid assigned network identity')
        neighbors = _rows(snapshot.get('switch_neighbors'))
        projected = project_neighbors(snapshot, complete=True)['switches']
        if len(neighbors) != len(projected):
            raise ValueError('Invalid discovery observation array')
        neighbor_by_switch = _unique(neighbors, 'device_serial')
        valid_discovery = {row['device_serial']: view['data'] for row, view in zip(neighbors, projected, strict=True) if view['data'] is not None}
        ports = _unique(_rows(snapshot.get('switch_ports')), 'device_serial')
        power = _unique(_rows(snapshot.get('switch_power')), 'device_serial')
        connection = _unique(_rows(snapshot.get('wireless_connections')), 'network_id')
        clients = _unique(_rows(snapshot.get('wireless_clients')), 'network_id')
        usage = _unique(_rows(snapshot.get('wan_usage')), 'network_id')
    except (ValueError, TypeError):
        return {'schema_version': 1, 'status': 'invalid_evidence', 'scope': SCOPE, 'networks': [], 'summary': None}

    channel = snapshot.get('channel_utilization') or {}
    channel_data = _data(channel)
    channel_rows = _rows(channel_data.get('rows'))
    wan = snapshot.get('wan_uplinks') or {}
    wan_rows = _rows(_data(wan).get('rows'))
    mappings = {}
    for serial, observation in neighbor_by_switch.items():
        local = devices.get(serial)
        if serial not in valid_discovery or not local or _kind(local) != 'switch': continue
        discovery_ports = {row['local_port']: row for row in valid_discovery[serial]['rows']}
        for row in _rows(_data(observation).get('rows')):
            remote = devices.get(row.get('neighbor_serial')) if isinstance(row.get('neighbor_serial'), str) else None
            if row.get('status') == 'matched' and remote and _kind(remote) == 'ap' and local.get('networkId') == remote.get('networkId'):
                mappings.setdefault(remote['serial'], {})[(serial, row['local_port'])] = dict(discovery_ports[row['local_port']]['neighbor_ports'])

    def ap_record(device):
        serial, network_id = device['serial'], device['networkId']
        bands, seen, invalid = [], set(), False
        for row in channel_rows:
            if row.get('device_serial') != serial or row.get('network_id') != network_id: continue
            band = row.get('band')
            if band not in ('2.4', '5', '6') or band in seen:
                invalid = True; break
            seen.add(band)
            values = row.get('percentages') if isinstance(row.get('percentages'), dict) else {}
            values = {key: _number(values.get(key),100) for key in ('total','wifi','nonWifi')}
            bands.append({'band':band,'percentages':values,'review_threshold_met': (values['total'] is not None and values['total'] >= 50) or (values['nonWifi'] is not None and values['nonWifi'] >= 20)})
        observation = connection.get(network_id, {})
        data = _data(observation)
        counters = [r for r in _rows(data.get('devices')) if r.get('device_serial') == serial]
        source = counters[0].get('counters') if len(counters) == 1 and isinstance(counters[0].get('counters'), dict) else {}
        clean_counters = {key: _number(source.get(key),10**12,integer=True) for key in ('success','assoc','auth','dhcp','dns')}
        return _device(device) | {'bands': [] if invalid else sorted(bands,key=lambda r:r['band']),
            'channel_status': 'invalid_evidence' if invalid else 'complete' if bands and all(all(v is not None for v in r['percentages'].values()) for r in bands) else 'partial' if bands else 'unavailable',
            'channel_timespan_seconds': _number(channel_data.get('requested_timespan_seconds'),integer=True),
            'connection_counters':clean_counters, 'connection_status':'complete' if all(v is not None for v in clean_counters.values()) else 'partial' if any(v is not None for v in clean_counters.values()) else 'unavailable',
            'connection_timespan_seconds': _number(data.get('requested_timespan_seconds'),integer=True)}

    output = []
    for network_id, network in sorted(networks.items(),key=lambda pair:(_text(pair[1].get('name')).casefold(),pair[0])):
        assigned = sorted((d for d in devices.values() if d.get('networkId') == network_id),key=lambda d:(_text(d.get('name')).casefold(),d['serial']))
        edges, switches, unmatched, ambiguous = [], [], [], []
        aps = {d['serial']:ap_record(d) for d in assigned if _kind(d) == 'ap'}
        for device in assigned:
            serial, kind = device['serial'], _kind(device)
            if kind == 'edge':
                interfaces = [{'interface':r.get('interface'),'state':r.get('state') if r.get('state') in ('active','ready','failed','not connected','connecting','disabled') else 'unknown'} for r in wan_rows if r.get('device_serial') == serial and r.get('network_id') == network_id and r.get('interface') in ('wan1','wan2','wan3','cellular')]
                edges.append(_device(device) | {'interfaces':interfaces, 'wan_status': 'complete' if interfaces else 'unavailable'})
            if kind != 'switch': continue
            port = ports.get(serial, {});port_data = _data(port)
            energy = power.get(serial, {});energy_data = _data(energy)
            port_rows = {r['port_id']: r for r in _rows(port_data.get('rows')) if isinstance(r.get('port_id'),str)}
            attached = []
            for ap_serial, ap in aps.items():
                candidates = mappings.get(ap_serial,{})
                if len(candidates) == 1:
                    (switch_serial,local_port), remote_ports = next(iter(candidates.items()))
                    if switch_serial == serial:
                        port_row = port_rows.get(local_port,{})
                        port_evidence = {'state': port_row.get('state') if port_row.get('state') in ('connected','disabled','disconnected') else None,
                            'speed':port_row.get('speed') if isinstance(port_row.get('speed'),str) and port_row['speed'] in SPEEDS else None,
                            'duplex':port_row.get('duplex') if port_row.get('duplex') in ('full','half') else None,
                            'error_count':_number(port_row.get('error_count'),integer=True),'warning_count':_number(port_row.get('warning_count'),integer=True)}
                        attached.append(ap | {'local_port':local_port,'neighbor_ports':remote_ports,'port_evidence':port_evidence})
            switches.append(_device(device) | {'port_status':port.get('status') if port.get('status') in ('complete','unsupported','unavailable','invalid_evidence') else 'unavailable',
                'review_port_count':_number(port_data.get('review_port_count'),integer=True),'reported_port_count':_number(port_data.get('reported_port_count'),integer=True),
                'connected_port_count':_number(port_data.get('connected_port_count'),integer=True),
                'discovery_status': 'complete' if serial in valid_discovery else 'unavailable',
                'power':{'energy_coverage':energy_data.get('energy_coverage') if energy_data.get('energy_coverage') in ('complete','partial','unavailable','invalid_evidence') else 'unavailable',
                    'measured_average_watts':_number(energy_data.get('measured_average_watts')),'requested_timespan_seconds':_number(energy_data.get('requested_timespan_seconds'),integer=True)},
                'aps':attached})
        for serial, ap in aps.items():
            count = len(mappings.get(serial,{}))
            if count == 0: unmatched.append(ap)
            elif count > 1: ambiguous.append(ap | {'mapping_count':count})
        client=clients.get(network_id,{});client_data=_data(client)
        counts={'assigned_ap_count':len(aps),'mapped_ap_count':sum(len(sw['aps']) for sw in switches),'unmapped_ap_count':len(unmatched),'ambiguous_ap_count':len(ambiguous),
                'review_band_count':sum(sum(b['review_threshold_met'] for b in ap['bands']) for ap in aps.values()),
                'ap_telemetry_unavailable_count':sum(ap['channel_status'] != 'complete' or ap['connection_status'] != 'complete' for ap in aps.values())}
        profiles = [p for control in _rows(snapshot.get('security_controls')) if control.get('network_id') == network_id and control.get('control') == 'Wireless RF profiles' and control.get('status') == 'complete' for p in _rows(control.get('data'))]
        wan_usage=[]
        for interface in _rows(_data(usage.get(network_id,{})).get('interfaces')):
            if interface.get('interface') not in ('wan1','wan2','wan3','cellular'): continue
            directions=interface.get('directions') if isinstance(interface.get('directions'),dict) else {}
            row={'interface':interface['interface']}
            for key,label in (('sent','upload'),('received','download')):
                direction=directions.get(key) if isinstance(directions.get(key),dict) else {}
                row[label]={field:_number(direction.get(field)) for field in ('average_mbps','peak_interval_average_mbps','observed_seconds')}
            wan_usage.append(row)
        output.append({'network_id':network_id,'name':_text(network.get('name')) or network_id,'edges':edges,'switches':switches,'unmapped_aps':unmatched,'ambiguous_aps':ambiguous,'summary':counts,
            'rf_profile_count':len(profiles),'wan_usage':wan_usage,'wireless_client_count':_number(client_data.get('wireless_client_count'),integer=True),'wireless_client_timespan_seconds':_number(client_data.get('requested_timespan_seconds'),integer=True)})
    summary={key:sum(n['summary'][key] for n in output) for key in ('assigned_ap_count','mapped_ap_count','unmapped_ap_count','ambiguous_ap_count','review_band_count','ap_telemetry_unavailable_count')}
    return {'schema_version':1,'status':'available','scope':SCOPE,'networks':output,'summary':summary}


def project_path_analysis(saved: Any, snapshot: dict, *, complete: bool = False) -> dict | None:
    if saved is None: return None
    if not isinstance(saved,dict) or type(saved.get('schema_version')) is not int or saved['schema_version'] != 1 or saved != build_path_analysis(snapshot):
        return {'schema_version':1,'status':'invalid_evidence','scope':SCOPE,'networks':[],'summary':None,'additional_networks':0}
    result=copy.deepcopy(saved)
    if complete: return result | {'additional_networks':0}
    result['additional_networks']=max(0,len(result['networks'])-20);result['networks']=result['networks'][:20]
    for network in result['networks']:
        for key,limit in (('edges',20),('switches',20),('unmapped_aps',50),('ambiguous_aps',50)):
            network['additional_'+key]=max(0,len(network[key])-limit);network[key]=network[key][:limit]
        for switch in network['switches']:
            switch['additional_aps']=max(0,len(switch['aps'])-50);switch['aps']=switch['aps'][:50]
    return result
