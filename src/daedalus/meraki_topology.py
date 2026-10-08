"""Named, scoped views of saved managed-device topology observations."""
from typing import Any


def _text(value: Any, limit: int = 240) -> str:
    return value[:limit] if isinstance(value, str) else ''


def _count(value: Any) -> int | None:
    return value if type(value) is int and 0 <= value <= 10**9 else None


def project_topology(snapshot: dict, *, complete: bool = False) -> dict:
    observations = snapshot.get('topology') if isinstance(snapshot.get('topology'), list) else []
    devices = snapshot.get('devices') if isinstance(snapshot.get('devices'), list) else []
    inventory = {d['serial']: d for d in devices if isinstance(d, dict) and isinstance(d.get('serial'), str)}
    result = []
    network_limit, node_limit, link_limit = (500, 5000, 10000) if complete else (20, 50, 100)
    for observation in observations[:network_limit]:
        if not isinstance(observation, dict): continue
        view = {'network_name': _text(observation.get('network_name')), 'status': _text(observation.get('status'),40),
                'nodes': [], 'links': [], 'node_count': None, 'link_count': None, 'isolated_node_count': None,
                'root_node_count': None, 'additional_nodes': 0, 'additional_links': 0}
        data = observation.get('data')
        if view['status'] != 'complete' or not isinstance(data, dict):
            result.append(view);continue
        raw_nodes = data.get('nodes') if isinstance(data.get('nodes'), list) else None
        raw_links = data.get('links') if isinstance(data.get('links'), list) else None
        if raw_nodes is None or raw_links is None or len(raw_nodes)>5000 or len(raw_links)>10000:
            view['status']='invalid_evidence';result.append(view);continue
        network_id = observation.get('network_id')
        if not isinstance(network_id, str) or not network_id:
            view['status']='invalid_evidence';result.append(view);continue
        allowed = {serial: d for serial,d in inventory.items() if isinstance(network_id,str) and d.get('networkId')==network_id}
        nodes = {}
        invalid = False
        for row in raw_nodes:
            if not isinstance(row, dict) or not isinstance(row.get('device_serial'), str) or row['device_serial'] not in allowed: continue
            serial = row['device_serial']
            if serial in nodes: invalid=True;break
            device=allowed[serial]
            nodes[serial]={'device_serial':serial,'name':_text(device.get('name')) or _text(device.get('model')) or _text(serial),
                'model':_text(device.get('model'),80),'reported_root': row.get('root') if type(row.get('root')) is bool else None}
        pairs = {}; touched = set()
        for row in raw_links:
            ends = row.get('device_serials') if isinstance(row, dict) else None
            count = _count(row.get('link_count')) if isinstance(row, dict) else None
            if not isinstance(ends,list) or len(ends)!=2 or any(not isinstance(v,str) for v in ends) or count is None or count==0:
                invalid=True;break
            if ends[0]==ends[1]: invalid=True;break
            if any(v not in nodes for v in ends):continue
            pair=tuple(sorted(ends))
            if pair in pairs:invalid=True;break
            pairs[pair]=count;touched.update(pair)
        if invalid:
            view['status']='invalid_evidence';result.append(view);continue
        node_rows=sorted(nodes.values(),key=lambda row:(row['name'].casefold(),row['device_serial']))
        shown=node_rows[:node_limit];shown_ids={row['device_serial'] for row in shown}
        links=[{'device_serials':list(pair),'endpoint_names':[nodes[v]['name'] for v in pair],
                'link_count':count} for pair,count in sorted(pairs.items()) if all(v in shown_ids for v in pair)]
        view.update({'nodes':shown,'links':links[:link_limit],'node_count':len(nodes),'link_count':len(pairs),
            'isolated_node_count':len(nodes.keys()-touched),'root_node_count':sum(row['reported_root'] is True for row in nodes.values()),
            'additional_nodes':max(0,len(nodes)-len(shown)), 'additional_links':len(pairs)-min(len(links),link_limit),
            'excluded_node_count':len(raw_nodes)-len(nodes),'excluded_link_pair_count':len(raw_links)-len(pairs),
            'omitted_node_count':_count(data.get('omitted_node_count')),'omitted_link_count':_count(data.get('omitted_link_count')),
            'reported_error_count':_count(data.get('reported_error_count'))})
        result.append(view)
    return {'networks':result,'additional_networks':max(0,len(observations)-network_limit),
        'scope':'Observed undirected relationships between assigned devices in the same saved network. Root flags are API observations. Link counts count reported relationships, not verified redundant cables. Layout does not establish traffic direction, Internet reachability or a complete topology; devices without observed links are not inferred offline.'}
