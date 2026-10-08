"""Extract narrowly scoped coverage from complete, hash-verified original XML."""
import hashlib
import ipaddress
import re

from lxml import etree

from daedalus.scanner_report_template import original_xml_documents


def _ports(services):
    if not isinstance(services, str) or len(services) > 400000:
        raise ValueError("Invalid scanned port list")
    ports = set()
    for token in services.split(','):
        if not re.fullmatch(r'[0-9]{1,5}(?:-[0-9]{1,5})?', token):
            raise ValueError("Invalid scanned port range")
        bounds = [int(x) for x in token.split('-')]
        first, last = bounds[0], bounds[-1]
        if not 1 <= first <= last <= 65535:
            raise ValueError("Invalid scanned port range")
        values = set(range(first, last + 1))
        if ports.intersection(values):
            raise ValueError("Duplicate scanned ports")
        ports.update(values)
    return ports


def coverage_from_xml_events(events):
    """No subnet/hostname inference; ambiguous repeated host scans stay unknown."""
    groups = {}
    for event in events:
        payload = event.get('payload')
        if (event.get('event_name') == 'scan_xml_chunk' and isinstance(payload, dict)
                and isinstance(payload.get('target'), str) and isinstance(payload.get('sha256'), str)):
            groups.setdefault((payload['target'], payload['sha256']), []).append(event)
    coverage, ambiguous = {}, set()
    target_counts = {}
    for target, digest in groups:
        try:
            network = ipaddress.ip_network(target, strict=False)
        except ValueError:
            return {}
        if network.num_addresses != 1:
            return {}
        address = str(network.network_address)
        target_counts[address] = target_counts.get(address, 0) + 1
    for (target, _), chunks in groups.items():
        try:
            address = str(ipaddress.ip_address(target))
            if target_counts[address] != 1:
                continue
            raw, = original_xml_documents(chunks)
            parser = etree.XMLParser(resolve_entities=False, no_network=True, load_dtd=False)
            root = etree.fromstring(raw, parser)
            info = root.getroottree().docinfo
            if (info.system_url or info.public_id or any(isinstance(x, etree._Entity) for x in root.iter())
                    or (info.internalDTD is not None and list(info.internalDTD.iterentities()))):
                continue
            hosts, scans = root.findall('host'), root.findall('scaninfo')
            counts, finished = root.find('runstats/hosts'), root.find('runstats/finished')
            if (root.tag != 'nmaprun' or len(hosts) != 1 or len(scans) != 1
                    or len(root.findall('runstats')) != 1 or len(root.findall('runstats/hosts')) != 1
                    or len(root.findall('runstats/finished')) != 1 or counts is None
                    or finished is None or finished.get('exit') != 'success'
                    or any(counts.get(k) != v for k, v in [('up', '1'), ('down', '0'), ('total', '1')])):
                continue
            host, scan = hosts[0], scans[0]
            addresses = [str(ipaddress.ip_address(x.get('addr'))) for x in host.findall('address')
                         if x.get('addrtype') in {'ipv4', 'ipv6'}]
            status = host.find('status')
            if (addresses != [address] or len(host.findall('status')) != 1
                    or len(host.findall('ports')) != 1 or status is None or status.get('state') != 'up'):
                continue
            protocol = scan.get('protocol')
            supported_types = {'tcp': {'connect', 'syn'}, 'udp': {'udp'}, 'sctp': {'sctpinit'}}
            if scan.get('type') not in supported_types.get(protocol, set()):
                continue
            ports = _ports(scan.get('services'))
            if scan.get('numservices') != str(len(ports)):
                continue
            explicit = {}
            for port in host.findall('ports/port'):
                number = int(port.get('portid'))
                state = port.find('state')
                if (port.get('protocol') != protocol or number not in ports or number in explicit
                        or len(port.findall('state')) != 1 or state is None or state.get('state') not in {'open', 'closed', 'filtered'}):
                    raise ValueError('Ambiguous explicit port evidence')
                explicit[number] = state.get('state')
            extra, extra_states = 0, set()
            for row in host.findall('ports/extraports'):
                count = row.get('count')
                if (not isinstance(count, str) or not re.fullmatch(r'[0-9]{1,5}', count)
                        or row.get('state') not in {'closed', 'filtered'} or row.get('state') in extra_states):
                    raise ValueError('Ambiguous aggregate port evidence')
                extra_states.add(row.get('state'))
                extra += int(count)
            if len(explicit) + extra != len(ports):
                continue
            if address in coverage or address in ambiguous:
                coverage.pop(address, None)
                ambiguous.add(address)
                continue
            # Compact ranges preserve exact scanned membership, not all ports.
            ranges = []
            for number in sorted(ports):
                if ranges and number == ranges[-1][1] + 1:
                    ranges[-1][1] = number
                else:
                    ranges.append([number, number])
            coverage[address] = {'scan_type': scan.get('type'), 'scanned_port_count': len(ports), 'target': str(ipaddress.ip_network(address)), 'protocol': protocol,
                'ranges': ranges, 'explicit_states': explicit, 'xml_sha256': hashlib.sha256(raw).hexdigest(),
                'source_event_ids': [x['id'] for x in chunks if type(x.get('id')) is int],
                'latest_xml_occurred_at': max((x.get('occurred_at', '') for x in chunks), default='')}
        except (ValueError, TypeError, etree.XMLSyntaxError):
            continue
    return coverage


def matches_observation(evidence, host):
    """Only associate XML with compatible explicit result observations."""
    observed_open = {number for (protocol, number), value in host['ports'].items()
                     if protocol == evidence['protocol'] and value['state'] == 'open'}
    xml_open = {number for number, state in evidence['explicit_states'].items() if state == 'open'}
    return observed_open == xml_open and all(protocol == evidence['protocol'] and evidence['explicit_states'].get(number) == value['state']
               for (protocol, number), value in host['ports'].items())
