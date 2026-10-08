import hashlib

import pytest

from daedalus.scanner_comparison import normalize_snapshot, compare_snapshots
from daedalus.scanner_xml_coverage import coverage_from_xml_events, matches_observation

XML = b'''<nmaprun><scaninfo type="connect" protocol="tcp" numservices="3" services="22,80,443"/>
<host><status state="up"/><address addr="127.0.0.1" addrtype="ipv4"/>
<ports><extraports state="closed" count="2"/><port protocol="tcp" portid="22"><state state="open"/></port></ports>
</host><runstats><finished exit="success"/><hosts up="1" down="0" total="1"/></runstats></nmaprun>'''


def chunks(xml=XML, target='127.0.0.1'):
    return [{'id': 1, 'event_name': 'scan_xml_chunk', 'occurred_at': '2026-10-08T00:00:00Z', 'payload': {
        'target': target, 'sha256': hashlib.sha256(xml).hexdigest(), 'byte_count': len(xml),
        'chunk_index': 0, 'chunk_count': 1, 'xml': xml.decode()}}]


def test_complete_original_xml_retains_exact_scanned_port_membership():
    proof = coverage_from_xml_events(chunks())['127.0.0.1']
    assert proof['target'] == '127.0.0.1/32'
    assert proof['ranges'] == [[22, 22], [80, 80], [443, 443]]
    assert proof['xml_sha256'] == hashlib.sha256(XML).hexdigest()
    host = normalize_snapshot([{'ip':'127.0.0.1', 'ports':[{'port':22,'protocol':'tcp','state':'open'}]}])['hosts']['127.0.0.1']
    assert matches_observation(proof, host)
    assert not matches_observation(proof, {'ports': {}})


@pytest.mark.parametrize('xml', [
    XML.replace(b'exit="success"', b'exit="error"'),
    XML.replace(b'type="connect"', b'type="ack"'),
    XML.replace(b'extraports state="closed"', b'extraports state="open"'),
    XML.replace(b'<state state="open"', b'<state state="open|filtered"'),
    XML.replace(b'count="2"', b'count="1"'),
    XML.replace(b'numservices="3"', b'numservices="4"'),
    XML.replace(b'22,80,443', b'22,22,443'),
    XML.replace(b'22,80,443', b'0,80,443'),
    XML.replace(b'addr="127.0.0.1"', b'addr="127.0.0.2"'),
    b'<!DOCTYPE nmaprun SYSTEM "https://example.com/dtd">'+XML,
])
def test_incomplete_failed_ambiguous_or_external_xml_has_no_coverage(xml):
    assert coverage_from_xml_events(chunks(xml)) == {}


def test_missing_corrupt_subnet_or_repeated_host_documents_remain_unknown():
    corrupt = chunks(); corrupt[0]['payload']['xml'] += ' '
    assert coverage_from_xml_events(corrupt) == {}
    assert coverage_from_xml_events(chunks(target='127.0.0.0/24')) == {}
    assert coverage_from_xml_events(chunks(target='localhost')) == {}
    assert coverage_from_xml_events(chunks()+chunks(XML.replace(b'<nmaprun>', b'<nmaprun version="different">'))) == {}
    malformed = [{'event_name':'scan_xml_chunk','payload':{'target':[], 'sha256':{}}}]
    assert coverage_from_xml_events(malformed) == {}


def test_removal_requires_port_membership_in_both_scans_and_equal_targets():
    old = normalize_snapshot({'hosts':[{'ip':'127.0.0.1','ports':[
        {'port':22,'protocol':'tcp','state':'open'}, {'port':9000,'protocol':'tcp','state':'open'}]}], 'covered_targets':['127.0.0.1']})
    new = normalize_snapshot({'hosts':[{'ip':'127.0.0.1','ports':[]}], 'covered_targets':['127.0.0.1']})
    old['hosts']['127.0.0.1']['scanned_ports'] = {'tcp':[[22,22],[9000,9000]]}
    new['hosts']['127.0.0.1']['scanned_ports'] = {'tcp':[[22,22]]}
    result = compare_snapshots(old,new,previous_status='completed',current_status='completed')
    rows = {x['port']:x for x in result['port_changes']}
    assert rows[22]['change'] == 'removed' and rows[22]['confirmed']
    assert rows[9000]['change'] == 'not_observed' and not rows[9000]['confirmed']
    new['covered_targets'] = None
    assert compare_snapshots(old,new,previous_status='completed',current_status='completed')['counts']['confirmed_removed_ports'] == 0
