import copy
import io
import math

import httpx
import pytest
from pypdf import PdfReader

from daedalus.meraki_api import MerakiAPIError, MerakiClient, compare_meraki_snapshots, summarize_switch_power
from daedalus.meraki_planning import build_unifi_plan
from daedalus.reports import build_meraki_security_pdf


def test_power_partial_measurements_do_not_become_zero_or_peak_capacity():
    data = summarize_switch_power([{'portId': '1', 'powerUsageInWh': 240, 'poe': {'isAllocated': True}},
                                   {'portId': '2', 'powerUsageInWh': 0}, {'portId': '3'}])
    assert data['measured_energy_wh'] == 240
    assert data['measured_average_watts'] == 10
    assert data['measured_port_count'] == 2
    assert data['unmeasured_port_count'] == 1
    assert data['allocated_port_count'] == 1
    assert data['energy_coverage'] == 'partial'
    assert data['requested_timespan_seconds'] == 86400


@pytest.mark.parametrize('value', [None, True, '24', -1, math.nan, math.inf, 10**400])
def test_invalid_energy_stays_unavailable(value):
    data = summarize_switch_power([{'portId': '1', 'powerUsageInWh': value}])
    assert data['energy_coverage'] == 'unavailable'
    assert data['measured_energy_wh'] is None
    assert data['measured_average_watts'] is None


def test_empty_and_all_measured_zero_are_distinct():
    assert summarize_switch_power([])['measured_energy_wh'] is None
    data = summarize_switch_power([{'portId': '1', 'powerUsageInWh': 0}])
    assert data['energy_coverage'] == 'complete'
    assert data['measured_energy_wh'] == 0


@pytest.mark.parametrize('rows', [[{'portId': '1'}, {'portId': '1'}], [{}], [{'portId': 'a' * 129}]])
def test_unstable_identities_are_refused(rows):
    with pytest.raises(MerakiAPIError):
        summarize_switch_power(rows)


def collect_power(status=200, payload=None):
    seen = []
    responses = {
        '/organizations': [{'id': 'org-1', 'name': 'Fixture'}],
        '/organizations/org-1/networks': [{'id': 'N_1', 'name': 'HQ', 'productTypes': ['switch']}],
        '/organizations/org-1/devices': [{'serial': 'SW_1', 'model': 'MS120-24P', 'networkId': 'N_1'}],
        '/organizations/org-1/devices/availabilities': [],
    }
    def respond(request):
        path = request.url.path.removeprefix('/api/v1')
        if path.endswith('/statuses'):
            seen.append(request)
            return httpx.Response(status, json=payload)
        return httpx.Response(200, json=responses[path]) if path in responses else httpx.Response(404, json={})
    with MerakiClient('fixture-only', transport=httpx.MockTransport(respond), request_interval=0) as client:
        result = client.collect_security_report('org-1')
    assert len(seen) == 1
    assert seen[0].url.params['timespan'] == '86400'
    return result


def test_collection_uses_same_bounded_request_and_excludes_sensitive_fields():
    result = collect_power(payload=[{'portId': '1', 'status': 'Connected', 'powerUsageInWh': 48,
                                     'poe': {'isAllocated': True}, 'lldp': {'systemName': 'private-neighbor'}}])
    assert result['switch_power'][0]['data']['measured_average_watts'] == 2
    assert 'private-neighbor' not in str(result)
    control = next(row for row in result['security_controls'] if row['control'] == 'Switch port status')
    assert 'powerUsageInWh' not in control['data'][0]
    changed = copy.deepcopy(result)
    changed['switch_power'][0]['data']['measured_energy_wh'] = 120
    assert compare_meraki_snapshots(result, changed)['changed_control_count'] == 0


@pytest.mark.parametrize('status,expected', [(403, 'unavailable'), (404, 'unsupported')])
def test_failed_collection_preserves_coverage(status, expected):
    row = collect_power(status=status, payload={})['switch_power'][0]
    assert row['status'] == expected
    assert row['data'] is None


def test_invalid_power_identity_does_not_invalidate_saved_status_control():
    result = collect_power(payload=[{'portId': '1'}, {'portId': '1'}])
    assert result['switch_power'][0]['data']['energy_coverage'] == 'invalid_evidence'


def test_pdf_appendix_preserves_existing_pages_and_purchase_links():
    snapshot = {'domain': 'fixture.invalid', 'meraki': {'organization': {'id': 'org-1', 'name': 'Fixture'},
                 'collected_at': '2026-10-08T00:00:00Z', 'devices': [{'model': 'MS120-24P'}]}}
    snapshot['unifi_plan'] = build_unifi_plan(snapshot['meraki'])
    original = PdfReader(io.BytesIO(build_meraki_security_pdf(snapshot)))
    snapshot['meraki']['switch_power'] = [{'device_serial': 'SW_1', 'network_name': 'HQ', 'status': 'complete',
        'data': summarize_switch_power([{'portId': '1', 'powerUsageInWh': 240}])}]
    enhanced = PdfReader(io.BytesIO(build_meraki_security_pdf(snapshot)))
    assert len(enhanced.pages) == len(original.pages) + 1
    for old, new in zip(original.pages, enhanced.pages):
        assert old.get_contents().get_data() == new.get_contents().get_data()
    text = enhanced.pages[-1].extract_text()
    assert 'Switch PoE usage observations' in text
    assert '240 Wh / 10.0 W' in text
    assert 'not peak demand' in ' '.join(text.split())
