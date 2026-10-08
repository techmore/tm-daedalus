import copy
import io
import math
import pytest
from pypdf import PdfReader
from daedalus.meraki_switch import summarize_switch_ports, project_switch_ports, MAX_PORTS
from daedalus.meraki_api import compare_meraki_snapshots
from daedalus.reports import build_meraki_security_pdf


def port(**values):
    return {'portId': '1', 'enabled': True, 'status': 'Connected', 'isUplink': True,
            'speed': '100 Mbps', 'duplex': 'full', 'errors': [], 'warnings': [], **values}


def test_low_uplink_link_state_config_join_diagnostics_and_zero_counters():
    data = summarize_switch_ports([port(trafficInKbps={'total': 0}, usageInKb={'total': 123}, powerUsageInWh=0)],
        [{'portId': '1', 'type': 'trunk', 'vlan': 10}, {'portId': '2'}])
    row = data['rows'][0]
    assert row['review_prompts'] == ['Uplink negotiated at 10/100 Mbps']
    assert row['mode'] == 'trunk' and row['vlan'] == 10
    assert row['traffic_kbps']['total'] == 0 and row['traffic_kbps']['sent'] is None
    assert row['usage_kb']['total'] == 123 and row['power_usage_wh'] == 0
    assert data['missing_status_port_count'] == 1 and data['review_port_count'] == 1
    assert data['diagnostic_coverage_port_count'] == 1


def test_unknown_configuration_and_status_are_not_healthy_zero():
    data = summarize_switch_ports([{'portId': '1'}])
    assert data['configured_port_count'] is None and data['missing_status_port_count'] is None
    assert data['unknown_state_port_count'] == data['unknown_uplink_port_count'] == 1
    assert data['rows'][0]['error_count'] is None and data['rows'][0]['configured'] is None
    assert data['rows'][0]['speed'] is None and data['rows'][0]['vlan'] is None


def test_original_expected_access_disconnect_suppression_and_disabled_uplink():
    data = summarize_switch_ports([port(isUplink=False, status='Disconnected', errors=['Port disconnected', 'Port disabled']),
        port(portId='2', enabled=False, status='Disconnected'), port(portId='3', status='Disconnected')])
    assert data['rows'][0]['error_count'] == 2 and not data['rows'][0]['review_prompts']
    assert not data['rows'][1]['review_prompts']
    assert data['rows'][2]['review_prompts'] == ['Enabled uplink disconnected']


def test_fault_prompts_and_private_fields_not_retained():
    data = summarize_switch_ports([port(speed='1 Gbps', duplex='half', errors=['secret neighbor'], warnings=['private diagnostic'],
        lldp={'managementAddress':'10.0.0.1'}, cdp={'systemName':'private-name'}, clientCount=4, api_key='secret')])
    row = data['rows'][0]
    assert row['review_prompts'] == ['Connected port reports half duplex', 'Reported port errors', 'Reported port warnings']
    assert row['error_count'] == row['warning_count'] == 1
    assert 'private-name' not in str(data) and 'secret neighbor' not in str(data) and '10.0.0.1' not in str(data)


@pytest.mark.parametrize('value', [None, True, '1', -1, math.nan, math.inf, 10**400, 10**15+1, {}])
def test_invalid_numeric_counters_remain_unknown(value):
    row = summarize_switch_ports([port(powerUsageInWh=value, usageInKb={'total':value}, trafficInKbps={'total':value})])['rows'][0]
    assert row['power_usage_wh'] is None and row['usage_kb']['total'] is None and row['traffic_kbps']['total'] is None


@pytest.mark.parametrize('rows', [None, {}, [None], [{}], [port(),port()], [port(portId='bad id')], [port(portId='a'*65)], [port(portId=str(i)) for i in range(MAX_PORTS+1)]])
def test_invalid_or_duplicate_port_identity_is_refused(rows):
    with pytest.raises(ValueError): summarize_switch_ports(rows)


def test_malformed_diagnostic_and_field_types_unknown():
    row = summarize_switch_ports([port(errors='none', warnings=[1], speed={}, duplex={}, enabled=1, isUplink=0)], [{'portId':'1','vlan':True,'type':{}}])['rows'][0]
    assert all(row[key] is None for key in ('error_count','warning_count','speed','duplex','enabled','is_uplink','vlan','mode'))


def test_projection_prioritizes_review_and_preserves_complete_saved_order():
    rows = [port(portId=str(i),speed='1 Gbps') for i in range(70)]
    rows[-1]['speed'] = '100 Mbps'
    data = summarize_switch_ports(rows)
    data['private_field']='secret'
    observations=[{'device_serial':f'SW_{i}','status':'complete','private_field':'secret','data':data} for i in range(22)]
    original = copy.deepcopy(observations)
    result=project_switch_ports(observations)
    assert len(result['switches']) == 20 and result['additional_switches'] == 2
    assert len(result['switches'][0]['data']['rows']) == 50 and result['switches'][0]['data']['additional_rows'] == 20
    assert result['switches'][0]['data']['rows'][0]['port_id'] == '69'
    assert 'secret' not in str(result) and observations == original


def test_rolling_port_observations_do_not_trigger_configuration_change():
    baseline={'organization':{'id':'ORG'},'security_controls':[],'switch_ports':[{'data':summarize_switch_ports([port()])}]}
    changed=copy.deepcopy(baseline);changed['switch_ports'][0]['data']['rows'][0]['traffic_kbps']['total']=999
    assert compare_meraki_snapshots(baseline,changed)['changed_control_count']==0


def test_appendix_preserves_all_original_page_streams_and_escapes_text():
    snapshot={'domain':'example.test','meraki':{'organization':{'name':'Fixture'},'collected_at':'2026-10-08T00:00:00Z'}}
    legacy=PdfReader(io.BytesIO(build_meraki_security_pdf(snapshot)))
    snapshot['meraki']['switch_ports']=[{'device_name':'<script>literal</script>','network_name':'HQ','status':'complete',
        'configuration_status':'complete','data':summarize_switch_ports([port()],[{'portId':'1','vlan':10,'type':'trunk'}])}]
    enhanced=PdfReader(io.BytesIO(build_meraki_security_pdf(snapshot)))
    assert len(enhanced.pages)==len(legacy.pages)+1
    assert all(a.get_contents().get_data()==b.get_contents().get_data() for a,b in zip(legacy.pages,enhanced.pages))
    text=enhanced.pages[-1].extract_text()
    assert '<script>literal</script>' in text and 'Uplink negotiated at 10/100 Mbps' in text


def test_projection_omits_unknown_nested_values_and_bounds_display_strings():
    result=project_switch_ports([{'device_name':'x'*1000,'data':{'private':'secret','rows':[{'port_id':'1','usage_kb':{'total':0,'private':'secret'},'traffic_kbps':{},'review_prompts':['x'*1000]*100,'private':'secret'}]}}])
    switch=result['switches'][0];row=switch['data']['rows'][0]
    assert len(switch['device_name'])==240
    assert row['usage_kb']=={'total':0,'sent':None,'recv':None}
    assert len(row['review_prompts'])==5 and len(row['review_prompts'][0])==160
    assert 'secret' not in str(result)
