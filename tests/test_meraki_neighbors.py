import copy, io
import httpx
import pytest
from pypdf import PdfReader
from daedalus.meraki_neighbors import inventory_lookup, summarize_neighbors, project_neighbors
from daedalus.meraki_api import MerakiClient, compare_meraki_snapshots
from daedalus.reports import build_meraki_security_pdf


def inventory():
    return [{'serial':'SW','model':'MS120','name':'Switch','networkId':'N','mac':'00:11:22:33:44:55'},
            {'serial':'AP','model':'MR44','name':'<script>AP</script>','networkId':'N','mac':'AA:BB:CC:DD:EE:FF'},
            {'serial':'OTHER','model':'MR44','networkId':'OTHER','mac':'11:22:33:44:55:66'}]


def evidence():
    devices=inventory()
    data=summarize_neighbors({'ports':{'1':{'lldp':{'chassisId':'aa-bb-cc-dd-ee-ff','portId':'eth0','systemName':'never-save','managementAddress':'never-save'}},
         '2':{'cdp':{'deviceId':'OTHER','portId':'GigabitEthernet1'}},'3':{}}}, inventory_lookup(devices,'N'),'SW')
    return {'devices':devices,'switch_neighbors':[{'network_id':'N','network_name':'HQ','device_serial':'SW','status':'complete','data':data}]}


def test_exact_identity_same_network_and_no_raw_discovery():
    s=evidence();data=s['switch_neighbors'][0]['data']
    assert data['matched_port_count']==1 and data['unmatched_port_count']==2
    assert data['rows'][0]['neighbor_serial']=='AP' and data['rows'][0]['neighbor_port']=='eth0'
    assert 'never-save' not in str(data) and 'aa-bb' not in str(data) and 'OTHER' not in str(data)
    before=copy.deepcopy(s);view=project_neighbors(s)['switches'][0]['data']
    assert view['rows'][0]['neighbor_name']=='<script>AP</script>' and view['rows'][1]['neighbor_name'] is None
    assert s==before and 'neighbor_serial' not in str(view)


def test_collision_self_and_conflicting_protocols_are_ambiguous():
    devices=inventory()+[{'serial':'SECOND','networkId':'N','mac':'aa:bb:cc:dd:ee:ff'}]
    for ports in ({'1':{'deviceMac':'aa:bb:cc:dd:ee:ff'}},{'1':{'cdp':{'deviceId':'SW'}}},
                  {'1':{'lldp':{'chassisId':'AP'},'cdp':{'deviceId':'SW'}}}):
        data=summarize_neighbors({'ports':ports},inventory_lookup(devices,'N'),'SW')
        assert data['ambiguous_port_count']==1 and data['rows'][0]['neighbor_serial'] is None
    devices.append({'serial':'SECOND','networkId':'N'})
    data=summarize_neighbors({'ports':{'1':{'lldp':{'chassisId':'AP'},'cdp':{'deviceId':'SECOND'}}}},inventory_lookup(devices,'N'),'SW')
    assert data['ambiguous_port_count']==1


def test_remote_conflict_preserves_neighbor_not_port_and_names_never_match():
    data=summarize_neighbors({'ports':{'1':{'lldp':{'chassisId':'AP','portId':'eth0'},'cdp':{'deviceId':'AP','portId':'eth1'}},
                                      '2':{'lldp':{'systemName':'AP','managementAddress':'AP'}}}},inventory_lookup(inventory(),'N'),'SW')
    assert data['rows'][0]['status']=='matched' and data['rows'][0]['remote_port_conflict'] and data['rows'][0]['neighbor_port'] is None
    assert data['rows'][0]['neighbor_ports']=={'lldp':'eth0','cdp':'eth1'}
    assert data['rows'][1]['status']=='unmatched'


@pytest.mark.parametrize('raw',[None,[],{}, {'ports':[]},{'ports':{' ':{}}},{'ports':{'1':[]}}, {'ports':{'1':{'lldp':[]}}}, {'ports':{str(i):{} for i in range(1025)}}])
def test_malformed_discovery_is_unavailable(raw):
    with pytest.raises(ValueError): summarize_neighbors(raw,{},'SW')


@pytest.mark.parametrize('change',['local','remote','network','cross','duplicate','nonswitch'])
def test_saved_projection_scope_and_corrupt_identity(change):
    s=evidence();ob=s['switch_neighbors'][0]
    if change=='local': ob['device_serial']=[]
    if change=='remote': ob['data']['rows'][0]['neighbor_serial']={}
    if change=='network': ob.pop('network_id')
    if change=='cross': ob['data']['rows'][0]['neighbor_serial']='OTHER'
    if change=='duplicate': ob['data']['rows'].append(copy.deepcopy(ob['data']['rows'][0]))
    if change=='nonswitch': ob['device_serial']='AP'
    view=project_neighbors(s)['switches'][0]
    assert view['status']=='invalid_evidence' and view['data'] is None


def test_bounds_recompute_counts_unknown_and_empty():
    s=evidence();ob=s['switch_neighbors'][0]
    ob['data']=summarize_neighbors({'ports':{str(i):{} for i in range(60)}},{},'SW')
    ob['data']['unmatched_port_count']=999
    s['switch_neighbors']*=22
    view=project_neighbors(s); assert view['additional_switches']==2 and len(view['switches'])==20
    data=view['switches'][0]['data'];assert len(data['rows'])==50 and data['additional_rows']==10 and data['unmatched_port_count']==60
    assert len(project_neighbors(s,complete=True)['switches'][0]['data']['rows'])==60
    ob['status']='unsupported';assert project_neighbors(s)['switches'][0]['data'] is None
    ob['status']='complete';ob['data']=summarize_neighbors({'ports':{}},{},'SW');assert project_neighbors(s)['switches'][0]['data']['reported_port_count']==0


def test_collector_readonly_scoped_and_raw_mac_not_saved():
    calls=[]
    responses={'/organizations':[{'id':'O','name':'School'}],'/organizations/O/networks':[{'id':'N','name':'HQ','productTypes':['switch','wireless']},{'id':'OTHER','name':'Other','productTypes':[]}],
               '/organizations/O/devices':inventory(), '/organizations/O/devices/availabilities':[],
               '/devices/SW/lldpCdp':{'sourceMac':'never-save','ports':{'1':{'lldp':{'chassisId':'aabbccddeeff','portId':'eth0','systemName':'never-save'}}}}}
    def respond(request):
        assert request.method=='GET'
        path=request.url.path.removeprefix('/api/v1');calls.append(path)
        if path.endswith('/lldpCdp'): assert not request.url.query
        return httpx.Response(200,json=responses[path]) if path in responses else httpx.Response(404,json={})
    with MerakiClient('fixture',transport=httpx.MockTransport(respond),request_interval=0) as client:
        report=client.collect_security_report('O')
    assert calls.count('/devices/SW/lldpCdp')==1
    ob=report['switch_neighbors'][0];assert ob['device_serial']=='SW' and ob['data']['matched_port_count']==1 and ob['pdf_evidence_summary_version']==1
    assert 'aabbcc' not in str(report) and 'AA:BB' not in str(report) and 'never-save' not in str(report)
    other=copy.deepcopy(report);other['security_controls']=[copy.deepcopy(ob)];report['security_controls']=[ob]
    other['security_controls'][0]['data']['rows'][0]['neighbor_port']='eth1'
    assert compare_meraki_snapshots(report,other)['changed_control_count']==1


def test_pdf_appendix_preserves_all_existing_content_streams():
    s={'domain':'example.test','meraki':evidence()};s['meraki']['collected_at']='2026-10-08T00:00:00Z';saved=s['meraki'].pop('switch_neighbors')
    old=PdfReader(io.BytesIO(build_meraki_security_pdf(s)))
    s['meraki']['switch_neighbors']=saved;new=PdfReader(io.BytesIO(build_meraki_security_pdf(s)))
    assert len(new.pages)>len(old.pages)
    assert all(a.get_contents().get_data()==b.get_contents().get_data() for a,b in zip(old.pages,new.pages))
    assert 'Switch port relationships' in new.pages[-1].extract_text() and '<script>AP</script>' in new.pages[-1].extract_text()


def test_protocol_port_projection_allowlist_and_unknown_schema():
    s=evidence();ob=s['switch_neighbors'][0];row=ob['data']['rows'][0]
    row['neighbor_ports']={'lldp':'eth0','cdp':'GigabitEthernet0','private':'never-save'}
    assert project_neighbors(s)['switches'][0]['data']['rows'][0]['neighbor_ports']=={'lldp':'eth0','cdp':'GigabitEthernet0'}
    for data in (None,{}, {'schema_version':True},{'schema_version':2}):
        ob['data']=data;view=project_neighbors(s)['switches'][0];assert view['data'] is None and view['status']=='invalid_evidence'


def test_new_protocol_port_detail_is_coverage_not_a_network_change():
    ob=evidence()['switch_neighbors'][0];ob['control']='Switch managed neighbors'
    current={'organization':{'id':'O'},'security_controls':[ob]}
    previous=copy.deepcopy(current);old=previous['security_controls'][0]['data'];old.pop('port_id_detail_version')
    for row in old['rows']: row.pop('neighbor_ports')
    comparison=compare_meraki_snapshots(previous,current)
    assert comparison['changed_control_count']==0
    assert comparison['coverage_changes'][0]['evidence_dimension']=='remote_port_ids'
    assert comparison['coverage_changes'][0]['previous_status']=='not_collected'
    assert comparison['coverage_changes'][0]['current_status']=='complete'
    changed=copy.deepcopy(current);changed['security_controls'][0]['data']['rows'][0]['neighbor_ports']['lldp']='eth2'
    comparison=compare_meraki_snapshots(current,changed)
    assert comparison['changed_control_count']==1 and comparison['coverage_changes']==[]
