import copy,io,math
import pytest
from pypdf import PdfReader
from daedalus.meraki_paths import build_path_analysis,project_path_analysis
from daedalus.meraki_neighbors import summarize_neighbors,inventory_lookup
from daedalus.meraki_switch import summarize_switch_ports
from daedalus.reports import build_meraki_security_pdf


def snapshot():
    devices=[{'serial':'SW','name':'Switch','model':'MS120','networkId':'N','status':'online'},
             {'serial':'AP','name':'<script>AP</script>','model':'MR44','networkId':'N','status':'online'},
             {'serial':'AP2','name':'AP2','model':'MR44','networkId':'OTHER'},
             {'serial':'MX','name':'Edge','model':'MX100','networkId':'N'}]
    return {'collected_at':'2026-10-08T00:00:00Z','networks':[{'id':'N','name':'HQ'},{'id':'OTHER','name':'Other'}],'devices':devices,
            'switch_neighbors':[{'device_serial':'SW','network_id':'N','network_name':'HQ','status':'complete','data':summarize_neighbors({'ports':{'1':{'lldp':{'chassisId':'AP','portId':'0'}}}},inventory_lookup(devices,'N'),'SW')}],
            'switch_ports':[{'device_serial':'SW','status':'complete','data':summarize_switch_ports([{'portId':'1','status':'Connected','speed':'1 Gbps','duplex':'full','errors':[],'warnings':[]}])}],
            'switch_power':[{'device_serial':'SW','status':'complete','data':{'energy_coverage':'partial','measured_average_watts':0,'requested_timespan_seconds':86400}}],
            'channel_utilization':{'status':'complete','data':{'requested_timespan_seconds':86400,'rows':[
                {'device_serial':'AP','network_id':'N','band':'5','percentages':{'wifi':0,'total':50,'nonWifi':20}},
                {'device_serial':'AP','network_id':'OTHER','band':'6','percentages':{'total':100}}]}},
            'wireless_connections':[{'network_id':'N','status':'complete','data':{'requested_timespan_seconds':86400,'devices':[{'device_serial':'AP','counters':{'success':0,'assoc':0,'auth':0,'dhcp':0,'dns':0}}]}}],
            'wan_uplinks':{'status':'complete','data':{'rows':[{'device_serial':'MX','network_id':'N','interface':'wan1','state':'active','address':'never-save'}]}},
            'wireless_clients':[{'network_id':'N','status':'complete','data':{'wireless_client_count':0,'requested_timespan_seconds':3600}}],
            'wan_usage':[{'network_id':'N','status':'complete','data':{'interfaces':[{'interface':'wan1','directions':{'sent':{'average_mbps':0},'received':{'average_mbps':1}}}]}}]}


def test_scoped_grouping_zero_unknown_timespans_and_no_derived_rate():
    s=snapshot();before=copy.deepcopy(s);a=build_path_analysis(s)
    assert a['summary']=={'assigned_ap_count':2,'mapped_ap_count':1,'unmapped_ap_count':1,'ambiguous_ap_count':0,'review_band_count':1,'ap_telemetry_unavailable_count':1}
    n=a['networks'][0];ap=n['switches'][0]['aps'][0]
    assert ap['local_port']=='1' and ap['port_evidence']['speed']=='1 Gbps'
    assert len(ap['bands'])==1 and ap['bands'][0]['percentages']['wifi']==0
    assert ap['connection_counters']['success']==0 and ap['connection_status']=='complete'
    assert ap['connection_timespan_seconds']==86400 and n['wireless_client_timespan_seconds']==3600
    assert n['switches'][0]['power']['measured_average_watts']==0 and n['switches'][0]['power']['energy_coverage']=='partial'
    assert a['networks'][1]['unmapped_aps'][0]['connection_counters']['success'] is None
    assert n['edges'][0]['interfaces']==[{'interface':'wan1','state':'active'}]
    assert n['wan_usage'][0]['upload']['average_mbps']==0 and n['wan_usage'][0]['upload']['observed_seconds'] is None
    assert 'never-save' not in str(a) and 'failure_rate' not in str(a) and s==before


def test_multiple_switch_ports_make_ap_mapping_ambiguous_not_arbitrary():
    s=snapshot();ob=s['switch_neighbors'][0];ob['data']['rows'].append(ob['data']['rows'][0] | {'local_port':'2'})
    a=build_path_analysis(s);n=a['networks'][0]
    assert n['switches'][0]['aps']==[] and n['summary']['ambiguous_ap_count']==1
    assert n['ambiguous_aps'][0]['mapping_count']==2


@pytest.mark.parametrize('field',['networks','devices','switch_neighbors','switch_ports','switch_power','wireless_connections'])
def test_duplicate_evidence_is_invalid_not_a_healthy_empty_review(field):
    s=snapshot();s[field].append(copy.deepcopy(s[field][0]));a=build_path_analysis(s)
    assert a['status']=='invalid_evidence' and a['summary'] is None


def test_invalid_discovery_and_cross_network_ap_never_join():
    s=snapshot();s['switch_neighbors'][0]['data']['rows'][0]['neighbor_serial']='AP2'
    a=build_path_analysis(s);assert a['summary']['mapped_ap_count']==0 and a['summary']['unmapped_ap_count']==2
    assert a['networks'][0]['switches'][0]['discovery_status']=='unavailable'


@pytest.mark.parametrize('bad',[True,-1,math.inf,math.nan,'50'])
def test_invalid_numeric_telemetry_is_unknown(bad):
    s=snapshot();s['channel_utilization']['data']['rows'][0]['percentages']['total']=bad
    s['wireless_connections'][0]['data']['devices'][0]['counters']['success']=bad
    ap=build_path_analysis(s)['networks'][0]['switches'][0]['aps'][0]
    assert ap['bands'][0]['percentages']['total'] is None and ap['connection_counters']['success'] is None
    assert ap['channel_status']=='partial' and ap['connection_status']=='partial'


def test_missing_and_malformed_telemetry_remain_unavailable():
    s=snapshot();s['channel_utilization']['data']=[];s['wireless_connections'][0]['data']=None
    ap=build_path_analysis(s)['networks'][0]['switches'][0]['aps'][0]
    assert ap['bands']==[] and ap['channel_status']=='unavailable' and ap['connection_status']=='unavailable'
    assert build_path_analysis({})['status']=='invalid_evidence'


def test_projection_immutable_integrity_schema_and_private_fields():
    s=snapshot();a=build_path_analysis(s);before=copy.deepcopy(a);assert project_path_analysis(a,s)['summary']==a['summary'] and a==before
    assert project_path_analysis(None,s) is None
    for bad in (a | {'schema_version':True},a | {'schema_version':2},a | {'private':'never-save'}):
        view=project_path_analysis(bad,s);assert view['status']=='invalid_evidence' and 'never-save' not in str(view)
    s['devices'][1]['networkId']='OTHER';assert project_path_analysis(a,s)['status']=='invalid_evidence'


def test_projection_bounds_keep_total_mapping_counts_and_full_evidence():
    s={'networks':[{'id':str(i),'name':str(i)} for i in range(22)],'devices':[{'serial':str(i),'model':'MR44','networkId':'0'} for i in range(60)]}
    a=build_path_analysis(s);view=project_path_analysis(a,s)
    assert view['additional_networks']==2 and len(view['networks'])==20
    n=view['networks'][0];assert len(n['unmapped_aps'])==50 and n['additional_unmapped_aps']==10 and n['summary']['unmapped_ap_count']==60
    assert len(project_path_analysis(a,s,complete=True)['networks'][0]['unmapped_aps'])==60


def test_pdf_appendix_preserves_previous_content_streams():
    s={'domain':'example.test','meraki':snapshot()};old=PdfReader(io.BytesIO(build_meraki_security_pdf(s)))
    s['meraki_path_analysis']=build_path_analysis(s['meraki']);new=PdfReader(io.BytesIO(build_meraki_security_pdf(s)))
    assert len(new.pages)>len(old.pages)
    assert all(a.get_contents().get_data()==b.get_contents().get_data() for a,b in zip(old.pages,new.pages))
    text=' '.join(page.extract_text() for page in new.pages[len(old.pages):])
    assert 'Network traffic and connection review' in text and '<script>AP</script>' in text and 'Unavailable' in text


def test_switch_edge_and_mapped_ap_preview_bounds():
    s={'networks':[{'id':'N','name':'HQ'}], 'devices':[{'serial':f'S{i}','name':f'S{i:02}','model':'MS120','networkId':'N'} for i in range(22)]
       +[{'serial':f'M{i}','model':'MX100','networkId':'N'} for i in range(22)]
       +[{'serial':f'A{i}','model':'MR44','networkId':'N'} for i in range(60)]}
    s['switch_neighbors']=[{'device_serial':'S0','network_id':'N','status':'complete','data':summarize_neighbors({'ports':{str(i):{'lldp':{'chassisId':f'A{i}'}} for i in range(60)}},inventory_lookup(s['devices'],'N'),'S0')}]
    analysis=build_path_analysis(s);view=project_path_analysis(analysis,s)['networks'][0]
    assert len(view['switches'])==20 and view['additional_switches']==2
    assert len(view['edges'])==20 and view['additional_edges']==2
    assert view['summary']['mapped_ap_count']==60 and len(view['switches'][0]['aps'])==50 and view['switches'][0]['additional_aps']==10
    full=project_path_analysis(analysis,s,complete=True)['networks'][0]
    assert len(full['switches'])==22 and len(full['edges'])==22 and len(full['switches'][0]['aps'])==60


def test_duplicate_rf_band_is_invalid_and_missing_counter_not_zero():
    s=snapshot();rows=s['channel_utilization']['data']['rows'];rows.append(copy.deepcopy(rows[0]))
    del s['wireless_connections'][0]['data']['devices'][0]['counters']['dns']
    analysis=build_path_analysis(s);ap=analysis['networks'][0]['switches'][0]['aps'][0]
    assert ap['channel_status']=='invalid_evidence' and ap['bands']==[]
    assert ap['connection_status']=='partial' and ap['connection_counters']['dns'] is None
    assert analysis['summary']['ap_telemetry_unavailable_count']==2
