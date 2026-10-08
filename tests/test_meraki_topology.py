import copy,io
import pytest
from pypdf import PdfReader
from daedalus.meraki_topology import project_topology
from daedalus.reports import build_meraki_security_pdf


def snapshot():
    return {'devices':[{'serial':'A','name':'<script>literal</script>','model':'MS','networkId':'N'},
                       {'serial':'B','name':'AP','model':'MR','networkId':'N'},{'serial':'C','networkId':'OTHER'}],
            'topology':[{'network_id':'N','network_name':'HQ','status':'complete','data':{
                'nodes':[{'device_serial':'A','root':True},{'device_serial':'B'},{'device_serial':'C'},{'device_serial':'private-client'}],
                'links':[{'device_serials':['A','B'],'link_count':2},{'device_serials':['A','C'],'link_count':1}],
                'omitted_node_count':1,'omitted_link_count':2,'reported_error_count':0}}]}


def test_inventory_join_scope_undirected_counts_and_literal_names():
    s=snapshot();before=copy.deepcopy(s);view=project_topology(s)['networks'][0]
    assert view['node_count']==2 and view['link_count']==1 and view['isolated_node_count']==0
    assert view['root_node_count']==1 and view['nodes'][0]['name']=='<script>literal</script>'
    assert view['links'][0]['endpoint_names']==['<script>literal</script>','AP'] and view['links'][0]['link_count']==2
    assert view['excluded_node_count']==2 and view['excluded_link_pair_count']==1
    assert 'private-client' not in str(view) and s==before


@pytest.mark.parametrize('row',[{'device_serials':['A','A'],'link_count':1},{'device_serials':['A','B'],'link_count':True},
    {'device_serials':['A','B'],'link_count':0},{'device_serials':[{},'A'],'link_count':1},{}])
def test_invalid_relationships_are_unavailable_not_empty_map(row):
    s=snapshot();s['topology'][0]['data']['links']=[row]
    view=project_topology(s)['networks'][0];assert view['status']=='invalid_evidence' and view['node_count'] is None


def test_duplicate_nodes_or_pairs_refused():
    for field in ['nodes','links']:
        s=snapshot();s['topology'][0]['data'][field].append(s['topology'][0]['data'][field][0])
        assert project_topology(s)['networks'][0]['status']=='invalid_evidence'


def test_missing_network_join_never_exposes_other_inventory():
    s=snapshot();s['topology'][0].pop('network_id');view=project_topology(s)['networks'][0]
    assert view['nodes']==[] and view['links']==[] and view['node_count'] is None and view['status']=='invalid_evidence'


def test_failed_empty_and_unknown_error_counts_remain_distinct():
    s=snapshot();s['topology'][0]['status']='unsupported';view=project_topology(s)['networks'][0]
    assert view['node_count'] is None and view['link_count'] is None
    s['topology'][0]['status']='complete';s['topology'][0]['data']={'nodes':[],'links':[]}
    view=project_topology(s)['networks'][0];assert view['node_count']==0 and view['reported_error_count'] is None


def test_projection_bounded_endpoints_always_have_visible_nodes():
    s={'devices':[{'serial':str(i),'networkId':'N','name':str(i).zfill(3)} for i in range(70)],
       'topology':[{'network_id':'N','status':'complete','data':{'nodes':[{'device_serial':str(i)} for i in range(70)],
           'links':[{'device_serials':[str(i),str(i+1)],'link_count':1} for i in range(69)]}}]*22}
    view=project_topology(s);assert len(view['networks'])==20 and view['additional_networks']==2
    net=view['networks'][0];assert len(net['nodes'])==50 and net['additional_nodes']==20 and net['additional_links']==20
    shown={node['device_serial'] for node in net['nodes']}
    assert all(all(serial in shown for serial in link['device_serials']) for link in net['links'])
    assert len(project_topology(s,complete=True)['networks'][0]['nodes'])==70


def test_appendix_version_preserves_legacy_report_pages():
    s={'domain':'example.test','meraki':snapshot()};s['meraki']['collected_at']='2026-10-08T00:00:00Z'
    old=PdfReader(io.BytesIO(build_meraki_security_pdf(s)))
    s['meraki']['topology_detail_version']=1;new=PdfReader(io.BytesIO(build_meraki_security_pdf(s)))
    assert len(new.pages)==len(old.pages)+1
    assert all(a.get_contents().get_data()==b.get_contents().get_data() for a,b in zip(old.pages,new.pages))
    assert '<script>literal</script>' in new.pages[-1].extract_text() and 'Observed network relationships' in new.pages[-1].extract_text()
