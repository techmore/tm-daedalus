import copy
import io
from pypdf import PdfReader
from daedalus.meraki_topology import project_topology
from daedalus.reports import build_meraki_security_pdf
from daedalus.meraki_diagram import diagram_sheets


def snapshot(n=5):
    return {'organization':{'name':'Fixture'},'collected_at':'2026-10-08T00:00:00Z',
        'topology_detail_version':1,'topology_diagram_version':1,
        'devices':[{'serial':str(i),'networkId':'N','name':f'Device {i:03}','model':'MS'} for i in range(n)],
        'topology':[{'network_id':'N','network_name':'HQ','status':'complete','data':{
            'nodes':[{'device_serial':str(i),'root':i==0} for i in range(n)],
            'links':[{'device_serials':[str(i),str(i+1)],'link_count':1} for i in range(n-1)]}}]}


def test_deterministic_coordinates_scope_and_same_network_membership():
    s=snapshot();s['devices'].append({'serial':'private','networkId':'OTHER','name':'Private'})
    before=copy.deepcopy(s);diagram=project_topology(s)['networks'][0]['diagram']
    assert s==before and diagram==project_topology(s)['networks'][0]['diagram']
    assert len(diagram['nodes'])==5 and len(diagram['links'])==4 and 'Private' not in str(diagram)
    assert len({n['number'] for n in diagram['nodes']})==5
    assert all(0<=n['x']<=diagram['width']-n['width'] and 0<=n['y']<=diagram['height']-n['height'] for n in diagram['nodes'])
    assert 'do not establish upstream/downstream' in diagram['scope']


def test_cycles_isolates_and_preview_bounds_do_not_drop_visible_edges():
    s=snapshot(70);s['topology'][0]['data']['links'].append({'device_serials':['0','2'],'link_count':1})
    diagram=project_topology(s,complete=True)['networks'][0]['diagram']
    assert len(diagram['nodes'])==50 and diagram['additional_nodes']==20
    assert diagram['additional_links']==20 and len(diagram['links'])==50
    ids={n['device_serial'] for n in diagram['nodes']}
    assert all(set(l['device_serials'])<=ids for l in diagram['links'])
    s=snapshot();s['topology'][0]['data']['links']=[]
    assert len(project_topology(s)['networks'][0]['diagram']['nodes'])==5


def test_version_absent_bool_failed_and_empty_never_show_invented_nodes():
    s=snapshot();s.pop('topology_diagram_version');assert 'diagram' not in project_topology(s)['networks'][0]
    s['topology_diagram_version']=True;assert 'diagram' not in project_topology(s)['networks'][0]
    s['topology_diagram_version']=1;s['topology'][0]['status']='unavailable'
    assert 'diagram' not in project_topology(s)['networks'][0]
    s=snapshot(0);assert project_topology(s)['networks'][0]['diagram']['status']=='empty'


def test_pdf_diagram_appends_number_key_preserving_earlier_pages():
    s={'domain':'example.test','meraki':snapshot()};s['meraki'].pop('topology_diagram_version')
    old=PdfReader(io.BytesIO(build_meraki_security_pdf(s)));s['meraki']['topology_diagram_version']=1
    new=PdfReader(io.BytesIO(build_meraki_security_pdf(s)))
    assert len(new.pages)>len(old.pages)
    assert all(a.get_contents().get_data()==b.get_contents().get_data() for a,b in zip(old.pages,new.pages))
    text=' '.join(p.extract_text() for p in new.pages[len(old.pages):])
    assert 'Network diagram' in text and 'Device 004' in text and 'API root flag' in text
    assert '#1' in text and '#5' in text


def test_tall_diagrams_keep_readable_sheet_scale_and_cross_sheet_relationships():
    diagram=project_topology(snapshot(50))['networks'][0]['diagram']
    sheets=diagram_sheets(diagram)
    assert len(sheets)>1 and sum(len(s['nodes']) for s in sheets)==50
    assert all(s['height']<=855 and len(s['nodes'])<=8 for s in sheets)
    internal=sum(len(s['links']) for s in sheets)
    crossing=sum(len(s['cross_sheet_links']) for s in sheets)//2
    assert internal+crossing==49
    assert all(1<=r['other_sheet']<=len(sheets) for s in sheets for r in s['cross_sheet_links'])
