import copy, io, json, subprocess, shutil
from pathlib import Path
import pytest, httpx
from pypdf import PdfReader
from daedalus.meraki_eox import assigned_index, summarize_inventory_eox, build_provider_lifecycle, project_provider_lifecycle, SOURCE
from daedalus.meraki_api import MerakiClient, compare_meraki_snapshots
from daedalus.meraki_planning import build_unifi_plan, project_unifi_plan
from daedalus.reports import build_meraki_security_pdf


def fixture():
    devices=[{'serial':f'D{i}','networkId':'N1','model':model} for i,model in enumerate(['MR42','MR44','MR44','MR76'])]
    source=[{'serial':'D0','networkId':'N1','model':'MR42','eox':{'status':'endOfSupport','endOfSaleAt':'2022-07-14T00:00:00Z','endOfSupportAt':'2026-07-21T00:00:00Z'},'orderNumber':'PRIVATE'},
            {'serial':'D1','networkId':'N1','model':'MR44','eox':{'status':'endOfSale','endOfSaleAt':'2026-12-30T00:00:00Z','endOfSupportAt':'2031-12-30T00:00:00Z'}},
            {'serial':'D2','networkId':'N1','model':'MR44','eox':{'status':'','endOfSaleAt':None,'endOfSupportAt':None}},
            {'serial':'UNASSIGNED','networkId':None,'model':'MR42','mac':'PRIVATE','orderNumber':'PRIVATE','eox':{'status':'endOfSupport'}}]
    data=summarize_inventory_eox(source, assigned_index(devices, {'N1'}))
    return {'organization':{'id':'org1','name':'Fixture'},'collected_at':'2026-10-08T23:30:00-04:00','networks':[{'id':'N1','name':'<script>literal</script>'}],
              'devices':devices,'inventory_eox':{'status':'complete','data':data}}, source


def test_assigned_only_allowlist_status_and_frozen_utc_day():
    snapshot,_=fixture();result=build_provider_lifecycle(snapshot)
    assert result['summary']=={'assigned_devices':4,'reported_devices':3,'missing_devices':1,'provider_end_of_support':1,'provider_near_end_of_support':0,'unknown_status':2,'unknown_support_date':2,'date_conflicts':1,'no_notice_cross_check':2}
    assert result['as_of']=='2026-10-09' and result['rows'][0]['days_until_support_date']==-80
    assert result['rows'][1]['date_conflicts']==['end_of_sale_date','end_of_support_date']
    assert 'PRIVATE' not in str(snapshot) and 'UNASSIGNED' not in str(snapshot)
    assert project_provider_lifecycle(result)['status']=='available'
    assert 'D0' not in str(project_provider_lifecycle(result))


@pytest.mark.parametrize('value',[None,'','bad','2026-07-21','2026-07-21T00:00:00',True,[],{},'2026-99-99T00:00:00Z'])
def test_bad_or_naive_dates_stay_unknown(value):
    snapshot,raw=fixture();raw[0]['eox']['endOfSupportAt']=value
    snapshot['inventory_eox']['data']=summarize_inventory_eox(raw,assigned_index(snapshot['devices'], {'N1'}))
    row=build_provider_lifecycle(snapshot)['rows'][0]
    assert row['provider_status']=='endOfSupport' and row['end_of_support_date'] is None and row['days_until_support_date'] is None


@pytest.mark.parametrize('change',[lambda r:r.append(r[0]),lambda r:r.append(dict(r[0],serial='d0')),lambda r:r[0].update(networkId='OTHER'),lambda r:r[0].update(model='MR42X'),lambda r:r[0].update(serial=True)])
def test_duplicate_invalid_or_cross_network_evidence_rejected(change):
    snapshot,raw=fixture();change(raw)
    with pytest.raises(ValueError):summarize_inventory_eox(raw,assigned_index(snapshot['devices'], {'N1'}))


def test_scope_and_unavailable_are_explicit():
    snapshot,_=fixture();snapshot['devices'] += [{'serial':'stock','networkId':None,'model':'MR42'},{'serial':'outside','networkId':'other','model':'MR42'}]
    assert build_provider_lifecycle(snapshot)['summary']['assigned_devices']==4
    for status in ('unsupported','unavailable'):
        snapshot['inventory_eox']={'status':status,'data':None}
        assert project_provider_lifecycle(build_provider_lifecycle(snapshot))['status']=='unavailable'
    assert build_provider_lifecycle({}) is None
    snapshot['devices'].append(snapshot['devices'][0]);assert build_provider_lifecycle(snapshot)['status']=='invalid_evidence'


@pytest.mark.parametrize('change',[lambda r:r.update(schema_version=True),lambda r:r.update(private='PRIVATE'),lambda r:r.update(source_url='https://evil.invalid'),lambda r:r['rows'][0].update(quantity=True),lambda r:r['rows'][0].update(provider_status='supported'),lambda r:r['rows'][0].update(days_until_support_date=99),lambda r:r['rows'][0].update(published_end_of_support_date='2099-01-01'),lambda r:r['rows'][0].update(private='PRIVATE'),lambda r:r['summary'].update(missing_devices=True),lambda r:r['rows'].append(r['rows'][0])])
def test_projection_rejects_tampered_derived_fields_and_private_extras(change):
    snapshot,_=fixture();saved=build_provider_lifecycle(snapshot);change(saved)
    result=project_provider_lifecycle(saved);assert result['status']=='invalid_evidence' and 'PRIVATE' not in str(result)


def test_projection_limits_full_rows_and_legacy_absence():
    devices=[{'serial':f'D{i}','networkId':'N1','model':f'UNKNOWN{i}'} for i in range(101)]
    snapshot={'collected_at':'2026-10-08','networks':[{'id':'N1','name':'N'}],'devices':devices,'inventory_eox':{'status':'complete','data':summarize_inventory_eox([],assigned_index(devices,{'N1'}))}}
    result=build_provider_lifecycle(snapshot);projected=project_provider_lifecycle(result)
    assert len(projected['rows'])==100 and projected['additional_rows']==1 and projected['summary']['missing_devices']==101
    assert len(project_provider_lifecycle(result,complete=True)['rows'])==101
    assert project_unifi_plan(build_unifi_plan(snapshot))['provider_lifecycle']==projected
    snapshot.pop('inventory_eox');assert 'provider_lifecycle' not in build_unifi_plan(snapshot)


@pytest.mark.parametrize('failure',[None,403,404,'mismatch','duplicate'])
def test_normal_collector_pagination_allowlist_and_failure_coverage(failure):
    snapshot,raw=fixture();seen=[]
    if failure=='mismatch':raw[0]['model']='OTHER'
    if failure=='duplicate':raw.append(raw[0])
    def respond(request):
        assert request.method=='GET';path=request.url.path.removeprefix('/api/v1');seen.append(path)
        if path=='/organizations/org1/inventory/devices':
            if type(failure) is int:return httpx.Response(failure,json={})
            if request.url.params.get('startingAfter'):return httpx.Response(200,json=raw[2:])
            return httpx.Response(200,json=raw[:2],headers={'Link':'<https://api.meraki.com/api/v1/organizations/org1/inventory/devices?startingAfter=D1>; rel="next"'})
        routes={'/organizations':[snapshot['organization']],'/organizations/org1/networks':snapshot['networks'],'/organizations/org1/devices':snapshot['devices'],'/organizations/org1/devices/availabilities':[]}
        return httpx.Response(200,json=routes[path]) if path in routes else httpx.Response(404,json={})
    with MerakiClient('fixture-key',transport=httpx.MockTransport(respond),request_interval=0) as client:result=client.collect_security_report('org1')
    assert result['inventory_eox']['pdf_evidence_summary_version']==1
    if failure is None:
        assert seen.count('/organizations/org1/inventory/devices')==2
        assert result['inventory_eox']['status']=='complete' and result['inventory_eox']['data']==snapshot['inventory_eox']['data']
        assert 'PRIVATE' not in str(result) and 'UNASSIGNED' not in str(result)
        assert build_unifi_plan(result)['provider_lifecycle']['summary']['provider_end_of_support']==1
    else:
        assert result['inventory_eox']['status']==('unsupported' if failure==404 else 'unavailable')
        assert build_provider_lifecycle(result)['status']=='unavailable'


def test_history_provider_dates_without_daily_countdown_noise():
    snapshot,_=fixture();observation={'network_id':'','control':'Inventory lifecycle milestones','status':'complete','data':snapshot['inventory_eox']['data']}
    old={'organization':{'id':'org1'},'collected_at':'2026-10-08','security_controls':[observation]}
    new=copy.deepcopy(old);new['collected_at']='2026-10-09';assert compare_meraki_snapshots(old,new)['changed_control_count']==0
    new['security_controls'][0]['data']['rows'][0]['end_of_support_date']='2026-07-22';assert compare_meraki_snapshots(old,new)['changed_control_count']==1
    legacy=copy.deepcopy(old);legacy['security_controls']=[];comparison=compare_meraki_snapshots(legacy,new)
    assert comparison['changed_control_count']==0 and len(comparison['coverage_changes'])==1


def test_pdf_appends_preserves_previous_pages_and_literal_names():
    snapshot,_=fixture();report={'domain':'fixture.example','meraki':snapshot,'unifi_plan':build_unifi_plan(snapshot)}
    prior=copy.deepcopy(report);prior['unifi_plan'].pop('provider_lifecycle')
    old=PdfReader(io.BytesIO(build_meraki_security_pdf(prior)));new=PdfReader(io.BytesIO(build_meraki_security_pdf(report)))
    assert all(a.get_contents().get_data()==b.get_contents().get_data() for a,b in zip(old.pages,new.pages))
    texts=[p.extract_text() for p in new.pages[len(old.pages):]];text='\n'.join(texts)
    assert '1 devices reported end of support' in text and '2026-07-21' in text and 'API and published dates differ' in text and '<script>literal</script>' in text
    for text in texts:assert len(__import__('re').findall(r'/ \d+ assigned devices',text))==text.count('Provider status:')
    links=[a.get_object().get('/A',{}).get('/URI') for p in new.pages for a in p.get('/Annots',[])]
    assert SOURCE in links


@pytest.mark.skipif(not shutil.which('node'),reason='Node required')
def test_ui_literal_keyboard_unknown_and_overview():
    source=(Path(__file__).parents[1]/'src/daedalus/static/js/dashboard.js').read_text()
    helper=source[source.index('  function renderMerakiProviderLifecycle('):source.index('  function renderMerakiLifecycle(')]
    script='''const assert=require('node:assert/strict');class Node{constructor(tag){this.tag=tag;this.children=[];this.textContent='';this.attrs={}}append(...n){this.children.push(...n)}setAttribute(k,v){this.attrs[k]=v}}
const document={createElement:t=>new Node(t)};function all(n){return[n,...n.children.flatMap(all)]}
'''+helper+'''
const evidence=JSON.parse(require('node:fs').readFileSync(0,'utf8'));const box=new Node('div');renderMerakiProviderLifecycle(box,evidence,false);const nodes=all(box);
for(const t of ['1 devices reported end of support','<script>literal</script>','Unknown','2026-07-21','API and published dates differ','Inventory record missing'])assert.ok(nodes.some(n=>n.textContent.includes(t)),t);
assert.ok(nodes.some(n=>n.tag==='caption'));assert.ok(nodes.some(n=>n.tabIndex===0&&n.attrs.role==='region'));assert.ok(nodes.some(n=>n.tag==='a'&&n.rel==='noopener noreferrer'));assert.ok(!nodes.some(n=>n.tag==='script'));
const overview=new Node('div');renderMerakiProviderLifecycle(overview,evidence,true);assert.ok(!all(overview).some(n=>n.tag==='table'));
'''
    snapshot,_=fixture();r=subprocess.run(['node','-e',script],input=json.dumps(project_provider_lifecycle(build_provider_lifecycle(snapshot))),text=True,capture_output=True)
    assert r.returncode==0,r.stderr
    assert 'innerHTML' not in helper and source.count('renderMerakiProviderLifecycle(container, details.unifi_plan.provider_lifecycle, true)')==3


def test_history_missing_dates_and_rows_only_change_coverage():
    snapshot,_=fixture()
    old={'organization':{'id':'org1'},'security_controls':[{'network_id':'','control':'Inventory lifecycle milestones','status':'complete','data':snapshot['inventory_eox']['data']}]}
    for modify, dimension in [(lambda d:d['rows'][0].update(end_of_support_date=None),'end_of_support_date'),(lambda d:d['rows'][0].update(provider_status='unknown'),'provider_status'),(lambda d:d['rows'].pop(0),'inventory_eox_record')]:
        new=copy.deepcopy(old);modify(new['security_controls'][0]['data'])
        compared=compare_meraki_snapshots(old,new)
        assert compared['changed_control_count']==0
        assert any(r['evidence_dimension']==dimension for r in compared['coverage_changes'])
