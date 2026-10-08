import copy, io, json, shutil, subprocess
from pathlib import Path
import pytest
from pypdf import PdfReader
from daedalus.meraki_lifecycle import build_lifecycle, project_lifecycle
from daedalus.meraki_planning import build_unifi_plan, project_unifi_plan
from daedalus.reports import build_meraki_security_pdf


def fixture():
    models = ['MX100', 'MS120-24P', 'MS120-48FP', 'MR44', 'MR76', 'MX1000']
    return {'collected_at': '2026-10-08T13:00:00Z', 'organization': {'name':'Fixture'},
            'networks': [{'id': 'n', 'name':'<script>BFS</script>'}],
            'devices': [{'serial':str(i),'networkId':'n','model':m} for i,m in enumerate(models)]}


def test_exact_vendor_dates_and_unknown_without_prefix_guess():
    result=build_lifecycle(fixture()); rows={r['model']:r for r in result['rows']}
    assert rows['MX100']['end_of_support_date']=='2027-02-01'
    assert rows['MX100']['days_until_support_date']==116
    assert rows['MX100']['support_status']=='within_180_days'
    assert rows['MS120-24P']['sale_date_passed'] is True
    assert rows['MS120-24P']['support_status']=='later'
    assert rows['MR44']['end_of_support_date']=='2031-12-31'
    assert rows['MR44']['sale_date_passed'] is False
    assert rows['MR76']['end_of_support_date'] is None
    assert 'excluded' in rows['MR76']['note']
    assert rows['MX1000']['support_status']=='unknown'
    assert result['summary']=={'date_passed':0,'within_180_days':1,'later':3,'unknown':2}
    assert project_lifecycle(result)['status']=='available'


@pytest.mark.parametrize('collected,status,days',[
    ('2027-02-01','within_180_days',0),('2027-02-02','date_passed',-1),
    ('2026-01-01','later',396),('2026-10-08T23:30:00-04:00','within_180_days',115),
    (None,'unknown',None),('2026-10-08T13:00:00','unknown',None),('bad','unknown',None),
    (True,'unknown',None)])
def test_frozen_utc_date_and_support_day_boundary(collected,status,days):
    s=fixture();s['collected_at']=collected
    r=next(r for r in build_lifecycle(s)['rows'] if r['model']=='MX100')
    assert (r['support_status'],r['days_until_support_date'])==(status,days)


def test_scope_duplicate_and_invalid_inventory():
    s=fixture();s['devices'].append({'serial':'outside','networkId':'other','model':'MX100'})
    s['devices'].append({'serial':'stock','networkId':None,'model':'MX100'})
    assert sum(build_lifecycle(s)['summary'].values())==6
    for modify in [lambda s:s['devices'].append(s['devices'][0]),lambda s:s['networks'].append(s['networks'][0]),lambda s:s['devices'].__setitem__(0,{'serial':True,'networkId':'n','model':'MX100'}),lambda s:s['devices'].__setitem__(0,None)]:
        s=fixture();modify(s);assert build_lifecycle(s)['status']=='invalid_evidence'
    assert build_lifecycle({})['status']=='unavailable'


def test_projection_rejects_tampering_and_private_fields():
    raw=build_lifecycle(fixture())
    for modify in [lambda s:s.update(schema_version=True),lambda s:s.update(private='secret'),lambda s:s['rows'][0].update(source_url='https://evil.invalid'),lambda s:s['rows'][0].update(quantity=True),lambda s:s['rows'][0].update(end_of_support_date='2099-01-01'),lambda s:s['rows'][0].update(private='secret'),lambda s:s.update(summary={}),lambda s:s['rows'].append(s['rows'][0]),lambda s:s.update(as_of='bad')]:
        s=copy.deepcopy(raw);modify(s);r=project_lifecycle(s);assert r['status']=='invalid_evidence';assert 'secret' not in str(r)
    projected=project_lifecycle(raw);projected['rows'][0]['model']='changed';assert raw['rows'][0]['model']!='changed'
    assert project_lifecycle(None) is None


def test_bounded_projection_and_full_rows():
    s=fixture();s['devices']=[{'serial':str(i),'networkId':'n','model':f'UNKNOWN-{i}'} for i in range(101)]
    raw=build_lifecycle(s);r=project_lifecycle(raw)
    assert len(r['rows'])==100 and r['additional_rows']==1
    assert r['summary']['unknown']==101
    assert len(project_lifecycle(raw,complete=True)['rows'])==101
    assert len(raw['rows'])==101


def test_plan_integration_and_old_reports_absent():
    plan=build_unifi_plan(fixture());assert project_unifi_plan(plan)['lifecycle']['summary']['within_180_days']==1
    plan.pop('lifecycle');assert 'lifecycle' not in project_unifi_plan(plan)


def test_pdf_appendix_preserves_all_prior_content_streams():
    s={'domain':'bfs.org','meraki':fixture()};s['unifi_plan']=build_unifi_plan(s['meraki'])
    prior=copy.deepcopy(s);prior['unifi_plan'].pop('lifecycle')
    old=PdfReader(io.BytesIO(build_meraki_security_pdf(prior)));new=PdfReader(io.BytesIO(build_meraki_security_pdf(s)))
    assert len(new.pages)>len(old.pages)
    assert all(a.get_contents().get_data()==b.get_contents().get_data() for a,b in zip(old.pages,new.pages))
    text='\n'.join(p.extract_text() for p in new.pages[len(old.pages):])
    assert 'Hardware support milestones' in text and '2027-02-01' in text and '116 days' in text
    assert '<script>BFS</script>' in text
    links=[a.get_object().get('/A',{}).get('/URI') for p in new.pages for a in p.get('/Annots',[])]
    assert 'https://www.cisco.com/c/en/us/products/collateral/wireless/catalyst-9100ax-access-points/meraki-wi-fi-6-indoor-access-points-eol.html' in links


@pytest.mark.skipif(not shutil.which('node'),reason='Node required')
def test_ui_literal_text_keyboard_and_unknown_dates():
    source=(Path(__file__).parents[1]/'src/daedalus/static/js/dashboard.js').read_text()
    helper=source[source.index('  function renderMerakiLifecycle('):source.index('  function renderMerakiPaths(')]
    script='''const assert=require('node:assert/strict');class Node{constructor(tag){this.tag=tag;this.children=[];this.textContent='';this.attrs={}}append(...n){this.children.push(...n)}setAttribute(k,v){this.attrs[k]=v}}
const document={createElement:t=>new Node(t)};function all(n){return[n,...n.children.flatMap(all)]}
'''+helper+'''
const evidence=JSON.parse(require('node:fs').readFileSync(0,'utf8'));const box=new Node('div');renderMerakiLifecycle(box,evidence,false);let nodes=all(box);
for (let t of ['<script>BFS</script>','116 days','Unknown','1 devices with support dates within 180 days','2027-02-01']) assert.ok(nodes.some(n=>n.textContent.includes(t)),t);
assert.ok(nodes.some(n=>n.tag==='caption'));assert.ok(nodes.some(n=>n.tabIndex===0&&n.attrs.role==='region'));assert.ok(nodes.some(n=>n.tag==='a'&&n.rel==='noopener noreferrer'));assert.ok(!nodes.some(n=>n.tag==='script'));
const overview=new Node('div');renderMerakiLifecycle(overview,evidence,true);assert.ok(!all(overview).some(n=>n.tag==='table'));
const absent=new Node('div');renderMerakiLifecycle(absent,null,false);assert.equal(absent.children.length,0);
'''
    result=subprocess.run(['node','-e',script],input=json.dumps(project_lifecycle(build_lifecycle(fixture()))),text=True,capture_output=True)
    assert result.returncode==0,result.stderr
    assert 'innerHTML' not in helper
    assert source.count('renderMerakiLifecycle(container, details.unifi_plan.lifecycle, true)')==3
