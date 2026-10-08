import copy,io,json,subprocess,shutil
from pathlib import Path
import pytest
from pypdf import PdfReader
from daedalus.meraki_planning import build_unifi_plan,project_unifi_plan
from daedalus.meraki_catalog import CANDIDATES,PRICES,sensor_dependencies
from daedalus.reports import build_meraki_security_pdf

MODELS={'C9200L-48P-4X':3,'C9300-24U':2,'C9300-48UXM':8,'CW9163E':10,'CW9172I':1,'CW9176I':57,'CW9178I':2,'MR24':12,'MR34':14,'MR42':57,'MR42E':1,'MR44':35,'MR46':22,'MR52':6,'MR53E':2,'MR56':2,'MR66':3,'MR74':1,'MR86':6,'MS130-24P':1,'MS130-48P':10,'MS210-24P':1,'MS225-48FP':2,'MT20':5,'MX95':1}
def fixture():
 models=[m for m,n in MODELS.items() for _ in range(n)]
 return {'collected_at':'2026-10-08T12:00:00Z','organization':{'name':'Campus fixture'},'networks':[{'id':'n','name':'Campus'}], 'devices':[{'serial':str(i),'networkId':'n','model':m} for i,m in enumerate(models)]}


def test_all_penn_models_exactly_priced_with_required_hardware():
 p=build_unifi_plan(fixture());assert p['catalog_version']==2 and p['price_observed_on']=='2026-10-08'
 for scenario,total in zip(p['scenarios'],[15242500,17170800],strict=True):
  assert scenario['complete_inventory_pricing'] and scenario['priced_device_count']==264
  assert len(scenario['rows'])==25 and not scenario['unmatched']
  assert {r['meraki_model']:r['quantity'] for r in scenario['rows']}==MODELS
  assert scenario['required_hardware_subtotal_cents']==47100
  assert scenario['hardware_subtotal_cents']==total
  assert total==sum(r['subtotal_cents'] for r in scenario['rows']+scenario['additional_items'])
  assert [(r['candidate_model'],r['quantity']) for r in scenario['additional_items']]==[('USL-Gateway',1),('UNVR',1)]
  assert all(r['price_observed_on']=='2026-10-08' and r['purchase_url'].startswith('https://store.ui.com/us/en/products/') for r in scenario['rows']+scenario['additional_items'])
  assert next(r for r in scenario['rows'] if r['meraki_model']=='MX95')['candidate_model']=='EFG'
  assert 'Sold out' in next(r for r in scenario['rows'] if r['meraki_model']=='MX95')['availability_observed']
  assert next(r for r in scenario['rows'] if r['meraki_model']=='C9300-48UXM')['candidate_model']=='ECS-48-PoE'
  assert next(r for r in scenario['rows'] if r['meraki_model']=='CW9163E')['candidate_model']=='E7-Campus'
  assert 'External antenna reuse is not assumed' in next(r for r in scenario['rows'] if r['meraki_model']=='MR86')['review']
 assert project_unifi_plan(p)['scenarios'][0]['additional_items']==p['scenarios'][0]['additional_items']


def test_no_prefix_guess_and_unknown_sensor_location_is_partial():
 s=fixture();s['devices']=[{'model':'C9300-48UXM-OTHER'},{'model':'MR420'},{'model':'MT20'}]
 p=build_unifi_plan(s)['scenarios'][0]
 assert not p['complete_inventory_pricing'] and not p['required_hardware_quantity_complete']
 assert len(p['unmatched'])==2 and p['priced_device_count']==1
 assert [r['candidate_model'] for r in p['additional_items']]==['UNVR']


def test_gateway_budget_respects_networks_and_96_sensor_limit():
 devices=[{'model':'MT20','networkId':'a'} for _ in range(97)]+[{'model':'MT20','networkId':'b'}]
 rows,complete=sensor_dependencies(devices);assert complete
 assert rows[0]['quantity']==3
 devices.append({'model':'MT20'});assert sensor_dependencies(devices)[1] is False
 assert sensor_dependencies([{'model':'MR44'}])==([],True)


def test_every_candidate_resolves_to_verified_catalog():
 assert all(a in PRICES and b in PRICES and review for a,b,review in CANDIDATES.values())
 assert all(type(base) is int and type(total) is int and total>=base>=0 for base,total,slug,state in PRICES.values())


def test_pdf_required_items_present_and_prior_body_preserved():
 s={'domain':'fixture.example','meraki':fixture()};original=PdfReader(io.BytesIO(build_meraki_security_pdf(s)))
 s['unifi_plan']=build_unifi_plan(s['meraki']);enhanced=PdfReader(io.BytesIO(build_meraki_security_pdf(s)))
 assert all(a.get_contents().get_data()==b.get_contents().get_data() for a,b in zip(original.pages,enhanced.pages))
 text='\n'.join(p.extract_text() for p in enhanced.pages)
 assert '$152,425.00' in text and '$171,708.00' in text
 assert 'Required sensor gateways' in text and 'Required Protect controller' in text and 'UNVR' in text
 links=[a.get_object().get('/A',{}).get('/URI') for p in enhanced.pages for a in p.get('/Annots',[])]
 for slug in ('usl-gateway','unvr','efg','ecs-48-poe','e7-campus-us'):
  assert 'https://store.ui.com/us/en/products/'+slug in links


def test_legacy_plan_without_dependencies_remains_projectable():
 p=build_unifi_plan({'devices':[{'model':'MR44'}]});p['scenarios'][0].pop('additional_items');p['scenarios'][1].pop('additional_items')
 assert len(project_unifi_plan(p)['scenarios'])==2


def test_lifecycle_groups_keep_source_link_with_model():
 s={'domain':'fixture.example','meraki':fixture()};s['unifi_plan']=build_unifi_plan(s['meraki'])
 pdf=PdfReader(io.BytesIO(build_meraki_security_pdf(s)))
 start=next(i for i,p in enumerate(pdf.pages) if 'Hardware support milestones' in p.extract_text())
 for p in pdf.pages[start:]:
  text=p.extract_text()
  assert text.count('assigned devices')==text.count('Official vendor')


def test_ui_renders_required_items_alongside_candidates():
 source=(Path(__file__).parents[1]/'src/daedalus/static/js/dashboard.js').read_text()
 renderer=source[source.index('  function renderMerakiDashboardDetails('):source.index('  function fetchMerakiDashboardDetails(')]
 assert '(scenario.rows || []).concat(scenario.additional_items || []).forEach' in renderer

@pytest.mark.skipif(not shutil.which('node'),reason='Node required')
def test_actual_details_renderer_includes_required_hardware_links():
 source=(Path(__file__).parents[1]/'src/daedalus/static/js/dashboard.js').read_text()
 renderer=source[source.index('  function renderMerakiDashboardDetails('):source.index('  function fetchMerakiDashboardDetails(')]
 script='''const assert=require('node:assert/strict');class Node{constructor(tag){this.tag=tag;this.children=[];this.textContent=''}append(...n){this.children.push(...n)}replaceChildren(...n){this.children=n}setAttribute(k,v){this[k]=v}}
 const document={createElement:t=>new Node(t)};const dateLabel=x=>x;function all(n){return[n,...n.children.flatMap(all)]}
 function addMerakiDetailList(){} function renderMerakiRefreshPlan(){} function renderMerakiSwitchPorts(){} function renderMerakiPowerUsage(){} function renderMerakiWanuplinks(){} function renderMerakiWanUsage(){} function renderMerakiChannelUtilization(){} function renderMerakiWirelessConnections(){} function renderMerakiLifecycle(){} function renderMerakiActionPlan(){} function renderMerakiCis8(){} function renderMerakiNeighbors(){} function renderMerakiTopology(){} function renderMerakiClientDistributions(){}
 '''+renderer+'''
 const plan=JSON.parse(require('node:fs').readFileSync(0,'utf8'));const box=new Node('div');renderMerakiDashboardDetails(box,{unifi_plan:plan});const nodes=all(box);
 for(const t of ['Required sensor gateways','Required Protect controller','$152,425.00','$171,708.00','Sold out Oct 7'])assert.ok(nodes.some(n=>n.textContent.includes(t)),t);
 const links=nodes.filter(n=>n.tag==='a');assert.equal(links.length,54);assert.ok(links.some(n=>n.href==='https://store.ui.com/us/en/products/usl-gateway'));assert.ok(links.some(n=>n.href==='https://store.ui.com/us/en/products/unvr'));
 '''
 result=subprocess.run(['node','-e',script],input=json.dumps(project_unifi_plan(build_unifi_plan(fixture()))),capture_output=True,text=True)
 assert result.returncode==0,result.stderr
