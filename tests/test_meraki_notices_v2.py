import copy, io
import pytest
from pypdf import PdfReader
from daedalus.meraki_lifecycle import build_lifecycle,project_lifecycle,INDEX,INDEX_V2,NOTICES_V1,NOTICES_V2
from daedalus.meraki_eox import build_provider_lifecycle,project_provider_lifecycle,summarize_inventory_eox,assigned_index
from daedalus.meraki_planning import build_unifi_plan
from daedalus.reports import build_meraki_security_pdf
from test_meraki_penn_planning import fixture as campus_fixture

PROVIDER={
 'MR24':('endOfSupport','2014-05-31','2021-05-31'),
 'MR34':('endOfSupport','2016-10-31','2023-10-31'),
 'MR42':('endOfSupport','2022-07-14','2026-07-21'),
 'MR42E':('endOfSupport','2022-04-22','2026-07-31'),
 'MR53E':('endOfSupport','2022-04-22','2026-07-31'),
 'MR52':('endOfSupport','2022-04-07','2026-07-21'),
 'MR66':('endOfSupport','2017-06-09','2024-06-30'),
 'MR74':('endOfSupport','2022-04-22','2026-07-31'),
 'MR56':('endOfSale','2025-08-07','2030-08-08'),
 'MS210-24P':('endOfSale','2026-04-30',None),
 'MS225-48FP':('endOfSale','2026-04-30',None),
}

def fixture():
 snapshot=campus_fixture();raw=[]
 for d in snapshot['devices']:
  status,sale,support=PROVIDER.get(d['model'],('',None,None))
  raw.append({**d,'eox':{'status':status,'endOfSaleAt':sale+'T00:00:00Z' if sale else None,'endOfSupportAt':support+'T00:00:00Z' if support else None}})
 snapshot['inventory_eox']={'status':'complete','data':summarize_inventory_eox(raw,assigned_index(snapshot['devices'],{'n'}))}
 return snapshot


def test_exact_index_dates_and_expanded_assigned_counts():
 snapshot=fixture();published=build_lifecycle(snapshot,schema_version=2)
 assert published['summary']=={'date_passed':96,'within_180_days':0,'later':67,'unknown':101}
 assert project_lifecycle(published)['status']=='available'
 rows={r['model']:r for r in published['rows']}
 expected={'MR24':('2014-05-31','2021-05-31'),'MR34':('2016-10-31','2023-10-31'),
 'MR42':('2022-07-14','2026-07-21'),'MR42E':('2022-04-22','2026-07-21'),
 'MR53E':('2022-04-07','2026-07-21'),'MR52':('2022-04-07','2026-07-21'),
 'MR74':('2021-07-21','2026-07-21'),'MR66':('2017-06-09','2024-06-09'),
 'MR56':('2025-08-07','2030-08-07'),'MR46':('2026-12-31','2031-12-31'),
 'MS210-24P':('2026-04-30','2031-04-30'),'MS225-48FP':('2026-04-30','2031-04-30'),
 'MT20':('2026-11-10','2031-11-30')}
 for model,dates in expected.items():
  assert (rows[model]['end_of_sale_date'],rows[model]['end_of_support_date'])==dates
  assert rows[model]['source_url']==INDEX_V2
 assert rows['MR86']['end_of_support_date'] is None
 assert set(NOTICES_V1)=={'MX100','MS120-24P','MS120-48FP','MR44'}
 assert set(NOTICES_V2)==set(NOTICES_V1)|set(expected)


def test_provider_dates_separate_conflicts_exact_and_missing_dates_not_filled():
 provider=build_provider_lifecycle(fixture())
 assert provider['schema_version']==2
 assert provider['summary']=={'assigned_devices':264,'reported_devices':264,'missing_devices':0,'provider_end_of_support':96,
 'provider_near_end_of_support':0,'unknown_status':163,'unknown_support_date':166,'no_notice_cross_check':101,'date_conflicts':9}
 assert project_provider_lifecycle(provider)['status']=='available'
 rows={r['model']:r for r in provider['rows']}
 assert {m for m,r in rows.items() if r['date_conflicts']}=={'MR42E','MR53E','MR74','MR66','MR56'}
 assert rows['MR53E']['date_conflicts']==['end_of_sale_date','end_of_support_date']
 assert rows['MR56']['end_of_support_date']=='2030-08-08' and rows['MR56']['published_end_of_support_date']=='2030-08-07'
 assert rows['MS210-24P']['end_of_support_date'] is None and rows['MS210-24P']['published_end_of_support_date']=='2031-04-30'
 assert rows['MR44']['provider_status']=='unknown' and rows['MR44']['published_end_of_support_date']=='2031-12-31'
 assert rows['MR86']['published_end_of_support_date'] is None
 assert all(r['published_source_url'] in {INDEX_V2,NOTICES_V1['MR44'][3]} for r in provider['rows'])
 assert build_unifi_plan(fixture())['lifecycle']['schema_version']==2


def test_old_versions_reconstructed_with_their_own_catalog_and_scope():
 snapshot=fixture();old_notice=build_lifecycle(snapshot);old_provider=build_provider_lifecycle(snapshot,schema_version=1)
 assert old_notice['schema_version']==1 and old_notice['summary']['unknown']==229 and old_notice['summary']['date_passed']==0
 assert old_provider['schema_version']==1 and old_provider['summary']['no_notice_cross_check']==229 and old_provider['summary']['date_conflicts']==0
 assert project_lifecycle(old_notice,complete=True)==old_notice|{'additional_rows':0}
 assert project_provider_lifecycle(old_provider,complete=True)==old_provider|{'additional_rows':0}
 assert all('published_source_url' not in row for row in old_provider['rows'])
 assert any(row['source_url']==INDEX for row in old_notice['rows'])
 before=copy.deepcopy((old_notice,old_provider));build_lifecycle(snapshot,schema_version=2);build_provider_lifecycle(snapshot)
 assert (old_notice,old_provider)==before


@pytest.mark.parametrize('version',[True,3,None,'2'])
def test_unknown_and_bool_versions_rejected(version):
 snapshot=fixture()
 for builder in (build_lifecycle,build_provider_lifecycle):
  with pytest.raises(ValueError):builder(snapshot,schema_version=version)
 for builder,projector in [(build_lifecycle,project_lifecycle),(build_provider_lifecycle,project_provider_lifecycle)]:
  saved=builder(snapshot,schema_version=2);saved['schema_version']=version
  assert projector(saved)['status']=='invalid_evidence'


def test_v2_projection_rejects_changed_catalog_dates_and_source_urls():
 snapshot=fixture()
 for builder,projector,field in [(build_lifecycle,project_lifecycle,'source_url'),(build_provider_lifecycle,project_provider_lifecycle,'published_source_url')]:
  saved=builder(snapshot,schema_version=2)
  for value in ['https://evil.invalid',INDEX]:
   modified=copy.deepcopy(saved);modified['rows'][0][field]=value
   assert projector(modified)['status']=='invalid_evidence'
  modified=copy.deepcopy(saved)
  key='published_end_of_support_date' if builder is build_provider_lifecycle else 'end_of_support_date'
  modified['rows'][0][key]='2099-01-01'
  assert projector(modified)['status']=='invalid_evidence'


def test_pdf_v2_links_and_reviews_preserve_prior_main_body():
 snapshot=fixture();report={'domain':'fixture.example','meraki':snapshot,'unifi_plan':build_unifi_plan(snapshot)}
 prior=copy.deepcopy(report);prior['unifi_plan']['lifecycle']=build_lifecycle(snapshot);prior['unifi_plan']['provider_lifecycle']=build_provider_lifecycle(snapshot,schema_version=1)
 old=PdfReader(io.BytesIO(build_meraki_security_pdf(prior)));new=PdfReader(io.BytesIO(build_meraki_security_pdf(report)))
 first=next(i for i,p in enumerate(old.pages) if 'Hardware support milestones' in p.extract_text())
 assert all(old.pages[i].get_contents().get_data()==new.pages[i].get_contents().get_data() for i in range(first))
 text=' '.join(' '.join(p.extract_text() for p in new.pages).split())
 assert 'API and published dates differ' in text and 'API support date passed' in text
 assert '9 with differing published dates' in text and '101 without a published notice cross-check' in text
 links=[a.get_object().get('/A',{}).get('/URI') for p in new.pages for a in p.get('/Annots',[])]
 assert INDEX_V2 in links
 assert sum(str(url).startswith('https://store.ui.com/') for url in links)==54


def test_real_v2_dom_sources_counts_and_days_ago():
 import subprocess,json,shutil
 from pathlib import Path
 if not shutil.which('node'):pytest.skip('Node required')
 source=(Path(__file__).parents[1]/'src/daedalus/static/js/dashboard.js').read_text()
 helper=source[source.index('  function renderMerakiProviderLifecycle('):source.index('  function renderMerakiPaths(')]
 script='''const assert=require('node:assert/strict');class Node{constructor(tag){this.tag=tag;this.children=[];this.textContent='';this.attrs={}}append(...n){this.children.push(...n)}setAttribute(k,v){this.attrs[k]=v}}
const document={createElement:t=>new Node(t)};function all(n){return[n,...n.children.flatMap(all)]}
'''+helper+'''
const evidence=JSON.parse(require('node:fs').readFileSync(0,'utf8'));const box=new Node('div');renderMerakiProviderLifecycle(box,evidence.provider,false);renderMerakiLifecycle(box,evidence.published,false);const nodes=all(box);
for(const t of ['96 devices reported end of support','9 with differing published dates','101 without a published notice cross-check','API support date passed 1956 days ago','1956 days ago','2026-07-21','2026-07-31'])assert.ok(nodes.some(n=>n.textContent.includes(t)),t);
assert.ok(nodes.some(n=>n.tag==='a'&&n.textContent==='Published vendor dates'&&n.href.includes('End-of-Life_Notices/')));
assert.ok(nodes.some(n=>n.tag==='a'&&n.textContent==='Official vendor lifecycle index'&&n.href.includes('End-of-Life_Notices/')));
assert.ok(nodes.some(n=>n.tag==='a'&&n.textContent==='Review vendor index'));assert.equal(nodes.filter(n=>n.tabIndex===0&&n.attrs.role==='region').length,2);
'''
 snapshot=fixture();data={'provider':project_provider_lifecycle(build_provider_lifecycle(snapshot)),'published':project_lifecycle(build_lifecycle(snapshot,schema_version=2))}
 result=subprocess.run(['node','-e',script],input=json.dumps(data),text=True,capture_output=True)
 assert result.returncode==0,result.stderr
