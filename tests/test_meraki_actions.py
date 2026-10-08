import copy
import io
from pypdf import PdfReader
from daedalus.meraki_actions import build_action_plan, project_action_plan
from daedalus.reports import build_meraki_security_pdf


def test_missing_evidence_stays_gap_and_planning_not_health_certificate():
    plan=build_action_plan({'findings':None,'security_controls':None,'switch_ports':None}, {})
    assert [r['id'] for r in plan['rows']]==['coverage','refresh','segmentation']
    assert plan['summary']=={'review':0,'planning':2,'evidence_gap':1}
    assert 'not assigned deadlines' in plan['scope']
    assert all(r['verification'] and r['suggested_owner'] for r in plan['rows'])


def test_saved_findings_ports_and_all_rf_profiles_generate_conditional_guidance():
    snapshot={'collected_at':'2026-10-08T00:00:00Z','findings':[{'status':'Review','title':'Open guest SSID'}],
        'switch_ports':[{'status':'complete','data':{'review_port_count':2}}],
        'security_controls':[{'control':'Wireless RF profiles','status':'complete','network_name':'HQ','data':[
            {'id':'first','fiveGhzSettings':{'minBitrate':24}},
            {'name':'Second','apBandSettings':{'bandSteeringEnabled':False},'twoFourGhzSettings':{'minBitrate':11},'fiveGhzSettings':{'minBitrate':12,'channelWidth':'20'}}]},
            {'control':'Malware protection','status':'unavailable','data':None},
            {'control':'Switch port configuration','status':'complete','data':[]}],
        'channel_utilization':{'status':'complete','data':{'review_band_count':2}},'switch_power':[{'status':'complete','data':{'measured_average_watts':100}}]}
    before=copy.deepcopy(snapshot);plan=build_action_plan(snapshot,{'scenarios':[{},{}]});rows={r['id']:r for r in plan['rows']}
    assert snapshot==before and len(rows)==9
    assert rows['ports']['status']=='review' and '2 ports' in rows['ports']['observation']
    assert rows['coverage']['status']=='evidence_gap'
    assert 'Second' in rows['rf']['observation'] and 'first' not in rows['rf']['observation']
    assert '20 MHz channel may be intentional' in rows['rf']['action']
    assert rows['power']['status']=='planning' and 'peak' in rows['power']['action']
    assert 'support/EOL' in rows['refresh']['action']
    assert project_action_plan(plan)==plan


def test_failed_or_invalid_telemetry_does_not_create_review_condition():
    for data in (None,[],{'review_band_count':True},{'review_band_count':-1}):
        p=build_action_plan({'channel_utilization':{'status':'complete','data':data},
            'switch_ports':[{'status':'unavailable','data':{'review_port_count':10}}],
            'security_controls':[{'control':'Wireless RF profiles','status':'unavailable','data':[{'fiveGhzSettings':{'minBitrate':1}}]}]}, {})
        assert not {'rf','channels','ports'} & {r['id'] for r in p['rows']}


def test_projection_uses_catalog_and_recomputes_status_counts():
    p=build_action_plan({},{});p['summary']={'pass':100};p['scope']='spoof';p['private']='secret'
    p['rows'][0].update(title='spoof',action='spoof',phase=3,status='pass',observation='x'*4000,private='secret')
    p['rows'] += [{'id':[]},{'id':'unknown'},p['rows'][0]]
    clean=project_action_plan(p)
    assert len(clean['rows'])==3 and clean['rows'][0]['phase']==0
    assert clean['summary']['evidence_gap']==1 and 'spoof' not in str(clean) and 'secret' not in str(clean)
    assert len(clean['rows'][0]['observation'])==3000
    assert project_action_plan({'schema_version':True}) is None


def test_pdf_preserves_prior_pages_and_includes_validation_timeline():
    s={'domain':'example.test','meraki':{'organization':{'name':'Fixture'},'collected_at':'2026-10-08T00:00:00Z'}}
    old=PdfReader(io.BytesIO(build_meraki_security_pdf(s)))
    s['meraki_action_plan']=build_action_plan({}, {})
    new=PdfReader(io.BytesIO(build_meraki_security_pdf(s)))
    assert len(new.pages)>len(old.pages)
    assert all(a.get_contents().get_data()==b.get_contents().get_data() for a,b in zip(old.pages,new.pages))
    text=' '.join(p.extract_text() for p in new.pages[len(old.pages):])
    assert 'Recommendations & implementation plan' in text and 'Validation:' in text and 'Suggested owner:' in text
    assert '6–12 weeks' in text and '3–6 months' in text
