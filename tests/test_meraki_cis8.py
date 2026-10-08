import copy,io
from pypdf import PdfReader
from daedalus.meraki_cis8 import build_cis8_assessment,project_cis8_assessment
from daedalus.reports import build_meraki_security_pdf


def test_all_eighteen_controls_missing_evidence_never_pass():
    data=build_cis8_assessment({})
    assert [r['control_id'] for r in data['rows']]==list(range(1,19))
    assert data['summary']=={'partial':0,'review':0,'not_assessed':18}
    assert all(r['status']=='not_assessed' and r['next_action'] for r in data['rows'])
    assert 'No CIS safeguard compliance' in data['scope']


def test_disabled_and_open_wireless_are_review_without_enterprise_compliance():
    snapshot={'devices':[{'firmware':'version','serial':'A'}],'security_controls':[
        {'control':'Intrusion protection','status':'complete','data':{'mode':'disabled'}},
        {'control':'Malware protection','status':'unsupported','data':None},
        {'control':'Wireless SSID security','status':'complete','data':[{'enabled':True,'authMode':'open','name':'private-name'}]},
        {'control':'Content filtering','status':'complete','data':{}}],
        'findings':[{'status':'Review','title':'private-findings'}]}
    before=copy.deepcopy(snapshot);data=build_cis8_assessment(snapshot);rows={r['control_id']:r for r in data['rows']}
    assert rows[4]['status']==rows[6]['status']==rows[9]['status']==rows[13]['status']=='review'
    assert rows[10]['status']=='not_assessed' and rows[7]['status']=='partial'
    assert rows[5]['status']==rows[8]['status']==rows[11]['status']=='not_assessed'
    assert 'private-name' not in str(data) and 'private-findings' not in str(data) and snapshot==before
    assert sum(data['summary'].values())==18


def test_no_anomalies_is_partial_evidence_not_pass():
    data=build_cis8_assessment({'security_controls':[{'control':'Malware protection','status':'complete','data':{'mode':'enabled'}}]})
    rows={r['control_id']:r for r in data['rows']}
    assert rows[4]['status']==rows[9]['status']==rows[10]['status']=='partial'
    assert 'Endpoint malware defenses are not assessed' in rows[10]['observation']
    assert all(r['status']!='pass' for r in data['rows'])


def test_null_failed_unrequested_and_empty_collections_stay_not_assessed():
    for controls in [None,[],[None],[{'control':'Malware protection','status':'complete','data':None}],
                     [{'control':'Malware protection','status':'unavailable','data':{'mode':'disabled'}}]]:
        data=build_cis8_assessment({'security_controls':controls});assert data['summary']['not_assessed']==18


def test_port_review_and_disabled_ssid_scope():
    data=build_cis8_assessment({'security_controls':[{'control':'Switch port configuration','status':'complete','data':[]}],
        'switch_ports':[{'status':'complete','data':{'review_port_count':1}}]})
    assert data['rows'][3]['status']=='review' and '1 ports with review' in data['rows'][3]['observation']
    data=build_cis8_assessment({'security_controls':[{'control':'Wireless SSID security','status':'complete','data':[{'enabled':False,'authMode':'open'}]}]})
    assert data['rows'][5]['status']=='partial'


def test_projection_recomputes_counts_and_bounds_drops_unknowns():
    data=build_cis8_assessment({});data['summary']={'pass':18};data['source_url']='https://evil.invalid';data['private']='secret'
    data['rows'][0]['title']='private';data['rows'][0]['status']='pass';data['rows'][0]['observation']='x'*3000
    data['rows'][0]['evidence_references']=['y'*1000]*100;data['rows'][0]['private']='secret'
    projected=project_cis8_assessment(data)
    assert projected['summary']['not_assessed']==18 and 'pass' not in str(projected['summary'])
    assert 'evil.invalid' not in str(projected) and 'secret' not in str(projected)
    assert len(projected['rows'][0]['observation'])==2000 and len(projected['rows'][0]['evidence_references'])==12
    assert len(projected['rows'][0]['evidence_references'][0])==200
    assert project_cis8_assessment({'schema_version':True,'framework':'CIS Controls v8'}) is None


def test_new_appendix_preserves_historical_pdf_and_links():
    s={'domain':'example.test','meraki':{'organization':{'name':'Fixture'},'collected_at':'2026-10-08T00:00:00Z'}}
    old=PdfReader(io.BytesIO(build_meraki_security_pdf(s)));s['meraki_cis8']=build_cis8_assessment(s['meraki'])
    new=PdfReader(io.BytesIO(build_meraki_security_pdf(s)))
    assert len(new.pages)>len(old.pages)
    assert all(a.get_contents().get_data()==b.get_contents().get_data() for a,b in zip(old.pages,new.pages))
    text=' '.join(page.extract_text() for page in new.pages[len(old.pages):])
    assert 'CIS 18 - Penetration Testing' in text and 'not assessed: 18' in text
