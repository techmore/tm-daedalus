import copy
import io
import pytest
from pypdf import PdfReader
from daedalus.meraki_clients import summarize_wireless_clients, project_wireless_clients
from daedalus.meraki_api import compare_meraki_snapshots
from daedalus.reports import build_meraki_security_pdf


def clients():
    return [{"id": "secret-id-1", "mac": "private-mac", "user": "private-user",
             "recentDeviceConnection": "Wireless", "ssid": "Guest", "os": "iOS", "vlan": "10", "status": "Online"},
            {"id": "secret-id-2", "recentDeviceConnection": "Wireless", "ssid": "Guest", "deviceTypePrediction": "Tablet", "vlan": 20, "status": "Offline"},
            {"id": "secret-id-3", "recentDeviceConnection": "Wireless", "ssid": None, "status": "Other", "os": "", "vlan": True},
            {"id": "secret-id-4", "recentDeviceConnection": "Wired", "ssid": "Do not count"}]


def test_distributions_preserve_missing_labels_and_drop_identities():
    raw=clients(); before=copy.deepcopy(raw); data=summarize_wireless_clients(raw)
    assert raw==before and data['wireless_client_count']==3 and data['excluded_connection_count']==1
    assert data['distributions']['ssid']=={'unknown_count':1,'rows':[{'label':'Guest','count':2}]}
    assert data['distributions']['os']['unknown_count']==1
    assert data['distributions']['vlan']['unknown_count']==1
    assert data['distributions']['status']['unknown_count']==1
    assert 'secret-id' not in str(data) and 'private-' not in str(data) and 'Do not count' not in str(data)
    assert data['rssi_status']=='not_provided'


@pytest.mark.parametrize('raw',[None,{},[None],[{}],[{'id':True}], [{'id':'a'},{'id':'a'}]])
def test_invalid_or_duplicate_identity_is_not_silently_counted(raw):
    with pytest.raises(ValueError): summarize_wireless_clients(raw)


def test_empty_projection_bounds_unknowns_and_private_fields():
    empty=project_wireless_clients(summarize_wireless_clients([]))
    assert empty['wireless_client_count']==0 and all(d['status']=='complete' for d in empty['distributions'].values())
    raw=[{'id':str(i),'recentDeviceConnection':'Wireless','ssid':str(i)} for i in range(15)]
    saved=summarize_wireless_clients(raw);saved['private']='secret';saved['scope']='spoofed'
    projected=project_wireless_clients(saved)
    d=projected['distributions']['ssid'];assert len(d['rows'])==10 and d['additional_group_count']==5 and d['additional_client_count']==5
    assert 'secret' not in str(projected) and 'spoofed' not in str(projected)
    saved['distributions']['ssid']['rows'][0]['count']=True
    assert project_wireless_clients(saved)['distributions']['ssid']['status']=='invalid_evidence'
    assert project_wireless_clients({'schema_version':True}) is None


def test_rolling_distributions_do_not_create_configuration_changes():
    def snapshot(n): return {'organization':{'id':'org'},'security_controls':[{'network_id':'N','control':'Wireless client distributions','status':'complete','data':{'wireless_client_count':n}}]}
    assert compare_meraki_snapshots(snapshot(1),snapshot(2))['changed_control_count']==0


def test_pdf_appendix_keeps_legacy_pages_and_all_groups():
    snapshot={'domain':'example.test','meraki':{'organization':{'name':'Fixture'},'collected_at':'2026-10-08T00:00:00Z'}}
    old=PdfReader(io.BytesIO(build_meraki_security_pdf(snapshot)))
    snapshot['meraki']['wireless_clients']=[{'network_name':'HQ','status':'complete','data':summarize_wireless_clients(clients())}]
    new=PdfReader(io.BytesIO(build_meraki_security_pdf(snapshot)))
    assert all(a.get_contents().get_data()==b.get_contents().get_data() for a,b in zip(old.pages,new.pages))
    text=' '.join(p.extract_text() for p in new.pages[len(old.pages):])
    assert 'Wireless client analysis' in text and 'Tablet' in text and 'Missing/unsupported labels' in text
    assert 'secret-id' not in text and 'private-user' not in text and 'RSSI: not provided' in text
