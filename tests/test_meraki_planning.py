from daedalus.meraki_planning import build_unifi_plan


def test_bfs_inventory_quantities_and_surcharge_totals():
    devices = [{'model': model} for model, count in [('MX100', 1), ('MS120-24P', 6), ('MS120-48FP', 1), ('MR44', 16), ('MR76', 3)] for _ in range(count)]
    plan = build_unifi_plan({'devices': devices, 'collected_at': '2026-10-07'})
    standard, capacity = plan['scenarios']
    assert standard['priced_device_count'] == 27
    assert standard['complete_inventory_pricing']
    assert standard['hardware_subtotal_cents'] == 1135600
    assert capacity['hardware_subtotal_cents'] == 1294000
    assert all(r['purchase_url'].startswith('https://store.ui.com/us/en/products/') for r in standard['rows'])
    switch = next(r for r in standard['rows'] if r['meraki_model'] == 'MS120-24P')
    assert switch['quantity'] == 6
    assert switch['availability_observed'] == 'Sold out Oct 6'
    assert plan['price_observed_on'] == '2026-10-08'


def test_unknown_model_is_unpriced_instead_of_family_guess():
    plan = build_unifi_plan({'devices': [{'model': 'MS120-8LP'}, {'model': 'MX1000'}, {'model': 'MR44'}]})
    scenario = plan['scenarios'][0]
    assert not scenario['complete_inventory_pricing']
    assert scenario['priced_device_count'] == 1
    assert len(scenario['unmatched']) == 2


def test_empty_inventory_is_not_complete_pricing():
    assert not build_unifi_plan({})['scenarios'][0]['complete_inventory_pricing']


def test_details_projection_is_bounded_and_does_not_mutate_snapshot():
    from daedalus.meraki_planning import project_unifi_plan
    plan = build_unifi_plan({'devices': [{'model': f'UNKNOWN-{i}'} for i in range(120)]})
    projected = project_unifi_plan(plan)
    assert len(projected['scenarios'][0]['unmatched']) == 100
    assert projected['scenarios'][0]['additional_unmatched_models'] == 20
    assert len(plan['scenarios'][0]['unmatched']) == 120
    assert project_unifi_plan(None) is None


def test_pdf_appends_planning_and_preserves_existing_pages():
    import io
    from pypdf import PdfReader
    from daedalus.reports import build_meraki_security_pdf
    snapshot = {'domain': 'bfs.org', 'meraki': {'organization': {'name': 'BFS'}, 'collected_at': '2026-10-07', 'devices': [{'model': 'MR44'}]}}
    original = PdfReader(io.BytesIO(build_meraki_security_pdf(snapshot)))
    snapshot['unifi_plan'] = build_unifi_plan(snapshot['meraki'])
    enhanced = PdfReader(io.BytesIO(build_meraki_security_pdf(snapshot)))
    assert len(enhanced.pages) > len(original.pages)
    for i, page in enumerate(original.pages):
        assert page.extract_text() == enhanced.pages[i].extract_text()
        assert page.get_contents().get_data() == enhanced.pages[i].get_contents().get_data()
    appended = '\n'.join(p.extract_text() for p in enhanced.pages[len(original.pages):])
    assert 'UniFi comparison and purchase planning' in appended
    assert '$208.00' in appended
    assert '$307.00' in appended
    links = [a.get_object()['/A']['/URI'] for page in enhanced.pages for a in page.get('/Annots', []) if a.get_object().get('/A', {}).get('/S') == '/URI']
    assert 'https://store.ui.com/us/en/products/u7-pro' in links
    assert 'https://store.ui.com/us/en/products/u7-pro-max' in links


def test_saved_refresh_reserves_follow_eight_year_assumption():
    devices = [{'model': model} for model, count in [('MX100', 1), ('MS120-24P', 6), ('MS120-48FP', 1), ('MR44', 16), ('MR76', 3)] for _ in range(count)]
    plan = build_unifi_plan({'devices':devices})
    standard, higher = plan['refresh_plan']['scenarios']
    assert standard['annual_reserve_cents'] == 141950
    assert higher['annual_reserve_cents'] == 161750
    assert standard['replacement_cycle_years'] == 8 and standard['complete_inventory_pricing']
    assert standard['unpriced_device_count'] == 0


def test_empty_partial_zero_and_rounding_are_distinct():
    from daedalus.meraki_planning import build_refresh_plan
    assert build_unifi_plan({})['refresh_plan']['scenarios'][0]['annual_reserve_cents'] is None
    partial=build_unifi_plan({'devices':[{'model':'MR44'},{'model':'unknown'}]})['refresh_plan']['scenarios'][0]
    assert partial['annual_reserve_cents'] == 2600 and partial['unpriced_device_count'] == 1
    assert not partial['complete_inventory_pricing']
    for amount,expected in [(0,0),(3,0),(4,1),(12,2)]:
        assert build_refresh_plan([{'hardware_subtotal_cents':amount,'priced_device_count':1}])['scenarios'][0]['annual_reserve_cents']==expected
    for cycle in [0,31,True,1.5,'8']:
        import pytest
        with pytest.raises(ValueError): build_refresh_plan([],cycle)


def test_new_reserve_appendix_preserves_historical_plan_rendering():
    import copy,io
    from pypdf import PdfReader
    from daedalus.reports import build_meraki_security_pdf
    snapshot={'domain':'example.test','meraki':{'organization':{'name':'Fixture'},'collected_at':'2026-10-08T00:00:00Z'}}
    snapshot['unifi_plan']=build_unifi_plan({'devices':[{'model':'MR44'}]})
    prior=copy.deepcopy(snapshot);prior['unifi_plan'].pop('refresh_plan')
    old=PdfReader(io.BytesIO(build_meraki_security_pdf(prior)))
    new=PdfReader(io.BytesIO(build_meraki_security_pdf(snapshot)))
    assert len(new.pages)==len(old.pages)+1
    assert all(a.get_contents().get_data()==b.get_contents().get_data() for a,b in zip(old.pages,new.pages))
    assert 'Equipment refresh reserve' in new.pages[-1].extract_text()
    assert '$26.00' in new.pages[-1].extract_text()


def test_refresh_projection_bounds_and_drops_private_fields():
    from daedalus.meraki_planning import project_refresh_plan, project_unifi_plan
    plan=build_unifi_plan({'devices':[{'model':'MR44'}]})
    raw=plan['refresh_plan'];raw['private']='secret';raw['scenarios'][0]['private']='secret'
    raw['scenarios'][0]['name']='x'*1000
    raw['scenarios'][1]['annual_reserve_cents']=True
    projected=project_unifi_plan(plan)['refresh_plan']
    assert 'secret' not in str(projected) and len(projected['scenarios'][0]['name'])==240
    assert projected['scenarios'][1]['annual_reserve_cents'] is None
    assert project_refresh_plan({'schema_version':True,'currency':'USD'}) is None
