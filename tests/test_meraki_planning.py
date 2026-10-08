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
    assert plan['price_observed_on'] == '2026-10-07'


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
