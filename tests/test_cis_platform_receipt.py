import copy
import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location('cis_platform_receipt', Path(__file__).parents[1] / 'scripts/verify_cis_platform_receipt.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
profile_bytes = (Path(__file__).parents[1] / 'src/daedalus/profiles/cis-macos-26-tahoe-level-2.json').read_bytes()
profile = json.loads(profile_bytes)


def receipt():
    return {'schema': 1, 'real_platform_reads': True, 'production_upload': False,
            'managed_endpoint_acceptance': False, 'os_version': 'Version 26.6.2',
            'profile_slug': profile['slug'], 'profile_version': profile['version'],
            'profile_file_sha256': hashlib.sha256(profile_bytes).hexdigest(),
            'checks': [{'check_id': check['id'], 'status': 'manual'} for check in profile['checks']],
            'counts': {'pass': 0, 'fail': 0, 'manual': 119, 'error': 0}}


def test_complete_receipt_is_consistent_without_conformance_claim():
    result = module.validate_receipt(receipt(), profile, profile_bytes)
    assert result['checks'] == 119 and result['metadata_consistent']
    assert not result['conformance_verdict'] and not result['production_acceptance']


@pytest.mark.parametrize('field,value', [('schema', True), ('real_platform_reads', False),
    ('production_upload', True), ('managed_endpoint_acceptance', True), ('os_version', ''),
    ('profile_slug', 'wrong'), ('profile_version', 'wrong'), ('profile_file_sha256', 'wrong')])
def test_invalid_identity_and_scope_rejected(field, value):
    data = receipt(); data[field] = value
    with pytest.raises(ValueError): module.validate_receipt(data, profile, profile_bytes)


@pytest.mark.parametrize('kind', ['duplicate', 'missing', 'unknown_id', 'unknown_status', 'extra_field', 'wrong_counts', 'bool_count'])
def test_inconsistent_observations_rejected(kind):
    data = copy.deepcopy(receipt())
    if kind == 'duplicate': data['checks'][1] = data['checks'][0]
    elif kind == 'missing': data['checks'].pop()
    elif kind == 'unknown_id': data['checks'][0]['check_id'] = 'unknown'
    elif kind == 'unknown_status': data['checks'][0]['status'] = 'unknown'
    elif kind == 'extra_field': data['checks'][0]['details'] = 'not retained'
    elif kind == 'wrong_counts': data['counts']['manual'] = 118
    elif kind == 'bool_count': data['counts']['pass'] = False
    with pytest.raises(ValueError): module.validate_receipt(data, profile, profile_bytes)
