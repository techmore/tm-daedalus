#!/usr/bin/env python3
"""Check consistency of a real-platform CI receipt; not a conformance verdict."""
import argparse
import hashlib
import json
from pathlib import Path


def validate_receipt(receipt, profile, profile_bytes):
    def require(condition, message):
        if not condition:
            raise ValueError(message)

    require(isinstance(receipt, dict), 'Receipt must be an object')
    require(type(receipt.get('schema')) is int and receipt['schema'] == 1, 'Unsupported receipt schema')
    require(receipt.get('real_platform_reads') is True, 'Real platform reads were not declared')
    require(receipt.get('production_upload') is False and receipt.get('managed_endpoint_acceptance') is False,
            'Receipt must not claim production or managed endpoint acceptance')
    require(isinstance(receipt.get('os_version'), str) and bool(receipt['os_version'].strip()), 'OS evidence missing')
    require(receipt.get('profile_slug') == profile['slug'] and receipt.get('profile_version') == profile['version'],
            'Profile identity mismatch')
    require(receipt.get('profile_file_sha256') == hashlib.sha256(profile_bytes).hexdigest(), 'Profile checksum mismatch')
    expected = {check['id'] for check in profile['checks']}
    require(len(expected) == len(profile['checks']) == 119, 'Expected published 119-check Level 2 profile')
    observations = receipt.get('checks')
    require(isinstance(observations, list) and len(observations) == len(expected), 'Incomplete check observations')
    totals = dict.fromkeys(('pass', 'fail', 'manual', 'error'), 0)
    seen = set()
    for row in observations:
        require(isinstance(row, dict) and set(row) == {'check_id', 'status'}, 'Unexpected observation fields')
        check_id, status = row['check_id'], row['status']
        require(isinstance(check_id, str) and check_id in expected and check_id not in seen, 'Unknown or duplicate check ID')
        require(isinstance(status, str) and status in totals, 'Unknown status')
        seen.add(check_id)
        totals[status] += 1
    require(seen == expected, 'Missing checks')
    counts = receipt.get('counts')
    require(isinstance(counts, dict) and set(counts) == set(totals), 'Invalid count fields')
    require(all(type(value) is int and value >= 0 for value in counts.values()), 'Counts must be nonnegative integers')
    require(counts == totals, 'Counts differ from observations')
    return {'checks': len(seen), 'counts': totals, 'metadata_consistent': True,
            'conformance_verdict': False, 'production_acceptance': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('receipt', type=Path)
    parser.add_argument('--profile', type=Path, default=Path('src/daedalus/profiles/cis-macos-26-tahoe-level-2.json'))
    args = parser.parse_args()
    profile_bytes = args.profile.read_bytes()
    print(json.dumps(validate_receipt(json.loads(args.receipt.read_text()), json.loads(profile_bytes), profile_bytes)))


if __name__ == '__main__':
    main()
