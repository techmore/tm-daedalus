"""Dated, inventory-based purchase planning; candidates require design review."""
from collections import Counter
from typing import Any

PRICE_DATE = '2026-10-07'
# US vendor storefront observations, including the separately displayed surcharge.
# Each report freezes these values; refresh the catalog only from vendor evidence.
CATALOG = {
    'U7-Pro': (18900, 20800, 'u7-pro', 'Add to Cart'),
    'U7-Pro-Max': (27900, 30700, 'u7-pro-max', 'Add to Cart'),
    'U7-Outdoor': (19900, 21900, 'u7-outdoor', 'Add to Cart'),
    'USW-Pro-Max-24-PoE': (79900, 88000, 'usw-pro-max-24-poe', 'Sold out Oct 6'),
    'USW-Pro-Max-48-PoE': (129900, 143100, 'usw-pro-max-48-poe', 'Add to Cart'),
    'UDM-Pro-Max': (59900, 66000, 'udm-pro-max', 'Add to Cart'),
}
CANDIDATES = {
    'MX100': ('UDM-Pro-Max', 'Validate WAN, VPN, security policy, throughput and high availability requirements.'),
    'MS120-24P': ('USW-Pro-Max-24-PoE', 'Validate used ports, PoE load, uplinks, VLANs and spanning tree configuration.'),
    'MS120-48FP': ('USW-Pro-Max-48-PoE', 'Validate full PoE load, uplinks and redundancy; retain 48 access ports.'),
    'MR44': ('U7-Pro', 'Validate RF coverage, capacity, mounting and PoE; spatial stream counts differ.'),
    'MR76': ('U7-Outdoor', 'Validate outdoor coverage, antenna pattern, weather rating, mounting and surge protection.'),
}

def build_unifi_plan(snapshot: dict[str, Any]) -> dict[str, Any]:
    devices = snapshot.get('devices')
    counts = Counter(str(d.get('model') or 'Unknown').upper() for d in devices or [] if isinstance(d, dict))
    scenarios = []
    for name, capacity in [('Standard wireless candidate', False), ('Higher capacity indoor wireless candidate', True)]:
        rows, unmatched = [], []
        for model, count in sorted(counts.items()):
            candidate = CANDIDATES.get(model)
            if candidate is None:
                unmatched.append({'meraki_model': model, 'quantity': count})
                continue
            sku, review = candidate
            if capacity and model == 'MR44':
                sku = 'U7-Pro-Max'
            base, with_surcharge, slug, availability = CATALOG[sku]
            rows.append({'meraki_model': model, 'quantity': count, 'candidate_model': sku,
                         'unit_base_cents': base, 'unit_with_surcharge_cents': with_surcharge,
                         'subtotal_cents': count * with_surcharge,
                         'purchase_url': 'https://store.ui.com/us/en/products/' + slug,
                         'availability_observed': availability, 'review': review})
        scenarios.append({'name': name, 'rows': rows, 'unmatched': unmatched,
                          'hardware_subtotal_cents': sum(r['subtotal_cents'] for r in rows),
                          'priced_device_count': sum(r['quantity'] for r in rows),
                          'complete_inventory_pricing': bool(counts) and not unmatched})
    return {'schema_version': 1, 'currency': 'USD', 'price_observed_on': PRICE_DATE,
            'inventory_collected_at': snapshot.get('collected_at'), 'scenarios': scenarios,
            'assumptions': [
                'Planning candidates require design review; model names do not establish feature equivalence.',
                'Hardware subtotal includes the vendor displayed surcharge. Tax, shipping, optics, cables, mounting, spares, support and implementation are excluded.',
                'Quantities reflect assigned inventory, not discovered clients or unassigned stock. Each candidate replaces one assigned device.',
                'Meraki renewal and replacement quotes are not provided; savings and total cost of ownership are not calculated.',
                'Prices and availability are dated observations; confirm at purchase time.',
            ]}


def project_unifi_plan(plan: Any) -> dict[str, Any] | None:
    """Keep report details bounded; complete rows remain in the evidence download."""
    if not isinstance(plan, dict) or plan.get('schema_version') != 1:
        return None
    result = dict(plan)
    result['scenarios'] = []
    for scenario in plan.get('scenarios', [])[:2]:
        row = dict(scenario)
        unmatched = row.get('unmatched', [])
        row['unmatched'] = unmatched[:100]
        if len(unmatched) > 100:
            row['additional_unmatched_models'] = len(unmatched) - 100
        row['rows'] = row.get('rows', [])[:100]
        result['scenarios'].append(row)
    return result
