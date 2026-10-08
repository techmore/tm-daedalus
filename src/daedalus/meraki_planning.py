"""Dated, inventory-based purchase planning; candidates require design review."""
from collections import Counter
from typing import Any
from .meraki_eox import build_provider_lifecycle, project_provider_lifecycle
from .meraki_lifecycle import build_lifecycle, project_lifecycle

from .meraki_catalog import OBSERVED_ON as PRICE_DATE, PRICES as CATALOG, CANDIDATES, CATALOG_VERSION, item, sensor_dependencies

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
            standard, higher, review = candidate
            rows.append(item(higher if capacity else standard, count, model, review))
        additional, dependency_complete = sensor_dependencies(devices or [])
        assigned_total = sum(r['subtotal_cents'] for r in rows)
        additional_total = sum(r['subtotal_cents'] for r in additional)
        scenarios.append({'name': name, 'rows': rows, 'unmatched': unmatched,
                          'additional_items': additional, 'required_hardware_quantity_complete': bool(dependency_complete),
                          'assigned_hardware_subtotal_cents': assigned_total, 'required_hardware_subtotal_cents': additional_total,
                          'hardware_subtotal_cents': assigned_total + additional_total,
                          'priced_device_count': sum(r['quantity'] for r in rows),
                          'complete_inventory_pricing': bool(counts) and not unmatched and bool(dependency_complete)})
    refresh = build_refresh_plan(scenarios)
    provider = build_provider_lifecycle(snapshot)
    return {**({'provider_lifecycle': provider} if provider is not None else {}), 'lifecycle': build_lifecycle(snapshot), 'refresh_plan': refresh, 'catalog_version': CATALOG_VERSION, 'schema_version': 1, 'currency': 'USD', 'price_observed_on': PRICE_DATE,
            'inventory_collected_at': snapshot.get('collected_at'), 'scenarios': scenarios,
            'assumptions': [
                'Planning candidates require design review; model names do not establish feature equivalence.',
                'Hardware subtotal includes the vendor displayed surcharge. Tax, shipping, optics, cables, mounting, spares, support and implementation are excluded.',
                'Quantities reflect assigned inventory, not discovered clients or unassigned stock. Each candidate replaces one assigned device; additional required hardware is priced separately.',
                'Meraki renewal and replacement quotes are not provided; savings and total cost of ownership are not calculated.',
                'Prices and availability are dated observations; confirm at purchase time.',
                'Assigned inventory includes dormant and alerting devices. Confirm which equipment will be retained or retired before purchasing these quantities.',
                'All inventory priced means model quantities have dated prices, not an approved or complete procurement design. Required gateway/controller quantities are budget assumptions; RF, PoE, routing/stacking, redundancy, storage, accessories and migration still require review.',
            ]}


def project_unifi_plan(plan: Any) -> dict[str, Any] | None:
    """Keep report details bounded; complete rows remain in the evidence download."""
    if not isinstance(plan, dict) or plan.get('schema_version') != 1:
        return None
    result = dict(plan)
    result['scenarios'] = []
    if 'provider_lifecycle' in plan:
        result['provider_lifecycle'] = project_provider_lifecycle(plan['provider_lifecycle'])
    if 'lifecycle' in plan:
        result['lifecycle'] = project_lifecycle(plan['lifecycle'])
    if 'refresh_plan' in plan:
        result['refresh_plan'] = project_refresh_plan(plan['refresh_plan'])
    for scenario in plan.get('scenarios', [])[:2]:
        row = dict(scenario)
        unmatched = row.get('unmatched', [])
        row['unmatched'] = unmatched[:100]
        if len(unmatched) > 100:
            row['additional_unmatched_models'] = len(unmatched) - 100
        row['rows'] = row.get('rows', [])[:100]
        if 'additional_items' in row:
            row['additional_items'] = row.get('additional_items', [])[:100]
        result['scenarios'].append(row)
    return result


def build_refresh_plan(scenarios: list[dict[str, Any]], cycle_years: int = 8) -> dict[str, Any]:
    """Freeze a nominal equipment reserve; the cycle is a budget assumption."""
    if type(cycle_years) is not int or not 1 <= cycle_years <= 30:
        raise ValueError('Replacement cycle must be 1 to 30 whole years')
    rows = []
    for scenario in scenarios[:2]:
        subtotal = scenario.get('hardware_subtotal_cents')
        count = scenario.get('priced_device_count')
        measured = type(subtotal) is int and 0 <= subtotal <= 10**15 and type(count) is int and count > 0
        # Integer half-up rounding avoids float drift and rounds the aggregate,
        # rather than summing independently rounded per-model reserves.
        annual = (2 * subtotal + cycle_years) // (2 * cycle_years) if measured else None
        rows.append({'name': scenario.get('name'), 'replacement_cycle_years': cycle_years,
            'priced_device_count': count if type(count) is int and count >= 0 else None,
            'complete_inventory_pricing': scenario.get('complete_inventory_pricing') is True,
            'equipment_subtotal_cents': subtotal if measured else None,
            'annual_reserve_cents': annual,
            'unpriced_device_count': sum(row.get('quantity', 0) for row in scenario.get('unmatched', []) if type(row.get('quantity')) is int and row['quantity'] >= 0)})
    return {'schema_version': 1, 'currency': 'USD', 'scenarios': rows,
        'scope': 'Nominal annual equipment reserve using saved dated candidate prices divided by an assumed replacement cycle. This is not a forecast, warranty, equipment lifespan, Meraki renewal quote or savings estimate. Excludes inflation, tax, shipping, accessories, support and implementation. Partial pricing covers priced inventory only.'}


def project_refresh_plan(plan: Any) -> dict[str, Any] | None:
    if not isinstance(plan, dict) or type(plan.get('schema_version')) is not int or plan['schema_version'] != 1 or plan.get('currency') != 'USD':
        return None
    rows = plan.get('scenarios') if isinstance(plan.get('scenarios'), list) else []
    shown = []
    for row in rows[:2]:
        if not isinstance(row, dict): continue
        clean = {'name': row['name'][:240] if isinstance(row.get('name'), str) else '',
                 'complete_inventory_pricing': row.get('complete_inventory_pricing') is True}
        for key in ('replacement_cycle_years', 'priced_device_count', 'equipment_subtotal_cents', 'annual_reserve_cents', 'unpriced_device_count'):
            value = row.get(key)
            clean[key] = value if type(value) is int and 0 <= value <= 10**15 else None
        shown.append(clean)
    return {'schema_version': 1, 'currency': 'USD', 'scenarios': shown,
            'scope': plan['scope'][:1000] if isinstance(plan.get('scope'), str) else ''}
