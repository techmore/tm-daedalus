"""Exact-model planning candidates and US vendor observations for October 8."""
OBSERVED_ON = '2026-10-08'
CATALOG_VERSION = 2
# Base cents, displayed total including surcharge, official product slug, availability.
PRICES = {
 'U7-Pro': (18900,20800,'u7-pro','Add to Cart'),
 'U7-Pro-Max': (27900,30700,'u7-pro-max','Add to Cart'),
 'U7-Outdoor': (19900,21900,'u7-outdoor','Add to Cart'),
 'USW-Pro-Max-24-PoE': (79900,88000,'usw-pro-max-24-poe','Sold out Oct 6'),
 'USW-Pro-Max-48-PoE': (129900,143100,'usw-pro-max-48-poe','Add to Cart'),
 'UDM-Pro-Max': (59900,66000,'udm-pro-max','Add to Cart'),
 'E7': (49900,54900,'e7','Add to Cart'),
 'E7-Campus': (79900,88000,'e7-campus-us','Add to Cart'),
 'ECS-24-PoE': (249900,275300,'ecs-24-poe','Add to Cart'),
 'ECS-48-PoE': (349900,385500,'ecs-48-poe','Add to Cart'),
 'EFG': (199900,220200,'efg','Sold out Oct 7'),
 'USL-Entry': (3900,3900,'usl-entry','Add to Cart'),
 'USL-Gateway': (12900,14200,'usl-gateway','Add to Cart'),
 'UNVR': (29900,32900,'unvr','Add to Cart'),
}
RF = 'Validate RF survey, client compatibility, per-band spatial streams, mounting, VLAN/802.1X policy and PoE. This is a planning alternative, not established equivalence.'
OUTDOOR = 'Validate outdoor RF survey, directional antenna pattern versus existing antennas, weather rating, mounting, surge protection and PoE. External antenna reuse is not assumed.'
SWITCH = 'Validate used ports, uplink speeds/optics, VLANs, routing, access policies, spanning tree and PoE per-port/total budget. StackWise, Cisco routing and licensing features are not assumed equivalent.'
CAMPUS = SWITCH + ' Verify rack depth, AC voltage, redundant versus shared power budget and campus aggregation design; optics and additional aggregation are excluded.'
# Exact models only. Conservative campus tiers retain port counts and offer PoE+++.
# Two candidate choices support scenario iteration; administrator design approval is separate.
CANDIDATES = {
 'MX100': ('UDM-Pro-Max','UDM-Pro-Max','Validate WAN, VPN, security policy, throughput and high availability requirements.'),
 'MX95': ('EFG','EFG','Validate WAN/VPN/security policy, controller and client scale, throughput and high availability. A second EFG is required for gateway HA and is not included in this one-device budget. Protect sensors need a separate Protect console.'),
 'MS120-24P': ('USW-Pro-Max-24-PoE','USW-Pro-Max-24-PoE','Validate used ports, PoE load, uplinks, VLANs and spanning tree configuration.'),
 'MS120-48FP': ('USW-Pro-Max-48-PoE','USW-Pro-Max-48-PoE','Validate full PoE load, uplinks and redundancy; retain 48 access ports.'),
 'MS130-24P': ('USW-Pro-Max-24-PoE','USW-Pro-Max-24-PoE',SWITCH),
 'MS130-48P': ('USW-Pro-Max-48-PoE','USW-Pro-Max-48-PoE',SWITCH),
 'MS210-24P': ('USW-Pro-Max-24-PoE','USW-Pro-Max-24-PoE',SWITCH),
 'MS225-48FP': ('USW-Pro-Max-48-PoE','USW-Pro-Max-48-PoE',SWITCH),
 'C9200L-48P-4X': ('ECS-48-PoE','ECS-48-PoE',CAMPUS),
 'C9300-24U': ('ECS-24-PoE','ECS-24-PoE',CAMPUS),
 'C9300-48UXM': ('ECS-48-PoE','ECS-48-PoE',CAMPUS),
 'MR24': ('U7-Pro','U7-Pro-Max',RF),
 'MR34': ('U7-Pro','U7-Pro-Max',RF),
 'MR42': ('U7-Pro','U7-Pro-Max',RF),
 'MR42E': ('U7-Pro-Max','E7',RF+' Candidates use integrated antennas; external antenna pattern and cabling require redesign.'),
 'MR44': ('U7-Pro','U7-Pro-Max','Validate RF coverage, capacity, mounting and PoE; spatial stream counts differ.'),
 'MR46': ('U7-Pro-Max','E7',RF),
 'MR52': ('U7-Pro-Max','E7',RF),
 'MR53E': ('U7-Pro-Max','E7',RF+' Candidates use integrated antennas; external antenna pattern and cabling require redesign.'),
 'MR56': ('E7','E7',RF+' Validate dense-client performance; radio-chain counts are not preserved by this candidate.'),
 'MR66': ('U7-Outdoor','U7-Outdoor',OUTDOOR),
 'MR74': ('U7-Outdoor','U7-Outdoor',OUTDOOR),
 'MR76': ('U7-Outdoor','U7-Outdoor','Validate outdoor coverage, antenna pattern, weather rating, mounting and surge protection.'),
 'MR86': ('E7-Campus','E7-Campus',OUTDOOR),
 'CW9163E': ('E7-Campus','E7-Campus',OUTDOOR+' Candidate has integrated directional antennas; 6 GHz/AFC and local regulatory requirements need review.'),
 'CW9172I': ('U7-Pro','U7-Pro-Max',RF),
 'CW9176I': ('E7','E7',RF+' Candidate requires 43W PoE++ and a 10 GbE uplink for its rated uplink speed; design the switch/port assignment.'),
 'CW9178I': ('E7','E7',RF+' Validate dense-client requirements and per-band radio-chain differences; this is not a capacity-equivalent replacement.'),
 'MT20': ('USL-Entry','USL-Entry','Door/window monitoring candidate requires SuperLink and UniFi Protect. Validate placement, radio coverage, tamper/events, retention and battery policy; Meraki alert integrations do not transfer automatically.'),
}


def item(sku, quantity, label, review):
 base,total,slug,availability=PRICES[sku]
 return {'meraki_model':label,'quantity':quantity,'candidate_model':sku,'unit_base_cents':base,
         'unit_with_surcharge_cents':total,'subtotal_cents':quantity*total,
         'purchase_url':'https://store.ui.com/us/en/products/'+slug,
         'price_observed_on':OBSERVED_ON,'availability_observed':availability,'review':review}


def sensor_dependencies(devices):
 sensors=[d for d in devices if isinstance(d,dict) and str(d.get('model','')).upper()=='MT20']
 if not sensors:return [],True
 from collections import Counter
 networks=Counter(d['networkId'] for d in sensors if isinstance(d.get('networkId'),str) and d['networkId'])
 complete=all(isinstance(d.get('networkId'),str) and d['networkId'] for d in sensors)
 # One gateway per assigned sensor network is a transparent budget assumption,
 # not a coverage finding. Unknown location never becomes an invented quantity.
 rows=[]
 if networks:
  rows.append(item('USL-Gateway',sum((count+95)//96 for count in networks.values()),'Required sensor gateways',
       'Assume at least one gateway per assigned sensor network, with one per 96 sensors for capacity budgeting. RF placement/coverage may require more; verify Protect site adoption and gateway power.'))
 rows.append(item('UNVR',1,'Required Protect controller',
       'Assume one dedicated Protect console for these sensors; verify console/site design, software version, storage and retention requirements. Storage disks and further consoles are excluded.'))
 return rows,complete
