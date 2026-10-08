# Meraki audit and UniFi purchase planning

New Meraki report jobs save an inventory-based UniFi plan in `report_snapshot.unifi_plan`. The report details panel shows two scenarios, quantities, USD subtotals, dated vendor availability, design review notes and official product links. The JSON evidence download contains the saved plan. Historical jobs without a saved plan retain their original evidence.

The October 7, 2026 catalog covers the five exact models observed at Buckingham Friends School: MX100, MS120-24P, MS120-48FP, MR44 and MR76. Other models remain explicitly unpriced. These are design candidates, not assertions of feature equivalence. In particular, the MR44 wireless candidate requires capacity review and the gateway requires WAN, VPN, security and redundancy review.

## Price sources

Prices were observed on the official US store on October 7, 2026. Budget arithmetic uses the separately displayed surcharge-inclusive amount:

| Candidate | Base USD | Including surcharge USD | Vendor observation | Source |
| --- | ---: | ---: | --- | --- |
| UDM-Pro-Max | 599 | 660 | Add to Cart | [Product](https://store.ui.com/us/en/products/udm-pro-max) |
| USW-Pro-Max-24-PoE | 799 | 880 | Sold out Oct 6 | [Product](https://store.ui.com/us/en/products/usw-pro-max-24-poe) |
| USW-Pro-Max-48-PoE | 1,299 | 1,431 | Add to Cart | [Product](https://store.ui.com/us/en/category/all-switching/products/usw-pro-max-48-poe) |
| U7-Pro | 189 | 208 | Add to Cart | [Product](https://store.ui.com/us/en/products/u7-pro) |
| U7-Pro-Max | 279 | 307 | Add to Cart | [Product](https://store.ui.com/us/en/category/all-wifi/products/u7-pro-max) |
| U7-Outdoor | 199 | 219 | Add to Cart | [Product](https://store.ui.com/us/en/products/u7-outdoor) |

Tax, shipping, optics, cables, mounting, spares, support and implementation are excluded. No Meraki quote, renewal quote, savings or total cost of ownership is inferred. Price refreshes require vendor evidence and are frozen into new report jobs; they do not rewrite old reports.

## Live BFS evidence

A read-only collection using the existing legacy credential completed October 7: two networks, 27 assigned devices, all online, 48 configuration controls collected, none unavailable. Inventory: MX100 ×1, MS120-24P ×6, MS120-48FP ×1, MR44 ×16, MR76 ×3. The standard scenario subtotal is $11,356; higher capacity indoor wireless is $12,940. Private raw audit and plan receipts are retained under ignored `validation/` files.

## Production BFS validation — October 7, 2026

The SER8 Incus instance now runs source `7c26179`, release archive SHA-256 `cdad5b0a21b8e45186d188c1998af740df775b44b5dc067116b094a97e2040a2`. The BFS workspace has its encrypted legacy credential scoped to Cisco organization 296035 (Buckingham Friends School). Reports **40 and 41** completed on production with 27 devices, 48 controls collected, zero unavailable controls and three review observations. Report 41 compares with report 40: zero control, coverage or inventory changes. No Meraki change notice was emitted for this unchanged repeat. Both request and completion timestamps are retained in the workspace audit log.

Both reports save the two purchase scenarios and downloadable PDFs. Their scenarios match; the inventory collection timestamp correctly differs between runs. The report details plan matches its full saved JSON evidence. The dashboard serves the current purchase-planning code. A BFS access key cannot select CSP (403), and the existing CSP key cannot read BFS report details, evidence or PDF (404). The temporary BFS validation key was revoked; subsequent authentication returned 401. Existing memberships were preserved.

The Meraki PDF appends purchase planning after existing report sections. A locally generated real BFS artifact retains identical content streams for all 94 existing pages and adds two visually reviewed pages with 10 clickable vendor links. The production artifacts downloaded successfully; this is not a visual review of every production page. Scanner PDF templates were unchanged by this deployment. Full local validation: 774 tests passed, one skipped, 260 subtests. Broader model mappings, procurement design review and quoted Meraki renewal comparisons remain open.

## Inventory identity integrity

New collections require every network ID and device serial to be a unique, bounded opaque identifier. Missing, malformed or duplicate identities fail collection before a completed snapshot or purchase plan is saved. Rows are not silently omitted and duplicate devices cannot inflate replacement quantities. Failed attempts use the existing saved failure/audit/notice workflow; historical completed reports remain unchanged. A fresh read-only BFS collection passed these checks with two networks and 27 unique device serials.

## Switch PoE evidence — October 8, 2026

Review of the original Meraki-2026_planning source found switch port energy and average-power reporting that the portal discarded. New collections retain an allowlisted, per-switch aggregate from the existing switch-port-status request with an explicit prior-24-hour timespan. The [official Cisco endpoint](https://developer.cisco.com/meraki/api-v1/get-device-switch-ports-statuses/) documents the timespan and powerUsageInWh fields. No additional API endpoint or client/neighbor identities are collected.

Each switch records collection status, measured/unmeasured port counts, reported PoE allocations, measured Wh and average W over the requested 24 hours. Missing/invalid values remain unavailable; partial readings are labeled partial. Malformed/duplicate port identities invalidate energy coverage. Average usage does not prove peak demand, switch power budget or candidate capacity. These dated observations are retained separately from configuration controls and do not produce configuration-change alerts. Historical reports retain their original evidence.

The report details endpoint bounds the list to 100 switches and points to complete saved JSON; the dashboard displays coverage and measurements. A new PDF appendix follows existing sections. A real saved BFS fixture with synthetic power rows retained identical content streams for its previous 96 pages and added one visually reviewed appendix page. Focused Meraki/dashboard/report validation passed 110 tests and 24 subtests. This is source/fixture validation; live production PoE collection is pending at this checkpoint. The full suite passed 826 tests, one skipped and 293 subtests. Full legacy report coverage and procurement design review remain open.
