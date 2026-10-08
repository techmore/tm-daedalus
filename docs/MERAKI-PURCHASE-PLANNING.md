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

This collection has not been attached to the live BFS workspace. The October 6 backup contains no BFS credential or Meraki organization scope; the October 7 LAN SSH connection timed out. Production configuration, portal history, deployment and visual validation remain outstanding. The Meraki PDF now appends purchase planning after existing report sections. A real BFS artifact retains identical content streams for all 94 existing pages and adds two visually reviewed pages with 10 clickable vendor links. Scanner PDF templates are unchanged. Focused planning, Meraki and workspace checks: 19 tests plus four subtests passed.
