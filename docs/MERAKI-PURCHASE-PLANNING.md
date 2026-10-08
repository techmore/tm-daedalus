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

## Production PoE validation — October 8, 2026

SER8 source 219fc0e generated BFS report **42** through the normal authenticated report API. Two networks, 27 devices and 48 controls were collected with zero unavailable controls. All seven switch-status requests completed; each energy observation has partial port coverage; ports without energy values are counted as unmeasured. Partial measured totals are preserved, not represented as whole-switch or peak demand. Dashboard details match saved PoE evidence; purchase subtotals remain $11,356 / $12,940. Report 42 compares with 41 with zero control, coverage or inventory changes, and no change notice. Request/completion audit records are retained. The short-lived operator validation key was revoked and then returned 401.

The downloaded production PDF has 97 pages. Its preceding 96 page content streams match a rendering of the same saved report without the new PoE appendix. The actual production appendix was rendered and visually reviewed: all seven rows fit clearly. This is preservation of current report content and appendix acceptance, not approval of an unidentified historical scanner PDF baseline. Private receipts/artifacts: validation/meraki-poe-20261008/ and /data/codex-bfs-poe-20261008/.

## Wireless connection evidence — October 8, 2026

The original planning script collected per-AP connection outcomes but expected a total counter not supplied by the documented schema. New Daedalus collections use Cisco's [wireless device connection-statistics endpoint](https://developer.cisco.com/meraki/api-v1/get-network-wireless-devices-connection-stats/) with an explicit 86,400-second window. Only assigned AP serials and documented success/association/authentication/DHCP/DNS counts are retained. Missing or invalid counters remain partial, zero remains zero, missing APs are counted and duplicate identities invalidate collection. No combined success rate or security score is inferred.

Dashboard details show bounded per-network totals/coverage; complete per-AP evidence remains in saved JSON. New reports append a wireless observation page; historical snapshots remain unchanged. Rolling outcome changes are excluded from configuration-change notices. A saved real BFS baseline plus synthetic telemetry preserves all 94 existing page content streams and adds one visually reviewed page. Focused checks passed 97 tests/24 subtests; full suite passed 871 tests/308 subtests with one skip, followed by one passing actual JavaScript renderer test. Deployment and fresh live BFS telemetry validation are pending at this checkpoint. Full legacy report parity remains open.

## October 8, 2026 — live BFS wireless outcomes deployed

SER8 Incus runs source 5fe9fe08d224c50552847cee655b85f9469a1221, verified 80-file release SHA-256 1140ce06a26f8ec120fee569498074d38e3564709887f5bb3a6e60f766917d22. Verified off-host backup daedalus-data-20261008T051804Z.tar.gz preceded activation; internal/public health passed. Full local validation passed 871 tests/308 subtests with one skip, followed by a passing actual JavaScript wireless renderer test.

Normal authenticated BFS report 44 completed with two networks, 27 devices, 50 controls and zero unavailable/unsupported requests. All 19 assigned wireless APs supplied complete documented connection counters. The second wireless network has zero assigned APs and no counter observations; missing values remain unavailable. Dashboard totals match saved evidence. Purchase budgets remain $11,356/$12,940; comparison with report 42 retains zero configuration, coverage or inventory changes. The temporary scoped key was revoked and then returned 401. Private production receipts: /data/codex-bfs-wireless-20261008/ and ignored validation/meraki-wireless-20261008/.

The actual 101-page production PDF appendix was rendered and visually reviewed; its preceding 100 page content streams match the same saved snapshot rendered without the appendix. This verifies added observational content and prior-content preservation, not full legacy report parity. Original scanner report assets are unchanged. Scanner source 60897ad backend 37730983379 and installed Linux 37730983365 passed, including repeat comparison. Current wireless source backend 37731676563 and installed Linux 37731676541 are running at this checkpoint. Full project completion remains unproven.

## Channel-utilization evidence — October 8, 2026

The original AP-interference code expected flat utilization fields. Daedalus now uses Cisco's [documented per-device channel-utilization endpoint](https://developer.cisco.com/meraki/api-v1/get-organization-wireless-devices-channel-utilization-by-device/) with protected pagination and an explicit 24-hour window. Only assigned APs, matching network identities, unique supported bands and finite percentages from 0 through 100 are retained. Missing metrics stay partial; zero remains zero. Duplicate identifiers/bands, conflicting networks and invalid arrays leave collection unavailable. A paginated organization request is skipped when there are no assigned APs.

The original review prompts (total at least 50%, non-Wi-Fi at least 20%) are labeled review thresholds, not confirmed interference causes or replacement capacity. Dashboard details show bounded rows, AP/band coverage and a keyboard-scrollable table; full rows remain in saved evidence. Rolling averages do not trigger configuration-change alerts. New reports append a table with repeating headers; historical snapshots remain unchanged. A 57-row fixture adds two visually reviewed pages after 101 unchanged preceding page content streams. Full local validation: 876 passed, one skipped, 313 subtests. Live production collection is pending at this source checkpoint; full original report parity remains open.

## October 8, 2026 — live BFS channel utilization deployed

SER8 Incus activated source 51a671c79d4a8035f452fe37e43d51b9386ce1b5, verified 80-file release SHA-256 e3ad0fc6153998a16619867287cde6df9b2c4157dbf14bf877e29cc2d22c896c. The first attempt terminated before deployment because local Tailscale was stopped; the public portal remained ready. Reopening the existing Tailscale application restored the private route and SSH. The fresh deployment saved verified off-host backup daedalus-data-20261008T052505Z.tar.gz before activation; internal/public readiness passed.

Normal authenticated BFS report 45 completed with 27 devices and 51 collected controls, zero unavailable/unsupported requests. Channel observations cover all 19 assigned APs and 38 bands, with zero missing APs and zero readings meeting the labeled review thresholds. Dashboard rows match saved evidence; purchase budgets remain $11,356/$12,940. Comparison with report 44 retained zero configuration, coverage and inventory changes. The short-lived validation key was revoked and returned 401. Private receipts: /data/codex-bfs-channels-20261008/ and ignored validation/meraki-channels-20261008/.

Both actual production appendix pages were rendered and visually reviewed. The 108-page report retains identical content streams for all 106 preceding pages when compared with the same saved snapshot rendered without the new appendix. This is observational/report acceptance, not a claim of interference cause, replacement capacity or full original Meraki report parity. Full local suite: 876 passed, one skipped, 313 subtests. Backend 37731819528 passed the preceding wireless source at documentation head 1aefb18; superseded backend 37731676563 and installed Linux 37731676541 were cancelled. Current channel-source backend 37732142973 and installed Linux 37732142854 remain unverified at this checkpoint. Full project requirements remain open.

## Purchase planning in the main assessment — October 8, 2026

Normal signed-in BFS browser review confirmed 10 official purchase links and 38 channel rows inside report 45 details, while its two budgets were absent from the main assessment. Source now places the two saved scenario budgets after review findings, with their dated prices, exclusions and full/partial inventory-pricing labels. A keyboard-native button opens and focuses the matching saved report details without changing the topic hash. Literal text, bounded scenario count, unknown prices and matching report identity are tested. Full local suite: 877 passed, one skipped, 313 subtests; final focused renderer/topic checks: 41 passed, two subtests. Source deployment/revalidation is pending at this checkpoint. Screenshot capture still times out; DOM evidence does not establish visual acceptance. Installed Linux channel-source 37732142854 passed all three scenarios.

## October 8, 2026 — visible BFS purchase budgets and browser validation

SER8 Incus activated source 1deb5f4528b5964354ea2577857318ebfe0a4035, verified 80-file release SHA-256 7d471b1217d1a65d991048e7cfb958a535f86dbbc695f1e3791d2e58c0a14397, after verified off-host backup daedalus-data-20261008T053225Z.tar.gz. Internal/public health passed. Full local suite: 877 passed, one skipped, 313 subtests; final renderer/topic suite: 41 passed, two subtests.

The ordinary signed-in BFS browser now shows both dated purchase budgets in the main Meraki assessment after review findings. At 1440px and 390px, keyboard activation opens saved report 45, focuses its summary, retains all 10 official vendor links and 38 channel rows, and leaves the topic hash unchanged. Reload preserves #meraki and both budgets; no page-level horizontal overflow was detected. The first same-URL navigation retained the prior page assets; an explicit reload fetched revision 157 and subsequent checks used that revision. Browser screenshot capture still timed out, so this proves DOM, limited keyboard and refresh behavior, not visual acceptance. Private receipt: validation/meraki-browser-20261008/live-budget-summary.json.

A short-lived BFS browser key used the existing approved administrator membership without changing access grants. It was audited, revoked, and the former browser session then returned 401; the local token file was removed. The review generated no new Meraki scan/report or procurement order. Backend 37732878504 passed current source; installed Linux 37732878407 remains running. Preceding channel backend 37732142973 and installed Linux 37732142854 passed. Full project completion remains unproven.

## October 8, 2026 — WAN interface state source validation

The original Internet section was reviewed against Cisco's current [uplink status endpoint](https://developer.cisco.com/meraki/api-v1/get-organization-appliance-uplink-statuses/). New audits request paginated organization uplinks only when assigned appliance inventory exists. Typed unique device/interface identities must match the assigned network. Saved observations retain documented states, valid device report timestamps, missing appliance counts and bounded dashboard rows. Addresses and DNS values are omitted. Failed/unsupported reads retain explicit collection status; malformed identities cannot become successful evidence.

Dashboard and PDF distinguish reported interface state from circuit capacity, throughput or outage determination. Ready/disconnected secondary links do not establish an outage. Rolling states are excluded from configuration comparisons. A frozen real BFS snapshot with fixture WAN rows retains all 108 preceding PDF content streams and adds one visually reviewed appendix page. Focused tests cover malformed/duplicate/unassigned identities, unsupported states, timestamps, collection, literal text, keyboard table semantics and historical reports. Fresh production evidence and original WAN usage history remain pending at this checkpoint.

## October 8, 2026 — live BFS WAN evidence

SER8 Incus source 75eca09 passed internal/public readiness after a verified off-host backup (054924 UTC). Normal authenticated report **46** completed: two networks, 27 devices, 52 collected controls, zero unavailable/unsupported requests. WAN evidence reports one of one assigned appliances, one active WAN interface, zero missing appliances and a device report timestamp. Dashboard rows match complete saved evidence. The two purchase budgets remain $11,356/$12,940 with 10 official links. Comparison with report 45 has zero configuration, coverage or inventory changes. Temporary validation key was revoked and returned 401.

The actual production PDF has 109 pages. Removing only the new WAN field from the same saved snapshot yields 108 pages with identical preceding content streams. The production appendix was rendered and visually reviewed. Private receipts: /data/codex-bfs-wan-20261008/ and ignored validation/meraki-wan-20261008/. A follow-up source enhancement displays bounded appliance/site names while keeping identities in saved evidence; fresh named-row production validation is pending at this checkpoint. WAN history/capacity and full legacy report parity remain open.

## October 8 — named WAN rows, real link observation and browser checkpoint

Application source9eda671 is active on SER8 Incus; internal/public health passed after verified off-host backup055700 UTC. BFS report **47** completed with the same one active assigned WAN interface, named Firewall/BFS Wireless Network rows, device timestamp,52 collected controls, zero unavailable/unsupported requests, two budgets and10 official purchase links. Actual production PDF retains all108 preceding same-snapshot content streams and adds a visually reviewed named WAN page; all10 vendor links are clickable PDF annotations.

Report47 observed switch port17 negotiated speed changing from100 Mbps to1 Gbps while its connected/enabled/full-duplex values stayed unchanged. It retained the difference from46 and created durable notice53 at05:57:50 UTC. This is a reported link-speed observation, not proof of a security incident or policy edit. Existing generic notice wording says security-control change and needs refinement for operational evidence; historical records remain unchanged.

Ordinary signed-in browser keyboard activation opens report47 and focuses its summary. At390px, refresh retains #meraki, revision159, both budgets, named WAN rows and10links, with no page horizontal overflow. Screenshot capture again timed out; visual acceptance remains open. The temporary browser key and audit-validation key were revoked; both returned401. Local access-token file removed. Full named-source suite:882pass,1skip,325subtests; final focused20pass/26subtests. Backend9eda671 CI37734957788 passed. Source75eca09 installed Linux37734305963 passed all3scenarios; new-source installed/native CI remain live at this checkpoint.

Next WAN history work must parse the current documented [usage-history endpoint](https://developer.cisco.com/meraki/api-v1/get-network-appliance-uplinks-usage-history/): timestamped intervals with nested byInterface sent/received byte counters. The original flattened Kbps renderer is incompatible with that contract. Interval-derived throughput must retain scope/coverage and cannot establish subscribed circuit capacity.
