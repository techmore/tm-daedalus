# Daedalus project report

## Current state — October 9, 2026, 01:25 UTC

**Daedalus is a working, internet-hosted pilot. The full project remains incomplete.** This report covers the whole intended platform. The [historical checkpoints](PROJECT-HISTORY.md) preserve earlier receipts; their release identifiers and counts apply to their own dates.

Daedalus brings independent customer workspaces, domain and website health, managed internal scanners, Meraki planning, endpoint baselines and saved security evidence into the Cyber Security Pilot theme. The intended customer journey is: sign in, establish a workspace, connect services and scanners, understand findings and changes, produce the approved reports, and recover cleanly when collection fails.

- **Public marketing:** [Cyber Security Pilot](https://cybersecuritypilot.org/) is published from `site/` through GitHub Pages.
- **Application:** [Daedalus portal](https://daedalus.cybersecuritypilot.org/) runs on SER8 using Incus and persistent server storage.
- **Source:** [techmore/tm-daedalus](https://github.com/techmore/tm-daedalus) contains the marketing site, application, scanner integration, macOS CIS client and profiles.
- **Verified application release:** `fa02771f191fcce5a2a99e78f752e62d1cf47247`; 102-file archive SHA-256 `421cace59071262464b275c069fae61741af0e143eef65093106b1828656683e`. Internal/public readiness passed and all four served dashboard assets match source. Subsequent documentation commits do not change this application release.
- **Validation:** 1,304 local tests passed, one skipped, 426 subtests passed. Backend CI **37869582645** passed Python 3.11/3.12; managed Linux CI **37869582525** passed all five scenarios for this exact application source. These checks cover exercised behaviors; broader product acceptance remains open.

## Full platform scope

| Area | Working capability and evidence | Remaining completion work |
| --- | --- | --- |
| Identity and customer workspaces | Google owner sign-in; per-user scoped API/login keys; independent membership/roles, sharing approval and admin succession implementation. Normal scoped CSP/Penn reads and revoked-key 401s exercise isolation. | Actual additional users, approved sharing, succession and complete account/session lifecycle. |
| Domain ownership and onboarding | DNS TXT challenges, 30-day probation, audited 14-day active-check overrides and expiry controls. Explicit complimentary customer onboarding has its own 30-day review/renewal workflow. | Real customer TXT publication and verification; actual future expiry, renewal and access handoff. Meraki access does not verify DNS ownership. |
| DNS and email health | Saved DNS, SPF, DKIM, DMARC, DNSSEC observations, registration metadata and bounded certificate history. Actual CSP/Penn runs, successful-baseline selection, comparisons and themed reports. Unavailable lookups stay unknown. | Broader provider/checker acceptance, controlled DNS configuration-change walkthroughs and sustained recurring operation. Published email policies do not establish real message authentication or delivery. |
| Website health and linked vendors | Saved HTTPS/TLS, headers, cookies, page content, external resources, supported dependency/advisory observations and human vendor-review decisions. Fresh CSP website run 98 completed with zero differences. | Complete customer review/remediation workflows and provider/coverage review. Retrieved HTML and content differences do not establish execution, vendor security or an incident. |
| Authorized active website checks | Bounded exposure checks and Nikto runs/history, queue/cancellation controls, recorded authorization and expiring overrides. Existing active evidence remains separately dated in reports. | Broader procedure/coverage acceptance and operating limits. The current public-check validation did not initiate new active checks. |
| Local NmapUI scanner fleet | Managed Mac/Linux installers and upgrades; native Mac status window plus existing NmapUI web UI; detected address/mask/CIDR, approved ranges, readiness/activity and retained scan history. Actual installed clients check in to production. | Physical multiple VLANs/subnets, wider fleet, privileges/platform behavior and sustained operation. Detected connections inform scope; they do not automatically authorize new targets. |
| Realtime scan evidence and delivery | Real loopback progress/XML/upload/history, whole-run host/port comparisons, dated notices, measured queues and acknowledged uploads. Actual Mac/Linux interruption tests prove replay after a lost committed response without a duplicate event. Native status remains locally available during portal outages. | Physical multi-host/fleet outage and long-term acceptance. Unmeasurable delivery stays unknown; empty queues do not prove complete historical capture or scan coverage. |
| Remote operations | Typed health, diagnostics, approved scan requests, restart/update checks and managed upgrade workflows retain command/audit history. Installed Mac/Linux OS-update observation paths were exercised. | Broader requested machine-management contracts, portal upgrade reconciliation, recovery and maintenance acceptance. Cached update observations do not establish a freshly queried package catalog. |
| Meraki audits | Actual saved BFS and William Penn Charter assessments, scoped organization inventory/configuration, network/device/port/WAN/power/radio/lifecycle observations, comparison notices and reports. | Full original-script procedure/section parity, unavailable provider data, end-to-end operational evidence and customer acceptance. |
| UniFi replacement planning | Saved dated equipment quantities, priced/unpriced coverage, budgets and official purchase links. BFS/Penn inventory scenarios retain their report snapshots. | Approved RF, PoE, routing/stacking, HA, accessories, installation and procurement design. Inventory pricing does not establish feature equivalence, renewal savings or total ownership cost. |
| CIS macOS 26 | Published profile selection, source collectors, upload/score/coverage/history/report paths and authenticated release delivery support. Actual macOS 26.6.2 CI retains all 119 results: 10 pass, 22 fail, 87 manual. | Developer ID signed/notarized client; physical managed macOS 26 deployment/check-ins, selected profiles, remaining procedures and login/reboot persistence. No trusted production package is currently published. |
| Google Admin security | Deployed read-only OAuth connector, customer/domain validation, settings checklist, manual evidence, saved reports/comparisons and opt-in recurrence. | Dedicated OAuth setup and real tenant consent, benchmark applicability/version review, CSP/BFS assessment and recurring-operation acceptance. No live tenant audit is claimed. |
| Reports, comparisons and inbox | JIT generation/progress/download; frozen report evidence; workspace-scoped topic/history pagination, unread filtering/read receipts and durable dated notices. Original scanner XSL/assets and historical report versions are preserved. | Human approval of the complete report/customer workflow, operating-scale generation, retention and notification-delivery policy. Current notices are in-app; no customer email delivery is claimed. |
| Theme and product experience | CSP ivory/olive/brown styling, topic summaries, refreshable URLs, inline controls, history grouping and native scanner status. Implemented/API behavior and some visual receipts exist. | Populated desktop/mobile review of every topic, consistent priority/freshness/change/action hierarchy, keyboard/screen-reader review and final marketing/content acceptance. |
| Hosting and recovery | Incus deployment, verified off-host backups, staged activation, health checks and automatic rollback. A disposable restore recovered all 71 pre-deployment report pairs and passed SQLite integrity/foreign-key checks. | Independent recovery-secret custody, restored real Google sign-in, public DNS/TLS failover, storage/retention policy, capacity and sustained operating acceptance. |

## Latest completed customer workflow

Collection recovery now retains a dated failure attempt and the last successful evidence. Identical repeated failures stay quiet. The next successful run creates one **collection resumed** notice, including remaining limitations and recorded changes. A first successful collection is labelled as a baseline with no earlier comparison. Resumed collection does not establish that security findings were resolved.

Unchanged scheduled checks retain history without new inbox notices or completion banners. Manual checks still show completion feedback. Database admission prevents separate workers from starting the same workspace/check type concurrently; busy scheduled attempts defer for retry without a false collector-failure notice.

The authenticated isolated workflow exercised baseline → failed/repeated attempts → resumed collection → unchanged repeat → report generation/download → reload/read receipt. Earlier PDFs and frozen snapshots remained unchanged. Controlled failures were exercised locally.

Normal production CSP requests then saved DNS **97** and website **98**:

- DNS: completed with warnings against baseline 95; one SOA record difference and one certificate-history lookup-coverage difference. Three `www` DNS queries remain unavailable; certificate-history coverage is partial. Notice 68 preserves the distinction between a record change and collection coverage.
- Website: completed against baseline 96, zero recorded differences and no new inbox notice.
- Report **72**: completed at 100%, 11 visually reviewed pages, 25,666 bytes; SHA-256 `7fa3cdc94a957a0cddf8c1ee5299300bbdf751d97ce0ee1f23622973793c60ef`. It reuses separately dated prior active/Nikto evidence and retains the existing theme.
- All **71** earlier completed PDF/snapshot pairs remain identical. Temporary scoped validation keys were audited/revoked; both Bearer and token-login cookie access returned 401 afterward.

Verified pre-deployment backup `daedalus-data-20261009T012409Z.tar.gz` has SHA-256 `515603ac753136f5e849efcaf6fed8c2b7fe9c53c98302b2cc9af9cabdd7326e`. Its independent temporary restore recovered all 71 saved report pairs with matching hashes; temporary restored state was removed.

## Completion priorities

1. Finish and review the complete customer journey across populated desktop/mobile topics, keeping priority, freshness, changes and next actions consistent.
2. Validate actual customer TXT ownership, users/sharing/succession and expiry/renewal behavior.
3. Finish physical scanner fleet/recovery/upgrade acceptance and the signed macOS 26 CIS deployment workflow.
4. Complete live Google Admin consent/reporting and Meraki procedure/procurement acceptance.
5. Establish sustained scheduling, retention, capacity, restored sign-in and failover acceptance.

The original platform vision remains in scope. No overall completion or general customer-readiness claim is made.

## Supporting records

- [Dated completion audit and rollout receipts](docs/COMPLETION-AUDIT-20261008.md)
- [Historical project checkpoints](PROJECT-HISTORY.md)
- [Customer onboarding](docs/CUSTOMER-ONBOARDING.md)
- [Scanner live validation](docs/SCANNER-LIVE-VALIDATION.md), [comparison evidence](docs/SCANNER-COMPARISONS.md), [report fidelity](docs/SCANNER-REPORT-FIDELITY.md)
- [CIS macOS 26 alignment](CIS-MACOS26-ALIGNMENT.md), [client delivery](clients/csp-cis-audit/README.md#production-download-publishing)
- [Meraki purchase planning](docs/MERAKI-PURCHASE-PLANNING.md)
- [Google Admin security](docs/GOOGLE-ADMIN-SECURITY-AUDIT.md)
- [Incus deployment](docs/INCUS-DEPLOYMENT.md), [hosting/cost inventory](docs/WEBSITE-HOSTING-COSTS.md)
