# Daedalus project report

## October 4, 2026 — production linked dependency validation

Source **edeb6505f4c316b00b0be2a0e6ac8d524bd8d0a2** is deployed to Incus; internal/public health checks and off-host backup verification passed. Actual website check **53** completed with two external scripts, one external stylesheet, zero HTTP dependencies, zero declared integrity attributes and three missing script/style integrity attributes. Four external hosts were retained. These are root-HTML metadata observations, not validated hashes or a vendor-security assessment.

Run 53 compared with the older collection and recorded only page-content sampled-byte/fingerprint differences; the newly collected dependency namespace caused no artificial changes. Repeat check **54** completed with identical dependency observations and **zero differences**. Actual posture PDF **34** completed and downloaded; all seven rendered pages were reviewed, including dependency counts/limits, latest cancelled Nikto attempt 52 and retained completed audit 51. Private receipt: /data/codex-dependency-validation-20261004.json. Browser visual review and other original project requirements remain open.


## October 4, 2026 — linked dependency attribute evidence

The website collector now records a versioned dependency_observations block from the returned root HTML: HTTP references, external script/style counts, and declared/missing integrity attributes on those script/style tags. Counts exclude same-domain references and non-HTTP schemes, retain no resource URL paths/query tokens or integrity hashes, and do not fetch linked content. Declaration presence is not hash validation, browser enforcement, exploitability or a vendor-security verdict.

The dashboard's dependency group and posture PDF expose these counts and their limits. Comparison skips this new namespace when either saved report lacks the same schema, preventing collector-upgrade alerts; incomplete page evidence does not generate dependency-change conclusions. Fixtures cover whitespace attributes, applicable tag types, private-token/hash omission, old-schema compatibility, meaningful changes, incomplete-page comparison and PDF wording. Deeper vendor assessment and approval remain open; this change is not yet deployed or validated against a fresh production website run.


## October 4, 2026 — fresh production posture PDF review

Actual production posture report **33** completed and downloaded successfully. All seven pages were rendered and reviewed. The Nikto section explicitly shows latest cancelled attempt 52 and retained successful evidence from completed-with-warnings run 51, including all six observations. The PDF also retains DNS unknown lookup states, saved website response/header evidence and bounded exposure scope. Private generation receipt: /data/codex-posture-freshness-validation-20261004.json.

Review found a pagination issue: the last Nikto observation spilled onto a mostly empty page. The renderer now starts the Nikto assessment on its own page and keeps each observation heading with its description. The exact frozen production snapshot was rendered locally with this change; all seven pages were reviewed, with the full Nikto assessment together. Local validation artifact: validation/posture-grouped-20261004.pdf. Production deployment of this pagination refinement is pending.


## October 4, 2026 — production website queue completion and cancellation

Actual queued audit **51** completed with warnings at **07:47:52.706903 UTC**, after **601,780 ms** of collection. Six observations were retained. The single newly recorded comparison is an uncommon x-origin-cache header observed at /trace.axd; it is infrastructure metadata, not proof of exposed ASP.NET trace data. Coverage remains unconfirmed, test exhaustion is not established, and missing observations do not prove resolution. One persistent changes_and_warnings notice was verified against its saved run. Private receipt: /data/codex-nikto-queue-validation-20261004.json.

Source **41470b1bce7061ece24d2fc6848fb861ad4bce7b** is deployed with separate timestamps and queued cancellation. Internal/public health checks and off-host backup verification passed. Actual queued audit **52** was cancelled before collection, repeat cancellation remained cancelled, exactly one cancellation audit entry was saved, and collection_started_at remains null after worker polling. Legacy audit 51 retained null new timestamps. Private receipt: /data/codex-nikto-cancellation-validation-20261004.json. Backend CI 37186886685 passed; the preceding timestamp CI failure was the legacy snapshot expectation corrected in this source. The local full suite passed **478 tests and 96 subtests**. Browser pixel review and other full-project gaps remain open.


## October 4, 2026 — queued website audit cancellation

Workspace admins can cancel a queued Nikto audit through a scoped API and a history-row action. A conditional queued-to-cancelled update races safely with worker claiming; already-started collection returns HTTP 409. Cancelled attempts keep their original requester, timestamps and history, while the cancelling actor is recorded in external_check.cancelled. Repeated cancellation is idempotent and does not duplicate the audit entry. Current admin membership is required, including when domain authorization is no longer available. No new confirmation popup is used.

Fixtures confirm cancellation prevents collection, repeated cancellation creates one audit record, a running job is retained on conflict, and a downgraded member cannot cancel. Production audit 51 remains active on source 99ec2bb; cancellation and separate timestamp changes await deployment after terminal confirmation. The full goal remains active.


## October 4, 2026 — separate website queue and collection timestamps

Website jobs now record nullable queued_at and collection_started_at fields. Submission records queue entry, while the atomic worker claim records collection start. API history and frozen report snapshots expose both times, and Nikto history displays them separately. Existing started_at is retained for compatibility. Migration adds the fields without reconstructing timestamps for legacy runs; an idempotent old-schema fixture verifies preserved timestamps/snapshots and null new fields.

The concurrency fixtures also passed: simultaneous enqueue creates one job and one HTTP 409 rejection; competing workers collect one saved job once. Expiration of a previously valid override blocks collection. Production remains on source 99ec2bb while actual audit 51 is active; timestamp changes are not yet deployed.


## October 4, 2026 — production queue submission and authorization checks

Source **99ec2bb9efbeb410cb75961c20d76fb8cb961089** is deployed to Incus with internal/public health checks passed and a verified off-host backup. Actual owned-domain audit **51** returned HTTP **202** with status **queued** in **0.079 seconds**, then its saved history reported **running**. Completion remains pending; no repeated submission or restart was made. Private receipt: /data/codex-nikto-queue-validation-20261004.json.

Additional fixtures confirm collection is refused when domain verification is lost or the workspace domain changes after enqueue, preserving the original requested domain and terminal failed attempt. A full 25-job queue rejects submission with HTTP 429 and creates no additional row. These complement the existing role-revocation, duplicate, queued-recovery and single-claim checks. The full project remains active, with production terminal audit validation and earlier requirements still open.


## October 4, 2026 — persisted website audit queue

Nikto submissions now save a queued ExternalCheckRun and return HTTP 202 before collection. A dedicated server worker atomically claims saved jobs in order, rechecks the requester’s current approved admin role, domain identity and ownership/override authorization, then stores the result and publishes its update. Enqueue uses SQLite write serialization, rejects duplicate queued/running workspace audits, and bounds the global pending queue to 25. Queued rows survive startup recovery; running rows interrupted by process loss become failed with a persistent workspace notice. Interrupted active scans are not automatically repeated.

The website UI disables another submission while queued or running. Snapshot PDFs label queued work explicitly and do not claim collection has started. Fixtures prove prompt response without collector invocation, duplicate rejection, preservation of queued rows through recovery, single claim, and refusal after admin-role removal. The preceding full suite passed 467 tests and 96 subtests; queued-PDF wording received an additional focused check. Production queue execution is pending validation.


## October 4, 2026 — production report library validation

Production source **1bb372ec563e4ee235c3bb7bd400508db5321023** (dashboard asset 076) groups domain health, internal network, and Meraki/endpoint PDFs before report creation controls. Authenticated production HTML and JavaScript checks confirmed the new library and ordering. Latest completed PDFs downloaded successfully for all four topics: scanner **32** (5,970 bytes), Meraki **31** (10,510), endpoint **30** (24,923), external posture **28** (17,419). Private receipt: /data/codex-report-library-validation-20261004.json. This verifies served structure and downloads; browser visual review remains open.

The report status summary is being corrected to distinguish ready downloads, running/queued jobs, failures and jobs without a ready download. Full-project requirements listed in earlier checkpoints remain open.


## October 4, 2026 — topic layout and production Mac scanner evidence

Production source **b474133a6df3d9644d4881b96405bc952d26ef08** puts DNS and website assessment and change history ahead of detailed records; scope explanations are expandable. Incus deployment passed internal and public health checks, with a verified off-host backup. The authenticated served dashboard passed structural ordering checks; browser pixel review remains unverified.

Actual Mac scanner command **18** completed against **127.0.0.1**. Saved run **e9f020f1-d603-4616-a36c-f49c7aa8bc2c** is terminal completed with **18 events and three result events**. Its temporary loopback-only scope was restored to the original empty scope after terminal confirmation. Report **32** reached PDF ready, 100 percent; all three rendered pages were reviewed. This proves the local command/upload/saved-run/PDF path, not approved VLAN coverage or confirmed vulnerabilities. Private receipt: /data/codex-mac-loopback-validation-20261004.json.

Full CIS client CI **37184923850** and Python CI **37184923848** completed successfully. The earlier topic-layout full backend run passed **461 tests and 96 subtests**. Endpoint page grouping is being revised next. Real Tahoe execution, trusted client distribution, exact production VLAN scope, browser review and the remaining full-project requirements are still open.


## October 4, 2026 — pinned Tahoe retention and real presence timeout

Client source **dce0cb0289863c0110beec7f72a490448c912239** adds a dedicated `audit_retention_configure` path. The pinned CIS Level 1/2 policy is literal **30d**, independently of the legacy CSP seven-day check. A canonical age-only 30d field passes; an explicit shorter pure-age policy fails. Noncanonical equivalent/longer durations, combined age/size expressions, duplicates, malformed, unsupported and inaccessible fields stay manual. The details explain that policy evidence does not establish retained records or central storage. The fixed audit_control reader is bounded, no-follow and read-only; raw policy text is not uploaded. The macOS major-version gate remains in front of this check.

Mapping coverage is now **79/100 Level 1** and **84/119 Level 2** (86 distinct routines: 44 preferences, 32 command routines, one audit-policy routine, nine filesystem/ACL routines). **21 Level 1** and **35 Level 2** remain manual. Published profiles and saved reports are unchanged. All **460 backend tests and 96 subtests** passed; local client validation passed **70 unit tests**, zero failures/skips, confirmed through xcresulttool. Receipt: validation/cis-retention-unit-receipt-20261004.json. Current full client CI **37184923850** and Python CI **37184923848** are running. The earlier APFS source full client CI **37184590606** passed with **72 passing case records**, zero failures; its Python CI also passed.

At **07:08:01 UTC**, actual production status naturally marked the stopped client **offline / check-in overdue**, with **zero online clients**, using the configured **900-second** window. Its last heartbeat remained **06:51:44.180219 UTC** and its last report receipt remained **05:52:09.057259 UTC**. No timestamp was modified to simulate expiration. This completes the actual launch, scheduled repeat, stop and overdue-presence validation performed with the temporary Mac client; it does not establish a continuously deployed fleet. Private receipt: /data/codex-cis-presence-overdue-validation-20261004.json.

Production application remains on release 075. Real Tahoe execution, trusted client distribution, approved production VLAN scope, browser review and other earlier full-project requirements remain open. The full goal remains active.

## October 4, 2026 — internal APFS encryption implementation checkpoint

Client source **02d06660e8f565a13432d36217104eb9f454086f** adds the pinned Tahoe `os_internal_apfs_volumes_encrypted` rule. It uses structured diskutil inventory/info commands, validates bounded volume identifiers and internal/APFS identity, requires explicitly typed FileVault booleans, follows the pinned Preboot/Recovery/VM name exclusions, and keeps volume names/device paths out of report details. Enumeration is capped at 32 volumes; a six-second admission deadline plus the existing three-second command deadline bounds collection. Empty, missing, duplicate, malformed, timed-out, inaccessible, incorrectly typed or incomplete container evidence remains manual. An explicit eligible unencrypted volume fails; only complete captured eligible encrypted evidence passes. No storage or encryption setting is changed.

Mapping coverage is now **78/100 Level 1** and **83/119 Level 2** (85 distinct bundled rule IDs). **22 Level 1** and **36 Level 2** remain manual. These are routine mappings, not real Tahoe conformance evidence. External volumes remain manual and the existing server limitation on the boot-FileVault rule remains in force. Both alignment documents were reconciled to the current mapping counts; immutable published profile JSON and saved report evidence were not edited.

The full backend suite passed **460 tests and 96 subtests**. Final client source passed all **68 local unit tests**, zero failures/skips, confirmed through xcresulttool; local receipt: validation/cis-apfs-final-unit-receipt-20261004.json. Fixtures cover explicit encryption, exclusions, privacy, integer-vs-boolean ambiguity, unknown inventory, malformed identifiers, incomplete containers, duplicate volumes, output/count/time bounds and the exact command registry. Current Python CI **37184590661** and full client CI **37184590606** are running. Production remains on release 075; no newly distributed or continuously installed client is claimed. Real macOS 26 execution, trusted distribution, approved VLAN coverage, browser review and prior full-project gaps remain open. The goal remains active.

## October 4, 2026 — live rebuilt-client periodic check-in validation

Production remains on release 075, application commit **f7536e87ae9548b8aa753d4e46d584feca69614c**. Rebuilt the credential-free, locally ad-hoc signed Mac demo package and launched its real menu-bar executable with a temporary exclusive 0600 config and the existing endpoint identity. Selected the published macOS 26 profile on this macOS **27.0.1** host. Production recorded actual check-ins at **06:46:14.200912 UTC** and **06:51:44.180219 UTC**, about 330 seconds apart, within the five-minute timer's 30-second allowance. The two pre-existing report responses remained byte-equivalent as parsed JSON; no new report/score was uploaded. Console output was buffered/empty, so no observed profile-skip log claim is made.

Stopped the client (SIGTERM, exit -15), removed the temporary private config, and stored the receipt privately at /data/codex-cis-heartbeat-live-20261004.json and locally under validation/cis-heartbeat-live-20261004. Client presence remains recent until the real 15-minute expiry; production overdue transition is not yet observed. This validates actual launch and periodic delivery, not continuous deployment, macOS 26 rule execution or trusted public distribution.

Current release Python CI **37183579199**, managed Linux CI **37183579184**, and full Mac client CI **37183579192** all passed. The client log contains **69 passing case records**, zero failures, including unit/UI cases and the local-package workflow. Local signing capability inspection found one **Apple Development** identity and no **Developer ID Application** identity. Distribution signing/notarization remains unresolved.

Independent direct DNS queries to both ns1.hover.com and ns2.hover.com returned authoritative SERVFAIL for www.cybersecuritypilot.org A, AAAA and CNAME. This confirms failure at the authoritative layer; its root configuration cause is unproven. Receipt: /data/codex-www-authoritative-dns-20261004.json. No DNS records were changed.

Marketing source **0a0eab6e2172de8a747a51c5a321984cb82a8db2** replaces unimplemented email-enumeration and unsupported device-audit wording with DNS change history/alerts and versioned endpoint checks/history. All five public-site tests passed. Pages run **37184088374** and source Python CI **37184088369** passed. Actual public HTTPS returned 200 and confirmed both new feature descriptions and removal of the old claims; local receipt: validation/cis-heartbeat-live-20261004/public-marketing-validation.json. The full goal remains active with real Tahoe, trusted persistent client distribution, browser review, approved VLAN coverage and prior scope gaps open.

## October 4, 2026 — Release 075: independent CIS client presence

Production application commit **f7536e87ae9548b8aa753d4e46d584feca69614c** is active and healthy. The 59-file archive SHA-256 is **8002ea74ce5839229ab31f27803b13e40e430e6d0ebec36ab210d0cde1179d9a**; verified off-host backup: daedalus-data-20261004T064228Z.tar.gz. The backend suite passed **459 tests and 96 subtests**; after the fleet-count query refinement, all **36 affected tests and five subtests** passed again. Mac build-for-testing passed; the two new request-builder XCTest cases passed with zero skips/failures, confirmed through xcresulttool. Current CI: Python 37183579199, CIS client 37183579192 and managed Linux 37183579184 are running.

Added a nullable, additive/idempotent client-heartbeat timestamp, separate from report receipt/collection dates. Authenticated same-workspace check-ins update only an endpoint already registered by a report; they cannot create a device, score or result. Unknown devices and another workspace's key are rejected; revocation rejects subsequent check-ins. The updated client sends same-origin check-ins at launch and every five minutes while open using the existing private identifier and redirect-guarded ephemeral transport. The dashboard uses independent client presence: unknown for legacy clients, checking in within 15 minutes, overdue afterward. Existing API online_device_count/state fields retain their legacy report-recency meaning and now carry presence_source; the API separately provides client_state, heartbeat timestamps and an uncapped online_client_count. Overview wording explicitly identifies recent report receipts.

Production checks confirmed version-075 assets, successful migration with the existing device and two reports preserved, unknown client presence without a fabricated heartbeat, and HTTP 404 for a workspace-authenticated unregistered device. The request did not mutate devices. Private receipt: /data/codex-cis-presence-validation-20261004.json. Rebuilt-client periodic check-ins against production remain unvalidated; no persistent connected client, trusted distribution, or real Tahoe execution is claimed. The full objective remains active, including prior browser, approved VLAN and other scope gaps.

## October 4, 2026 — Release 074: internal network evidence before controls

Production application commit **69c7308bd45cc250f8a29f49fdd1d1860c1cd105** is active and healthy. The 59-file archive SHA-256 is **15e746d1d8611e7df8bc4d1c7a60cc55c59722fe6333e74a7b17acce749fdc27**; verified off-host backup: daedalus-data-20261004T063327Z.tar.gz. Full local validation passed **454 tests and 96 subtests** before the final DOM regression was added; all **nine topic tests**, including that new regression, then passed. JavaScript syntax/diff checks passed. Release 073 Python and managed Linux CI passed; current release CI remains unconfirmed.

Internal Network now leads with enabled scanner availability, confirmed online scan-engine readiness and approved-range assignment. These counts explicitly do not imply network scan coverage. Per-location saved runs and comparisons precede collapsed scan/management controls and command history. Open control panels are remembered across card rebuilding; existing target/scope buffers and inline confirmations retain their behavior. The page title uses the security topic. Server-rendered controls also start collapsed. Node DOM fixtures verify node order, literal scanner names, panel-open state, and disabled scanning without approved scope.

Authenticated production checks confirmed version-074 assets, the summary-before-scanner template order and hosted script ordering. Independent calculation from the actual dashboard API found **two enabled scanners, one online, one with a confirmed ready engine, zero with approved ranges**. No private scan was performed or scope inferred. Readiness is healthy. Private receipt: /data/codex-scanner-topic-validation-20261004.json. This is served-structure/data validation, not browser visual review. Approved production VLAN coverage, real Tahoe execution, trusted persistent CIS distribution, visual review and the other full-project requirements remain open. The goal remains active.

## October 4, 2026 — Release 073: unchanged warning notices are quiet

Production application commit **b3f54e94374abae74391b67bd11797f674862b9d** is active and healthy. The 59-file archive SHA-256 is **90e5c3550b149083aab4ed241cc80a12ac1cd9ab217d850045c6bf3639dddc16**; verified off-host backup: daedalus-data-20261004T062754Z.tar.gz. All **452 tests and 96 subtests** passed locally. Release 072 Python and managed Linux CI passed; current release CI remains unconfirmed.

External-check notices now suppress repeated unchanged coverage warnings against the latest terminal run of the same workspace/check type. Every run and its original errors remain saved. Failed DNS query identity is compared separately from transient exception text; changed query sets, material differences, and warnings returning after recovery or a failed run still notify. Existing notices are retained. Audit details record repeated-warning notice suppression. Added the previously absent warning reason for incomplete bounded website exposure coverage. Fixtures cover DNS and partial-page repetition, new failures, recovery/failure recurrence, retained run history and incomplete exposure reasons.

Actual authenticated production DNS run **50** completed_with_warnings, using explicit resolver 1.1.1.1. It saved zero differences, retained the three unknown www lookups, appeared as the latest history run, and produced **zero new notices**. Read-only production database inspection confirmed the suppression marker in its completion audit. Readiness remained healthy. Private receipt: /data/codex-warning-notice-validation-20261004.json. This proves the unchanged-warning workflow, not resolution of www DNS or complete project readiness. Visual review, real Tahoe validation, trusted persistent CIS distribution, approved production VLAN coverage and the previously recorded full-project gaps remain open. The goal remains active.

## October 4, 2026 — Release 072: DNS audit resolver provenance and repeat evidence

Production application commit **94dd267a4adcd019e88cf56a977b7ad06fb0093b** is active and healthy. The 59-file archive SHA-256 is **8651afce71d705b15e7063b04a7796534c357ac788deb2bd4f3fcec01cb97a43**; verified off-host backup: daedalus-data-20261004T062105Z.tar.gz. All **448 tests and 96 subtests** passed. Current Python CI passed; managed Linux CI was still running at the checkpoint.

Added operator-only `DAEDALUS_AUDIT_DNS_NAMESERVERS`, bounded to three literal unicast IP addresses, with no silent fallback. Saved snapshots record resolver mode/addresses, displayed in lookup evidence; resolver metadata is excluded from target-change comparisons. Website target validation and DNS TXT ownership verification retain their existing resolver behavior. Production now uses **1.1.1.1** for DNS/email audits. The original environment has a private 0600 backup.

Direct service restart failed to stop the old process because of Incus control-group permissions. Initial run **47** therefore accurately recorded system resolver 127.0.0.53; it is not explicit-resolver validation. The normal Incus instance restart restored healthy service and applied the setting. Actual run **48** recorded explicit resolver 1.1.1.1: DS/DNSKEY no-answer observations, with three remaining www SERVFAIL lookups. Its **13** differences are lookup-availability/DNSSEC observation changes after the collector switch, not thirteen domain configuration/security failures. Repeat run **49**, using the same explicit resolver, saved **zero changes** and the same three unknown www lookups. No DNSSEC chain validation is claimed.

Dated notices were saved for run 48 (changes_and_warnings) and run 49 (warnings). Repeated unchanged warnings still generate separate notices; reducing this inbox noise remains open. Private full run/history/notice receipt: /data/codex-dns-resolver-validation-20261004.json. The www failure requires further DNS diagnosis; visual review, real Tahoe execution, trusted persistent client distribution, approved VLAN coverage and other full-project requirements remain open. The full objective remains active.

## October 4, 2026 — Release 071: topic evidence grouping

Production application commit **fa3546b4d4f7f97638b3dabdf99e3b08bba5a0c0** is active and healthy. The 58-file archive SHA-256 is **7df74284c67c6e0aa91c2ee7dd54e5219691a33d000751b3e7d7cf9f11a6e769**; verified off-host backup: daedalus-data-20261004T061718Z.tar.gz. The full suite passed **445 tests and 90 subtests**. JavaScript syntax and diff checks passed; current-release CI remains unconfirmed.

DNS now leads with domain resolution and signing-record evidence, followed by email routing/protection. Website summaries precede the review list. DNS lookup failures stay unknown; signing-record observations do not imply local DNSSEC chain validation. Endpoint compliance highlights latest-report failed/manual/error counts alongside pass rate and enrolled devices; baseline reports precede availability. Meraki's current assessment is labeled network posture and coverage. These changes respond to the requested organization by security topic; remaining topic-level layout work is open.

Authenticated production checks confirmed version-071 assets, DNS/website summary order, endpoint report order and script grouping. The no-store posture endpoint still reports the actual latest endpoint evidence: 82 failed, 19 manual, 17 errors, 23.38% pass rate. Private receipt: /data/codex-topic-layout-validation-20261004.json. This verifies served structure and data, not rendered browser UX. Visual review, real Tahoe execution, trusted persistent client distribution, approved production VLAN coverage and the remaining full-project requirements are still open. The full objective remains active.

## October 4, 2026 — Release 069: Meraki observations visible in topic summary

Production application commit **517f38fe7106c2b16b71f30a4a20506e1c39efb7** is active and healthy. Archive: 58 files, SHA-256 **b18107c75baf87ac5cbd1263d4ccd7d605fdddf0a69fea7dbbf828ab1b85133f**; verified off-host backup: daedalus-data-20261004T060725Z.tar.gz. The full suite passed **443 tests and 90 subtests**; after removing a test-string escape warning, all four topic tests passed again. JavaScript syntax and diff checks passed. Release 068 Python CI **37181613402** and managed Linux CI **37181613380** both passed; current release CI remains unconfirmed.

The Meraki topic summary now presents the latest saved Review observation titles and guidance immediately beneath its assessment counts. It shares the immutable-report detail cache with the existing detail view, displays at most five observations, keeps missing evidence distinct from zero observations, renders provider strings through textContent and ignores detached refresh containers. Node fixtures verify literal HTML-like strings, shared request caching, the cap and unknown/empty/detached states. Coverage warning rows remain distinct from Review observations.

Authenticated production checks confirmed the version-069 template/script and the no-store saved-detail response for report 31, including its open-SSID review item. Receipt: /data/codex-meraki-summary-validation-20261004.json. Browser visual review is still pending; API/script validation is not pixel QA. Full project completion remains unproven with the previously recorded deployment, endpoint and operational requirements open.

## October 4, 2026 — Release 068: fresh Meraki report and review-first summaries

Production application commit **742141eefe0398ff411dfa45acb6d14badd45d35** is active and healthy. Archive: 58 files, SHA-256 **b90ead84f40578f1440e26e747dcb71b94842c637a650255b114989616e590b8**; verified off-host backup: daedalus-data-20261004T060210Z.tar.gz. All **442 tests and 90 subtests** passed locally after repairing a failed-job fixture that omitted its required snapshot. Python CI **37181613402** and managed Linux CI **37181613380** are running. Release 067's Python CI 37181241962 and managed Linux CI 37181241841 passed.

Used the existing stored Meraki credential and exactly one already-authorized organization; no credential rotation or scope grant was performed. Actual report **31** completed at 100% / PDF ready. It saved one network, zero assigned devices, ten collected controls and two unavailable controls. Comparison with report **26** recorded zero control, coverage, inventory or inventory-coverage changes, and no new change notice. The saved observation asks for review of an open SSID configuration; the intrusion and malware protection calls returned HTTP 400 coverage gaps, not disabled-protection evidence. The actual 10,510-byte, five-page PDF was downloaded, rendered and reviewed on every page. Private evidence: /data/codex-meraki-validation-20261004.json; local PDF: validation/csp-meraki-20261004.pdf.

Overview and Meraki topic summaries now lead with review observations and unavailable controls, then inventory counts. Missing finding evidence remains unknown / Not captured. A newer queued/running/failed Meraki attempt is represented separately while retaining the last completed evidence and its date. Authenticated production checks confirmed one review observation, two unavailable controls, attention state and current version-068 script content. Browser visual review remains pending; PDF review does not prove the browser layout.

The full objective remains active: macOS 26 validation, trusted persistent CIS distribution, remaining checker semantics, approved production VLAN coverage, browser review, broader authorized inventory and other earlier scope gaps are not declared complete.

## October 4, 2026 — Release 067: repeat CIS history, notice and visible review counts

Production application commit **3b3b0f16bcbf30817713f59cc05cd338262ae72e** is active and healthy. Archive: 58 files, SHA-256 **7bbe095e25092d9b5d4dfa4927a210ef357a78eb98ea3d5f50402a148addcc9c**; verified off-host backup: daedalus-data-20261004T055456Z.tar.gz. All **440 backend tests and 90 subtests** passed locally. Full client CI **37181000414** passed its configured suite (67 passing case records, zero failures), release-script syntax check and demo-package build. Current release backend/scanner CI remains unconfirmed.

Rebuilt and ran the corrected local CSP starter client against production. Actual report **2**, collected **2026-10-04T05:52:08Z**, saved all 154 results with profile verification and the same device identity: 36 pass, 82 fail, 19 manual, 17 error, observed pass rate **23.38%**. An independent status-map comparison of actual reports 1 and 2 exactly matched all **11** saved differences: ten old definitive statuses became manual, while the old audit-service false pass became fail. These reflect checker corrections, not Mac remediation. Exactly one dated source-report notification **9** was saved at **2026-10-04T05:52:09.057259Z**. Receipt: /data/codex-cis-repeat-validation-20261004.json.

The overview now labels the area Endpoint checks and surfaces the latest report's failed/manual/error counts beside its pass rate. Nonzero or unknown counts request review; raw endpoint names/evidence stay out of the summary. The authenticated production endpoint confirmed state attention and 82 failed / 19 manual / 17 errors for report 2. This is the latest endpoint report, not a fleet compliance score.

Stopped the temporary client (exit 143) and removed its private key configs. Device presence reflects the existing 36-hour report-recency window, not a running app after test cleanup. Real macOS 26 execution, persistent trusted CIS distribution, remaining check semantics, approved VLAN scanning, browser visual review and the other full-project requirements remain open.

## October 4, 2026 — Grouped legacy audit-policy corrections

Client source **7792fb3900e14189b86650cec728c8a44781354d** replaces seven sudo/grep flag checkers and the retention checker with a shared bounded no-follow read of the fixed audit_control file. Exact field/class parsing replaces substring matches on merged stdout/stderr. Missing, unreadable, duplicate, unknown or prefixed selections remain manual; explicit unmatched class criteria fail. Administrative, authentication, login, network and process selections use the macOS audit_class definitions. Results describe the CSP class-selection criterion and do not claim complete event coverage or kernel activation. Retention recognizes the documented case-sensitive age units (s, h, d, y) and the existing seven-day CSP criterion; unsupported and combined age/size policies require manual review. No file contents are uploaded or configuration changed.

Final source compiled with Xcode build-for-testing. Local client unit execution passed **63 tests**, zero failures/skips, confirmed through xcresulttool summary (validation/cis-policy-tests-20261004.json). This includes login, service-state and flag/retention fixtures. Full current client CI **37181000414** is pending; prior client run **37180718823** was cancelled by the workflow when superseded. Current backend CI **37181000395** is running; previous source backend CI 37180718842 passed. Production and the saved initial report retain their historical state. Updated live endpoint validation and full UI/package CI remain open alongside Tahoe, trusted distribution and the rest of the project scope.

## October 4, 2026 — Legacy auditing false-pass correction

Client source **ec0d61011c44a6487c47935947859424827c4a31** replaces the legacy audit-service substring test. That test merged stdout/stderr and could pass on an error containing com.apple.auditd. Legacy and Tahoe checks now share the explicit system-service, regular audit_control metadata and kernel-condition implementation. Known absent service fails; permission/unsupported/ambiguous evidence stays manual; explicit enabled evidence passes. The original legacy check ID is retained. Regression fixtures cover error text mentioning auditd, permission denial and enabled evidence. Saved production report 1 remains unchanged.

Local Xcode build-for-testing passed. Current full client CI **37180718823** is running; prior client run **37180619319** was cancelled when the updated source superseded it, so no prior success is inferred. Current backend CI **37180718842** is also running; the unchanged backend retains its local 439-test/90-subtest pass. No rebuilt client distribution or new production endpoint score is claimed. Requested a real macOS 26 endpoint while continuing independent client work. The full objective remains active.

## October 4, 2026 — Legacy automatic-login evidence correction

Client source **21cedc28792fc28cd56783598bc493d6151e576c** corrects the automatic-login checker exposed by actual production report 1. Previously it merged defaults stderr into stdout, treated a missing-key error as an enabled account, and treated process launch failure as a pass. It now uses the bounded no-follow regular-plist reader at the fixed system login-window path. Missing, inaccessible, malformed, unsupported and empty account evidence remains manual. An explicit nonempty account setting fails without uploading the account name. Both legacy implementations now use one checker; saved report 1 remains immutable.

Local Xcode build-for-testing completed successfully. All **439 backend tests and 90 subtests** passed. Full client CI **37180619319** is queued at this checkpoint; no full client-suite pass or rebuilt deployment is claimed for this correction. Production remains on release 066. Release 066 Python CI **37180444425** and managed Linux scanner CI **37180444368** passed; release 065 client CI **37180175288** passed. Further legacy checker semantics, repeat endpoint comparison, real macOS 26 execution, trusted distribution and the remaining project scope remain open.

## October 4, 2026 — Release 066: actual production CIS endpoint report

Production application commit **1341e8e9033ed33174d8ddfd2546210a59852b85** is active and healthy. Archive: 58 files, SHA-256 **c4857a02bb2f94a838a828a7b841e150499723ae4e755d015ea3adb3c787fe82**; verified off-host backup: daedalus-data-20261004T053756Z.tar.gz. The 438-test/90-subtest suite passed for the wording fix before adding its new regression test; that regression test then passed separately. Current release CI remains unconfirmed.

Built and ran the local CSP client against production using the operator's workspace-bound user key, without rotating the shared CIS key. Published the compatible legacy **csp-macos-browser-baseline 1.0.0** and saved actual endpoint report **1**, collected **2026-10-04T05:34:37Z** on macOS **27.0.1**: 154 results, 38 pass, 90 fail, 9 manual, 17 error, observed checklist pass rate **24.68%**, profile_verified true. Errors include time-limited legacy checks; some legacy failures report missing preference evidence as configuration failures. These saved statuses require checker validation and must not be treated as 90 confirmed security findings or Tahoe compliance. This proves live collection, upload and storage, not all legacy check semantics.

PDF job **29** completed, but visual/content review found misleading unchanged-settings wording when no prior report existed. The renderer now states that absent recorded differences do not prove settings unchanged. Corrected production PDF job **30** completed and downloaded. All eight pages were validated: pages 1–7 match the reviewed original renders exactly; revised page 8 was inspected. Private receipt: /data/codex-cis-production-validation-20261004.json. Local corrected artifact: validation/cis-production-20261004/endpoint-report-corrected.pdf.

Stopped the temporary local client (exit 143), removed both temporary access-key configs and retained production evidence. This is not a persistent production CIS deployment. Repeat-report comparison, real macOS 26 execution, remaining manual checks, trusted signing/notarization and the other full-project requirements remain open.

## October 4, 2026 — Release 065: independent CIS validation credentials

Production application commit **8ad1fefe928e5f1928e2886334a164f7b0e552e2** is active and healthy. The 58-file archive SHA-256 is **6b8dbedd765a2cae45a81d05e426c8fdb0ba006deb00f1eadddfcce301a86a77**; verified off-host backup: daedalus-data-20261004T053210Z.tar.gz. All **438 tests and 90 subtests** passed locally; current CI has not yet been confirmed.

CIS profile downloads and report uploads now accept existing revocable user access keys through the client's X-API-Key header. These keys retain their workspace binding and current approved membership checks; revocation, expiry and membership removal reject both endpoints. Tests uploaded a complete saved report, excluded a second workspace's profile and proved that revoking the user key leaves the shared CIS key valid. This enables independent endpoint validation without rotating the existing workspace deployment credential. User keys retain the owner's dashboard/API privileges and require private handling and renewal; they are not dedicated upload-only credentials.

Actual production catalog access using the CSP operator user key returned only the two CSP Tahoe profile revisions, with no shared-key mutation. Receipt: /data/codex-cis-user-key-validation-20261004.json. A real production endpoint report is still pending; the available Mac runs macOS 27 and cannot execute the Tahoe profiles. No compliance score or production client deployment is inferred from the catalog check.

## October 4, 2026 — CIS security-auditing implementation checkpoint

Source commit **8e8c0de2086a7920d704e98492460467e0b2110b** adds the bundled read-only **audit_auditd_enabled** Tahoe check. It checks the exact system audit service, regular audit_control file metadata and kernel audit condition with fixed executables/arguments. An explicit disabled service or kernel condition fails; inaccessible, unsupported or ambiguous evidence remains manual. No audit settings are modified and raw service/kernel output is not uploaded. The rule follows the pinned NIST mSCP Tahoe revision already used by the profiles.

Implementation coverage is now **77/100 Level 1** and **82/119 Level 2** checks (84 distinct implemented rule IDs); **23 Level 1** and **37 Level 2** remain manual. Published profile versions and saved reports are unchanged. Backend validation passed **436 tests and 90 subtests**. CIS client CI **37179625771** failed its exact command-registry expectation because the new audit rule was missing from that test dictionary; both new audit behavior tests passed. Source **9bce377d8da4034a287ef20019080b1d2ecada2d** adds the missing exact executable/argument expectation without relaxing the registry invariant. Corrected client CI **37179763205** passed the complete configured test suite (64 passing case records, zero failed records), release-script syntax check and credential-free demo-package build. Current backend CI **37179794159** also passed; intermediate backend run 37179763190 was cancelled by a later push. Both local Xcode processes were explicitly cancelled (exit 75): the first after the correction, the second after its unit tests passed and the independent full CI run succeeded; no completed local UI-suite result is claimed. Both local handles are terminal. CI package success does not supply Developer ID trust or notarization, and no public client distribution was enabled. A fresh production API check confirms two profiles, a configured upload key and zero CIS endpoints; production endpoint upload remains unverified. Real macOS 26 execution and trusted signing/notarization remain open. Production remains on application commit d8692c8 with the independently validated managed scanner fix.

## October 4, 2026 — Release 064: real Mac management and upgrade validation

Production application commit **d8692c8cf7ed86bd6d33a139e914af6de36a6365** is active and healthy. The 58-file release archive SHA-256 is **ddf8752107a18e0e30b9edd5ec7b738ce49092cd7b12ef7ac2e80114a576a502**; verified off-host backup: daedalus-data-20261004T051203Z.tar.gz. **436 tests and 90 subtests** passed; Python CI 37179189498 and managed Linux CI 37179189477 passed.

Actual production scanner 2 completed remote health refresh (command 14) and NmapUI release-channel check (15). OS catalog check 16 delivered and completed, but returned unknown. Direct read-only inspection proved Apple's successful no-updates message was on stderr; the bridge previously parsed stdout only. The parser now reads both bounded streams while retaining return-code validation and withholding raw output from reports.

Downloaded the authenticated production kit and completed the normal managed macOS upgrade with kit SHA-256 **74853a583581ff7e26466a7caf73800cc3329a16c1e499e3663603bfcd6c81b9**. The upgrader reported both services running/readiness satisfied and retained descriptor backups. Production retained scanner ID 2 and earlier command records. Repeated OS check **17** completed at **2026-10-04T05:14:42.746652Z**, with status **no_updates** and update_count **0**. Private evidence: /data/codex-scanner-management-validation-20261004.json. No network scan or update installation was performed.

This proves the management workflow on the available macOS **27.0.1** host, not macOS 26 compatibility. Browser visual review, authorized production VLAN coverage and the remaining full-project requirements are still open.

## October 4, 2026 — Release 063: current evidence first

Production application commit **70b6571eef69ebea2a07496211c81c0af78648f9** is active and healthy. The 58-file archive SHA-256 is **fdf8247d6301570ef6efd953c5f88aa5a6a4455abffbe66ba31cd89f4deda156**; verified off-host backup: daedalus-data-20261004T045749Z.tar.gz. All **435 tests and 90 subtests** passed. Python CI 37178474507 and managed Linux scanner/recovery CI 37178474579 both passed.

The overview now starts with five workspace-scoped assessment cards: DNS/email, website, scanners, CIS and Meraki. Each shows saved evidence, an assessment state, capture date when available, and a direct topic link. Scanner counters are collapsed below these cards. No combined security score is inferred. Latest failed/running DNS or website attempts retain the previous completed evidence; deeper website audit evidence has its own date. Rendering preserves focused cards and rejects stale responses.

Authenticated production validation confirmed the no-store posture endpoint, current assets, section order and removal of the old decorative hero. CSP evidence currently shows unpublished SPF/DMARC and five unknown DNS lookups; HTTPS 200, six absent selected headers and six deeper-audit observations; one of two scanners online with no approved ranges; CIS not assessed; and a dated Meraki report containing one network and zero assigned devices. Private receipt: /data/codex-overview-validation-20261004.json. These are evidence summaries, not declarations of compliance or complete audit coverage.

Browser visual QA remains pending return of the existing review session. Full-project completion remains open, including the previously recorded client, network coverage and operational validation gaps.

## October 4, 2026 — Release 062 and repeat-audit comparison

Production commit **3eed1aafd3bbfe5cd6853091e6584b7d7c1707fa** is active and healthy. Release archive: 58 files, SHA-256 **01368371378dd8adaaf37f166e79eeadfc15007ee19d575cfd7e443bc77b4bed**. Verified off-host backup: daedalus-data-20261004T043650Z.tar.gz. All **429 tests and 90 subtests** passed locally. Python CI 37177490712 and real managed Linux scanner/recovery CI 37177490710 both passed. The preceding grouped-review source passed managed Linux CI 37177228216.

Actual Nikto run **46** completed_with_warnings after 601.8 seconds, with six observation identities matching run 43, zero new observations, and zero recorded removals. Saved comparison_scope is new_observations_only and coverage_complete remains false. Exactly one dated warning notice **8** exists. The engine stopped and request session **27504 is terminal**; do not re-poll it as a live job. No observation disappeared between these two real audits; partial-report absence cases are covered by fixtures, not this real comparison. Receipt: /data/codex-nikto-comparison-receipt-20261004.json.

Website assessment now surfaces the latest completed audit's observations, grouped into policy review, application context and infrastructure information, while showing the latest running/failed attempt separately. Existing saved evidence is not rewritten. Future messages omit raw uncommon-header contents and changed-banner values. Production authenticated page/current script checks passed; browser visual validation still needs returned control of the existing review session under ego-browser rules.

Fresh host inspection: this Mac is macOS **27.0.1**, so it cannot prove macOS 26 execution. Production CSP has scanner 2 online and scanner 1 offline; both have empty approved CIDRs. Requested exact private subnet/VLAN ranges and deployment locations for production multi-subnet validation. The full goal remains active with these and previous operational/product gaps; these questions do not block independent backend work.


## October 4, 2026 — Release 061 and actual CSP audit evidence

Production application commit `ce7374760dbacd337590da16ffd90d2fa54daf07` is active and healthy. The 58-file release archive SHA-256 is `281ae2170695a1a8d8cae039370d891e9c394d426ed05eda02c4cb4894661412`. Deployment backed up current data off-host (`daedalus-data-20261004T042205Z.tar.gz`) and passed internal/public readiness checks. The source suite passed **427 tests and 90 subtests**. Python CI `37176679762` and real managed Linux scanner/recovery CI `37176679713` passed.

A real ten-minute Nikto audit of the authorized CSP website completed as run **43**, under the named CSP-only Codex operator. It saved six observations, 23 scoped HTTPS tunnels, zero rejected proxy connections, no collection error, and an explicit incomplete-coverage warning. These observations are not six confirmed vulnerabilities; test exhaustion is unproven. History retains the actor and timestamps, with dated warning notice **7**. DNS/email run **44** saved 14 differences and five unknown lookups; website run **45** saved two page-content differences. Each has exactly one dated source-run notice.

Actual PDF job **28** reached 100%, downloaded successfully (17,419 bytes), and all seven pages passed visual review. It includes DNS/email, HTTPS, vendors, fixed-path and Nikto evidence. Lookup-state differences are labeled recorded differences, and PDFs captured while an audit is running now show its start time and pending-results explanation. The generated report does not initiate another scan. Browser visual review of the dashboard remains pending; PDF review does not prove browser layout quality.

The full project goal remains active. Real macOS 26 checks and trusted client distribution, multi-VLAN production coverage, broader authorized Meraki inventory, independent backup replication, and production recovery evidence remain open. Older checkpoints below retain their historical release and readiness claims.


## October 4, 2026 deployment checkpoint

Release 058 adds per-user access keys for API authentication and dashboard sign-in. Keys are hashed, expire within 90 days, are revocable, and are bound to one workspace with live membership/role checks. A named Codex operator was explicitly provisioned only for CSP with a 30-day key; production bearer access, token login, secret-free key listing, and rejected workspace switching were validated. The source suite passed 423 tests and 90 subtests. Incus deployment and public readiness checks passed. Browser visual review remains pending.

Release 057 added the pinned Nikto runtime and bounded HTTPS website audits excluding denial-of-service checks, with saved history and PDF evidence. Real CSP execution remains pending; engine output cannot prove test exhaustion, so coverage stays explicitly incomplete. Managed Linux scanner and isolated portal recovery CI passed (`37174836552`).


**Daedalus** is a multi-organization security operations portal being developed for Cyber Security Pilot (CSP). Its public project overview is published at [`site/daedalus.html`](site/daedalus.html).

## Purpose

The project combines CSP's public-facing marketing site with the source for a separate authenticated application. The static marketing site is suitable for GitHub Pages. Authentication, customer data, scheduled or active checks, APIs, and scanner communication run in the Daedalus application service and are not hosted by GitHub Pages.

## Product areas

- **Organization access:** Google OpenID Connect sign-in, organization-scoped membership and roles, owner/admin approval for shared access, audited admin succession with a last-admin safeguard, and DNS TXT ownership verification with a probation period.
- **Workspace change notices:** temporary probation override grants and revocations produce durable inbox notices and live dashboard updates. Shared members see who changed access and when; free-text override reasons stay in the admin-only audit log.
- **Domain health:** passive DNS and email policy checks, website availability and configuration checks, historical observations, change summaries, and notifications.
- **Authorized website audits:** bounded active checks for approved domains, with time-limited administrator authorization and audit records.
- **NmapUI fleet:** one or more local scanner installations can report over an authenticated outbound connection. The portal records check-in state, scanner events, scan history, and comparisons, and issues scan commands only inside each node’s admin-approved private CIDR ranges. Narrowing a scanner's approved scope cancels queued out-of-scope work and requests best-effort cancellation of delivered work when no in-scope scan is active; the dashboard waits for a terminal scanner result before treating a scan as stopped. Command history is admin-only. Managed Linux installations support restarting the verified NmapUI user unit and local removal/recovery of the two services while preserving enrollment and evidence.
- **Meraki:** workspace-scoped inventory and audit reports using credentials supplied by an authorized administrator, with saved dashboard detail, control evidence, findings, and coverage gaps.
- **CIS endpoint baselines:** profile selection, macOS endpoint results, score and history, and generated reports. macOS 26 profile alignment is an active maintenance area.
- **Reports:** queued PDF generation with status and download history, alongside retained source evidence where supported.

## Architecture

- The **marketing frontend** is static HTML in `site/` and is published with GitHub Actions Pages.
- The **Daedalus application** is Python/FastAPI with server-rendered dashboard pages, a SQLite-backed data layer, workspace-aware API routes, and background report/check jobs.
- **Scanners** run on customer-controlled machines and initiate outbound connections to Daedalus; the portal does not require opening an inbound port on each scanner.
- **Runtime state and secrets** belong on the application host and its persistent storage, never in the Pages artifact or source repository.

## Current scope and open work

The repository contains implementation for the product areas above and has an existing pilot deployment. It remains pilot software: production readiness still depends on operational testing, an independent backup copy and live recovery rehearsal, additional-user onboarding, multi-subnet scanner validation, and review of the maintained CIS profiles. The Daedalus server downgrades FileVault `pass` results to manual for macOS 26 v1.1.0 until volume-aware client evidence exists, and rejects endpoint reports whose OS major version does not match the selected benchmark. A real Tahoe endpoint run remains outstanding. GitHub Pages publishes the CSP marketing site and Daedalus overview; the authenticated service and customer data remain on the Incus application host.

The Pages workflow intentionally publishes only `site/`. Private deployment runbooks, local validation receipts, databases, customer-specific packages, reports, and credentials are excluded from the Pages artifact. The NmapUI runtime source archive is tracked in the repository and includes a manifest identifying the source paths packaged from a working tree with local changes.

## Validation snapshot

As of October 3, 2026, the Daedalus source suite passes **401 tests and 79 subtests** locally. [Python CI run 37173415923](https://github.com/techmore/tm-daedalus/actions/runs/37173415923) passed on Python 3.11/3.12, and [Linux lifecycle CI run 37172870664](https://github.com/techmore/tm-daedalus/actions/runs/37172870664) passed against a real systemd user manager. The lifecycle check uses inert processes and synthetic enrollment/evidence; it proves service removal and exact restoration, without claiming a Linux NmapUI engine or portal workflow.

Production Release 056 runs commit `60e6c8cded1f6cf40fe0a75b5ad5623e10075ded`; its 53-file archive SHA-256 is `928cd42641c4422f5e4aa721a766cf719ba0430fbb0f60b33029778579d2b3ac`. Internal and public readiness checks passed after activation, and the deployment created a verified off-host backup. See [`INTEGRATION-READINESS.md`](INTEGRATION-READINESS.md) for current deployment and validation details.

The local CSP demo audit completed DNS/email, HTTPS, and five fixed-path website checks and generated a visually reviewed six-page PDF. A separate local loopback scanner run uploaded 18 complete events and produced a visually reviewed two-page PDF. The adjacent NmapUI suite passed 660 tests with 28 skipped; its packaged runtime matched the generated bundle, including source-worktree provenance. These earlier audit results were not rerun as part of the Linux lifecycle release.

A disposable Ubuntu 24.04 managed scanner completed the real fresh installer and enrollment against an isolated portal. With only `127.0.0.1/32` approved, it uploaded a completed 15-event real Nmap run with realtime broadcasts and a visually reviewed two-page PDF. The portal restart produced a different NmapUI PID and recovered readiness plus a fresh heartbeat. Generated credentials/data and the disposable instance were removed. The final source also passed [managed Linux CI run 37173085078](https://github.com/techmore/tm-daedalus/actions/runs/37173085078), including the portal restart and cleanup. CI found and drove fixes for inherited spool and user-bus environment settings. This does not establish production Linux enrollment or broader subnet coverage.

The consolidated [CIS client](clients/csp-cis-audit/) retains its 58-test macOS evidence and a disposable profile-fetch/report check-in. Its demo archive passed integrity checks but was rejected by Gatekeeper; a trusted Developer ID signature, notarization, and an actual macOS 26 audit remain outstanding. The current local Mac runs macOS 27.0.1 and has no Developer ID Application identity.

GitHub Pages publishes the CSP marketing site and Daedalus overview at the verified custom domain. Production remains an owner-operated pilot; additional-user onboarding and admin succession, a macOS 26 endpoint audit, multi-VLAN scanners, production Linux enrollment, independent backup replication, and live-data restoration remain open.

These checks do not replace a real macOS 26 endpoint audit, the FileVault connected-volume coverage noted above, Developer ID signing/notarization, additional-user onboarding, restoring over live `/data`, independent backup replication, or multi-VLAN scanner validation. Do not ask end users to bypass Gatekeeper for the ad hoc demo build. The consolidated client's [GitHub Actions run 37165166088](https://github.com/techmore/tm-daedalus/actions/runs/37165166088) passed the 58-test suite and credential-free demo-package build. A fresh off-host backup and temporary staging restore passed; the local Mac runs macOS 27, so the Tahoe-only profile is not run on it.

## Recent interaction and distribution work

The dashboard uses in-page confirmation panels for managed scanner restarts, scanner access revocation, membership role changes, and member removal. Routine dashboard refreshes preserve a pending confirmation; confirming a change still uses the workspace authorization and audit paths. The local browser check opened a scanner revocation panel, allowed a scheduled refresh, and cancelled without changing scanner access. A notarized distribution script requires a Developer ID Application identity, submits the archive through a configured `notarytool` profile, staples and verifies the app, and refuses to deliver unless Gatekeeper accepts it. External client distribution remains pending.

The upgrade kit reader hashes and extracts the same bounded byte snapshot, with file-replacement, FIFO, and size-limit fixtures.

## Release 056 update

Production now runs commit `60e6c8cded1f6cf40fe0a75b5ad5623e10075ded`, archive SHA-256 `928cd42641c4422f5e4aa721a766cf719ba0430fbb0f60b33029778579d2b3ac` (53 files). Internal and public health checks passed, and the deployed service is active. The local suite passed **401 tests and 79 subtests**; [Python CI](https://github.com/techmore/tm-daedalus/actions/runs/37173415923) also passed.

Linux in-place upgrades are implemented. [Managed Linux CI](https://github.com/techmore/tm-daedalus/actions/runs/37173085078) exercised the shipped installer, real loopback scan, portal restart, and local upgrade under systemd. It confirmed retained enrollment/settings, unchanged saved scan events, a fresh heartbeat, a repeated-upgrade no-op, and cleanup. Twelve Linux fixtures cover rollback, interrupted recovery, partial writes, locks, and tamper refusal. Production Linux enrollment and multi-VLAN coverage remain outstanding.

Release 055 puts local and portal-issued Linux restarts under the shared lifecycle lock. Both refuse an interrupted upgrade; local restart also checks the loaded unit path/drop-ins and active process state. Full managed CI confirmed the shipped local restart changed the PID, recovered readiness and a fresh heartbeat, and retained enrollment/settings. No installed scanner was upgraded by deploying the portal release.

## Release 056 backup integrity

The backup manifest hashes the exact bounded bytes consumed by the tar writer through one no-follow regular-file descriptor. Regression checks cover replacement paths, file growth, truncation, symlinks and FIFOs. Source and Python 3.11/3.12 CI passed 401 tests and 79 subtests.

After deployment, a new production backup was copied off-host and restored into a temporary private directory. SQLite integrity passed and all 27 manifest files matched their sizes and hashes, including 26 PDFs. This snapshot had zero scanner artifacts; artifact restoration remains covered by fixtures. The temporary restore was removed. Replacing live data and independent backup replication remain open.

## Running portal recovery rehearsal

[Managed Linux CI run 37173669066](https://github.com/techmore/tm-daedalus/actions/runs/37173669066) backed up its running isolated portal, made a visible post-backup state change, stopped the owned portal, activated the restored data directory and started a new process. The earlier state was restored; saved scan events and PDF bytes were unchanged, readiness recovered, and the scanner authenticated a fresh heartbeat. Cleanup completed. The scan used only an ephemeral loopback listener. No scanner artifact download existed in this run, so artifact recovery remains covered by fixtures. Production data was not replaced; production remains on Release 056. The current source suite and Python CI run 37173669119 passed 401 tests and 79 subtests.

Legacy source review also found an optional Nikto execution path in the original website audit script. The current five-path exposure check does not replace that broader audit; integrating its reporting and authorization flow remains product work.
