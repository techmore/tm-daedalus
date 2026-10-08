# Integration readiness

## October 8, 2026 — macOS scanner lifecycle coordination

The macOS helper now holds a private, owned, nonblocking lifecycle lock throughout upgrade validation, preparation, admission claim, cutover, readiness and rollback. Local restart/uninstall/restore and the updated bridge's remote restart use the same lock path. Overlapping actions defer before service mutations. Status remains read-only. The persistent inode is retained after release; symbolic links, FIFOs, hard links, unexpected ownership/permissions and directories writable by other users are refused. Missing/unsafe remote installation state yields a bounded command failure.

Tests exercise both directions of helper/bridge exclusion, a separate-process contender, exception release, readiness exclusion and unsafe paths. The final full suite passed 809 tests, one skip and 293 subtests; the engine archive remains SHA-256 48ab8f8166dfc17e107d0a37309c13b2441a0c3bc187be0a15ca175a20821d3e. This checkpoint is source validation pending deployment. This coordinates updated participants; an older installed bridge/helper does not acquire the new lock. The installed Mac engine and bridge have not been migrated in this checkpoint. Ordinary upgrades still require the engine admission API; no legacy bypass or report-template change was introduced. The prior managed Linux workflow [37720287895](https://github.com/techmore/tm-daedalus/actions/runs/37720287895), source 9068299, completed successfully in all three scenarios.


## October 8, 2026 — live certificate-history failure preservation

Source `9068299` is active on SER8 Incus: verified 79-file archive `4ce70f2f5469ed688957889dbd0ce1d7aa47ff89a9ca415080562a8339b86994`, pre-deploy off-host backup `daedalus-data-20261008T025632Z.tar.gz`, internal/public readiness passed. A normal authenticated CSP DNS audit completed as run 74 at 02:57:45Z, completed_with_warnings, zero recorded changes. Certificate history remained unavailable/timeout, with no entries or newly-observed-certificate claim. The saved completion audit records manual source, duration and repeat-warning suppression. Read-only database validation confirmed zero inbox notices for this run. Private receipts: /data/codex-dns-ct-independent-live-20261008.json and /data/codex-dns-ct-history-receipt-20261008.json.

[Backend CI 37720287963](https://github.com/techmore/tm-daedalus/actions/runs/37720287963) passed at the active source. Its Linux workflow 37720287895 remained in progress at this checkpoint; the unchanged engine/upgrade source previously passed all scenarios at d199aae. Successful public certificate-history collection remains an external evidence gap. The deployment and outage checks do not establish that crt.sh is unavailable to every client or that issuance history is empty. PDF assets and installed scanner software were unchanged.

## October 8, 2026 — independent certificate-history query coverage

Certificate-history collection now attempts root-domain and subdomain queries independently. A failed root query can retain valid subdomain observations as partial evidence, mirroring the existing root-only partial path. Failed query scope and bounded HTTP/error categories are recorded and displayed; partial observations still cannot produce newly-observed-certificate alerts. A root access/rate-limit refusal (401/403/429) stops additional requests. Both failed queries remain unavailable, with no empty issuance claim. Fixed provider, pinned public addresses, verified HTTPS, response bounds and redirect refusal are retained. No certificate/log proof validation is inferred.

Direct Mac and production probes returned HTTP 502 for the root query; a separate bounded subdomain probe also returned 502. The corrected local collector later returned unavailable/timeout with no entries. These are real provider/transport failures, not successful history collection evidence. Private receipts: validation/ct-live-20261008/ and /data/codex-ct-live-20261008.json. Focused collector/dashboard tests passed 55 tests and five subtests. After updating the expected asset cache version, the full suite passed 799 tests, one skipped and 290 subtests. JavaScript syntax and diff checks passed. This change has not yet been activated in production at this checkpoint; successful public certificate-history collection remains open.

## October 8, 2026 — isolated native activity visual acceptance

A separate validation application compiled the exact ScannerStatus.swift source, changing only its private configuration and observation paths. A loopback fixture supplied maintenance, simulated scan progress (127.0.0.1 / 42%) and unavailable responses. Native accessibility and screenshots confirmed the window labels for each state, with no clipped header text at the reviewed window width. This proves window presentation, not real scan execution, a live engine maintenance claim or the menu-bar badge's rendered appearance. No production enrollment/token was used. Active source d199aae also completed all three installed Linux scenarios in [workflow 37718904975](https://github.com/techmore/tm-daedalus/actions/runs/37718904975). The fixture app and server were stopped; the real scanner window was restored and still reported running/connected/idle with retained history. Private provenance and observations: validation/native-status-ui-20261008/.

PUBLIC-PROJECT-REPORT.md now replaces its stale October 6 completion summary with the active production/source evidence and a full-scope requirements matrix. Historical dated records are retained. Legacy migration, browser/mobile acceptance, exact scanner PDF approval, managed CIS distribution and operational acceptance remain open.

## October 8, 2026 — active portal release and installed Linux evidence

Production now runs source `d199aae`, verified 79-file release SHA-256 `08372a8b725e078ceab6284f9eb7273bf82a99a4f919b2f028e847073f5b39c9`. The pre-deploy off-host backup is `daedalus-data-20261008T023918Z.tar.gz`. Incus activation and internal/public readiness checks passed; a separate public check returned HTTP 200 / ready at 02:41:38Z. A normal authenticated CSP operator request downloaded the live scanner kit (HTTP 200, 1,000,130 bytes). Its engine ZIP, Swift status source and both upgrade helpers match active production bytes. BFS reports 40 and 41 remain completed with their original PDF sizes. No installed scanner engine or bridge was upgraded.

[Linux workflow 37718157847](https://github.com/techmore/tm-daedalus/actions/runs/37718157847), source `4e1a2aa`, completed successfully for all three scenarios: managed lifecycle, interrupted bridge and repeated scan comparison. The downloaded repeat receipt confirms distinct completed run IDs, two accepted/succeeded acknowledgement pairs, comparable explicit loopback coverage and zero host/port changes. Lifecycle receipt confirms maintenance refusal without service change, successful owner release and upgrade, retained enrollment/settings/history, repeated-kit no-op, recovery with identical saved PDF bytes and cleanup. These are disposable Linux loopback installations, not physical-host soak evidence.

For active source `d199aae`, [backend CI 37718905043](https://github.com/techmore/tm-daedalus/actions/runs/37718905043) and [native scanner status CI 37718905007](https://github.com/techmore/tm-daedalus/actions/runs/37718905007) passed. The fresh Linux workflow 37718904975 was still running at this observation. Local suite remains 795 passed, one skipped and 287 subtests. Legacy engine migration, live native maintenance display, scanner PDF baseline acceptance, broader dashboard/mobile acceptance and trusted CIS distribution remain open.

## October 8, 2026 — native scanner maintenance and activity presentation

The Mac status indicator now presents maintenance explicitly in the menu badge, window status and accessibility description, with an explanation that scan/report starts are paused. Unavailable engines show Offline; malformed or contradictory activity shows unknown rather than idle. Legacy coherent idle responses remain supported. Swift fixtures compile the actual application source and cover maintenance, resume, scan progress, report work, offline and unknown states. A dedicated macOS workflow runs these fixtures and compiles the complete application without changing any service installation.

The updated indicator was installed on this Mac, with its prior application retained privately for recovery. A native accessibility/screenshot review confirmed NmapUI running, Daedalus bridge connected, five saved runs and hosted PDF links. The private timestamped observation confirms the installed service running, page loaded and maintenance false. The installed engine remains the previous release; live paused-state acceptance and the legacy engine migration remain open. No scan was started and neither scanner engine nor bridge was upgraded for this change. Full local suite: 795 passed, one skipped and 287 subtests. The dedicated hosted native workflow has not yet run.

Source `4e1a2aa` passed the installed Linux lifecycle job in [workflow 37718157847](https://github.com/techmore/tm-daedalus/actions/runs/37718157847). Its downloaded sanitized receipt confirms the real engine gate refused the shipped upgrade without a PID/configuration change, owner release allowed upgrade, the repeated kit was a no-op, saved runs and recovered PDF bytes were unchanged, and cleanup completed. The interrupted-bridge job also passed. The workflow's repeat-comparison job was still running at this observation, so the whole workflow is not yet claimed successful. [Backend CI 37718157815](https://github.com/techmore/tm-daedalus/actions/runs/37718157815) completed successfully.

## October 8, 2026 — Linux upgrade and interrupted recovery admission

Linux upgrades now claim the packaged engine's atomic admission gate before stopping either service. Busy, unsupported or invalid claims defer without service changes or a pending transaction. The owner token is saved in the private pending record and excluded from public output. Recovery reasserts that owner on a running engine; after an engine restart, a fresh idle claim is persisted before any stop. A confirmed stopped engine needs no HTTP; ambiguous state defers. Retries preserve exact descriptor backups while permitting a new token. Local readiness and maintenance transport refuse proxies and redirects. An old engine without the API still needs a separately validated initial migration; no installed Mac or production scanner was changed for this batch.

The controlled bundle update changed only registry, routes and manifest; all PDF assets and other runtime files are byte-identical to the prior bundle. Candidate ZIP SHA-256: 48ab8f8166dfc17e107d0a37309c13b2441a0c3bc187be0a15ca175a20821d3e. The actual extracted candidate passed four registry/Flask authentication tests, including owner reassertion, foreign-owner rejection and invalid-token rejection. Final focused upgrade/package tests: 55 passed and 24 subtests. Full backend suite: 794 passed, one skipped and 287 subtests. The installed Linux CI script now holds a real engine gate and checks that the shipped upgrade command refuses without changing PID, descriptors, enrollment or settings, then releases the owner and exercises the upgrade. This new installed-service check has not yet completed. These fixtures do not establish physical-host soak, legacy migration or complete scanner acceptance.

## October 8, 2026 — atomic Mac scanner upgrade admission

The packaged NmapUI registry now claims maintenance under the same lock used to start scans and reports, and only when tracked work and child processes are idle. A local authenticated maintenance endpoint issues an opaque owner token and refuses foreign peers/origins; public status exposes only the active flag. Mac upgrades require this claim immediately before stopping services. Busy, unsupported or invalid claims defer cutover without service changes. Tokens do not expire; helper crashes/lost claim responses require owner release or an explicit idle-engine restart. Replacement engines cannot release another owner’s token. Linux coordination and initial migration of engines without this API remain open; no installed scanner upgrade was performed for this change.

The controlled bundle update changed only jobs.py, routes.py and its manifest. Every other runtime file, including report templates, styles and fonts, is byte-identical to baseline b4a6ad04. Candidate ZIP SHA-256: 31bf860b450c4f3208ab9e05c00e7e26dfde87093a0ef84b62dd79cd53e6d15d. The actual extracted candidate passed four registry/Flask authentication tests. Packaged concurrency tests exercise 100 simultaneous admission races. Upgrade fixtures cover claim refusal, ordering, rollback, bounded responses and redirect refusal. Full backend suite: 786 passed, one skipped and 287 subtests; focused final suite: 34 passed and 24 subtests. This is source/package fixture evidence, not installed-host acceptance.

Source caba121 also passed both hosted workflows: [backend 37716932433](https://github.com/techmore/tm-daedalus/actions/runs/37716932433) and [CIS client 37716932287](https://github.com/techmore/tm-daedalus/actions/runs/37716932287). Managed client distribution and rendered-menu acceptance remain open.

## October 7, 2026 — endpoint assessment activity and profile selection

The native menu now exposes assessment activity and explicit skipped-run reasons for unavailable/incompatible profiles and empty check sets. It labels the configured workspace and profile selection, disables duplicate run/config-import actions during collection, and clears displayed previous results after config import without removing stored evidence. Terminal activity is queued under the admission lock so an older run cannot overwrite a newer checking state. A configured published profile, including newest-compatible selection, no longer falls back to the bundled legacy checklist when its fetch fails. Native final xcresult confirms 120 passed, zero failed and one skipped real-Tahoe test on the local macOS 27 host. These are source/native fixture checks; installed clients and rendered-menu acceptance remain separate gates.

Prior source `876caed` passed [client CI 37716494111](https://github.com/techmore/tm-daedalus/actions/runs/37716494111), including native tests, real macOS 26 profile collection, script syntax and credential-free package build. The downloaded 119-check receipt passed local consistency verification. The home-folder outcome was fail on Version 26.6.2 (Build 25G83); this does not establish full benchmark or managed endpoint acceptance.

## October 7, 2026 — home-folder permissions and real Tahoe receipt

Added the pinned read-only home-folder rule using fixed find/stat arguments and only directory type/mode output. Complete direct-directory metadata passes only modes 0700/0711; explicit mismatches fail, while empty, failed, timed-out, oversized or malformed evidence remains manual. The source Shared/Guest-name exclusions are retained. No directory names or contents are uploaded and no permissions change. Native final xcresult: 117 passed, zero failed and one locally skipped real-Tahoe test; full backend suite: 777 passed, one skipped and 276 subtests. A read-only metadata transport check on this macOS 27 host returned one eligible row with no stderr. Mappings now total 102: 88/100 Level 1 and 100/119 Level 2. Published profile versions remain unchanged.

Separately, prior source `c34e936` passed native tests, real macOS 26 assessment, release-script syntax and credential-free local package build in [client CI 37715973973](https://github.com/techmore/tm-daedalus/actions/runs/37715973973). Its downloaded receipt identifies macOS 26.6.2 (25G83), all 119 Level 2 checks, 10 pass/20 fail/89 manual/zero errors. All seven audit-flag checks remained manual; the receipt does not explain missing evidence or assert conformance. Local receipt verification passed. This evidence does not include the subsequent home-folder implementation, a managed endpoint install or production upload. Trusted distribution and managed endpoint acceptance remain open.

## October 7, 2026 — Level 2 audit flag checkers

Added seven bounded read-only Tahoe audit flag checkers using the pinned NIST mSCP rules and existing no-follow audit_control reader. Exact required selections pass; explicit absent selections fail. Missing, malformed, unknown, conflicting and duplicate evidence remains manual, as do broader selections needing review against failure-only checks. Raw configuration stays local; no service or settings are changed. Mappings total 101 distinct rules: 87/100 Level 1 and 99/119 Level 2. Published profile versions and check sets are unchanged. Native xcresult confirms 116 passed, zero failed and one real-Tahoe test skipped locally; focused backend tests passed 60 tests and 18 subtests. No installed client upgrade or new production assessment is claimed for this batch. See [alignment and primary sources](CIS-MACOS26-ALIGNMENT.md).

## October 7, 2026 — native endpoint assessment context

The CIS menu now leads with assessed/unassessed counts and explains the all-check pass-rate denominator. Empty category percentages say Not assessed; entirely unassessed runs use a neutral icon. Shared presentation helpers reject inconsistent counts instead of showing a percentage. Final native xcresult: 115 passed, zero failed, one real-Tahoe platform test skipped on macOS 27.0.1. This changes the client UI; deployed endpoint binaries require an explicit update. Developer ID signing remains unavailable (only an Apple Development identity exists), so trusted distribution and actual macOS 26 validation remain open.

## October 7, 2026 — Meraki inventory identity validation

Source `8db114d` rejects malformed, missing and duplicate network/device identities before a completed audit and purchase plan can be saved. This prevents silently omitted networks and inflated replacement quantities. Ten malformed/duplicate fixture cases are covered; a fresh read-only BFS collection passed with two networks and 27 unique devices. Full local suite: 777 tests passed, one skipped and 276 subtests. Incus activated the verified 79-file release `24895e1fde5e956f9ef6133b19efe5d8f5aea9adc1c4b6ae6f5c1deb8046dae3`, with pre-deploy off-host backup and internal/public readiness checks passing. Existing completed reports and scanner PDF assets were retained.

## October 7, 2026 — latest production recovery validation

The post-BFS backup was restored into a fresh private directory. All 41 completed PDFs matched recorded sizes and PDF headers. Both saved Meraki credentials decrypted using the existing sealed recovery configuration; BFS purchase plans and temporary-key revocation were retained. The restored production-configured application started and stopped through an isolated TestClient lifespan, returned ready, denied unauthenticated report access and kept collectors disabled. No listening socket or production data mutation was used. Separate secret custody, public failover and restored Google login remain open. See [Incus recovery](docs/INCUS-DEPLOYMENT.md).

## October 7, 2026 — production BFS Meraki and purchase planning

SER8 Incus deployed source `7c26179` with public/internal readiness checks passing. BFS reports **40 and 41** completed against Buckingham Friends School (Cisco organization 296035), collecting 27 devices and 48 controls, with zero unavailable controls and three review observations. The repeat retained report 40 as its comparison baseline and found no control, coverage or inventory changes. Both reports retain dated UniFi purchase scenarios ($11,356 and $12,940), quantities and official vendor links in the dashboard, saved JSON and PDF. This is a candidate equipment budget; tax, shipping, accessories and implementation are excluded.

Normal authenticated API validation confirmed saved plans and report downloads, four request/completion audit records, and cross-workspace isolation. The temporary BFS validation key was revoked and then returned 401. An off-host verified backup was taken after the reports and revocation. The full local suite passed 774 tests, one skipped and 260 subtests. Details: [Meraki purchase planning](docs/MERAKI-PURCHASE-PLANNING.md). Full project readiness, exact standardized scanner PDF acceptance and wider visual review remain open.

## October 4, 2026 — endpoint PDF coverage summary and visual review

All **12 pages** of actual endpoint PDF 35 were rendered and visually inspected. Its tables were readable, but the Category heading broke across lines and category percentages obscured that browser checks were unassessed. Future PDFs use an Area header, an Assessment summary with explicit assessed coverage, and pass/fail/manual/error counts per area. The pass-rate denominator explains both manual and error results; missing summary metadata is labeled Not reported instead of inventing zeroes.

The revised renderer was applied to PDF 35’s exact frozen snapshot. All **12 revised pages** were rendered and visually reviewed; no clipping or overlap was found. Its first page identifies **74/154 checks assessed**, Chrome 33 manual and Safari 23 manual, alongside the saved overall counts. Original PDF 35 and endpoint report 3 remain unchanged. The full local suite passed **501 tests and 98 subtests**, including unassessed category counts and missing summary metadata. This is PDF review, not browser dashboard visual approval or macOS 26 conformance.


## October 4, 2026 — report worker claims and failure delivery

Report generation now conditionally claims only queued jobs. Duplicate worker invocations cannot render the same job, and invoking a completed or failed job does not rewrite its artifact or saved snapshot. Requesting another PDF creates a new job through the existing workflow.

Renderer failures create one persistent workspace notice linked to Reports, without exposing raw exception details. The failed state and notice are committed before the live event refreshes Reports and the inbox. Restart recovery marks unfinished queued/running jobs failed, audits the interruption and creates one notice per job; repeated recovery is a no-op. Completed jobs are preserved. No additional failure toast was introduced.

The full local suite passed **499 tests and 98 subtests**. Fixtures validate two concurrent workers rendering once, duplicate invocation, sanitized failure notice, publication after commit, restart recovery and preservation of completed jobs. The concurrent-render fixture uses inert bytes to validate worker ownership; it is not PDF layout evidence. No renderer failure was induced in production. Production runs source **50a6ef9** with verified release archive SHA-256 `19ec0caf1ab3419160496eb5a880789a96bec2aeac6a00ea20f8a06d097f6ca1`; internal/public health checks passed. Real endpoint PDF job **35** for saved report 3 was observed queued at 0%, running at 40%, then completed at 100%. Its download returned 31,841 bytes with a PDF header (SHA-256 `92d3d66cefe12285183ba7381ed0254cc27ae506e359e52c07b95e4a12f64ca0`). This validates live generation/progress/download, not the new document’s visual layout. Private receipt: `/data/codex-pdf-worker-live-validation-20261004.json`.


## October 4, 2026 — durable collector failure notices

Collector failures now create a workspace inbox notice alongside their saved run and audit event. The notice explicitly says that the failed run provides no fresh assessment and points users to the saved error and earlier evidence. Raw exception details are excluded. Consecutive failures with the same sanitized recorded error category suppress repeat inbox notices; a different category or failure after a successful run notifies again. Every attempt remains in history and the audit log.

The suppression flag is carried in the workspace WebSocket event. Repeated scheduled failures or warnings do not create another transient toast; explicit manual checks still give feedback. Existing first-baseline success behavior remains quiet. Fixtures cover failure persistence, category changes, recovery/recurrence, publication and manual/scheduled UI behavior. The full local suite passed **496 tests and 98 subtests**. These are isolated failure fixtures; no production failure was induced to validate the feature. Production deployed source af88e8b with verified archive SHA-256 `dbd498980c1fae7e8fe6a0db81d9ce667d3446d2d36afdb1cb3e92c1f56bad8c`; internal/public health checks passed. Actual DNS run **55** completed with existing warnings and **zero changes** at **2026-10-04T08:47:29.134113Z**. It returned the suppression flag and created no new inbox notice. This validates repeat-warning behavior on live data, not an induced failure. Private receipt: `/data/codex-external-notice-repeat-validation-20261004.json`.


## October 4, 2026 — endpoint assessment age and workspace coverage

The CIS status API now reports each endpoint’s latest collection time, report ID and assessment age separately from report receipt and client heartbeat. Collections within 36 hours are current, older collections are stale, absent reports are missing, and future collection timestamps require review. Latest evidence is selected by collection time with report ID as the tie-breaker, so a late upload of old data does not replace a newer assessment. Existing heartbeat and receipt fields remain compatible.

The dashboard displays workspace assessment-age totals and a per-device collection label. Counts include all enrolled devices, including those beyond the existing 250-device visible list limit. Incomplete or inconsistent count metadata remains unknown in the UI. These labels describe evidence age, not compliance. Fixture coverage includes fresh heartbeat with stale evidence, current/future/missing data, late uploads, a 251-device list boundary and malformed summary metadata. The complete local suite passed **493 tests and 98 subtests**. Broader real multi-endpoint deployment and browser visual review remain open.


## October 4, 2026 — concurrent workspace rejoin requests

Existing revoked memberships now return to pending through a conditional database update. Concurrent rejoin requests create one membership request audit and one scoped admin notification, and the pending membership has the user role. If an approval wins the race, its approved status and role remain intact. A changed/deleted membership that cannot be resolved returns HTTP 409 instead of being silently overwritten.

Forced-race fixtures validate both simultaneous rejoin requests and an approval between the initial read and conditional write. These are isolated fixture users, not additional live-human OAuth onboarding evidence. The full local suite passed **488 tests and 98 subtests**. Production subnet validation, trusted CIS distribution, macOS 26 execution, browser visual review and the rest of the original project scope remain open.


## October 4, 2026 — live browser evidence correction

Client source **1d5e7152780a28489f8e6c6bf6b8f9dcc3c53ae1** removes presumed defaults from 23 Chrome and 16 Safari guard branches, plus five Safari AutoFill routines. Missing, unreadable or incorrectly typed preferences remain manual. Explicit observed values still follow the existing checks; this does not establish that every legacy preference mapping matches current browser policy. All **73 local client unit tests** passed, including absent-preference fixtures across 33 Chrome and 23 Safari dispatch paths. The backend suite passed **485 tests and 98 subtests**; [Python CI run 37188941425](https://github.com/techmore/tm-daedalus/actions/runs/37188941425) passed.

A private ad hoc local build actually ran on **macOS 27.0.1**, fetched the existing CSP browser baseline, and uploaded production endpoint report **3**. It contains 154 checks: 24 pass, 50 fail, 75 manual, five errors, and a 15.58% pass rate. All 33 Chrome and 23 Safari checks were manual because local preference evidence was unavailable. The lower rate removes assumed passes; it is not endpoint degradation or a macOS 26 conformance result. Comparing with report 2 produced exactly **56 browser changes**, matching saved result statuses with no macOS status changes. One persistent `cis_report` notification was saved at **2026-10-04T08:26:54.108217Z**, explicitly describing status changes without a compliance conclusion. Earlier reports were retained.

The owned client process terminated and its temporary private config was removed; the persistent device identity was preserved. No launch-at-login enrollment or trusted external distribution was established. Private receipts: local `validation/cis-browser-no-defaults-local-20261004/live-receipt.json` and production `/data/codex-cis-browser-no-defaults-validation-20261004.json`. The portal remains on deployed source ad8cd2a; these are client changes, not a claim that installed endpoints were upgraded.


## October 4, 2026 — topic evidence hierarchy and CIS browser evidence

Production runs source **ad8cd2a03ec1299e3902cd6e7bc1f89bda608940**, with verified 59-file release archive SHA-256 `ceb7d6f33c4eabfbd8f31e504e2257f14694efa370f34bad7cb16ad02c0b3c4e`. The Incus deployment verified an off-host backup and passed internal/public health checks. An authenticated production dashboard request returned HTTP 200; its parsed hierarchy keeps DNS/email and website summary metrics outside collapsed details, groups them under topic evidence headings, and places detailed browser policy evidence in an expandable section. The served JavaScript includes endpoint result grouping: failed checks first, then unassessed checks, then passing checks, each grouped by category. Unknown result statuses remain unassessed. This verifies served structure and fixture renderer behavior, not browser pixels or user experience acceptance. Private receipt: `/data/codex-topic-grouping-validation-20261004.json`.

The local backend suite passed **485 tests and 98 subtests**. [Python CI run 37188596700](https://github.com/techmore/tm-daedalus/actions/runs/37188596700) passed for this source. The CIS client passed **71 local unit tests**, including missing/malformed Safe Browsing and Safari JavaScript evidence staying manual while explicit true/false values retain pass/fail semantics. Shared unavailable-preference handling now keeps those read failures unassessed; older saved reports remain immutable. Other browser routines that assume defaults still require review; this does not establish effective managed policies or real macOS 26 conformance. Trusted distribution, persistent endpoint installation, broader onboarding, production subnet coverage and browser visual review remain outstanding.


## October 4, 2026 — concurrent workspace access request handling

Concurrent first access requests from the same user/domain can collide with the membership uniqueness constraint. The request handler now rolls back the losing insert and returns the already-saved pending/approved status; other changed-access cases return HTTP 409. This preserves the pending user role and avoids a duplicate membership request audit or admin notification.

A forced-race fixture synchronizes two independent HTTP clients at membership insertion. Both responses return pending successfully, exactly one user-role membership and one membership.requested audit entry persist, and the scoped admin notification publishes once. This is concurrency validation with a fixture OAuth profile, not new real-human Google onboarding evidence. Existing domain independence, approval and admin succession requirements remain intact; broader live onboarding validation remains open.


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


Reviewed October 3, 2026 (New York); production currently runs Release 056 from application commit `60e6c8cded1f6cf40fe0a75b5ad5623e10075ded`. This note contains no credential values or organization IDs.

## Current deployment state (October 3, 2026)

The canonical portal is live at `https://daedalus.cybersecuritypilot.org/` in the `daedalus-prod` Incus container. Release 056 runs application commit `60e6c8cded1f6cf40fe0a75b5ad5623e10075ded`; its 53-file archive SHA-256 is `928cd42641c4422f5e4aa721a766cf719ba0430fbb0f60b33029778579d2b3ac`. Internal and public `/healthz` and `/readyz` returned HTTP 200 after activation. The deploy workflow completed its service and release checks. Pre-activation backup `daedalus-data-20261004T031339Z.tar.gz` was copied off-host and verified again locally; SHA-256 `7283519f2d011f4f1bc33243ab49b49ff97b04d63b69b5b8cf3448e6fc850ed0`. The deployed dashboard JS and CSS SHA-256 values matched the pushed source (`337fb1f10719125cd3cccd84abd05bfaa10500f6136ddd395aa1462ad277b8a7` and `6b1133a788872fcb2c96389b2380bdb78cf39dbc4a197732e026320e8db2281d`). A local deployment receipt is retained in the ignored operator-only `validation/` directory. GitHub Pages publishes the CSP marketing site and Daedalus overview from this repository at `https://cybersecuritypilot.org/`; Pages has workflow publishing, the custom domain, and HTTPS enforcement enabled.

Release 056 is active in `daedalus-prod`. In addition to Release 047's administrator succession and scanner-scope cancellation, the dashboard now uses in-page confirmations for managed scanner restarts, scanner access revocation, membership role changes, and member removal. Routine dashboard refreshes leave a pending confirmation in place; confirmed operations keep the existing authorization and audit behavior. The local UI check confirmed Cancel leaves scanner access enabled. Role changes continue to notify affected users and refresh the dashboard; a database-guarded update prevents demoting the last approved admin. Tests confirm non-admins cannot promote, transferred admins lose admin-only API access, and each workspace retains an admin. The source suite passes 401 tests and 79 subtests locally. Current Python CI run `37173415923` and real Linux lifecycle CI run `37172870664` passed. The unchanged CIS client source retains its prior 58-test CI evidence. Independent backup replication and restoring over live `/data` remain open.

The unconfigured `app.cybersecuritypilot.org` and `app.bfs.org` names below are historical alternate-host checks. They do not describe the canonical production portal. Real owner Google sign-in has been verified; additional-user onboarding remains open.

## NmapUI scanner check-in

The CSP Mac scanner is now configured to report to the canonical production portal. Its existing enrollment credential was verified against the production agent record before changing the endpoint. On October 2, 2026, the bridge restarted successfully, the agent heartbeat updated in the production database, NmapUI readiness returned true (`v2026.3.14.00_10`, protocol 3), and event uploads returned HTTP 200. The latest received events include earlier loopback scan results for `127.0.0.1`; they are not evidence of a VLAN scan. Production currently has no queued or running commands and the scanner has no approved network CIDRs, so broader network scanning remains unvalidated and disabled until explicit ranges are approved.

On October 3, 2026, the live local demo round-trip was verified using a separate NMapUI instance and a foreground Daedalus bridge. Its only approved target was `127.0.0.1/32`. The demo portal showed the scanner online with NMapUI ready; scan command 15 finished successfully, and its saved run group contained 18 events with no truncation. Scanner report job 31 reached 100%, downloaded as a valid two-page PDF, and passed visual review. The PDF reports loopback observations only; those open-port results do not establish LAN reachability. The existing production scanner service remained separate and received no scan command. This validates the bridge and NMapUI runtime together, but not the managed installer workflow or a VLAN scan. The local demo config is mode `0600` and stays in ignored runtime data.

Release 045 closed two scanner-management gaps: raw command history now requires admin membership (and is hidden in the dashboard for ordinary members), and managed Linux installs advertise remote NmapUI restart only when their fixed systemd user unit and private ownership record exist. Before executing restart, the bridge checks the recorded digests and permissions for both units and their environment file, then restarts only `daedalus-nmapui.service`. Release 046 now requests best-effort cancellation of delivered scans outside a newly narrowed scope when no in-scope scan is active; it does not claim cancellation succeeded before a terminal scanner result arrives. Local fixtures cover online, offline, mixed-scope, idempotent request, and terminal-result handling. No real Linux scanner restart or production scope-narrowing action has been exercised.

Release 047 adds admin succession for approved workspace members. The UI exposes promote/demote actions, confirms self-transfer, and refreshes affected members after a role change. Role changes are audited. A database-guarded update rejects demotion of the last approved admin, and server authorization was verified after transfer. Production admin succession has not yet been exercised with an additional account.

## Linux scanner removal and recovery

Release 050 fixed fresh-install cleanup after a partially successful systemd start. Each attempted service is stopped on failure; cleanup stop failures are reported, and enrollment/service files are retained. Three installer fixtures cover partial NmapUI start, partial bridge start, and a failed cleanup stop. The fresh Linux workflow is now exercised separately as described below.

Release 049 added `manage-service-linux.sh uninstall|restore`. Removal verifies the original private units/environment and the manager's loaded fragment path, refuses drop-ins, stops/disables the bridge before NmapUI, and retains enrollment, scanner evidence, runtime files, and exact recovery descriptors. Restore reinstates those descriptors and checks that both services are enabled and active. A private lock rejects concurrent uninstall/restore calls. Failures retain the recovery files for retry. This is an explicit local lifecycle command; portal enrollment is not revoked.

Local fixtures cover stopped-state confirmation, partial removal, failed restart, retries, ownership/schema checks, replacement/symlink refusal, and concurrent operations. A disposable Ubuntu 24.04 Incus instance exercised the real systemd 255 manager with inert loopback processes, preserved synthetic enrollment/evidence, restored byte-identical units, refused tampering, and was removed afterward. Its first attempt was blocked by nested user namespaces; `security.nesting=true` on that disposable instance allowed the existing `PrivateTmp` setting to work. The current helper also passed the actual CLI/systemd lifecycle in [CI run 37172870664](https://github.com/techmore/tm-daedalus/actions/runs/37172870664), with cleanup complete. The CI receipt helper SHA-256 `c9d0ef253015cb0e395651e8574fa1047538bc1192ed330a688c6f99f22227a5` matches the deployed helper. The earlier lifecycle checks used inert processes rather than a scanner engine. Broader subnet scans and production Linux enrollment remain open.

## Fresh managed Linux scanner validation

Release 051 fixed Linux preparation to honor the managed data-directory override and adds opt-in full managed validation. A disposable Ubuntu 24.04 Incus user ran the shipped installer against an isolated portal, completed one-time enrollment, and checked in at protocol 3 with owner-only config. The admin API approved only `127.0.0.1/32`. Real guarded Nmap observed one listener port; the portal retained a completed run with 15 events and emitted 16 realtime messages. Its 4,010-byte two-page PDF was downloaded and visually reviewed. A portal-issued restart succeeded, changed the NmapUI PID, and recovered direct readiness plus a fresh portal heartbeat. The validator confirmed removal of generated service descriptors, enrollment, runtime, and temporary logs; the disposable instance was then deleted. This is isolated loopback evidence, not production Linux enrollment or VLAN coverage. The final source also passed the complete [managed Linux CI run 37173085078](https://github.com/techmore/tm-daedalus/actions/runs/37173085078), with 15 events, 16 realtime messages, a successful portal restart, and cleanup. Earlier CI exposed inherited user-manager XDG settings: the bridge first crashed with a spool permission error, then its systemd control could not reach the user bus. Release 052 bound the spool to the installed configuration home and fixes the runtime/bus addresses to that scanner user's `/run/user/<uid>` directory. Full managed CI, lifecycle CI, and Python 3.11/3.12 CI passed after those fixes.

## Upgrade kit integrity

Release 053 reads a kit once through a no-follow file descriptor, checks regular-file type and bounded size, then hashes and parses the same byte snapshot. It refuses FIFOs without waiting for a writer and bounds reads if the file grows after its size check. A replacement-path regression confirms that archive members correspond to the recorded hash. All 13 managed-upgrade fixtures passed; the existing distributed protocol-3 kit also parsed with its original digest. The Release 053 upgrade helper SHA-256 was `95ba6722548b682101ae80b48e083ef5eb52e91ce86b3c72289c388b807171ac`. This fixes the current macOS upgrade reader and prepares shared parsing for Linux; Linux in-place upgrades are now validated in Release 054.

## Probation override inbox notices

Release 045 includes durable workspace inbox notices when an administrator grants or revokes a probation override. Shared members see the actor, expiry or revocation and a link to Members & access; the free-text reason stays in the admin-only audit log. Connected dashboard clients refresh the inbox and administrator audit log live. Tests cover grant/revoke, reason visibility by role, workspace isolation, and post-commit WebSocket notification. Production notices have not yet been exercised with a second account.

## CIS macOS endpoint reporting

A read-only production database check found the CSP workspace has both macOS 26 Tahoe profile revisions (`1.1.0-r2`) published, with **zero CIS devices and zero CIS reports**. The `bfs.org` workspace currently has no CIS profiles, devices, or reports. Production disables the unsigned demo client download endpoint, and a signed/notarized distributable client has not been provisioned.

On October 3, an isolated loopback Daedalus instance accepted a live report from the CSP menu-bar client running on macOS 27. The client fetched the published `csp-macos-browser-baseline` v1.0.0 profile, ran all 154 checks, uploaded the report, and received an acknowledgment. Daedalus stored one online endpoint and marked the report as profile-verified. The first attempt exposed a timestamp-format mismatch: the client emitted a filename-style timestamp that the API correctly rejected with HTTP 422. The adjacent `CSP-CIS_Audit` working copy now formats report timestamps as ISO 8601; its suite passes 58 tests, and the corrected client completed the round trip. The test database, temporary upload key, user-home config, logs, and report files were removed afterward.

This is a cross-version CSP starter-profile workflow check, not a macOS 26 Tahoe audit or a compliance conclusion. The CIS client source, tests, and ISO 8601 timestamp fix are now consolidated under `clients/csp-cis-audit/`; the original adjacent checkout remains untouched with its existing uncommitted changes and no Git remote. Its 58-test suite and credential-free demo-package build also passed in [GitHub Actions run 37165166088](https://github.com/techmore/tm-daedalus/actions/runs/37165166088). I built a fresh demo ZIP in a temporary directory from the consolidated source: its ad hoc app signature and archive integrity verified, but macOS Gatekeeper rejected it because there is no trusted Developer ID signature. The ignored downloadable bundle was not replaced or distributed. A real macOS 26 run, Developer ID signing/notarization, and connected-volume FileVault evidence remain open; do not ask users to override Gatekeeper.

## Cisco Meraki

| Source | Classification | Read-only verification |
| --- | --- | --- |
| `../Meraki-2026_planning/.env` | Nonplaceholder credential; reusable for the verified endpoint | `GET /api/v1/organizations` returned HTTP 200; three accessible organizations |
| `../dev/swift/Meraki-march/.env` | Nonplaceholder credential; reusable for the verified endpoint | The same GET returned HTTP 200; two accessible organizations |
| `../meraki/master_meraki_audit.py` and other legacy Meraki scripts | Embedded nonplaceholder candidates | Not independently verified during this review |
| `data/daedalus.db` | One existing encrypted Meraki credential | Existing workspace grant produced completed reports 12 and 19; the credential and grant were not changed |

The current Meraki dashboard exposes saved networks, device metadata, findings, warnings, control status, bounded evidence previews, aggregate client usage, and topology summaries through a no-store workspace-scoped details API. Topology summaries omit device serials, individual nodes, and links. The local portal loaded three organizations using the existing key. Only the already-approved CSP organization was selected; the two other organizations remained unauthorized. Fresh report 26 completed at 100% and compared with report 19 at zero control, coverage, inventory, or inventory-coverage changes. It covered one network and zero assigned devices; two control endpoints were unavailable and device-rich reporting remains unverified. The PDF marks an enabled wireless SSID reported as `open` for owner review. The credential and grant were unchanged, and no credentials were copied into source or config files. Receipt: `validation/csp-full-audit-20260930.json`.

## Google OAuth

- Authlib login and callback handling are implemented; the callback requires the literal boolean `email_verified=True`. Owner Google sign-in was verified for the production portal and the owner account has approved admin access to the CSP workspace. Additional-user onboarding and consent remain to be tested.
- OAuth secrets are held in production configuration and are not committed to source or release bundles. No legacy OAuth identifier was copied into Daedalus.
- The local demo previously responded on `127.0.0.1:8000` (`/healthz` HTTP 200); the October 2 local daemon state was not rechecked in this release validation. The managed NmapUI readiness endpoint and local browser UI were not rechecked in this turn.
- Production Google sign-in uses the canonical HTTPS callback `https://daedalus.cybersecuritypilot.org/oauth2/callback`. The alternate `app.cybersecuritypilot.org` and `app.bfs.org` names are not required for the current portal.

## Incus production deployment

- Production runs as the `daedalus-prod` Incus instance on the CSP host. The service is managed with systemd inside the instance; Docker is not part of this deployment.
- Release 056 public and internal `/healthz` and `/readyz` endpoints returned HTTP 200 on October 3, 2026. The active release archive SHA-256 is `928cd42641c4422f5e4aa721a766cf719ba0430fbb0f60b33029778579d2b3ac`.
- GitHub Pages publishes the static marketing and project overview pages. FastAPI authentication, customer data, APIs, and scanner communication remain on the Incus application host.
- Backup `daedalus-data-20261002T160720Z.tar.gz` was verified and restored into a temporary staging directory on October 2; all 24 tables loaded, SQLite integrity passed, and 26 report files were recovered. The snapshot contains 41 external-check runs and 110 scanner events. Those scanner events have inline payloads and no artifact digests, so the absence of a `scanner-artifacts/` directory matches the database references. The staging copy was removed after validation. The public DNS, trusted HTTPS, and `/healthz` check passed again during this review. Replication to independent storage and restoring over live `/data` remain untested. Owner Google sign-in is verified; additional-user onboarding, macOS 26 endpoint results, and multiple VLAN scanner behavior remain open validation items.
- A separate local-demo repeat ran DNS 44, passive website 45, and the five fixed-path probes in exposure run 46 for the verified CSP workspace. DNS retained three `www` SERVFAIL warnings with no confirmed record change; the passive website comparison detected page-content size/digest differences; all five bounded probes completed with no findings. The database saved two inbox notices (DNS warning and website change), both visible with review links in the dashboard. This is local-demo evidence, not a new production audit.
- A later local-demo run completed DNS 47 (three `www` SERVFAIL results, treated as unknown), passive website 48 (HTTPS 200), and bounded fixed-path run 49 (five paths, no configured signatures, complete coverage). No confirmed changes were found. The same evidence generated PDF job 30, which completed at 100%, downloaded successfully, and was visually reviewed as a six-page output. Receipt: `validation/local-csp-audit-20261003.json`.
- Report job 29's saved snapshot was rendered to a temporary QA PDF after correcting the TLS validity summary to evaluate captured certificate dates at run completion. The six-page output was visually reviewed; its page-content change rows now use readable labels. The original saved artifact was left unchanged, so newly generated reports receive this renderer fix.

## Review boundaries

Reviewed current configuration code and README, `../Meraki-2026_planning`, `../meraki`, `../dev`, and `../CSP-external-ui`. Credential searches were scoped to environment files and relevant source/credential filenames, excluding dependency and Git directories. Absence in this search does not prove that credentials are absent from other systems or account consoles.

The sibling CIS `config.yaml` was not opened. The local demo database includes DNS run 47, passive website run 48, bounded exposure run 49, Meraki report 26, and the managed scanner enrollment/check-in described in `BUILD-STATUS.md`. The local demo scanner validation added agent 3, loopback scan command 15, its completed event run, and scanner PDF job 31. These validations did not change OAuth secrets, Meraki credentials, or public DNS. Production Release 056 was deployed and checked as documented above.

## Release 054 Linux in-place upgrades

The shipped local upgrade command stages versioned runtimes, retains enrollment, credentials, settings and scan data, and verifies service ownership and readiness. Failed activation restores previous descriptors; interrupted recovery retains a private transaction for upgrade-rollback. A shared lock prevents overlapping lifecycle changes. Operators should schedule the cutover because active scans can be interrupted.

Managed Linux CI run 37173085078 confirmed a fresh heartbeat, retained enrollment/settings, unchanged saved scan events, a repeated-upgrade no-op, and cleanup after the real systemd upgrade. Twelve Linux fixtures cover recovery, partial writes, locks, and tamper refusal. The source suite passed 401 tests and 79 subtests. Production Linux enrollment and multi-VLAN coverage remain open.

Release 055 puts local and portal-issued Linux restarts under the shared lifecycle lock. Both refuse an interrupted upgrade; local restart also checks the loaded unit path/drop-ins and active process state. Full managed CI confirmed the shipped local restart changed the PID, recovered readiness and a fresh heartbeat, and retained enrollment/settings. No installed scanner was upgraded by deploying the portal release.

## Release 056 backup integrity

The backup manifest hashes the exact bounded bytes consumed by the tar writer through one no-follow regular-file descriptor. Regression checks cover replacement paths, file growth, truncation, symlinks and FIFOs. Source and Python 3.11/3.12 CI passed 401 tests and 79 subtests.

After deployment, a new production backup was copied off-host and restored into a temporary private directory. SQLite integrity passed and all 27 manifest files matched their sizes and hashes, including 26 PDFs. This snapshot had zero scanner artifacts; artifact restoration remains covered by fixtures. The temporary restore was removed. Replacing live data and independent backup replication remain open.

## Running portal recovery rehearsal

[Managed Linux CI run 37173669066](https://github.com/techmore/tm-daedalus/actions/runs/37173669066) backed up its running isolated portal, made a visible post-backup state change, stopped the owned portal, activated the restored data directory and started a new process. The earlier state was restored; saved scan events and PDF bytes were unchanged, readiness recovered, and the scanner authenticated a fresh heartbeat. Cleanup completed. The scan used only an ephemeral loopback listener. No scanner artifact download existed in this run, so artifact recovery remains covered by fixtures. Production data was not replaced; production remains on Release 056. The current source suite and Python CI run 37173669119 passed 401 tests and 79 subtests.

Legacy source review also found an optional Nikto execution path in the original website audit script. The current five-path exposure check does not replace that broader audit; integrating its reporting and authorization flow remains product work.


### 2026-10-04 — Assessment hierarchy and legacy Boolean evidence

DNS and Website now group change history between the assessment and supporting evidence. Scope limitations sit with evidence; expandable details use quieter separators rather than competing card surfaces. Dashboard structure and refresh checks passed (35 tests); signed-in browser visual review remains pending.

Ten active legacy macOS update/privacy Boolean collectors now require successful, canonical 0/1 output with no stderr or incomplete-command signal. Missing, malformed, failed, or timed-out preference reads remain manual instead of inferred pass/fail. These preserve the existing preference mappings, which do not establish managed enforcement for every user. Native client tests passed: 74, zero failures on macOS 27.0.1. Actual macOS 26 execution remains outstanding.


### 2026-10-04 — Meraki and endpoint assessment grouping

Meraki separates its current assessment from saved-report evidence. Endpoint compliance puts attention counts and their collection scope together in a prominent assessment, with separate labeled groups for coverage, baseline evidence, changes, and device presence. Setup remains collapsed. These are presentation changes; scope and collection semantics are unchanged. Browser visual review remains pending.


### 2026-10-04 — Workspace priorities

Overview adds area-level review, failed-collection, and unassessed counts. Area cards are stably ordered with failed collections and review observations first, followed by unknown/missing assessments, active checks, and saved evidence. These are area counts, not a combined security score. Missing or empty API coverage produces an unavailable message rather than zero attention counts. Rendering preserves literal text, keyboard focus, and stale-response protection. Visual review remains pending.


### 2026-10-04 — Consistent endpoint coverage on Overview

Overview and endpoint status share the same latest-per-device collection-time classifier. Fresh receipts do not make stale assessments current; future timestamps stay unknown and devices without results stay missing. Overview also counts devices whose latest assessment needs review, so a later clean report from another device cannot clear their attention state. Latest-report detail remains explicitly scoped to that report. Fixtures cover stale/future/missing assessments with fresh receipts and two devices with different latest results.


### 2026-10-04 — Scanner availability versus scan evidence

Overview now distinguishes online scanners, confirmed scan-engine readiness, approved ranges, and scanners whose latest saved scan completed. A ready scanner without any saved scan remains unassessed. Failed or conflicting latest-run evidence requires attention. Completion uses the existing run-summary validator; mixed scan/report metadata cannot count as a completed scan. Scan evidence timestamps are separate from availability check-ins. No claim is made that saved runs cover all approved ranges. Fixtures cover readiness without evidence, a completed run, a later failure, metadata conflict, and private-detail exclusion.


### 2026-10-04 — Website certificate overview

Website overview shows saved certificate expiry independently of HTTP response and selected browser headers. Unknown/malformed/naive expiry timestamps, expired certificates, and expiry within 30 days require review; timestamps must identify a timezone. Labels explicitly refer to the saved certificate, alongside the saved assessment time. Queued checks use the active-attempt state while preserving previous evidence. Fixtures cover unknown, malformed, naive, expired, soon-expiring, and later-expiring timestamps.


### 2026-10-04 — Real legacy Boolean collector validation

A private ad hoc client built from production source 4506665 ran on macOS 27.0.1 and uploaded report 4 at approximately 09:30 UTC. Production saved 154 checks: 24 pass, 47 fail, 78 manual, 5 errors; 71 assessed (46.1%). Against report 3, exactly macos_2, macos_68, and macos_72 changed fail to manual; all other statuses were unchanged. API history retained three changes and one persistent CIS notification at 2026-10-04T09:30:20.174850Z. This is classification correction, not remediation or macOS 26 conformance. The owned client terminated and matching temporary configuration was removed. Private production receipt: /data/codex-cis-boolean-evidence-live-validation-20261004.json.


### 2026-10-04 — Production CIS PDF 36 visual review

The actual production PDF 36 download matches SHA256 e03ba71765c546eba1f95e5be88387a7f8677c5f6db0c911973cc94efbb75cbd (31,819 bytes). All 12 pages were rendered and visually inspected, including assessment summary, the 154 saved check results, repeated table headings, footers, and 56 historical status changes. No clipping or overlapping text was observed. This PDF preserves endpoint report 3; it is not the later report 4. The original job and download were not edited or regenerated. Production receipt /data/codex-cis-summary-revised-validation-20261004.json now records the actual production visual review separately from the previous local frozen-snapshot review.


### 2026-10-04 — Legacy vendor source review and topic grouping

Reviewed ../dev/CSP-BFS/scripts/domain_analyzer.py and analyze_domains.sh. Their vendor feature categorized HTML references; it did not establish provider security or scan external vendors. Daedalus now groups saved linked-origin evidence by category, retaining each host, resource types, and reference count. HTTPS labels are neutral rather than green security-like badges. Categories remain hostname observations; missing metadata and partial inventory remain explicit. Grouping fixtures preserve input data and literal category text, including prototype-like names. Deeper vendor assessment remains open.


### 2026-10-04 — Full-project completion audit

Fresh authenticated production inspection on source 925b516 confirmed CSP verification; two scanners, one online and one offline, zero CIDR grants; three CIS profiles and one current assessment; configured Meraki credential; and 36 completed report jobs. Latest DNS completed with warnings, passive website completed, and latest deeper-audit attempt was cancelled (earlier completed evidence retained). Private receipt: /data/codex-project-completion-audit-20261004.json. PUBLIC-PROJECT-REPORT.md now maps the full requested scope to evidence and remaining gates. Completion remains unproven; open gates are not redefined away. Vendor review decisions/history are identified as the next independent implementation gap.


### 2026-10-04 — Vendor review backend (dashboard connection pending)

Added append-only VendorReview entries and workspace-scoped GET/POST /api/vendor-reviews. Each decision records saved website run, resource index, captured origin, actor, time, status (reviewed/needs_action/monitor), and rationale. Only current admins write; approved members may read. Input cannot supply an arbitrary host: the origin is selected from the scoped completed inventory. Reviews remain scoped to that inventory rather than silently approving later evidence. Request UUID uniqueness makes exact retries idempotent and rejects conflicting reuse. Audit entries commit with reviews. History is paginated separately from latest decisions per origin. External-check responses now identify latest_snapshot_run_id for the upcoming dashboard connection. These are human review records, not automated provider security assessments. Backend fixtures cover history/retry, invalid inventories/rationale, workspace isolation, live role downgrade, and sign-in. Dashboard controls and production validation remain pending.


### 2026-10-04 — Vendor review dashboard connection

Website dependency evidence now includes saved decisions, a rationale form for admins, and paginated history. Each form explicitly names its saved inventory run. A newer inventory does not silently retarget a draft; failed submissions retain their UUID for safe retry. Review entries render literal text, and refreshes preserve drafts and expanded history. Feedback is inline. Human decisions do not establish provider security and are not carried to a later inventory automatically. Node fixtures validate draft retention across new evidence, UUID reuse after failure, successful save/reset, and literal HTML-like rationale rendering. Production validation and browser visual review remain pending.


### 2026-10-04 — Production vendor review workflow validation

Source f14337e is deployed on Incus; health checks and verified off-host backup passed. Full suite: 511 tests, 104 subtests. Authenticated production dashboard includes version-091 controls. Saved website inventory 54 received review 1 (monitor) at 2026-10-04T09:50:33.395962Z, explicitly labeled workflow validation pending owner review and not a provider-security approval. An identical retry returned the same ID with created=false; history and read-only database inspection confirmed exactly one stored request row. Private receipt: /data/codex-vendor-review-live-validation-20261004.json. Browser visual review, automated provider assessment and review inclusion in frozen PDF reports remain outstanding.


### 2026-10-04 — Frozen vendor decisions in external reports

External report snapshots now capture current decisions and up to 100 history entries for exactly the selected saved website inventory, including origin, status, rationale, reviewer label, and time. Later decisions or account-label changes do not rewrite a saved report snapshot; a newer inventory does not inherit earlier decisions. PDFs show decision summaries and full captured history rationales, explicitly marking human review as distinct from provider security assessment. Long rationales are normal paragraphs that can flow across pages rather than oversized table rows. Fixtures check snapshot immutability, exact inventory scope, long notes, reviewer attribution, and bounded-history disclosure. Production generation and all-page visual review remain pending.


### 2026-10-04 — Production report 37 with frozen vendor history

Source 2cc7878 deployed with health/off-host backup checks passed; full suite 513 tests and 104 subtests. Production job 37 was observed queued at 0% then completed at 100%. Its frozen snapshot captures inventory 54 and review 1. Actual download: 17,392 bytes, SHA256 c2d8b5c0769a9718063bac76717252b4f0f4c6d089225bc1fad460d6b158dac1. All seven pages were rendered and visually reviewed, including reviewer/time, the labeled workflow-validation rationale, and scope disclaimers. No clipping or overlap was observed. Private receipt /data/codex-vendor-review-pdf-validation-20261004.json now records the production review. Automated provider assessment and browser visual review remain open.


### 2026-10-04 — Vendor review race and stale-view checks

A forced two-client flush race confirms identical request UUIDs produce one append-only review and one atomic audit entry, with both clients receiving the same review ID. Audit metadata now includes request_id for unambiguous retry correlation. The dashboard clears prior decision/history rows when no inventory context exists and replaces a failed-load message after recovery. Existing draft protection and literal rendering remain tested. These are fixture/renderer checks; browser visual review remains pending.


### 2026-10-04 — Vendor history pagination and older current rationale

A 102-entry fixture confirms two history pages contain every unique entry once, while latest decisions retain an origin whose current decision predates the first history page. Frozen snapshots retain both latest decisions and disclose the 100-history-entry limit. PDF rendering now includes full rationale for current decisions outside that recent-history window, avoiding silent omission. A separate two-page long-rationale fixture was rendered and visually reviewed without clipping or overlap. Full suite: 515 tests and 104 subtests. These are fixture checks; production has not been populated with artificial bulk history.


### 2026-10-04 — Topic reading order and login preference evidence

DNS and Website now place collection controls in a collapsed Refresh assessment group after supporting evidence. CIS changes precede detailed baseline reports. All 38 dashboard-topic and refresh tests pass; browser visual review remains pending. Three legacy login preference collectors now use bounded command evidence and require explicit successful canonical values; absent, failed, malformed or timed-out reads remain manual rather than inferred pass/fail. Native xcresult confirms 75 tests passed, zero failed or skipped. These collector fixtures do not establish live macOS 26 conformance or managed enforcement for every user.


### 2026-10-04 — Production topic ordering release

Source 7cad122 is active on Incus, with internal/public health checks and verified off-host backup daedalus-data-20261004T101051Z.tar.gz. Full suite: 515 tests and 104 subtests. An authenticated token-session request to /dashboard confirms DNS changes precede evidence, collection controls follow evidence, and CIS changes precede report detail. This confirms deployed markup, not rendered visual quality. Browser visual review and the full-project completion gates remain open.


### 2026-10-04 — Legacy screensaver evidence correction

Three legacy screensaver collectors now use the bounded reader. Password requirements require explicit successful Boolean evidence. Timer zero fails because it does not activate a screensaver; positive integral seconds must meet the retained legacy 1200-second threshold. Grace-period evidence accepts finite nonnegative decimal seconds and retains the legacy five-second threshold. Failed, missing, malformed, negative or timed-out reads are manual. Results explicitly limit claims to local preferences, not effective session-lock behavior or enforcement for every user. Native xcresult confirms 76 tests passed, zero failed/skipped, including boundary and unavailable-evidence fixtures. Initial test compilation exposed a nested Swift Testing macro; moving the collector call outside the assertion corrected the fixture. No live macOS 26 assessment or trusted public client distribution is claimed.


### 2026-10-04 — Legacy root query evidence

The legacy root collector now uses bounded directory reads and does not infer disabled root login from missing attributes, failed commands or unfamiliar authentication mechanisms. Both readable and unreadable mechanisms remain manual pending a supported platform-specific interpretation. This removes a false-pass path without claiming root-state assessment coverage. Native xcresult: 77 passed, zero failed/skipped. The separate pinned Tahoe rule remains distinct; actual Tahoe validation is still pending.


### 2026-10-04 — Real revised legacy session audit

Private source ab5b073 client build on macOS 27.0.1 uploaded production report 5: 154 checks, 23 pass, 41 fail, 85 manual, 5 errors; 14.94% pass rate and 41.56% assessment coverage. Production comparison retained seven transitions to manual (six formerly failed and one formerly passed); browser classifications remained unchanged. These are corrected evidence classifications, not device remediation or macOS 26 proof. The owned client process was stopped and its matching temporary configuration removed. Local ignored receipt: validation/cis-session-evidence-local-20261004/live-receipt.json. Public trusted distribution and supported root-state assessment remain unfinished.


### 2026-10-04 — DNS evidence grouped by assessment topic

Domain resolution and email protection now each retain their visible summary metrics followed by a separate collapsed record drawer. Resolver lookup details, coverage errors and upstream DNSSEC observations share a diagnostic drawer. Unknown lookup state remains visible in summary metrics; failures are not recast as absent records. A renderer fixture verifies topic-to-record placement, collapsed detail semantics, unknown resolution state and empty-snapshot handling. Dashboard/refresh suite: 39 passed. Visual browser acceptance remains pending.


### 2026-10-04 — Production DNS topic grouping release

Source 748131a is active on Incus. Internal/public readiness passed; off-host backup daedalus-data-20261004T102041Z.tar.gz was verified. Full suite: 516 passed and 104 subtests. Authenticated production HTML/JavaScript checks confirm asset version 093, domain/email evidence groups and the diagnostics drawer. These are deployment and renderer checks; browser visual acceptance remains open.


### 2026-10-04 — Saved network observations per scanner

Scanner cards now show the latest scan status and saved detailed-result counts (hosts, explicitly open ports, missing port states) before controls. Workspace-scoped assessment API selects the latest scan and latest detailed event without falling back to older malformed results; result artifacts retain size/digest validation and an 8 MiB summary bound. Metadata conflicts, absent detail and uninterpretable results remain unavailable. Counts are observations, not confirmed vulnerabilities or complete approved-range coverage. Renderer checks preserve unknown states and scope limits; scanner fixtures verify completion distinction, exact result identity, malformed-result handling and cross-workspace 404. Full suite: 518 tests and 104 subtests; scanner targeted suite 12 passed after the additional isolation assertion. Browser visual acceptance remains pending.


### 2026-10-04 — Production saved scanner assessment

Source bd11f9f is active on Incus with internal/public health checks passed and verified backup daedalus-data-20261004T102553Z.tar.gz. Authenticated production assessment for scanner 2 retains loopback run e9f020f1-d603-4616-a36c-f49c7aa8bc2c and detailed event 143: one host, 19 explicitly open ports, zero missing port states, collected 2026-10-04T07:13:36.503544Z. Reported covered targets remain null and coverage_complete remains false. Authenticated dashboard assets confirm version 094 and summary placement before controls. This is saved loopback evidence, not VLAN coverage or confirmed vulnerability assessment. Private receipt: /data/codex-scanner-assessment-validation-20261004.json.


### 2026-10-04 — Scanner summary failure and transport validation

Additional isolated fixtures prove oversized result artifacts are refused before loading, corrupted artifacts return 409, mixed scan/report metadata suppresses counts, and a failed newest scan is not replaced by an older successful scan. A real ephemeral HTTP listener also verifies artifact-backed summary counts and exact result-event identity while retaining unconfirmed target coverage. Full suite: 521 tests and 104 subtests; scanner suite 15 passed with the additional transport assertions. Production CIS report 5 retains seven changes and exactly one persistent cis_report notification, detected 2026-10-04T10:17:15.506743Z and routed to CIS. Private receipt /data/codex-cis-session-notification-validation-20261004.json. No production corruption or artificial failed scan was induced.


### 2026-10-04 — Source-backed Tahoe local password-hint check

Added bundled os_password_hint_remove using the pinned NIST mSCP dscl local-account hint enumeration. Successful complete recognized rows without hint text pass; explicit hint text fails. Empty, failed, timed-out, duplicate, malformed or over-10,000-record evidence remains manual. Account names and hint contents stay local; uploaded details contain only counts and scope. Command path/arguments are fixed and macOS 26 gating remains enforced. Native xcresult: 78 passed, zero failed/skipped. Supported mappings now total 87: 80/100 Level 1 and 85/119 Level 2. Published profile rule sets/versions are unchanged because this adds client implementation for an existing rule. Actual Tahoe execution and trusted distribution remain pending. Source: https://raw.githubusercontent.com/usnistgov/macos_security/beceac1d21baf9d924c2780f2e248577435bbfb1/rules/os/os_password_hint_remove.yaml

Full backend suite for the Tahoe hint implementation passed 521 tests and 104 subtests. No public client package was enabled and no incompatible Tahoe run was executed on the macOS 27 host.


### 2026-10-04 — Source-backed Tahoe session-owner authorization

Added os_unlock_active_user_session_disable based on the pinned NIST system.login.screensaver authorization read. Explicit owner-only policy passes; owner-or-admin fails. The two bundled PSSO names are followed once using fixed read arguments. Missing, unsuccessful, oversized, unsupported, multi-rule and duplicate canonical-key XML remain manual. No writes or live unlock attempts occur; results describe policy evidence and preserve smartcard/PSSO applicability limitations. Native xcresult: 79 passed, zero failed/skipped. Backend: 521 tests and 104 subtests passed. Mapping totals: 88 distinct, 81/100 Level 1, 86/119 Level 2. Actual Tahoe execution and trusted distribution remain pending. Source: https://raw.githubusercontent.com/usnistgov/macos_security/beceac1d21baf9d924c2780f2e248577435bbfb1/rules/os/os_unlock_active_user_session_disable.yaml


### 2026-10-04 — Source-backed Tahoe system-preference authorization

Added system_settings_system_wide_preferences_configure for the eight static authorization rights in the pinned NIST rule. Successful typed XML must show group admin, authenticate-user true, shared false and session-owner false for every right. Incomplete, unsuccessful, oversized, unsupported, ambiguous or wrongly typed evidence remains manual; explicit mismatches fail. Reads use fixed security authorizationdb read arguments, bounded command handling, and a six-second admission deadline. No authorization policy writes occur. Fixtures verify exact eight-right sequence, each expected field and mismatch, unavailable final right, numeric-versus-Boolean types and command failures. Native xcresult: 80 passed, zero failed/skipped; backend 521 tests and 104 subtests passed. Mapping totals: 89 distinct, 82/100 Level 1, 87/119 Level 2. Actual Tahoe execution and live System Settings interaction remain unverified. Source: https://raw.githubusercontent.com/usnistgov/macos_security/beceac1d21baf9d924c2780f2e248577435bbfb1/rules/system_settings/system_settings_system_wide_preferences_configure.yaml


### 2026-10-04 — Decoded authorization XML ambiguity checks

Replaced literal-key matching in both Tahoe authorization readers with shared bounded XML validation. Duplicate decoded keys in a dictionary are rejected, including numeric character-reference and CDATA spellings; valid equivalent spelling is accepted. Separate nested dictionaries may reuse a key. XML size, nesting and key lengths are bounded; internal entity declarations are rejected and external entity resolution is disabled. Raw policies remain local. Native xcresult confirms 81 tests passed, zero failed/skipped; backend profile/coverage suite 10 passed. Coverage mappings remain 82/100 Level 1 and 87/119 Level 2. Live Tahoe and trusted distribution remain pending.


### 2026-10-04 — Public marketing scope and repository validation

Marketing source b374123 clarifies saved scanner host/port observations, human dependency decisions/rationale, published Tahoe profiles and pending live Tahoe/trusted client distribution. Six public-site tests passed. GitHub Pages run 37196212082 completed successfully; live cybersecuritypilot.org home and daedalus.html returned HTTPS 200 with portal links, and the product overview includes the new endpoint-pilot wording. Production /readyz returned 200 with database/report storage healthy. Backend CI 37196132939 passed source 1d6e347. Client CI 37196132972 remains in progress; no success claim is made while its tests/package step is pending.


### 2026-10-04 — Client CI confirmation and Tahoe password history

Client CI 37196132972 completed successfully for source 1d6e347: client tests, release-script syntax and credential-free demo package build all passed. Added a separate bundled pwpolicy_history_enforce implementation using typed bounded global-account policy XML and the pinned CIS depth 24. Every captured depth must meet the threshold; an explicit shorter depth fails. Missing, unsupported, malformed, wrongly typed, unsuccessful or timed-out evidence remains manual. Raw policy stays local; no passwords are changed or tested. Native xcresult for the new implementation: 82 passed, zero failed/skipped. Full backend suite: 522 tests and 104 subtests passed. Mapping totals: 90 distinct, 83/100 Level 1, 88/119 Level 2. Actual Tahoe execution and trusted distribution remain pending. Source: https://raw.githubusercontent.com/usnistgov/macos_security/beceac1d21baf9d924c2780f2e248577435bbfb1/rules/pwpolicy/pwpolicy_history_enforce.yaml


### 2026-10-04 — Source-backed Tahoe minimum password length

Added pwpolicy_minimum_length_enforce using typed bounded local account-policy XML. Canonical standalone minimum-length conditions in password-content entries are parsed and the strongest explicit value is compared with the pinned CIS value 15. Unsupported, compound, absent, wrongly typed, ambiguous or unsuccessful evidence remains manual. Raw predicates and account policy remain local; no password creation/change attempt occurs. Fixtures cover the boundary, multiple explicit lengths, malformed values, compound OR/NOT conditions and failed command evidence. Native xcresult: 83 passed, zero failed/skipped. Backend: 522 tests and 104 subtests passed. Mapping totals: 91 distinct, 84/100 Level 1 and 89/119 Level 2. Actual Tahoe and trusted client distribution remain pending. Source: https://raw.githubusercontent.com/usnistgov/macos_security/beceac1d21baf9d924c2780f2e248577435bbfb1/rules/pwpolicy/pwpolicy_minimum_length_enforce.yaml


### 2026-10-04 — Consistent website certificate expiry presentation

Website priorities and supporting TLS metrics now share one expiry assessment. It requires an explicit timezone, valid calendar date and bounded ISO timestamp shape. Expiry uses exact milliseconds (including the expiry instant), rather than rounded days; the soon threshold is strictly less than 30 days. Invalid or timezone-free timestamps remain unknown, with no Invalid Date or inferred local-time result. Fixtures cover leap/calendar dates, offsets, exact expiry and 30-day boundaries, and verify both renderers call the shared helper. Targeted suite: 65 tests and 5 subtests; full suite: 523 tests and 104 subtests passed. This describes the saved certificate, not a new connection or protocol audit. Browser visual acceptance remains pending.


### 2026-10-04 — Structured legacy password length and history

Legacy CSP minimum-length and history collectors now call the bounded typed account-policy reader with their existing eight-character and five-password criteria. Tahoe retains 15/24. Missing setting names no longer count as pass; absent, malformed, flat-text, ambiguous, failed or timed-out evidence remains manual. The fixed pwpolicy argument is corrected to -getaccountpolicies. Original legacy check IDs and metadata are preserved, and details identify the legacy criterion rather than a Tahoe assertion. Native xcresult: 84 passed, zero failed/skipped; backend profile suite 10 passed. No new live endpoint run occurred. Production release 3aaaf06 remains pending in its existing deployment session while Tailscale requires an SSH identity check; the prior public service was ready and the new certificate helper was not yet served at the last inspection.


### 2026-10-04 — Typed password lifetime evidence

Added Tahoe pwpolicy_max_lifetime_enforce and replaced the legacy maximum-age keyword/minute-rounding collector with the shared typed account-policy reader. Positive finite policyAttributeExpiresEveryNDays values are compared precisely with Tahoe 365-day and legacy 90-day criteria. Zero, missing, unsupported, wrongly typed or failed evidence remains manual. Fixtures cover exact boundaries, fractional values just above each boundary, mixed captured lifetimes, zero and command failures. No policy or password was changed. Native xcresult: 85 passed, zero failed/skipped; backend profile suite 10 passed. Mapping totals: 92 distinct, 85/100 Level 1 and 90/119 Level 2. Actual Tahoe runtime and trusted distribution remain pending. Source: https://raw.githubusercontent.com/usnistgov/macos_security/beceac1d21baf9d924c2780f2e248577435bbfb1/rules/pwpolicy/pwpolicy_max_lifetime_enforce.yaml


### 2026-10-04 — Typed account-lockout policy evidence

Added Tahoe attempt-limit and timeout checks for explicit typed policyAttributeMaximumFailedAuthentications and autoEnableInSeconds values. Positive attempts must be <=5; durations must be >=900 seconds. Replaced the legacy attempt-limit collector keyword match with the same bounded structured reader, preserving legacy metadata. Missing, disabled attempt limits, wrongly typed, unsuccessful or ambiguous evidence remains manual. No failed-logon attempts or account/policy changes occur. Fixtures cover boundaries, mixed values, zero, unsupported types, failed commands and legacy keyword false-pass prevention. Native xcresult: 86 passed, zero failed/skipped. Full backend: 523 tests and 104 subtests passed. Mapping totals: 94 distinct, 87/100 Level 1 and 92/119 Level 2. Actual Tahoe runtime and trusted distribution remain pending. Sources: pinned NIST pwpolicy_account_lockout_enforce.yaml and pwpolicy_account_lockout_timeout_enforce.yaml at commit beceac1d21baf9d924c2780f2e248577435bbfb1.

### 2026-10-04: exact-origin evidence deployed and verified

fa0d275 deployed successfully to SER8 Incus with verified off-host backup and readiness. Backend suite: 561 tests and 122 subtests passed. Production web runs 57/58: complete, four origins, zero differences and zero persistent notices. PDF 38: frozen origin evidence matches storage, all seven pages rendered and visually reviewed. This closes the origin metadata presentation/deployment gate; whole-project acceptance remains open as recorded in PUBLIC-PROJECT-REPORT.md.

### Isolated recovery inspection configuration

Set DAEDALUS_BACKGROUND_WORKERS_ENABLED=false only on an isolated recovery copy to prevent automatic scheduled DNS/website checks and queued website-audit collection. The default is true. This is not a read-only or authentication mode: normal migrations and interrupted-job reconciliation still run, and API actions retain their existing permissions. Bind the inspection server to loopback, use separate data/report directories, and do not direct scanner clients at it. No production setting has been disabled. Startup fixtures verify both disabled and enabled worker paths; real restored-runtime validation remains pending.

### Password-encrypted recovery secrets

`scripts/recovery_secrets.py` seals an owned mode-600 secret file into a password-encrypted envelope and restores it only to a new mode-600 file. Run in an interactive terminal; passwords are prompted privately, never passed as command arguments. Keep the envelope off SER8 and store the recovery password independently. This utility does not choose a storage destination or export production secrets automatically.

```sh
python scripts/recovery_secrets.py seal /path/to/private-production.env /path/to/recovery-secrets.json
python scripts/recovery_secrets.py restore /path/to/recovery-secrets.json /path/to/new-private-production.env
```

Version 1 fixes Scrypt parameters (n=32768, r=8, p=1) and uses Fernet authenticated encryption with a random salt. Input secrets are capped at 1 MiB; envelopes at 2 MiB. Files must be owned private regular files; source symlinks and existing destinations are refused. The production recovery-secret location/password and an actual independent recovery rehearsal remain pending.

### 2026-10-07 — BFS Meraki inventory and UniFi purchase planning

An actual read-only Meraki collection for Buckingham Friends School completed with two networks, 27 assigned devices (all online), 48 security controls collected and none unavailable. Private audit evidence is retained under `validation/bfs-meraki-live-20261007.json`. It is not yet a production BFS report job: the October 6 backup has no BFS credential or organization grant and current LAN SSH checks timed out.

Source `678d115` saves two dated inventory-based UniFi scenarios with each new Meraki report and displays quantities, official product links, surcharge-inclusive USD subtotals, observed availability and sizing limitations. Unknown exact models remain unpriced. Historical reports retain their saved evidence. Source `d701d31` appends the same plan to Meraki PDFs. A real BFS PDF has 94 original pages with identical content streams plus two visually reviewed planning pages; the ten product links are clickable. The hardware subtotals are $11,356 and $12,940; they exclude tax, shipping, optics, cabling, spares, support and implementation. The 24-port candidate was observed sold out. Detailed vendor references and coverage are in `docs/MERAKI-PURCHASE-PLANNING.md`.

Focused final PDF/planning, Meraki and workspace tests passed 19 tests and four subtests. Source push completed. Production deployment, authenticated rendered dashboard review, live BFS history/comparison/notification and original Meraki report coverage parity remain open. This is progress within the full build-out, not completion of the project.

### 2026-10-07 — Actual local BFS report lifecycle

The running Mac demo now contains BFS report jobs 32 and 33, collected through the normal authenticated API and encrypted workspace credential. Both completed at 100% / PDF ready. Report 33 compares with 32 with zero changes in all four configuration/inventory/coverage categories and no notice. Purchase scenarios are saved and preserved; detail, evidence and PDF access are isolated from CSP (404). An identity without approved membership is denied with 403. Local current script matches source. Existing local SQLite was backed up before startup; scheduling workers are disabled for manual validation. Public production health/readiness return 200, but current SER8 source and BFS migration remain unverified after SSH timeouts. Private receipt: validation/bfs-local-app-validation-20261007.json. Full suite: 768 passing tests, 255 subtests, one skip. GitHub backend checkpoint run 37712449962 passed; managed Linux run 37712377274 remains live.

### 2026-10-07 — Actual managed Mac calendar upgrade

Resolved installed bridge provenance by comparing package source hashes with Git history: agent.py matches bd9ca59, with unchanged initialization and command journal. A private reviewed kit preserved those three source files byte for byte and matched installed declared dependencies/entry point. Managed cutover completed through upgrade_service, retaining enrollment bytes, data/log paths, local port and authentication. The active NmapUI source bundle is b4a6ad04efc868ff3559c9a8ebd83554b2374814e53629bd1f1d83a987d88ae9; only its scan banner script and manifest differ from the previous source bundle. Readiness and explicit idle checks passed, and the served script matches the active source. Native UI shows running/connected/idle and retained five completed runs and five hosted PDF entries. Hosted client status confirms online with fresh heartbeat. Current detected CIDR is 192.168.222.0/24; scan scope was not expanded. Private receipts: validation/mac-calendar-upgrade-result-20261007.json and validation/mac-calendar-hosted-status-20261007.json. Backend CI 37713238931 passed 37e65b1; managed Linux CI 37713238777 remains live. SER8 LAN/public SSH ports were unavailable while its public portal remained accessible.

### Native client local artifact and production upload

A credential-free ad hoc Release artifact built successfully from the updated client source. It ran once against the existing CSP legacy-profile config and uploaded actual production endpoint report **24** at `2026-10-08T01:59:18Z`. Read-only SER8 inspection confirmed the verified profile `csp-macos-browser-baseline` v1.0.0, 154 results: 11 pass, 10 fail, 133 manual and zero errors. Assessed coverage is 21/154 (13.64%); the all-check pass rate is 7.14%. This macOS 27.0.1 run does not establish Tahoe conformance. A local upload acknowledgement was retained and the owned client process was stopped. Native UI automation timed out, so rendered menu acceptance remains open. This is not a persistent installation or trusted distribution. Private artifact and native result receipts remain under ignored `validation/`.
