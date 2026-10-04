# Daedalus project report

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
