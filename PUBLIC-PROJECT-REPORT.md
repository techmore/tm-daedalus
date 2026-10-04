# Daedalus project report

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

As of October 3, 2026, the Daedalus source suite passes **397 tests and 77 subtests** locally. [Python CI run 37173085088](https://github.com/techmore/tm-daedalus/actions/runs/37173085088) passed on Python 3.11/3.12, and [Linux lifecycle CI run 37172392203](https://github.com/techmore/tm-daedalus/actions/runs/37172392203) passed against a real systemd user manager. The lifecycle check uses inert processes and synthetic enrollment/evidence; it proves service removal and exact restoration, without claiming a Linux NmapUI engine or portal workflow.

Production Release 055 runs commit `11ad49967190dd169309ce0669bfdc97589f7c08`; its 53-file archive SHA-256 is `e86b271e8eab12b69233b1df84dff480fee6497f0a9e2d74584f44e8b97a6b9e`. Internal and public readiness checks passed after activation, and the deployment created a verified off-host backup. See [`INTEGRATION-READINESS.md`](INTEGRATION-READINESS.md) for current deployment and validation details.

The local CSP demo audit completed DNS/email, HTTPS, and five fixed-path website checks and generated a visually reviewed six-page PDF. A separate local loopback scanner run uploaded 18 complete events and produced a visually reviewed two-page PDF. The adjacent NmapUI suite passed 660 tests with 28 skipped; its packaged runtime matched the generated bundle, including source-worktree provenance. These earlier audit results were not rerun as part of the Linux lifecycle release.

A disposable Ubuntu 24.04 managed scanner completed the real fresh installer and enrollment against an isolated portal. With only `127.0.0.1/32` approved, it uploaded a completed 15-event real Nmap run with realtime broadcasts and a visually reviewed two-page PDF. The portal restart produced a different NmapUI PID and recovered readiness plus a fresh heartbeat. Generated credentials/data and the disposable instance were removed. The final source also passed [managed Linux CI run 37173085078](https://github.com/techmore/tm-daedalus/actions/runs/37173085078), including the portal restart and cleanup. CI found and drove fixes for inherited spool and user-bus environment settings. This does not establish production Linux enrollment or broader subnet coverage.

The consolidated [CIS client](clients/csp-cis-audit/) retains its 58-test macOS evidence and a disposable profile-fetch/report check-in. Its demo archive passed integrity checks but was rejected by Gatekeeper; a trusted Developer ID signature, notarization, and an actual macOS 26 audit remain outstanding. The current local Mac runs macOS 27.0.1 and has no Developer ID Application identity.

GitHub Pages publishes the CSP marketing site and Daedalus overview at the verified custom domain. Production remains an owner-operated pilot; additional-user onboarding and admin succession, a macOS 26 endpoint audit, multi-VLAN scanners, production Linux enrollment, independent backup replication, and live-data restoration remain open.

These checks do not replace a real macOS 26 endpoint audit, the FileVault connected-volume coverage noted above, Developer ID signing/notarization, additional-user onboarding, restoring over live `/data`, independent backup replication, or multi-VLAN scanner validation. Do not ask end users to bypass Gatekeeper for the ad hoc demo build. The consolidated client's [GitHub Actions run 37165166088](https://github.com/techmore/tm-daedalus/actions/runs/37165166088) passed the 58-test suite and credential-free demo-package build. A fresh off-host backup and temporary staging restore passed; the local Mac runs macOS 27, so the Tahoe-only profile is not run on it.

## Recent interaction and distribution work

The dashboard uses in-page confirmation panels for managed scanner restarts, scanner access revocation, membership role changes, and member removal. Routine dashboard refreshes preserve a pending confirmation; confirming a change still uses the workspace authorization and audit paths. The local browser check opened a scanner revocation panel, allowed a scheduled refresh, and cancelled without changing scanner access. A notarized distribution script requires a Developer ID Application identity, submits the archive through a configured `notarytool` profile, staples and verifies the app, and refuses to deliver unless Gatekeeper accepts it. External client distribution remains pending.

The upgrade kit reader hashes and extracts the same bounded byte snapshot, with file-replacement, FIFO, and size-limit fixtures.

## Release 055 update

Production now runs commit `11ad49967190dd169309ce0669bfdc97589f7c08`, archive SHA-256 `e86b271e8eab12b69233b1df84dff480fee6497f0a9e2d74584f44e8b97a6b9e` (53 files). Internal and public health checks passed, and the deployed service is active. The local suite passed **397 tests and 77 subtests**; [Python CI](https://github.com/techmore/tm-daedalus/actions/runs/37173085088) also passed.

Linux in-place upgrades are implemented. [Managed Linux CI](https://github.com/techmore/tm-daedalus/actions/runs/37173085078) exercised the shipped installer, real loopback scan, portal restart, and local upgrade under systemd. It confirmed retained enrollment/settings, unchanged saved scan events, a fresh heartbeat, a repeated-upgrade no-op, and cleanup. Twelve Linux fixtures cover rollback, interrupted recovery, partial writes, locks, and tamper refusal. Production Linux enrollment and multi-VLAN coverage remain outstanding.

Release 055 puts local and portal-issued Linux restarts under the shared lifecycle lock. Both refuse an interrupted upgrade; local restart also checks the loaded unit path/drop-ins and active process state. Full managed CI confirmed the shipped local restart changed the PID, recovered readiness and a fresh heartbeat, and retained enrollment/settings. No installed scanner was upgraded by deploying the portal release.
