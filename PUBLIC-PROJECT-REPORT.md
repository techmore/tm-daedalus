# Daedalus project report

**Daedalus** is a multi-organization security operations portal being developed for Cyber Security Pilot (CSP). Its public project overview is published at [`site/daedalus.html`](site/daedalus.html).

## Purpose

The project combines CSP's public-facing marketing site with the source for a separate authenticated application. The static marketing site is suitable for GitHub Pages. Authentication, customer data, scheduled or active checks, APIs, and scanner communication run in the Daedalus application service and are not hosted by GitHub Pages.

## Product areas

- **Organization access:** Google OpenID Connect sign-in, organization-scoped membership and roles, owner/admin approval for shared access, audited admin succession with a last-admin safeguard, and DNS TXT ownership verification with a probation period.
- **Workspace change notices:** temporary probation override grants and revocations produce durable inbox notices and live dashboard updates. Shared members see who changed access and when; free-text override reasons stay in the admin-only audit log.
- **Domain health:** passive DNS and email policy checks, website availability and configuration checks, historical observations, change summaries, and notifications.
- **Authorized website audits:** bounded active checks for approved domains, with time-limited administrator authorization and audit records.
- **NmapUI fleet:** one or more local scanner installations can report over an authenticated outbound connection. The portal records check-in state, scanner events, scan history, and comparisons, and issues scan commands only inside each node’s admin-approved private CIDR ranges. Narrowing a scanner's approved scope cancels queued out-of-scope work and requests best-effort cancellation of delivered work when no in-scope scan is active; the dashboard waits for a terminal scanner result before treating a scan as stopped. In the tested source, command history is admin-only, and managed Linux installations support restarting the verified NmapUI systemd user unit.
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

As of October 3, 2026, the Daedalus source suite passes **359 tests and 63 subtests** locally. GitHub Actions run `37161664739` passed on Python 3.11 and 3.12 for commit `bd57ea1`. Production Release 047 runs commit `bd57ea165e7eca4c8ccbfe6aca3eeaadda2f4a07`; its 52-file archive SHA-256 is `58cc0ffefe0fc05202194b2d931ffe9a5f75cd40beaf43c9466b84a335170e69`. Internal and public readiness checks passed after activation. The deployment created a verified off-host backup. The local CSP demo audit completed DNS/email, HTTPS, and five fixed-path website checks and generated a visually reviewed six-page PDF. See [`INTEGRATION-READINESS.md`](INTEGRATION-READINESS.md) for the deployment and local validation record. The adjacent NmapUI source suite passed 660 tests with 28 skipped; its packaged runtime archive matched the generated bundle, including the tracked source-worktree provenance manifest. The adjacent CIS client unit suite passed 57 tests on macOS 27 with code signing disabled. GitHub Pages publishes the CSP marketing site and Daedalus overview at the verified custom domain. Production remains an owner-operated pilot; live admin succession with a second production account, a live macOS 26 endpoint audit, additional-user onboarding, multi-VLAN scanner validation, independent backup replication, live-data restore rehearsal, and a real Linux remote-restart exercise remain open.

These checks do not replace a real macOS 26 endpoint audit, the FileVault connected-volume coverage noted above, Developer ID signing/notarization, additional-user onboarding, restoring over live `/data`, independent backup replication, or multi-VLAN scanner validation. A fresh off-host backup and temporary staging restore passed; the local Mac runs macOS 27, so the Tahoe-only profile is not run on it.
