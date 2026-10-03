# Daedalus project report

**Daedalus** is a multi-organization security operations portal being developed for Cyber Security Pilot (CSP). Its public project overview is published at [`site/daedalus.html`](site/daedalus.html).

## Purpose

The project combines CSP's public-facing marketing site with the source for a separate authenticated application. The static marketing site is suitable for GitHub Pages. Authentication, customer data, scheduled or active checks, APIs, and scanner communication run in the Daedalus application service and are not hosted by GitHub Pages.

## Product areas

- **Organization access:** Google OpenID Connect sign-in, organization-scoped membership and roles, owner/admin approval for shared access, and DNS TXT ownership verification with a probation period.
- **Domain health:** passive DNS and email policy checks, website availability and configuration checks, historical observations, change summaries, and notifications.
- **Authorized website audits:** bounded active checks for approved domains, with time-limited administrator authorization and audit records.
- **NmapUI fleet:** one or more local scanner installations can report over an authenticated outbound connection. The portal records check-in state, scanner events, scan history, and comparisons, and issues scan commands only inside each node’s admin-approved private CIDR ranges.
- **Meraki:** workspace-scoped inventory and audit reports using credentials supplied by an authorized administrator, with saved dashboard detail, control evidence, findings, and coverage gaps.
- **CIS endpoint baselines:** profile selection, macOS endpoint results, score and history, and generated reports. macOS 26 profile alignment is an active maintenance area.
- **Reports:** queued PDF generation with status and download history, alongside retained source evidence where supported.

## Architecture

- The **marketing frontend** is static HTML in `site/` and is published with GitHub Actions Pages.
- The **Daedalus application** is Python/FastAPI with server-rendered dashboard pages, a SQLite-backed data layer, workspace-aware API routes, and background report/check jobs.
- **Scanners** run on customer-controlled machines and initiate outbound connections to Daedalus; the portal does not require opening an inbound port on each scanner.
- **Runtime state and secrets** belong on the application host and its persistent storage, never in the Pages artifact or source repository.

## Current scope and open work

The repository contains implementation for the product areas above and has an existing pilot deployment. It remains pilot software: production readiness still depends on operational testing, an independent backup copy and live recovery rehearsal, additional-user onboarding, multi-subnet scanner validation, and review of the maintained CIS profiles. The Daedalus server currently downgrades FileVault `pass` results to manual for macOS 26 v1.1.0; volume-aware client evidence and a real Tahoe endpoint run remain outstanding before that rule can pass. GitHub Pages publishes the CSP marketing site and Daedalus overview; the authenticated service and customer data remain on the Incus application host.

The Pages workflow intentionally publishes only `site/`. Private deployment runbooks, local validation receipts, databases, customer-specific packages, reports, and credentials are excluded from the Pages artifact. The NmapUI runtime source archive is tracked in the repository and includes a manifest identifying the source paths packaged from a working tree with local changes.

## Validation snapshot

On October 2, 2026, the current Daedalus source suite passed **339 tests and 58 subtests** locally. GitHub Actions run `37081228208` passed commit `d3e4574` on Python 3.11 and 3.12. The secret-free Release 040 candidate archive was built from that commit and its manifest verified: 52 files, 2,372,902 uncompressed bytes, 1,276,827 archive bytes, SHA-256 `06ca94689b519239f9202329ed6d396012f8d5e18f2ae6c5edafcbffd87aa9f3`. The adjacent NmapUI source suite passed 660 tests with 28 skipped; its packaged runtime archive matched the generated bundle, including the tracked source-worktree provenance manifest. The adjacent CIS client unit suite passed 57 tests on macOS 27 with code signing disabled. The `cybersecuritypilot.org` GitHub Pages custom domain is bound to this repository with HTTPS enforced. The marketing home, Daedalus overview, and both retained CSP school security resources returned HTTP 200 after Pages deployment `37030046563`. Production remains on Incus release 037 from commit `741975c`; public `/healthz` returned HTTP 200 on October 2. SSH to the host’s private address timed out and the public address refused port 22, so no new backup or activation was started. The pushed scanner CIDR and Meraki dashboard updates are not deployed.

These checks do not replace a real macOS 26 endpoint audit, the FileVault connected-volume coverage noted above, Developer ID signing/notarization, additional-user onboarding, restoring over live `/data`, independent backup replication, or multi-VLAN scanner validation. A fresh off-host backup and temporary staging restore passed; the local Mac runs macOS 27, so the Tahoe-only profile is not run on it.
