# Daedalus project report

**Daedalus** is a multi-organization security operations portal being developed for Cyber Security Pilot (CSP). Its public project overview is published at [`site/daedalus.html`](site/daedalus.html).

## Purpose

The project combines CSP's public-facing marketing site with the source for a separate authenticated application. The static marketing site is suitable for GitHub Pages. Authentication, customer data, scheduled or active checks, APIs, and scanner communication run in the Daedalus application service and are not hosted by GitHub Pages.

## Product areas

- **Organization access:** Google OpenID Connect sign-in, organization-scoped membership and roles, owner/admin approval for shared access, and DNS TXT ownership verification with a probation period.
- **Domain health:** passive DNS and email policy checks, website availability and configuration checks, historical observations, change summaries, and notifications.
- **Authorized website audits:** bounded active checks for approved domains, with time-limited administrator authorization and audit records.
- **NmapUI fleet:** one or more local scanner installations can report over an authenticated outbound connection. The portal records check-in state, scanner events, scan history, and comparisons, and can issue scoped scanner commands.
- **Meraki:** workspace-scoped inventory and audit reports using credentials supplied by an authorized administrator.
- **CIS endpoint baselines:** profile selection, macOS endpoint results, score and history, and generated reports. macOS 26 profile alignment is an active maintenance area.
- **Reports:** queued PDF generation with status and download history, alongside retained source evidence where supported.

## Architecture

- The **marketing frontend** is static HTML in `site/` and is published with GitHub Actions Pages.
- The **Daedalus application** is Python/FastAPI with server-rendered dashboard pages, a SQLite-backed data layer, workspace-aware API routes, and background report/check jobs.
- **Scanners** run on customer-controlled machines and initiate outbound connections to Daedalus; the portal does not require opening an inbound port on each scanner.
- **Runtime state and secrets** belong on the application host and its persistent storage, never in the Pages artifact or source repository.

## Current scope and open work

The repository contains implementation for the product areas above and has an existing pilot deployment. It remains pilot software: production readiness still depends on operational testing, a live recovery rehearsal, additional-user onboarding, scanner lifecycle validation, and review of the maintained CIS profiles. A GitHub Pages deployment can publish the CSP marketing site and Daedalus overview, but it does not move the authenticated service or its customer data to GitHub.

The Pages workflow intentionally publishes only `site/`. Private deployment runbooks, local validation receipts, databases, customer-specific packages, reports, and credentials are excluded from the Pages artifact. The NmapUI runtime source archive is tracked in the repository and includes a manifest identifying the source paths packaged from a working tree with local changes.

## Validation snapshot

On October 2, 2026, the Daedalus suite passed 324 tests and 58 subtests locally and in GitHub Actions under Python 3.11 and 3.12 (workflow run `37026727135`). The adjacent NmapUI source suite passed 660 tests with 28 skipped; its packaged runtime archive matched the generated bundle, including the tracked source-worktree provenance manifest. The adjacent CIS client unit suite passed 57 tests on macOS 27 with code signing disabled. The Incus production Daedalus health endpoint returned HTTP 200 after a report-module update; systemd is active and the deployed module hash matches commit `ac9c50a`. The GitHub Pages deployment workflow completed successfully (run `37022364071`), and both the marketing home and Daedalus overview returned HTTP 200. The latest verified production health check also returned HTTP 200.

These checks do not replace a real macOS 26 endpoint audit, Developer ID signing/notarization, additional-user onboarding, restoring over live `/data`, independent backup replication, or multi-VLAN scanner validation. A fresh off-host backup and temporary staging restore passed; the local Mac runs macOS 27, so the Tahoe-only profile is not run on it.
