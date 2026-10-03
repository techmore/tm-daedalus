# Integration readiness

Reviewed October 2, 2026 (New York); production remains on application commit `741975c`; source updates through `afff553` are pushed but not deployed. This note contains no credential values or organization IDs.

## Current deployment state (October 2, 2026)

The canonical portal is live at `https://daedalus.cybersecuritypilot.org/` in the `daedalus-prod` Incus container. Its application source commit is `741975c`; the public HTTPS health endpoint returns HTTP 200, the systemd service is active, and the persistent `/data` volume is mounted. The deployment release and off-host backup passed archive-manifest and SQLite verification. GitHub Pages now publishes the CSP marketing site and Daedalus overview from this repository at `https://cybersecuritypilot.org/`; Pages has workflow publishing, the custom domain, and HTTPS enforcement enabled.

Commits through `afff553` are pushed to `main`. Meraki report details include bounded evidence, aggregate client usage, and topology summaries that omit device serials and topology nodes/links. DNS, passive website, and fixed-path audit histories now support cursor paging and load-older controls for runs and changes. The CIS report API rejects endpoint reports whose OS major version differs from the selected macOS benchmark target. Release 041 from `afff553` is packaged and manifest-verified: 52 files, 2,384,537 uncompressed bytes, 1,278,574 archive bytes, SHA-256 `25c306f0e1fb12d454c11dca8122553c676ea911a98c4fb8d1aff235f700058a`. CI run `37082186935` passed on Python 3.11 and 3.12; the local suite passed 341 tests and 63 subtests. The private and public SSH routes were unavailable; the WireGuard host key matched the existing private-address trust record, but the SSH connection timed out. Deployment did not start, so production remains on `741975c`; public `/healthz` returned HTTP 200 on October 2.

The unconfigured `app.cybersecuritypilot.org` and `app.bfs.org` names below are historical alternate-host checks. They do not describe the canonical production portal. Real owner Google sign-in has been verified; additional-user onboarding remains open.

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
- The public application health endpoint returned HTTP 200 during the October 2, 2026 review. The deployed server, scanner bridge, dashboard template, and dashboard JavaScript matched the reviewed source snapshot.
- GitHub Pages publishes the static marketing and project overview pages. FastAPI authentication, customer data, APIs, and scanner communication remain on the Incus application host.
- Backup `daedalus-data-20261002T160720Z.tar.gz` was verified and restored into a temporary staging directory on October 2; all 24 tables loaded, SQLite integrity passed, and 26 report files were recovered. The snapshot contains 41 external-check runs and 110 scanner events. Those scanner events have inline payloads and no artifact digests, so the absence of a `scanner-artifacts/` directory matches the database references. The staging copy was removed after validation. The public DNS, trusted HTTPS, and `/healthz` check passed again during this review. Replication to independent storage and restoring over live `/data` remain untested. Owner Google sign-in is verified; additional-user onboarding, macOS 26 endpoint results, and multiple VLAN scanner behavior remain open validation items.
- A separate local-demo repeat ran DNS 44, passive website 45, and the five fixed-path probes in exposure run 46 for the verified CSP workspace. DNS retained three `www` SERVFAIL warnings with no confirmed record change; the passive website comparison detected page-content size/digest differences; all five bounded probes completed with no findings. The database saved two inbox notices (DNS warning and website change), both visible with review links in the dashboard. This is local-demo evidence, not a new production audit.
- Report job 29's saved snapshot was rendered to a temporary QA PDF after correcting the TLS validity summary to evaluate captured certificate dates at run completion. The six-page output was visually reviewed; its page-content change rows now use readable labels. The original saved artifact was left unchanged, so newly generated reports receive this renderer fix.

## Review boundaries

Reviewed current configuration code and README, `../Meraki-2026_planning`, `../meraki`, `../dev`, and `../CSP-external-ui`. Credential searches were scoped to environment files and relevant source/credential filenames, excluding dependency and Git directories. Absence in this search does not prove that credentials are absent from other systems or account consoles.

The sibling CIS `config.yaml` was not opened. The local demo database includes fresh DNS run 38, passive website run 39, bounded exposure run 40, Meraki report 26, and the managed scanner enrollment/check-in described in `BUILD-STATUS.md`. No OAuth secret, Meraki credential, production environment, public DNS record, or cloud deployment was changed.
