# Integration readiness

Reviewed September 30, 2026 (New York); deployment and Pages state refreshed October 2. This note contains no credential values or organization IDs.

## Current deployment state (October 2, 2026)

The canonical portal is live at `https://daedalus.cybersecuritypilot.org/` in the `daedalus-prod` Incus container. Its application source commit is `741975c`; the public HTTPS health endpoint returns HTTP 200, the systemd service is active, and the persistent `/data` volume is mounted. The deployment release and off-host backup passed archive-manifest and SQLite verification. GitHub Pages now publishes the CSP marketing site and Daedalus overview from this repository at `https://cybersecuritypilot.org/`; Pages has workflow publishing, the custom domain, and HTTPS enforcement enabled.

The unconfigured `app.cybersecuritypilot.org` and `app.bfs.org` names below are historical alternate-host checks. They do not describe the canonical production portal. Real owner Google sign-in has been verified; additional-user onboarding remains open.

## Cisco Meraki

| Source | Classification | Read-only verification |
| --- | --- | --- |
| `../Meraki-2026_planning/.env` | Nonplaceholder credential; reusable for the verified endpoint | `GET /api/v1/organizations` returned HTTP 200; three accessible organizations |
| `../dev/swift/Meraki-march/.env` | Nonplaceholder credential; reusable for the verified endpoint | The same GET returned HTTP 200; two accessible organizations |
| `../meraki/master_meraki_audit.py` and other legacy Meraki scripts | Embedded nonplaceholder candidates | Not independently verified during this review |
| `data/daedalus.db` | One existing encrypted Meraki credential | Existing workspace grant produced completed reports 12 and 19; the credential and grant were not changed |

The local portal loaded three organizations using the existing key. Only the already-approved CSP organization was selected; the two other organizations remained unauthorized. Fresh report 26 completed at 100% and compared with report 19 at zero control, coverage, inventory, or inventory-coverage changes. It covered one network and zero assigned devices; two control endpoints were unavailable and device-rich reporting remains unverified. The PDF marks an enabled wireless SSID reported as `open` for owner review. The credential and grant were unchanged, and no credentials were copied into source or config files. Receipt: `validation/csp-full-audit-20260930.json`.

## Google OAuth

- Authlib login and callback handling are implemented; the callback requires the literal boolean `email_verified=True`. Tests use a fake OAuth client and do not establish real Google consent or sign-in.
- Main `.env` and `.env.production` files are absent. The broader legacy search found a Google OAuth client ID in an unrelated MUD website demo under `../dev/golang/mud-api-01/client_web`, beside a “replace with your Google OAuth Client ID” comment and localhost backend endpoint. No matching client secret or reusable pair was found. This unrelated identifier was not copied into Daedalus or used for login.
- The local demo currently responds on `127.0.0.1:8000` (`/healthz` HTTP 200). The managed NmapUI readiness endpoint at `127.0.0.1:9001/api/health/ready` also returns HTTP 200 with `ready: true`. Current DNS queries still return NXDOMAIN for `app.cybersecuritypilot.org` and `app.bfs.org`; neither public app hostname is configured for sign-in.
- The local callback is `http://127.0.0.1:8000/auth/google/callback`; production requires a registered HTTPS callback for the selected canonical host. Real consent and sign-in remain unvalidated.
- Fresh DNS A lookups on September 30, 2026 UTC returned NXDOMAIN for both `app.cybersecuritypilot.org` and `app.bfs.org`; neither hostname currently reaches a production portal.

## Incus production deployment

- Production runs as the `daedalus-prod` Incus instance on the CSP host. The service is managed with systemd inside the instance; Docker is not part of this deployment.
- The public application health endpoint returned HTTP 200 during the October 2, 2026 review. The deployed server, scanner bridge, dashboard template, and dashboard JavaScript matched the reviewed source snapshot.
- GitHub Pages publishes the static marketing and project overview pages. FastAPI authentication, customer data, APIs, and scanner communication remain on the Incus application host.
- Backup `daedalus-data-20261002T160720Z.tar.gz` was verified and restored into a temporary staging directory on October 2; all 24 tables loaded, SQLite integrity passed, and 26 report files were recovered. The snapshot contains 41 external-check runs and 110 scanner events. Those scanner events have inline payloads and no artifact digests, so the absence of a `scanner-artifacts/` directory matches the database references. The staging copy was removed after validation. The public DNS, trusted HTTPS, and `/healthz` check passed again during this review. Replication to independent storage and restoring over live `/data` remain untested. Owner Google sign-in is verified; additional-user onboarding, macOS 26 endpoint results, and multiple VLAN scanner behavior remain open validation items.

## Review boundaries

Reviewed current configuration code and README, `../Meraki-2026_planning`, `../meraki`, `../dev`, and `../CSP-external-ui`. Credential searches were scoped to environment files and relevant source/credential filenames, excluding dependency and Git directories. Absence in this search does not prove that credentials are absent from other systems or account consoles.

The sibling CIS `config.yaml` was not opened. The local demo database includes fresh DNS run 38, passive website run 39, bounded exposure run 40, Meraki report 26, and the managed scanner enrollment/check-in described in `BUILD-STATUS.md`. No OAuth secret, Meraki credential, production environment, public DNS record, or cloud deployment was changed.
