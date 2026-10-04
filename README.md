# Daedalus

Daedalus is Cyber Security Pilot's multi-organization security portal. It brings domain health checks, managed network scanners, Meraki reporting, endpoint baselines, and audit history into one workspace.

- **Marketing site:** [`site/`](site/) — the Cyber Security Pilot homepage and Daedalus overview.
- **Application:** [`src/daedalus/`](src/daedalus/) — FastAPI service, dashboard, and API.
- **Scanner kit:** [`src/daedalus/agent_bundle/`](src/daedalus/agent_bundle/) — local NmapUI integration and outbound reporting bridge.
- **CIS macOS client:** [`clients/csp-cis-audit/`](clients/csp-cis-audit/) — menu-bar audit client, Tahoe checks, profile fetching, report upload, and Xcode tests.
- **Profiles:** [`src/daedalus/profiles/`](src/daedalus/profiles/) — endpoint baseline profiles.
- **Tests:** [`tests/`](tests/).

## GitHub Pages

GitHub Pages publishes only `site/` through [`.github/workflows/pages.yml`](.github/workflows/pages.yml). The Python application, its database, sign-in, reports, integrations, and scanner command channel require a server; GitHub Pages hosts only the static marketing pages. The Daedalus portal runs separately from the Pages site.

The Pages site is published through Actions at <https://cybersecuritypilot.org/>. GitHub Pages repository settings bind the custom domain; the workflow publishes the CSP home page, Daedalus overview, and retained school security resources. The project URL remains available at <https://techmore.github.io/tm-daedalus/>. See [`PUBLIC-PROJECT-REPORT.md`](PUBLIC-PROJECT-REPORT.md) for the public project summary.

## Run locally

Requirements: Python 3.11+ and [uv](https://docs.astral.sh/uv/).

```sh
cp .env.example .env
uv sync
uv run uvicorn daedalus.server:app --host 127.0.0.1 --port 8000
```

Open `http://127.0.0.1:8000`. Google sign-in and external integrations need their own credentials in the local environment. Never commit `.env` files, runtime databases, backups, generated reports, or customer scan data.

## Production on Incus

The pilot runs in Incus, without Docker. See [`docs/INCUS-DEPLOYMENT.md`](docs/INCUS-DEPLOYMENT.md) for the verified backup, staged release, health-check, and automatic rollback workflow.

## Managed Linux scanner lifecycle

The scanner kit includes `manage-service-linux.sh status|restart|uninstall|restore`.
Uninstall verifies ownership, stops and disables the two Daedalus user services,
and preserves enrollment, local evidence, and a private descriptor backup.
Restore reinstates the same installation and checks that both services are active.
See the [scanner kit instructions](src/daedalus/agent_bundle/README.md) for prerequisites and limits.

The opt-in `scripts/validate_linux_lifecycle.py` exercises removal and recovery with
real systemd user services and inert processes on a disposable Linux account.
It validates lifecycle behavior without issuing network scans or connecting to
a customer workspace. The Linux lifecycle workflow runs this check in CI.

The separate `scripts/validate_scanner_local.py --managed-linux --run-loopback`
mode runs a fresh installer and one-time enrollment against an isolated portal,
approves only loopback scope, collects a guarded real Nmap run and PDF, then
requests a portal restart and confirms a new PID plus recovered readiness.
It requires a disposable non-root Linux user and an active user manager;
existing Daedalus installations are refused. The managed scanner workflow
runs this path on Ubuntu 24.04. Generated credentials and runtime data are
removed after the check; the sanitized receipt and PDF are retained.

## Build and test the CIS client

The consolidated macOS client source is in `clients/csp-cis-audit/`. Run its unit suite with:

```sh
xcodebuild test \
  -project clients/csp-cis-audit/CSP-CIS_Audit.xcodeproj \
  -scheme CSP-CIS_Audit \
  -destination 'platform=macOS' \
  CODE_SIGNING_ALLOWED=NO
```

For a private local demo archive, run `sh clients/csp-cis-audit/scripts/build-local-client.sh`. It does not bundle workspace credentials. The app receives an ad hoc bundle signature for integrity checks, but that signature has no publisher identity and is not notarized; downloaded copies may still be blocked by Gatekeeper. Do not ask end users to override that protection. With a Developer ID Application identity and a configured `notarytool` keychain profile, build an external distribution ZIP using `sh clients/csp-cis-audit/scripts/build-notarized-client.sh`.

## Product overview

See the [Daedalus project overview](site/daedalus.html) for the feature map, architecture, and current scope. The application is an active pilot; the overview distinguishes implemented workflows from hosting and operational work that remains.

## License and contributions

This repository does not yet define a license or contribution policy. Contact Cyber Security Pilot before reusing or redistributing the software.
