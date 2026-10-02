# Daedalus

Daedalus is Cyber Security Pilot's multi-organization security portal. It brings domain health checks, managed network scanners, Meraki reporting, endpoint baselines, and audit history into one workspace.

- **Marketing site:** [`site/`](site/) — the Cyber Security Pilot homepage and Daedalus overview.
- **Application:** [`src/daedalus/`](src/daedalus/) — FastAPI service, dashboard, and API.
- **Scanner kit:** [`src/daedalus/agent_bundle/`](src/daedalus/agent_bundle/) — local NmapUI integration and outbound reporting bridge.
- **Profiles:** [`src/daedalus/profiles/`](src/daedalus/profiles/) — endpoint baseline profiles.
- **Tests:** [`tests/`](tests/).

## GitHub Pages

GitHub Pages publishes only `site/` through [`.github/workflows/pages.yml`](.github/workflows/pages.yml). The Python application, its database, sign-in, reports, integrations, and scanner command channel require a server; GitHub Pages hosts only the static marketing pages. The Daedalus portal runs separately from the Pages site.

The Pages preview is live at <https://techmore.github.io/tm-daedalus/>. GitHub Pages is configured to publish through Actions; the `cybersecuritypilot.org` domain is not connected to this repository. See [`PUBLIC-PROJECT-REPORT.md`](PUBLIC-PROJECT-REPORT.md) for the public project summary.

## Run locally

Requirements: Python 3.11+ and [uv](https://docs.astral.sh/uv/).

```sh
cp .env.example .env
uv sync
uv run uvicorn daedalus.server:app --host 127.0.0.1 --port 8000
```

Open `http://127.0.0.1:8000`. Google sign-in and external integrations need their own credentials in the local environment. Never commit `.env` files, runtime databases, backups, generated reports, or customer scan data.

## Product overview

See the [Daedalus project overview](site/daedalus.html) for the feature map, architecture, and current scope. The application is an active pilot; the overview distinguishes implemented workflows from hosting and operational work that remains.

## License and contributions

This repository does not yet define a license or contribution policy. Contact Cyber Security Pilot before reusing or redistributing the software.
