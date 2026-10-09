# Daedalus

Daedalus is Cyber Security Pilot's multi-organization security portal. It brings domain health checks, managed network scanners, Meraki reporting, endpoint baselines, and audit history into one workspace.

- **Marketing site:** [`site/`](site/) — the Cyber Security Pilot homepage and Daedalus overview.
- **Application:** [`src/daedalus/`](src/daedalus/) — FastAPI service, dashboard, and API.
- **Scanner kit:** [`src/daedalus/agent_bundle/`](src/daedalus/agent_bundle/) — local NmapUI integration and outbound reporting bridge.
- **CIS macOS client:** [`clients/csp-cis-audit/`](clients/csp-cis-audit/) — menu-bar audit client, Tahoe checks, profile fetching, report upload, and Xcode tests.
- **Profiles:** [`src/daedalus/profiles/`](src/daedalus/profiles/) — endpoint baseline profiles.
- **Tests:** [`tests/`](tests/).

## Google Admin security reporting

The deployed Google Admin connector supports read-only OAuth connection, customer/domain validation, CIS Controls v8.1 rationale, manual policy evidence and immutable recurring reports. Dedicated OAuth configuration, real tenant consent and CSP/BFS acceptance remain pending. See the [audit guide and checklist](docs/GOOGLE-ADMIN-SECURITY-AUDIT.md).

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

## Validate the application

Run from the repository root using the same commands as backend CI:

```sh
uv sync --locked
uv run --locked python -m playwright install chromium --only-shell
uv run --locked python -m pytest -q
```

On Linux, install the browser's system dependencies with `python -m playwright
install-deps chromium` from the configured virtual environment first. Use
`python -m pytest` so tests can import the repository's deployment scripts.
These tests include isolated report generation; passing them does not establish
visual approval of a PDF template or validation of a production scanner fleet.

## Scanner results delivery

Scanner cards show current activity and results delivery separately. The bridge
reports measured queued events, files retained for review, unfinished local
saves, and its last acknowledged upload. Missing, stale or unreadable queue
observations remain unknown. Overview counts fresh queued uploads and unresolved
review episodes; inbox notices record the first problem and its observed
clearance without repeating an alert on every heartbeat.

The Mac status app reads a bounded private local observation, so queued uploads
and save failures remain visible while the portal is unreachable. Observations
expire after 45 seconds. A clear queue does not prove that a scan completed or
covered its approved ranges; use the saved run and its supporting evidence.

The bridge persists event identities and collection dates before upload and
retries retained events after outages and restart. Only an explicit durable
server acknowledgement permits removal. A private save-intent journal preserves
unfinished saves across restart when that journal can be written; an unrelated
successful upload cannot clear them. Corrupt journals remain unknown and the
bounded journal's overflow remains latched for review. If storage cannot persist
intent before a process failure, recovery depends on the original scanner's
bounded replay window; this is not a guarantee of complete historical capture.
Physical fleet outage/recovery acceptance remains part of the completion audit.

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

## Review Google Admin evidence

Saved Google Admin assessments and manual notes survive failed refreshes. Notes waiting for the next audit remain visible after reload with source and recording dates; completed reports freeze their own evidence. Recurrence approval applies to the current audit connection, and setup/audit writes wait for a successful current read. See the [Google Admin evidence workflow](docs/GOOGLE-ADMIN-EVIDENCE-REVIEW.md). Real tenant consent and collection remain pending.

## Review saved endpoint assessments

The endpoint topic preserves the latest saved assessment, profiles, device observations, open check evidence and selected client profile through a failed refresh. An inline dated warning identifies stale workspace data; cached presence becomes **Last observed**. **Refresh saved endpoint data** is read-only. Key/profile setup actions wait for a successful current read, and their outcomes survive failed reconciliation. See the [endpoint refresh contract](docs/ENDPOINT-EVIDENCE-REFRESH.md) for limits and remaining acceptance.

## Review DNS and website health

DNS and Website use shared **Check now**, **Monitoring schedule**, and **Create PDF report** actions. Schedule summaries retain daily/weekly cadence and identify past expected collection times. PDF creation opens the existing report library for progress and download. Saved-data refresh retains findings and dates after a failed read. See the [domain review workflow](docs/DOMAIN-REVIEW-WORKFLOW.md) for the local browser/collector/report receipts and remaining production acceptance.

Overview status refresh also retains saved priorities and evidence after an interruption. Last-observed availability stays explicit, review links remain usable, and check/schedule writes wait for a fresh workspace and role read. Unchanged polls preserve keyboard focus and partial collection retries.

**All customers** retains its saved rows through failed reads and opens each customer’s Overview. Workspace switches have visible failure/retry feedback and one pending request. Workspace access keys receive only their own portfolio entry; dashboard requests reject a stale tab’s conflicting workspace context before changing data.

## Manage personal access keys

The account page identifies the selected customer and shows dated key status. Refresh reads saved records; interrupted reads retain the view and pause writes. A new token stays visible until saved and cleared, while self-revocation returns to sign-in. Key requests bind to the displayed workspace. See the [access-key customer workflow](docs/ACCESS-KEY-WORKFLOW.md) for scope, interruption behavior and remaining acceptance.

## Review members and transfer administrator access

Members & access and Overview share dated access requests and decision state. Failed reads retain saved members and pause changes; normal background reads preserve usable controls and focus. Approval grants user access. Admin succession, removal and rejoining retain dated audit events, and current-role/stale-decision checks protect concurrent changes. See the [member workflow and validation](docs/MEMBERS-ACCESS-WORKFLOW.md).

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


## Nikto website audits

The Website panel offers a manual Nikto audit to workspace admins with a verified
domain or active 14-day override. It uses HTTPS port 443, pins public addresses,
blocks proxy connections to other hosts/ports, and excludes denial-of-service
tests. Runs retain actor/time, findings, history, new-observation notices and
themed PDF evidence. Nikto does not confirm test exhaustion in its JSON output;
missing findings are not treated as resolved issues. Website Nmap is not run.

Install the optional external runtime once on an Ubuntu application host:

```sh
sudo apt-get install perl libnet-ssleay-perl libxml-writer-perl
sudo python3 scripts/install_nikto_runtime.py --destination /opt/daedalus/nikto
```

The installer pins source commit `312645d873478a77986627ab1fc8cffe595e85d4`
and verifies the download digest. It retains Nikto's license files and refuses
to replace an existing runtime. `DAEDALUS_NIKTO_EXECUTABLE` can point to another
reviewed absolute program path. Engine updates require an operator review;
audits disable interactive prompts, startup update checks and telemetry.
See the [official Nikto options](https://github.com/sullo/nikto/blob/main/documentation/nikto.1).

## License and contributions

This repository does not yet define a license or contribution policy. Contact Cyber Security Pilot before reusing or redistributing the software.

## Personal access keys

Signed-in users can manage workspace-bound keys from **Access keys** in the dashboard. Keys are shown once, stored as SHA-256 hashes, expire in 1–90 days, and retain the user's live membership and role. Use `Authorization: Bearer <key>` for API requests, or the access-key form on the sign-in page. Revocation invalidates key sessions and closes their live connection within five seconds. Key sessions cannot issue more keys or select another workspace; use Google sign-in for those actions.

Host operators can explicitly provision the named Codex operator for an existing verified domain with `python -m daedalus.operator_key --domain cybersecuritypilot.org --output /private/new-key.json`. The command refuses an existing output file and writes mode 0600; it never prints the token. This service identity has an audited admin membership solely in that domain, with a 30-day key. It does not impersonate a Google user.

## Customer onboarding

**Add or join workspace → Your workspaces & requests** shows saved approvals and access requests with recorded dates. **Refresh workspaces** retries saved reads without starting collection. The same review is available before the account has an approved workspace. Failed reads retain the list and confirmed request feedback, mark access as last observed and pause workspace switching until recovery. [Request and membership workflow](docs/MEMBERS-ACCESS-WORKFLOW.md#account-workspace-requests--october-9-follow-up).

Configured platform administrators can grant complimentary 30-day onboarding in **Add or join workspace → Add a customer**, or review existing customers in the same dialog. The DNS exception requires explicit reapproval every 30 days. A dashboard reminder counts approvals needing review; **Review customer access** opens the review dialog. Loads, refreshes and background polls never open it automatically. Expiry still closes the exception and creates durable workspace notices. Configure `DAEDALUS_PLATFORM_ADMIN_EMAILS` with the intended authenticated owners. [Authority, expiry and rollout](docs/CUSTOMER-ONBOARDING.md).

## Report and notification history

### Collection failures and recovery

Failed DNS and website attempts retain the last successful evidence and record a dated failure notice. Identical repeated failures stay quiet. The next successful collection records one **collection resumed** notice, including remaining limitations and any observed changes. A first successful collection is explicitly a baseline without a prior comparison. Resumed collection does not establish that security findings were resolved.

Unchanged scheduled checks retain their run history without creating inbox notices or completion banners. Manual checks still show completion feedback. Each workspace/check type has a database admission guard across workers; a busy scheduled check is deferred for retry instead of recorded as a collector failure. Network collection starts after the admission transaction commits.

### Reviewing saved evidence during connection problems

DNS, website, exposure and Nikto views retain displayed evidence and loaded older history when a refresh fails. An inline message identifies the retained evidence as potentially out of date and offers **Retry saved evidence**. The warning remains until a complete retry succeeds. These refresh controls read saved data; they do not run an audit. Run/check controls remain separate.

Refreshes preserve independent run/change history boundaries and stage all pages before replacing the view. Malformed pages or outdated overlapping requests cannot replace the saved view. Nikto retains expanded run details and uses the latest successful saved assessment independently from the visible history page. Background polls leave an in-progress request alone and stay quiet when successful. See [behavior and validation scope](docs/SAVED-EVIDENCE-REFRESH.md).

Saved reports are grouped by topic, with counts and **Load older reports** controls. Topic pages query their own history, so a busy topic cannot hide another topic's reports. The Meraki summary uses the latest completed assessment even when newer failed attempts fill the first page. In-page refresh retains the loaded older boundary; failed refreshes preserve the evidence already shown and offer a retry.

The workspace inbox supports **All notices** and **Unread notices**, counts and **Load older notices**. Unread state belongs to each member. The selected inbox filter stays in the URL across reloads, alongside the topic hash. Refreshes retain focused review actions where their notice is still present. Access notices lead to Overview's Workspace access section; failed PDF notices lead to report history.

Authenticated history API parameters:

- `GET /api/reports`: `limit` (1–100, default 50), `before` (the previous page's `next_before`), `report_type` (one supported type or comma-separated types), and `status` (`queued`, `running`, `completed`, `failed`).
- `GET /api/notifications`: `limit`, `before`, and `unread_only` (default false).
- `GET /api/audit-log` (workspace admins): `limit` (1–200, default 100) and `before`. Responses also identify the workspace and observation date. Members loads 40 actions per page, retains its review depth/open details/focus after refresh and offers retry without clearing saved history. See the [recorded action workflow](docs/MEMBERS-ACCESS-WORKFLOW.md#recorded-action-history--october-9-follow-up).

Responses include `total_count`, `has_more`, and `next_before`; report responses also include `latest_completed`, and inbox responses retain the current member's overall `unread_count`. Report ordering follows descending job ID. Inbox ordering follows detection time and then ID, including delayed notices and timestamp ties. Positions are scoped to the authenticated workspace; unread pagination remains valid after marking its anchor read. Responses are not cached. History reads do not regenerate PDFs or mark notices read.

Saved Network evidence can recover after a failed read through inline retry: [Meraki evidence recovery](docs/MERAKI-EVIDENCE-RETRY.md).

Report refreshes retain unchanged cards, expanded Meraki evidence and focused actions: [report review context](docs/REPORT-REVIEW-CONTEXT.md).

Saved Meraki connection refresh restores approved organizations and protects setup actions through failed reads: [connection and approval workflow](docs/MERAKI-CONNECTION-REVIEW.md).
