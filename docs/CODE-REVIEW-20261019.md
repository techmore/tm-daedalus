# Full-repo code review: 2026-10-19

Scope: FastAPI portal (`src/daedalus`), scanner kit (`src/daedalus/agent*`, `agent_bundle`), CIS macOS client
(`clients/`, read only: Swift cannot be built or tested here), `scripts/`, `tests/`.
Base: `origin/main` at `dc09b4e`. Baseline suite: 1581 passed, 1 skipped (`umask 022; pytest -q`, 117 s).
Method: manual read of the auth, tenancy, SSRF, command-channel, upload, backup/restore and deploy paths, with each
claim checked against the code. Nothing was run against a real target, production host or external service.
Line numbers refer to the tree on this branch (after the fixes below).

## Overall

The portal is carefully built. Every workspace-scoped route I traced (`/api/agents/*`, `/api/events/*`,
`/api/reports/*`, `/api/cis/*`, `/api/user-keys/*`, `/api/notifications/*`, probation overrides) resolves the
record through `get_org_context` and filters by `organization_id`; path-parameter workspace IDs are compared to
the session workspace; user API keys are pinned to one workspace and re-validated against current membership.
Outbound website/Nikto/icon checks resolve DNS once, reject non-global addresses, pin the IP, and block cross-host
redirects; Nikto runs through an allow-list CONNECT proxy with argv (no shell). Backup/restore validates paths,
sizes and digests. No cross-tenant read or write, command injection, or SSRF was found.

## Fixed in this PR (each with a test in `tests/test_review_fixes.py`)

1. **Single-use scanner enrollment code could be redeemed twice** (`server.py` `enroll_agent`, ~L6950-6990).
   The code was read, checked for `used_at is None`, and only later marked used, with no atomic claim. Two
   concurrent enrollments with one code could both pass and create two scanner credentials. Now claimed with
   `UPDATE ... WHERE used_at IS NULL` and a rowcount check; the loser gets 401. Test simulates the interleaving
   and fails without the fix.
2. **Scanner bridge forwarded any target to NmapUI** (`agent.py` `_run_one_command`, `local_scan_target_refusal`).
   The portal restricts scans to bounded private CIDRs inside the scanner's approved scope, but the bridge on
   the customer device passed `command["target"]` straight to NmapUI, whose own validator
   (`nmapui/validation.py:85`) accepts public IPs and hostnames. A compromised or buggy portal/queue could point a
   customer device at public hosts. The bridge now refuses anything that is not a private/loopback/link-local
   IP or CIDR of at most 65,536 addresses (the same rule the portal uses) and reports `failed`. It does not
   re-check the per-scanner authorized CIDRs (the bridge does not persist them); see finding 4.
3. **CIS report body fully buffered before the 5 MiB check** (`server.py` `receive_cis_report`, ~L5010).
   Chunked uploads have no `Content-Length`, so `await request.body()` read the whole body first. The body is now
   streamed and rejected as soon as it passes 5 MiB (memory bound; the HTTP result for an oversize body was
   already 413, so the test guards behavior rather than proving the memory bound). Requires a valid CIS key.

## Remaining findings, ranked

### Medium

1. **SQLite has no WAL and no busy timeout** (`db.py:19-23`; listener at `db.py:26-31`). One process shares a thread pool, the scheduler,
   the website audit worker and report threads over a single SQLite file with SQLAlchemy defaults
   (rollback journal, 5 s driver timeout). Under concurrent scanner uploads plus a scheduled run, writers can hit
   `database is locked`; several handlers (`receive_agent_event`, `agent_heartbeat`) would return 500 and rely on
   agent retries. Suggested: `PRAGMA journal_mode=WAL; PRAGMA busy_timeout=30000` in the existing `connect`
   listener (db.py:26-31). Not changed here because it alters on-disk files on the pilot volume and needs a
   backup/restore check (`backup_data.py` uses the SQLite backup API, which is WAL-safe). The in-memory
   `live_hub` (`live.py`) and per-process workers also assume exactly one uvicorn worker; document or enforce it.
2. **No global CSRF/Origin check on cookie-authenticated mutations** (`server.py:457-463`). Protection is
   `SameSite=Lax` only. The Google Admin router (`google_admin_routes.py:20-28`, which also rejects
   `Sec-Fetch-Site: same-site`) and onboarding (`onboarding.py:32-37`) add explicit checks; the other ~50 POST/PUT/
   DELETE routes do not, and `require_same_origin_mutation` ignores `PUT`. Lax blocks cross-site POSTs in current
   browsers, so this is defense in depth (a hostile sibling subdomain or a browser without Lax-by-default is the
   gap). Suggested: one middleware that rejects cookie-session requests lacking a bearer token when
   `Sec-Fetch-Site`/`Origin` is cross-site, for all non-safe methods.
3. **Scan authorization is enforced only by the portal** (`agent.py`, no use of the enrollment response's
   `authorized_networks`). After fix 2 the bridge still does not persist or enforce its approved CIDRs, and
   NmapUI itself accepts public targets (`nmapui-source.zip`: `nmapui/validation.py`). Suggested: store
   `authorized_networks` from enrollment/heartbeat in the agent config and refuse targets outside them locally.
4. **`web-nikto` runs inline in the request** (`server.py:6260-6262`, `nikto_checks.py:20`: up to 615 s).
   The handler awaits `run_in_threadpool` for the whole scan before returning 202. Reverse-proxy or client
   timeouts will drop the response while the thread keeps running, and several workspaces can exhaust the default
   40-thread pool, stalling every sync route. `web-active` has a 40 s bound and is fine. Suggested: enqueue to the
   existing website audit worker and return 202 immediately.
5. **Demo login trusts the TCP peer address** (`server.py:3012-3017`). `DEMO_MODE` defaults to true whenever
   `DAEDALUS_ENV != production` (`config.py:34`) and `/dev/login` accepts any request whose peer is loopback. Behind
   a local reverse proxy in a non-production environment (staging, CI preview), every client appears to be
   `127.0.0.1` and gets an admin session. Production is guarded (`config.py:73`), so this affects only staging.
   Suggested: require `DAEDALUS_DEMO_MODE=true` explicitly, and ignore the endpoint when `X-Forwarded-For` is set.

### Low

6. **Placeholder secrets pass the app's own config check** (`config.py:75-79`). The app only rejects the dev
   default and values shorter than 32 characters, so the 42-character example
   `replace-with-at-least-32-random-characters` (`.env.production.example:8`) boots. `scripts/check_production_env.py`
   rejects it, but only if the deploy path runs it. Suggested: reuse its `PLACEHOLDERS` markers in `config.py`.
7. **Unbounded request bodies on authenticated scanner routes** (`server.py:7072-7090` `/events`, heartbeat).
   Pydantic parses the entire body before the 512 KB payload check, so a stolen agent token can force large
   allocations. The artifact route (`~L7150`) already streams with a cap; apply the same to `/events`.
8. **Scan-target and detection ranges are broader than the intent** (`server.py:2546-2561`). `127.0.0.0/8` and
   `169.254.0.0/16` are valid scan targets and valid authorized scopes; `169.254.169.254` (cloud metadata) is
   scannable if an admin adds it. Python's `is_private` also treats `198.18.0.0/15` and documentation ranges as
   private on the agent side (`agent.py:150`), but the portal rejects them with 422 on heartbeat
   (`AgentHeartbeatRequest.normalize_detected_networks`, `server.py:531`), which makes the whole heartbeat fail for
   a scanner on such a network. Suggested: drop `detected_networks` entries the portal rejects instead of 422.
9. **CIS upload keys never expire and show no last-use** (`server.py:4730-4770`, `get_cis_workspace_from_key`
   `4320-4339`). One static key per workspace, valid until rotated; the redundant `hmac.compare_digest` after a
   hash lookup (`server.py:4334`) adds nothing.
10. **Site icon fetch has no total deadline** (`site_icon.py:47-70`). Per-socket timeout is 8 s, but a server
    trickling bytes can stretch one fetch well beyond that for each of four hops and three candidates. It runs on a
    background path and is size-capped. Add an overall deadline like `active_website_checks.OVERALL_DEADLINE_SECONDS`.
11. **Deploy helper uses a fixed `/tmp` archive path** (`scripts/deploy_incus_remote.sh:16,23-29`). The archive is
    digest-checked then extracted as root later; a local user in the container could swap it in between. Move it
    into a root-owned `0700` directory. Container-local only.
12. **`backup_data.py` leaks connections** (`scripts/backup_data.py:104-106`). `with sqlite3.connect()` commits but
    does not close; harmless in a one-shot process.

### Dead code and hygiene

- `uv.lock` and `requirements-production.txt` agree: CI regenerates and diffs it (`tests.yml:36-37`).
  `python-socketio[client]` is a portal dependency only because `agent.py` lives in the same package; splitting the
  scanner bridge into an extra would shrink the portal image. `jinja2` and `itsdangerous` are imported only by
  Starlette (templates, sessions) and are correctly declared.
- `upgrade_service.py:100,162` uses `__import__("io")` although `io` is already imported at L7.
- `DAEDALUS_HOSTNAMES` is read only by deploy scripts, never by the app (`config.py` uses `DAEDALUS_ALLOWED_HOSTS`).
  Keep, but say so in `.env.production.example`.

## Not covered

- Swift client behavior (read only: HTTPS-or-loopback endpoint check at `Main.swift:30-41`, key sent in
  `X-API-Key` header, private config) and macOS-only scanner service scripts.
- Meraki/Google Admin API clients beyond credential storage (Fernet-encrypted; key required in production).
- Load/concurrency behavior (finding 1 is from reading, not measured).

## Follow-up (2026-10-20)

Findings Medium 1 (SQLite WAL/busy timeout, single-worker assumption), Medium 2 (cross-site session writes) and
Medium 3 (bridge scope) were addressed in the hardening PR. Not changed: global CSRF tokens (Origin and
Sec-Fetch-Site checks only), enforcing one worker in code, and refusing scans for legacy enrollments whose scope is
unknown until their first heartbeat.

## Follow-up (2026-10-21)

- **Medium 4 (`web-nikto` inline) was a misreading and is withdrawn.** `start_external_check` passes
  `enqueue_only=True` (`server.py`, `_execute_external_check`), which queues the run (25-run cap) and returns 202;
  `website_audit_worker` executes it. No change needed.
- **Low 8**: link-local (169.254.0.0/16, fe80::/10) is no longer an accepted scan target or authorized scope
  (server and bridge). Loopback stays allowed for same-host validation. The heartbeat 422 part is covered by PR #10.
- **Low 9**: CIS upload keys record `last_used_at` (written at most once a minute) and accept an optional
  `expires_in_days` (1-365) at issue time; the default is no expiry, so existing keys keep working. Status shows
  `key_expires_at`, `key_expired` and `key_last_used_at` to admins.
- Left to PR #10: demo login, placeholder secrets, scanner request bodies, heartbeat detected networks, icon fetch.
