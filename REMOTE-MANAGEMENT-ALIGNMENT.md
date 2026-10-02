# Remote management alignment

Reviewed 2026-09-30 UTC (2026-09-29 New York) against the current Daedalus source and sibling `../remote-control`. This is a source review and implementation plan. No sibling remote-control server, host command, agent, audit, installer, or service was run. Runtime credentials and customer configuration were not opened. No applicable `AGENTS.md` was found in either reviewed tree or its ancestor directories.

## Subsequent implementation

The credential-origin and administrative revocation gaps described in the original review have since been closed with endpoint validation and the scoped scanner-disable route. Version 1 diagnostics now add anonymous OS, architecture, CPU count and physical memory; receipts remain bounded, complete JSON with exact journal replay. A separate explicit local macOS kit-upgrade command stages immutable releases, preserves enrollment and scanner evidence, saves exact private LaunchAgent backups, waits for NmapUI readiness, and rolls back descriptors on cutover failure. A new protocol-v3 action performs an admin-requested, read-only `/usr/sbin/softwareupdate --list` check on online macOS scanners, returning a bounded structured receipt and never installing updates. General machine management and portal-driven client update deployment remain incomplete.

## Scope and current evidence

The requested end state is independent domain workspaces with approved user access, multiple local scanners, fresh online/offline information, live results/history, and remote management of their machines. Current Daedalus implements scanner-specific controls; broader machine management remains incomplete.

| Capability | Current Daedalus source evidence | Limit |
|---|---|---|
| Enrollment and identity | Single-use expiring enrollment tokens; per-agent hashed token; `require_agent` checks `Agent.enabled` and compares token digests; admin disable is workspace-scoped, audited, cancels undelivered commands, and retains evidence | Re-enrollment is deliberate; token rotation continuity still needs an explicit handoff contract |
| Access boundaries | Admin workspace context for command creation; agent organization checked; domain verification or a logged temporary override required | Keep these checks for every added operation and detail endpoint |
| Availability | Fresh bridge heartbeat within 45 seconds; NmapUI connectivity/readiness recorded separately; local service status distinguishes running from loaded-but-not-running | Bridge online does not prove scan-engine readiness; command 12 has now completed a loopback run with explicit `-Pn`, but wider subnet coverage is unverified |
| Structured controls | Protocol-gated `start_scan` (including per-scan `-Pn` choice), `cancel_scan`, metadata-only `check_nmapui_updates`, read-only `check_os_updates`, `restart_nmapui`, `refresh_health`, and `collect_diagnostics` | No general machine service controls, OS update installation, reboot, remote desktop, or shell endpoint |
| Execution receipts | Atomic server claim; delivery/deadline/completion timestamps; terminal replay protection; private local command claim/result journal; v2 local fingerprints include the per-scan host-discovery option and safely recognize legacy claims | An interrupted claimed operation can remain unconfirmed; timeout does not prove it stopped |
| Restart | Fixed managed NmapUI LaunchAgent label, bounded `launchctl kickstart`; success requires reconnect/readiness | macOS managed user services only; Linux bridge remains a foreground workflow. Explicit local upgrade uses content-addressed releases, private descriptor backups, readiness verification, and descriptor rollback; portal updates are not supported |
| Diagnostics | Explicit operational fields, versions, connectivity, queue counts and free disk bytes; no logs/config/environment/usernames/targets | Text result field is capped at 1,000 characters; richer structured diagnosis requires a versioned artifact contract |
| Audit | Command queue, delivery, expiry, timeout and reported result linked to workspace, user and scanner; disable event records actor and outstanding command counts | Broader host changes need immutable before/after facts, operation policy and approval evidence |

Sources: `src/daedalus/server.py` (`NewCommandRequest`, `require_agent`, `agent_bridge_online`, command routes), `models.py` (`Agent`, `AgentCommand`), `agent.py` (`_run_one_command`, `_collect_diagnostics`, restart handling), `command_journal.py`, and `agent_bundle/macos_service.py`. Relevant existing fixtures include `tests/test_scanner_commands.py`, `test_command_journal.py`, and `test_agent_bridge.py`. Their presence is source evidence; this review did not rerun them.

## Reusable sibling components

`remote-control` provides useful patterns, but it is a separate personal/tailnet control plane. Its JSON agent/policy stores and global admin token do not implement Daedalus tenant membership or actor authorization.

| Sibling component | Useful pattern to adapt | Adaptation required |
|---|---|---|
| `mdm.go` enrollment/check-in | Random one-time enrollment and per-agent hashed tokens; outbound identity-based check-in | Keep Daedalus organization ownership, approved membership and transactional SQL records |
| `cmd/tm-remote-agent/main.go` | Platform adapters for read-only inventory, update checks and typed operations; server fallback/backoff | Fixed executable/argument arrays, bounded output, declared capabilities, durable Daedalus receipts |
| `policies.go` | Explicit platform/tag selection with deterministic specificity and storage thresholds | Tenant-scoped assignments; versioned policy snapshots on commands; maintenance/deadline enforcement at execution |
| `inventory.go`, monitors | Inventory sections and down/up transition history | Structured allowlisted fields, organization keys, retention and timestamp provenance |
| `internal/updater/updater.go` | Staged download, checksum comparison, atomic executable replacement | Approved origin and release channel, authenticated/signed manifest, rollback and readiness verification before success |
| macOS/Linux packaging scripts | User LaunchAgent/systemd installation patterns | Preserve Daedalus exact service ownership checks; do not install or replace unrelated services |

Do not import the sibling's `shell_exec`. Its agent explicitly invokes `/bin/sh -c` for that operation. Its broad service/package names, OS installation and reboot handlers also need a narrower operation policy before reuse. The SSH fallback executes server-selected shell snippets and is not an appropriate default for an internet-hosted tenant portal.

The sibling has concrete protocol differences that must not replace the current Daedalus receipts:

- `mdm.go` requeues a running command after two minutes, while the agent permits execution for ten minutes. A long-running side effect may be delivered again. Preserve Daedalus durable claims; re-delivery must never imply permission to repeat an uncertain mutation.
- Its result handler permits rewriting a stored terminal result. Preserve Daedalus conditional state transitions and immutable terminal outcomes.
- Its administrative bearer token has no per-user workspace identity. Its local action log is best-effort and does not establish an accountable tenant actor.
- Its updater validates a checksum obtained from the same release source. This verifies matching bytes, not an independent release signature.
- The agent's `storageAllowsPolicy` enforces free-space thresholds for installation; the broader maintenance/defer/reboot roadmap is not proof that all those policies are enforced in that path.

## Prioritized implementation

### 1. Completed: close credential-origin and revocation gaps

The current bridge validates origins before credential-bearing requests. The scoped disable endpoint and dashboard action enforce workspace-admin access, preserve history, cancel queued commands, leave active work explicitly unconfirmed, and reject future authentication. These paths have dedicated endpoint and revocation fixtures. Token rotation remains a separate design item.

### 2. Continue capability-based scanner operations

The command union is a fixed action allowlist and actions are checked server-side and on the bridge. Continue with declared capability metadata instead of treating the protocol number as support for every future operation. Suitable additions include structured status for Daedalus-owned services and allowlisted settings/profile snapshots. Keep the bridge reachable if NmapUI is stopped. Service state must come from validated ownership plus observed state, not a generic successful process exit.

Each action should declare its payload schema, platform, component, prerequisites, expected observation, timeout and reconciliation behavior. Reject unsupported actions server-side and again locally. No remote executable path, service name, package URL or command string should be accepted from the portal.

### 3. Add machine inventory and update checks

The read-only macOS update catalog action is implemented. Continue with typed inventory refresh and other platform update checks only after defining bounded result fields, collection time, and unavailable/permission-limited outcomes. Do not store unrestricted command output or log files. Show bridge health, scanner readiness, inventory age and scan activity as separate facts.

### 4. Add narrowly scoped maintenance operations

OS/software installation and reboot require platform-specific capability, explicit workspace policy, maintenance window, free-space checks, active-scan coordination and durable operation receipts. Use approved package identities/releases and a separately reviewed local privilege boundary. Add a reboot success criterion based on a later authenticated check-in and observed boot identity, not loss of connection. No reboot or update installation is implemented by this document.

### 5. Validate the requested experience end to end

Use the enrolled CSP scanner to prove: portal admin action → tenant-bound command → durable local claim → fixed local operation → observed result → authenticated receipt → visible history/audit. Protocol v3 is installed and checked in. On September 30, a dashboard command scanned only `127.0.0.1` with the explicit `-Pn` option; command 12 reached `succeeded`, and 18 events formed a completed run in the scoped run API. Its full-run PDF was queued as report job 20 and completed at 100%. This closes the live command/result/history/PDF path for the installed Mac; it does not validate a broader subnet. Still include outage/restart during delivery and execution, override expiry, duplicate delivery, disabled agent, unsupported platform, and insufficient local privilege. Validate the intended Linux deployment separately.

The existing typed scanner controls provide an integration foundation. Full remote machine management is not complete until the selected additional operations and those runtime paths are implemented and verified.
