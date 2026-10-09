# Real packaged scanner validation

This opt-in harness exercises the shipped NmapUI source bundle, Daedalus bridge, an isolated portal/database, ordinary command enrollment/scope/acknowledgments, realtime websocket events, immutable run history and the existing report renderer. It runs actual Nmap against one temporary listener on `127.0.0.1`. No production enrollment or external target is used.

## Recovery queue observation

Portal completion is recorded before the bridge removes its acknowledged local result file. The interruption harness now waits up to 30 seconds for event/result queues to empty while requiring the owned bridge to remain alive. Rejected evidence and an unavailable spool fail immediately; persistent queues still fail with their counts. The subsequent reported delivery observation must also show zero pending events and a saved acknowledgement. No recovery acceptance condition was removed.

The previous source `9b62da3` passed four Linux scenarios but failed interrupted-bridge CI **37887109103** at its immediate queue check. Its failure receipt is retained. A new real Mac loopback run with the bounded observation succeeded: 12 original pending events recovered with unchanged identity, one deep Nmap invocation, one lost committed event response replayed without duplication, zero final pending events, 21 realtime messages and the existing two-page PDF. The PDF SHA-256 is `bc0d198cc31e458a83713585da909faf05e4979556e0fbc279f735de9baff024`. Approved scanner source/report assets were not edited. New Linux exact-source CI remains a separate acceptance requirement.

## Rejected recovery evidence

The later interruption run for source `41d0070` failed Linux CI **37891108169** with zero pending events, zero command-result files and **one rejected event**. Its other four scenarios passed; backend CI **37891108104** passed. The actual Nmap result and accepted/succeeded command acknowledgements do not close this recovery failure. It is different from the earlier immediate queue-cleanup observation. No rejection acceptance condition was relaxed and the failed run was not blindly rerun.

The harness now records at most 20 rejected event identities, numeric permanent-rejection HTTP status when the owned bridge log contains it, whether the portal saved that identity, and names of conflicting fields. It omits payload values, raw log content and credentials, reads the database without writes, skips symbolic links, and records log/comparison error classes without masking the original failure. Ephemeral evidence is still cleaned up. The original failed artifact lacks those comparisons; new diagnostics cannot retroactively identify its cause.

A separate direct fixture executed the shipped broadcaster and SQLite replay code. Mutating the caller's nested payload after recording an event changed the in-memory replay while the persisted source event retained its original payload and the same event identity. This established a replay defect; its relation to the particular Linux rejection remains unproven. Source/report assets were unchanged at that investigation checkpoint. The subsequent correction is recorded below.

## Frozen event payload correction — October 9

The broadcaster now snapshots nested data when recording an event, returns independent emission/replay copies and retains stable original buffer contents. Persistence and every browser/bridge recipient use the recorded snapshot. A consumer changing its copy cannot change another recipient's contents or replay an altered payload under the same event ID.

The correction was applied to the original NmapUI source and packaged through `build_nmapui_source_bundle.py`. Before editing, every runtime file in that checkout matched the previous shipped bundle. The new source ZIP SHA-256 is `734c19b7db708ce60f775ef765cdfd0369a6d93936067166b78ebc0a2a3321b1`, with source-tree SHA-256 `787610e5ff9b7e16cacfc73c0fd7654f687fedef6531f97d81972d2c4a92b52c`. Only `nmapui/jobs.py`, `nmapui/scan_runtime.py` and the manifest changed; all other entries, including approved report styles/fonts/XSL, are byte-identical. The [exact source patch](../scripts/nmapui-patches/frozen-replay-payloads.patch) applies to the preceding bundle and reproduces both current source files. The sibling checkout retains its existing uncommitted work; the distributable source and patch are tracked in Daedalus.

Six new scan/report mutation cases failed against the preceding bundle and passed with the correction. They cover caller data, returned envelopes, both replay views, persistence and multiple independently mutating recipients. Packaged scanner/report checks passed **102 tests and 16 subtests**; focused payload/recovery checks passed **35 tests and seven subtests**; original NmapUI job/grouping/reconnect checks passed **23 tests**.

The interruption harness now additionally compares each original spooled payload with the saved portal payload, including JSON value types, without writing payload values to the public receipt. Missing/changed payloads fail acceptance. The final actual Mac run at **07:02 UTC** recovered 12 original events with unchanged IDs, times and payloads, retained one deep Nmap invocation, replayed one lost committed acknowledgement only once and drained event/result queues with zero rejected events. It received 21 realtime messages, confirmed command success and generated the existing two-page report. Both pages were rendered and viewed; PDF SHA-256 is `f4ebb71030f3aeaab5b8df40ea6ee726a284ce6867f463a1576d8c88b0194dc8`.

The preceding member source `8fa2080` independently passed backend CI **37895490255** and all five Linux scenarios in **37895490130**, with the preceding scanner ZIP. That successful interruption run does not erase the earlier `41d0070` rejection or prove its cause. The corrected ZIP requires its own exact-source Linux CI and installed-client/production activation acceptance. Wider fleet, VLAN, privilege and sustained outage behavior remain open.

## Run on a development machine

Use the project Python environment for the harness and a Python environment containing the shipped NmapUI requirements for `--nmapui-python`. Nmap must be on PATH. The harness extracts the shipped source bundle; it does not use an independently modified sibling source tree. PDF generation requires the configured Chromium runtime. Do not paste enrollment/API credentials into command arguments.

```sh
.venv/bin/python scripts/validate_scanner_local.py \
  --run-loopback --repeat-scan --close-listener \
  --nmapui-python /absolute/path/to/nmapui-runtime/bin/python \
  --receipt validation/scanner-listener-change.json
```

The listener-change scenario scans its owned listener, closes it, observes the product's normal five-minute scan cooldown, and scans the same single port again. It requires successful completion and exact single-IP/port evidence; an unconfirmed change or another tested port fails validation. The saved comparison must contain exactly one confirmed open-to-closed port observation and one matching workspace inbox notice. Repeated comparison reads must preserve the saved history and avoid another notice. This controlled listener closure is known to the fixture; the product reports an observation change and does not infer its cause for arbitrary networks.

Linux additionally supports a four-address whole-run test:

```sh
.venv/bin/python scripts/validate_scanner_local.py \
  --run-loopback --repeat-scan --close-listener --multi-host \
  --nmapui-python /absolute/path/to/nmapui-runtime/bin/python \
  --receipt validation/scanner-multi-host.json
```

This mode authorizes only `127.0.0.0/30` in its isolated workspace, discovers all four loopback addresses, and scans one port per host with separate original XML files. The listener is on `127.0.0.1`; the final detailed host must be unchanged in both runs. The comparison must use four saved results and four compatible XML proofs per run, show exactly one confirmed earlier-host state change, and retain its deduplicated inbox notice. It fails if evidence is missing, another target is included, or the last host changes. Linux is required; the test does not configure loopback aliases on the user's Mac.

Other modes:

| Arguments | Exercised behavior |
| --- | --- |
| `--run-loopback` | One real scan, command acknowledgment, live events, saved run and original report generation. |
| `--run-loopback --repeat-scan` | Two unchanged actual scans with distinct run IDs and comparable single-target evidence. |
| `--run-loopback --repeat-scan --close-listener` | One controlled port state change, immutable history and a durable deduplicated inbox notice. |
| `--run-loopback --interrupt-bridge` | Kill only the owned bridge during an in-flight scan, then recover spooled original events and acknowledgments without repeating the scan. |
| `--run-loopback --managed-linux` | Fresh disposable non-root Linux installation, service restart/maintenance/upgrade and cleanup. Requires a disposable Linux user with a running user manager and no existing Daedalus installation. |

Repeat/change and interrupted modes are separate bounded workflows. Managed mode also runs separately. The guard refuses unexpected executable arguments, targets and XML output paths, and bounds the actual scan to one port with bounded service detection, no DNS and no privilege escalation. Processes, ephemeral credentials/database/logs/spool and the listener are owned by the harness and cleaned up. Only a sanitized receipt and the generated fixture PDF are retained.

## Evidence limits

This is a physical loopback transport/change-path test. It does not establish default/all-port scan coverage, multiple physical hosts, VLAN routing, fleet scale, production alerts, signed native distribution, long-running persistence or complete UI/accessibility acceptance. It preserves the existing shipped scanner report assets. Linux CI runs lifecycle/repeat/change/interruption/multi-host scenarios independently; results are evidence only after their runs complete successfully.
