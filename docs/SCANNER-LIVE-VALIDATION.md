# Real packaged scanner validation

This opt-in harness exercises the shipped NmapUI source bundle, Daedalus bridge, an isolated portal/database, ordinary command enrollment/scope/acknowledgments, realtime websocket events, immutable run history and the existing report renderer. It runs actual Nmap against one temporary listener on `127.0.0.1`. No production enrollment or external target is used.

## Run on a development machine

Use the project Python environment for the harness and a Python environment containing the shipped NmapUI requirements for `--nmapui-python`. Nmap must be on PATH. The harness extracts the shipped source bundle; it does not use an independently modified sibling source tree. PDF generation requires the configured Chromium runtime. Do not paste enrollment/API credentials into command arguments.

```sh
.venv/bin/python scripts/validate_scanner_local.py \
  --run-loopback --repeat-scan --close-listener \
  --nmapui-python /absolute/path/to/nmapui-runtime/bin/python \
  --receipt validation/scanner-listener-change.json
```

The listener-change scenario scans its owned listener, closes it, observes the product's normal five-minute scan cooldown, and scans the same single port again. It requires successful completion and exact single-IP/port evidence; an unconfirmed change or another tested port fails validation. The saved comparison must contain exactly one confirmed open-to-closed port observation and one matching workspace inbox notice. Repeated comparison reads must preserve the saved history and avoid another notice. This controlled listener closure is known to the fixture; the product reports an observation change and does not infer its cause for arbitrary networks.

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

This is a physical loopback transport/change-path test. It does not establish default/all-port scan coverage, multiple physical hosts, VLAN routing, fleet scale, production alerts, signed native distribution, long-running persistence or complete UI/accessibility acceptance. It preserves the existing shipped scanner report assets. Linux CI runs all four lifecycle/repeat/change/interruption scenarios independently; results are evidence only after their runs complete successfully.
