# NmapUI platforms and how Daedalus consumes the engine

Updated 2026-10-20. This records where each NmapUI surface lives and what Daedalus depends on, so
scanner-kit rebuilds and front-end work do not drift apart.

## One engine, three front ends

| Surface | Repository / branch | What runs | Status |
|---|---|---|---|
| Web (shared engine) | [TM-NmapUI `main`](https://github.com/techmore/TM-NmapUI) | Flask + Socket.IO application (`app.py`, `nmapui/`), browser UI, reports, scheduler. Themed for elementary OS by `static/css/elementary.css`; falls back to the same look everywhere. | Active. CI: unit/contract, browser regressions, Ubuntu systemd smoke, packaged Mac smoke. |
| Native macOS | [TM-NmapUI `swift-native`](https://github.com/techmore/TM-NmapUI/tree/swift-native) | SwiftUI app under `packaging/macos/` with its own scan, report, privilege-helper and scheduling code; no loopback HTTP server. | Preserved, not merged. 29 commits ahead of and 71 behind `main` (last change 2026-08-23); merge preview conflicts in six files. Reconcile against the shared engine before integrating (see TM-NmapUI `docs/notes/PROJECT_STATUS.md`). |
| Native elementary OS | [TM-NmapUI-elementary](https://github.com/techmore/TM-NmapUI-elementary) | Granite/GTK 4 window (Vala) around the loopback engine, Wingpanel indicator, summary helper, per-user `nmapui.service` (Gunicorn, one threaded worker). Installs the engine from TM-NmapUI `main`. | Active. Extracted from TM-NmapUI `packaging/elementary` on 2026-10-20. |
| Marketing site | [TM-NMapUI-www](https://github.com/techmore/TM-NMapUI-www) | Static pages and screenshots. | Last pushed 2026-05. |

The macOS menu-bar launcher on `main` (`packaging/macos/NmapUIMenuBarLauncher.swift`, `build.sh`)
and the root LaunchDaemon installer are part of the web/shared-engine line, not of `swift-native`.

## What Daedalus takes from NmapUI

- `src/daedalus/agent_bundle/nmapui-source.zip` is a curated runtime-only copy of the engine
  (`app.py`, `nmapui/`, `templates/`, `static/`, XSL, Vulners scripts, examples), built by
  `scripts/build_nmapui_source_bundle.py` from a sibling TM-NmapUI checkout. The manifest records the
  source commit and a tree digest; `tests/test_packaged_scanner_maintenance.py` and
  `tests/test_cis_pdf_flow.py` verify the digest, and `server.py` reports it to scanners.
- The bridge (`src/daedalus/agent.py`, packaged as `daedalus-scanner-bridge`) talks only to the engine
  on `127.0.0.1:<port>` and to the portal. Mac and Linux installers in `agent_bundle/` stage versioned
  engine releases, LaunchAgents or systemd user units, and the upgrade/maintenance handshake.
- `scripts/nmapui-patches/` holds corrections that were applied to the shipped engine ahead of the
  upstream repository; TM-NmapUI `main` already includes them.

Current bundle: engine commit `ead498812fd3`, version `v2026.3.14.00_10`, 130 files. TM-NmapUI `main`
is 13 commits past that commit. Runtime-relevant upstream changes since then: MAC OUI vendor
discovery (`nmapui/mac_vendor.py`), inventory report additions (`nmapui/reporting.py`), the
elementary theme stylesheets, `templates/index.html`, `static/js/scan_runtime.js` and the committed
Tailwind build. Rebuilding the bundle is a scanner-kit release: follow
[SCANNER-LIVE-VALIDATION.md](SCANNER-LIVE-VALIDATION.md) and the packaged-source regression suite
rather than refreshing the zip in isolation.

## Port and data-directory coexistence

The elementary app, the Ubuntu root service, the elementary user service and a Daedalus-managed
scanner all default to port 9000. Only one of them can run on a machine at a time unless
`NMAPUI_PORT` is changed. Data directories differ: the elementary user service uses
`~/.local/share/nmapui`; Daedalus-managed installs use their own `nmapui-data` directory under the
Daedalus Application Support or XDG data directory and never touch the former.
