# Daedalus scanner kit

The kit contains a curated NmapUI runtime source bundle and the Daedalus bridge.
It excludes local NmapUI settings, customer data, credentials, and Node build
dependencies. NmapUI runs on this machine at `http://127.0.0.1:9000`; the
bridge only connects to that loopback service and to your Daedalus server.

## Managed install on macOS

Install Nmap and extract the kit in `~/Downloads`:

```sh
brew install nmap
cd "$HOME/Downloads/daedalus-scanner-kit"
sh install-service-macos.sh "https://your-daedalus-host" "scanner-name"
```

The installer prepares a versioned NmapUI source install, installs the bridge,
and asks for the one-time Daedalus enrollment code without echoing it. It
installs owner-level LaunchAgents for NmapUI and the bridge. They start at login
and restart after a process exit. NmapUI remains bound to loopback, with
scheduled scans and optional external enrichment disabled. The agent token,
LaunchAgent files, database, and logs stay in the user's Application Support
directories with owner-only permissions. Managed NmapUI data is isolated under
`~/Library/Application Support/Daedalus/nmapui-data`; existing data under the
legacy `~/Library/Application Support/NmapUI` directory is left untouched.

The installer stops if port 9000 is already in use. Choose another local port
with `NMAPUI_PORT=9001` before running it. If NmapUI Basic Authentication is
enabled, set both `NMAPUI_USERNAME` and `NMAPUI_PASSWORD` in that Terminal before
installing; the LaunchAgent files are owner-only.

### Local service lifecycle

From the extracted kit, use these explicit operator actions:

```sh
sh manage-service-macos.sh status
sh manage-service-macos.sh restart
sh manage-service-macos.sh uninstall
sh manage-service-macos.sh restore
```

Uninstall stops only recognized Daedalus user services and removes their
LaunchAgent files. It preserves enrollment, queued uploads and command receipts,
scan evidence, settings, logs, installed releases, and private service backups.
Restore recreates the original service files and requests startup using the
preserved enrollment; it never enrolls again or changes the scanner token.
The same current user, exact enrollment file, and original installed executables
are required. Changed enrollment, missing releases, foreign service files, and
modified backups are refused. Keep the private `service-resume` directory in
Daedalus Application Support if you intend to restore.

To upgrade an existing managed scanner, extract the newly downloaded kit and
run this from its directory:

```sh
sh manage-service-macos.sh upgrade /path/to/daedalus-scanner-kit.zip
```

Upgrade is separate from enrollment. It stages versioned NmapUI and bridge
releases, preserves the existing enrollment, settings, scan data, event spool,
command journal, service port, and authentication environment, then switches
the LaunchAgents and waits for NmapUI readiness. If startup fails, it restores
the previous service descriptors and requests the old releases to start again.
Old releases and a private descriptor backup remain available for recovery.

Restart and restore report a startup request, not confirmed readiness. Check
the local NmapUI readiness and the scanner's next portal heartbeat afterwards.
If startup fails, the preserved files permit another restore or explicit
restart. Use restore after uninstall instead of rerunning the enrollment
installer. These actions manage macOS user LaunchAgents.

## Managed install on Linux

Use a Linux host with systemd, an active systemd user manager, Python 3.11 or
newer, Nmap, and `unzip`. The units use `PrivateTmp`, which needs unprivileged
user namespaces in a user service ([systemd's namespace requirements](https://raw.githubusercontent.com/systemd/systemd/v255/man/system-or-user-ns.xml)).
Our Incus lifecycle validation required `security.nesting=true` on the
disposable scanner instance. The installer does not change host policy.
From the extracted kit, run:

```sh
sh install-service-linux.sh "https://your-daedalus-host" "scanner-name"
```

The installer prepares NmapUI, prompts for the one-time enrollment code, then
creates two fixed systemd **user** services: `daedalus-nmapui.service` and
`daedalus-scanner-bridge.service`. NmapUI binds only to `127.0.0.1`; the bridge
connects outward to Daedalus. No inbound port, root service, shell command, or
automatic software update is installed. NmapUI's local trust bypass is disabled.
Unit files, enrollment config, and
optional NmapUI Basic Authentication credentials are owner-only. Existing
units or files with these names are never overwritten. The bridge uses the
installation configuration directory for its durable event spool, even if
the user manager inherited a different XDG configuration home. If startup fails, the
installer attempts to stop every service it tried to start, including a
partially successful systemd start. Enrollment and private service files are
retained for recovery. A failed cleanup stop is reported explicitly because
the service may still be running.

Use the managed service helper for a status check or restart:

```sh
sh manage-service-linux.sh status
sh manage-service-linux.sh restart
sh manage-service-linux.sh uninstall
sh manage-service-linux.sh restore
```

It verifies that the unit and private environment files still match their
installation fingerprints before issuing commands to the two fixed unit
names. Startup is tied to the user's systemd manager. On systems that stop the
user manager at logout, an administrator may explicitly enable lingering for
that account with `loginctl enable-linger <user>` if unattended startup is
required. Daedalus does not change that host-wide login policy. After restart,
check NmapUI readiness and the scanner's next portal heartbeat.

Local restart shares the lifecycle lock with upgrade, removal and recovery.
It refuses a pending upgrade transaction, changed service descriptors, or
unexpected systemd fragments/drop-ins, and verifies that each restarted
process is active.

Managed Linux validation also backs up its isolated running portal, makes a
post-backup state change, stops that owned portal, activates the restored
data, and starts a new process. It checks point-in-time state, saved scan
events, PDF bytes, and the next scanner heartbeat. This is a disposable
recovery rehearsal; customer production data is not replaced.

`uninstall` stops and disables the bridge first, then NmapUI. It confirms
systemd reports both inactive and disabled before removing their verified unit files.
Enrollment credentials, scanner evidence, queues, logs, runtime releases, and
the private environment file are retained. A private recovery record holds
the exact original unit descriptors. `restore` reinstates those descriptors,
enables both services, and checks that both processes are active. Check NmapUI
readiness and the next portal heartbeat afterward; a running process alone
does not prove the scanner is ready. These are local operator actions and do
not revoke the scanner's portal enrollment. Stop any scan you need to finish
before uninstalling.

If stop, disable, or startup cannot be confirmed, the helper reports an error
and retains its recovery files. Retrying uses the same installation and
credentials. Changed, symlinked, incorrectly owned, or public service files
are refused. Only the two fixed Daedalus units are operated. The managed Linux
workflow includes an explicit local in-place upgrade path. Concurrent uninstall/restore
commands are refused until the current lifecycle operation releases its lock.

## Upgrading a managed Linux scanner

Extract the newly downloaded kit, then run its helper against that kit ZIP:

```sh
sh manage-service-linux.sh upgrade /path/to/daedalus-scanner-kit.zip
```

Both existing services must be active and enabled. The helper stages private,
content-versioned runtimes, retains the same enrollment, credentials, data
paths, settings and spool, then stops the bridge before NmapUI. It switches
only the two verified units and their ownership record. NmapUI must become
ready before the bridge starts. Repeating the same installed kit is a no-op.
The portal does not install upgrades remotely.

Failures attempt to restore the exact previous descriptors and start both
previous services. If interrupted or recovery fails, the private transaction
record stays in the configuration directory. From the same extracted kit run:

```sh
sh manage-service-linux.sh upgrade-rollback
```

Changed descriptors, recovery records, enrollment or credentials are refused.
Removal/restore and another upgrade are blocked until the pending transaction
is resolved. Runtime releases remain available for rollback; this command
retains them and does not revoke portal enrollment. Verify the next portal
heartbeat after upgrading. An explicit service cutover interrupts running work.

## Validating a managed Linux scanner

The repository's opt-in `scripts/validate_scanner_local.py --managed-linux`
mode uses a disposable, non-root Linux user with an active systemd user
manager. It runs the shipped fresh installer against an isolated loopback
portal, approves only `127.0.0.1/32`, executes real Nmap against one guarded
listener port, checks saved results and realtime broadcasts, generates the
scan PDF, and requests a managed restart through the portal. It verifies a
new NmapUI PID, fresh portal heartbeat, and direct readiness. It also runs the
local upgrade command, checks retained configuration/settings and saved scan
history, and confirms a repeated kit is a no-op before cleanup.
Use this only in a disposable environment: it temporarily changes that
user manager's PATH for the scan guard and removes its generated enrollment
and scanner data afterward. It refuses an existing Daedalus installation.
The `Test managed Linux scanner` workflow runs this validation on Ubuntu.
This does not establish broader subnet coverage or production fleet scale.

## Foreground install on Linux

Python 3.11 or newer, Nmap, and `unzip` are required. Start NmapUI and keep it
running:

```sh
sh install-nmapui.sh
```

Once NmapUI is ready, enroll the bridge from a second Terminal using the
command shown in Daedalus:

```sh
sh install.sh "https://your-daedalus-host" "scanner-name"
```

The bridge installer creates a Python virtual environment and prompts for the
single-use enrollment code. It saves the per-scanner token with owner-only
permissions and runs in the foreground.

The bridge makes outbound HTTPS requests to Daedalus and a local authenticated
Socket.IO connection to NmapUI. It opens no inbound port and provides no remote
shell. Workspace admins can run or cancel private-network scans, check the
NmapUI release channel, and restart NmapUI on managed macOS installs. Restart
requests require a fresh bridge heartbeat and are recorded in workspace audit
history.

An approved workspace admin can ask an online macOS scanner running bridge
protocol 3 or later to check Apple's software update catalog. The check invokes
`/usr/sbin/softwareupdate --list`, stores a bounded structured summary in
command history, and never installs or schedules updates.

When an admin narrows a scanner's approved CIDRs, Daedalus cancels queued scans
outside the new scope. For already-delivered scans, it requests `cancel_scan`
only when the scanner is online and every active scan is out of scope; NmapUI's
cancel action stops all active scans on that scanner. Mixed-scope jobs are left
running to avoid stopping an in-scope scan. A queued cancellation is best-effort
and does not mark scans stopped: the original scan command remains unconfirmed
until the scanner reports its terminal result. Offline scanners cannot receive
the request. Each decision is recorded in workspace audit history.

## Upload recovery

Scanner events are written to private local storage before upload. A portal or
network outage keeps them queued across bridge restarts. Replay preserves each
event's UUID and original UTC collection time; Daedalus stores a retried event
once. Retries back off from two seconds to five minutes and send at most twenty
events per batch. Scanner online status is updated by heartbeats, independently
of older queued scan evidence.

The bundled NmapUI announces a versioned bridge event protocol. Scan/report
events carry the same source UUID and UTC collection time through live delivery,
reconnect replay and SQLite recovery. A disconnected initiating browser or
bridge does not mark a running job completed; a reconnecting bridge rejoins it.
Older NmapUI runtimes still use the legacy raw-event path, whose timestamps are
the bridge's receipt time and whose replays cannot be correlated with previously
uploaded legacy records.

Recovery is bounded: in-memory replay keeps at most 500 events and 8 MiB per
active job; SQLite event replay keeps at most 200 events and 32 MiB per job.
Bridge reconnect reads the latest 20 persisted jobs, excluding finished jobs
older than seven days. Existing runtime maintenance retains the latest 2,000
finished jobs by default (`NMAPUI_FINISHED_JOBS_KEEP_LATEST` configures that).
Recovery outside these windows requires a separate history import and cannot
reconstruct evicted events. Validation currently uses fixtures; an installed
scanner disconnect during an active scan remains to be validated.

The queue lives under Daedalus's configuration directory in `event-spool`, with
a separate directory for each portal and scanner. Directories are owner-only
and event files are readable only by their owner. Successful uploads remove
their local queue entries. Permanent rejections remain as `.rejected` files for
review and log an error; other events can continue uploading. In particular,
results exceeding 512 KB automatically use private JSON artifact uploads.
Artifacts retain the original full JSON, digest and collection time; approved
workspace users can download them from the scanner event list. Artifact uploads
are capped at 32 MiB of uncompressed JSON; larger events remain locally rejected
for review. Saved scan result events can generate themed PDFs without another
scan. Database backups include scanner artifacts and a digest manifest.
The local queue is capped at 256 MiB;
if storage is full, new events cannot be saved and the bridge logs an error.


## Command receipts

Health refresh and sanitized diagnostics work when the bridge is online even if NmapUI is disconnected. Command results use a private ordered journal, with explicit portal ID/status acknowledgements and permanent rejections retained for review. Claims are bound to an enrollment namespace derived from portal URL, scanner ID, and its token, so credentials are never included in receipt payloads. Retained claims prevent repeating side effects after restart. The journal stops accepting new commands at 16 MiB or 10,000 files; operator review is required before cleanup. A process interruption between claiming and confirming an operation leaves its outcome unconfirmed rather than re-executing it.

An administrator's **Check NmapUI updates** command makes a bounded metadata request to the official NmapUI GitHub release API. Managed installs keep idle/background checks disabled; a direct operator request does not enable the idle update workflow. The command reports the release through scanner history and never installs software. Updates remain an explicit local operator action through the managed upgrade command above; the portal does not install releases remotely.

Modern bundled NmapUI emits command-linked accepted/terminal receipts and replays retained outcomes. Older installations confirm only delivery. A timeout records missing confirmation, not proof that the operation stopped or failed. Managed restarts require observed reconnect and readiness before success.

### Known targets and discovery

NmapUI's **Scan known targets without host discovery** option is off by default. Enable it in local scanner settings when a known host blocks discovery probes. It adds Nmap's `-Pn` to discovery and subsequent scans; target profiles can inherit the global choice or explicitly override it. This may scan unresponsive addresses. Existing comprehensive report scans already use `-Pn`. **Scan-only mode** independently skips MAC/vendor enrichment. When exclusions are configured, ARP enrichment is skipped so it cannot probe excluded addresses; Nmap retains its exclusions. Completion history reports the number of discovered or explicitly selected hosts, including zero.

## Mac menu bar status

After managed enrollment, run `sh install-status-macos.sh` to install the native
Daedalus Scanner Status companion. It starts at login, reads the existing private
enrollment config, and shows local NmapUI availability, active jobs, portal bridge
status, and the five latest saved runs. Open the local UI for detailed live scan
results or the portal for saved history. Quitting the indicator leaves scanning
services running. Building this local companion requires Apple's Swift command
line tools; it is locally ad-hoc signed, not a notarized distribution package.
