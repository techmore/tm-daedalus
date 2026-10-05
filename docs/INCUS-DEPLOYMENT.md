# Incus production releases

Daedalus runs in the `daedalus-prod` Incus container on the owner-managed SER8
host. The application is served by `daedalus.service`; persistent application
data is on `/data`, an Incus-mounted volume. Deployment keeps the existing
systemd unit and stable `/opt/daedalus/app` path. It does not use Docker.

## Production Linux scanner

The dedicated `daedalus-scanner-linux` Ubuntu 24.04 Incus container runs the
managed scanner separately from the portal. Its configuration enables nesting,
two CPU cores, 2 GiB memory and `boot.autostart=true`. The unprivileged `scanner`
account has linger enabled and runs `daedalus-nmapui.service` and
`daedalus-scanner-bridge.service` as systemd user units. NmapUI listens only on
container loopback port 9000; the bridge connects outward to the portal.

It is enrolled as scanner 3 with only `127.0.0.1/32` authorized for validation.
Additional subnet grants require the workspace administrator's explicit scope
configuration. Enrollment and local authentication files are owner-only. The
[scanner kit instructions](../src/daedalus/agent_bundle/README.md) describe
Ubuntu prerequisites, installation, status, restart and upgrades.

Actual acceptance includes scan/XML upload, portal-managed restart, container
restart with automatic service startup, in-place upgrade and a repeated-kit
no-op. Host reboot and additional VLAN locations remain separate open checks.

## Preview a release

From a clean checkout of `main`, with SSH access to the Incus host:

```sh
DAEDALUS_INCUS_HOST='operator@incus-host' uv run python scripts/deploy_incus.py --plan
```

The plan builds and verifies the secret-free release archive but makes no
remote changes. Production deployment refuses an uncommitted tree, a branch
other than `main`, or a local `main` that does not match `origin/main`.

## Deploy

```sh
DAEDALUS_INCUS_HOST='operator@incus-host' uv run python scripts/deploy_incus.py
```

The command takes a verified, SQLite-consistent off-host backup of `/data`,
publishes the archive only after it has been fully written, builds the
allowlisted application archive, verifies it again inside Incus, then prepares a
new release directory with a fresh Python 3.12 virtual environment. Runtime
dependencies are installed with hashes from `requirements-production.txt`;
the candidate must import the service and render a synthetic PDF before it can
be activated. Secrets, databases, backups, scanner client bundles, and reports
are excluded from the source archive.

The release becomes active through an atomic symlink switch at
`/opt/daedalus/app`, followed by an Incus container restart. The command checks
the systemd unit and readiness endpoint from inside the container and checks the
public HTTPS readiness endpoint. `/readyz` verifies that the database and report
storage are usable; `/healthz` remains the lightweight process liveness check.
If activation or either readiness check fails, the command switches back to the
previous release, restarts Incus, and verifies the restored service. The first
managed release preserves the existing application tree as a legacy rollback
target. Prior releases are retained; disk cleanup is a
separate, operator-reviewed task.

`requirements-production.txt` is exported from `uv.lock`. CI regenerates and
compares it on each run so deployment pins cannot silently drift.

## Data recovery

The release process never replaces `/data`. Its verified off-host backup is
stored locally in the ignored `backups/incus-production/` directory with
restrictive permissions. See `scripts/restore_data.py` for verification and
staging-restore instructions. Do not restore directly over the live volume as
part of an application release.

### DNS audit resolver provenance

Set `DAEDALUS_AUDIT_DNS_NAMESERVERS` to up to three comma-separated IPv4/IPv6 resolver addresses to use an explicit upstream for DNS/email audits. Empty uses the system resolver. For the current Incus host, restart the instance after changing the environment (`incus restart --timeout 120 daedalus-prod`) and verify `/readyz`. A direct systemd restart on this host can fail to stop the prior process because of container control-group permissions; checking the next snapshot's resolver provenance confirms that the new environment took effect. Snapshots retain resolver mode and addresses; resolver metadata changes do not create domain configuration alerts. Query availability changes remain evidence and may generate notices. No silent fallback is performed. Website target validation and ownership verification keep their existing resolvers. Resolver AD flags do not prove locally validated DNSSEC.
