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

On October 8, the installed older engine lacked the maintenance endpoint and
correctly refused a normal upgrade. The explicit local `upgrade-offline` path
was used after verifying the owned units, confirming no active jobs, stopping
both units and proving the configured listener closed. The upgrade retained
enrollment/authentication bytes, exact descriptor backups and all 68 portal
PDF/snapshot pairs. A subsequent normal upgrade of that same kit was a no-op.
Installed agent source hashes match application source `5318e6a`; portal
command 33 successfully returned a Linux update-check receipt from the existing
APT index without refreshing catalogs or installing packages. This proves the
installed Linux command path, not a remote portal-driven upgrade feature.

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

### Production secrets and isolated rehearsal

Data archives do not contain `/etc/daedalus/production.env`. Recovery needs its
original encryption key to decrypt saved Meraki credentials, plus the session
secret and OAuth configuration. Use `scripts/recovery_secrets.py` to seal and
restore a private environment file; never commit an environment or recovery
password. Keep a separately held recovery password for protection beyond loss
of the application host.

The October 5 recovery copy is under the user's Mac application-support
directory, `Daedalus/Recovery/20261005T224647Z`, outside this repository. Its
envelope and password are private files on the same Mac; separate custody has
not been established. A rehearsal unsealed locally, started the restored portal
with production configuration validation, disabled all background collectors,
bound only to loopback, and authenticated 39 exact PDF downloads using the
existing local user key. The temporary process was stopped after validation.
This does not verify public DNS/TLS failover or Google OAuth login on a restored
host. Rehearse against a separate restored data directory before any live switch.

### DNS audit resolver provenance

Set `DAEDALUS_AUDIT_DNS_NAMESERVERS` to up to three comma-separated IPv4/IPv6 resolver addresses to use an explicit upstream for DNS/email audits. Empty uses the system resolver. For the current Incus host, restart the instance after changing the environment (`incus restart --timeout 120 daedalus-prod`) and verify `/readyz`. A direct systemd restart on this host can fail to stop the prior process because of container control-group permissions; checking the next snapshot's resolver provenance confirms that the new environment took effect. Snapshots retain resolver mode and addresses; resolver metadata changes do not create domain configuration alerts. Query availability changes remain evidence and may generate notices. No silent fallback is performed. Website target validation and ownership verification keep their existing resolvers. Resolver AD flags do not prove locally validated DNSSEC.

### October 7 recovery refresh

The post-BFS/report/key-revocation archive `daedalus-data-20261008T014901Z.tar.gz` was verified and restored into a fresh private local directory. All **41 completed PDFs** were present with their recorded sizes and PDF headers; both encrypted Meraki credentials decrypted using the existing sealed recovery configuration. BFS reports 40/41 retained saved USD purchase plans, and the temporary validation key remained revoked. The restored production-configured application completed its lifespan and returned ready through an isolated TestClient, with collectors disabled and no listening socket. Unauthenticated report access returned 401; the runtime then stopped. Receipt: ignored `validation/recovery-20261008/receipt.json`.

This verifies the latest archive, configuration and application startup. Separate recovery-password custody, public failover and restored Google OAuth login remain unverified.

## Optional staging cleanup and access checks

Deployment activation, restart, rollback and health inspection keep their normal SSH access checks. Optional cleanup of temporary container/host archives has a 20-second process deadline and stops its local SSH connection if another Tailscale identity check is requested. It logs a skipped cleanup, leaving temporary files for later management. This prevents optional cleanup from withholding the deployment's final success/failure result.

A failed rollback still retains its container recovery helper/state. Skipping cleanup does not verify recovery or authorize another rollout. Inspect the active release and health before retrying a failed deployment. These changes do not alter the host SSH policy or grant access.
