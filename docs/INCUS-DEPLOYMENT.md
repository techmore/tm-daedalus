# Incus production releases

Daedalus runs in the `daedalus-prod` Incus container on the owner-managed SER8
host. The application is served by `daedalus.service`; persistent application
data is on `/data`, an Incus-mounted volume. Deployment keeps the existing
systemd unit and stable `/opt/daedalus/app` path. It does not use Docker.

## Preview a release

From a clean checkout of `main`, with SSH access to the Incus host:

```sh
DAEDALUS_INCUS_HOST='operator@incus-host' uv run python scripts/deploy_incus.py --plan
```

The plan builds and verifies the secret-free release archive but makes no
remote changes. Production deployment refuses an uncommitted tree or a branch
other than `main`.

## Deploy

```sh
DAEDALUS_INCUS_HOST='operator@incus-host' uv run python scripts/deploy_incus.py
```

The command takes a verified, SQLite-consistent off-host backup of `/data`,
builds the allowlisted archive, verifies it again inside Incus, then prepares a
new release directory with a fresh Python 3.12 virtual environment. Runtime
dependencies are installed with hashes from `requirements-production.txt`;
the candidate must import the service and render a synthetic PDF before it can
be activated. Secrets, databases, backups, scanner client bundles, and reports
are excluded from the source archive.

The release becomes active through an atomic symlink switch at
`/opt/daedalus/app`, followed by an Incus container restart. The command checks
the systemd unit and health endpoint from inside the container and checks the
public HTTPS endpoint. If activation or either health check fails, it switches
back to the previous release, restarts Incus, and verifies the restored
service. The first managed release preserves the existing application tree as
a legacy rollback target. Prior releases are retained; disk cleanup is a
separate, operator-reviewed task.

`requirements-production.txt` is exported from `uv.lock`. CI regenerates and
compares it on each run so deployment pins cannot silently drift.

## Data recovery

The release process never replaces `/data`. Its verified off-host backup is
stored locally in the ignored `backups/incus-production/` directory with
restrictive permissions. See `scripts/restore_data.py` for verification and
staging-restore instructions. Do not restore directly over the live volume as
part of an application release.
