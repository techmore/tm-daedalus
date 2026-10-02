#!/usr/bin/env bash
set -euo pipefail

phase=${1:-}
release_id=${2:-}
instance=${3:-}
[[ "$release_id" =~ ^[0-9a-f]{64}$ ]] || { echo "Invalid release digest." >&2; exit 2; }
case "$instance" in
  *[!A-Za-z0-9_-]*|'') echo "Invalid Incus instance name." >&2; exit 2 ;;
esac

root=/opt/daedalus
app=$root/app
releases=$root/releases
candidate=$releases/$release_id
archive=/tmp/daedalus-$release_id.tar.gz
state=$releases/.previous-$release_id

case "$phase" in
  prepare)
    if [[ -e "$candidate" || -L "$candidate" ]]; then
      echo "Release directory already exists: $candidate" >&2
      exit 1
    fi
    mkdir -p "$releases"
    [[ -d "$app" || -L "$app" ]] || { echo "Current application path is missing." >&2; exit 1; }
    [[ -f "$archive" ]] || { echo "Release archive is missing." >&2; exit 1; }
    actual_digest=$(sha256sum "$archive" | awk '{print $1}')
    [[ "$actual_digest" == "$release_id" ]] || { echo "Release archive checksum mismatch." >&2; exit 1; }
    mkdir -m 0755 "$candidate"
    trap 'rm -rf "$candidate"' ERR
    tar -xzf "$archive" --strip-components=1 --no-same-owner --no-same-permissions -C "$candidate"
    python3.12 -m venv "$candidate/.venv"
    "$candidate/.venv/bin/python" -m pip install --disable-pip-version-check --no-compile --require-hashes -r "$candidate/requirements-production.txt"
    site_packages=$("$candidate/.venv/bin/python" -c 'import sysconfig; print(sysconfig.get_paths()["purelib"])')
    printf '%s\n' "$app/src" > "$site_packages/daedalus-release.pth"
    chown -R daedalus:daedalus "$candidate"
    DAEDALUS_ENV=development \
      DAEDALUS_DATA_DIR=/tmp/daedalus-deploy-smoke \
      DAEDALUS_REPORTS_DIR=/tmp/daedalus-deploy-smoke/reports \
      DAEDALUS_DATABASE_URL=sqlite:////tmp/daedalus-deploy-smoke/daedalus.db \
      PYTHONPATH="$candidate/src" \
      "$candidate/.venv/bin/python" -c 'import daedalus.server; from daedalus.reports import build_external_posture_pdf; pdf = build_external_posture_pdf({"domain": "deployment-smoke.invalid", "checks": {}}); assert pdf.startswith(b"%PDF-") and pdf.rstrip().endswith(b"%%EOF")'
    if [[ -L "$app" ]]; then
      previous=$(readlink -f "$app")
      [[ "$previous" == "$releases"/* ]] || { echo "Current release target is outside the release directory." >&2; exit 1; }
    else
      previous=REAL_APP
    fi
    printf '%s\n' "$previous" > "$state"
    chmod 0600 "$state"
    trap - ERR
    ;;
  activate)
    [[ -d "$candidate" && -f "$state" ]] || { echo "Prepared release state is missing." >&2; exit 1; }
    previous=$(cat "$state")
    if [[ "$previous" == REAL_APP ]]; then
      legacy=$releases/legacy-$release_id
      [[ ! -e "$legacy" ]] || { echo "Legacy release path already exists." >&2; exit 1; }
      mv "$app" "$legacy"
      previous=$legacy
      printf '%s\n' "$previous" > "$state"
      chmod 0600 "$state"
    fi
    link=$root/.app-next-$release_id
    rm -f "$link"
    ln -s "$candidate" "$link"
    mv -Tf "$link" "$app"
    ;;
  rollback)
    [[ -f "$state" ]] || { echo "Rollback state is missing." >&2; exit 1; }
    previous=$(cat "$state")
    if [[ "$previous" == REAL_APP ]]; then
      if [[ -d "$app" && ! -L "$app" ]]; then
        exit 0
      fi
      previous=$releases/legacy-$release_id
    fi
    [[ -d "$previous" ]] || { echo "Previous release directory is missing." >&2; exit 1; }
    link=$root/.app-rollback-$release_id
    rm -f "$link"
    ln -s "$previous" "$link"
    mv -Tf "$link" "$app"
    ;;
  cleanup)
    rm -f "$archive" /tmp/daedalus-deploy-remote.sh "$state"
    ;;
  *)
    echo "Usage: deploy_incus_remote.sh {prepare|activate|rollback|cleanup} RELEASE_SHA256 INSTANCE" >&2
    exit 2
    ;;
esac
