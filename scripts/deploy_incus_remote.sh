#!/usr/bin/env bash
set -euo pipefail

phase=${1:-}
release_id=${2:-}
instance=${3:-}
staging=${4:-}
[[ $EUID == 0 ]] || { echo "Deployment helper requires root." >&2; exit 2; }
[[ "$release_id" =~ ^[0-9a-f]{64}$ ]] || { echo "Invalid release digest." >&2; exit 2; }
case "$instance" in
  *[!A-Za-z0-9_-]*|'') echo "Invalid Incus instance name." >&2; exit 2 ;;
esac

root=/opt/daedalus
[[ "$staging" =~ ^/opt/daedalus/\.deploy-[0-9a-f]{32}$ ]] || { echo "Invalid staging directory." >&2; exit 2; }
# Cleanup retries after a confirmed removal are harmless. Never accept a symlink.
if [[ "$phase" == cleanup && ! -e "$staging" && ! -L "$staging" ]]; then exit 0; fi
for directory in /opt "$root"; do
  [[ -d "$directory" && ! -L "$directory" && $(stat -c %u "$directory") == 0 ]] || {
    echo "Deployment ancestor is not a root-owned directory." >&2; exit 1;
  }
  mode=$(stat -c %a "$directory")
  (( (8#$mode & 0022) == 0 )) || { echo "Deployment ancestor is writable by others." >&2; exit 1; }
done
[[ -d "$staging" && ! -L "$staging" && $(stat -c '%u:%g:%a' "$staging") == 0:0:700 ]] || {
  echo "Staging must be a root-owned private directory." >&2; exit 1;
}
umask 077
app=$root/app
releases=$root/releases
candidate=$releases/$release_id
archive=$staging/release.tar.gz
state=$staging/previous
helper=$staging/deploy-remote.sh
[[ -f "$helper" && ! -L "$helper" && $(stat -c '%u:%g:%a:%h' "$helper") == 0:0:600:1 ]] || {
  echo "Deployment helper ownership or permissions are unsafe." >&2; exit 1;
}

case "$phase" in
  prepare)
    if [[ -e "$candidate" || -L "$candidate" ]]; then
      echo "Release directory already exists: $candidate" >&2
      exit 1
    fi
    if [[ ! -e "$releases" && ! -L "$releases" ]]; then mkdir -m 0755 "$releases"; fi
    [[ ! -L "$releases" && $(stat -c %u "$releases") == 0 ]] || { echo "Unsafe release directory." >&2; exit 1; }
    mode=$(stat -c %a "$releases")
    (( (8#$mode & 0022) == 0 )) || { echo "Release directory is writable by others." >&2; exit 1; }
    [[ -d "$app" || -L "$app" ]] || { echo "Current application path is missing." >&2; exit 1; }
    [[ -f "$archive" && ! -L "$archive" && $(stat -c '%u:%g:%a:%h' "$archive") == 0:0:600:1 ]] || {
      echo "Release archive ownership or permissions are unsafe." >&2; exit 1;
    }
    # Both operations read the same opened inode inside a directory that the
    # service user cannot traverse or modify.
    exec 9<"$archive"
    actual_digest=$(sha256sum /proc/self/fd/9 | awk '{print $1}')
    [[ "$actual_digest" == "$release_id" ]] || { echo "Release archive checksum mismatch." >&2; exit 1; }
    mkdir -m 0755 "$candidate"
    prepared=false
    trap 'if [[ "$prepared" != true ]]; then rm -rf -- "$candidate"; fi' EXIT
    trap 'exit 1' HUP INT TERM
    tar -xzf /proc/self/fd/9 --strip-components=1 --no-same-owner --no-same-permissions -C "$candidate"
    exec 9<&-
    python3.12 -m venv "$candidate/.venv"
    "$candidate/.venv/bin/python" -m pip install --disable-pip-version-check --no-compile --require-hashes -r "$candidate/requirements-production.txt"
    site_packages=$("$candidate/.venv/bin/python" -c 'import sysconfig; print(sysconfig.get_paths()["purelib"])')
    printf '%s\n' "$app/src" > "$site_packages/daedalus-release.pth"
    chown -R daedalus:daedalus "$candidate"
    # Install the pinned browser used by the approved NmapUI PDF stylesheet.
    # ProtectHome=true hides home caches from the production service. Keep the
    # pinned browser under /opt, readable after ProtectSystem becomes strict.
    "$candidate/.venv/bin/python" -m playwright install-deps chromium
    install -d -o daedalus -g daedalus -m 0755 /opt/daedalus/browser-runtime
    runuser -u daedalus -- env PLAYWRIGHT_BROWSERS_PATH=/opt/daedalus/browser-runtime "$candidate/.venv/bin/python" -m playwright install chromium --only-shell
    DAEDALUS_ENV=development \
      DAEDALUS_DATA_DIR="$staging/smoke" \
      DAEDALUS_REPORTS_DIR="$staging/smoke/reports" \
      DAEDALUS_DATABASE_URL="sqlite:///$staging/smoke/daedalus.db" \
      PYTHONPATH="$candidate/src" \
      "$candidate/.venv/bin/python" -c 'import daedalus.server; from daedalus.reports import build_external_posture_pdf; pdf = build_external_posture_pdf({"domain": "deployment-smoke.invalid", "checks": {}}); assert pdf.startswith(b"%PDF-") and pdf.rstrip().endswith(b"%%EOF")'
    if [[ -L "$app" ]]; then
      previous=$(readlink -f "$app")
      [[ "$previous" == "$releases"/* ]] || { echo "Current release target is outside the release directory." >&2; exit 1; }
    else
      previous=REAL_APP
    fi
    printf '%s\n' "$previous" > "$state.new"
    mv -f "$state.new" "$state"
    prepared=true
    trap - EXIT HUP INT TERM
    ;;
  activate)
    [[ -d "$candidate" && -f "$state" ]] || { echo "Prepared release state is missing." >&2; exit 1; }
    if [[ -L "$app" && $(readlink -f "$app") == "$candidate" ]]; then exit 0; fi
    previous=$(cat "$state")
    if [[ "$previous" == REAL_APP ]]; then
      legacy=$releases/legacy-$release_id
      [[ ! -e "$legacy" ]] || { echo "Legacy release path already exists." >&2; exit 1; }
      mv "$app" "$legacy"
      previous=$legacy
      printf '%s\n' "$previous" > "$state.new"
      mv -f "$state.new" "$state"
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
    rm -rf -- "$staging"
    ;;
  *)
    echo "Usage: deploy_incus_remote.sh {prepare|activate|rollback|cleanup} RELEASE_SHA256 INSTANCE STAGING" >&2
    exit 2
    ;;
esac
