#!/usr/bin/env bash
# Deploy the current commit to the throwaway `daedalus-test` Incus container on SER8.
# Demo mode only: seeded demo workspace, no production data, secrets or OAuth.
# Reach it through an SSH tunnel (the demo login only accepts loopback peers):
#   ssh -N -L 18101:127.0.0.1:18101 sdolbec-ser8   then open http://localhost:18101
set -euo pipefail

HOST="${DAEDALUS_PREVIEW_HOST:-sdolbec-ser8}"
CONTAINER="${DAEDALUS_PREVIEW_CONTAINER:-daedalus-test}"
PORT="${DAEDALUS_PREVIEW_PORT:-18101}"
REV="$(git rev-parse --short HEAD)"
ARCHIVE="daedalus-preview-${REV}.tar.gz"

git archive --format=tar.gz -o "/tmp/${ARCHIVE}" HEAD
scp -q "/tmp/${ARCHIVE}" "${HOST}:/tmp/${ARCHIVE}"
rm -f "/tmp/${ARCHIVE}"

ssh -o BatchMode=yes "${HOST}" bash -s -- "${CONTAINER}" "${ARCHIVE}" "${PORT}" "${REV}" <<'REMOTE'
set -euo pipefail
container="$1"; archive="$2"; port="$3"; rev="$4"
incus file push -q --mode 0644 "/tmp/${archive}" "${container}/tmp/${archive}"
rm -f "/tmp/${archive}"
incus exec "${container}" -- bash -s -- "${archive}" "${rev}" <<'INSIDE'
set -euo pipefail
archive="$1"; rev="$2"
release="/opt/daedalus/releases/${rev}"
rm -rf "${release}"; mkdir -p "${release}" /opt/daedalus/data
tar -xzf "/tmp/${archive}" -C "${release}"; rm -f "/tmp/${archive}"
python3 -m venv "${release}/.venv"
"${release}/.venv/bin/pip" install -q --require-hashes -r "${release}/requirements-production.txt"
ln -sfn "${release}" /opt/daedalus/app
if [ ! -f /etc/daedalus-preview.env ]; then
  umask 077
  cat > /etc/daedalus-preview.env <<ENV
DAEDALUS_ENV=development
DAEDALUS_DEMO_MODE=true
DAEDALUS_SESSION_SECRET=$(head -c 48 /dev/urandom | base64 | tr -d '\n/+=')
DAEDALUS_DATABASE_URL=sqlite:////opt/daedalus/data/daedalus.db
DAEDALUS_DATA_DIR=/opt/daedalus/data
DAEDALUS_REPORTS_DIR=/opt/daedalus/data/reports
DAEDALUS_BASE_URL=http://localhost:18101
ENV
fi
cat > /etc/systemd/system/daedalus-preview.service <<UNIT
[Unit]
Description=Daedalus UI preview (demo data only)
After=network-online.target

[Service]
User=daedalus
WorkingDirectory=/opt/daedalus/app
EnvironmentFile=/etc/daedalus-preview.env
ExecStart=/opt/daedalus/app/.venv/bin/python -m uvicorn daedalus.server:app --host 127.0.0.1 --port 8000 --app-dir src
Restart=on-failure
RestartSec=2
KillMode=mixed
TimeoutStopSec=10

[Install]
WantedBy=multi-user.target
UNIT
chown -R daedalus:daedalus /opt/daedalus
systemctl daemon-reload
systemctl enable -q daedalus-preview.service
systemctl stop daedalus-preview.service || true
# A previous release can outlive its unit (open live-update sockets); free the port first.
pkill -u daedalus -f 'uvicorn daedalus.server:app' || true
for _ in $(seq 1 5); do ss -ltn | grep -q '127.0.0.1:8000 ' || break; sleep 1; done
pkill -KILL -u daedalus -f 'uvicorn daedalus.server:app' || true
for _ in $(seq 1 5); do ss -ltn | grep -q '127.0.0.1:8000 ' || break; sleep 1; done
systemctl reset-failed daedalus-preview.service || true
systemctl start daedalus-preview.service
for _ in $(seq 1 30); do
  curl -fsS -o /dev/null http://127.0.0.1:8000/healthz 2>/dev/null && break
  sleep 1
done
sleep 3; systemctl is-active --quiet daedalus-preview.service && readlink /opt/daedalus/app | grep -q "${rev}" && curl -fsS http://127.0.0.1:8000/healthz >/dev/null && echo "preview healthy at ${rev}"
INSIDE
# Loopback-only forward on the SER8 host; peers arrive as 127.0.0.1 so the demo login works.
if ! incus config device show "${container}" | grep -q '^preview:'; then
  incus config device add "${container}" preview proxy listen="tcp:127.0.0.1:${port}" connect="tcp:127.0.0.1:8000" >/dev/null
fi
REMOTE
echo "Tunnel: ssh -N -L ${PORT}:127.0.0.1:${PORT} ${HOST}   then open http://localhost:${PORT}"
