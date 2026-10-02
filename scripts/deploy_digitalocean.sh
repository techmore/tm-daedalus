#!/bin/sh
set -eu

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$project_dir"
export COMPOSE_PROJECT_NAME=daedalus

if ! command -v docker >/dev/null 2>&1; then
  echo "Docker is required. Install Docker Engine and Docker Compose first." >&2
  exit 1
fi
if docker compose version >/dev/null 2>&1; then
  compose() { docker compose "$@"; }
elif command -v docker-compose >/dev/null 2>&1; then
  compose() { docker-compose "$@"; }
else
  echo "Docker Compose is required (docker compose or docker-compose)." >&2
  exit 1
fi
if [ ! -f .env.production ]; then
  echo "Create .env.production from .env.production.example and configure the real hostnames and credentials." >&2
  exit 1
fi

python3 scripts/check_production_env.py .env.production
compose --env-file .env.production config --quiet
# Include stopped containers: an unavailable deployment must never be mistaken
# for a first install and updated without a recoverable copy of its data.
if ! existing_ids=$(compose --env-file .env.production ps -a -q daedalus); then
  echo "Cannot inspect the existing Daedalus deployment. Update refused. Check Docker/Compose access and take a verified local backup or use the documented offline recovery workflow." >&2
  exit 1
fi
if [ -n "$existing_ids" ]; then
  # The service is single-instance; ambiguous state needs operator recovery.
  set -- $existing_ids
  if [ "$#" -ne 1 ]; then
    echo "Multiple Daedalus containers found. Update refused. Resolve deployment state and take a verified local backup before retrying." >&2
    exit 1
  fi
  if ! existing_running=$(docker inspect --format '{{.State.Running}}' "$1" 2>/dev/null); then
    echo "Cannot inspect the existing Daedalus container. Update refused. Restore access and take a verified local backup or use the documented offline recovery workflow." >&2
    exit 1
  fi
  if [ "$existing_running" != "true" ]; then
    echo "Existing Daedalus container is stopped or unavailable. Update refused. Recover it to run scripts/backup_digitalocean.sh, or take a verified offline backup before following the documented recovery workflow." >&2
    exit 1
  fi
  if ! sh scripts/backup_digitalocean.sh; then
    echo "Pre-update backup failed. Update refused; no build or replacement was started. Check backup access/storage and retry scripts/backup_digitalocean.sh before deploying." >&2
    exit 1
  fi
else
  echo "No existing Daedalus container found; proceeding with first deployment."
fi
compose --env-file .env.production build daedalus
compose --env-file .env.production up -d
daedalus_id=$(compose --env-file .env.production ps -q daedalus)
caddy_id=$(compose --env-file .env.production ps -q caddy)
python3 scripts/wait_deployment.py "$daedalus_id" "$caddy_id"
python3 scripts/check_public_deployment.py .env.production
compose --env-file .env.production ps
