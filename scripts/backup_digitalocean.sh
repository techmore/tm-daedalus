#!/bin/sh
set -eu

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$project_dir"
export COMPOSE_PROJECT_NAME=daedalus

if [ ! -f .env.production ]; then
  echo "Create .env.production before backing up the deployment." >&2
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

backup_name=$(compose --env-file .env.production exec -T daedalus python /app/scripts/backup_data.py)
backup_dir=${DAEDALUS_BACKUP_DIR:-"$project_dir/backups"}
mkdir -p "$backup_dir"
chmod 700 "$backup_dir"
compose --env-file .env.production cp "daedalus:/data/backups/$backup_name" "$backup_dir/$backup_name"
chmod 600 "$backup_dir/$backup_name"
if ! python3 scripts/restore_data.py "$backup_dir/$backup_name" --verify-only; then
  echo "Copied backup failed archive, manifest, or SQLite verification; it cannot protect an update." >&2
  exit 1
fi
printf 'Created protected backup: %s/%s\n' "$backup_dir" "$backup_name"
