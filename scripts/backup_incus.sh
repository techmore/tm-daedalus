#!/bin/sh
set -eu

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$project_dir"

incus_host=${DAEDALUS_INCUS_HOST:-}
instance=${DAEDALUS_INCUS_INSTANCE:-daedalus-prod}
if [ -z "$incus_host" ]; then
  echo "Set DAEDALUS_INCUS_HOST to the SSH destination for your Incus host." >&2
  exit 2
fi
case "$instance" in
  *[!A-Za-z0-9_-]*|'') echo "Invalid Incus instance name." >&2; exit 2 ;;
esac

backup_dir=${DAEDALUS_BACKUP_DIR:-"$project_dir/backups/incus-production"}
mkdir -p "$backup_dir"
chmod 700 "$backup_dir"
temporary=$(mktemp "$backup_dir/.daedalus-backup.XXXXXX")
trap 'rm -f "$temporary"' EXIT HUP INT TERM

backup_name=$(ssh "$incus_host" "incus exec $instance -- bash -lc 'set -a; . /etc/daedalus/production.env; set +a; cd /opt/daedalus/app; runuser -u daedalus -- .venv/bin/python scripts/backup_data.py'")
case "$backup_name" in
  daedalus-data-????????T??????Z.tar.gz) ;;
  *) echo "Incus backup command returned an unexpected filename." >&2; exit 1 ;;
esac

ssh "$incus_host" "incus file pull $instance/data/backups/$backup_name -" > "$temporary"
chmod 600 "$temporary"
python3 scripts/restore_data.py "$temporary" --verify-only
destination="$backup_dir/$backup_name"
if [ -e "$destination" ]; then
  echo "Backup destination already exists: $destination" >&2
  exit 1
fi
mv "$temporary" "$destination"
trap - EXIT HUP INT TERM
printf 'Verified off-host backup: %s\n' "$destination"
