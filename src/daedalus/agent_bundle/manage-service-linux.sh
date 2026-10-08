#!/bin/sh
set -eu
umask 077

fail() {
  printf '%s\n' "$1" >&2
  exit 1
}

case "$(uname -s)" in Linux) ;; *) fail "Managed systemd user service commands require Linux." ;; esac
[ "$#" -ge 1 ] || fail "Usage: sh manage-service-linux.sh status|restart|uninstall|restore|upgrade|upgrade-offline|upgrade-rollback [scanner-kit.zip]"
BUNDLE_PATH=${2:-}
if [ "$1" = upgrade ] || [ "$1" = upgrade-offline ]; then
  [ "$#" -eq 2 ] || fail "Usage: sh manage-service-linux.sh upgrade|upgrade-offline <scanner-kit.zip>"
else
  [ "$#" -eq 1 ] || fail "This action takes no bundle argument."
fi
case "$1" in status|restart|uninstall|restore|upgrade|upgrade-offline|upgrade-rollback) ACTION=$1 ;; *) fail "Supported actions are status, restart, uninstall, restore, upgrade, upgrade-offline and upgrade-rollback." ;; esac
PYTHON_BIN=${PYTHON_BIN:-python3}
command -v "$PYTHON_BIN" >/dev/null 2>&1 || fail "Python 3 is required."
command -v systemctl >/dev/null 2>&1 || fail "systemctl is required."
systemctl --user show-environment >/dev/null 2>&1 || fail "No active systemd user manager."

XDG_CONFIG_HOME=${XDG_CONFIG_HOME:-"$HOME/.config"}
UNIT_DIR="$XDG_CONFIG_HOME/systemd/user"
CONFIG_DIR="$XDG_CONFIG_HOME/daedalus"
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
if [ "$ACTION" = upgrade ] || [ "$ACTION" = upgrade-offline ] || [ "$ACTION" = upgrade-rollback ]; then
  XDG_DATA_HOME=${XDG_DATA_HOME:-"$HOME/.local/share"}
  if [ "$ACTION" = upgrade ] || [ "$ACTION" = upgrade-offline ]; then
    exec "$PYTHON_BIN" "$SCRIPT_DIR/linux_upgrade.py" "$ACTION" --bundle "$BUNDLE_PATH" --unit-dir "$UNIT_DIR" --config-dir "$CONFIG_DIR" --data-home "$XDG_DATA_HOME"
  fi
  exec "$PYTHON_BIN" "$SCRIPT_DIR/linux_upgrade.py" "$ACTION" --unit-dir "$UNIT_DIR" --config-dir "$CONFIG_DIR" --data-home "$XDG_DATA_HOME"
fi
if [ "$ACTION" = uninstall ] || [ "$ACTION" = restore ] || [ "$ACTION" = restart ]; then
  exec "$PYTHON_BIN" "$SCRIPT_DIR/systemd_service.py" "$ACTION" --unit-dir "$UNIT_DIR" --config-dir "$CONFIG_DIR"
fi
"$PYTHON_BIN" "$SCRIPT_DIR/systemd_service.py" verify --unit-dir "$UNIT_DIR" --config-dir "$CONFIG_DIR" >/dev/null \
  || fail "Managed service files are missing or changed; refusing to operate them."

NMAPUI_UNIT=daedalus-nmapui.service
BRIDGE_UNIT=daedalus-scanner-bridge.service

for unit in "$NMAPUI_UNIT" "$BRIDGE_UNIT"; do
  if systemctl --user is-active --quiet "$unit"; then active=active; else active=inactive; fi
  if systemctl --user is-enabled --quiet "$unit"; then enabled=enabled; else enabled=disabled; fi
  printf '%s: %s, %s\n' "$unit" "$active" "$enabled"
done
