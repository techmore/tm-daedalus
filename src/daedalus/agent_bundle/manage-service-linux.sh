#!/bin/sh
set -eu
umask 077

fail() {
  printf '%s\n' "$1" >&2
  exit 1
}

case "$(uname -s)" in Linux) ;; *) fail "Managed systemd user service commands require Linux." ;; esac
[ "$#" -eq 1 ] || fail "Usage: sh manage-service-linux.sh status|restart|uninstall|restore"
case "$1" in status|restart|uninstall|restore) ACTION=$1 ;; *) fail "Supported actions are status, restart, uninstall and restore." ;; esac
PYTHON_BIN=${PYTHON_BIN:-python3}
command -v "$PYTHON_BIN" >/dev/null 2>&1 || fail "Python 3 is required."
command -v systemctl >/dev/null 2>&1 || fail "systemctl is required."
systemctl --user show-environment >/dev/null 2>&1 || fail "No active systemd user manager."

XDG_CONFIG_HOME=${XDG_CONFIG_HOME:-"$HOME/.config"}
UNIT_DIR="$XDG_CONFIG_HOME/systemd/user"
CONFIG_DIR="$XDG_CONFIG_HOME/daedalus"
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
if [ "$ACTION" = uninstall ] || [ "$ACTION" = restore ]; then
  exec "$PYTHON_BIN" "$SCRIPT_DIR/systemd_service.py" "$ACTION" --unit-dir "$UNIT_DIR" --config-dir "$CONFIG_DIR"
fi
"$PYTHON_BIN" "$SCRIPT_DIR/systemd_service.py" verify --unit-dir "$UNIT_DIR" --config-dir "$CONFIG_DIR" >/dev/null \
  || fail "Managed service files are missing or changed; refusing to operate them."

NMAPUI_UNIT=daedalus-nmapui.service
BRIDGE_UNIT=daedalus-scanner-bridge.service
if [ "$ACTION" = restart ]; then
  systemctl --user restart "$NMAPUI_UNIT"
  systemctl --user restart "$BRIDGE_UNIT"
fi

for unit in "$NMAPUI_UNIT" "$BRIDGE_UNIT"; do
  if systemctl --user is-active --quiet "$unit"; then active=active; else active=inactive; fi
  if systemctl --user is-enabled --quiet "$unit"; then enabled=enabled; else enabled=disabled; fi
  printf '%s: %s, %s\n' "$unit" "$active" "$enabled"
done
if [ "$ACTION" = restart ]; then
  printf '%s\n' 'Restart requested for the verified Daedalus user services; check NmapUI readiness and the next portal heartbeat.'
fi
