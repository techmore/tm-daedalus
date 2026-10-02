#!/bin/sh
# Explicit operator actions only. Preserve enrollment config, queues, scans and logs.
set -eu
umask 077
case "$(uname -s)" in
  Darwin) ;;
  *) printf '%s\n' 'Managed LaunchAgent lifecycle commands require macOS.' >&2; exit 1 ;;
esac
if [ "${1:-}" = upgrade ]; then
  [ "$#" -eq 2 ] || { printf '%s\n' 'Usage: sh manage-service-macos.sh upgrade <scanner-kit.zip>' >&2; exit 1; }
else
  [ "$#" -eq 1 ] || { printf '%s\n' 'Usage: sh manage-service-macos.sh status|restart|uninstall|restore' >&2; exit 1; }
  case "$1" in status|restart|uninstall|restore) ;; *) printf '%s\n' 'Unsupported managed service action.' >&2; exit 1 ;; esac
fi
PYTHON_BIN=${PYTHON_BIN:-python3}
command -v "$PYTHON_BIN" >/dev/null 2>&1 || { printf '%s\n' 'Python 3.11 or newer is required.' >&2; exit 1; }
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
if [ "$1" = upgrade ]; then
  exec "$PYTHON_BIN" "$SCRIPT_DIR/macos_service.py" manage upgrade --bundle "$2"
fi
exec "$PYTHON_BIN" "$SCRIPT_DIR/macos_service.py" manage "$1"
