#!/bin/sh
set -eu
umask 077

fail() {
  printf '%s\n' "$1" >&2
  exit 1
}

reject_symlink() {
  [ ! -L "$1" ] || fail "Refusing to install through a symbolic link: $1"
}

if [ "$#" -ne 2 ]; then
  fail "Usage: sh install-service-macos.sh <Daedalus HTTPS URL> <scanner name>"
fi

case "$(uname -s)" in
  Darwin) ;;
  *) fail "The managed scanner service installer currently supports macOS. Use install.sh for a foreground Linux bridge." ;;
esac

DAEDALUS_SERVER=$1
AGENT_NAME=$2
case "$DAEDALUS_SERVER" in
  https://*) ;;
  http://127.0.0.1:*|http://localhost:*) ;;
  *) fail "Use HTTPS for remote Daedalus servers. HTTP is allowed only for loopback demos." ;;
esac

PYTHON_BIN=${PYTHON_BIN:-python3}
NMAPUI_PORT=${NMAPUI_PORT:-9000}
NMAPUI_URL="http://127.0.0.1:$NMAPUI_PORT"
case "$NMAPUI_PORT" in
  ''|*[!0-9]*) fail "NMAPUI_PORT must be a number from 1 to 65535." ;;
esac
[ "$NMAPUI_PORT" -ge 1 ] && [ "$NMAPUI_PORT" -le 65535 ] \
  || fail "NMAPUI_PORT must be a number from 1 to 65535."
command -v "$PYTHON_BIN" >/dev/null 2>&1 || fail "Python 3.11 or newer is required."
"$PYTHON_BIN" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)' \
  || fail "Python 3.11 or newer is required."
command -v nmap >/dev/null 2>&1 || fail "Nmap is required. Install it with 'brew install nmap'."
command -v unzip >/dev/null 2>&1 || fail "unzip is required to prepare the NmapUI source."
command -v launchctl >/dev/null 2>&1 || fail "launchctl is required to install the managed scanner service."
command -v plutil >/dev/null 2>&1 || fail "plutil is required to validate the generated LaunchAgents."

if [ -n "${NMAPUI_USERNAME:-}" ] || [ -n "${NMAPUI_PASSWORD:-}" ]; then
  [ -n "${NMAPUI_USERNAME:-}" ] && [ -n "${NMAPUI_PASSWORD:-}" ] \
    || fail "Set both NMAPUI_USERNAME and NMAPUI_PASSWORD, or leave both unset."
fi

APP_SUPPORT="$HOME/Library/Application Support/Daedalus"
NMAPUI_DATA_ROOT="$APP_SUPPORT/nmapui-data"
NMAPUI_RELEASES="$APP_SUPPORT/nmapui/releases"
BRIDGE_INSTALL_ROOT="$APP_SUPPORT/scanner-bridge"
BRIDGE_SOURCE="$BRIDGE_INSTALL_ROOT/src/daedalus"
BRIDGE_VENV="$BRIDGE_INSTALL_ROOT/.venv"
CONFIG_PATH="$APP_SUPPORT/managed-agent.json"
LOG_DIR="$APP_SUPPORT/logs"
LAUNCHD_DIR="$HOME/Library/LaunchAgents"
NMAPUI_LABEL="org.daedalus.nmapui"
BRIDGE_LABEL="org.daedalus.scanner-bridge"
NMAPUI_PLIST="$LAUNCHD_DIR/$NMAPUI_LABEL.plist"
BRIDGE_PLIST="$LAUNCHD_DIR/$BRIDGE_LABEL.plist"
LAUNCHD_DOMAIN="gui/$(id -u)"

reject_symlink "$HOME/Library"
reject_symlink "$HOME/Library/Application Support"
reject_symlink "$APP_SUPPORT"
reject_symlink "$NMAPUI_DATA_ROOT"
reject_symlink "$NMAPUI_RELEASES"
reject_symlink "$BRIDGE_INSTALL_ROOT"
for bridge_path in "$BRIDGE_INSTALL_ROOT/src" "$BRIDGE_SOURCE" "$BRIDGE_VENV" "$BRIDGE_INSTALL_ROOT/pyproject.toml" "$BRIDGE_SOURCE/__init__.py" "$BRIDGE_SOURCE/agent.py" "$BRIDGE_SOURCE/command_journal.py" "$BRIDGE_SOURCE/scanner_activity.py" "$BRIDGE_SOURCE/scanner_delivery.py" "$APP_SUPPORT/nmapui" "$LOG_DIR" "$NMAPUI_DATA_ROOT/data" "$NMAPUI_DATA_ROOT/logs"; do
  reject_symlink "$bridge_path"
done
reject_symlink "$LAUNCHD_DIR"

for existing_path in "$CONFIG_PATH" "$NMAPUI_PLIST" "$BRIDGE_PLIST"; do
  [ ! -e "$existing_path" ] && [ ! -L "$existing_path" ] \
    || fail "A managed scanner installation already exists at $existing_path."
done

if "$PYTHON_BIN" - "$NMAPUI_PORT" <<'PY'
import socket
import sys

with socket.socket() as connection:
    connection.settimeout(1)
    try:
        connection.connect(("127.0.0.1", int(sys.argv[1])))
    except OSError:
        raise SystemExit(1)
raise SystemExit(0)
PY
then
  fail "Port $NMAPUI_PORT is already in use. Stop the existing NmapUI service or choose another NMAPUI_PORT."
fi

NMAPUI_LOADED=0
BRIDGE_LOADED=0
CONFIG_CREATED=0
NMAPUI_PLIST_CREATED=0
BRIDGE_PLIST_CREATED=0
rollback_failed_install() {
  setup_status=$?
  trap - EXIT
  if [ "$setup_status" -ne 0 ]; then
    if [ "$BRIDGE_LOADED" -eq 1 ]; then
      launchctl bootout "$LAUNCHD_DOMAIN" "$BRIDGE_PLIST" >/dev/null 2>&1 || true
    fi
    if [ "$NMAPUI_LOADED" -eq 1 ]; then
      launchctl bootout "$LAUNCHD_DOMAIN" "$NMAPUI_PLIST" >/dev/null 2>&1 || true
    fi
    if [ "$CONFIG_CREATED" -eq 1 ]; then
      printf '%s\n' "Managed scanner setup failed after enrollment; create a new enrollment code before retrying." >&2
    fi
    set --
    [ "$CONFIG_CREATED" -eq 0 ] || set -- "$@" "$CONFIG_PATH"
    [ "$NMAPUI_PLIST_CREATED" -eq 0 ] || set -- "$@" "$NMAPUI_PLIST"
    [ "$BRIDGE_PLIST_CREATED" -eq 0 ] || set -- "$@" "$BRIDGE_PLIST"
    "$PYTHON_BIN" - "$@" <<'PY'
from pathlib import Path
import sys
for value in sys.argv[1:]:
    Path(value).unlink(missing_ok=True)
PY
  fi
  exit "$setup_status"
}
trap rollback_failed_install EXIT

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
SOURCE_ARCHIVE="$SCRIPT_DIR/nmapui-source.zip"
[ -f "$SOURCE_ARCHIVE" ] || fail "NmapUI source archive is missing from this scanner kit."

if command -v shasum >/dev/null 2>&1; then
  SOURCE_HASH=$(shasum -a 256 "$SOURCE_ARCHIVE" | awk '{print $1}')
elif command -v sha256sum >/dev/null 2>&1; then
  SOURCE_HASH=$(sha256sum "$SOURCE_ARCHIVE" | awk '{print $1}')
else
  fail "A SHA-256 utility is required to identify the NmapUI source bundle."
fi
RELEASE_DIR="$NMAPUI_RELEASES/$SOURCE_HASH"
SOURCE_DIR="$RELEASE_DIR/daedalus-nmapui-source"
NMAPUI_VENV="$RELEASE_DIR/.venv"
NMAPUI_PYTHON="$NMAPUI_VENV/bin/python"
PLAYWRIGHT_DIR="$RELEASE_DIR/playwright-browsers"
NMAPUI_LOG_DIR="$NMAPUI_DATA_ROOT/logs"

mkdir -p "$APP_SUPPORT" "$NMAPUI_DATA_ROOT" "$LOG_DIR" "$LAUNCHD_DIR"
chmod 700 "$APP_SUPPORT" "$NMAPUI_DATA_ROOT" "$LOG_DIR"
NMAPUI_PORT="$NMAPUI_PORT" NMAPUI_URL="$NMAPUI_URL" \
  DAEDALUS_NMAPUI_DATA_ROOT="$NMAPUI_DATA_ROOT" \
  sh "$SCRIPT_DIR/install-nmapui.sh" --prepare-only
[ -f "$SOURCE_DIR/app.py" ] || fail "Prepared NmapUI source is missing its Flask application."
[ -x "$NMAPUI_PYTHON" ] || fail "Prepared NmapUI Python environment is missing."

mkdir -p "$BRIDGE_SOURCE"
chmod 700 "$BRIDGE_INSTALL_ROOT" "$BRIDGE_INSTALL_ROOT/src" "$BRIDGE_SOURCE"
cp -f "$SCRIPT_DIR/pyproject.toml" "$BRIDGE_INSTALL_ROOT/pyproject.toml"
cp -f "$SCRIPT_DIR/src/daedalus/__init__.py" "$BRIDGE_SOURCE/__init__.py"
cp -f "$SCRIPT_DIR/src/daedalus/agent.py" "$BRIDGE_SOURCE/agent.py"
cp -f "$SCRIPT_DIR/src/daedalus/command_journal.py" "$BRIDGE_SOURCE/command_journal.py"
cp -f "$SCRIPT_DIR/src/daedalus/scanner_activity.py" "$BRIDGE_SOURCE/scanner_activity.py"
cp -f "$SCRIPT_DIR/src/daedalus/scanner_delivery.py" "$BRIDGE_SOURCE/scanner_delivery.py"
"$PYTHON_BIN" -m venv "$BRIDGE_VENV"
"$BRIDGE_VENV/bin/python" -m pip install --disable-pip-version-check "$BRIDGE_INSTALL_ROOT"

"$BRIDGE_VENV/bin/daedalus-agent" \
  --server "$DAEDALUS_SERVER" \
  --nmapui-url "$NMAPUI_URL" \
  --name "$AGENT_NAME" \
  --config-path "$CONFIG_PATH" \
  --nmapui-service-label "$NMAPUI_LABEL" \
  --enroll-only
CONFIG_CREATED=1

NMAPUI_MANAGEMENT_PORTAL_URL="$DAEDALUS_SERVER" "$PYTHON_BIN" "$SCRIPT_DIR/macos_service.py" nmapui \
  --output "$NMAPUI_PLIST" --exclusive \
  --python "$NMAPUI_PYTHON" \
  --app-dir "$SOURCE_DIR" \
  --data-dir "$NMAPUI_DATA_ROOT" \
  --log-dir "$NMAPUI_LOG_DIR" \
  --browser-dir "$PLAYWRIGHT_DIR" \
  --port "$NMAPUI_PORT"
NMAPUI_PLIST_CREATED=1
"$PYTHON_BIN" "$SCRIPT_DIR/macos_service.py" bridge \
  --output "$BRIDGE_PLIST" --exclusive \
  --agent-executable "$BRIDGE_VENV/bin/daedalus-agent" \
  --config-path "$CONFIG_PATH" \
  --install-dir "$BRIDGE_INSTALL_ROOT" \
  --log-dir "$LOG_DIR"
BRIDGE_PLIST_CREATED=1
plutil -lint "$NMAPUI_PLIST" >/dev/null || fail "Generated NmapUI LaunchAgent is invalid."
plutil -lint "$BRIDGE_PLIST" >/dev/null || fail "Generated bridge LaunchAgent is invalid."

launchctl bootstrap "$LAUNCHD_DOMAIN" "$NMAPUI_PLIST"
NMAPUI_LOADED=1
"$PYTHON_BIN" - "$NMAPUI_URL" <<'PY'
import base64
import json
import os
import sys
import time
from urllib.error import URLError
from urllib.request import Request, urlopen

url = sys.argv[1].rstrip("/") + "/api/health/ready"
auth = os.environ.get("NMAPUI_USERNAME", "")
password = os.environ.get("NMAPUI_PASSWORD", "")
deadline = time.monotonic() + 60
while time.monotonic() < deadline:
    request = Request(url)
    if auth and password:
        token = base64.b64encode(f"{auth}:{password}".encode()).decode()
        request.add_header("Authorization", f"Basic {token}")
    try:
        with urlopen(request, timeout=3) as response:
            body = json.load(response)
        if body.get("status") == "ready" and body.get("ready") is True:
            raise SystemExit(0)
    except (URLError, TimeoutError, ValueError):
        pass
    time.sleep(1)
raise SystemExit("Managed NmapUI did not become ready within 60 seconds.")
PY

launchctl bootstrap "$LAUNCHD_DOMAIN" "$BRIDGE_PLIST"
BRIDGE_LOADED=1
launchctl print "$LAUNCHD_DOMAIN/$BRIDGE_LABEL" >/dev/null \
  || fail "The Daedalus bridge LaunchAgent did not load."
trap - EXIT HUP INT TERM
printf 'NmapUI and the Daedalus bridge are installed as user LaunchAgents.\n'
printf 'NmapUI is available on loopback at %s. Agent config: %s\n' "$NMAPUI_URL" "$CONFIG_PATH"
printf 'Both services start at login and restart after a process exit.\n'
