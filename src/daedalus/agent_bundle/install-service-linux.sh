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

[ "$#" -eq 2 ] || fail "Usage: sh install-service-linux.sh <Daedalus HTTPS URL> <scanner name>"
case "$(uname -s)" in Linux) ;; *) fail "The managed scanner service installer requires Linux with a systemd user manager." ;; esac

DAEDALUS_SERVER=$1
AGENT_NAME=$2
case "$DAEDALUS_SERVER" in
  https://*) ;;
  http://127.0.0.1:*|http://localhost:*) ;;
  *) fail "Use HTTPS for remote Daedalus servers. HTTP is allowed only for loopback demos." ;;
esac

PYTHON_BIN=${PYTHON_BIN:-python3}
NMAPUI_PORT=${NMAPUI_PORT:-9000}
case "$NMAPUI_PORT" in ''|*[!0-9]*) fail "NMAPUI_PORT must be a number from 1 to 65535." ;; esac
[ "$NMAPUI_PORT" -ge 1 ] && [ "$NMAPUI_PORT" -le 65535 ] || fail "NMAPUI_PORT must be a number from 1 to 65535."
NMAPUI_URL="http://127.0.0.1:$NMAPUI_PORT"
command -v "$PYTHON_BIN" >/dev/null 2>&1 || fail "Python 3.11 or newer is required."
"$PYTHON_BIN" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)' || fail "Python 3.11 or newer is required."
command -v nmap >/dev/null 2>&1 || fail "Nmap is required. Install it with your Linux distribution package manager."
command -v unzip >/dev/null 2>&1 || fail "unzip is required to prepare the NmapUI source."
command -v systemctl >/dev/null 2>&1 || fail "systemctl is required for managed Linux services."
systemctl --user show-environment >/dev/null 2>&1 || fail "No active systemd user manager. Log in through a systemd user session before installing."
if [ -n "${NMAPUI_USERNAME:-}" ] || [ -n "${NMAPUI_PASSWORD:-}" ]; then
  [ -n "${NMAPUI_USERNAME:-}" ] && [ -n "${NMAPUI_PASSWORD:-}" ] || fail "Set both NMAPUI_USERNAME and NMAPUI_PASSWORD, or leave both unset."
fi
"$PYTHON_BIN" - <<'PY' || fail "NMAPUI Basic Authentication values cannot contain control characters."
import os
for name in ("NMAPUI_USERNAME", "NMAPUI_PASSWORD"):
    if any(ord(character) < 32 or ord(character) == 127 for character in os.environ.get(name, "")):
        raise SystemExit(1)
PY

XDG_DATA_HOME=${XDG_DATA_HOME:-"$HOME/.local/share"}
XDG_CONFIG_HOME=${XDG_CONFIG_HOME:-"$HOME/.config"}
APP_SUPPORT="$XDG_DATA_HOME/daedalus"
NMAPUI_DATA_ROOT="$APP_SUPPORT/nmapui-data"
NMAPUI_RELEASES="$APP_SUPPORT/nmapui/releases"
BRIDGE_INSTALL_ROOT="$APP_SUPPORT/scanner-bridge"
BRIDGE_SOURCE="$BRIDGE_INSTALL_ROOT/src/daedalus"
BRIDGE_VENV="$BRIDGE_INSTALL_ROOT/.venv"
CONFIG_DIR="$XDG_CONFIG_HOME/daedalus"
CONFIG_PATH="$CONFIG_DIR/managed-agent.json"
SYSTEMD_DIR="$XDG_CONFIG_HOME/systemd"
UNIT_DIR="$SYSTEMD_DIR/user"
ENV_FILE="$CONFIG_DIR/daedalus-nmapui.env"
STATE_FILE="$CONFIG_DIR/.daedalus-scanner-services.json"
NMAPUI_UNIT="$UNIT_DIR/daedalus-nmapui.service"
BRIDGE_UNIT="$UNIT_DIR/daedalus-scanner-bridge.service"
NMAPUI_LABEL=daedalus-nmapui.service
BRIDGE_LABEL=daedalus-scanner-bridge.service

for path in "$HOME/.local" "$XDG_DATA_HOME" "$APP_SUPPORT" "$NMAPUI_DATA_ROOT" "$APP_SUPPORT/nmapui" "$NMAPUI_RELEASES" "$BRIDGE_INSTALL_ROOT" "$BRIDGE_INSTALL_ROOT/src" "$BRIDGE_SOURCE" "$BRIDGE_VENV" "$XDG_CONFIG_HOME" "$CONFIG_DIR" "$SYSTEMD_DIR" "$UNIT_DIR"; do
  reject_symlink "$path"
done
for path in "$CONFIG_PATH" "$ENV_FILE" "$STATE_FILE" "$NMAPUI_UNIT" "$BRIDGE_UNIT"; do
  [ ! -e "$path" ] && [ ! -L "$path" ] || fail "A managed scanner installation already exists at $path. Use manage-service-linux.sh status, restart, or restore."
done

if "$PYTHON_BIN" - "$NMAPUI_PORT" <<'PY'
import socket, sys
with socket.socket() as connection:
    connection.settimeout(1)
    try:
        connection.connect(("127.0.0.1", int(sys.argv[1])))
    except OSError:
        raise SystemExit(1)
raise SystemExit(0)
PY
then
  fail "Port $NMAPUI_PORT is already in use. Stop the other service or choose a different NMAPUI_PORT."
fi

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
[ -f "$SCRIPT_DIR/nmapui-source.zip" ] || fail "NmapUI source archive is missing from this scanner kit."
[ -f "$SCRIPT_DIR/systemd_service.py" ] || fail "Daedalus systemd service helper is missing from this scanner kit."
NMAPUI_URL="$NMAPUI_URL" NMAPUI_PORT="$NMAPUI_PORT" DAEDALUS_NMAPUI_DATA_ROOT="$NMAPUI_DATA_ROOT" \
  sh "$SCRIPT_DIR/install-nmapui.sh" --prepare-only
SOURCE_HASH=$("$PYTHON_BIN" - "$SCRIPT_DIR/nmapui-source.zip" <<'PY'
import hashlib, pathlib, sys
print(hashlib.sha256(pathlib.Path(sys.argv[1]).read_bytes()).hexdigest())
PY
)
RELEASE_DIR="$NMAPUI_RELEASES/$SOURCE_HASH"
NMAPUI_PYTHON="$RELEASE_DIR/.venv/bin/python"
NMAPUI_APP_DIR="$RELEASE_DIR/daedalus-nmapui-source"
BROWSER_DIR="$RELEASE_DIR/playwright-browsers"
[ -x "$NMAPUI_PYTHON" ] && [ -f "$NMAPUI_APP_DIR/app.py" ] || fail "Prepared NmapUI release is incomplete."

mkdir -p "$CONFIG_DIR" "$UNIT_DIR" "$NMAPUI_DATA_ROOT" "$BRIDGE_SOURCE"
chmod 700 "$APP_SUPPORT" "$NMAPUI_DATA_ROOT" "$CONFIG_DIR" "$UNIT_DIR" "$BRIDGE_INSTALL_ROOT" "$BRIDGE_INSTALL_ROOT/src" "$BRIDGE_SOURCE"
cp -f "$SCRIPT_DIR/pyproject.toml" "$BRIDGE_INSTALL_ROOT/pyproject.toml"
cp -f "$SCRIPT_DIR/src/daedalus/__init__.py" "$BRIDGE_SOURCE/__init__.py"
cp -f "$SCRIPT_DIR/src/daedalus/agent.py" "$BRIDGE_SOURCE/agent.py"
cp -f "$SCRIPT_DIR/src/daedalus/command_journal.py" "$BRIDGE_SOURCE/command_journal.py"
"$PYTHON_BIN" -m venv "$BRIDGE_VENV"
"$BRIDGE_VENV/bin/python" -m pip install --disable-pip-version-check "$BRIDGE_INSTALL_ROOT"

printf 'Daedalus one-time enrollment code: '
"$BRIDGE_VENV/bin/daedalus-agent" --server "$DAEDALUS_SERVER" --nmapui-url "$NMAPUI_URL" \
  --name "$AGENT_NAME" --config-path "$CONFIG_PATH" --enroll-only \
  --nmapui-systemd-unit-dir "$UNIT_DIR" --nmapui-systemd-config-dir "$CONFIG_DIR"

"$PYTHON_BIN" "$SCRIPT_DIR/systemd_service.py" install \
  --unit-dir "$UNIT_DIR" --config-dir "$CONFIG_DIR" \
  --nmapui-python "$NMAPUI_PYTHON" --nmapui-app-dir "$NMAPUI_APP_DIR" \
  --nmapui-data-dir "$NMAPUI_DATA_ROOT" --browser-dir "$BROWSER_DIR" \
  --agent-executable "$BRIDGE_VENV/bin/daedalus-agent" --bridge-working-dir "$BRIDGE_INSTALL_ROOT" \
  --agent-config "$CONFIG_PATH" --port "$NMAPUI_PORT"

NMAPUI_START_ATTEMPTED=0
BRIDGE_START_ATTEMPTED=0
rollback_startup() {
  status=$?
  trap - EXIT HUP INT TERM
  if [ "$status" -ne 0 ]; then
    if [ "$BRIDGE_START_ATTEMPTED" -eq 1 ]; then
      systemctl --user stop "$BRIDGE_LABEL" >/dev/null 2>&1 || printf '%s\n' "Could not stop $BRIDGE_LABEL after failed startup; it may still be running." >&2
    fi
    if [ "$NMAPUI_START_ATTEMPTED" -eq 1 ]; then
      systemctl --user stop "$NMAPUI_LABEL" >/dev/null 2>&1 || printf '%s\n' "Could not stop $NMAPUI_LABEL after failed startup; it may still be running." >&2
    fi
    printf '%s\n' "Service startup failed. Private unit/config files and enrollment were retained; inspect with sh manage-service-linux.sh status, then retry with sh manage-service-linux.sh restart." >&2
  fi
  exit "$status"
}
trap rollback_startup EXIT HUP INT TERM

if command -v systemd-analyze >/dev/null 2>&1; then
  systemd-analyze verify "$NMAPUI_UNIT" "$BRIDGE_UNIT" || fail "Generated systemd unit validation failed."
fi
systemctl --user daemon-reload
NMAPUI_START_ATTEMPTED=1
systemctl --user enable --now "$NMAPUI_LABEL"
"$PYTHON_BIN" - "$NMAPUI_URL" <<'PY'
import base64, json, os, sys, time
from urllib.error import URLError
from urllib.request import Request, urlopen
url = sys.argv[1].rstrip("/") + "/api/health/ready"
username, password = os.environ.get("NMAPUI_USERNAME", ""), os.environ.get("NMAPUI_PASSWORD", "")
deadline = time.monotonic() + 60
while time.monotonic() < deadline:
    request = Request(url)
    if username and password:
        token = base64.b64encode(f"{username}:{password}".encode()).decode()
        request.add_header("Authorization", "Basic " + token)
    try:
        with urlopen(request, timeout=3) as response:
            payload = json.load(response)
        if payload.get("ready") is True and payload.get("status") == "ready":
            raise SystemExit(0)
    except (URLError, TimeoutError, ValueError):
        pass
    time.sleep(1)
raise SystemExit("Managed NmapUI did not become ready within 60 seconds.")
PY
BRIDGE_START_ATTEMPTED=1
systemctl --user enable --now "$BRIDGE_LABEL"
systemctl --user is-active --quiet "$NMAPUI_LABEL" || fail "NmapUI service is not active."
systemctl --user is-active --quiet "$BRIDGE_LABEL" || fail "Daedalus bridge service is not active."
trap - EXIT HUP INT TERM

printf 'NmapUI and Daedalus bridge are installed as systemd user services.\n'
printf 'NmapUI is bound to loopback at %s. Managed credentials and units are owner-only.\n' "$NMAPUI_URL"
printf 'Services start with the systemd user manager. For startup without an active login, an administrator may explicitly enable linger with: loginctl enable-linger %s\n' "$(id -un)"
printf 'The bridge check-in is visible in Daedalus; no inbound scanner port was opened.\n'
