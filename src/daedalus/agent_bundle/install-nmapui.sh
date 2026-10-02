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

PREPARE_ONLY=0
if [ "${1:-}" = "--prepare-only" ]; then
  PREPARE_ONLY=1
  shift
fi
[ "$#" -eq 0 ] || fail "Usage: sh install-nmapui.sh [--prepare-only]"

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
SOURCE_ARCHIVE="$SCRIPT_DIR/nmapui-source.zip"
PYTHON_BIN=${PYTHON_BIN:-python3}
NMAPUI_PORT=${NMAPUI_PORT:-9000}
NMAPUI_URL=${NMAPUI_URL:-http://127.0.0.1:$NMAPUI_PORT}

case "$NMAPUI_URL" in
  http://127.0.0.1:"$NMAPUI_PORT"|http://localhost:"$NMAPUI_PORT") ;;
  *) fail "NMAPUI_URL must use the local NmapUI service on port $NMAPUI_PORT." ;;
esac
case "$NMAPUI_PORT" in
  ''|*[!0-9]*) fail "NMAPUI_PORT must be a number from 1 to 65535." ;;
esac
[ "$NMAPUI_PORT" -ge 1 ] && [ "$NMAPUI_PORT" -le 65535 ] || fail "NMAPUI_PORT must be a number from 1 to 65535."
command -v "$PYTHON_BIN" >/dev/null 2>&1 || fail "Python 3.11 or newer is required."
"$PYTHON_BIN" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)' \
  || fail "Python 3.11 or newer is required."

if "$PYTHON_BIN" - "$NMAPUI_URL" <<'PY'
import base64
import json
import os
import sys
from urllib.request import Request, urlopen

try:
    request = Request(sys.argv[1].rstrip("/") + "/api/health/ready")
    username = os.environ.get("NMAPUI_USERNAME", "")
    password = os.environ.get("NMAPUI_PASSWORD", "")
    if username or password:
        if not username or not password:
            raise SystemExit(1)
        credentials = base64.b64encode(f"{username}:{password}".encode()).decode()
        request.add_header("Authorization", f"Basic {credentials}")
    with urlopen(request, timeout=2) as response:
        payload = json.load(response)
except Exception:
    raise SystemExit(1)
raise SystemExit(0 if payload.get("ready") is True and payload.get("status") == "ready" and payload.get("app_version") else 1)
PY
then
  printf 'NmapUI is already ready at %s; keeping the existing service.\n' "$NMAPUI_URL"
  exit 0
fi

case "$(uname -s)" in
  Darwin)
    APP_SUPPORT="$HOME/Library/Application Support/Daedalus"
    DATA_ROOT=${DAEDALUS_NMAPUI_DATA_ROOT:-"$APP_SUPPORT/nmapui-data"}
    reject_symlink "$HOME/Library"
    reject_symlink "$HOME/Library/Application Support"
    reject_symlink "$APP_SUPPORT"
    reject_symlink "$DATA_ROOT"
    ;;
  Linux)
    DATA_HOME=${XDG_DATA_HOME:-$HOME/.local/share}
    APP_SUPPORT="$DATA_HOME/daedalus"
    DATA_ROOT="$DATA_HOME/nmapui"
    reject_symlink "$HOME/.local"
    reject_symlink "$DATA_HOME"
    reject_symlink "$APP_SUPPORT"
    reject_symlink "$DATA_ROOT"
    ;;
  *)
    fail "The Daedalus NmapUI source kit supports macOS and Linux hosts."
    ;;
esac

command -v nmap >/dev/null 2>&1 || fail "Nmap is required. On macOS, install it with 'brew install nmap'."
command -v unzip >/dev/null 2>&1 || fail "unzip is required to prepare the NmapUI source."
[ -f "$SOURCE_ARCHIVE" ] || fail "NmapUI source archive is missing from this scanner kit."

if command -v shasum >/dev/null 2>&1; then
  SOURCE_HASH=$(shasum -a 256 "$SOURCE_ARCHIVE" | awk '{print $1}')
elif command -v sha256sum >/dev/null 2>&1; then
  SOURCE_HASH=$(sha256sum "$SOURCE_ARCHIVE" | awk '{print $1}')
else
  fail "A SHA-256 utility is required to identify the NmapUI source bundle."
fi

INSTALL_ROOT="$APP_SUPPORT/nmapui"
RELEASES="$INSTALL_ROOT/releases"
RELEASE_DIR="$RELEASES/$SOURCE_HASH"
SOURCE_DIR="$RELEASE_DIR/daedalus-nmapui-source"
VENV_DIR="$RELEASE_DIR/.venv"
reject_symlink "$INSTALL_ROOT"
reject_symlink "$RELEASES"
reject_symlink "$RELEASE_DIR"
reject_symlink "$SOURCE_DIR"
reject_symlink "$VENV_DIR"
reject_symlink "$DATA_ROOT/data"
reject_symlink "$DATA_ROOT/logs"
mkdir -p "$RELEASES" "$RELEASE_DIR" "$DATA_ROOT/data" "$DATA_ROOT/logs"
chmod 700 "$APP_SUPPORT" "$INSTALL_ROOT" "$RELEASES" "$RELEASE_DIR" "$DATA_ROOT" "$DATA_ROOT/data" "$DATA_ROOT/logs"

if [ ! -f "$SOURCE_DIR/app.py" ]; then
  STAGING=$(mktemp -d "$RELEASES/.stage.XXXXXX")
  trap 'rm -rf "$STAGING"' EXIT HUP INT TERM
  unzip -q "$SOURCE_ARCHIVE" -d "$STAGING"
  [ -f "$STAGING/daedalus-nmapui-source/app.py" ] \
    || fail "NmapUI source archive did not contain its Flask application."
  mv "$STAGING/daedalus-nmapui-source" "$SOURCE_DIR"
  rm -rf "$STAGING"
  trap - EXIT HUP INT TERM
fi

if [ ! -x "$VENV_DIR/bin/python" ]; then
  "$PYTHON_BIN" -m venv "$VENV_DIR"
fi
"$VENV_DIR/bin/python" -m pip install --disable-pip-version-check \
  -r "$SOURCE_DIR/requirements.txt"
PLAYWRIGHT_BROWSERS_PATH="$RELEASE_DIR/playwright-browsers" \
  "$VENV_DIR/bin/python" -m playwright install chromium

if [ "$PREPARE_ONLY" -eq 1 ]; then
  printf 'NmapUI prepared at %s for port %s.\n' "$SOURCE_DIR" "$NMAPUI_PORT"
  exit 0
fi

printf 'Starting NmapUI on %s (loopback only). Keep this Terminal window open.\n' "$NMAPUI_URL"
printf 'After readiness is reported, use a second Terminal to run the Daedalus bridge installer.\n'
cd "$SOURCE_DIR"
exec env \
  NMAPUI_DATA_DIR="$DATA_ROOT/data" \
  NMAPUI_LOG_DIR="$DATA_ROOT/logs" \
  NMAPUI_SKIP_LEGACY_MIGRATION=1 \
  NMAPUI_HOST=127.0.0.1 \
  NMAPUI_PORT="$NMAPUI_PORT" \
  NMAPUI_ENABLE_NETWORK_FINGERPRINT=false \
  NMAPUI_ENABLE_VULNERS=false \
  NMAPUI_ENABLE_UPDATE_CHECK=false \
  NMAPUI_ALLOW_UNSAFE_WERKZEUG=true \
  PLAYWRIGHT_BROWSERS_PATH="$RELEASE_DIR/playwright-browsers" \
  "$VENV_DIR/bin/python" app.py
