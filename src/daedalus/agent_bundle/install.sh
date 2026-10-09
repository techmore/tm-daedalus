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
  fail "Usage: sh install.sh <Daedalus URL> <scanner name>"
fi

DAEDALUS_SERVER=$1
AGENT_NAME=$2
NMAPUI_URL=${NMAPUI_URL:-http://127.0.0.1:9000}
case "$DAEDALUS_SERVER" in
  https://*) ;;
  http://127.0.0.1:*|http://localhost:*) ;;
  *) fail "Use HTTPS for remote Daedalus servers. HTTP is allowed only for loopback demos." ;;
esac
case "$NMAPUI_URL" in
  http://127.0.0.1:*|http://localhost:*) ;;
  *) fail "The bridge may connect only to the local NmapUI service." ;;
esac

case "$(uname -s)" in
  Darwin)
    INSTALL_ROOT="$HOME/Library/Application Support/Daedalus/scanner-bridge"
    reject_symlink "$HOME/Library"
    reject_symlink "$HOME/Library/Application Support"
    reject_symlink "$HOME/Library/Application Support/Daedalus"
    reject_symlink "$INSTALL_ROOT"
    ;;
  Linux)
    DATA_HOME=${XDG_DATA_HOME:-$HOME/.local/share}
    INSTALL_ROOT="$DATA_HOME/daedalus/scanner-bridge"
    reject_symlink "$HOME/.local"
    reject_symlink "$DATA_HOME"
    reject_symlink "$DATA_HOME/daedalus"
    reject_symlink "$INSTALL_ROOT"
    ;;
  *)
    fail "The Daedalus scanner bridge supports macOS and Linux."
    ;;
esac

PYTHON_BIN=${PYTHON_BIN:-python3}
command -v "$PYTHON_BIN" >/dev/null 2>&1 || fail "Python 3.11 or newer is required."
"$PYTHON_BIN" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)' \
  || fail "Python 3.11 or newer is required."

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
for bridge_path in "$INSTALL_ROOT/src" "$INSTALL_ROOT/src/daedalus" "$INSTALL_ROOT/.venv" "$INSTALL_ROOT/pyproject.toml" "$INSTALL_ROOT/src/daedalus/__init__.py" "$INSTALL_ROOT/src/daedalus/agent.py" "$INSTALL_ROOT/src/daedalus/command_journal.py" "$INSTALL_ROOT/src/daedalus/scanner_activity.py" "$INSTALL_ROOT/src/daedalus/scanner_delivery.py"; do
  reject_symlink "$bridge_path"
done
mkdir -p "$INSTALL_ROOT/src/daedalus"
chmod 700 "$INSTALL_ROOT" "$INSTALL_ROOT/src" "$INSTALL_ROOT/src/daedalus"
cp -f "$SCRIPT_DIR/pyproject.toml" "$INSTALL_ROOT/pyproject.toml"
cp -f "$SCRIPT_DIR/src/daedalus/__init__.py" "$INSTALL_ROOT/src/daedalus/__init__.py"
cp -f "$SCRIPT_DIR/src/daedalus/agent.py" "$INSTALL_ROOT/src/daedalus/agent.py"
cp -f "$SCRIPT_DIR/src/daedalus/command_journal.py" "$INSTALL_ROOT/src/daedalus/command_journal.py"
cp -f "$SCRIPT_DIR/src/daedalus/scanner_activity.py" "$INSTALL_ROOT/src/daedalus/scanner_activity.py"
cp -f "$SCRIPT_DIR/src/daedalus/scanner_delivery.py" "$INSTALL_ROOT/src/daedalus/scanner_delivery.py"

"$PYTHON_BIN" -m venv "$INSTALL_ROOT/.venv"
"$INSTALL_ROOT/.venv/bin/python" -m pip install \
  --disable-pip-version-check "$INSTALL_ROOT"
exec "$INSTALL_ROOT/.venv/bin/daedalus-agent" \
  --server "$DAEDALUS_SERVER" \
  --nmapui-url "$NMAPUI_URL" \
  --name "$AGENT_NAME"
