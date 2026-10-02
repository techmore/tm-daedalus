#!/bin/sh
set -eu

project_dir=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
nmapui_dir=$(CDPATH= cd -- "$project_dir/../NmapUI" && pwd)
nmapui_python="$nmapui_dir/.venv/bin/python"
demo_data="$project_dir/data/nmapui-demo"

if [ ! -x "$nmapui_python" ]; then
  echo "NmapUI's local virtual environment was not found at $nmapui_python" >&2
  exit 1
fi

mkdir -p "$demo_data"
cd "$nmapui_dir"
exec env \
  NMAPUI_DATA_DIR="$demo_data" \
  NMAPUI_SKIP_LEGACY_MIGRATION=1 \
  NMAPUI_HOST=127.0.0.1 \
  NMAPUI_PORT=9000 \
  NMAPUI_ENABLE_NETWORK_FINGERPRINT=false \
  NMAPUI_ENABLE_VULNERS=false \
  NMAPUI_ENABLE_UPDATE_CHECK=false \
  NMAPUI_ALLOW_UNSAFE_WERKZEUG=true \
  "$nmapui_python" app.py
