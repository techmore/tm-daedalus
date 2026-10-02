#!/bin/sh
set -eu

cd "$(dirname "$0")/.."
uv sync
uv run python -m daedalus.server
