#!/usr/bin/env bash
# One-command launcher for VulNova Observatory (macOS / Linux).
# Creates an isolated virtual env, installs the app, and starts the dashboard.
# Usage:  ./run.sh            (starts on http://127.0.0.1:5000)
#         ./run.sh --port 8080 --refresh-hours 6
set -euo pipefail

if [ ! -d ".venv" ]; then
    echo "[*] Creating virtual environment (.venv)..."
    python3 -m venv .venv
fi

echo "[*] Installing VulNova Observatory..."
./.venv/bin/python -m pip install --upgrade pip >/dev/null
./.venv/bin/python -m pip install . >/dev/null

echo "[*] Starting the dashboard..."
exec ./.venv/bin/python -m vulnova.cli web "$@"
