#!/usr/bin/env bash
# PyDPI one-command launcher for Linux and macOS.  Usage:  ./start_pydpi.sh [pydpi auto options]
set -e
cd "$(dirname "$0")"

PY=$(command -v python3 || command -v python || true)
[ -z "$PY" ] && { echo "ERROR: install Python 3.10 or newer first."; exit 1; }
"$PY" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' || { echo "ERROR: Python 3.10+ needed."; exit 1; }

# virtual environment: rebuild it if it is missing or broken
if ! .venv/bin/python -c "import sys" 2>/dev/null; then
    echo "Creating the project environment (.venv)..."
    rm -rf .venv
    "$PY" -m venv .venv
fi

# install PyDPI if needed
if ! .venv/bin/python -c "import pydpi, scapy, dpkt, cryptography, yaml, rich, typer" 2>/dev/null; then
    echo "Installing PyDPI and its libraries (first time only)..."
    .venv/bin/python -m pip install --quiet --upgrade pip
    .venv/bin/python -m pip install --quiet -e .
fi

# watching traffic needs root on Linux/macOS (not needed for --replay demos)
if [ "$(id -u)" -ne 0 ] && [[ " $* " != *" --replay "* ]]; then
    exec sudo .venv/bin/python -m pydpi auto "$@"
fi
exec .venv/bin/python -m pydpi auto "$@"
