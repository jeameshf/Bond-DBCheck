#!/usr/bin/env bash
cd "$(dirname "$0")"
PY="${PYTHON:-python3}"
"$PY" app.py "$@"
