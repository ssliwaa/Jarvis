#!/usr/bin/env bash
# The local regression gate: static lint first, then the whole unit suite.
set -euo pipefail
cd "$(dirname "$0")/.."
.venv/bin/python scripts/lint.py
.venv/bin/python -m unittest discover -s tests
