"""Locate Node for the JS contract tests without requiring it on PATH."""
from __future__ import annotations

import os
import shutil
from pathlib import Path


def node_binary() -> str | None:
    explicit = os.environ.get("JARVIS_NODE") or os.environ.get("NODE_BINARY")
    if explicit and Path(explicit).is_file():
        return explicit
    found = shutil.which("node")
    if found:
        return found
    home = Path.home()
    candidates = [
        *sorted((home / ".hermes/tools").glob("node-*/bin/node")),
        *sorted((home / ".nvm/versions/node").glob("*/bin/node")),
        home / ".volta/bin/node",
        home / ".local/bin/node",
        Path("/usr/local/bin/node"),
        Path("/usr/bin/node"),
    ]
    for candidate in reversed(candidates):
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
    return None
