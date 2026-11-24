#!/usr/bin/env python3
"""Central runtime paths for Jarvis.

Everything writable — the main ``config.json`` (which may hold provider API
keys), the credential store, databases, queues and other state — lives
OUTSIDE the project directory, so the repository itself can be published
as open source without leaking secrets or personal data.

Layout (all overridable with environment variables):

- ``JARVIS_CONFIG``  -> main config file (default ``$XDG_CONFIG_HOME/jarvis/config.json``)
- ``JARVIS_STATE``   -> state root (default ``~/.jarvis-tools``)
- ``JARVIS_VAULT``   -> markdown notes root indexed by ``build.py``
- ``XDG_CONFIG_HOME`` / ``XDG_DATA_HOME`` are honoured when set.
"""
from __future__ import annotations

import os
import shutil
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent

HOME = Path.home()


def xdg_config_home() -> Path:
    return Path(os.environ.get("XDG_CONFIG_HOME") or (HOME / ".config")).expanduser()


def xdg_data_home() -> Path:
    return Path(os.environ.get("XDG_DATA_HOME") or (HOME / ".local" / "share")).expanduser()


def default_config_path() -> Path:
    """Main config (may contain API keys) — never inside the project tree."""
    env = os.environ.get("JARVIS_CONFIG")
    if env:
        return Path(env).expanduser()
    return xdg_config_home() / "jarvis" / "config.json"


def default_state_root() -> Path:
    """State root (secrets metadata, databases, queues) — outside the project."""
    env = os.environ.get("JARVIS_STATE")
    if env:
        return Path(env).expanduser()
    return HOME / ".jarvis-tools"


def default_vault_root() -> Path:
    env = os.environ.get("JARVIS_VAULT")
    if env:
        return Path(env).expanduser()
    return HOME / "notes"


CONFIG_PATH = default_config_path()
STATE_ROOT = default_state_root()
VAULT_ROOT = default_vault_root()


def resolve_config_path(root: Path | None = None) -> Path:
    """Resolve the main config path for a given project root.

    Production runs (``root`` == this project's directory) always use the
    XDG location; a legacy ``<root>/config.json`` is migrated out of the
    project tree on first start. Test/dev runs with a different ``root``
    keep using ``<root>/config.json`` so temporary roots stay isolated.
    """
    root = Path(root).resolve() if root is not None else PROJECT_ROOT
    env = os.environ.get("JARVIS_CONFIG")
    if env:
        return Path(env).expanduser()
    target = xdg_config_home() / "jarvis" / "config.json"
    if root == PROJECT_ROOT:
        legacy = root / "config.json"
        if legacy.exists() and not target.exists():
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(legacy), str(target))
            try:
                target.chmod(0o600)
            except OSError:
                pass
        return target
    return root / "config.json"
