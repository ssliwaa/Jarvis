"""Shared atomic file write helper with optional chmod and backup retention.

Eliminates duplicated temp-file + chmod + os.replace boilerplate across
plan_files, operator_schedule, vault_health, and operator_tools.
"""
from __future__ import annotations

import json
import os
import shutil
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any


def atomic_write_bytes(
    target: Path,
    data: bytes,
    *,
    mode: int | None = 0o600,
    dir_mode: int | None = 0o700,
    backup_dir: Path | None = None,
) -> Path | None:
    """Write ``data`` to ``target`` atomically via a sibling temporary file.

    Refuses symbolic-link targets so a planted symlink never redirects writes.
    When ``backup_dir`` is provided and ``target`` already exists as a regular
    file, a private (0600) timestamped copy is saved before replacement.
    """
    target = Path(target)
    if target.is_symlink():
        raise OSError(f"Refusing to overwrite symbolic link: {target}")
    parent = target.parent
    if dir_mode is not None:
        parent.mkdir(mode=dir_mode, parents=True, exist_ok=True)
        try:
            parent.chmod(dir_mode)
        except OSError:
            pass
    else:
        parent.mkdir(parents=True, exist_ok=True)

    backup_path: Path | None = None
    if backup_dir is not None and target.is_file():
        bdir = Path(backup_dir)
        bdir.mkdir(mode=0o700, parents=True, exist_ok=True)
        backup_path = bdir / f"{int(time.time())}-{uuid.uuid4().hex[:8]}-{target.name}"
        shutil.copy2(target, backup_path)
        try:
            backup_path.chmod(0o600)
        except OSError:
            pass

    fd, tmp_name = tempfile.mkstemp(dir=str(parent), prefix=f".{target.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
        if mode is not None:
            os.chmod(tmp_name, mode)
        os.replace(tmp_name, target)
    except BaseException:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise
    return backup_path


def atomic_write_text(
    target: Path,
    text: str,
    *,
    encoding: str = "utf-8",
    mode: int | None = 0o600,
    dir_mode: int | None = 0o700,
    backup_dir: Path | None = None,
) -> Path | None:
    """UTF-8 wrapper around ``atomic_write_bytes``."""
    return atomic_write_bytes(
        target,
        str(text).encode(encoding),
        mode=mode,
        dir_mode=dir_mode,
        backup_dir=backup_dir,
    )


def atomic_write_json(
    target: Path,
    payload: Any,
    *,
    indent: int = 2,
    ensure_ascii: bool = True,
    mode: int | None = 0o600,
    dir_mode: int | None = 0o700,
) -> None:
    """Serialize ``payload`` as JSON and atomically replace ``target``."""
    serialized = json.dumps(payload, ensure_ascii=ensure_ascii, indent=indent) + "\n"
    atomic_write_text(target, serialized, mode=mode, dir_mode=dir_mode)
