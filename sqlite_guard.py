"""SQLite quarantine and private-state permissions.

WAL sidecars are part of the database. Renaming only ``name.db`` during a
corruption quarantine leaves ``name.db-wal`` behind; reopening the original
path can then discard the uncheckpointed WAL and lose the newest rows. Every
SQLite store in Jarvis uses these helpers so the sidecars move together.
"""
from __future__ import annotations

import os
import sqlite3
import sys
import time
from pathlib import Path

SIDECARS = ("-wal", "-shm", "-journal")
PRIVATE_DIRS = ("backups", "trash", "plans", "selfmod", "documents", "skills",
                "background", "agent", "rea")


def is_corruption(error: Exception) -> bool:
    """True for a torn/garbage SQLite file, not for a contented write lock."""
    text = f"{type(error).__name__}: {error}".casefold()
    return any(token in text for token in
               ("not a database", "malformed", "corrupt", "encrypted", "eof"))


def _fsync_dir(path: Path) -> None:
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except OSError:
        pass


def quarantine_database(path: Path, label: str = "database") -> Path:
    """Move a corrupt DB and all of its sidecars to timestamped names."""
    path = Path(path)
    stamp = f"{os.getpid()}-{time.time_ns()}"
    corrupt = path.with_name(f"{path.name}.corrupt-{stamp}")
    try:
        path.rename(corrupt)
    except OSError:
        pass
    for suffix in SIDECARS:
        sidecar = path.with_name(path.name + suffix)
        if not sidecar.exists():
            continue
        try:
            sidecar.rename(corrupt.with_name(corrupt.name + suffix))
        except OSError:
            pass
    _fsync_dir(path.parent)
    print(f"quarantined corrupt {label} database as {corrupt.name}", file=sys.stderr)
    return corrupt


def secure_database(path: Path) -> None:
    """Best-effort 0600 for the DB and its sidecars; 0700 for the parent."""
    path = Path(path)
    try:
        path.parent.chmod(0o700)
    except OSError:
        pass
    for candidate in (path, *(path.with_name(path.name + suffix) for suffix in SIDECARS)):
        try:
            if candidate.exists():
                candidate.chmod(0o600)
        except OSError:
            pass


def secure_state_root(root: Path) -> None:
    """Make ~/.jarvis-tools and its private subdirectories owner-only."""
    root = Path(root)
    try:
        root.mkdir(parents=True, exist_ok=True)
        root.chmod(0o700)
    except OSError:
        pass
    for name in PRIVATE_DIRS:
        candidate = root / name
        if candidate.is_dir():
            try:
                candidate.chmod(0o700)
            except OSError:
                pass
    try:
        for path in root.glob("*.db*"):
            if path.is_file():
                path.chmod(0o600)
    except OSError:
        pass


def connect_private(path: Path, *, timeout: float = 10.0) -> sqlite3.Connection:
    """Open a DB, quarantine a corrupt file, and secure the on-disk files."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        connection = sqlite3.connect(str(path), check_same_thread=False, timeout=timeout)
        secure_database(path)
        return connection
    except sqlite3.DatabaseError as error:
        if not is_corruption(error):
            raise
        quarantine_database(path)
        connection = sqlite3.connect(str(path), check_same_thread=False, timeout=timeout)
        secure_database(path)
        return connection
