"""Small periodic maintenance: SQLite backups and optional artifact retention.

Backups use SQLite's online backup API, so a WAL database can be copied while
the server is running. The thread is advisory: a failure is logged and never
stops the server.
"""
from __future__ import annotations

import json
import os
import shutil
import sqlite3
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

BACKUP_KEEP = 5
ARTIFACT_KEEP = 25
ARTIFACT_DAYS = 7
INTERVAL = 6 * 3600


def _databases(state_root: Path) -> list[Path]:
    names = ("sessions.db", "memory.db", "memory-vectors.db")
    paths = [state_root / name for name in names]
    paths.extend(sorted(state_root.glob("embeddings-*.db")))
    return [path for path in paths if path.is_file()]


def backup_databases(state_root: Path, keep: int = BACKUP_KEEP) -> dict:
    state_root = Path(state_root)
    sources = _databases(state_root)
    if not sources:
        return {"ok": True, "copied": 0, "dir": ""}
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    destination = state_root / "backups" / f"db-{stamp}"
    destination.mkdir(parents=True, exist_ok=True)
    destination.chmod(0o700)
    copied = 0
    for source in sources:
        target = destination / source.name
        try:
            source_conn = sqlite3.connect(f"file:{source}?mode=ro", uri=True, timeout=10)
            target_conn = sqlite3.connect(str(target))
            try:
                source_conn.backup(target_conn)
            finally:
                target_conn.close()
                source_conn.close()
            target.chmod(0o600)
            copied += 1
        except sqlite3.Error as error:
            print(f"[jarvis-maintenance] backup {source.name}: {error}", file=sys.stderr)
    folders = sorted((state_root / "backups").glob("db-*"), reverse=True)
    for old in folders[max(1, int(keep)):]:
        shutil.rmtree(old, ignore_errors=True)
    return {"ok": copied == len(sources), "copied": copied, "dir": str(destination)}


def prune_artifacts(root: Path, keep: int = ARTIFACT_KEEP, days: float = ARTIFACT_DAYS) -> dict:
    removed = 0
    for relative in ("artifacts/evidence", "artifacts/agent"):
        directory = Path(root) / relative
        if not directory.is_dir():
            continue
        cutoff = time.time() - max(0.0, days) * 86400
        rows = []
        for path in directory.iterdir():
            try:
                rows.append((path.stat().st_mtime, path))
            except OSError:
                continue
        rows.sort(reverse=True)
        for index, (mtime, path) in enumerate(rows):
            if index < keep or mtime >= cutoff:
                continue
            if path.is_dir():
                shutil.rmtree(path, ignore_errors=True)
            else:
                path.unlink(missing_ok=True)
            removed += 1
    return {"removed": removed}


def prune_tool_storage(state_root: Path, keep: int = 40, days: float = 14.0) -> dict:
    state_root = Path(state_root)
    protected: set[Path] = set()
    undo_path = state_root / "undo.json"
    if undo_path.is_file():
        try:
            entries = json.loads(undo_path.read_text(encoding="utf-8"))
            if isinstance(entries, list):
                for row in entries:
                    if not isinstance(row, dict):
                        continue
                    for key in ("backup", "trash"):
                        val = row.get(key)
                        if isinstance(val, str) and val.strip():
                            try:
                                protected.add(Path(val).resolve())
                            except OSError:
                                pass
        except (OSError, ValueError, UnicodeError):
            pass

    removed = 0
    cutoff = time.time() - max(0.0, float(days)) * 86400
    for subdir, skip_db_dirs in (("backups", True), ("trash", False), ("background", False)):
        directory = state_root / subdir
        if not directory.is_dir():
            continue
        rows = []
        for path in directory.iterdir():
            if skip_db_dirs and path.name.startswith("db-"):
                continue
            try:
                if path.resolve() in protected:
                    continue
                rows.append((path.stat().st_mtime, path))
            except OSError:
                continue
        rows.sort(reverse=True)
        for index, (mtime, path) in enumerate(rows):
            if index < keep or mtime >= cutoff:
                continue
            if path.is_dir():
                shutil.rmtree(path, ignore_errors=True)
            else:
                path.unlink(missing_ok=True)
            removed += 1
    return {"removed": removed}


def trim_memory() -> bool:
    try:
        import ctypes
        return bool(ctypes.CDLL('libc.so.6').malloc_trim(0))
    except Exception:
        return False


def run_once(root: Path, state_root: Path) -> dict:
    result = {
        "backup": backup_databases(Path(state_root)),
        "tool_storage": prune_tool_storage(Path(state_root)),
        "memory_trimmed": trim_memory(),
    }
    try:
        import storage_guard
        result["storage"] = storage_guard.enforce_retention(Path(state_root))
    except Exception as error:
        result["storage"] = {"ok": False, "error": str(error)}
    if os.environ.get("JARVIS_ARTIFACT_PRUNE", "0") == "1":
        result["artifacts"] = prune_artifacts(Path(root))
    try:
        import checkpoint_maintenance
        result["checkpoints"] = checkpoint_maintenance.auto_prune_from_env(
            Path(state_root) / "checkpoints")
    except Exception as error:
        result["checkpoints"] = {"skipped": True,
                                 "error": f"{type(error).__name__}: {error}"[:200]}
    return result


def start_background(root: Path, state_root: Path, interval: float = INTERVAL) -> threading.Thread:
    def loop():
        # Let boot health/self-mod reconcile finish before touching files.
        time.sleep(min(60.0, interval))
        while True:
            try:
                run_once(Path(root), Path(state_root))
            except Exception as error:
                print(f"[jarvis-maintenance] {type(error).__name__}: {error}", file=sys.stderr)
            time.sleep(max(60.0, float(interval)))

    thread = threading.Thread(target=loop, name="jarvis-maintenance", daemon=True)
    thread.start()
    return thread
