"""Storage guard and retention enforcement for Jarvis.

Monitors disk partition headroom and caps temporary artifact / cache growth
under ~/.jarvis-tools so the root filesystem never exhausts free space.
"""
from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path

STATE_ROOT = Path(os.environ.get("JARVIS_STATE", Path.home() / ".jarvis-tools"))
WARNING_FREE_GB = 15.0
CRITICAL_FREE_GB = 8.0
DEFAULT_STORAGE_LIMIT_MB = 2048  # 2 GB max for pruneable artifacts


def get_storage_status(path: Path | str | None = None) -> dict:
    """Check disk capacity and usage for the filesystem hosting state_root."""
    target = Path(path).resolve() if path else STATE_ROOT.resolve()
    try:
        usage = shutil.disk_usage(str(target))
    except OSError as error:
        return {
            "ok": False,
            "error": str(error),
            "free_gb": 0.0,
            "used_gb": 0.0,
            "total_gb": 0.0,
            "percent_used": 100.0,
            "warning": True,
            "critical": True,
        }

    total_gb = round(usage.total / (1024 ** 3), 2)
    used_gb = round(usage.used / (1024 ** 3), 2)
    free_gb = round(usage.free / (1024 ** 3), 2)
    percent_used = round((usage.used / usage.total) * 100, 1) if usage.total else 100.0

    return {
        "ok": True,
        "path": str(target),
        "total_gb": total_gb,
        "used_gb": used_gb,
        "free_gb": free_gb,
        "percent_used": percent_used,
        "warning": free_gb < WARNING_FREE_GB,
        "critical": free_gb < CRITICAL_FREE_GB,
    }


def enforce_retention(state_root: Path | str | None = None,
                      max_storage_mb: float = DEFAULT_STORAGE_LIMIT_MB) -> dict:
    """Prune oldest non-essential cache files if state directory exceeds quota."""
    root = Path(state_root).resolve() if state_root else STATE_ROOT.resolve()
    if not root.is_dir():
        return {"ok": True, "pruned_bytes": 0, "pruned_files": 0}

    max_bytes = int(max_storage_mb * 1024 * 1024)
    # Prunable directories in priority order (temporary artifacts first)
    prune_targets = ("trash", "background", "evidence", "watch-pages", "backups")
    candidates = []

    for name in prune_targets:
        folder = root / name
        if not folder.is_dir():
            continue
        try:
            for item in folder.iterdir():
                # Keep the very latest db backup safe
                if name == "backups" and item.name.startswith("db-"):
                    continue
                try:
                    stat = item.stat()
                    candidates.append((stat.st_mtime, stat.st_size, item))
                except OSError:
                    continue
        except OSError:
            continue

    total_size = sum(size for _, size, _ in candidates)
    pruned_bytes = 0
    pruned_files = 0

    if total_size > max_bytes:
        # Sort oldest first
        candidates.sort(key=lambda row: row[0])
        for _, size, path in candidates:
            if total_size - pruned_bytes <= max_bytes:
                break
            try:
                if path.is_dir():
                    shutil.rmtree(path, ignore_errors=True)
                else:
                    path.unlink(missing_ok=True)
                pruned_bytes += size
                pruned_files += 1
            except OSError as error:
                print(f"[storage_guard] could not prune {path}: {error}", file=sys.stderr)

    return {
        "ok": True,
        "storage_status": get_storage_status(root),
        "initial_bytes": total_size,
        "pruned_bytes": pruned_bytes,
        "pruned_files": pruned_files,
    }
