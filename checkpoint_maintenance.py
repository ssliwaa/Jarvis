"""Retention and store status for Jarvis filesystem checkpoints.

Checkpoints are useful only while the store stays bounded.  This module deletes
per-project refs whose working directory is observably gone or whose last
touch is older than the retention window, then asks git to repack.  Orphan
deletion is opt-in for unattended maintenance: a missing workdir can mean a
deleted project or merely an unmounted volume, and deleting restore points on
that ambiguity would be worse than keeping them.

Adapted from Hermes Agent's ``tools/checkpoint_maintenance.py`` (MIT).  The
single-store layout has no pre-v2 migration branches.
"""
from __future__ import annotations

import logging
import os
import time
from pathlib import Path

from checkpoint_manager import (
    _GIT_TIMEOUT,
    _REFS_PREFIX,
    _STORE_DIRNAME,
    _dir_size_bytes,
    _index_path,
    _ledger_path,
    _list_projects,
    _project_meta_path,
    _ref_name,
    _run_git,
)
from checkpoint_pruning import PruneError, Pruner, store_lock

logger = logging.getLogger("jarvis.checkpoints")
_PRUNE_MARKER_NAME = ".last_prune"


def _delete_ref(store: Path, ref: str) -> bool:
    ok, _, _ = _run_git(["update-ref", "-d", ref], store, str(store.parent),
                        allowed_returncodes={128})
    return ok


def _dir_has_any_entry(directory: Path) -> bool:
    try:
        with os.scandir(directory) as entries:
            return next(entries, None) is not None
    except OSError:
        return False


def _workdir_is_observably_gone(
    workdir: str,
    parent_dev: int | None = None,
    parent_ino: int | None = None,
) -> bool:
    """True only when the project's absence is positively observed."""
    if not workdir:
        return False
    path = Path(workdir)
    try:
        if path.exists():
            return False
        parent = path.parent
        if parent == path or not parent.is_dir():
            return False
        if parent_dev is None or parent_ino is None:
            # No identity recorded: a detached volume and a deleted project
            # are indistinguishable. Retention still reclaims this later.
            return False
        stat_result = parent.stat()
        if (stat_result.st_dev, stat_result.st_ino) != (parent_dev, parent_ino):
            return False
        return _dir_has_any_entry(parent) or os.path.ismount(parent)
    except OSError:
        return False


def prune_checkpoints(
    retention_days: int = 30,
    delete_orphans: bool = False,
    checkpoint_base: Path | str | None = None,
    max_total_size_mb: int = 500,
    orphan_allowlist: set | None = None,
) -> dict:
    """Delete stale/orphan refs and reclaim store space.

    Returns ``{"scanned", "deleted_orphan", "deleted_stale", "errors",
    "bytes_freed"}``.  Never raises into a request path.
    """
    from checkpoint_manager import CheckpointManager

    base = Path(checkpoint_base or CheckpointManager().base).expanduser().resolve()
    result = {"scanned": 0, "deleted_orphan": 0, "deleted_stale": 0,
              "errors": 0, "bytes_freed": 0}
    if not base.exists():
        return result
    try:
        with store_lock(base):
            store = base / _STORE_DIRNAME
            if not (store / "HEAD").exists():
                return result
            before = _dir_size_bytes(base)
            cutoff = time.time() - max(0, int(retention_days)) * 86400 if retention_days else 0
            for meta in _list_projects(store):
                dir_hash = meta.get("_hash") or ""
                workdir = meta.get("workdir") or ""
                if not dir_hash:
                    continue
                result["scanned"] += 1
                reason = None
                parent_dev = meta.get("workdir_parent_dev")
                parent_ino = meta.get("workdir_parent_ino")
                if (delete_orphans
                        and (not workdir or _workdir_is_observably_gone(
                            workdir,
                            parent_dev if isinstance(parent_dev, int) else None,
                            parent_ino if isinstance(parent_ino, int) else None,
                        ))
                        and (orphan_allowlist is None or dir_hash in orphan_allowlist)):
                    reason = "orphan"
                elif retention_days > 0:
                    last_touch = float(meta.get("last_touch", 0) or 0)
                    if last_touch > 0 and last_touch < cutoff:
                        reason = "stale"
                if reason is None:
                    continue
                if not _delete_ref(store, _ref_name(dir_hash)):
                    result["errors"] += 1
                    continue
                for path in (_index_path(store, dir_hash),
                             _project_meta_path(store, dir_hash),
                             _ledger_path(store, dir_hash)):
                    try:
                        path.unlink(missing_ok=True)
                    except OSError:
                        pass
                result[f"deleted_{reason}"] += 1
            pruner = Pruner(_run_git, store, str(base), _GIT_TIMEOUT,
                            _dir_size_bytes, _REFS_PREFIX)
            try:
                if result["deleted_orphan"] or result["deleted_stale"] or pruner.gc_pending():
                    pruner.reclaim()
                if not pruner.enforce_size(max(0, int(max_total_size_mb)) * 1024 * 1024):
                    result["errors"] += 1
            except (PruneError, OSError) as error:
                result["errors"] += 1
                logger.warning("checkpoint pruning stopped: %s", error)
            result["bytes_freed"] = max(0, before - _dir_size_bytes(base))
    except (PruneError, OSError) as error:
        result["errors"] += 1
        logger.warning("checkpoint maintenance stopped: %s", error)
    return result


def maybe_auto_prune_checkpoints(
    retention_days: int = 30,
    min_interval_hours: int = 24,
    delete_orphans: bool = False,
    checkpoint_base: Path | str | None = None,
    max_total_size_mb: int = 500,
) -> dict:
    """Idempotent periodic maintenance; writes ``.last_prune`` on claim."""
    from checkpoint_manager import CheckpointManager

    base = Path(checkpoint_base or CheckpointManager().base).expanduser().resolve()
    output: dict = {"skipped": False}
    if not base.exists():
        output["result"] = {"scanned": 0, "deleted_orphan": 0, "deleted_stale": 0,
                            "errors": 0, "bytes_freed": 0}
        return output
    marker = base / _PRUNE_MARKER_NAME
    now = time.time()
    try:
        if marker.exists() and now - float(marker.read_text(encoding="utf-8-sig").strip()) < min_interval_hours * 3600:
            output["skipped"] = True
            return output
    except (OSError, ValueError):
        pass
    try:
        marker.write_text(str(now), encoding="utf-8")
    except OSError:
        pass
    output["result"] = prune_checkpoints(
        retention_days=retention_days,
        delete_orphans=delete_orphans,
        checkpoint_base=base,
        max_total_size_mb=max_total_size_mb,
    )
    return output


def auto_prune_from_env(checkpoint_base: Path | str | None = None) -> dict:
    """Maintenance tick driven by ``JARVIS_CHECKPOINT_*`` environment values."""
    if os.environ.get("JARVIS_CHECKPOINTS", "1") == "0":
        return {"skipped": True, "reason": "checkpoints disabled"}
    try:
        retention = int(os.environ.get("JARVIS_CHECKPOINT_RETENTION_DAYS", "30"))
        interval = int(os.environ.get("JARVIS_CHECKPOINT_PRUNE_HOURS", "24"))
        cap = int(os.environ.get("JARVIS_CHECKPOINT_MAX_TOTAL_MB", "500"))
    except ValueError:
        retention, interval, cap = 30, 24, 500
    return maybe_auto_prune_checkpoints(
        retention_days=max(1, retention),
        min_interval_hours=max(1, interval),
        delete_orphans=False,
        checkpoint_base=checkpoint_base,
        max_total_size_mb=max(0, cap),
    )


def store_status(checkpoint_base: Path | str | None = None) -> dict:
    """Return a content-free summary of the checkpoint store for the UI."""
    from checkpoint_manager import CheckpointManager

    base = Path(checkpoint_base or CheckpointManager().base).expanduser().resolve()
    output = {
        "ok": True,
        "base": str(base),
        "enabled": os.environ.get("JARVIS_CHECKPOINTS", "1") != "0",
        "store_size_bytes": 0,
        "total_size_bytes": 0,
        "project_count": 0,
        "projects": [],
    }
    if not base.exists():
        return output
    store = base / _STORE_DIRNAME
    if store.exists():
        output["store_size_bytes"] = _dir_size_bytes(store)
        if (store / "HEAD").exists():
            for meta in _list_projects(store):
                dir_hash = meta.get("_hash") or ""
                workdir = meta.get("workdir") or ""
                ok, count_out, _ = _run_git(
                    ["rev-list", "--count", _ref_name(dir_hash)], store, str(base),
                    allowed_returncodes={128},
                )
                try:
                    commits = int(count_out) if ok else 0
                except ValueError:
                    commits = 0
                output["projects"].append({
                    "hash": dir_hash,
                    "workdir": workdir,
                    "exists": bool(workdir) and Path(workdir).exists(),
                    "created_at": meta.get("created_at"),
                    "last_touch": meta.get("last_touch"),
                    "commits": commits,
                })
    output["project_count"] = len(output["projects"])
    output["total_size_bytes"] = _dir_size_bytes(base)
    return output


def clear_all(checkpoint_base: Path | str | None = None) -> dict:
    """Delete the entire checkpoint base; callers must require confirmation."""
    from checkpoint_manager import CheckpointManager

    base = Path(checkpoint_base or CheckpointManager().base).expanduser().resolve()
    if not base.exists():
        return {"ok": True, "deleted": False, "bytes_freed": 0}
    size = _dir_size_bytes(base)
    try:
        with store_lock(base):
            import shutil
            shutil.rmtree(base)
        return {"ok": True, "deleted": True, "bytes_freed": size}
    except OSError as error:
        return {"ok": False, "deleted": False, "bytes_freed": 0,
                "error": f"{type(error).__name__}: {error}"}
