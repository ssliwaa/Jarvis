"""Safe file organizer: inspect duplicates/old/empty files, quarantine, undo.

Nothing is deleted. Quarantined files move under
``~/.jarvis-tools/organizer-trash/<batch>/`` with a JSON manifest that can be
restored. Paths outside the user's home, /tmp and mounted media are refused.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import threading
import time
import uuid
from pathlib import Path

TOOLS = Path.home() / ".jarvis-tools"
TRASH = TOOLS / "organizer-trash"
ARCHIVE = TOOLS / "organizer-archive"
MANIFEST = TOOLS / "organizer-manifest.json"
ALLOWED = (Path.home(), Path("/tmp"), Path("/media"), Path("/mnt"))
MANIFEST_LOCK = threading.Lock()  # read-modify-write on MANIFEST


def _append_manifest_history(manifest: dict) -> None:
    """Publish one batch into MANIFEST atomically; a concurrent batch must not erase it."""
    with MANIFEST_LOCK:
        try:
            history = json.loads(MANIFEST.read_text(encoding="utf-8"))
            if not isinstance(history, list):
                history = []
        except (OSError, ValueError, UnicodeError):
            history = []
        history = (history + [manifest])[-20:]
        MANIFEST.parent.mkdir(parents=True, exist_ok=True)
        temporary = MANIFEST.with_name(f".manifest-{uuid.uuid4().hex[:8]}.tmp")
        temporary.write_text(json.dumps(history, ensure_ascii=False, indent=2), encoding="utf-8")
        temporary.replace(MANIFEST)
        MANIFEST.chmod(0o600)


class OrganizerError(Exception):
    pass


def _inside(path: Path) -> bool:
    path = path.resolve()
    return any(path == root.resolve() or root.resolve() in path.parents for root in ALLOWED)


def _safe(path) -> Path:
    candidate = Path(path).expanduser()
    if not candidate.is_absolute() or not _inside(candidate):
        raise OrganizerError("The path is outside the allowed home/temp/media roots.")
    if candidate.is_symlink():
        raise OrganizerError("Symlinks are not organized.")
    return candidate


def _batch_dir(root: Path, batch) -> Path:
    """Resolve one batch name without letting `../` or an absolute path escape."""
    name = str(batch or "").strip()
    try:
        parts_ok = bool(name) and name not in (".", "..") and Path(name).name == name
    except ValueError:
        parts_ok = False
    if not parts_ok or "\\" in name:
        raise OrganizerError("The batch name is invalid.")
    return root / name


def _within(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
    except (OSError, ValueError):
        return False
    return True


def _edge_hash(path: Path, size: int) -> str:
    """Fast 64 KiB head+tail fingerprint before reading a large file in full."""
    window = 65536
    if size <= window * 2:
        return _hash(path)
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        digest.update(handle.read(window))
        handle.seek(max(0, size - window))
        digest.update(handle.read(window))
    return digest.hexdigest()


def _hash(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


SKIP_DIRS = frozenset({"node_modules", "__pycache__", "venv", ".venv", "dist", "build", "target"})


def scan(root, older_days=365, max_files=5000):
    root = _safe(root)
    if not root.is_dir():
        raise OrganizerError("The scan root is not a directory.")
    files, empty_dirs, errors = [], [], []
    now = time.time()
    for current, dirs, names in os.walk(root):
        # Stop the WALK, not just the file loop: the previous inner `break`
        # still descended every remaining directory (hours of stat calls).
        if len(files) >= max_files:
            dirs[:] = []
            break
        current_path = Path(current)
        if current_path.name.startswith(".") or current_path.name in SKIP_DIRS:
            dirs[:] = []
            continue
        dirs[:] = [d for d in dirs if not d.startswith(".") and d not in SKIP_DIRS]
        if not names and not dirs and current_path != root:
            empty_dirs.append(str(current_path))
        for name in names:
            if len(files) >= max_files:
                break
            path = current_path / name
            try:
                if path.is_symlink() or not path.is_file():
                    continue
                stat = path.stat()
                files.append({"path": str(path), "size": stat.st_size,
                              "modified": stat.st_mtime,
                              "age_days": round((now - stat.st_mtime) / 86400, 1)})
            except OSError as error:
                errors.append({"path": str(path), "error": str(error)[:160]})
    by_size = {}
    for row in files:
        if row["size"] > 0:
            by_size.setdefault(row["size"], []).append(row)
    duplicates = []
    for size, group in by_size.items():
        if len(group) < 2:
            continue
        if size > 131072:
            pre_groups = {}
            for row in group:
                try:
                    pre_groups.setdefault(_edge_hash(Path(row["path"]), size), []).append(row)
                except OSError:
                    continue
            candidate_groups = [rows for rows in pre_groups.values() if len(rows) > 1]
        else:
            candidate_groups = [group]
        for candidates in candidate_groups:
            hashes = {}
            for row in candidates:
                try:
                    hashes.setdefault(_hash(Path(row["path"])), []).append(row)
                except OSError:
                    continue
            duplicates.extend([rows for rows in hashes.values() if len(rows) > 1])
    old = sorted((row for row in files if row["age_days"] >= older_days),
                 key=lambda row: row["modified"])[:30]
    large = sorted(files, key=lambda row: row["size"], reverse=True)[:20]
    return {"root": str(root), "files": len(files), "empty_dirs": empty_dirs[:30],
            "duplicates": duplicates[:20], "old": old, "large": large,
            "older_days": older_days, "errors": errors[:20],
            "duplicate_waste": sum(row["size"] for group in duplicates for row in group[1:])}


def preview(root, older_days=365):
    report = scan(root, older_days=older_days)
    return {"root": report["root"], "old": report["old"], "empty_dirs": report["empty_dirs"],
            "duplicate_groups": report["duplicates"], "dry_run": True,
            "count": len(report["old"]) + len(report["empty_dirs"])}


def archive(root, older_days=365, confirm=False):
    """Preview old files, or move them into a restorable archive when confirmed."""
    plan = preview(root, older_days)
    candidates = [row["path"] for row in plan["old"] if Path(row["path"]).is_file()]
    empty = list(plan["empty_dirs"])
    if confirm is not True:
        return {"ok": True, "dry_run": True, "candidates": candidates, "empty_dirs": empty,
                "count": len(candidates) + len(empty), "root": plan["root"]}
    batch = time.strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:6]
    target = ARCHIVE / batch
    target.mkdir(parents=True, exist_ok=True)
    moved, errors = [], []
    for raw in candidates:
        source = _safe(raw)
        try:
            relative = source.relative_to(Path(plan["root"]).resolve())
        except ValueError:
            relative = Path(source.name)
        destination = target / relative
        if destination.exists():
            # A flattened fallback (root boundary change) must never silently
            # overwrite a file that was already archived in this batch.
            destination = target / (source.stem + "-" + uuid.uuid4().hex[:6] + source.suffix)
        destination.parent.mkdir(parents=True, exist_ok=True)
        try:
            shutil.move(str(source), str(destination))
            moved.append({"source": str(source), "destination": str(destination)})
        except OSError as error:
            errors.append({"source": str(source), "error": str(error)[:160]})
    removed_dirs = []
    for raw in empty:
        path = Path(raw)
        try:
            if path.is_dir() and not any(path.iterdir()):
                path.rmdir()
                removed_dirs.append(str(path))
        except OSError:
            pass
    manifest = {"batch": batch, "root": plan["root"], "created": time.time(),
                "moved": moved, "removed_dirs": removed_dirs, "errors": errors}
    manifest_path = target / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    return {"ok": bool(moved or removed_dirs), "dry_run": False, "batch": batch,
            "moved": moved, "removed_dirs": removed_dirs, "errors": errors,
            "manifest": str(manifest_path), "count": len(moved) + len(removed_dirs)}


def _read_manifest(path: Path, kind: str) -> dict:
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeError):
        raise OrganizerError(f"That {kind} manifest is missing or corrupt; restore refused.") from None
    if not isinstance(manifest, dict) or not isinstance(manifest.get("moved"), list):
        raise OrganizerError(f"That {kind} manifest is corrupt; restore refused.")
    return manifest


def restore_archive(batch, confirm=False):
    if confirm is not True:
        return {"ok": False, "dry_run": True, "error": "restore_archive requires confirm:true"}
    target = _batch_dir(ARCHIVE, batch)
    manifest_path = target / "manifest.json"
    if not manifest_path.is_file():
        raise OrganizerError("That archive batch has no manifest.")
    manifest = _read_manifest(manifest_path, "archive")
    restored = []
    for row in manifest.get("moved", []):
        source, destination = Path(row.get("source", "")), Path(row.get("destination", ""))
        if not destination.is_file() or source.exists() or not _inside(source):
            continue
        if not _within(destination, target):
            continue
        try:
            source.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(destination), str(source))
            restored.append(str(source))
        except OSError:
            continue
    return {"ok": bool(restored), "restored": restored, "batch": batch}


def trash(paths, confirm=False):
    if confirm is not True:
        raise OrganizerError("Quarantine requires confirm:true.")
    if not isinstance(paths, list) or not paths or len(paths) > 50:
        raise OrganizerError("Pass between 1 and 50 explicit paths.")
    batch = time.strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:6]
    target = TRASH / batch
    target.mkdir(parents=True, exist_ok=True)
    moved, errors = [], []
    for raw in paths:
        source = _safe(raw)
        if not source.is_file():
            errors.append({"source": str(source), "error": "not a regular file"})
            continue
        destination = target / source.name
        if destination.exists():
            destination = target / (source.stem + "-" + uuid.uuid4().hex[:6] + source.suffix)
        try:
            shutil.move(str(source), str(destination))
            moved.append({"source": str(source), "destination": str(destination)})
        except OSError as error:
            errors.append({"source": str(source), "error": str(error)[:160]})
    manifest = {"batch": batch, "created": time.time(), "moved": moved, "errors": errors}
    manifest_path = target / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    _append_manifest_history(manifest)
    return {"ok": bool(moved), "batch": batch, "moved": moved, "errors": errors,
            "manifest": str(manifest_path)}


def restore(batch, confirm=False):
    if confirm is not True:
        raise OrganizerError("Restore requires confirm:true.")
    target = _batch_dir(TRASH, batch)
    manifest_path = target / "manifest.json"
    if not manifest_path.is_file():
        raise OrganizerError("That quarantine batch has no manifest.")
    manifest = _read_manifest(manifest_path, "quarantine")
    restored = []
    for row in manifest.get("moved", []):
        source, destination = Path(row.get("source", "")), Path(row.get("destination", ""))
        if not destination.is_file() or source.exists() or not _inside(source):
            continue
        if not _within(destination, target):
            continue
        try:
            source.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(destination), str(source))
            restored.append(str(source))
        except OSError:
            continue
    return {"ok": bool(restored), "restored": restored, "batch": batch}
