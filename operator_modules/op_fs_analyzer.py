"""Filesystem inspection, disk usage analysis, large file discovery, broken/circular symlink detection,
and structural hygiene auditing for Jarvis.

Exclusively uses the Python standard library. Zero external dependencies.
"""

from __future__ import annotations

import datetime
import errno
import fnmatch
import os
import shutil
import stat
import time
from pathlib import Path
from typing import Any

# Security perimeter: Allowed root directories
HOME = Path.home().resolve()
ALLOWED_ROOTS: tuple[Path, ...] = (
    HOME,
    Path("/tmp").resolve(),
    Path("/mnt").resolve(),
    Path("/media").resolve(),
)

# Sensitive paths and filenames that must never be traversed or exposed
SENSITIVE_NAMES: frozenset[str] = frozenset({
    ".ssh",
    ".gnupg",
    ".password-store",
    ".hermes",
    ".aws",
    ".docker",
    ".kube",
    ".bashrc",
    ".bash_profile",
    ".profile",
    ".zshrc",
    ".zshenv",
    ".xprofile",
    ".gitconfig",
    "config.json",
    "secrets.json",
    ".git-credentials",
    ".npmrc",
    ".pypirc",
})

TEMP_ARTIFACT_PATTERNS: tuple[str, ...] = (
    "*~",
    "*.swp",
    "*.swo",
    "*.tmp",
    "*.temp",
    "*.bak",
    "*.orig",
    ".DS_Store",
    "Thumbs.db",
    "core",
)

LOCK_PATTERNS: tuple[str, ...] = (
    "*.lock",
    "*.lck",
    "*.pid",
)

VALID_ACTIONS: frozenset[str] = frozenset({
    "tree_summary",
    "disk_usage",
    "find_large",
    "find_broken_symlinks",
    "hygiene_audit",
})

KNOWN_ARGUMENTS: frozenset[str] = frozenset({
    "action",
    "path",
    "max_depth",
    "min_size_mb",
    "limit",
    "pattern",
    "include_hidden",
})


class FSError(Exception):
    """Base exception for fs_analyzer."""


class PathSecurityError(FSError):
    """Raised when path resolves outside ALLOWED_ROOTS or attempts directory escape."""


class SensitivePathError(FSError):
    """Raised when access to sensitive paths is restricted."""


def _envelope_success(data: Any) -> dict[str, Any]:
    """Return standardized 5-key Jarvis operator success envelope."""
    return {"ok": True, "success": True, "data": data, "result": data, "error": None}


def _envelope_error(error: str | Exception) -> dict[str, Any]:
    """Return standardized 5-key Jarvis operator error envelope."""
    if isinstance(error, Exception):
        msg = f"{type(error).__name__}: {error}"
    else:
        msg = str(error)
    return {"ok": False, "success": False, "data": None, "result": None, "error": msg}


def _format_size(size_bytes: int | float) -> str:
    """Format byte count into human-readable size string."""
    try:
        num = float(size_bytes)
    except (ValueError, TypeError):
        return "0 B"
    if num < 0:
        return "0 B"
    for unit in ("B", "KB", "MB", "GB", "TB", "PB"):
        if num < 1024.0 or unit == "PB":
            if unit == "B":
                return f"{int(num)} B"
            return f"{num:.2f} {unit}"
        num /= 1024.0
    return f"{num:.2f} PB"


def _is_inside_allowed_roots(path: Path) -> bool:
    """Verify that path resides strictly inside ALLOWED_ROOTS."""
    try:
        resolved = Path(os.path.realpath(str(path)))
        for root in ALLOWED_ROOTS:
            try:
                root_res = Path(os.path.realpath(str(root)))
                if resolved == root_res or resolved.is_relative_to(root_res):
                    return True
            except (OSError, RuntimeError, ValueError):
                continue
        return False
    except (OSError, RuntimeError, ValueError):
        return False


def _is_sensitive_path(path: Path) -> bool:
    """Check if any path component touches sensitive credential or configuration directories."""
    parts = [p.casefold() for p in path.parts]
    for part in parts:
        if part in SENSITIVE_NAMES:
            return True
        if part == ".env" or (part.startswith(".env.") and len(part) > 5):
            return True
        if part == ".jarvis-tools":
            return True
    return False


def _validate_and_resolve_path(raw_path: Any) -> Path:
    """Validate and canonically resolve target path within ALLOWED_ROOTS."""
    if raw_path is None or raw_path == "":
        path_str = str(Path.cwd())
    elif isinstance(raw_path, (str, Path)):
        path_str = str(raw_path).strip()
        if not path_str:
            path_str = str(Path.cwd())
    else:
        raise ValueError("Parameter 'path' must be a valid string.")

    if len(path_str) > 4096 or "\x00" in path_str:
        raise ValueError("Invalid path string: exceeds length limit or contains null bytes.")

    p = Path(path_str).expanduser()
    if not p.is_absolute():
        p = Path.cwd() / p

    try:
        resolved = Path(os.path.realpath(str(p)))
    except (OSError, ValueError) as err:
        raise ValueError(f"Path resolution error: {err}") from err

    if not _is_inside_allowed_roots(resolved):
        raise PathSecurityError(
            f"Target path '{path_str}' resolves to '{resolved}', which is outside "
            "allowed roots (HOME, /tmp, /mnt, /media)."
        )

    if _is_sensitive_path(resolved):
        raise SensitivePathError(f"Access to sensitive path '{resolved}' is restricted.")

    if not resolved.exists() and not resolved.is_symlink():
        raise FileNotFoundError(f"Target path does not exist: {resolved}")

    return resolved


def _do_tree_summary(target: Path, max_depth: int, include_hidden: bool, limit: int) -> dict[str, Any]:
    """Calculate hierarchical tree summary."""
    if target.is_file():
        st = target.stat()
        return {
            "action": "tree_summary",
            "target_path": str(target),
            "is_directory": False,
            "max_depth": max_depth,
            "include_hidden": include_hidden,
            "summary": {
                "total_files": 1,
                "total_directories": 0,
                "total_symlinks": 1 if target.is_symlink() else 0,
                "total_other": 0,
                "total_entries": 1,
                "total_size_bytes": st.st_size,
                "total_size_human": _format_size(st.st_size),
            },
            "depth_breakdown": [],
            "first_level_entries": [],
            "skipped_sensitive": [],
            "permission_errors": [],
            "truncated": False,
        }

    total_files = 0
    total_dirs = 0
    total_symlinks = 0
    total_other = 0
    total_bytes = 0
    depth_stats: dict[int, dict[str, Any]] = {
        d: {"depth": d, "directories": 0, "files": 0, "size_bytes": 0, "size_human": "0 B"}
        for d in range(1, max_depth + 1)
    }

    first_level_entries: list[dict[str, Any]] = []
    skipped_sensitive: list[str] = []
    permission_errors: list[str] = []
    visited_inodes: set[tuple[int, int]] = set()

    # Track directory sizes for first level entries
    first_level_dir_sizes: dict[str, int] = {}

    stack = [(target, 0, None)]  # (curr_dir, depth, top_level_name)

    while stack:
        curr_dir, depth, top_level_name = stack.pop()
        try:
            st = os.stat(curr_dir, follow_symlinks=False)
            inode_key = (st.st_dev, st.st_ino)
            if inode_key in visited_inodes:
                continue
            visited_inodes.add(inode_key)
        except OSError:
            pass

        try:
            with os.scandir(curr_dir) as scanner:
                subdirs = []
                for entry in scanner:
                    if not include_hidden and entry.name.startswith("."):
                        continue
                    entry_path = Path(entry.path)
                    if _is_sensitive_path(entry_path):
                        skipped_sensitive.append(str(entry_path))
                        continue

                    try:
                        is_sym = entry.is_symlink()
                        is_dir = entry.is_dir(follow_symlinks=False)
                        is_fil = entry.is_file(follow_symlinks=False)
                    except OSError:
                        continue

                    if is_sym:
                        total_symlinks += 1
                    elif is_dir:
                        total_dirs += 1
                    elif is_fil:
                        total_files += 1
                    else:
                        total_other += 1

                    item_size = 0
                    try:
                        if is_fil:
                            item_size = entry.stat(follow_symlinks=False).st_size
                            total_bytes += item_size
                    except OSError:
                        pass

                    next_depth = depth + 1
                    if 1 <= next_depth <= max_depth:
                        ds = depth_stats[next_depth]
                        if is_dir:
                            ds["directories"] += 1
                        elif is_fil:
                            ds["files"] += 1
                            ds["size_bytes"] += item_size

                    current_top = top_level_name if top_level_name is not None else (entry.name if depth == 0 else None)
                    if current_top and is_fil:
                        first_level_dir_sizes[current_top] = first_level_dir_sizes.get(current_top, 0) + item_size

                    if depth == 0:
                        first_level_entries.append({
                            "name": entry.name,
                            "type": "directory" if is_dir else ("symlink" if is_sym else "file"),
                            "size_bytes": item_size,
                            "size_human": _format_size(item_size),
                        })

                    if is_dir and not is_sym and next_depth < max_depth:
                        subdirs.append((entry_path, next_depth, current_top))

                for item in reversed(subdirs):
                    stack.append(item)
        except (PermissionError, OSError) as err:
            permission_errors.append(f"{curr_dir}: {err}")

    for d in range(1, max_depth + 1):
        depth_stats[d]["size_human"] = _format_size(depth_stats[d]["size_bytes"])

    # Update size_bytes for first level directory entries
    for item in first_level_entries:
        if item["type"] == "directory" and item["name"] in first_level_dir_sizes:
            dir_total = first_level_dir_sizes[item["name"]]
            item["size_bytes"] = dir_total
            item["size_human"] = _format_size(dir_total)

    first_level_entries.sort(key=lambda x: (x["type"] != "directory", -x["size_bytes"], x["name"]))
    truncated = len(first_level_entries) > limit
    returned_first_level = first_level_entries[:limit]

    return {
        "action": "tree_summary",
        "target_path": str(target),
        "is_directory": True,
        "max_depth": max_depth,
        "include_hidden": include_hidden,
        "summary": {
            "total_files": total_files,
            "total_directories": total_dirs,
            "total_symlinks": total_symlinks,
            "total_other": total_other,
            "total_entries": total_files + total_dirs + total_symlinks + total_other,
            "total_size_bytes": total_bytes,
            "total_size_human": _format_size(total_bytes),
        },
        "depth_breakdown": [depth_stats[d] for d in range(1, max_depth + 1)],
        "first_level_entries": returned_first_level,
        "skipped_sensitive": skipped_sensitive[:50],
        "permission_errors": permission_errors[:50],
        "truncated": truncated,
    }


def _do_disk_usage(target: Path, max_depth: int, include_hidden: bool, limit: int) -> dict[str, Any]:
    """Calculate partition and directory subtree disk usage."""
    # Partition info
    try:
        du = shutil.disk_usage(str(target))
        total_p = du.total
        used_p = du.used
        free_p = du.free
        percent_used = round(used_p / max(1, total_p) * 100.0, 2)
    except OSError:
        total_p, used_p, free_p, percent_used = 0, 0, 0, 0.0

    partition_info = {
        "total_bytes": total_p,
        "total_human": _format_size(total_p),
        "used_bytes": used_p,
        "used_human": _format_size(used_p),
        "free_bytes": free_p,
        "free_human": _format_size(free_p),
        "percent_used": percent_used,
    }

    if target.is_file():
        st = target.stat()
        return {
            "action": "disk_usage",
            "target_path": str(target),
            "partition": partition_info,
            "target_usage": {
                "total_scanned_bytes": st.st_size,
                "total_scanned_human": _format_size(st.st_size),
                "total_scanned_files": 1,
                "total_scanned_dirs": 0,
            },
            "children": [],
            "total_children_found": 0,
            "returned_count": 0,
            "truncated": False,
            "limit": limit,
            "permission_errors": [],
        }

    # Aggregate children sizes
    children_info: list[dict[str, Any]] = []
    permission_errors: list[str] = []
    total_scanned_bytes = 0
    total_scanned_files = 0
    total_scanned_dirs = 0

    try:
        with os.scandir(str(target)) as scanner:
            for entry in scanner:
                if not include_hidden and entry.name.startswith("."):
                    continue
                entry_path = Path(entry.path)
                if _is_sensitive_path(entry_path):
                    continue

                try:
                    is_sym = entry.is_symlink()
                    is_dir = entry.is_dir(follow_symlinks=False)
                    is_fil = entry.is_file(follow_symlinks=False)
                except OSError:
                    continue

                if is_fil:
                    total_scanned_files += 1
                    try:
                        sz = entry.stat(follow_symlinks=False).st_size
                    except OSError:
                        sz = 0
                    total_scanned_bytes += sz
                    children_info.append({
                        "name": entry.name,
                        "path": str(entry_path),
                        "type": "file",
                        "size_bytes": sz,
                        "size_human": _format_size(sz),
                        "items_count": 1,
                    })
                elif is_dir and not is_sym:
                    total_scanned_dirs += 1
                    # Recurse up to max_depth
                    dir_bytes = 0
                    dir_files = 0
                    stack = [(entry_path, 1)]
                    visited: set[tuple[int, int]] = set()

                    while stack:
                        c_dir, c_depth = stack.pop()
                        try:
                            c_st = os.stat(c_dir, follow_symlinks=False)
                            inode = (c_st.st_dev, c_st.st_ino)
                            if inode in visited:
                                continue
                            visited.add(inode)
                        except OSError:
                            pass

                        try:
                            with os.scandir(str(c_dir)) as sub_scan:
                                for sub_entry in sub_scan:
                                    if not include_hidden and sub_entry.name.startswith("."):
                                        continue
                                    sub_p = Path(sub_entry.path)
                                    if _is_sensitive_path(sub_p):
                                        continue

                                    try:
                                        s_sym = sub_entry.is_symlink()
                                        s_dir = sub_entry.is_dir(follow_symlinks=False)
                                        s_fil = sub_entry.is_file(follow_symlinks=False)
                                    except OSError:
                                        continue

                                    if s_fil:
                                        dir_files += 1
                                        try:
                                            s_sz = sub_entry.stat(follow_symlinks=False).st_size
                                            dir_bytes += s_sz
                                        except OSError:
                                            pass
                                    elif s_dir and not s_sym and c_depth < max_depth:
                                        stack.append((sub_p, c_depth + 1))
                        except (PermissionError, OSError) as err:
                            permission_errors.append(f"{c_dir}: {err}")

                    total_scanned_bytes += dir_bytes
                    total_scanned_files += dir_files
                    children_info.append({
                        "name": entry.name,
                        "path": str(entry_path),
                        "type": "directory",
                        "size_bytes": dir_bytes,
                        "size_human": _format_size(dir_bytes),
                        "items_count": dir_files,
                    })
                elif is_sym:
                    children_info.append({
                        "name": entry.name,
                        "path": str(entry_path),
                        "type": "symlink",
                        "size_bytes": 0,
                        "size_human": "0 B",
                        "items_count": 0,
                    })
    except (PermissionError, OSError) as err:
        permission_errors.append(f"{target}: {err}")

    # Calculate percent of target for each child
    for ch in children_info:
        pct = round(ch["size_bytes"] / max(1, total_scanned_bytes) * 100.0, 2)
        ch["percent_of_target"] = pct

    children_info.sort(key=lambda x: -x["size_bytes"])
    total_children = len(children_info)
    truncated = total_children > limit
    returned_children = children_info[:limit]

    return {
        "action": "disk_usage",
        "target_path": str(target),
        "partition": partition_info,
        "target_usage": {
            "total_scanned_bytes": total_scanned_bytes,
            "total_scanned_human": _format_size(total_scanned_bytes),
            "total_scanned_files": total_scanned_files,
            "total_scanned_dirs": total_scanned_dirs,
        },
        "children": returned_children,
        "total_children_found": total_children,
        "returned_count": len(returned_children),
        "truncated": truncated,
        "limit": limit,
        "permission_errors": permission_errors[:50],
    }


def _do_find_large(
    target: Path, min_size_mb: float, pattern: str | None, max_depth: int, include_hidden: bool, limit: int
) -> dict[str, Any]:
    """Find files exceeding minimum size threshold."""
    min_size_bytes = int(min_size_mb * 1024 * 1024)
    matching_files: list[dict[str, Any]] = []
    permission_errors: list[str] = []
    visited_inodes: set[tuple[int, int]] = set()

    stack = [(target, 0)]

    while stack:
        curr_dir, depth = stack.pop()
        try:
            st = os.stat(curr_dir, follow_symlinks=False)
            inode = (st.st_dev, st.st_ino)
            if inode in visited_inodes:
                continue
            visited_inodes.add(inode)
        except OSError:
            pass

        try:
            with os.scandir(str(curr_dir)) as scanner:
                for entry in scanner:
                    if not include_hidden and entry.name.startswith("."):
                        continue
                    entry_path = Path(entry.path)
                    if _is_sensitive_path(entry_path):
                        continue

                    try:
                        is_sym = entry.is_symlink()
                        is_dir = entry.is_dir(follow_symlinks=False)
                        is_fil = entry.is_file(follow_symlinks=False)
                    except OSError:
                        continue

                    if is_fil:
                        if pattern and not fnmatch.fnmatch(entry.name, pattern):
                            continue
                        try:
                            f_st = entry.stat(follow_symlinks=False)
                            sz = f_st.st_size
                            if sz >= min_size_bytes:
                                mtime_iso = datetime.datetime.fromtimestamp(
                                    f_st.st_mtime, tz=datetime.timezone.utc
                                ).strftime("%Y-%m-%dT%H:%M:%SZ")
                                try:
                                    rel = str(entry_path.relative_to(target))
                                except ValueError:
                                    rel = entry.name

                                matching_files.append({
                                    "name": entry.name,
                                    "path": str(entry_path),
                                    "relative_path": rel,
                                    "size_bytes": sz,
                                    "size_human": _format_size(sz),
                                    "modified_time": mtime_iso,
                                    "extension": entry_path.suffix.lower(),
                                    "is_symlink": is_sym,
                                })
                        except OSError:
                            pass
                    elif is_dir and not is_sym and depth < max_depth:
                        stack.append((entry_path, depth + 1))
        except (PermissionError, OSError) as err:
            permission_errors.append(f"{curr_dir}: {err}")

    matching_files.sort(key=lambda x: -x["size_bytes"])
    total_matches = len(matching_files)
    truncated = total_matches > limit
    returned_files = matching_files[:limit]

    return {
        "action": "find_large",
        "target_path": str(target),
        "min_size_mb": min_size_mb,
        "min_size_bytes": min_size_bytes,
        "pattern": pattern,
        "max_depth": max_depth,
        "include_hidden": include_hidden,
        "total_matches": total_matches,
        "returned_count": len(returned_files),
        "truncated": truncated,
        "limit": limit,
        "files": returned_files,
        "permission_errors": permission_errors[:50],
    }


def _do_find_broken_symlinks(target: Path, max_depth: int, include_hidden: bool, limit: int) -> dict[str, Any]:
    """Find dangling or circular symbolic links."""
    total_scanned = 0
    broken_symlinks: list[dict[str, Any]] = []
    permission_errors: list[str] = []
    visited_inodes: set[tuple[int, int]] = set()

    stack = [(target, 0)]

    while stack:
        curr_dir, depth = stack.pop()
        try:
            st = os.stat(curr_dir, follow_symlinks=False)
            inode = (st.st_dev, st.st_ino)
            if inode in visited_inodes:
                continue
            visited_inodes.add(inode)
        except OSError:
            pass

        try:
            with os.scandir(str(curr_dir)) as scanner:
                for entry in scanner:
                    if not include_hidden and entry.name.startswith("."):
                        continue
                    entry_path = Path(entry.path)
                    if _is_sensitive_path(entry_path):
                        continue

                    try:
                        is_sym = entry.is_symlink()
                        is_dir = entry.is_dir(follow_symlinks=False)
                    except OSError:
                        continue

                    if is_sym:
                        total_scanned += 1
                        try:
                            raw_target = os.readlink(entry.path)
                        except OSError:
                            raw_target = "unknown"

                        try:
                            rel = str(entry_path.relative_to(target))
                        except ValueError:
                            rel = entry.name

                        reason = None
                        resolved_target = None
                        try:
                            # Test stat to see if file exists or loop
                            os.stat(entry.path)
                            # If stat succeeds, test if realpath loops back to itself
                            rp = os.path.realpath(entry.path)
                            if rp == str(entry_path):
                                reason = "circular_loop"
                        except FileNotFoundError:
                            reason = "dangling"
                            resolved_target = str(Path(curr_dir) / raw_target)
                        except OSError as e:
                            if e.errno == errno.ELOOP:
                                reason = "circular_loop"
                            elif isinstance(e, PermissionError):
                                reason = "permission_denied"
                            else:
                                reason = "dangling"

                        if reason is not None:
                            broken_symlinks.append({
                                "path": str(entry_path),
                                "relative_path": rel,
                                "raw_target": raw_target,
                                "resolved_target": resolved_target,
                                "reason": reason,
                            })
                    elif is_dir and depth < max_depth:
                        stack.append((entry_path, depth + 1))
        except (PermissionError, OSError) as err:
            permission_errors.append(f"{curr_dir}: {err}")

    broken_count = sum(1 for b in broken_symlinks if b["reason"] == "dangling")
    circular_count = sum(1 for b in broken_symlinks if b["reason"] == "circular_loop")
    total_issues = len(broken_symlinks)
    truncated = total_issues > limit
    returned_links = broken_symlinks[:limit]

    return {
        "action": "find_broken_symlinks",
        "target_path": str(target),
        "max_depth": max_depth,
        "total_symlinks_scanned": total_scanned,
        "broken_count": broken_count,
        "circular_count": circular_count,
        "total_issues": total_issues,
        "returned_count": len(returned_links),
        "truncated": truncated,
        "limit": limit,
        "broken_symlinks": returned_links,
        "permission_errors": permission_errors[:50],
    }


def _do_hygiene_audit(target: Path, max_depth: int, include_hidden: bool, limit: int) -> dict[str, Any]:
    """Perform structural hygiene audit."""
    empty_dirs_count = 0
    zero_byte_count = 0
    temp_artifacts_count = 0
    stale_locks_count = 0
    permission_anomalies_count = 0

    issues: list[dict[str, Any]] = []
    permission_errors: list[str] = []
    visited_inodes: set[tuple[int, int]] = set()
    now = time.time()

    stack = [(target, 0)]

    while stack:
        curr_dir, depth = stack.pop()
        try:
            st = os.stat(curr_dir, follow_symlinks=False)
            inode = (st.st_dev, st.st_ino)
            if inode in visited_inodes:
                continue
            visited_inodes.add(inode)
        except OSError:
            pass

        try:
            with os.scandir(str(curr_dir)) as scanner:
                entries = list(scanner)
                # Check for empty directory (only for subdirectories of target or target itself)
                if len(entries) == 0:
                    empty_dirs_count += 1
                    try:
                        rel = str(curr_dir.relative_to(target))
                    except ValueError:
                        rel = curr_dir.name
                    issues.append({
                        "category": "empty_directory",
                        "description": "Empty directory containing 0 entries",
                        "path": str(curr_dir),
                        "relative_path": rel or ".",
                    })

                for entry in entries:
                    if not include_hidden and entry.name.startswith("."):
                        continue
                    entry_path = Path(entry.path)
                    if _is_sensitive_path(entry_path):
                        continue

                    try:
                        is_sym = entry.is_symlink()
                        is_dir = entry.is_dir(follow_symlinks=False)
                        is_fil = entry.is_file(follow_symlinks=False)
                        e_st = entry.stat(follow_symlinks=False)
                        mode = e_st.st_mode
                    except OSError:
                        continue

                    try:
                        rel = str(entry_path.relative_to(target))
                    except ValueError:
                        rel = entry.name

                    # 1. World-writable permission anomaly
                    if not is_sym:
                        if is_fil and (mode & stat.S_IWOTH):
                            permission_anomalies_count += 1
                            issues.append({
                                "category": "permission_anomaly",
                                "description": "World-writable regular file",
                                "path": str(entry_path),
                                "relative_path": rel,
                                "mode": oct(stat.S_IMODE(mode)),
                            })
                        elif is_dir and (mode & stat.S_IWOTH) and not (mode & stat.S_ISVTX):
                            permission_anomalies_count += 1
                            issues.append({
                                "category": "permission_anomaly",
                                "description": "World-writable directory without sticky bit",
                                "path": str(entry_path),
                                "relative_path": rel,
                                "mode": oct(stat.S_IMODE(mode)),
                            })

                    # 2. Temp artifacts
                    if any(fnmatch.fnmatch(entry.name, pat) for pat in TEMP_ARTIFACT_PATTERNS) or entry.name == "__pycache__":
                        temp_artifacts_count += 1
                        issues.append({
                            "category": "temp_artifact",
                            "description": "Temporary or editor backup artifact",
                            "path": str(entry_path),
                            "relative_path": rel,
                            "size_bytes": e_st.st_size if is_fil else 0,
                        })

                    # 3. Stale locks
                    if is_fil and any(fnmatch.fnmatch(entry.name, pat) for pat in LOCK_PATTERNS):
                        age_sec = now - e_st.st_mtime
                        if age_sec > 86400:  # > 24 hours
                            stale_locks_count += 1
                            age_hours = round(age_sec / 3600.0, 1)
                            mtime_iso = datetime.datetime.fromtimestamp(
                                e_st.st_mtime, tz=datetime.timezone.utc
                            ).strftime("%Y-%m-%dT%H:%M:%SZ")
                            issues.append({
                                "category": "stale_lock",
                                "description": f"Lock file modified > 24 hours ago ({age_hours}h)",
                                "path": str(entry_path),
                                "relative_path": rel,
                                "size_bytes": e_st.st_size,
                                "modified_time": mtime_iso,
                                "age_hours": age_hours,
                            })

                    # 4. Zero-byte files
                    if is_fil and not is_sym and e_st.st_size == 0:
                        zero_byte_count += 1
                        issues.append({
                            "category": "zero_byte_file",
                            "description": "Zero-byte empty file",
                            "path": str(entry_path),
                            "relative_path": rel,
                        })

                    if is_dir and not is_sym and depth < max_depth:
                        stack.append((entry_path, depth + 1))
        except (PermissionError, OSError) as err:
            permission_errors.append(f"{curr_dir}: {err}")

    total_issues = len(issues)
    truncated = total_issues > limit
    returned_issues = issues[:limit]

    recommendations: list[str] = []
    if empty_dirs_count:
        recommendations.append(f"Found {empty_dirs_count} empty directory(ies) that can be safely pruned.")
    if zero_byte_count:
        recommendations.append(f"Found {zero_byte_count} zero-byte file(s) that may be aborted or dangling operations.")
    if temp_artifacts_count:
        recommendations.append(f"Found {temp_artifacts_count} temporary or cache artifact(s).")
    if stale_locks_count:
        recommendations.append(f"Found {stale_locks_count} stale lock file(s) older than 24 hours.")
    if permission_anomalies_count:
        recommendations.append(f"Found {permission_anomalies_count} permission anomalie(s) with insecure world-writable bits.")

    return {
        "action": "hygiene_audit",
        "target_path": str(target),
        "max_depth": max_depth,
        "include_hidden": include_hidden,
        "summary": {
            "empty_directories_count": empty_dirs_count,
            "zero_byte_files_count": zero_byte_count,
            "temp_artifacts_count": temp_artifacts_count,
            "stale_locks_count": stale_locks_count,
            "permission_anomalies_count": permission_anomalies_count,
            "total_hygiene_issues": total_issues,
        },
        "issues": returned_issues,
        "returned_count": len(returned_issues),
        "total_issues": total_issues,
        "truncated": truncated,
        "limit": limit,
        "recommendations": recommendations,
        "permission_errors": permission_errors[:50],
    }


def fs_analyzer(arguments: dict[str, Any], context: dict[str, Any] | None = None) -> dict[str, Any]:
    """Execute filesystem analyzer action adhering to Jarvis operator standards."""
    if not isinstance(arguments, dict):
        return _envelope_error(ValueError("Arguments must be a dictionary."))

    for key in arguments:
        if key not in KNOWN_ARGUMENTS:
            return _envelope_error(ValueError(f"Unknown argument '{key}' or schema violation"))

    action = arguments.get("action")
    if not action or not isinstance(action, str):
        return _envelope_error(ValueError("Missing required parameter 'action'"))

    if action not in VALID_ACTIONS:
        return _envelope_error(ValueError(f"Invalid or unsupported action '{action}'"))

    try:
        raw_path = arguments.get("path")
        target = _validate_and_resolve_path(raw_path)

        max_depth = int(arguments.get("max_depth", 3))
        max_depth = max(1, min(10, max_depth))

        limit = int(arguments.get("limit", 50))
        limit = max(1, min(200, limit))

        include_hidden = bool(arguments.get("include_hidden", False))

        if action == "tree_summary":
            return _envelope_success(_do_tree_summary(target, max_depth, include_hidden, limit))
        elif action == "disk_usage":
            return _envelope_success(_do_disk_usage(target, max_depth, include_hidden, limit))
        elif action == "find_large":
            min_size_mb = float(arguments.get("min_size_mb", 10.0))
            if min_size_mb < 0.0:
                raise ValueError("min_size_mb must be a non-negative number.")
            pattern = arguments.get("pattern")
            if pattern is not None and not isinstance(pattern, str):
                raise ValueError("pattern must be a string.")
            return _envelope_success(_do_find_large(target, min_size_mb, pattern, max_depth, include_hidden, limit))
        elif action == "find_broken_symlinks":
            return _envelope_success(_do_find_broken_symlinks(target, max_depth, include_hidden, limit))
        elif action == "hygiene_audit":
            return _envelope_success(_do_hygiene_audit(target, max_depth, include_hidden, limit))
        else:
            return _envelope_error(ValueError(f"Unhandled action '{action}'"))
    except Exception as exc:
        return _envelope_error(exc)


TOOL = {
    "name": "fs_analyzer",
    "description": (
        "Zero-dependency filesystem inspection, disk usage analysis, large file discovery, "
        "broken/circular symlink detection, and structural hygiene auditing for Jarvis. "
        "Operates read-only with strict path confinement to ALLOWED_ROOTS (HOME, /tmp, /mnt, /media) "
        "and bounded traversal limits."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "action": {
                "type": "string",
                "enum": [
                    "tree_summary",
                    "disk_usage",
                    "find_large",
                    "find_broken_symlinks",
                    "hygiene_audit",
                ],
                "description": "Filesystem analysis action to perform.",
            },
            "path": {
                "type": "string",
                "description": (
                    "Target directory or file path to analyze. Defaults to current working directory. "
                    "Must resolve within ALLOWED_ROOTS (HOME, /tmp, /mnt, /media)."
                ),
            },
            "max_depth": {
                "type": "integer",
                "minimum": 1,
                "maximum": 10,
                "description": "Maximum directory traversal depth (1 to 10, default 3).",
            },
            "min_size_mb": {
                "type": "number",
                "minimum": 0.0,
                "description": "Minimum file size threshold in megabytes (MB) for 'find_large' (default: 10.0 MB).",
            },
            "limit": {
                "type": "integer",
                "minimum": 1,
                "maximum": 200,
                "description": "Maximum number of items/entries to return in list results (1 to 200, default 50).",
            },
            "pattern": {
                "type": "string",
                "description": "Optional glob pattern to filter filenames (e.g. '*.log', '*.py'). Evaluated using fnmatch.",
            },
            "include_hidden": {
                "type": "boolean",
                "description": "Whether to include hidden files and directories (names starting with '.') in scan results (default: false).",
            },
        },
        "required": ["action"],
        "additionalProperties": False,
    },
    "handler": fs_analyzer,
    "approval": False,
}
