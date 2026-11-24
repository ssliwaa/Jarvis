"""Zero-dependency multi-stage transactional branching sandbox with rollback protection.

Inspired by Plandex, Open Interpreter, and LLM CLI: isolates multi-file edits in
disposable staging directories, validates diffs, applies search/replace or full content
updates without touching working trees, and supports atomic commits or instant rollbacks.
Exclusively uses the Python standard library.
"""

from __future__ import annotations

import difflib
import hashlib
import json
import os
import re
import shutil
import time
import uuid
from pathlib import Path
from typing import Any, Optional

try:
    from atomic_io import atomic_write_text
except ImportError:  # standalone copy: reach the repo root next to operator_modules/
    import sys
    _repo_root = str(Path(__file__).resolve().parents[1])
    if _repo_root not in sys.path:
        sys.path.insert(0, _repo_root)
    from atomic_io import atomic_write_text

# Security perimeter: Allowed root directories
HOME = Path.home().resolve()
ALLOWED_ROOTS: tuple[Path, ...] = (
    HOME,
    Path("/tmp").resolve(),
    Path("/mnt").resolve(),
    Path("/media").resolve(),
)

SENSITIVE_PARTS: frozenset[str] = frozenset({
    ".ssh",
    ".gnupg",
    ".password-store",
    ".hermes",
    ".aws",
    ".docker",
    ".kube",
})

SENSITIVE_NAMES: frozenset[str] = frozenset({
    ".bashrc",
    ".bash_profile",
    ".profile",
    ".zshrc",
    ".zshenv",
    ".gitconfig",
    "config.json",
    "secrets.json",
    ".git-credentials",
    ".npmrc",
    ".pypirc",
    "shadow",
})

# Sandbox storage base directory inside /tmp
SANDBOX_BASE_DIR = Path("/tmp/jarvis_plan_sandboxes")

VALID_ACTIONS: frozenset[str] = frozenset({
    "create_stage",
    "create_sandbox",
    "stage_file",
    "apply_edit",
    "diff_stage",
    "diff_sandbox",
    "commit_stage",
    "commit_sandbox",
    "rollback_stage",
    "rollback_sandbox",
    "list_sandboxes",
    "list_stages",
})


class PlanSandboxError(Exception):
    """Base exception for plan_sandbox operations."""


class PathSecurityError(PlanSandboxError):
    """Raised when path traversal or forbidden boundary escape is detected."""


class SensitivePathError(PlanSandboxError):
    """Raised when access to a sensitive credential path is attempted."""


def _envelope_success(data: Any) -> dict[str, Any]:
    """Return standardized 5-key Jarvis operator success envelope."""
    return {"ok": True, "success": True, "data": data, "result": data, "error": None}


def _envelope_error(err: str | Exception) -> dict[str, Any]:
    """Return standardized 5-key Jarvis operator error envelope."""
    msg = f"{type(err).__name__}: {err}" if isinstance(err, Exception) else str(err)
    return {"ok": False, "success": False, "data": None, "result": None, "error": msg}


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
    """Check if any path component touches sensitive credential directories or files."""
    parts = [p.casefold() for p in path.parts]
    for part in parts:
        if part in SENSITIVE_PARTS:
            return True
        if part in SENSITIVE_NAMES:
            return True
    if path.name.casefold() in SENSITIVE_NAMES:
        return True
    return False


def _resolve_and_validate_path(path_str: str, must_exist: bool = True, is_dir: bool | None = None) -> Path:
    """Resolve and validate path against ALLOWED_ROOTS and sensitive filters."""
    if not isinstance(path_str, str) or not path_str.strip():
        raise ValueError("Path must be a non-empty string.")
    if "\0" in path_str:
        raise PathSecurityError("Null bytes are prohibited in file paths.")

    expanded = os.path.expanduser(path_str)
    resolved = Path(os.path.realpath(expanded))

    if not _is_inside_allowed_roots(resolved):
        raise PathSecurityError(f"Path '{path_str}' resolves outside ALLOWED_ROOTS.")

    if _is_sensitive_path(resolved):
        raise SensitivePathError(f"Access to sensitive path '{resolved}' is restricted.")

    if must_exist and not resolved.exists():
        raise FileNotFoundError(f"Path not found: '{path_str}'")

    if resolved.exists():
        if is_dir is True and not resolved.is_dir():
            raise ValueError(f"Path '{path_str}' is not a directory.")
        if is_dir is False and not resolved.is_file():
            raise ValueError(f"Path '{path_str}' is not a regular file.")

    return resolved


def _sha256_file(filepath: Path) -> str:
    """Compute SHA-256 digest of a file."""
    h = hashlib.sha256()
    with filepath.open("rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def _get_sandbox_dir(session_id: str) -> Path:
    """Get the directory path for a specific sandbox session."""
    clean_id = re.sub(r"[^a-zA-Z0-9_\-]", "", session_id)
    if not clean_id:
        raise ValueError(f"Invalid sandbox session ID: '{session_id}'")
    sdir = SANDBOX_BASE_DIR / clean_id
    return sdir


def _load_manifest(sdir: Path) -> dict[str, Any]:
    """Read the sandbox metadata manifest."""
    manifest_file = sdir / "manifest.json"
    if not manifest_file.exists():
        raise PlanSandboxError(f"Sandbox session manifest not found at '{manifest_file}'")
    try:
        return json.loads(manifest_file.read_text(encoding="utf-8"))
    except Exception as exc:
        raise PlanSandboxError(f"Failed to read sandbox manifest: {exc}")


def _save_manifest(sdir: Path, manifest: dict[str, Any]) -> None:
    """Write the sandbox metadata manifest atomically."""
    manifest_file = sdir / "manifest.json"
    atomic_write_text(manifest_file, json.dumps(manifest, indent=2))


def _action_create_sandbox(session_id: Optional[str]) -> dict[str, Any]:
    """Create a new isolated sandbox staging directory."""
    sid = session_id or f"stage_{uuid.uuid4().hex[:12]}"
    sdir = _get_sandbox_dir(sid)

    if sdir.exists():
        manifest = _load_manifest(sdir)
        return {
            "stage_id": sid,
            "sandbox_id": sid,
            "sandbox_dir": str(sdir),
            "created_at": manifest.get("created_at"),
            "status": manifest.get("status", "ACTIVE"),
            "staged_files_count": len(manifest.get("files", {})),
            "message": "Existing sandbox loaded",
        }

    sdir.mkdir(parents=True, mode=0o700, exist_ok=True)
    manifest = {
        "stage_id": sid,
        "created_at": time.time(),
        "status": "ACTIVE",
        "files": {},
    }
    _save_manifest(sdir, manifest)

    return {
        "stage_id": sid,
        "sandbox_id": sid,
        "sandbox_dir": str(sdir),
        "created_at": manifest["created_at"],
        "status": "ACTIVE",
        "staged_files_count": 0,
        "message": "New sandbox created successfully",
    }


def _action_stage_file(sid: str, raw_path: str) -> dict[str, Any]:
    """Copy an existing file from ALLOWED_ROOTS into the sandbox."""
    sdir = _get_sandbox_dir(sid)
    if not sdir.exists():
        raise PlanSandboxError(f"Sandbox '{sid}' does not exist. Call create_stage first.")

    manifest = _load_manifest(sdir)
    src_file = _resolve_and_validate_path(raw_path, must_exist=True, is_dir=False)

    # Use hash of original absolute path to avoid directory collision in sandbox
    path_key = str(src_file)
    file_id = hashlib.sha256(path_key.encode("utf-8")).hexdigest()[:16]
    staged_copy = sdir / f"file_{file_id}_{src_file.name}"

    shutil.copy2(src_file, staged_copy)
    file_hash = _sha256_file(src_file)

    manifest["files"][path_key] = {
        "original_path": path_key,
        "staged_file": staged_copy.name,
        "original_hash": file_hash,
        "staged_hash": file_hash,
        "staged_at": time.time(),
        "size_bytes": src_file.stat().st_size,
    }
    _save_manifest(sdir, manifest)

    return {
        "stage_id": sid,
        "sandbox_id": sid,
        "file_path": path_key,
        "original_hash": file_hash,
        "staged_file_name": staged_copy.name,
        "staged_files_count": len(manifest["files"]),
        "status": "STAGED",
    }


def _action_apply_edit(
    sid: str,
    raw_path: str,
    content: Optional[str],
    search_block: Optional[str],
    replace_block: Optional[str],
) -> dict[str, Any]:
    """Modify the sandboxed copy of a file without touching the working tree."""
    sdir = _get_sandbox_dir(sid)
    if not sdir.exists():
        raise PlanSandboxError(f"Sandbox '{sid}' does not exist.")

    manifest = _load_manifest(sdir)
    src_file = _resolve_and_validate_path(raw_path, must_exist=True, is_dir=False)
    path_key = str(src_file)

    if path_key not in manifest["files"]:
        # Auto-stage if not staged yet
        _action_stage_file(sid, raw_path)
        manifest = _load_manifest(sdir)

    file_info = manifest["files"][path_key]
    staged_copy = sdir / file_info["staged_file"]

    if content is not None:
        new_content = content
    elif search_block is not None and replace_block is not None:
        current_text = staged_copy.read_text(encoding="utf-8", errors="replace")
        if search_block not in current_text:
            raise ValueError(f"search_block was not found in staged file '{src_file.name}'")
        new_content = current_text.replace(search_block, replace_block, 1)
    else:
        raise ValueError("Must provide either 'content' or both 'search_block' and 'replace_block'.")

    atomic_write_text(staged_copy, new_content, mode=None, dir_mode=None)
    new_hash = _sha256_file(staged_copy)

    file_info["staged_hash"] = new_hash
    file_info["last_edited_at"] = time.time()
    _save_manifest(sdir, manifest)

    is_modified = new_hash != file_info["original_hash"]

    return {
        "stage_id": sid,
        "sandbox_id": sid,
        "file_path": path_key,
        "is_modified": is_modified,
        "original_hash": file_info["original_hash"],
        "staged_hash": new_hash,
        "size_bytes": len(new_content.encode("utf-8")),
    }


def _action_diff_sandbox(sid: str) -> dict[str, Any]:
    """Calculate unified diff between sandboxed files and the live disk files."""
    sdir = _get_sandbox_dir(sid)
    if not sdir.exists():
        raise PlanSandboxError(f"Sandbox '{sid}' does not exist.")

    manifest = _load_manifest(sdir)
    files_diff: list[dict[str, Any]] = []
    combined_diff_lines: list[str] = []
    total_additions = 0
    total_deletions = 0

    for path_key, file_info in manifest.get("files", {}).items():
        original_path = Path(path_key)
        staged_copy = sdir / file_info["staged_file"]

        if not original_path.exists():
            orig_lines = []
        else:
            orig_lines = original_path.read_text(encoding="utf-8", errors="replace").splitlines(keepends=True)

        if not staged_copy.exists():
            staged_lines = []
        else:
            staged_lines = staged_copy.read_text(encoding="utf-8", errors="replace").splitlines(keepends=True)

        diff = list(difflib.unified_diff(
            orig_lines,
            staged_lines,
            fromfile=f"a/{original_path.name}",
            tofile=f"b/{original_path.name}",
        ))

        file_adds = sum(1 for line in diff if line.startswith("+") and not line.startswith("+++"))
        file_dels = sum(1 for line in diff if line.startswith("-") and not line.startswith("---"))
        total_additions += file_adds
        total_deletions += file_dels

        diff_text = "".join(diff)
        if diff_text:
            combined_diff_lines.append(diff_text)

        files_diff.append({
            "file_path": path_key,
            "has_changes": len(diff) > 0,
            "additions": file_adds,
            "deletions": file_dels,
            "unified_diff": diff_text,
        })

    return {
        "stage_id": sid,
        "sandbox_id": sid,
        "total_files": len(files_diff),
        "modified_files_count": sum(1 for f in files_diff if f["has_changes"]),
        "total_additions": total_additions,
        "total_deletions": total_deletions,
        "files": files_diff,
        "unified_diff": "\n".join(combined_diff_lines),
    }


def _action_commit_sandbox(sid: str) -> dict[str, Any]:
    """Atomically commit all staged files from the sandbox to their target destinations."""
    sdir = _get_sandbox_dir(sid)
    if not sdir.exists():
        raise PlanSandboxError(f"Sandbox '{sid}' does not exist.")

    manifest = _load_manifest(sdir)
    committed: list[dict[str, Any]] = []

    for path_key, file_info in manifest.get("files", {}).items():
        dest_path = _resolve_and_validate_path(path_key, must_exist=False)
        staged_copy = sdir / file_info["staged_file"]

        if not staged_copy.exists():
            continue

        # Create backup of target file before committing
        backup_path = None
        if dest_path.exists():
            backup_path = dest_path.with_suffix(f"{dest_path.suffix}.bak_{sid}")
            shutil.copy2(dest_path, backup_path)

        # Atomic replacement: write to temp file on same filesystem, then replace
        temp_dest = dest_path.with_name(f".{dest_path.name}.stage_tmp_{os.getpid()}")
        shutil.copy2(staged_copy, temp_dest)
        temp_dest.replace(dest_path)

        committed.append({
            "file_path": path_key,
            "hash": _sha256_file(dest_path),
            "backup_path": str(backup_path) if backup_path else None,
        })

    manifest["status"] = "COMMITTED"
    manifest["committed_at"] = time.time()
    _save_manifest(sdir, manifest)

    return {
        "stage_id": sid,
        "sandbox_id": sid,
        "status": "COMMITTED",
        "committed_files_count": len(committed),
        "committed_files": committed,
    }


def _action_rollback_sandbox(sid: str) -> dict[str, Any]:
    """Discard all staged changes and securely clean up the sandbox directory."""
    sdir = _get_sandbox_dir(sid)
    if not sdir.exists():
        return {
            "stage_id": sid,
            "sandbox_id": sid,
            "status": "ROLLED_BACK",
            "message": "Sandbox already wiped or did not exist",
        }

    try:
        shutil.rmtree(sdir)
    except Exception as exc:
        raise PlanSandboxError(f"Failed to wipe sandbox directory '{sdir}': {exc}")

    return {
        "stage_id": sid,
        "sandbox_id": sid,
        "status": "ROLLED_BACK",
        "message": "Sandbox successfully discarded; live working tree untouched",
    }


def _action_list_sandboxes() -> dict[str, Any]:
    """List all existing plan sandbox staging sessions."""
    SANDBOX_BASE_DIR.mkdir(parents=True, exist_ok=True)
    sandboxes: list[dict[str, Any]] = []

    for entry in sorted(SANDBOX_BASE_DIR.iterdir()):
        if entry.is_dir():
            manifest_file = entry / "manifest.json"
            if manifest_file.exists():
                try:
                    m = json.loads(manifest_file.read_text(encoding="utf-8"))
                    sandboxes.append({
                        "stage_id": m.get("stage_id", entry.name),
                        "sandbox_id": m.get("stage_id", entry.name),
                        "created_at": m.get("created_at"),
                        "status": m.get("status", "ACTIVE"),
                        "files_staged": len(m.get("files", {})),
                        "directory": str(entry),
                    })
                except Exception:
                    pass

    return {
        "total_sandboxes": len(sandboxes),
        "sandboxes": sandboxes,
    }


def plan_sandbox(arguments: dict[str, Any], context: Optional[dict[str, Any]] = None) -> dict[str, Any]:
    """Operator tool entrypoint for plan_sandbox."""
    if not isinstance(arguments, dict):
        return _envelope_error("Arguments must be a dictionary.")

    action = arguments.get("action")
    if not action or action not in VALID_ACTIONS:
        return _envelope_error(
            f"Invalid or missing action '{action}'. Valid actions: {sorted(VALID_ACTIONS)}"
        )

    try:
        sid = arguments.get("stage_id") or arguments.get("sandbox_id")
        raw_path = arguments.get("file_path") or arguments.get("path")
        content = arguments.get("content")
        search_block = arguments.get("search_block")
        replace_block = arguments.get("replace_block")

        if action in ("create_stage", "create_sandbox"):
            data = _action_create_sandbox(sid)
            return _envelope_success(data)

        elif action == "stage_file":
            if not sid:
                return _envelope_error("Missing required parameter 'stage_id' or 'sandbox_id'.")
            if not raw_path:
                return _envelope_error("Missing required parameter 'file_path' or 'path'.")
            data = _action_stage_file(str(sid), str(raw_path))
            return _envelope_success(data)

        elif action == "apply_edit":
            if not sid:
                return _envelope_error("Missing required parameter 'stage_id' or 'sandbox_id'.")
            if not raw_path:
                return _envelope_error("Missing required parameter 'file_path' or 'path'.")
            data = _action_apply_edit(str(sid), str(raw_path), content, search_block, replace_block)
            return _envelope_success(data)

        elif action in ("diff_stage", "diff_sandbox"):
            if not sid:
                return _envelope_error("Missing required parameter 'stage_id' or 'sandbox_id'.")
            data = _action_diff_sandbox(str(sid))
            return _envelope_success(data)

        elif action in ("commit_stage", "commit_sandbox"):
            if not sid:
                return _envelope_error("Missing required parameter 'stage_id' or 'sandbox_id'.")
            data = _action_commit_sandbox(str(sid))
            return _envelope_success(data)

        elif action in ("rollback_stage", "rollback_sandbox"):
            if not sid:
                return _envelope_error("Missing required parameter 'stage_id' or 'sandbox_id'.")
            data = _action_rollback_sandbox(str(sid))
            return _envelope_success(data)

        elif action in ("list_sandboxes", "list_stages"):
            data = _action_list_sandboxes()
            return _envelope_success(data)

        else:
            return _envelope_error(f"Action '{action}' is not supported.")

    except Exception as exc:
        return _envelope_error(exc)


TOOL = {
    "name": "plan_sandbox",
    "description": (
        "Multi-stage transactional staging sandbox with rollback protection. "
        "Isolates multi-file edits in temporary branches/directories, calculates "
        "unified diffs, applies search/replace or full edits, and commits atomically or rolls back."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "action": {
                "type": "string",
                "enum": [
                    "create_stage",
                    "create_sandbox",
                    "stage_file",
                    "apply_edit",
                    "diff_stage",
                    "diff_sandbox",
                    "commit_stage",
                    "commit_sandbox",
                    "rollback_stage",
                    "rollback_sandbox",
                    "list_sandboxes",
                    "list_stages",
                ],
                "description": "Sandbox lifecycle action to perform.",
            },
            "stage_id": {
                "type": "string",
                "description": "Unique identifier of the sandbox session.",
            },
            "sandbox_id": {
                "type": "string",
                "description": "Alias for stage_id.",
            },
            "file_path": {
                "type": "string",
                "description": "File path within ALLOWED_ROOTS to stage or edit.",
            },
            "path": {
                "type": "string",
                "description": "Alias for file_path.",
            },
            "content": {
                "type": "string",
                "description": "New file content to write inside the sandbox.",
            },
            "search_block": {
                "type": "string",
                "description": "Exact text block to replace in the staged file.",
            },
            "replace_block": {
                "type": "string",
                "description": "Replacement text block.",
            },
        },
        "required": ["action"],
        "additionalProperties": False,
    },
    "handler": plan_sandbox,
    "approval": True,
}
