"""Pure standard library text diffing, patch application, 3-way merge, and similarity comparison."""

from __future__ import annotations

import difflib
import os
from pathlib import Path
from typing import Any

try:
    from atomic_io import atomic_write_text
except ImportError as _error:
    # Fail closed: a plain write_text silently loses the atomicity contract the
    # in-place patch path is advertised under, and a crash mid-write would
    # destroy the file being patched instead of leaving the original intact.
    _ATOMIC_IMPORT_ERROR = str(_error)

    def atomic_write_text(target: Path, text: str, **kwargs) -> Path | None:  # type: ignore
        raise RuntimeError(
            "diff_patch in-place writes require the atomic_io helper; "
            f"import failed: {_ATOMIC_IMPORT_ERROR}"
        )

try:
    import operator_tools
except ImportError:
    operator_tools = None  # type: ignore

MAX_DIFF_BYTES = 512 * 1024  # 512 KB
MAX_DIFF_LINES = 10_000


def _safe_resolve_path(raw_path: str, must_exist: bool = False) -> Path:
    """Validate and canonicalize path against allowed roots and sensitive targets."""
    if not isinstance(raw_path, str) or not raw_path.strip():
        raise ValueError("Target file path must be a non-empty string.")
    if len(raw_path) > 4096:
        raise ValueError("File path exceeds maximum length.")

    expanded = Path(raw_path).expanduser()
    if any(part in ("..", "") for part in expanded.parts):
        raise PermissionError(f"Directory traversal sequences not allowed: {raw_path}")

    try:
        resolved = Path(os.path.realpath(str(expanded)))
    except (OSError, ValueError):
        resolved = expanded.resolve()

    if operator_tools is not None:
        if not operator_tools._inside(resolved):
            raise PermissionError(f"Path outside allowed roots: {resolved}")
        if operator_tools.is_sensitive(resolved) or operator_tools.is_credential_target(resolved):
            raise PermissionError(f"Access to sensitive/credential target is blocked: {resolved}")
    else:
        home = Path.home().resolve()
        tmp = Path("/tmp").resolve()
        allowed = (
            resolved == home or resolved.is_relative_to(home) or
            resolved == tmp or resolved.is_relative_to(tmp)
        )
        if not allowed:
            raise PermissionError(f"Path outside allowed directories: {resolved}")

    if must_exist and not resolved.is_file():
        raise FileNotFoundError(f"File not found or is not a regular file: {resolved}")

    return resolved


def _read_file_safe(path: Path) -> str:
    """Read file content with strict size guard."""
    size = path.stat().st_size
    if size > MAX_DIFF_BYTES:
        raise ValueError(f"File {path.name} exceeds maximum allowed size ({size} > {MAX_DIFF_BYTES} bytes)")
    return path.read_text(encoding="utf-8", errors="replace")


def _get_text(content: Any, path_arg: str | None, param_name: str) -> str:
    """Resolve text either from direct string or target file path."""
    if content is not None:
        if not isinstance(content, str):
            raise TypeError(f"Parameter '{param_name}' must be a string.")
        encoded = content.encode("utf-8")
        if len(encoded) > MAX_DIFF_BYTES:
            raise ValueError(f"Parameter '{param_name}' exceeds maximum limit of {MAX_DIFF_BYTES} bytes.")
        return content

    if path_arg:
        resolved = _safe_resolve_path(path_arg, must_exist=True)
        return _read_file_safe(resolved)

    return ""


def _parse_unified_patch(patch_text: str) -> list[dict[str, Any]]:
    """Parse unified diff text into structured hunks."""
    lines = patch_text.splitlines(keepends=True)
    hunks = []
    current_hunk = None

    for line in lines:
        if line.startswith("@@"):
            # Format: @@ -start,len +start,len @@
            parts = line.split("@@")
            if len(parts) >= 3:
                header = parts[1].strip()
                hunk_info = header.split(" ")
                if len(hunk_info) >= 2:
                    orig_info = hunk_info[0].lstrip("-").split(",")
                    orig_start = int(orig_info[0]) if orig_info[0].isdigit() else 1
                    orig_count = int(orig_info[1]) if len(orig_info) > 1 and orig_info[1].isdigit() else 1

                    mod_info = hunk_info[1].lstrip("+").split(",")
                    mod_start = int(mod_info[0]) if mod_info[0].isdigit() else 1
                    mod_count = int(mod_info[1]) if len(mod_info) > 1 and mod_info[1].isdigit() else 1

                    current_hunk = {
                        "header": line,
                        "orig_start": orig_start,
                        "orig_count": orig_count,
                        "mod_start": mod_start,
                        "mod_count": mod_count,
                        "lines": [],
                    }
                    hunks.append(current_hunk)
                    continue

        if current_hunk is not None:
            if line.startswith(("-", "+", " ", "\\")):
                current_hunk["lines"].append(line)

    return hunks


def _apply_patch(original_text: str, patch_text: str) -> tuple[str, int, int]:
    """Apply a unified diff patch to original text.

    Returns (patched_text, hunks_applied, hunks_failed).
    """
    hunks = _parse_unified_patch(patch_text)
    if not hunks:
        # If no standard @@ headers found, check if patch_text was empty or unparseable
        if not patch_text.strip():
            return original_text, 0, 0
        raise ValueError("Could not parse any valid diff hunks from patch_text.")

    orig_lines = original_text.splitlines(keepends=True)
    if not orig_lines and original_text:
        orig_lines = [original_text]

    applied = 0
    failed = 0

    # We iterate and apply hunks while keeping track of line offsets
    offset = 0
    output_lines = list(orig_lines)

    for hunk in hunks:
        if hunk.get("orig_count") == 0:
            # A context-free pure-insertion hunk "-N,0" places new lines AFTER
            # old line N (GNU unified-diff semantics), i.e. at 0-based index N;
            # the generic "- 1" would insert them one line too early.
            orig_start = hunk["orig_start"] + offset
        else:
            orig_start = hunk["orig_start"] - 1 + offset
        hunk_lines = hunk["lines"]

        # Extract expected original lines from hunk
        expected_orig = []
        replacement = []
        for hline in hunk_lines:
            prefix = hline[:1]
            content = hline[1:]
            if prefix == " ":
                expected_orig.append(content)
                replacement.append(content)
            elif prefix == "-":
                expected_orig.append(content)
            elif prefix == "+":
                replacement.append(content)
            elif prefix == "\\":
                # '\ No newline at end of file' - strip newline from last replacement line if needed
                if replacement and replacement[-1].endswith("\n"):
                    replacement[-1] = replacement[-1].rstrip("\r\n")

        # Try to match at orig_start
        match_idx = -1
        # 1. Exact expected position
        if 0 <= orig_start <= len(output_lines):
            slice_end = orig_start + len(expected_orig)
            if [line.rstrip("\r\n") for line in output_lines[orig_start:slice_end]] == [line.rstrip("\r\n") for line in expected_orig]:
                match_idx = orig_start

        # 2. Search fuzzily around offset (+/- 20 lines) if not exact match
        if match_idx == -1:
            search_min = max(0, orig_start - 20)
            search_max = min(len(output_lines), orig_start + 20)
            for idx in range(search_min, search_max + 1):
                slice_end = idx + len(expected_orig)
                if slice_end <= len(output_lines):
                    if [line.rstrip("\r\n") for line in output_lines[idx:slice_end]] == [line.rstrip("\r\n") for line in expected_orig]:
                        match_idx = idx
                        break

        if match_idx != -1:
            slice_end = match_idx + len(expected_orig)
            output_lines[match_idx:slice_end] = replacement
            offset += len(replacement) - len(expected_orig)
            applied += 1
        else:
            failed += 1

    patched_text = "".join(output_lines)
    return patched_text, applied, failed


def _render_region_with_changes(base_lines: list[str], changes: dict, start: int, end: int) -> list[str]:
    """One side's version of base[start:end) with its embedded changes applied."""
    out: list[str] = []
    pos = start
    while pos < end:
        entry = changes.get(pos)
        if entry is not None:
            _, lines, ch_end = entry
            out.extend(lines)
            pos = max(ch_end, pos + 1)
        else:
            if pos < len(base_lines):
                out.append(base_lines[pos])
            pos += 1
    return out


def _conflict_span(mine_changes: dict, theirs_changes: dict, start: int, initial_end: int) -> int:
    """Base span a conflict block covering a change at `start` must absorb.

    Any change that begins inside the span belongs to the block, and its end
    can extend the span; keep absorbing until both sides fall quiet past it.
    """
    end = max(start, initial_end)
    grown = True
    while grown:
        grown = False
        for changes in (mine_changes, theirs_changes):
            for key in changes:
                if start <= key < end:
                    ch_end = changes[key][2]
                    if ch_end > end:
                        end = ch_end
                        grown = True
    return end


def _merge3_impl(base: str, mine: str, theirs: str) -> tuple[str, int]:
    """Perform a 3-way line merge between base, mine, and theirs.

    Returns (merged_text, conflict_count).
    """
    base_lines = base.splitlines(keepends=True)
    mine_lines = mine.splitlines(keepends=True)
    theirs_lines = theirs.splitlines(keepends=True)

    sm_mine = difflib.SequenceMatcher(None, base_lines, mine_lines)
    sm_theirs = difflib.SequenceMatcher(None, base_lines, theirs_lines)

    mine_ops = sm_mine.get_opcodes()
    theirs_ops = sm_theirs.get_opcodes()

    # Align base indices
    # We will build base_line-indexed changes for both sides
    n_base = len(base_lines)

    mine_changes: dict[int, tuple[str, list[str], int]] = {}  # base_idx -> (tag, lines, end_idx)
    for tag, i1, i2, j1, j2 in mine_ops:
        if tag != "equal":
            mine_changes[i1] = (tag, mine_lines[j1:j2], i2)

    theirs_changes: dict[int, tuple[str, list[str], int]] = {}
    for tag, i1, i2, j1, j2 in theirs_ops:
        if tag != "equal":
            theirs_changes[i1] = (tag, theirs_lines[j1:j2], i2)

    merged: list[str] = []
    conflicts = 0
    idx = 0

    while idx < n_base or (idx == n_base and (idx in mine_changes or idx in theirs_changes)):
        has_mine = idx in mine_changes
        has_theirs = idx in theirs_changes

        if not has_mine and not has_theirs:
            if idx < n_base:
                merged.append(base_lines[idx])
            idx += 1
            continue

        # One or both have changes starting at or covering idx
        m_tag, m_lines, m_end = mine_changes.get(idx, ("equal", base_lines[idx:idx+1], idx + 1))
        t_tag, t_lines, t_end = theirs_changes.get(idx, ("equal", base_lines[idx:idx+1], idx + 1))
        consumed_end = max(m_end, t_end, idx + 1)

        # The other side's change embedded inside this block's range was
        # silently dropped by the block's index jump: it is a conflict, and
        # the conflict block must render (and consume) both sides' edits.
        embedded = any(idx < k < consumed_end for k in mine_changes)
        embedded = embedded or any(idx < k < consumed_end for k in theirs_changes)
        if embedded:
            span_end = _conflict_span(mine_changes, theirs_changes, idx, consumed_end)
            conflicts += 1
            merged.append("<<<<<<< ORIGINAL\n")
            merged.extend(_render_region_with_changes(base_lines, mine_changes, idx, span_end))
            merged.append("=======\n")
            merged.extend(_render_region_with_changes(base_lines, theirs_changes, idx, span_end))
            merged.append(">>>>>>> MODIFIED\n")
            idx = max(span_end, idx + 1)
            continue

        # Check if identical changes
        if m_lines == t_lines:
            merged.extend(m_lines)
        elif not has_mine:
            # Only theirs changed
            merged.extend(t_lines)
        elif not has_theirs:
            # Only mine changed
            merged.extend(m_lines)
        else:
            # Both changed differently -> CONFLICT
            conflicts += 1
            merged.append("<<<<<<< ORIGINAL\n")
            merged.extend(m_lines)
            merged.append("=======\n")
            merged.extend(t_lines)
            merged.append(">>>>>>> MODIFIED\n")
        idx = consumed_end

    return "".join(merged), conflicts


def diff_patch(arguments: dict[str, Any], context: dict[str, Any] | None = None) -> dict[str, Any]:
    """Diffing, patch preview/application, 3-way merge, and similarity ratio handler."""
    del context
    try:
        args = arguments or {}
        action = str(args.get("action") or "").strip().lower()
        if not action:
            return {"ok": False, "success": False, "data": None, "result": None, "error": "Missing required 'action' parameter."}

        target_file = args.get("target_file")
        in_place = bool(args.get("in_place", False))
        context_lines = min(20, max(0, int(args.get("context_lines") if args.get("context_lines") is not None else 3)))

        if action == "diff":
            orig = _get_text(args.get("original"), target_file, "original")
            mod = _get_text(args.get("modified"), None, "modified")

            orig_lines = orig.splitlines(keepends=True)
            mod_lines = mod.splitlines(keepends=True)

            if len(orig_lines) > MAX_DIFF_LINES or len(mod_lines) > MAX_DIFF_LINES:
                return {
                    "ok": False,
                    "success": False,
                    "data": None,
                    "result": None,
                    "error": f"Input exceeds maximum line limit ({MAX_DIFF_LINES} lines)",
                }

            diff_iter = difflib.unified_diff(
                orig_lines,
                mod_lines,
                fromfile="a/original",
                tofile="b/modified",
                n=context_lines,
            )
            diff_lines = list(diff_iter)
            diff_text = "".join(diff_lines)

            adds = sum(1 for line in diff_lines if line.startswith("+") and not line.startswith("+++"))
            dels = sum(1 for line in diff_lines if line.startswith("-") and not line.startswith("---"))
            matcher = difflib.SequenceMatcher(None, orig, mod)
            ratio = round(matcher.ratio(), 4)

            payload = {
                "diff": diff_text,
                "additions": adds,
                "deletions": dels,
                "identical": orig == mod,
                "similarity_ratio": ratio,
                "context_lines": context_lines,
            }
            return {"ok": True, "success": True, "data": payload, "result": payload, "error": None}

        elif action == "compare_ratio":
            orig = _get_text(args.get("original"), target_file, "original")
            mod = _get_text(args.get("modified"), None, "modified")

            matcher = difflib.SequenceMatcher(None, orig, mod)
            ratio = round(matcher.ratio(), 4)
            quick_ratio = round(matcher.quick_ratio(), 4)

            payload = {
                "ratio": ratio,
                "quick_ratio": quick_ratio,
                "identical": orig == mod,
                "original_length": len(orig),
                "modified_length": len(mod),
            }
            return {"ok": True, "success": True, "data": payload, "result": payload, "error": None}

        elif action == "patch":
            if in_place and not target_file:
                return {
                    "ok": False,
                    "success": False,
                    "data": None,
                    "result": None,
                    "error": "Cannot apply patch in_place without 'target_file'.",
                }

            patch_text = args.get("patch_text")
            if not patch_text or not isinstance(patch_text, str):
                return {
                    "ok": False,
                    "success": False,
                    "data": None,
                    "result": None,
                    "error": "Parameter 'patch_text' must be a non-empty string.",
                }

            if len(patch_text.encode("utf-8")) > MAX_DIFF_BYTES:
                return {
                    "ok": False,
                    "success": False,
                    "data": None,
                    "result": None,
                    "error": f"Parameter 'patch_text' exceeds limit of {MAX_DIFF_BYTES} bytes.",
                }

            target_path = None
            if target_file:
                target_path = _safe_resolve_path(target_file, must_exist=True)
                orig_text = _read_file_safe(target_path)
            else:
                orig_text = _get_text(args.get("original"), None, "original")

            patched, applied, failed = _apply_patch(orig_text, patch_text)

            if in_place:
                if not target_path:
                    return {
                        "ok": False,
                        "success": False,
                        "data": None,
                        "result": None,
                        "error": "Cannot apply patch in_place without 'target_file'.",
                    }
                atomic_write_text(target_path, patched)

            payload = {
                "patched_text": patched,
                "hunks_applied": applied,
                "hunks_failed": failed,
                "in_place": in_place,
                "target_file": str(target_path) if target_path else None,
                "success_rate": 1.0 if (applied + failed == 0 or failed == 0) else round(applied / (applied + failed), 2),
            }
            return {"ok": True, "success": True, "data": payload, "result": payload, "error": None}

        elif action == "merge3":
            base = _get_text(args.get("base"), None, "base")
            mine = _get_text(args.get("original"), target_file, "original")
            theirs = _get_text(args.get("modified"), None, "modified")

            merged_text, conflicts = _merge3_impl(base, mine, theirs)

            payload = {
                "merged_text": merged_text,
                "conflicts": conflicts,
                "clean": conflicts == 0,
            }
            return {"ok": True, "success": True, "data": payload, "result": payload, "error": None}

        else:
            return {
                "ok": False,
                "success": False,
                "data": None,
                "result": None,
                "error": f"Unsupported action: {action!r}. Supported actions: diff, patch, merge3, compare_ratio.",
            }

    except Exception as err:
        return {
            "ok": False,
            "success": False,
            "data": None,
            "result": None,
            "error": f"{type(err).__name__}: {err}",
        }


TOOL = {
    "name": "diff_patch",
    "description": (
        "Pure Python text diffing, unified patch generation, patch application (dry-run & in-place), "
        "3-way line merge, and text similarity ratio calculation."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "action": {
                "type": "string",
                "enum": ["diff", "patch", "merge3", "compare_ratio"],
                "description": "Operation to perform.",
            },
            "original": {"type": "string", "description": "Original text string."},
            "modified": {"type": "string", "description": "Modified text string."},
            "base": {"type": "string", "description": "Base text string for 3-way merge."},
            "patch_text": {"type": "string", "description": "Unified diff patch string to apply."},
            "target_file": {"type": "string", "description": "Target file path to diff or patch."},
            "in_place": {"type": "boolean", "description": "Write patched content to target_file (default: false)."},
            "context_lines": {
                "type": "integer",
                "minimum": 0,
                "maximum": 20,
                "description": "Context lines for diff (default: 3).",
            },
        },
        "required": ["action"],
        "additionalProperties": False,
    },
    "handler": diff_patch,
    "approval": True,
}
