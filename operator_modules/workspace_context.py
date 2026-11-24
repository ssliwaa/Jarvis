"""On-demand Active Workspace Context extractor with mandatory secret redaction.

Captures the user's immediate Linux working context (focused desktop window,
git repository status, recently modified project files, and opt-in clipboard)
so deictic requests ("napraw ten błąd", "przetłumacz to co mam na ekranie",
"dodaj ten artykuł do Sejfu") resolve against real desktop/workspace state
without polling in the background.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any

HOME = Path.home()
DEFAULT_WORKSPACE = Path(os.environ.get("JARVIS_WORKSPACE", str(HOME / "Jarvis"))).expanduser()
SKIP_DIRS = frozenset({
    ".git", ".venv", "venv", "node_modules", "__pycache__", ".mypy_cache",
    ".pytest_cache", ".obsidian", ".trash", ".jarvis-tools", ".ssh", ".gnupg",
    ".aws", ".config", ".cache", ".local",
})
_FALLBACK_SECRET_RE = re.compile(
    r"(?:\bsk-(?:or-|ant-)?[A-Za-z0-9_-]{8,}|\bgsk_[A-Za-z0-9_-]{16,}|"
    r"\bgh[pousr]_[A-Za-z0-9_]{20,}|\bAKIA[A-Z0-9]{16}\b|\bBearer\s+\S+|"
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|\Z)|"
    r"(?:api[_-]?key|token|password|secret)\s*[:=]\s*[^\s,;]{4,})",
    re.I | re.S,
)


def _safe_redact(text: Any, limit: int = 2000) -> str:
    try:
        from operator_tools import redact
        return redact(text, limit)
    except Exception:
        value = _FALLBACK_SECRET_RE.sub("[REDACTED]", str(text or ""))
        value = value.replace(str(HOME) + "/", "~/")
        return value[:limit]


def _is_protected(path: Path) -> bool:
    try:
        from operator_tools import is_sensitive_target
        return bool(is_sensitive_target(path))
    except Exception:
        parts = {p.casefold() for p in path.parts}
        return bool(parts & {".ssh", ".gnupg", ".aws", ".jarvis-tools"}) or path.name.startswith(".env")


def _run_quick(argv: list[str], cwd: Path | None = None, timeout: float = 2.5) -> tuple[int, str]:
    try:
        proc = subprocess.run(
            argv,
            cwd=str(cwd) if cwd else None,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return proc.returncode, (proc.stdout or proc.stderr or "").strip()
    except (OSError, subprocess.SubprocessError):
        return 1, ""


def _active_window() -> dict[str, Any] | None:
    """Inspect focused desktop window via CuaDriver or xdotool without starting a daemon."""
    try:
        from operator_tools import CuaDriver
        driver = CuaDriver()
        sock = HOME / ".cache" / "cua-driver" / "cua-driver.sock"
        if driver.available() and sock.exists():
            windows = driver.windows()
            if windows:
                focused = next(
                    (w for w in windows if w.get("focused") or w.get("active") or w.get("is_active")),
                    windows[0],
                )
                return {
                    "source": "cua-driver",
                    "app": _safe_redact(focused.get("app_name") or focused.get("class") or "", 120),
                    "title": _safe_redact(focused.get("title") or "", 240),
                    "pid": focused.get("pid"),
                    "window_id": focused.get("window_id") or focused.get("id"),
                }
    except Exception:
        pass

    if shutil.which("xdotool") and os.environ.get("DISPLAY"):
        code, win_id = _run_quick(["xdotool", "getactivewindow"], timeout=1.5)
        if code == 0 and win_id.isdigit():
            _, title = _run_quick(["xdotool", "getwindowname", win_id], timeout=1.5)
            _, pid_str = _run_quick(["xdotool", "getwindowpid", win_id], timeout=1.5)
            return {
                "source": "xdotool",
                "app": "",
                "title": _safe_redact(title, 240),
                "pid": int(pid_str) if pid_str.isdigit() else None,
                "window_id": int(win_id),
            }
    return None


def _git_context(workdir: Path) -> dict[str, Any] | None:
    if not workdir.is_dir() or not shutil.which("git"):
        return None
    code, top = _run_quick(["git", "rev-parse", "--show-toplevel"], cwd=workdir, timeout=2.0)
    if code != 0 or not top:
        return None
    repo_root = Path(top.splitlines()[0].strip())
    _, branch = _run_quick(["git", "rev-parse", "--abbrev-ref", "HEAD"], cwd=repo_root, timeout=2.0)
    _, status_out = _run_quick(["git", "status", "--porcelain"], cwd=repo_root, timeout=2.5)
    modified: list[str] = []
    untracked: list[str] = []
    for line in status_out.splitlines()[:40]:
        if len(line) < 4:
            continue
        xy, rel = line[:2], line[3:].strip()
        if xy == "??":
            untracked.append(_safe_redact(rel, 160))
        else:
            modified.append(_safe_redact(rel, 160))
    _, last_commit = _run_quick(["git", "log", "-1", "--oneline"], cwd=repo_root, timeout=2.0)
    return {
        "root": _safe_redact(str(repo_root), 240),
        "branch": _safe_redact(branch, 80),
        "dirty": bool(modified or untracked),
        "modified_files": modified[:15],
        "untracked_files": untracked[:10],
        "last_commit": _safe_redact(last_commit, 160),
    }


def _recent_files(workdir: Path, limit: int = 8) -> list[dict[str, Any]]:
    if not workdir.is_dir() or _is_protected(workdir):
        return []
    found: list[tuple[float, Path, int]] = []
    inspected = 0

    def walk(folder: Path, depth: int) -> None:
        nonlocal inspected
        if depth > 3 or inspected >= 1500:
            return
        try:
            entries = list(folder.iterdir())
        except OSError:
            return
        for entry in entries:
            if inspected >= 1500:
                return
            name = entry.name
            if name in SKIP_DIRS or (name.startswith(".") and name not in (".gitignore",)):
                continue
            if entry.is_symlink():
                continue
            inspected += 1
            try:
                if entry.is_dir():
                    walk(entry, depth + 1)
                elif entry.is_file() and not _is_protected(entry):
                    st = entry.stat()
                    found.append((st.st_mtime, entry, st.st_size))
            except OSError:
                continue

    walk(workdir, 0)
    found.sort(key=lambda item: item[0], reverse=True)
    now = time.time()
    rows = []
    for mtime, path, size in found[:max(1, min(limit, 20))]:
        try:
            rel = str(path.relative_to(workdir))
        except ValueError:
            rel = str(path)
        rows.append({
            "path": _safe_redact(rel, 200),
            "bytes": size,
            "age_seconds": max(0, int(now - mtime)),
        })
    return rows


def _read_clipboard() -> dict[str, Any]:
    """Read plain-text clipboard only when explicitly requested, and redact secrets."""
    commands: list[list[str]] = []
    if os.environ.get("WAYLAND_DISPLAY") and shutil.which("wl-paste"):
        commands.append(["wl-paste", "--no-newline", "--type", "text/plain"])
    if os.environ.get("DISPLAY"):
        if shutil.which("xclip"):
            commands.append(["xclip", "-selection", "clipboard", "-o"])
        if shutil.which("xsel"):
            commands.append(["xsel", "--clipboard", "--output"])
    for argv in commands:
        code, out = _run_quick(argv, timeout=1.5)
        if code == 0:
            redacted = _safe_redact(out, 1500)
            return {
                "available": True,
                "chars": len(out),
                "truncated": len(out) > 1500,
                "text": redacted,
            }
    return {"available": False, "chars": 0, "truncated": False, "text": ""}


def capture_workspace_context(
    cwd: str | Path | None = None,
    *,
    include_clipboard: bool = False,
    recent_limit: int = 8,
) -> dict[str, Any]:
    """Collect a bounded, secret-redacted snapshot of the active workspace."""
    raw_dir = Path(cwd).expanduser() if cwd else (DEFAULT_WORKSPACE if DEFAULT_WORKSPACE.is_dir() else HOME)
    try:
        workdir = raw_dir.resolve()
    except OSError:
        workdir = HOME
    if not workdir.is_dir() or _is_protected(workdir):
        workdir = HOME

    window = _active_window()
    git_info = _git_context(workdir)
    recent = _recent_files(workdir, limit=recent_limit)
    clipboard = _read_clipboard() if include_clipboard else None

    summary_parts = [f"cwd={_safe_redact(str(workdir), 120)}"]
    if window and (window.get("title") or window.get("app")):
        wlabel = " — ".join(p for p in (window.get("app"), window.get("title")) if p)
        summary_parts.append(f"okno={wlabel[:100]}")
    if git_info:
        dirty_tag = f"{len(git_info['modified_files'])} zmienionych" if git_info["dirty"] else "czyste"
        summary_parts.append(f"git={git_info['branch']} ({dirty_tag})")
    if recent:
        summary_parts.append(f"ostatni_plik={recent[0]['path']}")

    return {
        "ok": True,
        "cwd": _safe_redact(str(workdir), 240),
        "active_window": window,
        "git": git_info,
        "recent_files": recent,
        "clipboard": clipboard,
        "summary": " | ".join(summary_parts),
    }


def _requires_approval(arguments: dict[str, Any] | None = None) -> bool:
    """Clipboard may hold copied credentials or private text, so reading it asks approval."""
    args = arguments if isinstance(arguments, dict) else {}
    return bool(args.get("include_clipboard", False))


def workspace_context_handler(arguments: dict[str, Any], context=None) -> dict[str, Any]:
    del context
    args = arguments if isinstance(arguments, dict) else {}
    raw_limit = args.get("recent_limit")
    try:
        recent_limit = max(1, min(int(raw_limit if raw_limit is not None else 8), 20))
    except (TypeError, ValueError):
        return {"ok": False, "error": "Parameter 'recent_limit' must be an integer."}
    return capture_workspace_context(
        cwd=args.get("cwd"),
        include_clipboard=bool(args.get("include_clipboard", False)),
        recent_limit=recent_limit,
    )


TOOL = {
    "name": "workspace_context",
    "description": (
        "Capture the user's active Linux workspace context on demand: focused desktop window, "
        "current git branch & modified files, recently edited files, and opt-in clipboard text "
        "(secret-redacted; include_clipboard=true requires approval)."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "cwd": {
                "type": "string",
                "description": "Optional project directory to inspect (defaults to active Jarvis workspace).",
            },
            "include_clipboard": {
                "type": "boolean",
                "description": "Include redacted plain-text clipboard contents (default: false; requires approval).",
            },
            "recent_limit": {
                "type": "integer",
                "minimum": 1,
                "maximum": 20,
                "description": "Maximum number of recently modified files to list (default: 8).",
            },
        },
        "additionalProperties": False,
    },
    "handler": workspace_context_handler,
    "approval": True,
    "approval_predicate": _requires_approval,
}
