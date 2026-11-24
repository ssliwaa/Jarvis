"""Instant background watcher for the knowledge vault.

Monitors the markdown notes tree (e.g. ~/notes) and automatically
rebuilds viewer/graph-data.js whenever notes are created, modified or deleted,
eliminating the need for manual 'python3 build.py' runs.
"""
from __future__ import annotations

import os
import sys
import threading
import time
from pathlib import Path

import build

PROJECT_ROOT = Path(__file__).resolve().parent
DEFAULT_VAULT = Path(os.environ.get("JARVIS_VAULT", Path.home() / "notes")).expanduser()
GRAPH_OUTPUT = PROJECT_ROOT / "viewer/graph-data.js"
POLL_INTERVAL = 1.0
DEBOUNCE_SECONDS = 0.5

_WATCHER_THREAD: threading.Thread | None = None
_WATCHER_STOP = threading.Event()
_LOCK = threading.Lock()
_STATUS = {
    "running": False,
    "vault": str(DEFAULT_VAULT),
    "last_rebuild": None,
    "rebuild_count": 0,
    "notes_count": 0,
    "links_count": 0,
    "last_error": None,
}


def _scan_mtimes(vault_dir: Path) -> dict[str, float]:
    mtimes = {}
    if not vault_dir.is_dir():
        return mtimes
    try:
        for path in vault_dir.rglob("*.md"):
            try:
                rel = path.relative_to(vault_dir)
                if any(part in ("captures", ".git", ".trash", "trash") for part in rel.parts):
                    continue
                if path.name.startswith(("preflight", "tmp", ".tmp")):
                    continue
                if path.is_file() and not path.is_symlink():
                    mtimes[str(path)] = path.stat().st_mtime
            except OSError:
                continue
    except OSError:
        pass
    return mtimes


def rebuild_now(vault_dir: Path | None = None, output: Path | None = None) -> dict:
    """Run an immediate graph rebuild and update status."""
    v_dir = Path(vault_dir or DEFAULT_VAULT).expanduser()
    out_file = Path(output or GRAPH_OUTPUT).resolve()
    with _LOCK:
        try:
            graph = build.make_graph(v_dir)
            build.write_graph(graph, out_file)
            _STATUS["last_rebuild"] = time.time()
            _STATUS["rebuild_count"] += 1
            _STATUS["notes_count"] = len(graph.get("nodes", []))
            _STATUS["links_count"] = len(graph.get("links", []))
            _STATUS["last_error"] = None
            return {
                "ok": True,
                "notes": _STATUS["notes_count"],
                "links": _STATUS["links_count"],
                "output": str(out_file),
            }
        except Exception as error:
            _STATUS["last_error"] = f"{type(error).__name__}: {error}"
            print(f"[vault_watcher] rebuild failed: {error}", file=sys.stderr)
            return {"ok": False, "error": _STATUS["last_error"]}


def status() -> dict:
    with _LOCK:
        return dict(_STATUS)


def start_watcher(vault_dir: Path | None = None,
                  output: Path | None = None,
                  interval: float = POLL_INTERVAL) -> threading.Thread:
    """Start the lightweight background watcher thread."""
    global _WATCHER_THREAD
    with _LOCK:
        if _WATCHER_THREAD is not None and _WATCHER_THREAD.is_alive():
            return _WATCHER_THREAD
        _WATCHER_STOP.clear()

    v_dir = Path(vault_dir or DEFAULT_VAULT).expanduser()
    out_file = Path(output or GRAPH_OUTPUT).resolve()

    def _loop():
        _STATUS["running"] = True
        _STATUS["vault"] = str(v_dir)
        known_mtimes = _scan_mtimes(v_dir)
        while not _WATCHER_STOP.is_set():
            time.sleep(interval)
            current_mtimes = _scan_mtimes(v_dir)
            if current_mtimes != known_mtimes:
                # Changes detected; debounce briefly
                time.sleep(DEBOUNCE_SECONDS)
                known_mtimes = _scan_mtimes(v_dir)
                rebuild_now(v_dir, out_file)

        _STATUS["running"] = False

    thread = threading.Thread(target=_loop, name="jarvis-vault-watcher", daemon=True)
    thread.start()
    _WATCHER_THREAD = thread
    return thread


def stop_watcher():
    _WATCHER_STOP.set()
