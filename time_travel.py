"""Session + Filesystem 'Time-Travel Fork' for Jarvis.

Binds conversation turns (`session_id`, `turn_index`, `messages`) with shadow-git
file snapshots from `CheckpointManager`. Rewinding/forking to any saved timepoint
creates a clean branched session (`fork-<id>`) with the exact conversation prefix
and optionally restores the workspace directory to that exact shadow-git commit.
"""

from __future__ import annotations

import fcntl
import json
import os
import threading
import time
import uuid
from contextlib import contextmanager
from pathlib import Path

import agent_cli
import checkpoint_manager

MAX_TIMEPOINTS = 300


class TimeTravelError(Exception):
    """Raised when a timepoint or checkpoint cannot be bound or restored."""


def _tt_dir() -> Path:
    d = agent_cli.ROOT.parent / "time_travel"
    d.mkdir(mode=0o700, parents=True, exist_ok=True)
    return d


def _index_path() -> Path:
    return _tt_dir() / "timepoints.json"


def _forks_dir() -> Path:
    d = _tt_dir() / "forks"
    d.mkdir(mode=0o700, parents=True, exist_ok=True)
    return d


@contextmanager
def _tt_lock():
    base = _tt_dir()
    fd = os.open(base / ".timetravel.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        try:
            os.close(fd)
        except OSError:
            pass


def _atomic_write_text(path: Path, text: str) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.tmp-{os.getpid()}-{threading.get_ident()}-{time.time_ns()}")
    try:
        tmp.write_text(text, encoding="utf-8")
        os.chmod(tmp, 0o600)
        tmp.replace(path)
    finally:
        if tmp.exists():
            try:
                tmp.unlink()
            except OSError:
                pass


def _load_rows() -> list[dict]:
    try:
        data = json.loads(_index_path().read_text(encoding="utf-8"))
        return [r for r in data if isinstance(r, dict)] if isinstance(data, list) else []
    except (OSError, ValueError):
        return []


def _save_rows(rows: list[dict]) -> None:
    _atomic_write_text(_index_path(), json.dumps(rows[-MAX_TIMEPOINTS:], indent=2, ensure_ascii=False))


def record_timepoint(*, session_id: str, turn_index: int = 0,
                     project_dir: str | Path | None = None,
                     messages: list[dict] | None = None,
                     label: str = "") -> dict:
    """Capture a shadow-git checkpoint (when project_dir is given) and bind it to a session turn."""
    sid = str(session_id or "default").strip()[:80]
    tp_id = f"tp-{uuid.uuid4().hex[:10]}"
    commit_hash = ""
    proj_str = ""

    if project_dir:
        proj = Path(project_dir).expanduser().resolve()
        if proj.is_dir():
            proj_str = str(proj)
            mgr = checkpoint_manager.default_manager()
            mgr.ensure_checkpoint(proj, reason=f"timepoint:{sid}:t{int(turn_index)}")
            snaps = mgr.list_checkpoints(proj)
            if snaps:
                commit_hash = str(snaps[0].get("hash") or snaps[0].get("short_hash") or "")

    msg_snapshot_file = ""
    if isinstance(messages, list):
        snap_path = _forks_dir() / f"{tp_id}-msgs.json"
        _atomic_write_text(snap_path, json.dumps(messages, ensure_ascii=False, indent=2))
        msg_snapshot_file = snap_path.name

    entry = {
        "id": tp_id,
        "session_id": sid,
        "turn_index": max(0, int(turn_index or 0)),
        "project_dir": proj_str,
        "commit_hash": commit_hash,
        "messages_file": msg_snapshot_file,
        "message_count": len(messages) if isinstance(messages, list) else 0,
        "label": str(label or f"Tura #{int(turn_index)}").strip()[:160],
        "created_at": round(time.time(), 3),
    }
    with _tt_lock():
        rows = _load_rows()
        rows.append(entry)
        _save_rows(rows)
    return entry


def list_timepoints(session_id: str = "", limit: int = 40) -> list[dict]:
    rows = _load_rows()
    if session_id:
        rows = [r for r in rows if r.get("session_id") == session_id]
    rows.sort(key=lambda r: float(r.get("created_at") or 0.0), reverse=True)
    return rows[:max(1, min(int(limit or 40), 200))]


def fork_timepoint(timepoint_id: str, *, restore_files: bool = False,
                   new_title: str = "") -> dict:
    """Create a branched session from `timepoint_id` and optionally rewind files to its checkpoint."""
    rows = _load_rows()
    tp = next((r for r in rows if r.get("id") == timepoint_id), None)
    if tp is None:
        raise TimeTravelError(f"Nie znaleziono punktu w czasie: {timepoint_id}")

    fork_session_id = f"{tp['session_id']}-fork-{uuid.uuid4().hex[:6]}"
    restored_messages = []
    if tp.get("messages_file"):
        mpath = _forks_dir() / str(tp["messages_file"])
        if mpath.is_file():
            try:
                loaded = json.loads(mpath.read_text(encoding="utf-8"))
                if isinstance(loaded, list):
                    cutoff = int(tp.get("turn_index") or len(loaded))
                    restored_messages = loaded[:cutoff] if cutoff > 0 else loaded
            except (OSError, ValueError):
                restored_messages = []

    fork_meta = {
        "fork_session_id": fork_session_id,
        "parent_session_id": tp["session_id"],
        "from_timepoint": tp["id"],
        "turn_index": tp["turn_index"],
        "title": str(new_title or f"Fork od {tp.get('label') or tp['id']}")[:140],
        "messages": restored_messages,
        "created_at": round(time.time(), 3),
    }
    fork_file = _forks_dir() / f"{fork_session_id}.json"
    _atomic_write_text(fork_file, json.dumps(fork_meta, ensure_ascii=False, indent=2))

    file_restore_result = None
    if restore_files:
        proj_str = str(tp.get("project_dir") or "")
        commit_hash = str(tp.get("commit_hash") or "")
        if not proj_str or not commit_hash:
            raise TimeTravelError("Ten punkt czasu nie posiada powiązanego checkpointu plików.")
        mgr = checkpoint_manager.default_manager()
        res = mgr.restore(Path(proj_str), commit_hash)
        if not isinstance(res, dict) or not res.get("success", res.get("ok", False)):
            err = (res or {}).get("error") or "Przywrócenie plików nie powiodło się."
            raise TimeTravelError(str(err))
        file_restore_result = res

    return {
        "ok": True,
        "fork_session_id": fork_session_id,
        "from_timepoint": tp["id"],
        "messages_restored": len(restored_messages),
        "files_restored": bool(restore_files),
        "checkpoint_hash": tp.get("commit_hash") or "",
        "restore_detail": file_restore_result,
    }
