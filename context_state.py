"""Persistence and mutual exclusion for context-compression state.

Three concerns live here instead of inside the compressor:

* a small JSON state blob per conversation (summary, counters, lineage),
* the process-wide lease that stops two lanes from compacting the same
  conversation at once, and
* bounded lineage entries so a compaction can be audited without storing the
  whole removed transcript.

Hermes spreads equivalent behaviour across its session DB, a lease row and a
telemetry table.  Jarvis has one SQLite session store and no multi-process
gateway, so the same contract fits in this module and a generic
``context_state`` table.
"""
from __future__ import annotations

import contextlib
import copy
import json
import os
import re
import tempfile
import threading
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterator, Protocol

STATE_KEY_RE = re.compile(r"[A-Za-z0-9_.:-]{1,160}")
MAX_STATE_BYTES = 512 * 1024
MAX_SUMMARY_CHARS = 80_000
MAX_LINEAGE = 30


class CompressionLeaseBusy(RuntimeError):
    """Another thread is already compacting this conversation."""


@dataclass
class CompressionState:
    """Durable per-conversation state.

    ``summary`` is the rolling summary BODY (without the model-visible prefix).
    ``lineage`` is a bounded list of compaction events.  Counters mirror the
    guards in the compressor: a restart must not silently re-enable thrashing.
    """

    key: str = ""
    summary: str = ""
    summary_has_user_turn: bool | None = None
    generation: int = 0
    compression_count: int = 0
    last_prompt_tokens: int = 0
    last_completion_tokens: int = 0
    last_total_tokens: int = 0
    ineffective_count: int = 0
    fallback_streak: int = 0
    overload_aborts: int = 0
    cooldown_until: float = 0.0
    fallback_probe_at: float = 0.0
    anti_thrash_deadline: float = 0.0
    structural_backoff_until: float = 0.0
    updated_at: float = 0.0
    lineage: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, value: Any) -> "CompressionState":
        if not isinstance(value, dict):
            return cls()
        state = cls()
        for name in state.__dataclass_fields__:
            if name not in value:
                continue
            current = getattr(state, name)
            incoming = value[name]
            try:
                if isinstance(current, bool) or current is None:
                    # bool|None fields keep their "unknown" third state but
                    # never absorb arbitrary junk types from a foreign dict.
                    setattr(state, name, None if incoming is None else bool(incoming))
                elif isinstance(current, int):
                    setattr(state, name, int(incoming or 0))
                elif isinstance(current, float):
                    setattr(state, name, float(incoming or 0.0))
                elif isinstance(current, list):
                    setattr(state, name, incoming if isinstance(incoming, list) else [])
                elif isinstance(current, str):
                    setattr(state, name, str(incoming or ""))
            except (TypeError, ValueError):
                continue
        state.summary = state.summary[:MAX_SUMMARY_CHARS]
        state.lineage = [row for row in state.lineage if isinstance(row, dict)][-MAX_LINEAGE:]
        return state


def validate_state_key(key: str) -> str:
    key = str(key or "")
    if not STATE_KEY_RE.fullmatch(key):
        raise ValueError("invalid compression state key")
    return key


def append_lineage(state: CompressionState, event: dict[str, Any]) -> None:
    """Append one bounded, content-free lineage event."""
    # Deep copy: a caller mutating its event afterwards must not rewrite the
    # audit trail that was already recorded.
    row = copy.deepcopy(event)
    row.setdefault("at", time.time())
    state.lineage = (state.lineage + [row])[-MAX_LINEAGE:]


class StateStore(Protocol):
    def load(self, key: str) -> dict[str, Any]: ...
    def save(self, key: str, value: dict[str, Any]) -> None: ...
    def delete(self, key: str) -> None: ...


class NullStateStore:
    """In-memory no-op store used by tests and one-shot compressors."""

    def __init__(self):
        self.rows: dict[str, dict[str, Any]] = {}
        self.lock = threading.RLock()

    def load(self, key: str) -> dict[str, Any]:
        with self.lock:
            return json.loads(json.dumps(self.rows.get(key, {})))

    def save(self, key: str, value: dict[str, Any]) -> None:
        with self.lock:
            self.rows[validate_state_key(key)] = json.loads(json.dumps(value))

    def delete(self, key: str) -> None:
        with self.lock:
            self.rows.pop(key, None)


class SessionStateStore:
    """Adapter over ``SessionStore``'s generic context-state table."""

    def __init__(self, session_store):
        self.session_store = session_store

    def load(self, key: str) -> dict[str, Any]:
        if self.session_store is None:
            return {}
        return self.session_store.load_context_state(validate_state_key(key))

    def save(self, key: str, value: dict[str, Any]) -> None:
        if self.session_store is None:
            return
        self.session_store.save_context_state(validate_state_key(key), value)

    def delete(self, key: str) -> None:
        if self.session_store is None:
            return
        self.session_store.delete_context_state(validate_state_key(key))


class FileStateStore:
    """Atomic 0600 JSON files, one per conversation key.

    Used by Operator jobs, whose state belongs beside their artifacts and must
    survive a process restart even when no chat session row exists.
    """

    def __init__(self, root: Path):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        try:
            self.root.chmod(0o700)
        except OSError:
            pass
        self.lock = threading.RLock()

    def _path(self, key: str) -> Path:
        safe = validate_state_key(key).replace(":", "_")
        return self.root / (safe + ".json")

    def load(self, key: str) -> dict[str, Any]:
        path = self._path(key)
        with self.lock:
            try:
                if path.stat().st_size > MAX_STATE_BYTES:
                    return {}
                payload = json.loads(path.read_text(encoding="utf-8"))
                return payload if isinstance(payload, dict) else {}
            except (OSError, ValueError, UnicodeError):
                return {}

    def save(self, key: str, value: dict[str, Any]) -> None:
        path = self._path(key)
        encoded = json.dumps(value, ensure_ascii=True, separators=(",", ":"))
        if len(encoded.encode("utf-8")) > MAX_STATE_BYTES:
            raise ValueError("compression state is too large")
        with self.lock:
            path.parent.mkdir(parents=True, exist_ok=True)
            fd, temporary = tempfile.mkstemp(prefix=path.name + ".", dir=str(path.parent))
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as handle:
                    handle.write(encoded)
                    handle.flush()
                    os.fsync(handle.fileno())
                os.chmod(temporary, 0o600)
                os.replace(temporary, path)
            finally:
                try:
                    if os.path.exists(temporary):
                        os.unlink(temporary)
                except OSError:
                    pass

    def delete(self, key: str) -> None:
        with self.lock:
            try:
                self._path(key).unlink()
            except OSError:
                pass


class CompositeStateStore:
    """Best-effort mirror: keep a local cache even when the durable store fails."""

    def __init__(self, primary: StateStore, secondary: StateStore | None = None):
        self.primary = primary
        self.secondary = secondary or NullStateStore()

    def load(self, key: str) -> dict[str, Any]:
        try:
            value = self.primary.load(key)
        except Exception:
            value = {}
        if value:
            return value
        try:
            return self.secondary.load(key)
        except Exception:
            return {}

    def save(self, key: str, value: dict[str, Any]) -> None:
        try:
            self.primary.save(key, value)
        except Exception:
            pass
        try:
            self.secondary.save(key, value)
        except Exception:
            pass

    def delete(self, key: str) -> None:
        for store in (self.primary, self.secondary):
            try:
                store.delete(key)
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Process-wide lease
# ---------------------------------------------------------------------------

_LEASE_LOCK = threading.Lock()
_LEASES: dict[str, list[Any]] = {}  # key -> [lock, users]


def _lease_lock_for(key: str) -> threading.Lock:
    with _LEASE_LOCK:
        row = _LEASES.get(key)
        if row is None:
            row = [threading.Lock(), 0]
            _LEASES[key] = row
        row[1] += 1
        return row[0]


def _release_lease_lock(key: str) -> None:
    with _LEASE_LOCK:
        row = _LEASES.get(key)
        if not row:
            return
        row[1] -= 1
        if row[1] <= 0:
            _LEASES.pop(key, None)


@contextlib.contextmanager
def compression_lease(key: str, timeout: float = 5.0) -> Iterator[None]:
    """Exclusive compaction for ``key``; raises ``CompressionLeaseBusy`` on timeout."""
    key = validate_state_key(key)
    lock = _lease_lock_for(key)
    acquired = lock.acquire(timeout=max(0.0, float(timeout)))
    if not acquired:
        _release_lease_lock(key)
        raise CompressionLeaseBusy(f"another compaction holds {key!r}")
    try:
        yield
    finally:
        try:
            lock.release()
        finally:
            _release_lease_lock(key)


def lease_stats() -> dict[str, Any]:
    with _LEASE_LOCK:
        return {"keys": len(_LEASES), "users": sum(row[1] for row in _LEASES.values())}
