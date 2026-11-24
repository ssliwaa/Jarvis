"""Lightweight thread-safe Server-Sent Events (SSE) ring buffer for Jarvis.

Keeps at most `MAX_BUFFER` recent structured events in memory (< 64 KB RAM) and
wakes waiting SSE HTTP streams via `threading.Condition` with zero polling overhead.
"""

from __future__ import annotations

import json
import threading
import time
from collections import deque

MAX_BUFFER = 200
_COND = threading.Condition()
_NEXT_ID = 1
_EVENTS: deque[dict] = deque(maxlen=MAX_BUFFER)
_SUBSCRIBERS: dict[str, list] = {}


def subscribe(topic: str, callback) -> None:
    """Register an in-process listener `callback(event)` for `topic` (or `'*'`)."""
    key = str(topic or "*").strip() or "*"
    with _COND:
        bucket = _SUBSCRIBERS.setdefault(key, [])
        if callback not in bucket:
            bucket.append(callback)


def publish(topic: str, payload: dict | None = None) -> dict:
    """Publish a structured event to all connected SSE listeners and ring buffer."""
    global _NEXT_ID
    clean_topic = str(topic or "system.event").strip()[:64] or "system.event"
    data = payload if isinstance(payload, dict) else {"value": payload}
    with _COND:
        eid = _NEXT_ID
        _NEXT_ID += 1
        event = {
            "id": eid,
            "topic": clean_topic,
            "ts": round(time.time(), 3),
            "data": data,
        }
        _EVENTS.append(event)
        listeners = list(_SUBSCRIBERS.get(clean_topic, ())) + list(_SUBSCRIBERS.get("*", ()))
        _COND.notify_all()
    for cb in listeners:
        try:
            cb(event)
        except Exception:
            pass
    if clean_topic in ("owner.answered", "router.circuit_tripped", "night_shift.completed"):
        try:
            import episodic_memory
            episodic_memory.handle_bus_event(event)
        except Exception:
            pass
    return event


def recent(after_id: int = 0, limit: int = 50) -> list[dict]:
    """Return buffered events with `id > after_id`."""
    aid = int(after_id or 0)
    cap = max(1, min(int(limit or 50), MAX_BUFFER))
    with _COND:
        items = [ev for ev in _EVENTS if ev["id"] > aid]
    return items[-cap:]


def latest_id() -> int:
    """Return the most recently assigned event ID (or 0 if none)."""
    with _COND:
        return _EVENTS[-1]["id"] if _EVENTS else 0


def wait_next(after_id: int, timeout: float = 15.0) -> list[dict]:
    """Block up to `timeout` seconds until at least one event with `id > after_id` arrives."""
    aid = int(after_id or 0)
    deadline = time.monotonic() + max(0.05, float(timeout))
    with _COND:
        while True:
            ready = [ev for ev in _EVENTS if ev["id"] > aid]
            if ready:
                return ready
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return []
            _COND.wait(timeout=remaining)


def format_sse(event: dict) -> bytes:
    """Encode an event dict into wire-ready UTF-8 SSE frame bytes."""
    eid = int(event.get("id") or 0)
    topic = str(event.get("topic") or "message").replace("\n", " ").replace("\r", " ")
    payload = json.dumps(event, ensure_ascii=False)
    frame = f"id: {eid}\nevent: {topic}\ndata: {payload}\n\n"
    return frame.encode("utf-8")


def reset_for_tests() -> None:
    """Clear buffered events (used by unit tests)."""
    global _NEXT_ID
    with _COND:
        _EVENTS.clear()
        _NEXT_ID = 1
