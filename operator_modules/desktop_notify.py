"""Desktop notifications (notify-send / D-Bus) and non-blocking timers for Jarvis."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import threading
import time
import uuid
from pathlib import Path
from typing import Any

STATE_PATH = Path.home() / ".jarvis-tools" / "notifications.json"
_LOCK = threading.Lock()
_ACTIVE_TIMERS: dict[str, dict[str, Any]] = {}


def _send_os_notification(title: str, body: str, urgency: str = "normal") -> bool:
    urgency = urgency if urgency in ("low", "normal", "critical") else "normal"
    if shutil.which("notify-send"):
        try:
            proc = subprocess.run(
                ["notify-send", "-a", "Jarvis", "-u", urgency, title[:120], body[:500]],
                capture_output=True, text=True, timeout=3.0, check=False,
            )
            if proc.returncode == 0:
                return True
        except (OSError, subprocess.SubprocessError):
            pass
    if shutil.which("gdbus"):
        try:
            proc = subprocess.run(
                [
                    "gdbus", "call", "--session",
                    "--dest", "org.freedesktop.Notifications",
                    "--object-path", "/org/freedesktop/Notifications",
                    "--method", "org.freedesktop.Notifications.Notify",
                    "Jarvis", "0", "dialog-information",
                    title[:120], body[:500], "[]", "{}", "5000",
                ],
                capture_output=True, text=True, timeout=3.0, check=False,
            )
            return proc.returncode == 0
        except (OSError, subprocess.SubprocessError):
            pass
    return False


def _record_notification(entry: dict[str, Any]) -> None:
    with _LOCK:
        rows: list[dict[str, Any]] = []
        try:
            if STATE_PATH.is_file():
                loaded = json.loads(STATE_PATH.read_text(encoding="utf-8"))
                if isinstance(loaded, list):
                    rows = [r for r in loaded if isinstance(r, dict)]
        except (OSError, ValueError):
            rows = []
        rows.append(entry)
        try:
            STATE_PATH.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            import tempfile
            fd, tmp_name = tempfile.mkstemp(dir=STATE_PATH.parent, prefix=".notify-", suffix=".json.tmp")
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as fh:
                    fh.write(json.dumps(rows[-50:], ensure_ascii=False, indent=2))
                os.replace(tmp_name, STATE_PATH)
            except BaseException:
                try:
                    os.unlink(tmp_name)
                except OSError:
                    pass
                raise
            STATE_PATH.chmod(0o600)
        except OSError:
            pass


def _read_history() -> list[dict[str, Any]]:
    with _LOCK:
        try:
            if STATE_PATH.is_file():
                loaded = json.loads(STATE_PATH.read_text(encoding="utf-8"))
                if isinstance(loaded, list):
                    return [r for r in loaded if isinstance(r, dict)][-20:]
        except (OSError, ValueError):
            pass
    return []


def desktop_notify(arguments: dict[str, Any], context=None) -> dict[str, Any]:
    """Send an instant desktop notification, schedule a reminder timer, or list timers."""
    del context
    args = arguments or {}
    action = str(args.get("action") or "send").strip().lower()
    title = str(args.get("title") or "Jarvis").strip()[:120] or "Jarvis"
    body = str(args.get("body") or args.get("message") or "").strip()[:500]
    urgency = str(args.get("urgency") or "normal").strip().lower()

    if action == "list":
        with _LOCK:
            timers = [dict(v) for v in _ACTIVE_TIMERS.values()]
        return {
            "ok": True,
            "action": "list",
            "active_timers": timers,
            "recent": _read_history(),
        }

    if action == "send":
        if not body:
            return {"ok": False, "error": "Notification body cannot be empty."}
        delivered = _send_os_notification(title, body, urgency)
        entry = {
            "id": uuid.uuid4().hex[:8],
            "title": title,
            "body": body,
            "urgency": urgency,
            "delivered": delivered,
            "at": time.time(),
        }
        _record_notification(entry)
        return {"ok": True, "action": "send", "delivered": delivered, "notification": entry}

    if action == "timer":
        if not body:
            return {"ok": False, "error": "Timer reminder message cannot be empty."}
        delay = max(1, min(int(args.get("delay_seconds") or 60), 86400))
        timer_id = f"timer-{uuid.uuid4().hex[:8]}"
        due_at = time.time() + delay
        meta = {
            "id": timer_id,
            "title": title,
            "body": body,
            "urgency": urgency,
            "delay_seconds": delay,
            "due_at": due_at,
        }
        with _LOCK:
            _ACTIVE_TIMERS[timer_id] = meta

        def _fire():
            try:
                delivered = _send_os_notification(title, body, urgency)
                _record_notification({
                    "id": timer_id,
                    "title": title,
                    "body": body,
                    "urgency": urgency,
                    "delivered": delivered,
                    "at": time.time(),
                })
            finally:
                with _LOCK:
                    _ACTIVE_TIMERS.pop(timer_id, None)

        timer = threading.Timer(delay, _fire)
        timer.daemon = True
        timer.start()
        return {"ok": True, "action": "timer", "timer": meta}

    return {"ok": False, "error": f"Unsupported action: {action!r}"}


TOOL = {
    "name": "desktop_notify",
    "description": (
        "Send a native Linux desktop notification (Xfce/freedesktop) or schedule a "
        "background countdown reminder timer."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "action": {
                "type": "string",
                "enum": ["send", "timer", "list"],
                "description": "Action: 'send' immediate notification, 'timer' countdown reminder, or 'list'.",
            },
            "title": {
                "type": "string",
                "description": "Notification title (default: 'Jarvis').",
            },
            "body": {
                "type": "string",
                "description": "Notification body text.",
            },
            "urgency": {
                "type": "string",
                "enum": ["low", "normal", "critical"],
                "description": "Urgency level (default: 'normal').",
            },
            "delay_seconds": {
                "type": "integer",
                "description": "Countdown seconds (1-86400) when action='timer'.",
            },
        },
        "additionalProperties": False,
    },
    "handler": desktop_notify,
    "approval": False,
}
