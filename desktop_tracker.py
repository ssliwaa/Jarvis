"""Lightweight event-driven desktop tracker for X11 / XFCE.

Monitors active window changes using low-overhead xdotool/xprop calls (<0.1% CPU),
recording application names, window titles, and dwell times into a local SQLite
history store without continuous video or heavy OCR recording.
"""
from __future__ import annotations

import os
import re
import sqlite3
import subprocess
import sys
import threading
import time
from pathlib import Path

STATE_ROOT = Path(os.environ.get("JARVIS_STATE", Path.home() / ".jarvis-tools"))
DB_PATH = STATE_ROOT / "desktop-history.db"
MAX_HISTORY_ROWS = 5000
POLL_INTERVAL = 3.0

_TRACKER_THREAD: threading.Thread | None = None
_TRACKER_STOP = threading.Event()
_LOCK = threading.Lock()


def _ensure_db(db_path: Path = DB_PATH) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path), timeout=5.0)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS desktop_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp REAL NOT NULL,
            app_name TEXT NOT NULL,
            window_title TEXT NOT NULL,
            pid INTEGER,
            duration REAL NOT NULL DEFAULT 0.0
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_desktop_history_ts ON desktop_history (timestamp DESC)")
    return conn


def get_active_window_info() -> dict | None:
    """Retrieve active window title, application name, and PID via xdotool and xprop."""
    display = os.environ.get("DISPLAY", ":0.0")
    env = {**os.environ, "DISPLAY": display}

    try:
        window_id_out = subprocess.run(
            ["xdotool", "getactivewindow"],
            capture_output=True,
            text=True,
            env=env,
            timeout=1.0,
        )
        if window_id_out.returncode != 0 or not window_id_out.stdout.strip():
            return None
        window_id = window_id_out.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return None

    title = ""
    try:
        title_out = subprocess.run(
            ["xdotool", "getwindowname", window_id],
            capture_output=True,
            text=True,
            env=env,
            timeout=1.0,
        )
        if title_out.returncode == 0:
            title = title_out.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        pass

    app_name = "unknown"
    pid = None
    try:
        xprop_out = subprocess.run(
            ["xprop", "-id", window_id, "WM_CLASS", "_NET_WM_PID"],
            capture_output=True,
            text=True,
            env=env,
            timeout=1.0,
        )
        if xprop_out.returncode == 0:
            for line in xprop_out.stdout.splitlines():
                if "WM_CLASS" in line:
                    match = re.search(r'"([^"]+)"', line)
                    if match:
                        app_name = match.group(1)
                elif "_NET_WM_PID" in line:
                    parts = line.split("=")
                    if len(parts) == 2 and parts[1].strip().isdigit():
                        pid = int(parts[1].strip())
    except (OSError, subprocess.SubprocessError):
        pass

    return {
        "window_id": window_id,
        "app_name": app_name,
        "window_title": title or app_name,
        "pid": pid,
    }


def record_active_window(db_path: Path = DB_PATH) -> dict | None:
    """Sample active window and record/update duration in SQLite."""
    info = get_active_window_info()
    if not info:
        return None

    now = time.time()
    with _LOCK:
        conn = _ensure_db(db_path)
        try:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT id, timestamp, app_name, window_title, duration FROM desktop_history ORDER BY id DESC LIMIT 1"
            )
            last = cursor.fetchone()

            if last and (now - last[1] - last[4]) < 10.0 and last[2] == info["app_name"] and last[3] == info["window_title"]:
                # Same window continues: update duration
                new_duration = now - last[1]
                cursor.execute(
                    "UPDATE desktop_history SET duration = ? WHERE id = ?",
                    (new_duration, last[0])
                )
                conn.commit()
                return {
                    "id": last[0],
                    "app_name": info["app_name"],
                    "window_title": info["window_title"],
                    "pid": info["pid"],
                    "duration": round(new_duration, 1),
                    "action": "updated",
                }
            else:
                # Window changed: create new record
                cursor.execute(
                    "INSERT INTO desktop_history (timestamp, app_name, window_title, pid, duration) VALUES (?, ?, ?, ?, 0.0)",
                    (now, info["app_name"], info["window_title"], info["pid"])
                )
                conn.commit()

                # Prune if too many rows
                cursor.execute(
                    "DELETE FROM desktop_history WHERE id NOT IN (SELECT id FROM desktop_history ORDER BY id DESC LIMIT ?)",
                    (MAX_HISTORY_ROWS,)
                )
                conn.commit()

                return {
                    "id": cursor.lastrowid,
                    "app_name": info["app_name"],
                    "window_title": info["window_title"],
                    "pid": info["pid"],
                    "duration": 0.0,
                    "action": "inserted",
                }
        finally:
            conn.close()


def get_history(limit: int = 20, query: str | None = None, db_path: Path = DB_PATH) -> list[dict]:
    """Retrieve recent desktop activity sorted by most recent first."""
    limit = max(1, min(int(limit or 20), 100))
    with _LOCK:
        conn = _ensure_db(db_path)
        try:
            cursor = conn.cursor()
            if query and query.strip():
                term = f"%{query.strip()}%"
                cursor.execute(
                    """
                    SELECT timestamp, app_name, window_title, pid, duration
                    FROM desktop_history
                    WHERE app_name LIKE ? OR window_title LIKE ?
                    ORDER BY id DESC LIMIT ?
                    """,
                    (term, term, limit)
                )
            else:
                cursor.execute(
                    """
                    SELECT timestamp, app_name, window_title, pid, duration
                    FROM desktop_history
                    ORDER BY id DESC LIMIT ?
                    """,
                    (limit,)
                )
            rows = cursor.fetchall()
            return [
                {
                    "timestamp": row[0],
                    "time_str": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(row[0])),
                    "app_name": row[1],
                    "window_title": row[2],
                    "pid": row[3],
                    "duration_seconds": round(row[4], 1),
                }
                for row in rows
            ]
        finally:
            conn.close()


def start_tracker(interval: float = POLL_INTERVAL, db_path: Path = DB_PATH) -> threading.Thread:
    """Start background desktop sampling daemon."""
    global _TRACKER_THREAD
    with _LOCK:
        if _TRACKER_THREAD is not None and _TRACKER_THREAD.is_alive():
            return _TRACKER_THREAD
        _TRACKER_STOP.clear()

    def _loop():
        while not _TRACKER_STOP.is_set():
            try:
                record_active_window(db_path)
            except Exception as error:
                print(f"[desktop_tracker] error: {error}", file=sys.stderr)
            time.sleep(interval)

    thread = threading.Thread(target=_loop, name="jarvis-desktop-tracker", daemon=True)
    thread.start()
    _TRACKER_THREAD = thread
    return thread


def stop_tracker():
    _TRACKER_STOP.set()
