"""Durable chat-session archive with FTS5 search.

The live conversation still lives in ``Application.sessions`` for fast access;
this store makes it survive a restart and makes old conversations searchable.
"""
from __future__ import annotations

import json
import os
import re
import sqlite3
import sys
import threading
import time
from pathlib import Path

import sqlite_guard

DEFAULT_PATH = Path.home() / ".jarvis-tools" / "sessions.db"


def _keep_days_from_env() -> float:
    raw = (os.environ.get("JARVIS_SESSION_KEEP_DAYS") or "").strip()
    if not raw:
        return 0.0
    try:
        value = float(raw)
    except ValueError:
        print("JARVIS_SESSION_KEEP_DAYS is not a number; keeping all sessions", file=sys.stderr)
        return 0.0
    return value if value > 0 else 0.0


class SessionError(Exception):
    pass


SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY,
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS turns (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token TEXT NOT NULL,
    role TEXT NOT NULL,
    content TEXT NOT NULL,
    created_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS turns_token ON turns(token, id);
CREATE INDEX IF NOT EXISTS turns_created ON turns(created_at);
CREATE TABLE IF NOT EXISTS session_meta (
    token TEXT NOT NULL,
    key TEXT NOT NULL,
    value TEXT NOT NULL,
    updated_at REAL NOT NULL,
    PRIMARY KEY (token, key)
);
CREATE TABLE IF NOT EXISTS context_state (
    key TEXT PRIMARY KEY,
    data TEXT NOT NULL,
    updated_at REAL NOT NULL
);
"""

# FTS5 is optional: a Python build without it must not stop Jarvis from
# booting. Search has a LIKE fallback when the virtual table is absent.
FTS_SCHEMA = "CREATE VIRTUAL TABLE IF NOT EXISTS turns_fts USING fts5(content);"


class SessionStore:
    def __init__(self, path: Path | None = None):
        self.path = Path(path or DEFAULT_PATH)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.lock = threading.RLock()
        self.fts = True
        self.conn = self._open()
        # Opt-in retention: unlimited by default, because silently deleting the
        # user's chat history is worse than a slowly growing local file.
        self.keep_days = _keep_days_from_env()
        self._last_prune = 0.0

    def _open(self):
        """Open the archive; a corrupt file is quarantined, never a boot failure."""
        conn = sqlite_guard.connect_private(self.path)
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.executescript(SCHEMA)
            try:
                conn.execute(FTS_SCHEMA)
            except sqlite3.OperationalError as error:
                if "fts5" not in str(error).lower():
                    raise
                self.fts = False
        except sqlite3.DatabaseError as error:
            if not sqlite_guard.is_corruption(error):
                raise
            try:
                conn.close()
            except sqlite3.Error:
                pass
            sqlite_guard.quarantine_database(self.path, "sessions")
            conn = sqlite_guard.connect_private(self.path)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.executescript(SCHEMA)
            try:
                conn.execute(FTS_SCHEMA)
            except sqlite3.OperationalError as error:
                if "fts5" not in str(error).lower():
                    raise
                self.fts = False
        sqlite_guard.secure_database(self.path)
        return conn

    def _maybe_prune(self, now: float) -> None:
        if now - self._last_prune < 3600:
            return
        self._last_prune = now
        try:
            if self.keep_days > 0:
                self.prune(self.keep_days)
            # Compaction state is derived cache, not chat history: stale
            # operator-job rows get a fixed 90-day floor even when the user
            # chose unlimited retention for their conversations.
            self.prune_context_state(90)
        except sqlite3.Error as error:
            print(f"session prune failed: {error}", file=sys.stderr)

    def prune(self, keep_days: float = 90) -> int:
        """Delete turns older than *keep_days*; larger sessions stay searchable.

        Returns the number of removed turns. Session rows (token + timestamps)
        are kept: old conversations remain visible in ``recent()`` even when
        their turns were discarded.
        """
        keep_days = float(keep_days or 0)
        if keep_days <= 0:
            return 0
        cutoff = time.time() - keep_days * 86400
        with self.lock:
            row = self.conn.execute(
                "SELECT COUNT(*) FROM turns WHERE created_at < ?", (cutoff,)).fetchone()
            removed = int(row[0]) if row else 0
            if not removed:
                return 0
            if getattr(self, "fts", True):
                try:
                    self.conn.execute(
                        "DELETE FROM turns_fts WHERE rowid IN "
                        "(SELECT id FROM turns WHERE created_at < ?)", (cutoff,))
                except sqlite3.Error as error:
                    print(f"turns_fts prune failed: {error}", file=sys.stderr)
            self.conn.execute("DELETE FROM turns WHERE created_at < ?", (cutoff,))
            self.conn.commit()
            return removed

    def _sync_fts(self, rowid: int) -> None:
        if not getattr(self, "fts", True):
            return
        try:
            self.conn.execute("DELETE FROM turns_fts WHERE rowid = ?", (rowid,))
            row = self.conn.execute("SELECT content FROM turns WHERE id = ?", (rowid,)).fetchone()
            if row:
                self.conn.execute("INSERT INTO turns_fts(rowid, content) VALUES (?, ?)", (rowid, row["content"]))
        except sqlite3.Error as error:
            print(f"turns_fts rowid {rowid}: {error}", file=sys.stderr)

    def append(self, token: str, user: str, answer: str = "") -> None:
        token = str(token or "").strip()
        if not re.fullmatch(r"[A-Za-z0-9_-]{20,128}", token):
            return
        now = time.time()
        with self.lock:
            self.conn.execute("INSERT INTO sessions(token, created_at, updated_at) VALUES (?, ?, ?) "
                              "ON CONFLICT(token) DO UPDATE SET updated_at = excluded.updated_at",
                              (token, now, now))
            rows = [(token, "user", str(user or "")[:12000], now)]
            if answer:
                rows.append((token, "assistant", str(answer or "")[:12000], now))
            for row in rows:
                cursor = self.conn.execute("INSERT INTO turns(token, role, content, created_at) "
                                           "VALUES (?, ?, ?, ?)", row)
                self._sync_fts(cursor.lastrowid)
            self.conn.commit()
        self._maybe_prune(now)

    def history(self, token: str, limit: int = 40) -> list[dict]:
        limit = max(1, min(int(limit or 40), 200))
        with self.lock:
            rows = self.conn.execute("SELECT id, role, content, created_at FROM turns WHERE token = ? "
                                     "ORDER BY id DESC LIMIT ?", (token, limit)).fetchall()
        return [dict(row) for row in reversed(rows)]

    def latest_turn_id(self, token: str) -> int:
        """Newest turn id for a session, or 0 when the session has no turns."""
        with self.lock:
            row = self.conn.execute(
                "SELECT MAX(id) AS id FROM turns WHERE token = ?", (token,)).fetchone()
        return int(row["id"] or 0) if row else 0

    def history_after(self, token: str, after_id: int = 0, limit: int = 200) -> list[dict]:
        """Turns newer than ``after_id``, oldest first; bounded by *limit*."""
        after_id = max(0, int(after_id or 0))
        limit = max(1, min(int(limit or 200), 500))
        with self.lock:
            rows = self.conn.execute(
                "SELECT id, role, content, created_at FROM turns "
                "WHERE token = ? AND id > ? ORDER BY id LIMIT ?",
                (token, after_id, limit)).fetchall()
        return [dict(row) for row in rows]

    def recent(self, limit: int = 20) -> list[dict]:
        with self.lock:
            rows = self.conn.execute("SELECT token, created_at, updated_at FROM sessions "
                                     "ORDER BY updated_at DESC LIMIT ?", (limit,)).fetchall()
        return [dict(row) for row in rows]

    def last_seen(self, token: str) -> float:
        with self.lock:
            row = self.conn.execute("SELECT updated_at FROM sessions WHERE token = ?", (token,)).fetchone()
        return float(row["updated_at"]) if row else 0.0

    def set_meta(self, token: str, **values) -> None:
        """Persist small trusted session facts (for example the Operator job).

        The live map is lost on restart; without this record a follow-up such
        as "did you open it?" again had no source for the Operator outcome.
        """
        token = str(token or "").strip()
        if not re.fullmatch(r"[A-Za-z0-9_-]{20,128}", token):
            return
        now = time.time()
        with self.lock:
            for key, value in values.items():
                encoded = json.dumps(value, ensure_ascii=False)
                if len(encoded) > 4000:
                    encoded = json.dumps(str(value)[:3000], ensure_ascii=False)
                self.conn.execute(
                    "INSERT INTO session_meta(token, key, value, updated_at) VALUES (?, ?, ?, ?) "
                    "ON CONFLICT(token, key) DO UPDATE SET value=excluded.value, "
                    "updated_at=excluded.updated_at", (token, str(key)[:64], encoded, now))
            self.conn.commit()

    def meta(self, token: str) -> dict:
        token = str(token or "").strip()
        if not re.fullmatch(r"[A-Za-z0-9_-]{20,128}", token):
            return {}
        with self.lock:
            rows = self.conn.execute(
                "SELECT key, value FROM session_meta WHERE token = ?", (token,)).fetchall()
        result = {}
        for row in rows:
            try:
                result[str(row["key"])] = json.loads(row["value"])
            except (TypeError, ValueError):
                continue
        return result

    # -- generic context-compression state ---------------------------------

    @staticmethod
    def _state_key(key: str) -> str:
        value = str(key or "").strip()
        if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,160}", value):
            raise ValueError("invalid context state key")
        return value

    def load_context_state(self, key: str) -> dict:
        """Load one compression/context state blob; corrupt data is ignored.

        The key is not a chat token: ``chat:<token>`` and ``operator:<id>``
        share this table so both lanes use the same persistence primitive.
        """
        key = self._state_key(key)
        with self.lock:
            row = self.conn.execute(
                "SELECT data FROM context_state WHERE key = ?", (key,)).fetchone()
        if not row:
            return {}
        try:
            payload = json.loads(row["data"])
        except (TypeError, ValueError):
            return {}
        return payload if isinstance(payload, dict) else {}

    def save_context_state(self, key: str, payload: dict) -> None:
        key = self._state_key(key)
        if not isinstance(payload, dict):
            raise ValueError("context state must be an object")
        encoded = json.dumps(payload, ensure_ascii=True, separators=(",", ":"))
        if len(encoded.encode("utf-8")) > 512 * 1024:
            raise ValueError("context state is too large")
        now = time.time()
        with self.lock:
            self.conn.execute(
                "INSERT INTO context_state(key, data, updated_at) VALUES (?, ?, ?) "
                "ON CONFLICT(key) DO UPDATE SET data=excluded.data, updated_at=excluded.updated_at",
                (key, encoded, now))
            self.conn.commit()

    def delete_context_state(self, key: str) -> None:
        key = self._state_key(key)
        with self.lock:
            self.conn.execute("DELETE FROM context_state WHERE key = ?", (key,))
            self.conn.commit()

    def prune_context_state(self, keep_days: float = 30) -> int:
        """Drop old compression state; the transcript itself is untouched."""
        keep_days = float(keep_days or 0)
        if keep_days <= 0:
            return 0
        cutoff = time.time() - keep_days * 86400
        with self.lock:
            cursor = self.conn.execute(
                "DELETE FROM context_state WHERE updated_at < ?", (cutoff,))
            self.conn.commit()
            return int(cursor.rowcount or 0)

    def _search_rows(self, query: str, limit: int) -> list:
        query = str(query or "").strip()
        if not query:
            return []
        limit = max(1, min(int(limit or 10), 50))
        tokens = re.findall(r"[a-zA-Z0-9ąćęłńóśźżĄĆĘŁŃÓŚŹŻ_-]{2,}", query.casefold())
        expression = " OR ".join(
            '"' + token.replace('"', '""') + '"*'
            for token in dict.fromkeys(tokens[:12]) if token
        ) or query.replace('"', "")[:100]
        try:
            with self.lock:
                rows = self.conn.execute(
                    "SELECT t.id, t.token, t.role, t.content, t.created_at FROM turns_fts "
                    "JOIN turns t ON t.id = turns_fts.rowid WHERE turns_fts MATCH ? "
                    "ORDER BY rank LIMIT ?", (expression, limit)).fetchall()
        except sqlite3.Error:
            # LIKE folds case for ASCII only, and a % or _ in the query used to
            # act as an unescaped wildcard: fetch a small candidate pool with
            # the wildcards escaped, then casefold-filter here (covers Polish).
            needle = query[:100].replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            try:
                with self.lock:
                    rows = self.conn.execute(
                        "SELECT id, token, role, content, created_at FROM turns "
                        "WHERE content LIKE ? ESCAPE '\\' ORDER BY id DESC LIMIT ?",
                        ("%" + needle + "%", limit * 4)).fetchall()
            except sqlite3.Error:
                rows = []
            folded = query[:100].casefold()
            rows = [row for row in rows if folded in str(row["content"]).casefold()][:limit]
        return rows

    def search(self, query: str, limit: int = 10) -> list[dict]:
        return [{"token": row["token"], "role": row["role"], "content": row["content"],
                 "created_at": row["created_at"]}
                for row in self._search_rows(query, limit)]

    def search_context(self, query: str, limit: int = 10, window: int = 2) -> list[dict]:
        """Search with neighbouring turns, like a conversational scroll window.

        The old search returned an isolated row; a model could not tell what the
        user asked before or what the answer actually said. The session token is
        masked because this payload is model-facing.
        """
        limit = max(1, min(int(limit or 10), 20))
        window = max(1, min(int(window or 2), 5))
        hits = []
        for row in self._search_rows(query, limit):
            token = str(row["token"])
            hit_id = int(row["id"])
            with self.lock:
                neighbours = self.conn.execute(
                    "SELECT id, role, content, created_at FROM turns "
                    "WHERE token = ? AND id BETWEEN ? AND ? ORDER BY id",
                    (token, hit_id - window * 2, hit_id + window * 2)).fetchall()
            context = [{"role": item["role"], "content": str(item["content"])[:1200],
                        "at": item["created_at"], "is_match": item["id"] == hit_id}
                       for item in neighbours]
            hits.append({
                "session": token[:8] + "…",
                "match": {"role": row["role"], "content": str(row["content"])[:700],
                          "at": row["created_at"]},
                "context": context,
            })
        return hits

    def clear(self, token: str) -> None:
        with self.lock:
            ids = [row["id"] for row in self.conn.execute("SELECT id FROM turns WHERE token = ?", (token,))]
            self.conn.execute("DELETE FROM turns WHERE token = ?", (token,))
            for rowid in ids:
                try:
                    self.conn.execute("DELETE FROM turns_fts WHERE rowid = ?", (rowid,))
                except sqlite3.Error:
                    pass
            self.conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
            self.conn.execute("DELETE FROM session_meta WHERE token = ?", (token,))
            try:
                self.conn.execute(
                    "DELETE FROM context_state WHERE key IN (?, ?)",
                    ("chat:" + token, "chat-cursor:" + token))
            except sqlite3.Error:
                pass
            self.conn.commit()

    def summary(self, token: str) -> str:
        """Prefer the rolling compaction summary; fall back to recent raw turns."""
        try:
            state = self.load_context_state("chat:" + str(token or ""))
        except ValueError:
            state = {}
        compressed = state.get("summary") if isinstance(state, dict) else ""
        if isinstance(compressed, str) and compressed.strip():
            return compressed[-16000:]
        turns = self.history(token, 12)
        if not turns:
            return ""
        lines = [f"{row['role']}: {row['content'][:280]}" for row in turns]
        return "\n".join(lines)[-3000:]

    def close(self) -> None:
        try:
            self.conn.close()
        except sqlite3.Error:
            pass

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass
