"""Personal long-term memory for Jarvis.

Separate from the Sejf vault: notes are documents, memory is a small set of
durable facts. The store keeps evidence instead of overwriting silently — a
repeated fact bumps ``evidence_count`` and ``last_confirmed``, a changed fact
supersedes the old value and leaves an event behind, and the prompt can carry a
rewritten standing summary ("mental model") that costs no retrieval.

SQLite WAL + FTS5, plus an optional semantic lane driven by the same local
embedding model as the note vault (see ``attach_semantic``).
"""
from __future__ import annotations

import math
import re
import sqlite3
import sys
import threading
import time
from pathlib import Path

import sqlite_guard

CATEGORIES = ("identity", "preferences", "projects", "relations", "hardware", "rules", "notes")
AUTO_CATEGORIES = ("identity", "hardware", "relations")
DEFAULT_PATH = Path.home() / ".jarvis-tools" / "memory.db"
DEFAULT_MODEL_NAME = "owner"
DEFAULT_MODEL_QUESTION = "Kim jest właściciel i czego oczekuje od asystenta?"
MIN_NEW_FACTS = 3


class MemoryError_(Exception):
    pass


def slug_key(text: str, fallback: str = "") -> str:
    """THE one key-normalizer for personal memory.

    remember(), propose(), suggest() and memory_extract all write through this
    rule: lowercase with Polish letters kept, whitespace as underscores. Two
    contradicting normalizers used to store the same fact under two keys and
    defeat the dedupe check.
    """
    slug = re.sub(r"[^a-z0-9ąćęłńóśźż _-]+", "", str(text or "").casefold()).strip()
    slug = re.sub(r"\s+", "_", slug)
    return slug[:120].strip("_-") or fallback


def _tokens(text: str) -> list[str]:
    return re.findall(r"[a-zA-Z0-9ąćęłńóśźżĄĆĘŁŃÓŚŹŻ_-]{2,}", (text or "").casefold())


def _match_expression(tokens: list[str]) -> str:
    # Quote every term: a bare ``covid-19`` is parsed by FTS5 as a minus
    # operator and raises "no such column: 19", which used to dump the query
    # into a poor LIKE fallback.
    return " OR ".join(
        '"' + token.replace('"', '""') + '"*' for token in dict.fromkeys(tokens) if token
    )


SCHEMA = """
CREATE TABLE IF NOT EXISTS memories (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    category TEXT NOT NULL,
    key TEXT NOT NULL,
    value TEXT NOT NULL,
    importance REAL NOT NULL DEFAULT 0.5,
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL,
    last_used REAL NOT NULL,
    use_count INTEGER NOT NULL DEFAULT 0,
    UNIQUE(category, key)
);
CREATE INDEX IF NOT EXISTS memories_category ON memories(category);
CREATE VIRTUAL TABLE IF NOT EXISTS memories_fts USING fts5(category, key, value);
CREATE TABLE IF NOT EXISTS memory_suggestions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    category TEXT NOT NULL,
    key TEXT NOT NULL,
    value TEXT NOT NULL,
    reason TEXT NOT NULL,
    created_at REAL NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending'
);
CREATE TABLE IF NOT EXISTS memory_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    memory_id INTEGER NOT NULL,
    kind TEXT NOT NULL,
    old_value TEXT,
    new_value TEXT,
    quote TEXT NOT NULL DEFAULT '',
    source TEXT NOT NULL DEFAULT '',
    at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS memory_events_memory ON memory_events(memory_id);
CREATE TABLE IF NOT EXISTS mental_models (
    name TEXT PRIMARY KEY,
    question TEXT NOT NULL,
    answer TEXT NOT NULL DEFAULT '',
    memory_version INTEGER NOT NULL DEFAULT 0,
    updated_at REAL NOT NULL DEFAULT 0,
    model TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS memory_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
"""

MEMORY_COLUMNS = {
    "evidence_count": "INTEGER NOT NULL DEFAULT 1",
    "first_seen": "REAL",
    "last_confirmed": "REAL",
    "confidence": "REAL NOT NULL DEFAULT 0.5",
    "source": "TEXT NOT NULL DEFAULT 'manual'",
    "quote": "TEXT NOT NULL DEFAULT ''",
}
SUGGESTION_COLUMNS = {
    "confidence": "REAL NOT NULL DEFAULT 0.5",
    "quote": "TEXT NOT NULL DEFAULT ''",
    "source": "TEXT NOT NULL DEFAULT 'regex'",
}


class MemoryStore:
    def __init__(self, path: Path | None = None, semantic=None):
        self.path = Path(path or DEFAULT_PATH)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.lock = threading.RLock()
        self.conn = self._connect()
        self.embedder = None
        self.vectors = None
        self._vector_signature = None
        if semantic is not None:
            self.attach_semantic(semantic)

    def _open(self):
        conn = sqlite_guard.connect_private(self.path)
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.executescript(SCHEMA)
            self._migrate(conn)
        except sqlite3.DatabaseError as error:
            if not sqlite_guard.is_corruption(error):
                raise
            try:
                conn.close()
            except sqlite3.Error:
                pass
            sqlite_guard.quarantine_database(self.path, "memory")
            conn = sqlite_guard.connect_private(self.path)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.executescript(SCHEMA)
            self._migrate(conn)
        sqlite_guard.secure_database(self.path)
        return conn

    def _connect(self):
        return self._open()

    # -- schema --------------------------------------------------------
    def _migrate(self, conn=None):
        conn = conn if conn is not None else self.conn
        with self.lock:
            columns = {row[1] for row in conn.execute("PRAGMA table_info(memories)")}
            for name, ddl in MEMORY_COLUMNS.items():
                if name not in columns:
                    conn.execute(f"ALTER TABLE memories ADD COLUMN {name} {ddl}")
            columns = {row[1] for row in conn.execute("PRAGMA table_info(memory_suggestions)")}
            for name, ddl in SUGGESTION_COLUMNS.items():
                if name not in columns:
                    conn.execute(f"ALTER TABLE memory_suggestions ADD COLUMN {name} {ddl}")
            conn.execute(
                "UPDATE memories SET first_seen = COALESCE(first_seen, created_at), "
                "last_confirmed = COALESCE(last_confirmed, updated_at) "
                "WHERE first_seen IS NULL OR last_confirmed IS NULL")
            conn.commit()

    def _sync_fts(self, rowid: int) -> None:
        try:
            self.conn.execute("DELETE FROM memories_fts WHERE rowid = ?", (rowid,))
            row = self.conn.execute("SELECT category, key, value FROM memories WHERE id = ?",
                                    (rowid,)).fetchone()
            if row:
                self.conn.execute("INSERT INTO memories_fts(rowid, category, key, value) VALUES (?, ?, ?, ?)",
                                  (rowid, row["category"], row["key"], row["value"]))
        except sqlite3.Error as error:
            # A stale FTS row must be loud, not silently invisible forever.
            print(f"[jarvis-memory] fts sync failed: {error}", file=sys.stderr, flush=True)

    # -- versioning and events ----------------------------------------
    def version(self) -> int:
        with self.lock:
            row = self.conn.execute("SELECT value FROM memory_meta WHERE key = 'version'").fetchone()
        try:
            return int(row[0]) if row else 0
        except (TypeError, ValueError):
            return 0

    def _bump_version(self) -> int:
        # Single upsert: the read-then-write pair used to re-read the row and
        # could interleave with another thread's bump between the two.
        self.conn.execute("INSERT INTO memory_meta(key, value) VALUES ('version', '1') "
                          "ON CONFLICT(key) DO UPDATE SET value = "
                          "CAST(CAST(memory_meta.value AS INTEGER) + 1 AS TEXT)")
        row = self.conn.execute("SELECT CAST(value AS INTEGER) FROM memory_meta "
                                "WHERE key = 'version'").fetchone()
        return int(row[0]) if row else 1

    def _event(self, memory_id, kind, old_value=None, new_value=None, quote="", source=""):
        self.conn.execute(
            "INSERT INTO memory_events(memory_id, kind, old_value, new_value, quote, source, at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (int(memory_id), kind, old_value, new_value, str(quote or "")[:300],
             str(source or "")[:40], time.time()))
        # The audit log grows once per write; keep only the recent window that
        # any consumer actually reads (events(), changes_since()).
        self.conn.execute("DELETE FROM memory_events WHERE id <= "
                          "(SELECT MAX(id) FROM memory_events) - ?", (4096,))

    def events(self, memory_id=None, limit=20) -> list[dict]:
        limit = max(1, min(int(limit or 20), 200))
        with self.lock:
            if memory_id is None:
                rows = self.conn.execute("SELECT * FROM memory_events ORDER BY id DESC LIMIT ?",
                                         (limit,)).fetchall()
            else:
                rows = self.conn.execute("SELECT * FROM memory_events WHERE memory_id = ? "
                                         "ORDER BY id DESC LIMIT ?", (int(memory_id), limit)).fetchall()
        return [dict(row) for row in rows]

    def changes_since(self, timestamp, limit=50) -> list[dict]:
        with self.lock:
            rows = self.conn.execute("SELECT * FROM memory_events WHERE at >= ? ORDER BY id DESC LIMIT ?",
                                     (float(timestamp or 0), max(1, min(int(limit or 50), 200)))).fetchall()
        return [dict(row) for row in rows]

    # -- writes --------------------------------------------------------
    def remember(self, category: str, key: str, value: str, importance: float = 0.5,
                 source: str = "manual", quote: str = "", confidence: float = 0.5) -> dict:
        category = str(category or "notes").strip().lower()
        if category not in CATEGORIES:
            category = "notes"
        key = slug_key(key)
        value = str(value or "").strip()
        if not key or not value:
            raise MemoryError_("A memory needs a key and a value.")
        value = value[:4000]
        importance = max(0.0, min(1.0, float(importance or 0.5)))
        confidence = max(0.0, min(1.0, float(confidence or 0.5)))
        quote = str(quote or "").strip()[:300]
        source = str(source or "manual")[:40]
        now = time.time()
        with self.lock:
            try:
                return self._remember_inside_lock(category, key, value, importance, confidence,
                                                  quote, source, now)
            except sqlite3.IntegrityError:
                # Another process won the UNIQUE(category, key) race between
                # our SELECT and INSERT; rerun once and take the refine path.
                return self._remember_inside_lock(category, key, value, importance, confidence,
                                                  quote, source, now)

    def _remember_inside_lock(self, category, key, value, importance, confidence, quote, source, now):
        with self.lock:
            row = self.conn.execute("SELECT * FROM memories WHERE category = ? AND key = ?",
                                    (category, key)).fetchone()
            if row is None:
                cursor = self.conn.execute(
                    "INSERT INTO memories(category, key, value, importance, created_at, updated_at, "
                    "last_used, evidence_count, first_seen, last_confirmed, confidence, source, quote) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?)",
                    (category, key, value, importance, now, now, now, now, now, confidence, source, quote))
                rowid, action = cursor.lastrowid, "added"
                self._event(rowid, "added", None, value, quote, source)
            elif str(row["value"]).strip() == value:
                rowid, action = row["id"], "refined"
                self.conn.execute(
                    "UPDATE memories SET evidence_count = evidence_count + 1, last_confirmed = ?, "
                    "updated_at = ?, importance = MAX(importance, ?), confidence = MAX(confidence, ?), "
                    "quote = CASE WHEN ? != '' THEN ? ELSE quote END, source = ? WHERE id = ?",
                    (now, now, importance, confidence, quote, quote, source, rowid))
                self._event(rowid, "confirmed", value, value, quote, source)
            else:
                rowid, action = row["id"], "superseded"
                self.conn.execute(
                    "UPDATE memories SET value = ?, importance = MAX(importance, ?), updated_at = ?, "
                    "last_confirmed = ?, evidence_count = 1, confidence = ?, source = ?, quote = ? "
                    "WHERE id = ?",
                    (value, importance, now, now, confidence, source, quote, rowid))
                self._event(rowid, "superseded", row["value"], value, quote, source)
            self._sync_fts(rowid)
            self._bump_version()
            self._vector_signature = None
            self.conn.commit()
        result = self.get(rowid)
        result["action"] = action
        return result

    def propose(self, category, key, value, reason="detected in conversation",
                confidence=0.5, quote="", source="extract"):
        """Queue a fact for approval; nothing is written until it is accepted."""
        category = str(category or "notes").strip().lower()
        if category not in CATEGORIES:
            category = "notes"
        # The shared slug rule with propose(): the stored form a later accept
        # would write is the form the dedupe compares.
        key = slug_key(key)
        value = str(value or "").strip()[:300]
        if len(key) < 2 or len(value) < 2:
            return None
        confidence = max(0.0, min(1.0, float(confidence or 0.5)))
        with self.lock:
            existing = self.conn.execute("SELECT id FROM memories WHERE key = ? AND value = ?",
                                         (key, value)).fetchone()
            already_decided = self.conn.execute(
                "SELECT id FROM memory_suggestions WHERE key = ? AND value = ? "
                "AND status IN ('pending', 'rejected')", (key, value)).fetchone()
            if existing or already_decided:
                return None
            pending_key = self.conn.execute(
                "SELECT id FROM memory_suggestions WHERE category = ? AND key = ? "
                "AND status = 'pending'", (category, key)).fetchone()
            if pending_key:
                self.conn.execute(
                    "UPDATE memory_suggestions SET value = ?, reason = ?, created_at = ?, "
                    "confidence = ?, quote = ?, source = ? WHERE id = ?",
                    (value, str(reason or "")[:200], time.time(), confidence,
                     str(quote or "")[:300], str(source or "extract")[:40], pending_key["id"]))
                self.conn.commit()
                return {"id": pending_key["id"], "category": category, "key": key,
                        "value": value, "confidence": confidence, "reason": reason}
            cursor = self.conn.execute(
                "INSERT INTO memory_suggestions(category, key, value, reason, created_at, confidence, "
                "quote, source) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (category, key, value, str(reason or "")[:200], time.time(), confidence,
                 str(quote or "")[:300], str(source or "extract")[:40]))
            self.conn.commit()
            return {"id": cursor.lastrowid, "category": category, "key": key, "value": value,
                    "confidence": confidence, "reason": reason}

    SUGGESTIONS = (
        (re.compile(r"\b(?:wolę|wole|preferuję|preferuje|prefer|like)\s+(.{3,160})", re.I), "preferences"),
        (re.compile(r"\b(?:mieszkam\s+(?:w|we)|live\s+in|i\s+live\s+in)\s+(.{2,100})", re.I), "identity"),
        (re.compile(r"\b(?:nazywam\s+się|nazywam\s+sie|my\s+name\s+is)\s+(.{2,100})", re.I), "identity"),
        (re.compile(r"\b(?:używam|uzywam|korzystam\s+z|i\s+use|use)\s+(.{3,120})", re.I), "preferences"),
    )

    def suggest(self, text: str) -> list[dict]:
        """Cheap regex pass; the model-driven path lives in memory_extract."""
        raw = str(text or "").strip()
        if len(raw) < 8 or len(raw) > 2000:
            return []
        proposals = []
        for pattern, category in self.SUGGESTIONS:
            match = pattern.search(raw)
            if not match:
                continue
            value = match.group(1).strip().strip(".,;:!?")
            value = re.sub(r"\s+(?:i|and|oraz)\s+.*$", "", value)[:300].strip()
            if len(value) < 2:
                continue
            key = slug_key(value, fallback="preference")
            proposals.append((category, key, value))
        output = []
        for category, key, value in proposals:
            suggestion = self.propose(category, key, value, reason="detected in conversation",
                                      confidence=0.5, source="regex")
            if suggestion:
                output.append(suggestion)
        return output

    def suggestions(self, limit: int = 20) -> list[dict]:
        with self.lock:
            rows = self.conn.execute("SELECT * FROM memory_suggestions WHERE status = 'pending' "
                                     "ORDER BY created_at DESC LIMIT ?",
                                     (max(1, min(int(limit or 20), 50)),)).fetchall()
        return [dict(row) for row in rows]

    def accept_suggestion(self, identifier: int) -> dict:
        with self.lock:
            row = self.conn.execute("SELECT * FROM memory_suggestions WHERE id = ? AND status = 'pending'",
                                    (identifier,)).fetchone()
            if not row:
                raise MemoryError_("That memory suggestion is no longer pending.")
            keys = set(row.keys())
            saved = self.remember(
                row["category"], row["key"], row["value"], 0.7,
                source=row["source"] if "source" in keys else "suggestion",
                quote=row["quote"] if "quote" in keys else "",
                confidence=row["confidence"] if "confidence" in keys else 0.7)
            self.conn.execute("UPDATE memory_suggestions SET status = 'accepted' WHERE id = ?", (identifier,))
            self.conn.commit()
            return saved

    def reject_suggestion(self, identifier: int) -> bool:
        with self.lock:
            cursor = self.conn.execute("UPDATE memory_suggestions SET status = 'rejected' "
                                       "WHERE id = ? AND status = 'pending'", (identifier,))
            self.conn.commit()
            return bool(cursor.rowcount)

    def forget(self, identifier: str, as_key: bool = False) -> bool:
        """Delete by id, or by key when the caller explicitly means the key.

        ``WHERE id=? OR key=?`` let a numeric key such as "42" delete the
        unrelated memory row with id 42.
        """
        identifier = str(identifier)
        with self.lock:
            if as_key:
                row = self.conn.execute("SELECT * FROM memories WHERE key = ?",
                                        (identifier,)).fetchone()
            elif identifier.isdigit():
                row = self.conn.execute("SELECT * FROM memories WHERE id = ?",
                                        (int(identifier),)).fetchone()
            else:
                row = self.conn.execute("SELECT * FROM memories WHERE key = ?",
                                        (identifier,)).fetchone()
            if not row:
                return False
            self.conn.execute("DELETE FROM memories WHERE id = ?", (row["id"],))
            self._event(row["id"], "forgot", row["value"], None, "", "manual")
            self._sync_fts(row["id"])
            self._bump_version()
            self._vector_signature = None
            self.conn.commit()
            return True

    def restore(self, event_id: int) -> dict:
        """Undo a supersede using the value recorded in the event log."""
        with self.lock:
            event = self.conn.execute("SELECT * FROM memory_events WHERE id = ? AND kind = 'superseded'",
                                      (int(event_id),)).fetchone()
            if not event:
                return {}
            memory = self.conn.execute("SELECT * FROM memories WHERE id = ?",
                                       (event["memory_id"],)).fetchone()
            if not memory:
                return {}
            now = time.time()
            self.conn.execute(
                "UPDATE memories SET value = ?, updated_at = ?, last_confirmed = ?, evidence_count = 1 "
                "WHERE id = ?", (event["old_value"], now, now, memory["id"]))
            self._event(memory["id"], "restored", memory["value"], event["old_value"], "", "manual")
            self._sync_fts(memory["id"])
            self._bump_version()
            self._vector_signature = None
            self.conn.commit()
            return self.get(memory["id"])

    def decay(self, days: int = 90) -> int:
        """Apply Ebbinghaus forgetting curve R = exp(-dt / S) to stale facts.

        Stability S grows with spaced-repetition recalls (use_count) and
        repeated confirmations (evidence_count), so frequently used facts resist
        decay while untouched one-off facts fade gracefully toward 0.05.
        """
        base_days = max(7.0, float(days))
        now = time.time()
        cutoff = now - base_days * 86400.0
        with self.lock:
            rows = self.conn.execute(
                "SELECT id, importance, last_used, last_confirmed, updated_at, "
                "use_count, evidence_count FROM memories "
                "WHERE category != 'identity' AND last_used < ? "
                "AND COALESCE(last_confirmed, updated_at) < ? AND importance > 0.05",
                (cutoff, cutoff),
            ).fetchall()
            if not rows:
                return 0
            updates = []
            for row in rows:
                last_touch = max(
                    float(row["last_used"] or 0.0),
                    float(row["last_confirmed"] or 0.0),
                    float(row["updated_at"] or 0.0),
                )
                elapsed_days = max(0.0, (now - last_touch) / 86400.0)
                reinforcements = max(0, int(row["use_count"] or 0)) + max(1, int(row["evidence_count"] or 1))
                stability = base_days * (1.0 + 0.6 * math.log1p(reinforcements))
                retention = math.exp(-elapsed_days / max(base_days, stability))
                factor = max(0.5, min(0.95, retention))
                new_importance = round(max(0.05, float(row["importance"] or 0.5) * factor), 4)
                updates.append((new_importance, row["id"]))
            self.conn.executemany("UPDATE memories SET importance = ? WHERE id = ?", updates)
            self.conn.commit()
            return len(updates)

    def prune_suggestions(self, days: int = 14) -> int:
        cutoff = time.time() - max(1, int(days)) * 86400
        with self.lock:
            cursor = self.conn.execute("DELETE FROM memory_suggestions WHERE status = 'pending' AND created_at < ?",
                                       (cutoff,))
            self.conn.commit()
            return int(cursor.rowcount)

    # -- reads ---------------------------------------------------------
    def get(self, rowid: int) -> dict:
        with self.lock:
            row = self.conn.execute("SELECT * FROM memories WHERE id = ?", (rowid,)).fetchone()
        return dict(row) if row else {}

    def list(self, category: str | None = None) -> list[dict]:
        with self.lock:
            if category:
                rows = self.conn.execute("SELECT * FROM memories WHERE category = ? ORDER BY updated_at DESC",
                                         (category,)).fetchall()
            else:
                rows = self.conn.execute("SELECT * FROM memories ORDER BY updated_at DESC").fetchall()
        return [dict(row) for row in rows]

    # -- semantic lane -------------------------------------------------
    def attach_semantic(self, embedder, vectors=None):
        """Wire the shared local embedding model into memory recall."""
        import memory_vectors
        self.embedder = embedder
        self.vectors = vectors or memory_vectors.MemoryVectors(
            model=getattr(embedder, "model_name", ""))
        self._vector_signature = None
        return self

    def _sync_vectors(self):
        if self.embedder is None or self.vectors is None:
            return False
        # One aggregate instead of materialising the whole table just to title
        # a change signature: the count plus the newest write is enough.
        with self.lock:
            row = self.conn.execute(
                "SELECT COUNT(*), COALESCE(MAX(updated_at), 0) FROM memories").fetchone()
        signature = (row[0], round(row[1] or 0, 3))
        if signature == self._vector_signature:
            return True
        self.vectors.sync(self.list(), self.embedder)
        self._vector_signature = signature
        return True

    def _semantic_ids(self, query, limit=8):
        if self.embedder is None or self.vectors is None:
            return []
        try:
            if not self._sync_vectors():
                return []
            vector = self.embedder.embed_query(query)
            if vector is None:
                return []
            return [memory_id for memory_id, _ in self.vectors.search(vector, limit)]
        except Exception:
            return []

    def recall(self, query: str, limit: int = 8, semantic: bool = True) -> list[dict]:
        tokens = _tokens(query)
        limit = max(1, min(int(limit or 8), 30))
        rows = []
        if tokens:
            expression = _match_expression(tokens[:12])
            with self.lock:
                try:
                    rows = self.conn.execute(
                        "SELECT m.*, bm25(memories_fts) AS score FROM memories_fts "
                        "JOIN memories m ON m.id = memories_fts.rowid "
                        "WHERE memories_fts MATCH ? ORDER BY score LIMIT ?",
                        (expression, limit)).fetchall()
                except sqlite3.Error:
                    like = "%" + tokens[0] + "%"
                    rows = self.conn.execute(
                        "SELECT * FROM memories WHERE key LIKE ? OR value LIKE ? "
                        "ORDER BY importance DESC LIMIT ?", (like, like, limit)).fetchall()
        ordered = [dict(row) for row in rows]
        for row in ordered:
            row.setdefault("match", "bm25")
        ids = [row["id"] for row in ordered]
        matches = self._semantic_ids(query, max(limit, 8)) if semantic else []
        if matches:
            from retrieval import fuse
            fused = fuse([ids, matches], limit=limit, weights=[1.0, 0.6])
            by_id = {row["id"]: row for row in ordered}
            merged = []
            for memory_id in fused:
                row = by_id.get(memory_id) or self.get(memory_id)
                if not row:
                    continue
                row = dict(row)
                row["match"] = ("both" if memory_id in by_id and memory_id in matches
                                else ("bm25" if memory_id in by_id else "vector"))
                merged.append(row)
            ordered = merged
        with self.lock:
            if ordered:
                stamp = time.time()
                # One executemany: a per-row UPDATE+commit writes a WAL frame
                # and pays an fsync boundary per recalled memory. Spaced recall
                # gently reinforces importance (capped at 1.0).
                self.conn.executemany(
                    "UPDATE memories SET last_used = ?, use_count = use_count + 1, "
                    "importance = MIN(1.0, ROUND(importance + 0.02, 4)) WHERE id = ?",
                    [(stamp, row["id"]) for row in ordered])
                self.conn.commit()
        return ordered

    # -- mental models -------------------------------------------------
    def _ensure_default_models(self):
        # One shared connection: committing without the lock could make a
        # concurrent remember() transaction durable halfway through.
        with self.lock:
            self.conn.execute("INSERT OR IGNORE INTO mental_models(name, question) VALUES (?, ?)",
                              (DEFAULT_MODEL_NAME, DEFAULT_MODEL_QUESTION))
            self.conn.commit()

    def models(self, refresh=False) -> list[dict]:
        if refresh:
            self._ensure_default_models()
        with self.lock:
            rows = self.conn.execute("SELECT * FROM mental_models ORDER BY name").fetchall()
        return [dict(row) for row in rows]

    def model(self, name=DEFAULT_MODEL_NAME) -> dict:
        with self.lock:
            row = self.conn.execute("SELECT * FROM mental_models WHERE name = ?", (name,)).fetchone()
        return dict(row) if row else {}

    def _facts_text(self, limit=60) -> str:
        with self.lock:
            rows = self.conn.execute(
                "SELECT category, key, value, evidence_count FROM memories "
                "ORDER BY importance DESC, last_confirmed DESC LIMIT ?", (limit,)).fetchall()
        return "\n".join(f"[{row['category']}] {row['key']}: {row['value']} (x{row['evidence_count']})"
                         for row in rows)

    def refresh_models(self, generate, force=False, min_new_facts=MIN_NEW_FACTS) -> list[dict]:
        """Rewrite standing answers when enough new facts arrived."""
        self._ensure_default_models()
        version = self.version()
        rewritten = []
        for row in self.models():
            if not force and version - int(row["memory_version"] or 0) < max(1, int(min_new_facts)):
                continue
            facts = self._facts_text()
            if not facts:
                continue
            try:
                answer = generate(row["question"], facts)
            except Exception:
                continue
            answer = str(answer or "").strip()[:1200]
            if not answer:
                continue
            with self.lock:
                self.conn.execute(
                    "UPDATE mental_models SET answer = ?, memory_version = ?, updated_at = ? WHERE name = ?",
                    (answer, version, time.time(), row["name"]))
                self.conn.commit()
            rewritten.append({"name": row["name"], "answer": answer})
        return rewritten

    # -- prompt --------------------------------------------------------
    # Two bounded reads instead of fetching every recorded memory and walking
    # a character budget over it: a long-used store paid hundreds of rows per
    # prompt call for lines the budget never reached.
    PROMPT_IDENTITY = 40
    PROMPT_OTHERS = 80

    def prompt(self, core_chars: int = 1200) -> str:
        with self.lock:
            identity = [dict(row) for row in self.conn.execute(
                "SELECT * FROM memories WHERE category = 'identity' "
                "ORDER BY importance DESC, last_confirmed DESC, updated_at DESC LIMIT ?",
                (self.PROMPT_IDENTITY,)).fetchall()]
            rows = identity + [dict(row) for row in self.conn.execute(
                "SELECT * FROM memories WHERE category != 'identity' "
                "ORDER BY importance DESC, last_confirmed DESC, updated_at DESC LIMIT ?",
                (self.PROMPT_OTHERS,)).fetchall()]
        if not rows:
            return ""
        lines = ["PERSONAL MEMORY (facts you may rely on; do not invent more):"]
        budget = core_chars
        standing = self.model()
        if standing.get("answer"):
            block = "Standing summary: " + str(standing["answer"])[:400]
            lines.append(block)
            budget -= len(block)
        others = [row for row in rows if row["category"] != "identity"]
        for row in rows:
            evidence = int(row["evidence_count"] or 1)
            suffix = f" (x{evidence})" if evidence > 1 else ""
            line = f"- [{row['category']}] {row['key']}: {row['value']}{suffix}"
            if len(line) > budget:
                break
            lines.append(line[:520])
            budget -= len(line)
        if budget > 80:
            keys = ", ".join(f"{row['category']}/{row['key']}" for row in others[:30])
            if keys:
                lines.append("Index (use recall_memory for details): " + keys[:max(0, budget - 50)])
        return "\n".join(lines)

    def stats(self) -> dict:
        with self.lock:
            total = self.conn.execute("SELECT COUNT(*) FROM memories").fetchone()[0]
            by_category = {row[0]: row[1] for row in self.conn.execute(
                "SELECT category, COUNT(*) FROM memories GROUP BY category").fetchall()}
            pending = self.conn.execute(
                "SELECT COUNT(*) FROM memory_suggestions WHERE status = 'pending'").fetchone()[0]
            events = self.conn.execute("SELECT COUNT(*) FROM memory_events").fetchone()[0]
        return {"total": int(total), "by_category": by_category,
                "pending_suggestions": int(pending), "events": int(events),
                "version": self.version(), "semantic": self.embedder is not None,
                "vectors": self.vectors.status() if self.vectors is not None else None,
                "models": len(self.models())}

    def close(self) -> None:
        try:
            if self.vectors is not None:
                self.vectors.close()
        except Exception:
            pass
        try:
            self.conn.close()
        except Exception:
            pass

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass
