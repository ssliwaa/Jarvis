"""Standard-library BM25 retrieval over the note vault.

SQLite's FTS5 is used as the index engine; the original keyword scorer remains
available in server.py as a fallback. Notes are folded to a search form so
Polish diacritics and case do not prevent a match.
"""
from __future__ import annotations

import os
import re
import sqlite3
import threading
import time
import unicodedata
from pathlib import Path

STOPWORDS = frozenset(
    "a an and are as at be by for from how i in is it of on or the to what when where who why with you "
    "about do does this that czy co jak jest na nie o po w z ze i oraz się to ten ta te mi mnie a jakie "
    "jaki która które czym".split()
)
_WORD = re.compile(r"[^\W_]+", re.UNICODE)
_POLISH = str.maketrans({"ł": "l", "Ł": "L", "ø": "o", "Ø": "O", "đ": "d", "Đ": "D", "ß": "ss"})


class RetrievalError(RuntimeError):
    pass


def fold(text):
    text = unicodedata.normalize("NFKD", str(text or ""))
    text = "".join(char for char in text if not unicodedata.combining(char))
    return text.translate(_POLISH).casefold()


def terms(text):
    return [word for word in (fold(part) for part in _WORD.findall(str(text or "")))
            if len(word) > 1 and word not in STOPWORDS]


def fuse(rank_lists, k=60, limit=8, weights=None):
    """Reciprocal rank fusion: BM25 and vector candidates on one ranked list."""
    scores = {}
    for index, ids in enumerate(rank_lists):
        weight = 1.0
        if weights and index < len(weights):
            try:
                weight = float(weights[index])
            except (TypeError, ValueError):
                weight = 1.0
        for position, note_id in enumerate(ids or ()):
            if type(note_id) is not int:
                continue
            scores[note_id] = scores.get(note_id, 0.0) + weight / (k + position + 1)
    ordered = sorted(scores.items(), key=lambda pair: (-pair[1], pair[0]))
    return [note_id for note_id, _ in ordered[:max(1, min(int(limit), 32))]]


class BM25Index:
    """In-memory FTS5 index; thread-safe across concurrent readers."""

    def __init__(self, notes, root=None):
        self.lock = threading.Lock()
        try:
            self.db = sqlite3.connect(":memory:", check_same_thread=False)
            self.db.execute(
                "CREATE VIRTUAL TABLE notes USING fts5("
                "title, body, note_id UNINDEXED, path UNINDEXED, modified UNINDEXED)"
            )
        except sqlite3.OperationalError as error:
            raise RetrievalError("SQLite FTS5 is unavailable") from error
        self.root = Path(root) if root is not None else None
        self.ids = []
        rows = []
        for note in notes:
            note_id = note.get("id", note.get("index"))
            if type(note_id) is not int:
                continue
            path = str(note.get("path", ""))
            modified = float(note["modified"]) if isinstance(note.get("modified"), (int, float)) else self._modified(path)
            title = note.get("title") or note.get("label") or ""
            rows.append((fold(title), fold(note.get("content", "")),
                         note_id, path, modified))
            self.ids.append(note_id)
        self.db.executemany("INSERT INTO notes VALUES (?, ?, ?, ?, ?)", rows)
        self.db.commit()

    def close(self):
        with self.lock:
            try:
                self.db.close()
            except Exception:
                pass

    def __del__(self):
        self.close()

    def _modified(self, path):
        if self.root is None or not path:
            return 0.0
        try:
            return float(os.stat(self.root / path, follow_symlinks=False).st_mtime)
        except OSError:
            return 0.0

    @staticmethod
    def _expression(words):
        clean = [re.sub(r"[^a-z0-9]+", "", word) for word in words]
        clean = [word for word in clean if word]
        # A Polish query often carries an ending the note does not ("samochodu"
        # against "samochód"). Prefix search alone only helps when the query is
        # the shorter form, so also try the word with one or two trailing
        # letters removed. Short words are left alone to avoid noise.
        variants = []
        for word in clean:
            variants.append(word)
            if len(word) >= 6:
                variants.append(word[:-1])
            if len(word) >= 8:
                variants.append(word[:-2])
            # Polish inflection can add three letters ("utorrencie" against the
            # note's "utorrent"); stopping at two missed the whole topic.
            if len(word) >= 9:
                variants.append(word[:-3])
        # FTS5 treats OR/NEAR/AND as operators; the folded tokens are alnum.
        return " OR ".join(f"{word}*" for word in dict.fromkeys(variants))

    def search(self, query, previous=(), top_k=6):
        """Return note ids, best first; fall back to history only when needed."""
        current = terms(query)
        older = [word for word in terms(" ".join(previous or ())) if word not in set(current)]
        candidates = current or older
        if not candidates:
            return []
        expression = self._expression(candidates)
        if not expression:
            return []
        try:
            with self.lock:
                rows = self.db.execute(
                    "SELECT note_id, bm25(notes, 12.0, 1.0) AS rank, modified "
                    "FROM notes WHERE notes MATCH ? ORDER BY rank LIMIT 32",
                    (expression,),
                ).fetchall()
                if not rows and current and older:
                    fallback_expr = self._expression(older)
                    if fallback_expr:
                        rows = self.db.execute(
                            "SELECT note_id, bm25(notes, 12.0, 1.0) AS rank, modified "
                            "FROM notes WHERE notes MATCH ? ORDER BY rank LIMIT 32",
                            (fallback_expr,),
                        ).fetchall()
        except sqlite3.OperationalError as error:
            raise RetrievalError("FTS5 query failed") from error
        now = time.time()
        ranked = []
        for note_id, rank, modified in rows:
            recency = 0.0
            if modified:
                age_days = max(0.0, (now - float(modified)) / 86400.0)
                # Quantise to sub-day resolution: notes written in the same
                # session must tie on recency, otherwise microsecond mtimes
                # reorder equally-ranked titles and bury the expected note.
                recency = round(1.0 / (1.0 + age_days / 30.0), 3)
            ranked.append((-float(rank) + 0.25 * recency, int(note_id)))
        ranked.sort(key=lambda row: (-row[0], row[1]))
        limit = max(1, min(int(top_k), 32))
        return [note_id for _, note_id in ranked[:limit]]
