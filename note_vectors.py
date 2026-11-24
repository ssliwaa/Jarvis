"""Persistent note vectors in SQLite, synced incrementally.

Vectors are stored as float32 blobs and compared with cosine similarity in
numpy: at this vault size (hundreds of notes) an exact scan is faster and more
predictable than an ANN index, and it keeps the lane dependency-light. The sync
is content-addressed, so a restart re-embeds only notes that actually changed.
"""
from __future__ import annotations

import hashlib
import math
import os
import tempfile
import time
from pathlib import Path

import numpy as np

from vector_store_base import VectorStoreBase, unit

DEFAULT_PATH = Path.home() / ".jarvis-tools" / "embeddings.db"
BATCH = 32
CHUNK_CHARS = 1200
CHUNK_OVERLAP = 200
MAX_CHUNKS = 24


def _digest(title, content):
    payload = (str(title or "") + "\n" + str(content or "")).encode("utf-8", "replace")
    return hashlib.sha1(payload).hexdigest()


def _split(content, size=CHUNK_CHARS, overlap=CHUNK_OVERLAP):
    """Split long notes into overlapping windows, preferring a clean boundary.

    A single embedding for a two-thousand-word note blurs the parts: the whole
    note competes with a short, focused one for the same vector slot. Windows
    keep each idea searchable, while the overlap stops a sentence that falls on
    a boundary from becoming invisible.
    """
    text = str(content or "").strip()
    if len(text) <= size:
        return [text]
    chunks = []
    start = 0
    while start < len(text) and len(chunks) < MAX_CHUNKS:
        end = min(len(text), start + size)
        if end < len(text):
            # Prefer the last paragraph/sentence break in the final quarter.
            window = text[start:end]
            cut = max(window.rfind("\n\n"), window.rfind("\n"), window.rfind(". "))
            if cut >= size * 0.70:
                end = start + cut + 1
        chunk = text[start:end].strip()
        if chunk:
            chunks.append(chunk)
        if end >= len(text):
            break
        start = max(end - overlap, start + 1)
    return chunks or [""]


def _is_scratch_root(root):
    """True for pytest-style temporary vaults under the OS temp directory."""
    try:
        resolved = Path(str(root)).resolve()
        scratch = Path(tempfile.gettempdir()).resolve()
    except (OSError, RuntimeError):
        return False
    return resolved == scratch or scratch in resolved.parents


class VectorIndex(VectorStoreBase):
    TABLE = "note_chunks"
    ID_COLUMN = "note_id"
    LABEL = "note chunks"
    QUARANTINE_LABEL = "vectors"

    def __init__(self, path=None, model="", root=None):
        if path is None:
            override = os.environ.get("JARVIS_VECTORS_DB")
            if override:
                path = Path(override)
            elif root:
                # One vault, one index file: a test application pointed at a
                # temporary root must never rewrite the real vault's vectors,
                # and must not leave a database behind in the tools directory.
                stamp = hashlib.sha1(str(root).encode("utf-8", "replace")).hexdigest()[:8]
                base = DEFAULT_PATH
                if _is_scratch_root(root):
                    base = Path(tempfile.gettempdir()) / "jarvis-vectors" / "embeddings.db"
                path = base.with_name(f"embeddings-{stamp}.db")
            else:
                path = DEFAULT_PATH
        super().__init__(path, model)

    def schema(self):
        return (
            "CREATE TABLE IF NOT EXISTS note_chunks ("
            "note_id INTEGER NOT NULL, chunk INTEGER NOT NULL, path TEXT, "
            "digest TEXT NOT NULL, dim INTEGER NOT NULL, vec BLOB NOT NULL, "
            "updated REAL NOT NULL, PRIMARY KEY (note_id, chunk))",
            "CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT)",
        )

    def _prepare(self, db):
        super()._prepare(db)
        # Databases from before chunking stored exactly one row per note in
        # ``vectors``. Reuse those rows as chunk zero when the note still fits
        # one window, then retire the old table so the two cannot drift apart.
        legacy = db.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'vectors'").fetchone()
        if not legacy:
            return
        empty = db.execute("SELECT COUNT(*) FROM note_chunks").fetchone()[0] == 0
        if empty:
            db.execute(
                "INSERT OR IGNORE INTO note_chunks"
                "(note_id, chunk, path, digest, dim, vec, updated) "
                "SELECT note_id, 0, path, digest, dim, vec, updated FROM vectors")
        db.execute("DROP TABLE vectors")
        db.commit()

    def sync(self, notes, embedder) -> dict:
        """Embed new/changed notes and drop chunks for notes that disappeared."""
        desired = {}
        texts = {}
        for note in notes:
            note_id = note.get("id", note.get("index"))
            if type(note_id) is not int:
                continue
            title = str(note.get("title") or note.get("label") or "")
            content = str(note.get("content") or "")
            pieces = _split(content)
            desired[note_id] = (str(note.get("path") or ""), _digest(title, content),
                                len(pieces))
            texts[note_id] = [title + "\n" + piece for piece in pieces]
        with self.lock:
            existing = {row[0]: (row[1], row[2], int(row[3]))
                        for row in self.db.execute(
                            "SELECT note_id, path, digest, COUNT(*) FROM note_chunks "
                            "GROUP BY note_id")}
        removed = [note_id for note_id in existing if note_id not in desired]
        changed = [note_id for note_id, (_, digest, chunks) in desired.items()
                   if existing.get(note_id, (None, None, None))[1:] != (digest, chunks)]
        path_updates = [(path, note_id) for note_id, (path, digest, chunks) in desired.items()
                        if note_id in existing and note_id not in changed
                        and existing[note_id][0] != path]
        if path_updates:
            with self.lock:
                for path, note_id in path_updates:
                    self.db.execute(
                        "UPDATE note_chunks SET path = ? WHERE note_id = ?", (path, note_id))
                self.db.commit()
        cleared = set()
        queue = [(note_id, index, text)
                 for note_id in changed
                 for index, text in enumerate(texts[note_id])]
        for start in range(0, len(queue), BATCH):
            batch = queue[start:start + BATCH]
            arrays = self._embed([text for _, _, text in batch], embedder)
            now = time.time()
            with self.lock:
                for (note_id, index, _), array in zip(batch, arrays):
                    if note_id not in cleared:
                        # Replacing every window at once is what makes a
                        # shortened note lose its stale tail chunks.
                        self.db.execute("DELETE FROM note_chunks WHERE note_id = ?", (note_id,))
                        cleared.add(note_id)
                    self.db.execute(
                        "INSERT INTO note_chunks "
                        "(note_id, chunk, path, digest, dim, vec, updated) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?)",
                        (note_id, index, desired[note_id][0], desired[note_id][1],
                         int(array.size), array.tobytes(), now),
                    )
                self.db.commit()
        # Deleting is independent of embedding: a note removed from the vault
        # must disappear even when nothing else changed.
        if removed:
            with self.lock:
                for note_id in removed:
                    self.db.execute("DELETE FROM note_chunks WHERE note_id = ?", (note_id,))
                self.db.commit()
        if changed or removed:
            self._matrix_cache = None
        return {"embedded": len(changed), "removed": len(removed), "total": len(desired)}

    def search(self, vector, top_k=8, min_score=0.10):
        """Best matching window per note, ranked by cosine similarity."""
        query = unit(vector)
        with self.lock:
            cached = self._matrix_cache
            if cached is None or cached[0] != query.size:
                rows = self.db.execute(
                    "SELECT note_id, chunk, vec FROM note_chunks").fetchall()
                ids, chunks, vecs = [], [], []
                for note_id, chunk, blob in rows:
                    array = np.frombuffer(blob, dtype=np.float32)
                    if array.size != query.size:
                        continue
                    ids.append(int(note_id))
                    chunks.append(int(chunk))
                    vecs.append(array)
                matrix = np.vstack(vecs) if vecs else None
                cached = (query.size, ids, chunks, matrix)
                self._matrix_cache = cached
        _, ids, chunks, matrix = cached
        if matrix is None:
            return []
        raw_scores = (matrix @ query).tolist()
        best = {}
        for note_id, chunk, score in zip(ids, chunks, raw_scores):
            if not math.isfinite(score) or score < min_score:
                continue
            current = best.get(note_id)
            if current is None or score > current[0] or (
                    score == current[0] and chunk < current[1]):
                best[note_id] = (score, chunk)
        scored = [(note_id, score) for note_id, (score, _) in best.items()]
        scored.sort(key=lambda pair: (-pair[1], pair[0]))
        return scored[:max(1, min(int(top_k), 50))]

    def count(self, note_ids=None):
        """Distinct notes covered by the current set, not stale rows."""
        if note_ids is None:
            with self.lock:
                return int(self.db.execute(
                    "SELECT COUNT(DISTINCT note_id) FROM note_chunks").fetchone()[0])
        ids = [int(note_id) for note_id in note_ids if type(note_id) is int]
        if not ids:
            return 0
        placeholders = ",".join("?" * len(ids))
        with self.lock:
            row = self.db.execute(
                f"SELECT COUNT(DISTINCT note_id) FROM note_chunks "
                f"WHERE note_id IN ({placeholders})", ids).fetchone()
        return int(row[0])

    def status(self, note_ids=None) -> dict:
        with self.lock:
            chunks = int(self.db.execute(
                "SELECT COUNT(*) FROM note_chunks").fetchone()[0])
        return {"rows": self.count(note_ids), "total_rows": self.count(),
                "chunks": chunks, "path": str(self.path), "model": self.model}
