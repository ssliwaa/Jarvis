"""Vector lane for personal memories.

Same idea as the note index, kept in its own small file: memories are a few
dozen short rows, so an exact cosine scan is enough and an ANN index would only
add failure modes.
"""
from __future__ import annotations

import hashlib
import os
import time
from pathlib import Path

from vector_store_base import VectorStoreBase

DEFAULT_PATH = Path.home() / ".jarvis-tools" / "memory-vectors.db"


def _digest(category, key, value):
    payload = f"{category}\n{key}\n{value}".encode("utf-8", "replace")
    return hashlib.sha1(payload).hexdigest()


class MemoryVectors(VectorStoreBase):
    TABLE = "memory_vectors"
    ID_COLUMN = "memory_id"
    LABEL = "memory vectors"
    QUARANTINE_LABEL = "memory-vectors"

    def __init__(self, path=None, model=""):
        super().__init__(Path(path or os.environ.get("JARVIS_MEMORY_VECTORS_DB") or DEFAULT_PATH),
                         model)

    def schema(self):
        return (
            "CREATE TABLE IF NOT EXISTS memory_vectors ("
            "memory_id INTEGER PRIMARY KEY, digest TEXT NOT NULL, dim INTEGER NOT NULL, "
            "vec BLOB NOT NULL, updated REAL NOT NULL)",
            "CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT)",
        )

    def sync(self, rows, embedder) -> dict:
        desired = {}
        by_id = {}
        for row in rows:
            memory_id = row.get("id")
            if type(memory_id) is not int:
                continue
            desired[memory_id] = _digest(row.get("category"), row.get("key"), row.get("value"))
            by_id[memory_id] = row
        with self.lock:
            existing = dict(self.db.execute(
                "SELECT memory_id, digest FROM memory_vectors").fetchall())
        changed = [memory_id for memory_id, digest in desired.items()
                   if existing.get(memory_id) != digest]
        removed = [memory_id for memory_id in existing if memory_id not in desired]
        embedded = 0
        for start in range(0, len(changed), 32):
            chunk = changed[start:start + 32]
            texts = [f"{by_id[memory_id].get('key')}: {by_id[memory_id].get('value')}"
                     for memory_id in chunk]
            arrays = self._embed(texts, embedder)
            now = time.time()
            with self.lock:
                for memory_id, array in zip(chunk, arrays):
                    self.db.execute(
                        "INSERT INTO memory_vectors (memory_id, digest, dim, vec, updated) "
                        "VALUES (?, ?, ?, ?, ?) ON CONFLICT(memory_id) DO UPDATE SET "
                        "digest=excluded.digest, dim=excluded.dim, vec=excluded.vec, "
                        "updated=excluded.updated",
                        (memory_id, desired[memory_id], int(array.size), array.tobytes(), now))
                    embedded += 1
                self.db.commit()
        if removed:
            with self.lock:
                for memory_id in removed:
                    self.db.execute("DELETE FROM memory_vectors WHERE memory_id = ?", (memory_id,))
                self.db.commit()
        if changed or removed:
            self._matrix_cache = None
        return {"embedded": embedded, "removed": len(removed), "total": len(desired)}

    def search(self, vector, top_k=8, min_score=0.30):
        return super().search(vector, top_k, min_score)

    def status(self) -> dict:
        return {"rows": self.count(), "model": self.model}
