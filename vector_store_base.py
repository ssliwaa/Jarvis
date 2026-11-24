"""Shared SQLite float32 vector store.

Both vector lanes (notes and personal memories) store unit vectors as float32
blobs and compare them with an exact cosine scan; at this size an ANN index
would only add failure modes.  This module owns the parts that must behave
identically in both lanes: the corrupt-file quarantine, the model-change
tripwire, the connection lifecycle and the scan itself.
"""
from __future__ import annotations

import math
import sqlite3
import threading
from pathlib import Path

import numpy as np

import sqlite_guard


def is_corruption(error: Exception) -> bool:
    return sqlite_guard.is_corruption(error)


def unit(vector):
    array = np.asarray(vector, dtype=np.float32)
    norm = float(np.linalg.norm(array))
    return array / norm if norm else array


class VectorStoreBase:
    """One table of ``(id, digest, dim, vec, updated)`` rows, scanned by cosine."""

    TABLE = "vectors"
    ID_COLUMN = "note_id"
    LABEL = "vectors"
    QUARANTINE_LABEL = "vectors"

    def __init__(self, path, model=""):
        self.path = Path(path)
        self.model = model
        self.lock = threading.Lock()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._matrix_cache = None
        self.db = self._connect()

    def schema(self):
        raise NotImplementedError

    def _prepare(self, db):
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA synchronous=NORMAL")
        for statement in self.schema():
            db.execute(statement)
        db.commit()

    def _connect(self):
        """Open the database, quarantining a corrupt file (with sidecars)."""
        db = sqlite_guard.connect_private(self.path)
        try:
            self._prepare(db)
        except sqlite3.DatabaseError as error:
            if not is_corruption(error):
                raise
            try:
                db.close()
            except Exception:
                pass
            sqlite_guard.quarantine_database(self.path, self.QUARANTINE_LABEL)
            db = sqlite_guard.connect_private(self.path)
            self._prepare(db)
        self._sync_model(db)
        sqlite_guard.secure_database(self.path)
        return db

    def _sync_model(self, db):
        """Wipe stale rows when the embedding model changed.

        Digests cover only content, so after switching the model every digest
        would still match while every stored vector answers from a different
        embedding space; search would then silently return nothing forever.
        The stored model name is the tripwire to re-embed from zero.
        """
        if not self.model:
            return
        row = db.execute("SELECT value FROM meta WHERE key = 'model'").fetchone()
        if row and row[0] == self.model:
            return
        db.execute(f"DELETE FROM {self.TABLE}")
        if row:
            db.execute("UPDATE meta SET value = ? WHERE key = 'model'", (self.model,))
        else:
            db.execute("INSERT INTO meta(key, value) VALUES ('model', ?)", (self.model,))
        db.commit()

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass

    def close(self):
        with self.lock:
            try:
                self.db.close()
            except Exception:
                pass

    def _embed(self, texts, embedder):
        """Embed one batch and return unit vectors, failing closed on a short reply."""
        vectors = embedder.embed(texts)
        if len(vectors) != len(texts):
            raise RuntimeError("the embedder returned a different number of vectors")
        return [unit(vector) for vector in vectors]

    def search(self, vector, top_k=8, min_score=0.10):
        query = unit(vector)
        with self.lock:
            cached = self._matrix_cache
            if cached is None or cached[0] != query.size:
                rows = self.db.execute(f"SELECT {self.ID_COLUMN}, vec FROM {self.TABLE}").fetchall()
                same_dim_ids, same_dim_vecs = [], []
                for row_id, blob in rows:
                    array = np.frombuffer(blob, dtype=np.float32)
                    if array.size != query.size:
                        continue
                    same_dim_ids.append(row_id)
                    same_dim_vecs.append(array)
                matrix = np.vstack(same_dim_vecs) if same_dim_vecs else None
                cached = (query.size, same_dim_ids, matrix)
                self._matrix_cache = cached
        _, same_dim_ids, matrix = cached
        if matrix is None:
            return []
        scored = []
        raw_scores = matrix @ query
        for row_id, score in zip(same_dim_ids, raw_scores.tolist()):
            if math.isfinite(score) and score >= min_score:
                scored.append((row_id, float(score)))
        scored.sort(key=lambda pair: (-pair[1], pair[0]))
        return scored[:max(1, min(int(top_k), 50))]

    def count(self):
        with self.lock:
            return int(self.db.execute(f"SELECT COUNT(*) FROM {self.TABLE}").fetchone()[0])
