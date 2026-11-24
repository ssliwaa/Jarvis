"""Float32 vector store base: unit math, corrupt-file quarantine, model-change
tripwire, cosine scan with the matrix-cache protocol and embed batching."""
import sqlite3
import sys
import tempfile
import time
from pathlib import Path
from unittest import TestCase

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import vector_store_base as store_base


class _Store(store_base.VectorStoreBase):
    """Minimal concrete subclass matching the base table contract."""

    def schema(self):
        return [
            "CREATE TABLE IF NOT EXISTS vectors (note_id INTEGER PRIMARY KEY, vec BLOB, updated REAL)",
            "CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT)",
        ]

    def add(self, row_id, vector):
        blob = store_base.unit(vector).astype(np.float32).tobytes()
        self.db.execute("INSERT OR REPLACE INTO vectors(note_id, vec, updated) VALUES (?,?,?)",
                        (row_id, blob, time.time()))
        self.db.commit()
        self._matrix_cache = None

    def add_raw(self, row_id, blob):
        self.db.execute("INSERT OR REPLACE INTO vectors(note_id, vec) VALUES (?,?)", (row_id, blob))
        self.db.commit()


class _NewStoreEachTime(TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.path = self.dir / "sub" / "store.sqlite3"


class UnitMathTests(_NewStoreEachTime):
    def test_unit_normalizes_zero_and_dtype(self):
        normalized = store_base.unit([3.0, 4.0])
        self.assertEqual(normalized.dtype.name, "float32")
        self.assertAlmostEqual(float(normalized[0]), 0.6, places=6)
        self.assertAlmostEqual(float(normalized[1]), 0.8, places=6)
        self.assertEqual(store_base.unit([0.0, 0.0]).tolist(), [0.0, 0.0])
        diagonal = store_base.unit((1.0, 1.0))
        self.assertAlmostEqual(float(np.linalg.norm(diagonal)), 1.0, places=5)

    def test_is_corruption_delegates_to_sqlite_guard(self):
        self.assertTrue(store_base.is_corruption(sqlite3.DatabaseError("file is not a database")))
        self.assertTrue(store_base.is_corruption(
            sqlite3.DatabaseError("database disk image is malformed")))
        self.assertFalse(store_base.is_corruption(ValueError("x")))
        self.assertFalse(store_base.is_corruption(sqlite3.OperationalError("database is locked")))


class StoreLifecycleTests(_NewStoreEachTime):
    def test_connects_wal_private_and_creates_parent(self):
        store = _Store(self.path, model="embed-a")
        self.assertTrue(self.path.is_file())
        self.assertEqual(oct(self.path.stat().st_mode & 0o777), "0o600")
        self.assertEqual(oct(self.path.parent.stat().st_mode & 0o777), "0o700")
        self.assertEqual(store.db.execute("PRAGMA journal_mode").fetchone()[0], "wal")
        self.assertEqual(
            store.db.execute("SELECT value FROM meta WHERE key='model'").fetchone(),
            ("embed-a",))

    def test_count_close_and_after_close(self):
        store = _Store(self.path, model="")
        self.assertEqual(store.count(), 0)
        store.add(1, [1.0, 0.0, 0.0])
        store.add(2, [0.0, 1.0, 0.0])
        self.assertEqual(store.count(), 2)
        store.close()
        with self.assertRaises(sqlite3.ProgrammingError):
            store.count()

    def test_model_tripwire_wipes_only_on_model_change(self):
        first = _Store(self.path, model="embed-a")
        first.add(1, [1.0, 0.0, 0.0])
        first.close()
        same = _Store(self.path, model="embed-a")
        self.assertEqual(same.count(), 1)
        same.close()
        changed = _Store(self.path, model="embed-b")
        self.assertEqual(changed.count(), 0)
        self.assertEqual(
            changed.db.execute("SELECT value FROM meta WHERE key='model'").fetchone(), ("embed-b",))
        changed.add(7, [1.0, 2.0, 3.0])
        changed.close()
        empty = _Store(self.path, model="")
        self.assertEqual(empty.count(), 1)
        self.assertEqual(
            empty.db.execute("SELECT value FROM meta WHERE key='model'").fetchone(),
            ("embed-b",))

    def test_quarantine_moves_corrupt_file_and_reopens(self):
        store = _Store(self.path, model="embed-a")
        store.add(1, [0.5, 0.5, 0.5])
        store.close()
        self.path.write_bytes(b"NOT A DATABASE AT ALL" * 20)
        reopened = _Store(self.path, model="embed-a")
        quarantined = list(self.path.parent.glob(f"{self.path.name}.corrupt-*"))
        self.assertEqual(len(quarantined), 1)
        self.assertTrue(quarantined[0].read_bytes().startswith(b"NOT A DATABASE"))
        self.assertEqual(reopened.count(), 0)
        self.assertEqual(
            reopened.db.execute("SELECT value FROM meta WHERE key='model'").fetchone(),
            ("embed-a",))

    def test_noncorruption_errors_propagate(self):
        class BadSchema(_Store):
            def schema(self):
                return ["CREATE TABLE ((",]

        with self.assertRaises(sqlite3.OperationalError):
            BadSchema(self.path)
        self.assertTrue(self.path.is_file())

        class FailPrepare(_Store):
            def schema(self):
                return ["CREATE TABLE IF NOT EXISTS vectors (note_id INTEGER PRIMARY KEY, vec BLOB)",
                        "CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT)"]

            def _prepare(self, db):
                raise sqlite3.OperationalError("no such table: meta")

        failing = self.dir / "fail.sqlite3"
        with self.assertRaises(sqlite3.OperationalError) as ctx:
            FailPrepare(failing)
        self.assertEqual(str(ctx.exception), "no such table: meta")
        self.assertTrue(failing.is_file())


class SearchTests(_NewStoreEachTime):
    def _seeded(self):
        store = _Store(self.path, model="")
        store.add(1, [1.0, 0.0, 0.0])
        store.add(4, [1.0, 0.0, 0.0])
        store.add(2, [0.0, 1.0, 0.0])
        store.add(3, [0.0, -1.0, 0.0])
        return store

    def test_scoring_ties_and_min_score_cutoff(self):
        store = self._seeded()
        self.assertEqual(store.search([1.0, 0.0, 0.0]), [(1, 1.0), (4, 1.0)])
        self.assertEqual(store.search([0.0, 1.0, 0.0], min_score=0.99), [(2, 1.0)])
        self.assertEqual(store.search([0.0, -1.0, 0.0], min_score=0.99), [(3, 1.0)])

        self.assertEqual(store.search([-1.0, 0.0, 0.0], min_score=0.0),
                         [(2, 0.0), (3, 0.0)])  # ortogonalne przechodza przy >= 0.0
        everything = store.search([1.0, 0.0, 0.0], min_score=0.0)
        self.assertEqual([row_id for row_id, _ in everything], [1, 4, 2, 3])

    def test_top_k_clamps(self):
        store = self._seeded()
        self.assertEqual(len(store.search([1.0, 0.0, 0.0], top_k=0)), 1)
        self.assertEqual(len(store.search([1.0, 0.0, 0.0], top_k=-5)), 1)
        self.assertEqual(len(store.search([1.0, 0.0, 0.0], top_k=999, min_score=0.0)), 4)
        self.assertEqual(len(store.search([1.0, 0.0, 0.0], top_k=1)), 1)

    def test_skips_dim_mismatch_and_nan_rows(self):
        store = self._seeded()
        store.add_raw(99, store_base.unit([1.0, 1.0]).astype(np.float32).tobytes())
        store.add_raw(98, np.array([np.nan, 0.0, 0.0], dtype=np.float32).tobytes())
        self.assertEqual(store.search([1.0, 0.0, 0.0]), [(1, 1.0), (4, 1.0)])
        self.assertEqual(store.count(), 6)

    def test_matrix_cache_protocol(self):
        store = self._seeded()
        store.search([1.0, 0.0, 0.0])  # rozgrzewa cache dla dim=3
        store.db.execute(
            "INSERT INTO vectors(note_id, vec) VALUES (50, ?)",
            (store_base.unit([0.0, 0.0, 1.0]).astype(np.float32).tobytes(),))
        store.db.commit()
        stale = store.search([0.0, 0.0, 1.0])
        self.assertEqual(stale, [])  # cache nie widzi nowego wiersza
        store._matrix_cache = None
        self.assertEqual(store.search([0.0, 0.0, 1.0]), [(50, 1.0)])
        store.search([1.0, 1.0])  # wymiar 2 wymusza przebudowę cache'u
        self.assertEqual(store._matrix_cache[0], 2)

    def test_empty_store_returns_empty(self):
        store = _Store(self.dir / "empty.sqlite3", model="")
        self.assertEqual(store.search([1.0, 1.0, 1.0]), [])
        self.assertEqual(store.count(), 0)


class EmbedBatchTests(_NewStoreEachTime):
    def test_embed_normalizes_and_fails_closed(self):
        store = _Store(self.path, model="")

        class Embedder:
            def __init__(self, reply):
                self.reply = reply

            def embed(self, texts):
                assert texts == ["a", "b"]
                return self.reply

        vectors = store._embed(["a", "b"], Embedder([[3.0, 4.0], [0.0, 2.0]]))
        self.assertAlmostEqual(float(vectors[0][0]), 0.6, places=6)
        for vector in vectors:
            self.assertAlmostEqual(float(np.linalg.norm(vector)), 1.0, places=5)

        class Short(Embedder):
            def __init__(self):
                super().__init__([[1.0, 0.0]])

        with self.assertRaises(RuntimeError) as ctx:
            store._embed(["a", "b"], Short())
        self.assertEqual(str(ctx.exception),
                         "the embedder returned a different number of vectors")

    def test_embedded_vectors_are_searchable_end_to_end(self):
        store = _Store(self.path, model="embed-x")
        vectors = store._embed(["q"], _FixedEmbedder())
        store.add(11, vectors[0])
        hits = store.search(vectors[0], min_score=0.99)
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0][0], 11)
        self.assertAlmostEqual(hits[0][1], 1.0, places=6)  # float32 roundtrip ~1.0000001


class _FixedEmbedder:
    def embed(self, texts):
        return [[0.2, 0.4, 0.4] for _ in texts]


if __name__ == "__main__":
    import unittest
    unittest.main()
