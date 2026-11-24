"""Semantic lane for personal memory."""
import tempfile
import unittest
from pathlib import Path

import memory_vectors
from memory_store import MemoryStore


class FakeEmbedder:
    model_name = "fake/model"

    def _vector(self, text):
        lowered = str(text or "").casefold()
        if "mieszk" in lowered or "testville" in lowered:
            return [1.0, 0.0, 0.0]
        if "kino" in lowered or "film" in lowered:
            return [0.0, 1.0, 0.0]
        return [0.0, 0.0, 1.0]

    def embed(self, texts):
        return [self._vector(text) for text in texts]

    def embed_query(self, text):
        return self._vector(text)


class VectorStoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = memory_vectors.MemoryVectors(Path(self.tmp.name) / "vectors.db")
        self.addCleanup(self.store.close)

    def rows(self):
        return [{"id": 1, "category": "identity", "key": "miasto", "value": "Testville"},
                {"id": 2, "category": "projects", "key": "kino", "value": "biblioteka filmów"}]

    def test_sync_embeds_once_and_prunes_removed_rows(self):
        embedder = FakeEmbedder()
        first = self.store.sync(self.rows(), embedder)
        self.assertEqual(first["embedded"], 2)
        self.assertEqual(self.store.sync(self.rows(), embedder)["embedded"], 0)
        removed = self.store.sync(self.rows()[:1], embedder)
        self.assertEqual(removed["removed"], 1)
        self.assertEqual(self.store.count(), 1)

    def test_search_returns_the_nearest_memory(self):
        self.store.sync(self.rows(), FakeEmbedder())
        hits = self.store.search([1.0, 0.0, 0.0], top_k=2)
        self.assertEqual(hits[0][0], 1)


class SemanticRecallTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        folder = Path(self.tmp.name)
        self.store = MemoryStore(folder / "memory.db")
        self.store.attach_semantic(FakeEmbedder(), vectors=memory_vectors.MemoryVectors(folder / "vectors.db"))
        self.addCleanup(self.store.close)

    def test_a_paraphrase_finds_the_fact_bm25_misses(self):
        self.store.remember("identity", "miasto", "Testville")
        keyword = self.store.recall("gdzie mieszkam", semantic=False)
        self.assertEqual(keyword, [])
        hits = self.store.recall("gdzie mieszkam")
        self.assertEqual(hits[0]["key"], "miasto")
        self.assertEqual(hits[0]["match"], "vector")

    def test_keyword_hits_stay_first_when_both_lanes_agree(self):
        self.store.remember("identity", "miasto", "Testville")
        hits = self.store.recall("Testville")
        self.assertEqual(hits[0]["key"], "miasto")
        self.assertIn(hits[0]["match"], ("both", "bm25"))

    def test_a_new_fact_is_indexed_on_the_next_recall(self):
        self.store.remember("identity", "miasto", "Testville")
        self.store.recall("gdzie mieszkam")
        self.store.remember("projects", "kino", "biblioteka filmów")
        hits = self.store.recall("jaki film obejrzeć")
        self.assertEqual(hits[0]["key"], "kino")

    def test_keyword_only_rows_are_labelled(self):
        self.store.remember("identity", "miasto", "Testville")
        hits = self.store.recall("Testville", semantic=False)
        self.assertEqual(hits[0]["match"], "bm25")

    def test_semantic_failure_falls_back_to_keywords(self):
        self.store.remember("identity", "miasto", "Testville")

        class Broken(FakeEmbedder):
            def embed_query(self, text):
                raise RuntimeError("model gone")

        self.store.embedder = Broken()
        self.store._vector_signature = None
        hits = self.store.recall("Testville")
        self.assertEqual(hits[0]["key"], "miasto")


class QuarantineTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def rows(self):
        return [{"id": 1, "category": "identity", "key": "miasto", "value": "Testville"}]

    def test_a_corrupt_database_is_quarantined_not_fatal(self):
        bad = Path(self.tmp.name) / "broken.db"
        bad.write_bytes(b"no sqlite magic here" * 200)
        store = memory_vectors.MemoryVectors(bad)
        self.addCleanup(store.close)
        quarantined = list(bad.parent.glob("broken.db.corrupt-*"))
        self.assertEqual(len(quarantined), 1)
        self.assertEqual(store.count(), 0)

    def test_switching_the_embedding_model_wipes_stale_rows(self):
        path = Path(self.tmp.name) / "model-swap.db"
        named = memory_vectors.MemoryVectors(path, model="fake/model")
        named.sync(self.rows(), FakeEmbedder())
        self.assertEqual(named.count(), 1)
        named.close()

        swapped = memory_vectors.MemoryVectors(path, model="other/model")
        self.addCleanup(swapped.close)
        self.assertEqual(swapped.count(), 0)  # stale space wiped, re-embed happens on next sync
        swapped.sync(self.rows(), FakeEmbedder())
        self.assertEqual(swapped.count(), 1)
        swapped.close()

        again = memory_vectors.MemoryVectors(path, model="other/model")
        self.addCleanup(again.close)
        self.assertEqual(again.count(), 1)  # unchanged model keeps its rows


if __name__ == "__main__":
    unittest.main()
