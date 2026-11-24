"""Vector store: incremental sync, cosine search, honest removal."""
import tempfile
import unittest
from pathlib import Path

import note_vectors


class FakeEmbedder:
    """Deterministic 2-D vectors chosen per note so ordering is provable."""

    def __init__(self, mapping):
        self.mapping = mapping
        self.calls = 0

    def embed(self, texts):
        self.calls += 1
        out = []
        for text in texts:
            key = text.split("\n")[0]
            out.append(self.mapping.get(key, [0.0, 1.0]))
        return out


def note(note_id, title, content="body", path=None):
    return {"id": note_id, "title": title, "content": content,
            "path": path or f"notes/{note_id}.md"}


class VectorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "vectors.db"
        self.addCleanup(self.tmp.cleanup)

    def index(self):
        store = note_vectors.VectorIndex(path=self.path, model="fake/model")
        self.addCleanup(store.close)
        return store

    def test_sync_embeds_once_and_skips_unchanged_notes(self):
        embedder = FakeEmbedder({"alpha": [1.0, 0.0], "beta": [0.0, 1.0]})
        store = self.index()
        first = store.sync([note(1, "alpha"), note(2, "beta")], embedder)
        self.assertEqual(first, {"embedded": 2, "removed": 0, "total": 2})
        second = store.sync([note(1, "alpha"), note(2, "beta")], embedder)
        self.assertEqual(second["embedded"], 0)
        self.assertEqual(embedder.calls, 1)

    def test_changed_content_is_re_embedded_and_removed_notes_are_dropped(self):
        embedder = FakeEmbedder({"alpha": [1.0, 0.0], "beta": [0.0, 1.0]})
        store = self.index()
        store.sync([note(1, "alpha"), note(2, "beta")], embedder)
        updated = store.sync([note(1, "alpha", "new body")], embedder)
        self.assertEqual(updated["embedded"], 1)
        self.assertEqual(updated["removed"], 1)
        self.assertEqual(store.status()["rows"], 1)

    def test_search_ranks_by_cosine_and_applies_the_floor(self):
        store = self.index()
        store.sync([note(1, "alpha"), note(2, "beta")],
                   FakeEmbedder({"alpha": [1.0, 0.0], "beta": [0.0, 1.0]}))
        # 0.995/0.005 keeps beta under the 0.10 floor.
        hits = store.search([0.995, 0.005], top_k=5)
        self.assertEqual([row[0] for row in hits], [1])
        self.assertAlmostEqual(hits[0][1], 1.0, places=3)
        self.assertEqual(store.search([0.1, 0.9], top_k=5)[0][0], 2)

    def test_search_on_an_empty_index_is_empty(self):
        self.assertEqual(self.index().search([1.0, 0.0]), [])

    def test_nan_scores_are_never_ranked(self):
        store = self.index()
        store.sync([note(1, "alpha")], FakeEmbedder({"alpha": [1.0, 0.0]}))
        self.assertEqual(store.search([float("nan"), 0.0]), [])
        self.assertEqual(store.search([1.0, 0.0])[0][0], 1)

    def test_negative_scores_are_filtered_out(self):
        store = self.index()
        store.sync([note(1, "alpha")], FakeEmbedder({"alpha": [-1.0, 0.0]}))
        self.assertEqual(store.search([1.0, 0.0]), [])

    def test_removed_note_is_deleted_even_when_nothing_else_changed(self):
        embedder = FakeEmbedder({"alpha": [1.0, 0.0], "beta": [0.0, 1.0]})
        store = self.index()
        store.sync([note(1, "alpha"), note(2, "beta")], embedder)
        result = store.sync([note(1, "alpha")], embedder)
        self.assertEqual(result["embedded"], 0)
        self.assertEqual(result["removed"], 1)
        self.assertEqual(store.status()["total_rows"], 1)
        self.assertEqual(store.status()["rows"], 1)

    def test_status_reports_coverage_not_stale_rows(self):
        store = self.index()
        store.sync([note(1, "alpha"), note(2, "beta")], FakeEmbedder({}))
        # A note that vanished before the next sync leaves a stale row behind;
        # coverage must describe the current note set, not the table size.
        self.assertEqual(store.status(note_ids=[1])["rows"], 1)
        self.assertEqual(store.status(note_ids=[1])["total_rows"], 2)
        self.assertEqual(store.status()["rows"], 2)

    def test_each_vault_root_gets_its_own_index_file(self):
        from unittest import mock
        base = Path(self.tmp.name) / "tools" / "embeddings.db"
        with mock.patch.object(note_vectors, "DEFAULT_PATH", base):
            first = note_vectors.VectorIndex(root="/vaults/one")
            second = note_vectors.VectorIndex(root="/vaults/two")
            self.addCleanup(first.close)
            self.addCleanup(second.close)
            self.assertNotEqual(first.path, second.path)
            self.assertTrue(first.path.name.startswith("embeddings-"))
            self.assertEqual(first.path.parent, base.parent)

    def test_a_temporary_vault_never_writes_into_the_tools_directory(self):
        import tempfile
        with tempfile.TemporaryDirectory() as folder:
            store = note_vectors.VectorIndex(root=folder)
            self.addCleanup(store.close)
            self.assertEqual(store.path.parent.name, "jarvis-vectors")
            self.assertNotEqual(store.path.parent, note_vectors.DEFAULT_PATH.parent)

    def test_env_override_wins_over_the_root_hash(self):
        from unittest import mock
        with mock.patch.dict("os.environ", {"JARVIS_VECTORS_DB": str(self.path)}):
            store = note_vectors.VectorIndex(root="/vaults/one")
            self.addCleanup(store.close)
            self.assertEqual(store.path, self.path)

    def test_a_corrupt_database_is_quarantined_not_fatal(self):
        bad = self.path.with_name("corrupt.db")
        bad.write_bytes(b"this file is not a sqlite database at all" * 100)
        store = note_vectors.VectorIndex(path=bad, model="fake/model")
        self.addCleanup(store.close)
        quarantined = list(bad.parent.glob("corrupt.db.corrupt-*"))
        self.assertEqual(len(quarantined), 1)
        self.assertTrue(store.count() == 0)  # fresh, empty index works

    def test_long_notes_are_chunked_and_still_rank_as_one_note(self):
        class ContentEmbedder:
            def embed(self, texts):
                return [[1.0, 0.0] if "needle" in text else [0.0, 1.0] for text in texts]

        store = self.index()
        body = ("filler sentence. " * 200) + "needle lives here. " + ("tail. " * 50)
        store.sync([note(1, "long", body)], ContentEmbedder())
        status = store.status()
        self.assertEqual(status["rows"], 1)
        self.assertGreater(status["chunks"], 1)
        hits = store.search([1.0, 0.0], top_k=8)
        self.assertEqual([row[0] for row in hits], [1])

        store.sync([note(1, "long", "short now")], ContentEmbedder())
        self.assertEqual(store.status()["chunks"], 1)

    def test_legacy_whole_note_vectors_are_migrated(self):
        import sqlite3

        import numpy as np
        connection = sqlite3.connect(str(self.path))
        connection.execute(
            "CREATE TABLE vectors (note_id INTEGER PRIMARY KEY, path TEXT, "
            "digest TEXT NOT NULL, dim INTEGER NOT NULL, vec BLOB NOT NULL, "
            "updated REAL NOT NULL)")
        vector = np.asarray([1.0, 0.0], dtype=np.float32)
        connection.execute(
            "INSERT INTO vectors VALUES (?, ?, ?, ?, ?, ?)",
            (7, "notes/7.md", note_vectors._digest("alpha", "body"),
             vector.size, vector.tobytes(), 0.0))
        connection.execute("CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT)")
        connection.execute("INSERT INTO meta VALUES ('model', 'fake/model')")
        connection.commit()
        connection.close()

        store = self.index()
        self.assertEqual(store.count(), 1)
        self.assertEqual(store.status()["chunks"], 1)
        self.assertEqual(store.search([1.0, 0.0])[0][0], 7)

    def test_switching_the_embedding_model_wipes_stale_vectors(self):
        store = note_vectors.VectorIndex(path=self.path, model="fake/model")
        self.addCleanup(store.close)
        first = FakeEmbedder({"alpha": [1.0, 0.0]})
        store.sync([note(1, "alpha")], first)
        self.assertEqual(store.count(), 1)
        store.close()

        # Same file, different model name: every stored vector now comes from
        # a different embedding space, so the lane must re-embed from zero.
        second = note_vectors.VectorIndex(path=self.path, model="other/model")
        self.addCleanup(second.close)
        self.assertEqual(second.count(), 0)
        third = FakeEmbedder({"beta": [0.0, 1.0]})
        second.sync([note(2, "beta")], third)
        self.assertEqual(second.count(), 1)
        second.close()

        same = note_vectors.VectorIndex(path=self.path, model="other/model")
        self.addCleanup(same.close)
        self.assertEqual(same.count(), 1)  # no wipe when the model is unchanged


if __name__ == "__main__":
    unittest.main()
