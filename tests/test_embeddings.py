"""Lazy embedding lifecycle: load once, unload after idle, never at boot."""
import time
import unittest

import embeddings


class FakeModel:
    def __init__(self, name):
        self.name = name
        self.calls = 0

    def embed(self, texts):
        self.calls += 1
        return [[1.0, 0.0, 0.0] for _ in texts]


class LifecycleTests(unittest.TestCase):
    def make(self, idle=300):
        made = {}

        def loader(name):
            made["model"] = FakeModel(name)
            return made["model"]

        engine = embeddings.Embeddings(model_name="fake/model", idle_seconds=idle, loader=loader)
        self.addCleanup(engine.close)
        return engine, made

    def test_nothing_loads_before_the_first_query(self):
        engine, made = self.make()
        self.assertFalse(engine.status()["loaded"])
        self.assertNotIn("model", made)

    def test_first_query_loads_and_later_queries_reuse(self):
        engine, made = self.make()
        engine.embed(["a", "b"])
        engine.embed(["c"])
        self.assertTrue(engine.status()["loaded"])
        self.assertEqual(engine.loads, 1)
        self.assertEqual(made["model"].calls, 2)

    def test_idle_timeout_unloads_the_model(self):
        engine, made = self.make(idle=60)
        engine.embed(["a"])
        engine._last_used = time.time() - 120
        engine._maybe_unload()
        self.assertFalse(engine.status()["loaded"])
        self.assertEqual(engine.unloads, 1)
        engine.embed(["b"])
        self.assertEqual(engine.loads, 2)

    def test_recent_use_is_not_unloaded(self):
        engine, _ = self.make(idle=60)
        engine.embed(["a"])
        engine._maybe_unload()
        self.assertTrue(engine.status()["loaded"])

    def test_unload_is_idempotent(self):
        engine, _ = self.make()
        self.assertFalse(engine.unload())
        engine.embed(["a"])
        self.assertTrue(engine.unload())
        self.assertFalse(engine.unload())

    def test_disabled_flag_wins(self):
        import os
        from unittest import mock
        with mock.patch.dict(os.environ, {"JARVIS_EMBEDDINGS": "off"}):
            self.assertFalse(embeddings.Embeddings.enabled())
        with mock.patch.dict(os.environ, {"JARVIS_EMBEDDINGS": "1"}):
            self.assertTrue(embeddings.Embeddings.enabled())


if __name__ == "__main__":
    unittest.main()
