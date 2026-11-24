"""Standing summary: when it is rewritten and how it reaches the prompt."""
import tempfile
import unittest
from pathlib import Path

from memory_store import MemoryStore


class ModelTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = MemoryStore(Path(self.tmp.name) / "memory.db")
        self.addCleanup(self.store.close)

    def generate(self, question, facts):
        self.asked = (question, facts)
        return "Właściciel mieszka w Testville i uczy się w Przykładowie."

    def test_nothing_happens_without_facts(self):
        self.assertEqual(self.store.refresh_models(self.generate, force=True), [])

    def test_forced_refresh_writes_the_answer(self):
        self.store.remember("identity", "miasto", "Testville")
        rewritten = self.store.refresh_models(self.generate, force=True)
        self.assertEqual(rewritten[0]["name"], "owner")
        self.assertIn("Testville", self.store.model()["answer"])
        self.assertEqual(self.store.model()["memory_version"], self.store.version())

    def test_a_small_change_does_not_trigger_a_rewrite(self):
        self.store.remember("identity", "miasto", "Testville")
        self.store.refresh_models(self.generate, force=True)
        self.store.remember("notes", "drobiazg", "jeden")
        self.assertEqual(self.store.refresh_models(self.generate), [])

    def test_enough_new_facts_trigger_a_rewrite(self):
        self.store.remember("identity", "miasto", "Testville")
        self.store.refresh_models(self.generate, force=True)
        for index in range(3):
            self.store.remember("notes", f"fakt{index}", f"wartość {index}")
        self.assertEqual(len(self.store.refresh_models(self.generate)), 1)

    def test_a_failing_generator_is_ignored(self):
        self.store.remember("identity", "miasto", "Testville")

        def broken(question, facts):
            raise RuntimeError("model down")

        self.assertEqual(self.store.refresh_models(broken, force=True), [])

    def test_the_prompt_carries_the_standing_summary(self):
        self.store.remember("identity", "miasto", "Testville")
        self.store.refresh_models(self.generate, force=True)
        prompt = self.store.prompt()
        self.assertIn("Standing summary:", prompt)
        self.assertIn("Przykładowie", prompt)


if __name__ == "__main__":
    unittest.main()
