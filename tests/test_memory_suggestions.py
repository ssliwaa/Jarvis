import tempfile
import unittest
from pathlib import Path

from memory_store import MemoryStore


class MemorySuggestionTests(unittest.TestCase):
    def test_suggestion_is_not_saved_until_accepted(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = MemoryStore(Path(tmp) / "memory.db")
            suggestions = store.suggest("Wolę kawę bez cukru.")
            self.assertEqual(len(suggestions), 1)
            self.assertEqual(store.list(), [])
            saved = store.accept_suggestion(suggestions[0]["id"])
            self.assertEqual(saved["value"], "kawę bez cukru")
            self.assertEqual(store.list()[0]["key"], saved["key"])

    def test_reject_does_not_touch_memory(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = MemoryStore(Path(tmp) / "memory.db")
            suggestions = store.suggest("Mieszkam w Testville.")
            self.assertTrue(store.reject_suggestion(suggestions[0]["id"]))
            self.assertEqual(store.list(), [])
            # A rejected fact must not be proposed again on the same input.
            self.assertEqual(store.suggest("Mieszkam w Testville."), [])

    def test_propose_updates_existing_pending_key_instead_of_duplicating(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = MemoryStore(Path(tmp) / "memory.db")
            first = store.propose("preferences", "trening", "Biega 3 razy w tygodniu")
            second = store.propose("preferences", "trening", "Biega 4 razy w tygodniu wg 80/20")
            self.assertEqual(first["id"], second["id"])
            pending = store.suggestions()
            self.assertEqual(len(pending), 1)
            self.assertEqual(pending[0]["value"], "Biega 4 razy w tygodniu wg 80/20")


if __name__ == "__main__":
    unittest.main()
