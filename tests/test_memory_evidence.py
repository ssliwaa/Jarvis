"""Evidence, supersede, restore and the event log."""
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import memory_extract
import memory_store
from memory_store import MemoryStore


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = MemoryStore(Path(self.tmp.name) / "memory.db")
        self.addCleanup(self.store.close)

    def test_first_write_is_added_and_repeat_confirms(self):
        first = self.store.remember("identity", "miasto", "Testville", 0.8)
        self.assertEqual(first["action"], "added")
        self.assertEqual(first["evidence_count"], 1)
        second = self.store.remember("identity", "miasto", "Testville", 0.8)
        self.assertEqual(second["action"], "refined")
        self.assertEqual(second["evidence_count"], 2)
        self.assertGreaterEqual(second["last_confirmed"], first["last_confirmed"])
        self.assertEqual(second["value"], "Testville")

    def test_a_changed_value_supersedes_and_keeps_the_old_one_in_history(self):
        self.store.remember("projects", "kino", "wersja 1.4.44")
        changed = self.store.remember("projects", "kino", "wersja 1.4.46")
        self.assertEqual(changed["action"], "superseded")
        self.assertEqual(changed["value"], "wersja 1.4.46")
        self.assertEqual(changed["evidence_count"], 1)
        events = self.store.events(changed["id"])
        supersede = [event for event in events if event["kind"] == "superseded"][0]
        self.assertEqual(supersede["old_value"], "wersja 1.4.44")
        self.assertEqual(supersede["new_value"], "wersja 1.4.46")

    def test_restore_brings_the_previous_value_back(self):
        self.store.remember("projects", "kino", "wersja 1.4.44")
        changed = self.store.remember("projects", "kino", "wersja 1.4.46")
        event = [e for e in self.store.events(changed["id"]) if e["kind"] == "superseded"][0]
        restored = self.store.restore(event["id"])
        self.assertEqual(restored["value"], "wersja 1.4.44")
        self.assertEqual(self.store.list("projects")[0]["value"], "wersja 1.4.44")

    def test_restore_ignores_events_that_are_not_supersedes(self):
        row = self.store.remember("identity", "imie", "Kowalski")
        event = self.store.events(row["id"])[0]
        self.assertEqual(self.store.restore(event["id"]), {})

    def test_forget_logs_an_event_and_bumps_the_version(self):
        row = self.store.remember("notes", "test", "coś")
        before = self.store.version()
        self.assertTrue(self.store.forget(row["id"]))
        self.assertGreater(self.store.version(), before)
        self.assertEqual(self.store.events(row["id"])[0]["kind"], "forgot")

    def test_prompt_marks_repeated_facts(self):
        self.store.remember("identity", "miasto", "Testville")
        self.store.remember("identity", "miasto", "Testville")
        prompt = self.store.prompt()
        self.assertIn("Testville", prompt)
        self.assertIn("(x2)", prompt)

    def test_changes_since_returns_recent_events_only(self):
        self.store.remember("identity", "imie", "Kowalski")
        stamp = self.store.events()[0]["at"] - 1
        self.assertTrue(self.store.changes_since(stamp))
        self.assertEqual(self.store.changes_since(self.store.events()[0]["at"] + 1), [])

    def test_stats_describe_the_store(self):
        self.store.remember("identity", "imie", "Kowalski")
        self.store.propose("preferences", "kawa", "bez cukru")
        stats = self.store.stats()
        self.assertEqual(stats["total"], 1)
        self.assertEqual(stats["pending_suggestions"], 1)
        self.assertFalse(stats["semantic"])


class PromptBoundsTests(unittest.TestCase):
    def test_prompt_has_a_row_cap_and_keeps_identity_ranked_first(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = memory_store.MemoryStore(Path(tmp) / "memory.db")
            store.remember("identity", "miasto", "Testville", 0.6)
            for number in range(memory_store.MemoryStore.PROMPT_OTHERS + 20):
                store.remember("notes", f"nota-{number}", "wypełniacz")
            text = store.prompt(200_000)
            self.assertIn("- [identity] miasto: Testville", text)
            # the bounded reads keep the exact store shape below a sane cap
            self.assertLess(memory_store.MemoryStore.PROMPT_IDENTITY
                            + memory_store.MemoryStore.PROMPT_OTHERS, 200)

    def test_recall_bumps_use_count_exactly_once_per_hit(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = memory_store.MemoryStore(Path(tmp) / "memory.db")
            store.remember("preferences", "kawa", "bez cukru")
            store.remember("notes", "kino", "Katowice Silesia")
            hits = store.recall("kawa kino")
            self.assertEqual(len(hits), 2)
            # the returned dicts predate the update; the database holds the bump
            for row in hits:
                self.assertEqual(store.get(row["id"])["use_count"], 1)


class KeyNormalizerTests(unittest.TestCase):
    def test_suggest_and_extract_write_the_same_stored_form(self):
        text = "wolę kawę bez cukru"
        key = memory_store.slug_key(text, fallback="preference")
        self.assertEqual(key, memory_extract._slug(text))
        self.assertNotIn(" ", key)  # spaces become underscores
        self.assertEqual(key, "wolę_kawę_bez_cukru")

    def test_a_corrupt_memory_file_is_quarantined_not_fatal(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "memory.db"
            path.write_bytes(b"this file is not a sqlite database at all" * 300)
            store = memory_store.MemoryStore(path)
            self.addCleanup(store.close)
            quarantined = list(path.parent.glob("memory.db.corrupt-*"))
            self.assertEqual(len(quarantined), 1)
            store.remember("identity", "miasto", "Testville")  # the fresh store works
            self.assertEqual(store.recall("miasto")[0]["key"], "miasto")

    def test_a_locked_database_error_is_not_quarantined(self):
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(memory_store.MemoryStore, "_open",
                                   side_effect=sqlite3.OperationalError("database is locked")):
                with self.assertRaises(sqlite3.OperationalError):
                    memory_store.MemoryStore(Path(tmp) / "memory.db")
            # nothing was renamed to *.corrupt-* on a transient error
            self.assertEqual(list(Path(tmp).iterdir()), [])

    def test_version_counts_each_write_and_survives_reopen(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "memory.db"
            store = memory_store.MemoryStore(path)
            self.addCleanup(store.close)
            store.remember("identity", "miasto", "Testville")
            store.remember("preferences", "kawa", "bez cukru")
            self.assertEqual(store.version(), 2)
            store.close()
            reopened = memory_store.MemoryStore(path)
            self.assertEqual(reopened.version(), 2)


if __name__ == "__main__":
    unittest.main()
