"""Personal memory and durable session archive tests."""
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

import memory_store
import session_store
import sqlite_guard


class MemorySessionTests(unittest.TestCase):
    def test_memory_persists_and_recalls(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "memory.db"
            store = memory_store.MemoryStore(path)
            row = store.remember("preferences", "answer_style", "concise and direct", 0.9)
            self.assertTrue(row["id"])
            self.assertTrue(store.recall("answer style"))
            self.assertIn("concise", store.prompt())
            store.close()
            reopened = memory_store.MemoryStore(path)
            self.assertEqual(reopened.list("preferences")[0]["value"], "concise and direct")
            self.assertTrue(reopened.forget(row["id"]))
            self.assertEqual(reopened.list(), [])
            reopened.close()

    def test_numeric_key_forget_does_not_hit_an_unrelated_row_id(self):
        with tempfile.TemporaryDirectory() as directory:
            store = memory_store.MemoryStore(Path(directory) / "memory.db")
            first = store.remember("preferences", "theme", "dark")
            second = store.remember("preferences", "42", "answer")
            self.assertNotEqual(first["id"], second["id"])
            self.assertTrue(store.forget("42", as_key=True))
            self.assertEqual(store.list("preferences")[0]["key"], "theme")
            store.close()

    def test_session_archive_is_searchable_and_clearable(self):
        token = "a" * 43
        with tempfile.TemporaryDirectory() as directory:
            store = session_store.SessionStore(Path(directory) / "sessions.db")
            store.append(token, "where did we discuss Kino?", "In the media note.")
            store.append(token, "and the projector?", "The lamp is warm.")
            hits = store.search("Kino")
            self.assertTrue(hits)
            self.assertEqual(hits[0]["token"], token)
            self.assertEqual(len(store.history(token)), 4)
            self.assertIn("Kino", store.summary(token))
            hits = store.search_context("projector")
            self.assertTrue(hits)
            self.assertIn("…", hits[0]["session"])
            self.assertTrue(any(turn["is_match"] for turn in hits[0]["context"]))
            self.assertLessEqual(len(hits[0]["context"]), 10)
            store.set_meta(token, operator={"id": "job1", "status": "done"})
            self.assertEqual(store.meta(token)["operator"]["status"], "done")
            store.clear(token)
            self.assertEqual(store.history(token), [])
            self.assertEqual(store.meta(token), {})
            self.assertEqual(store.recent(), [])
            store.close()

    def test_prune_removes_old_turns_and_their_fts_rows(self):
        token = "b" * 43
        with tempfile.TemporaryDirectory() as directory:
            store = session_store.SessionStore(Path(directory) / "sessions.db")
            store.append(token, "ancient question", "ancient answer")
            # age the turns by hand: append stamps them with "now"
            old = time.time() - 400 * 86400
            store.conn.execute("UPDATE turns SET created_at = ?", (old,))
            store.conn.execute("UPDATE sessions SET updated_at = ?", (old,))
            store.conn.commit()
            store.append(token, "fresh question", "fresh answer")

            self.assertEqual(store.prune(365), 2)  # stale user+assistant pair
            self.assertEqual(len(store.history(token)), 2)
            self.assertEqual([turn["content"] for turn in store.history(token)],
                             ["fresh question", "fresh answer"])
            self.assertTrue(store.search("ancient") == [] or all(
                "ancient" not in str(hit["content"]) for hit in store.search("ancient")))
            # old sessions stay listed: only turns are discarded
            self.assertTrue(any(row["token"] == token for row in store.recent()))
            self.assertEqual(store.prune(365), 0)  # second pass is a no-op
            store.close()

    def test_prune_disabled_keeps_everything(self):
        token = "c" * 43
        with tempfile.TemporaryDirectory() as directory:
            store = session_store.SessionStore(Path(directory) / "sessions.db")
            store.append(token, "hello", "hi")
            self.assertEqual(store.prune(0), 0)
            self.assertEqual(len(store.history(token)), 2)
            store.close()

    def test_retention_env_is_parsed_conservatively(self):
        token = "d" * 43
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.dict(os.environ, {"JARVIS_SESSION_KEEP_DAYS": "30"}):
            store = session_store.SessionStore(Path(directory) / "s.db")
            self.assertEqual(store.keep_days, 30.0)
            store.append(token, "question", "answer")
            store.close()
        with mock.patch.dict(os.environ, {"JARVIS_SESSION_KEEP_DAYS": "not a number"}):
            self.assertEqual(session_store._keep_days_from_env(), 0.0)
        self.assertEqual(session_store._keep_days_from_env(), 0.0)


class PrivatePermissionTests(unittest.TestCase):
    def test_state_database_and_parent_are_owner_only(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "private" / "memory.db"
            store = memory_store.MemoryStore(path)
            try:
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
                self.assertEqual(path.parent.stat().st_mode & 0o777, 0o700)
            finally:
                store.close()


class QuarantineTests(unittest.TestCase):
    def test_quarantine_moves_the_wal_and_shm_sidecars(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.db"
            path.write_bytes(b"not a database")
            (Path(directory) / "state.db-wal").write_bytes(b"wal")
            (Path(directory) / "state.db-shm").write_bytes(b"shm")
            corrupt = sqlite_guard.quarantine_database(path, "test")
            self.assertTrue(corrupt.is_file())
            self.assertTrue(corrupt.with_name(corrupt.name + "-wal").is_file())
            self.assertTrue(corrupt.with_name(corrupt.name + "-shm").is_file())
            self.assertFalse(path.exists())
            self.assertFalse((Path(directory) / "state.db-wal").exists())

    def test_a_corrupt_session_archive_is_quarantined_instead_of_failing_boot(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sessions.db"
            path.write_bytes(b"not a database" * 100)
            store = session_store.SessionStore(path)
            self.assertEqual(store.recent(), [])
            store.close()
            self.assertTrue(list(Path(directory).glob("sessions.db.corrupt-*")))


if __name__ == "__main__":
    unittest.main()
