"""session_store: durable chat archive, FTS search and context-state blobs.

Real SQLite on a scratch file — no schema mocking. Pinned contracts: token
gating (invalid tokens silently no-op everywhere, never stored), turns stay
ordered and bounded, old turns can be pruned while session rows survive
searchability, FTS and the LIKE fallback must both obey the MASKED token
rule for model-facing payloads, and the context-state table (the persistence
behind compression, operator jobs and cursor state) round-trips with size
guards and corruption tolerance.
"""
import json
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from session_store import SessionStore, _keep_days_from_env

TOKEN_A = "a" * 24
TOKEN_B = "b" * 24


class KeepDaysEnvTests(unittest.TestCase):
    def test_env_parsing_is_tolerance_first(self):
        cases = {
            "": 0.0,
            "   ": 0.0,
            "abc": 0.0,
            "-5": 0.0,
            "0": 0.0,
            "30": 30.0,
            "7.5": 7.5,
        }
        for raw, expected in cases.items():
            with patch.dict(os.environ, {"JARVIS_SESSION_KEEP_DAYS": raw}):
                self.assertEqual(_keep_days_from_env(), expected, repr(raw))


class StoreTestCase(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.path = Path(tmp.name) / "sessions.db"
        self.store = SessionStore(self.path)
        self.addCleanup(self.store.close)

    def sql(self, query, args=()):
        with self.store.lock:
            return self.store.conn.execute(query, args)


class AppendHistoryTests(StoreTestCase):
    def test_invalid_tokens_are_silently_ignored(self):
        for bad in ("", "short", "with spaces" * 3, "zażółć-gęślą-także", "a" * 129,
                    None, 42):
            self.store.append(bad, "user text", "answer text")
        self.assertEqual(self.store.recent(), [])
        self.assertEqual(self.store.history("with spaces" * 3), [])

    def test_user_and_assistant_turns_persist_in_order(self):
        self.store.append(TOKEN_A, "pytanie pierwsze", "odpowiedź pierwsza")
        self.store.append(TOKEN_A, "pytanie drugie", "")
        turns = self.store.history(TOKEN_A)
        self.assertEqual(len(turns), 3)
        self.assertEqual([row["role"] for row in turns],
                         ["user", "assistant", "user"])
        self.assertEqual(turns[0]["content"], "pytanie pierwsze")
        self.assertEqual(turns[-1]["content"], "pytanie drugie")

    def test_turn_ids_order_history_after_and_latest(self):
        self.store.append(TOKEN_A, "one", "one-a")
        self.store.append(TOKEN_A, "two", "two-a")
        first_id = self.store.history(TOKEN_A)[0]["id"]
        latest = self.store.latest_turn_id(TOKEN_A)
        self.assertGreater(latest, first_id)
        middle = self.store.history_after(TOKEN_A, after_id=first_id, limit=10)
        self.assertEqual([row["content"] for row in middle],
                         ["one-a", "two", "two-a"])
        self.assertEqual(self.store.latest_turn_id(TOKEN_B), 0)
        # Boundaries: a bogus after_id of -3 behaves like 0.
        self.assertEqual(len(self.store.history_after(TOKEN_A, after_id=-3)), 4)

    def test_content_is_clipped_to_12000_chars(self):
        self.store.append(TOKEN_A, "x" * 15000, "y" * 15000)
        turns = self.store.history(TOKEN_A)
        self.assertEqual(len(turns[0]["content"]), 12000)
        self.assertEqual(len(turns[1]["content"]), 12000)

    def test_recent_orders_by_last_update(self):
        self.store.append(TOKEN_A, "hello")
        time.sleep(0.01)
        self.store.append(TOKEN_B, "world")
        recent = self.store.recent()
        self.assertEqual([row["token"] for row in recent][:2], [TOKEN_B, TOKEN_A])
        self.assertGreater(self.store.last_seen(TOKEN_B), self.store.last_seen(TOKEN_A))
        self.assertEqual(self.store.last_seen("missing" + "x" * 16), 0.0)


class MetaTests(StoreTestCase):
    def test_meta_round_trip_values_and_types(self):
        self.store.set_meta(TOKEN_A, job={"id": "op-1"}, count=3, label="test")
        meta = self.store.meta(TOKEN_A)
        self.assertEqual(meta["job"], {"id": "op-1"})
        self.assertEqual(meta["count"], 3)
        self.assertEqual(meta["label"], "test")
        self.store.set_meta(TOKEN_A, count=5)
        self.assertEqual(self.store.meta(TOKEN_A)["count"], 5)
        self.assertIn("job", self.store.meta(TOKEN_A))  # other keys untouched

    def test_meta_guards(self):
        self.store.set_meta("too-short", key="value")     # invalid token: no-op
        self.assertEqual(self.store.meta("too-short"), {})
        huge = {"blob": "z" * 9000}
        self.store.set_meta(TOKEN_A, huge=huge)
        stored = self.store.meta(TOKEN_A)["huge"]
        self.assertEqual(len(stored), 3000)                # degenerated to str[:3000]

    def test_meta_skips_corrupt_rows(self):
        self.store.set_meta(TOKEN_A, good="value")
        self.sql("INSERT INTO session_meta(token, key, value, updated_at) "
                 "VALUES (?, 'broken', '{not json', ?)", (TOKEN_A, time.time()))
        meta = self.store.meta(TOKEN_A)
        self.assertEqual(meta, {"good": "value"})


class ContextStateTests(StoreTestCase):
    def test_context_state_round_trip_and_guards(self):
        self.assertEqual(self.store.load_context_state("chat:" + TOKEN_A), {})
        self.store.save_context_state("chat:" + TOKEN_A,
                                       {"summary": "stan", "generation": 2})
        self.assertEqual(self.store.load_context_state("chat:" + TOKEN_A),
                         {"summary": "stan", "generation": 2})
        # Oversized payloads are refused without partial writes.
        with self.assertRaises(ValueError):
            self.store.save_context_state("chat:" + TOKEN_A, {"b": "x" * 600_000})
        self.assertEqual(self.store.load_context_state("chat:" + TOKEN_A)["generation"], 2)
        # Non-dict payloads are refused; invalid keys never touch the table.
        with self.assertRaises(ValueError):
            self.store.save_context_state("chat:" + TOKEN_A, ["not", "a", "dict"])
        with self.assertRaises(ValueError):
            self.store.save_context_state("../evil", {"a": 1})
        self.store.delete_context_state("chat:" + TOKEN_A)
        self.assertEqual(self.store.load_context_state("chat:" + TOKEN_A), {})

    def test_corrupt_blob_loads_empty(self):
        self.store.save_context_state("operator:o1", {"ok": True})
        self.sql("UPDATE context_state SET data = '{broken json' WHERE key = ?",
                 ("operator:o1",))
        self.assertEqual(self.store.load_context_state("operator:o1"), {})

    def test_prune_context_state_respects_time_and_zero(self):
        self.store.save_context_state("old:key", {"a": 1})
        self.sql("UPDATE context_state SET updated_at = 1 WHERE key = ?", ("old:key",))
        removed = self.store.prune_context_state(keep_days=30)
        self.assertGreaterEqual(removed, 1)
        self.assertEqual(self.store.load_context_state("old:key"), {})
        self.assertEqual(self.store.prune_context_state(keep_days=0), 0)


class SearchTests(StoreTestCase):
    def test_fts_search_finds_words_including_polish(self):
        self.store.append(TOKEN_A, "pytanie o żółć i zimną herbatę", "odpowiedź: wrinka")
        self.store.append(TOKEN_B, "coś zupełnie innego", "nie ma nic")
        hits = self.store.search("żółć")
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["token"], TOKEN_A)
        self.assertIn("żółć", hits[0]["content"])
        self.assertEqual(self.store.search("  "), [])
        japanese_miss = self.store.search("wrinka")
        self.assertEqual(len(japanese_miss), 1)

    def test_search_context_masks_tokens_and_marks_the_match(self):
        self.store.append(TOKEN_A, "first", "odpowiedź z magicznym słowem")
        hits = self.store.search_context("magicznym", window=2)
        self.assertEqual(len(hits), 1)
        hit = hits[0]
        self.assertTrue(hit["session"].endswith("…"))
        self.assertTrue(hit["session"].startswith(TOKEN_A[:8]))
        self.assertNotIn(TOKEN_A, json.dumps(hit))
        marked = [row for row in hit["context"] if row["is_match"]]
        self.assertEqual(len(marked), 1)
        self.assertIn("magicznym", marked[0]["content"])
        self.assertFalse(any(row["is_match"] for row in hit["context"]
                             if not row["content"].count("magicznym")))

    def test_clear_removes_every_trace_of_a_session(self):
        self.store.append(TOKEN_A, "usuń mnie completely", "i tę odpowiedź")
        self.store.set_meta(TOKEN_A, job="op-7")
        self.store.save_context_state("chat:" + TOKEN_A, {"summary": "s"})
        self.store.clear(TOKEN_A)
        self.assertEqual(self.store.history(TOKEN_A), [])
        self.assertEqual(self.store.meta(TOKEN_A), {})
        self.assertEqual(self.store.load_context_state("chat:" + TOKEN_A), {})
        self.assertEqual(self.store.latest_turn_id(TOKEN_A), 0)
        self.assertEqual(self.store.search("completely"), [])
        self.assertEqual(self.store.recent(), [])


class PruneTests(StoreTestCase):
    def test_prune_drops_old_turns_but_keeps_sessions(self):
        self.store.append(TOKEN_A, "stara wiadomość", "stara odpowiedź")
        self.sql("UPDATE turns SET created_at = 1 WHERE token = ?", (TOKEN_A,))
        removed = self.store.prune(keep_days=90)
        self.assertEqual(removed, 2)
        self.assertEqual(self.store.history(TOKEN_A), [])
        # The session row survives: recent()/searchability stay intact.
        recent = self.store.recent()
        self.assertEqual([row["token"] for row in recent], [TOKEN_A])
        self.assertEqual(self.store.prune(keep_days=0), 0)

    def test_append_throttles_prune_to_once_an_hour(self):
        with patch.dict(os.environ, {"JARVIS_SESSION_KEEP_DAYS": "30"}):
            store = SessionStore(self.path)
            self.addCleanup(store.close)
            store._last_prune = time.time()  # a prune window is currently open
            with patch.object(store, "prune") as prune, \
                    patch.object(store, "prune_context_state") as prune_state:
                store.append(TOKEN_B, "one")
                store.append(TOKEN_B, "two")
            self.assertEqual(prune.call_count, 0)
            self.assertEqual(prune_state.call_count, 0)

    def test_first_append_prunes_when_retention_is_set(self):
        with patch.dict(os.environ, {"JARVIS_SESSION_KEEP_DAYS": "7"}):
            store = SessionStore(self.path)
            self.assertEqual(store.keep_days, 7.0)
            self.addCleanup(store.close)
            with patch.object(store, "prune") as prune, \
                    patch.object(store, "prune_context_state") as prune_state:
                store.append(TOKEN_B, "kickoff")
            prune.assert_called_once_with(7.0)      # the user's retention
            prune_state.assert_called_once_with(90)  # the state floor


class SummaryTests(StoreTestCase):
    def test_summary_prefers_the_rolling_compression(self):
        self.store.append(TOKEN_A, "surowa historia", "surowa odpowiedź")
        self.store.save_context_state("chat:" + TOKEN_A,
                                       {"summary": "skompresowane podsumowanie"})
        self.assertEqual(self.store.summary(TOKEN_A), "skompresowane podsumowanie")

    def test_summary_falls_back_to_recent_raw_turns(self):
        self.store.append(TOKEN_A, "pytanie numer", "odpowiedź numer")
        summary = self.store.summary(TOKEN_A)
        self.assertIn("pytanie numer", summary)
        self.assertNotIn("skompresowane", summary)
        self.assertEqual(self.store.summary(TOKEN_B), "")
        # A corrupt state blob degrades to raw turns, not to a crash.
        self.store.save_context_state("chat:" + TOKEN_B, {"summary": {"not": "str"}})
        self.assertEqual(self.store.summary(TOKEN_B), "")


if __name__ == "__main__":
    unittest.main()
