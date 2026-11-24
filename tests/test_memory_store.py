"""memory_store: personal long-term memory semantics.

Real SQLite on a scratch file. The contracts that matter: remembering never
overwrites silently (repeat bumps evidence, a change supersedes and leaves an
event, restore can roll a supersede back), suggestions are a queue that only
reaches the store through accept (with dedupe against memories and rejected),
forget distinguishes numeric ids from numeric keys, decay leaves identity
alone and has a hard floor, recall reinforces gently, and the prompt builds a
bounded mental model with the standing summary first.
"""
import tempfile
import time
import unittest
from pathlib import Path

from memory_store import MemoryError_, MemoryStore, slug_key


class SlugKeyTests(unittest.TestCase):
    def test_normalizes_case_whitespace_and_drops_noise(self):
        cases = {
            "Lubię Koty": "lubię_koty",
            "  WOLĘ  ciemny motyw!": "wolę_ciemny_motyw",
            "TOR-01: wersja": "tor-01_wersja",
            "UPPER": "upper",
        }
        for raw, expected in cases.items():
            self.assertEqual(slug_key(raw), expected, repr(raw))

    def test_fallback_and_bounds(self):
        self.assertEqual(slug_key("!!!", "pref"), "pref")
        self.assertEqual(slug_key(None, "pref"), "pref")
        self.assertEqual(slug_key(""), "")
        self.assertEqual(len(slug_key("x" * 500)), 120)


class StoreTestCase(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.store = MemoryStore(Path(tmp.name) / "memory.db")
        self.addCleanup(self.store.close)

    def sql(self, query, args=()):
        with self.store.lock:
            return self.store.conn.execute(query, args)


class RememberTests(StoreTestCase):
    def test_action_ladder_added_refined_superseded(self):
        first = self.store.remember("identity", "imię", "Kowalski")
        self.assertEqual(first["action"], "added")
        self.assertEqual(first["evidence_count"], 1)
        again = self.store.remember("identity", "imię", "Kowalski")
        self.assertEqual(again["action"], "refined")
        self.assertEqual(again["evidence_count"], 2)
        changed = self.store.remember("identity", "imię", "Adam")
        self.assertEqual(changed["action"], "superseded")
        self.assertEqual(changed["value"], "Adam")
        self.assertEqual(changed["evidence_count"], 1)   # reset on supersede

    def test_guards_and_clamps(self):
        for args in (("notes", "", "v"), ("notes", "k", ""), ("notes", None, "v")):
            with self.assertRaises(MemoryError_):
                self.store.remember(*args)
        weird = self.store.remember("bogus-category", "k", "v")
        self.assertEqual(weird["category"], "notes")      # unknown -> notes
        long_value = self.store.remember("notes", "k2", "z" * 6000)
        self.assertEqual(len(long_value["value"]), 4000)
        clamped = self.store.remember("notes", "k3", "v", importance=9.0)
        self.assertEqual(clamped["importance"], 1.0)

    def test_refinement_never_lowers_importance_or_confidence(self):
        self.store.remember("notes", "ważne", "v1", importance=0.9, confidence=0.9)
        # A refinement with weaker scores revises, never lowers.
        self.store.remember("notes", "ważne", "v1", importance=0.2, confidence=0.2)
        row = self.sql("SELECT * FROM memories WHERE key = ?", ("ważne",)).fetchone()
        self.assertEqual(row["importance"], 0.9)
        self.assertEqual(row["confidence"], 0.9)

    def test_events_and_version_bump(self):
        self.store.remember("notes", "first", "v1")
        version0 = self.store.version()
        self.store.remember("notes", "first", "v1")     # confirmed
        self.store.remember("notes", "first", "v2")     # superseded
        self.assertGreater(self.store.version(), version0 + 1)
        kinds = [event["kind"] for event in self.store.events()]
        self.assertEqual(kinds[:3], ["superseded", "confirmed", "added"])
        supersede = self.store.events(limit=1)[0]
        self.assertEqual(supersede["old_value"], "v1")
        self.assertEqual(supersede["new_value"], "v2")


class ProposalQueueTests(StoreTestCase):
    def test_propose_dedupes_against_memories_and_decisions(self):
        self.store.remember("preferences", "motyw", "ciemny")
        self.assertIsNone(self.store.propose("preferences", "motyw", "ciemny"))
        proposal = self.store.propose("preferences", "muzyka", "rock")
        self.assertEqual(proposal["key"], "muzyka")
        # The same fact cannot queue twice while pending...
        self.assertIsNone(self.store.propose("preferences", "muzyka", "rock"))
        # ...but a pending key is updated in place, never duplicated.
        updated = self.store.propose("preferences", "muzyka", "metal")
        self.assertEqual(updated["id"], proposal["id"])
        self.assertEqual(self.store.suggestions(limit=10)[0]["value"], "metal")
        self.store.reject_suggestion(updated["id"])
        # A rejected fact stays answered: it does not come back.
        self.assertIsNone(self.store.propose("preferences", "muzyka", "metal"))

    def test_propose_rejects_tiny_input(self):
        self.assertIsNone(self.store.propose("notes", "a", "too short"))
        self.assertIsNone(self.store.propose("notes", "key", "x"))

    def test_accept_writes_through_remember_and_closes_the_queue(self):
        proposal = self.store.propose("projects", "jarvis", "rozwój asystenta")
        saved = self.store.accept_suggestion(proposal["id"])
        self.assertEqual(saved["action"], "added")
        self.assertEqual(saved["importance"], 0.7)
        self.assertEqual(self.store.suggestions(), [])
        with self.assertRaises(MemoryError_):
            self.store.accept_suggestion(proposal["id"])
        # Accepting again through a new proposal of the same fact no-ops:
        self.assertIsNone(self.store.propose("projects", "jarvis", "rozwój asystenta"))

    def test_suggest_extracts_preferences_and_identity(self):
        found = self.store.suggest("Wolę ciemny motyw interfejsu i klimatyzację")
        self.assertTrue(found)
        categories = {item["category"] for item in found}
        self.assertIn("preferences", categories)
        self.assertEqual(self.store.suggest("krótko"), [])
        self.assertEqual(self.store.suggest("x" * 2001), [])


class ForgetRestoreTests(StoreTestCase):
    def test_forget_by_id_key_and_the_numeric_key_hazard(self):
        row = self.store.remember("notes", "kod_pocztowy", "31-030", importance=0.9)
        self.store.remember("notes", "42", "odpowiedź na wszystko")
        pure_id = row["id"]
        # A numeric key must not match an unrelated row id.
        self.assertFalse(self.store.forget("99"))
        self.assertTrue(self.store.forget(str(pure_id)))          # by id
        self.assertEqual(self.store.get(pure_id), {})
        self.assertEqual(self.store.list("notes")[0]["value"], "odpowiedź na wszystko")
        self.assertTrue(self.store.forget("42", as_key=True))     # explicitly by key
        self.assertEqual(self.store.list("notes"), [])

    def test_restore_rolls_back_a_supersede(self):
        self.store.remember("identity", "zawód", "programista")
        self.store.remember("identity", "zawód", "astronauta")
        supersede = [event for event in self.store.events()
                     if event["kind"] == "superseded"][0]
        restored = self.store.restore(supersede["id"])
        self.assertEqual(restored["value"], "programista")
        self.assertEqual(restored["evidence_count"], 1)
        kinds = [event["kind"] for event in self.store.events(limit=2)]
        self.assertIn("restored", kinds)
        self.assertEqual(self.store.restore(999999), {})
        forgot_event = [event for event in self.store.events()
                        if event["kind"] == "forgot"]
        self.assertEqual(self.store.restore(forgot_event[0]["id"]) if forgot_event else {}, {})


class DecayTests(StoreTestCase):
    def test_decay_touches_only_stale_non_identity_rows(self):
        self.store.remember("identity", "imię", "Kowalski")
        self.store.remember("notes", "notatka", "stara treść", importance=0.8)
        self.store.remember("notes", "nowa", "świeża treść", importance=0.8)
        self.sql("UPDATE memories SET last_used = 1, last_confirmed = 1, updated_at = 1 "
                 "WHERE key = ? OR key = ?", ("imię", "notatka"))
        decayed = self.store.decay(days=90)
        self.assertEqual(decayed, 1)
        old = self.sql("SELECT importance FROM memories WHERE key = 'notatka'").fetchone()
        fresh = self.sql("SELECT importance FROM memories WHERE key = 'nowa'").fetchone()
        identity = self.sql("SELECT importance FROM memories WHERE key = 'imię'").fetchone()
        self.assertEqual(old[0], 0.4)       # factor floor 0.5 on an ancient row
        self.assertEqual(fresh[0], 0.8)    # untouched inside the window
        self.assertEqual(identity[0], 0.5) # identity is never decayed
        # Below the floor stays below: repeated decay converges, never zero.
        self.sql("UPDATE memories SET last_used = 1, last_confirmed = 1, updated_at = 1 "
                 "WHERE key = 'notatka'")
        self.store.decay(days=90)
        again = self.sql("SELECT importance FROM memories WHERE key = 'notatka'").fetchone()
        self.assertGreaterEqual(again[0], 0.05)

    def test_decay_days_clamped_to_seven(self):
        row = self.store.remember("notes", "k", "v")
        self.sql("UPDATE memories SET last_used = ?, last_confirmed = ?, updated_at = ? "
                 "WHERE id = ?", (time.time() - 3 * 86400, time.time() - 3 * 86400,
                                  time.time() - 3 * 86400, row["id"]))
        self.assertEqual(self.store.decay(days=-1), 0)   # 3 days < the 7-day clamp
        self.assertEqual(self.sql("SELECT importance FROM memories WHERE id = ?",
                                  (row["id"],)).fetchone()[0], 0.5)


class RecallTests(StoreTestCase):
    def test_recall_reinforces_gently(self):
        row = self.store.remember("projects", "jarvis", "asystent rozwijany w Pythonie")
        hits = self.store.recall("jarvis python", semantic=False)
        self.assertTrue(hits)
        self.assertEqual(hits[0]["match"], "bm25")
        self.assertEqual(hits[0]["id"], row["id"])
        after = self.store.get(row["id"])
        self.assertEqual(after["importance"], 0.52)   # +0.02 per recall
        self.assertEqual(after["use_count"], 1)
        self.store.recall("pythonie", semantic=False)
        self.assertEqual(self.store.get(row["id"])["importance"], 0.54)
        self.assertEqual(self.store.get(row["id"])["use_count"], 2)

    def test_recall_reinforcement_is_capped_and_off_cases(self):
        row = self.store.remember("notes", "kot", "mruczy bardzo głośno", importance=1.0)
        self.store.recall("mruczy", semantic=False)
        self.assertEqual(self.store.get(row["id"])["importance"], 1.0)  # capped at 1.0
        self.assertEqual(self.store.recall("", semantic=False), [])
        self.assertEqual(self.store.recall("zzzz nie istnieje", semantic=False), [])


class ModelsAndPromptTests(StoreTestCase):
    def setUp(self):
        super().setUp()
        self.store.remember("identity", "imię", "Kowalski", importance=0.9)
        self.store.remember("preferences", "motyw", "ciemny", importance=0.7)

    def test_default_model_seeded_and_refresh_rewrites(self):
        seeded = self.store.models(refresh=True)
        names = [row["name"] for row in seeded]
        self.assertIn("owner", names)
        first = seeded[0]
        self.assertEqual(first.get("answer") or "", "")
        rewritten = self.store.refresh_models(
            lambda question, facts: "KRÓTKA ODPOWIEDŹ na pytanie", force=True)
        self.assertEqual(rewritten, [{"name": "owner",
                                      "answer": "KRÓTKA ODPOWIEDŹ na pytanie"}])
        stored = self.store.model("owner")
        self.assertTrue(stored["answer"].startswith("KRÓTKA ODPOWIEDŹ"))
        self.assertGreaterEqual(stored["memory_version"], self.store.version() - 1)
        # Without force and with no new facts, nothing is regenerated.
        self.assertEqual(self.store.refresh_models(lambda *_: "nowa wersja",
                                                   min_new_facts=100), [])

    def test_prompt_is_bounded_summary_first(self):
        self.store.refresh_models(lambda question, facts: "Właściciel: Kowalski", force=True)
        prompt = self.store.prompt(core_chars=2000)
        self.assertTrue(prompt.startswith("PERSONAL MEMORY"))
        self.assertIn("Standing summary: Właściciel: Kowalski", prompt)
        self.assertIn("[identity] imię: Kowalski", prompt)
        abrupt = self.store.prompt(core_chars=60)
        self.assertLessEqual(len(abrupt), 200)   # budget cuts, nothing more
        self.assertIn("PERSONAL MEMORY", abrupt)

    def test_stats_shape(self):
        stats = self.store.stats()
        self.assertEqual(stats["total"], 2)
        self.assertEqual(stats["by_category"].get("identity"), 1)
        self.assertEqual(stats["pending_suggestions"], 0)
        self.assertFalse(stats["semantic"])
        self.assertIsNone(stats["vectors"])
        self.assertGreaterEqual(stats["version"], 1)
        # Mental models seed lazily: none exist until someone asks for them.
        self.assertEqual(stats["models"], 0)
        self.store.models(refresh=True)
        self.assertGreaterEqual(self.store.stats()["models"], 1)


class PruneSuggestionsTests(StoreTestCase):
    def test_old_pending_suggestions_are_pruned(self):
        self.store.propose("notes", "stare", "something old")
        self.sql("UPDATE memory_suggestions SET created_at = 1 WHERE key = 'stare'")
        removed = self.store.prune_suggestions(days=14)
        self.assertGreaterEqual(removed, 1)
        self.assertEqual(self.store.suggestions(), [])


if __name__ == "__main__":
    unittest.main()
