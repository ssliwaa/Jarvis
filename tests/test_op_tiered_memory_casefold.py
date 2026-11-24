"""Regression tests: entity_upsert identity is case-insensitive (P3 fix).

The (subject, predicate) lookup in _entity_upsert used to compare strings
exactly, so "ALICE"/"alice"/"Alice" minted parallel active triples and the
Mem0-style contradiction resolution never fired. The fix folds subject and
predicate with str.casefold() - the same full-Unicode semantics the object
comparison already uses - so these tests also pin the non-ASCII folding that
SQLite's ASCII-only NOCASE collation could not provide.

All data lives in a tmp SQLite file per test; nothing touches a real store.
"""
import sqlite3
import tempfile
import unittest

import operator_modules.op_tiered_memory as tm

# "zazolc" with Polish diacritics, built via escapes to keep this file pure
# ASCII; its uppercase spelling differs only in non-ASCII letters.
_SUBJECT_LOWER = "za\u017c\u00f3\u0142\u0107"     # zazolc (ogonki)
_SUBJECT_UPPER = "ZA\u017b\u00d3\u0141\u0106"     # ZAZOLC (duze ogonki)


class TestEntityUpsertCasefold(unittest.TestCase):
    """Upsert identity: same entity regardless of capitalisation."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.db = self._tmp.name + "/casefold.sqlite3"

    def upsert(self, subject, predicate, obj):
        return tm.tiered_memory({
            "action": "entity_upsert", "db_path": self.db,
            "subject": subject, "predicate": predicate, "object": obj,
        })

    def rows(self):
        conn = sqlite3.connect(self.db)
        conn.row_factory = sqlite3.Row
        try:
            return [dict(r) for r in conn.execute(
                "SELECT * FROM entity_triples ORDER BY id").fetchall()]
        finally:
            conn.close()

    def test_subject_casing_reconfirms_instead_of_duplicating(self):
        first = self.upsert("Alice", "likes", "tea")
        self.assertEqual(first["data"]["status"], "inserted")
        second = self.upsert("ALICE", "likes", "tea")
        self.assertEqual(second["data"]["status"], "reconfirmed")
        self.assertEqual(second["data"]["evidence_count"], 2)
        self.assertFalse(second["data"]["contradiction_resolved"])
        self.assertEqual(len(self.rows()), 1)

    def test_predicate_casing_reconfirms(self):
        self.upsert("Alice", "likes", "tea")
        again = self.upsert("Alice", "LIKES", "TEA")
        self.assertEqual(again["data"]["status"], "reconfirmed")
        self.assertEqual(again["data"]["evidence_count"], 2)

    def test_case_variant_contradiction_supersedes_old_triple(self):
        self.upsert("Alice", "likes", "tea")
        result = self.upsert("aLiCe", "LIKEs", "herbs")
        data = result["data"]
        self.assertEqual(data["status"], "inserted")
        self.assertTrue(data["contradiction_resolved"])
        self.assertEqual([s["old_object"] for s in data["superseded_triples"]],
                         ["tea"])
        rows = self.rows()
        self.assertEqual(len(rows), 2)
        self.assertEqual([r["is_active"] for r in rows], [0, 1])
        # Response keeps the caller's spelling (documented behaviour).
        self.assertEqual(data["triple"]["subject"], "aLiCe")

    def test_active_query_sees_the_newest_object_only(self):
        self.upsert("Alice", "likes", "tea")
        self.upsert("aLiCe", "likes", "herbs")
        found = tm.tiered_memory({"action": "entity_query",
                                  "db_path": self.db, "subject": "alice"})
        triples = found["data"]["triples"]
        self.assertEqual([t["object"] for t in triples], ["herbs"])
        self.assertTrue(all(t["is_active"] for t in triples))

    def test_evidence_accumulates_across_spellings(self):
        self.upsert("alice", "likes", "tea")
        self.upsert("ALICE", "likes", "TEA")
        third = self.upsert("Alice", "likes", "tea")
        self.assertEqual(third["data"]["status"], "reconfirmed")
        self.assertEqual(third["data"]["evidence_count"], 3)

    def test_other_subjects_are_never_superseded(self):
        self.upsert("Alice", "likes", "tea")
        self.upsert("Bob", "likes", "tea")
        result = self.upsert("ALICE", "likes", "coffee")
        self.assertEqual(result["data"]["contradiction_resolved"], True)
        self.assertEqual([s["old_object"] for s in
                          result["data"]["superseded_triples"]], ["tea"])
        rows = {r["subject"]: r for r in self.rows()}
        self.assertEqual(len(rows), 3)          # three triples total
        self.assertTrue(rows["Bob"]["is_active"])     # Bob untouched
        self.assertEqual(rows["Bob"]["evidence_count"], 1)
        self.assertFalse(rows["Alice"]["is_active"])  # old Alice superseded

    def test_full_unicode_folding_beyond_ascii_nocase(self):
        # The uppercase spelling differs only in non-ASCII letters, which
        # SQLite's ASCII-only NOCASE collation would not fold.
        self.upsert(_SUBJECT_LOWER, "lubi", "herbata")
        again = self.upsert(_SUBJECT_UPPER, "LUBI", "HERBATA")
        self.assertEqual(again["data"]["status"], "reconfirmed")
        self.assertEqual(len(self.rows()), 1)

    def test_exact_case_still_reconfirms_after_fix(self):
        self.upsert("Jarvis", "likes", "Python")
        again = self.upsert("Jarvis", "likes", "Python")
        self.assertEqual(again["data"]["status"], "reconfirmed")
        self.assertEqual(again["data"]["evidence_count"], 2)


if __name__ == "__main__":
    unittest.main()
