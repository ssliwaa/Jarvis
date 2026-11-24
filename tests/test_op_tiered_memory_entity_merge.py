"""Regression + feature tests for tiered_memory's entity_merge action.

entity_merge folds case-variant spellings of one subject into a canonical
row set: a maintenance action for stores written before the casefold
identity fix. Legacy duplicate rows are seeded with direct SQL (bypassing
the fixed upsert) so the merge paths are exercised against realistic
pre-fix data. Everything lives in tmp SQLite files; no real store is
touched.
"""
import sqlite3
import tempfile
import unittest

import operator_modules.op_tiered_memory as tm


class _MergeCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.db = self._tmp.name + "/merge.sqlite3"

    def call(self, **kwargs):
        kwargs.setdefault("db_path", self.db)
        return tm.tiered_memory(kwargs)

    def upsert(self, subject, predicate, obj):
        return self.call(action="entity_upsert", subject=subject,
                         predicate=predicate, object=obj)

    def seed_legacy(self, subject, predicate, obj, evidence=1,
                    is_active=1):
        """Insert a pre-fix row directly, bypassing the upsert gate."""
        conn = sqlite3.connect(self.db)
        with conn:
            conn.execute(
                "INSERT INTO entity_triples "
                "(subject, predicate, object, evidence_count, is_active,"
                " created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (subject, predicate, obj, evidence, is_active,
                 1000.0, 1000.0),
            )
        conn.close()

    def rows(self, only_active=False):
        conn = sqlite3.connect(self.db)
        conn.row_factory = sqlite3.Row
        try:
            sql = ("SELECT * FROM entity_triples"
                   + (" WHERE is_active = 1" if only_active else "")
                   + " ORDER BY id")
            return [dict(r) for r in conn.execute(sql).fetchall()]
        finally:
            conn.close()


class TestEntityMergeBasics(_MergeCase):
    """Merge mechanics: move, reconfirm, conflict, noop."""

    def test_variant_row_moved_in_place_with_id_and_evidence(self):
        self.upsert("Alice", "likes", "tea")  # creates schema + canonical
        self.seed_legacy("ALICE", "manages", "ProjectX", evidence=5)
        alice_id = self.rows()[0]["id"]

        result = self.call(action="entity_merge", subject="Alice")

        data = result["data"]
        self.assertEqual(result["ok"], True)
        self.assertEqual(data["status"], "merged")
        self.assertEqual(data["rows_affected"], 1)
        self.assertEqual(data["moved"],
                         [{"predicate": "manages", "object": "ProjectX"}])
        self.assertEqual(data["reconfirmed"], [])
        self.assertEqual(data["conflicts_superseded"], [])
        self.assertEqual(data["merged_spellings"], ["ALICE"])
        moved_row = [r for r in self.rows() if r["predicate"] == "manages"][0]
        self.assertEqual(moved_row["subject"], "Alice")
        self.assertEqual(moved_row["is_active"], 1)
        self.assertEqual(moved_row["evidence_count"], 5)  # preserved
        self.assertNotEqual(moved_row["id"], alice_id)  # legacy row kept

    def test_equal_object_reconfirms_by_summing_evidence(self):
        self.upsert("Alice", "likes", "tea")
        self.upsert("Alice", "likes", "tea")  # canonical evidence now 2
        self.seed_legacy("ALICE", "LIKES", "TEA", evidence=3)

        result = self.call(action="entity_merge", subject="Alice")

        entry, = result["data"]["reconfirmed"]
        self.assertEqual((entry["predicate"], entry["object"]),
                         ("LIKES", "tea"))
        self.assertEqual(entry["evidence_count"], 5)  # 2 + 3
        active = self.rows(only_active=True)
        self.assertEqual(len(active), 1)
        self.assertEqual(active[0]["subject"], "Alice")
        self.assertEqual(active[0]["evidence_count"], 5)

    def test_conflicting_object_superseded_canonical_wins(self):
        self.upsert("Alice", "likes", "tea")
        self.seed_legacy("aLiCe", "LIKEs", "herbs", evidence=9)

        result = self.call(action="entity_merge", subject="Alice")

        conflict, = result["data"]["conflicts_superseded"]
        self.assertEqual(conflict["predicate"], "LIKEs")
        self.assertEqual(conflict["kept_object"], "tea")
        self.assertEqual(conflict["superseded_object"], "herbs")
        active = self.rows(only_active=True)
        self.assertEqual(len(active), 1)
        self.assertEqual((active[0]["subject"], active[0]["object"]),
                         ("Alice", "tea"))
        self.assertEqual(active[0]["evidence_count"], 1)  # untouched

    def test_mixed_legacy_dataset_full_paths(self):
        self.upsert("Alice", "likes", "tea")          # canonical anchor
        self.upsert("Alice", "owns", "car")          # second anchor
        self.seed_legacy("ALICE", "likes", "TEA", evidence=4)      # reconfirm
        self.seed_legacy("alice", "knows", "Bob", evidence=2)     # move
        self.seed_legacy("AlicE", "owns", "truck", evidence=3)     # conflict

        result = self.call(action="entity_merge", subject="Alice")
        data = result["data"]

        self.assertEqual(data["status"], "merged")
        self.assertEqual(data["rows_affected"], 3)
        self.assertEqual([m["predicate"] for m in data["moved"]], ["knows"])
        self.assertEqual([r["predicate"] for r in data["reconfirmed"]],
                         ["likes"])
        self.assertEqual([r["evidence_count"]
                          for r in data["reconfirmed"]], [5])
        self.assertEqual([c["predicate"]
                          for c in data["conflicts_superseded"]], ["owns"])
        # ASCII sort: uppercase letters order before lowercase ones.
        self.assertEqual(data["merged_spellings"],
                         ["ALICE", "AlicE", "alice"])

        # Post-merge view: one entity, three active facts, spelled once.
        active = self.rows(only_active=True)
        self.assertEqual(len(active), 3)
        self.assertTrue(all(r["subject"] == "Alice" for r in active))
        listing = self.call(action="list_entities")["data"]["entities"]
        self.assertEqual([e["subject"] for e in listing], ["Alice"])
        self.assertEqual([e["relation_count"] for e in listing], [3])
        self.assertEqual([e["total_evidence"]
                          for e in listing], [1 + 5 + 2])

    def test_chain_of_variants_accumulates_evidence(self):
        self.upsert("Alice", "likes", "tea")              # evidence 1
        self.seed_legacy("ALICE", "likes", "TEA", evidence=2)
        self.seed_legacy("alice", "LIKES", "tEa", evidence=3)

        data = self.call(action="entity_merge", subject="Alice")["data"]

        # 1 + 2 + 3 = 6 across the whole chain, not just the last pair.
        self.assertEqual([r["evidence_count"]
                          for r in data["reconfirmed"]], [3, 6])
        active, = self.rows(only_active=True)
        self.assertEqual(active["evidence_count"], 6)

    def test_noop_when_no_variants_and_idempotent_second_run(self):
        self.upsert("Alice", "likes", "tea")
        first = self.call(action="entity_merge", subject="Alice")
        self.assertEqual(first["data"]["status"], "noop")
        self.assertEqual(first["data"]["rows_affected"], 0)
        self.assertEqual(first["data"]["moved"], [])

        self.seed_legacy("ALICE", "likes", "TEA")
        merged = self.call(action="entity_merge", subject="Alice")
        self.assertEqual(merged["data"]["status"], "merged")
        again = self.call(action="entity_merge", subject="Alice")
        self.assertEqual(again["data"]["status"], "noop")

    def test_history_rows_keep_their_legacy_spelling(self):
        self.upsert("Alice", "likes", "tea")
        self.seed_legacy("ALICE", "likes", "TEA", evidence=2, is_active=0)

        result = self.call(action="entity_merge", subject="Alice")

        # Inactive rows are audit trail: untouched subject and activity.
        self.assertEqual(result["data"]["status"], "noop")
        historic = [r for r in self.rows() if r["is_active"] == 0]
        self.assertEqual(len(historic), 1)
        self.assertEqual(historic[0]["subject"], "ALICE")

    def test_merge_without_any_active_rows_moves_everything(self):
        # Canonical spelling itself has no rows: all variants repoint.
        self.upsert("Bob", "unrelated", "fact")  # schema bootstrap
        self.seed_legacy("ALICE", "likes", "tea", evidence=7)

        result = self.call(action="entity_merge", subject="Alice")

        self.assertEqual(result["data"]["status"], "merged")
        moved, = [r for r in self.rows()
                  if r["predicate"] == "likes"]
        self.assertEqual(moved["subject"], "Alice")


class TestEntityMergeContract(_MergeCase):
    """Validation and tool-schema exposure."""

    def test_missing_subject_is_an_envelope_error(self):
        result = self.call(action="entity_merge")
        self.assertFalse(result["ok"])
        self.assertIn("'subject'", result["error"])

    def test_whitespace_subject_is_an_envelope_error(self):
        result = self.call(action="entity_merge", subject="   ")
        self.assertFalse(result["ok"])

    def test_action_in_valid_actions_and_tool_schema(self):
        self.assertIn("entity_merge", tm.VALID_ACTIONS)
        self.assertIn("entity_merge",
                      tm.TOOL["input_schema"]["properties"]["action"]["enum"])
        self.assertIn("subject", tm.KNOWN_ARGUMENTS)

    def test_unknown_arguments_still_rejected(self):
        result = self.call(action="entity_merge", subject="Alice",
                           alias="ALICE")
        self.assertFalse(result["ok"])
        self.assertIn("alias", result["error"])

    def test_merge_works_through_export_envelope(self):
        self.upsert("Alice", "likes", "tea")
        self.seed_legacy("ALICE", "likes", "TEA")
        export = self._tmp.name + "/merge_report.json"
        result = self.call(action="entity_merge", subject="Alice",
                           export_path=export)
        self.assertTrue(result["ok"])
        self.assertEqual(result["data"]["rows_affected"], 1)
        import json
        from pathlib import Path
        payload = json.loads(Path(export).read_text(encoding="utf-8"))
        self.assertEqual(payload["status"], "merged")


if __name__ == "__main__":
    unittest.main()
