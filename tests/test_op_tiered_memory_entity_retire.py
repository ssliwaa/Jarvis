"""Feature tests for tiered_memory's entity_retire action.

entity_retire is the first-class forgetting operation: a wrong or stale
fact can be retired without inventing a replacement (the upsert supersede
path always needs one). Soft delete only - is_active flips to 0, evidence
and history stay, nothing is ever removed. Offline tmp SQLite per test.
"""
import sqlite3
import tempfile
import unittest

import operator_modules.op_tiered_memory as tm


class _RetireCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.db = self._tmp.name + "/retire.sqlite3"

    def call(self, **kwargs):
        kwargs.setdefault("db_path", self.db)
        return tm.tiered_memory(kwargs)

    def upsert(self, subject, predicate, obj):
        return self.call(action="entity_upsert", subject=subject,
                         predicate=predicate, object=obj)

    def retire(self, **kwargs):
        kwargs["action"] = "entity_retire"
        return self.call(**kwargs)

    def seed(self, subject, predicate, obj, evidence=1, is_active=1):
        """Direct INSERT for states the (fixed) upsert cannot produce."""
        conn = sqlite3.connect(self.db)
        with conn:
            conn.execute(
                "INSERT INTO entity_triples "
                "(subject, predicate, object, evidence_count, is_active,"
                " created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (subject, predicate, obj, evidence, is_active, 1000.0, 1000.0),
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


class TestRetireMechanics(_RetireCase):
    """Deactivation paths: single, fold-variant, disambiguated, multi."""

    def test_retire_single_fact_casefold_identity(self):
        self.upsert("Alice", "likes", "tea")  # evidence stays for audit
        self.upsert("Alice", "owns", "car")

        result = self.retire(subject="ALICE", predicate="LIKES")

        data = result["data"]
        self.assertTrue(result["ok"])
        self.assertEqual(data["status"], "retired")
        self.assertEqual(data["retired_count"], 1)
        entry, = data["retired"]
        self.assertEqual((entry["subject"], entry["predicate"],
                          entry["object"]), ("Alice", "likes", "tea"))
        self.assertTrue(data["soft_delete"])

        active = self.rows(only_active=True)
        self.assertEqual([r["predicate"] for r in active], ["owns"])
        retired_row = [r for r in self.rows() if r["predicate"] == "likes"]
        self.assertEqual(retired_row[0]["is_active"], 0)
        self.assertEqual(retired_row[0]["evidence_count"], 1)  # audit kept

    def test_retire_with_object_filter_disambiguates(self):
        self.upsert("Alice", "likes", "tea")
        # two actives for one predicate can only come from pre-fix data:
        self.seed("Alice", "likes", "coffee", evidence=4)

        result = self.retire(subject="Alice", predicate="likes",
                             object="COFFEE")

        data = result["data"]
        self.assertEqual(data["retired_count"], 1)
        self.assertEqual(data["retired"][0]["object"], "coffee")
        active = self.rows(only_active=True)
        self.assertEqual([r["object"] for r in active], ["tea"])

    def test_retire_without_object_takes_all_actives_of_predicate(self):
        self.upsert("Alice", "likes", "tea")
        self.seed("Alice", "likes", "coffee", evidence=4)

        result = self.retire(subject="alice", predicate="likes",
                             reason="stale preference data")

        data = result["data"]
        self.assertEqual(data["retired_count"], 2)
        self.assertEqual(data["reason"], "stale preference data")
        self.assertEqual(sorted(r["object"] for r in data["retired"]),
                         ["coffee", "tea"])
        self.assertEqual(self.rows(only_active=True), [])
        self.assertEqual(len(self.rows()), 2)  # soft delete: kept

    def test_noop_when_fact_absent_or_already_retired(self):
        self.upsert("Alice", "likes", "tea")
        first = self.retire(subject="Alice", predicate="likes")
        self.assertEqual(first["data"]["status"], "retired")
        again = self.retire(subject="Alice", predicate="likes")
        self.assertEqual(again["data"]["status"], "noop")
        self.assertEqual(again["data"]["retired_count"], 0)
        self.assertEqual(again["data"]["recreate_hint"], "")

        missing = self.retire(subject="Bob", predicate="knows")
        self.assertEqual(missing["data"]["status"], "noop")

    def test_retired_fact_visible_only_via_include_superseded(self):
        self.upsert("Alice", "likes", "tea")
        self.retire(subject="Alice", predicate="likes")

        active_view = self.call(action="entity_query", subject="Alice")
        self.assertEqual(active_view["data"]["match_count"], 0)
        historic_view = self.call(action="entity_query", subject="Alice",
                                  include_superseded=True)
        self.assertEqual(historic_view["data"]["match_count"], 1)
        triple, = historic_view["data"]["triples"]
        self.assertFalse(triple["is_active"])
        self.assertEqual(triple["object"], "tea")

    def test_retire_reshapes_list_entities(self):
        self.upsert("Alice", "likes", "tea")
        self.upsert("Alice", "owns", "car")
        self.retire(subject="Alice", predicate="likes")

        listing = self.call(action="list_entities")["data"]["entities"]
        entity, = listing
        self.assertEqual(entity["subject"], "Alice")
        self.assertEqual(entity["relation_count"], 1)
        self.assertEqual(entity["total_evidence"], 1)

    def test_upsert_reinstates_fact_with_fresh_evidence(self):
        self.upsert("Alice", "likes", "tea")
        self.upsert("Alice", "likes", "tea")
        self.retire(subject="Alice", predicate="likes")

        reinstated = self.upsert("Alice", "likes", "tea")["data"]

        # upsert folded the two confirmations into one superseded row,
        # so the audit trail holds exactly 1 retired + 1 reinstated row.
        self.assertEqual(reinstated["status"], "inserted")
        self.assertEqual(reinstated["evidence_count"], 1)
        active = self.rows(only_active=True)
        self.assertEqual(len(active), 1)
        self.assertEqual(len(self.rows()), 2)

    def test_retire_then_merge_reports_clean_identity(self):
        self.upsert("Alice", "likes", "tea")
        self.retire(subject="Alice", predicate="likes")
        merge = self.call(action="entity_merge", subject="Alice")
        self.assertEqual(merge["data"]["status"], "noop")


class TestRetireContract(_RetireCase):
    """Validation and schema exposure."""

    def test_missing_required_params_are_envelope_errors(self):
        no_subject = self.retire(predicate="likes")
        self.assertFalse(no_subject["ok"])
        self.assertIn("'subject'", no_subject["error"])
        no_pred = self.retire(subject="Alice")
        self.assertFalse(no_pred["ok"])
        self.assertIn("'predicate'", no_pred["error"])
        blank = self.retire(subject="  ", predicate="x")
        self.assertFalse(blank["ok"])

    def test_extra_arguments_rejected_and_reason_accepted(self):
        extra = self.retire(subject="Alice", predicate="likes", force="yes")
        self.assertFalse(extra["ok"])
        self.assertIn("force", extra["error"])
        result = self.retire(subject="Alice", predicate="likes",
                             reason="cleanup notes")
        self.assertTrue(result["ok"])
        self.assertEqual(result["data"]["reason"], "cleanup notes")

    def test_action_in_valid_actions_and_tool_schema(self):
        self.assertIn("entity_retire", tm.VALID_ACTIONS)
        enum = tm.TOOL["input_schema"]["properties"]["action"]["enum"]
        self.assertIn("entity_retire", enum)
        self.assertIn("reason", tm.KNOWN_ARGUMENTS)
        reason_prop = tm.TOOL["input_schema"]["properties"].get("reason")
        self.assertIsNotNone(reason_prop)
        self.assertIn("deactivated", reason_prop["description"])

    def test_retire_export_envelope_works(self):
        import json
        from pathlib import Path
        self.upsert("Alice", "likes", "tea")
        export = self._tmp.name + "/retire_report.json"
        result = self.retire(subject="Alice", predicate="likes",
                             export_path=export)
        self.assertTrue(result["ok"])
        self.assertEqual(result["data"]["retired_count"], 1)
        payload = json.loads(Path(export).read_text(encoding="utf-8"))
        self.assertEqual(payload["status"], "retired")


if __name__ == "__main__":
    unittest.main()
