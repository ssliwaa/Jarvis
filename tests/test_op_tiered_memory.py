"""Automated test suite for operator_modules/op_tiered_memory.py.

Tests the dispatch contract, db_path guardrails (perimeter, sensitive
blocklist, shared default /tmp database - read-only checks),
L1 Core Memory primitives (seeded defaults, read/write/append/replace
with the 2000-char capacity ceiling), L3 Archival Memory (insert with
category, FTS5 search with category filter and required query), and
the L4 entity-relation graph (upsert with evidence counting,
case-insensitive matching across subject/predicate identity and
object (case folding), supersede/contradiction resolution,
active vs include_superseded queries, list_entities aggregation), plus
export_path snapshots. Every test uses its own TemporaryDirectory
SQLite database; the shared-default test performs read-only calls.
"""

from __future__ import annotations

import json
import tempfile
import unittest

import operator_modules.op_tiered_memory as tm


class TestDispatch(unittest.TestCase):
    """Handler contract: envelope and argument validation."""

    def test_rejects_non_dict_arguments(self):
        res = tm.tiered_memory("nope")
        self.assertFalse(res["ok"])
        self.assertIn("JSON dictionary", res["error"])

    def test_rejects_disallowed_extra_keys(self):
        with tempfile.TemporaryDirectory() as td:
            res = tm.tiered_memory({"action": "core_read",
                                    "db_path": td + "/m.sqlite3",
                                    "rogue": 1})
        self.assertFalse(res["ok"])
        self.assertIn("Disallowed additional arguments", res["error"])
        self.assertIn("rogue", res["error"])

    def test_invalid_action(self):
        with tempfile.TemporaryDirectory() as td:
            res = tm.tiered_memory({"action": "teleport",
                                    "db_path": td + "/m.sqlite3"})
        self.assertFalse(res["ok"])
        self.assertIn("Invalid or missing action 'teleport'", res["error"])
        self.assertIn("core_read", res["error"])

    def test_success_envelope_shape(self):
        with tempfile.TemporaryDirectory() as td:
            res = tm.tiered_memory({"action": "core_read",
                                    "db_path": td + "/m.sqlite3"})
        self.assertEqual(set(res), {"ok", "success", "data", "result",
                                    "error"})
        self.assertTrue(res["ok"])
        self.assertEqual(res["data"], res["result"])
        self.assertIsNone(res["error"])


class TestDbPathGuardrails(unittest.TestCase):
    """db_path validation: perimeter, sensitive blocklist, default."""

    def test_outside_allowed_roots_rejected(self):
        res = tm.tiered_memory({"action": "core_read",
                                "db_path": "/proc/forbidden/m.sqlite3"})
        self.assertFalse(res["ok"])
        self.assertIn("PathSecurityError", res["error"])
        self.assertIn("outside allowed roots", res["error"])

    def test_sensitive_path_rejected(self):
        res = tm.tiered_memory({"action": "core_read",
                                "db_path": "/tmp/tm_probe/.ssh/m.sqlite3"})
        self.assertFalse(res["ok"])
        self.assertIn("SensitivePathError", res["error"])

    def test_default_db_seeds_core_blocks_readonly(self):
        # Default db is the shared /tmp/jarvis_tiered_memory.sqlite3;
        # verify seeded defaults exist (read-only, no writes performed).
        res = tm.tiered_memory({"action": "core_read"})
        self.assertTrue(res["ok"])
        self.assertGreaterEqual(res["data"]["total_blocks"], 3)
        self.assertIn("human_profile", res["data"]["blocks"])


class TestCoreMemory(unittest.TestCase):
    """L1 core_read/core_write/core_append/core_replace primitives."""

    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.db = self._td.name + "/m.sqlite3"

    def tearDown(self):
        self._td.cleanup()

    def test_defaults_seeded_on_fresh_db(self):
        res = tm.tiered_memory({"action": "core_read", "db_path": self.db})
        data = res["data"]
        self.assertEqual(data["total_blocks"], 3)
        self.assertEqual(sorted(data["blocks"]),
                         ["human_profile", "persona_spec", "scratchpad"])
        for info in data["blocks"].values():
            self.assertEqual(info["max_chars"], 2000)
            self.assertGreater(info["char_count"], 0)
        self.assertGreater(data["total_chars"], 0)

    def test_read_single_existing_block(self):
        res = tm.tiered_memory({"action": "core_read",
                                "db_path": self.db,
                                "block_name": "human_profile"})
        data = res["data"]
        self.assertTrue(data["exists"])
        self.assertIn("Linux", data["content"])
        self.assertEqual(data["char_count"], len(data["content"]))

    def test_read_missing_block(self):
        res = tm.tiered_memory({"action": "core_read",
                                "db_path": self.db,
                                "block_name": "no_such_block"})
        data = res["data"]
        self.assertTrue(res["ok"])
        self.assertFalse(data["exists"])
        self.assertEqual(data["content"], "")
        self.assertEqual(data["char_count"], 0)
        self.assertIsNone(data["updated_at"])

    def test_write_creates_block_and_persists(self):
        res = tm.tiered_memory({"action": "core_write",
                                "db_path": self.db,
                                "block_name": "project_notes",
                                "content": "Iteration BM in progress"})
        data = res["data"]
        self.assertEqual(data["status"], "written")
        self.assertEqual(data["char_count"], 24)
        read = tm.tiered_memory({"action": "core_read",
                                 "db_path": self.db,
                                 "block_name": "project_notes"})
        self.assertTrue(read["data"]["exists"])
        self.assertEqual(read["data"]["content"], "Iteration BM in progress")

    def test_write_over_capacity_rejected(self):
        res = tm.tiered_memory({"action": "core_write",
                                "db_path": self.db,
                                "block_name": "big",
                                "content": "x" * 2001})
        self.assertFalse(res["ok"])
        self.assertIn("exceeds capacity limit", res["error"])
        self.assertIn("2001", res["error"])

    def test_append_joins_with_newline(self):
        tm.tiered_memory({"action": "core_write", "db_path": self.db,
                         "block_name": "log", "content": "first"})
        res = tm.tiered_memory({"action": "core_append",
                                "db_path": self.db,
                                "block_name": "log",
                                "content": "second"})
        data = res["data"]
        self.assertEqual(data["status"], "appended")
        self.assertEqual(data["content"], "first\nsecond")
        self.assertEqual(data["char_count"], len("first\nsecond"))

    def test_append_over_capacity_rejected(self):
        tm.tiered_memory({"action": "core_write", "db_path": self.db,
                         "block_name": "log", "content": "x" * 1990})
        res = tm.tiered_memory({"action": "core_append",
                                "db_path": self.db,
                                "block_name": "log",
                                "content": "y" * 20})
        self.assertFalse(res["ok"])
        self.assertIn("would exceed capacity", res["error"])

    def test_replace_first_occurrence_only(self):
        tm.tiered_memory({"action": "core_write", "db_path": self.db,
                         "block_name": "spec",
                         "content": "alpha beta alpha"})
        res = tm.tiered_memory({"action": "core_replace",
                                "db_path": self.db,
                                "block_name": "spec",
                                "old_content": "alpha",
                                "new_content": "gamma"})
        data = res["data"]
        self.assertEqual(data["status"], "replaced")
        self.assertEqual(data["content"], "gamma beta alpha")

    def test_replace_errors(self):
        # Missing block
        res = tm.tiered_memory({"action": "core_replace",
                                "db_path": self.db,
                                "block_name": "ghost",
                                "old_content": "a", "new_content": "b"})
        self.assertFalse(res["ok"])
        self.assertIn("not found", res["error"])
        # Substring not present
        tm.tiered_memory({"action": "core_write", "db_path": self.db,
                         "block_name": "spec", "content": "hello"})
        res2 = tm.tiered_memory({"action": "core_replace",
                                 "db_path": self.db,
                                 "block_name": "spec",
                                 "old_content": "zzz",
                                 "new_content": "b"})
        self.assertFalse(res2["ok"])
        self.assertIn("not found in core block", res2["error"])
        # Missing parameters
        res3 = tm.tiered_memory({"action": "core_replace",
                                 "db_path": self.db,
                                 "block_name": "spec",
                                 "old_content": "hello"})
        self.assertFalse(res3["ok"])
        self.assertIn("'old_content' and 'new_content' are required",
                      res3["error"])


class TestArchivalMemory(unittest.TestCase):
    """L3 archival_insert/archival_search with FTS5."""

    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.db = self._td.name + "/m.sqlite3"
        for content, category in [
            ("Quantum flux capacitor theory explained", "physics"),
            ("Completely unrelated cooking recipe content", "cooking"),
        ]:
            tm.tiered_memory({"action": "archival_insert",
                              "db_path": self.db,
                              "content": content,
                              "category": category})

    def tearDown(self):
        self._td.cleanup()

    def test_insert_defaults_category(self):
        res = tm.tiered_memory({"action": "archival_insert",
                                "db_path": self.db,
                                "content": "untagged fact"})
        data = res["data"]
        self.assertEqual(data["status"], "inserted")
        self.assertEqual(data["category"], "general")
        self.assertEqual(data["content"], "untagged fact")

    def test_search_matches_by_fts(self):
        res = tm.tiered_memory({"action": "archival_search",
                                "db_path": self.db,
                                "query": "flux capacitor"})
        data = res["data"]
        self.assertTrue(res["ok"])
        self.assertEqual(data["match_count"], 1)
        self.assertEqual(data["results"][0]["category"], "physics")
        self.assertEqual(data["results"][0]["content"],
                         "Quantum flux capacitor theory explained")

    def test_search_with_category_filter_and_missing_query(self):
        res = tm.tiered_memory({"action": "archival_search",
                                "db_path": self.db,
                                "query": "recipe", "category": "cooking"})
        self.assertEqual(res["data"]["match_count"], 1)
        res2 = tm.tiered_memory({"action": "archival_search",
                                 "db_path": self.db,
                                 "query": "recipe",
                                 "category": "physics"})
        self.assertEqual(res2["data"]["match_count"], 0)
        res3 = tm.tiered_memory({"action": "archival_search",
                                 "db_path": self.db})
        self.assertFalse(res3["ok"])
        self.assertIn("'query' is required", res3["error"])


class TestEntityGraph(unittest.TestCase):
    """L4 entity_upsert/entity_query/list_entities (Mem0 pattern)."""

    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.db = self._td.name + "/m.sqlite3"

    def tearDown(self):
        self._td.cleanup()

    def test_upsert_requires_all_three_params(self):
        res = tm.tiered_memory({"action": "entity_upsert",
                                "db_path": self.db,
                                "subject": "Jarvis", "predicate": "likes"})
        self.assertFalse(res["ok"])
        self.assertIn("'subject', 'predicate', and 'object' are required",
                      res["error"])

    def test_insert_and_reconfirm_evidence(self):
        tm.tiered_memory({"action": "entity_upsert", "db_path": self.db,
                          "subject": "Jarvis", "predicate": "likes",
                          "object": "Python"})
        res = tm.tiered_memory({"action": "entity_upsert",
                                "db_path": self.db,
                                "subject": "Jarvis", "predicate": "likes",
                                "object": "Python"})
        data = res["data"]
        self.assertEqual(data["status"], "reconfirmed")
        self.assertEqual(data["evidence_count"], 2)
        self.assertFalse(data["contradiction_resolved"])

    def test_object_match_is_case_insensitive_for_reconfirm(self):
        tm.tiered_memory({"action": "entity_upsert", "db_path": self.db,
                          "subject": "Jarvis", "predicate": "likes",
                          "object": "Python"})
        res = tm.tiered_memory({"action": "entity_upsert",
                                "db_path": self.db,
                                "subject": "Jarvis", "predicate": "likes",
                                "object": "PYTHON"})
        data = res["data"]
        self.assertEqual(data["status"], "reconfirmed")
        self.assertEqual(data["evidence_count"], 2)

    def test_contradiction_supersedes_active_triple(self):
        tm.tiered_memory({"action": "entity_upsert", "db_path": self.db,
                          "subject": "Jarvis", "predicate": "likes",
                          "object": "Python"})
        res = tm.tiered_memory({"action": "entity_upsert",
                                "db_path": self.db,
                                "subject": "Jarvis", "predicate": "likes",
                                "object": "Rust"})
        data = res["data"]
        self.assertEqual(data["status"], "inserted")
        self.assertTrue(data["contradiction_resolved"])
        self.assertEqual([s["old_object"] for s in data["superseded_triples"]],
                         ["Python"])
        # Active query sees only the newest triple
        q = tm.tiered_memory({"action": "entity_query",
                              "db_path": self.db, "subject": "Jarvis"})
        self.assertEqual([t["object"] for t in q["data"]["triples"]],
                         ["Rust"])
        self.assertTrue(all(t["is_active"] for t in q["data"]["triples"]))
        # include_superseded reveals both
        q2 = tm.tiered_memory({"action": "entity_query",
                               "db_path": self.db, "subject": "Jarvis",
                               "include_superseded": True})
        self.assertEqual(len(q2["data"]["triples"]), 2)
        self.assertTrue(any(not t["is_active"]
                            for t in q2["data"]["triples"]))

    def test_subject_lookup_folds_case_into_one_identity(self):
        # Since the casefold hardening (see
        # tests/test_op_tiered_memory_casefold.py) the (subject,
        # predicate) lookup folds capitalisation the same way the object
        # comparison always did: "Jarvis" and "jarvis" are one entity, so
        # a lone case variant reconfirms instead of minting a duplicate.
        tm.tiered_memory({"action": "entity_upsert", "db_path": self.db,
                          "subject": "Jarvis", "predicate": "likes",
                          "object": "Python"})
        res = tm.tiered_memory({"action": "entity_upsert",
                                "db_path": self.db,
                                "subject": "jarvis", "predicate": "likes",
                                "object": "Python"})
        self.assertEqual(res["data"]["status"], "reconfirmed")
        self.assertEqual(res["data"]["evidence_count"], 2)
        listing = tm.tiered_memory({"action": "list_entities",
                                    "db_path": self.db})
        subjects = {e["subject"] for e in listing["data"]["entities"]}
        self.assertEqual(subjects, {"Jarvis"})

    def test_list_entities_aggregates_evidence(self):
        for _ in range(3):
            tm.tiered_memory({"action": "entity_upsert", "db_path": self.db,
                              "subject": "A", "predicate": "knows",
                              "object": "B"})
        tm.tiered_memory({"action": "entity_upsert", "db_path": self.db,
                          "subject": "A", "predicate": "owes",
                          "object": "C"})
        res = tm.tiered_memory({"action": "list_entities",
                                "db_path": self.db})
        entities = res["data"]["entities"]
        self.assertEqual(res["data"]["entity_count"], 1)
        ent = entities[0]
        self.assertEqual(ent["subject"], "A")
        self.assertEqual(ent["relation_count"], 2)
        self.assertEqual(ent["total_evidence"], 4)

    def test_entity_query_free_text(self):
        tm.tiered_memory({"action": "entity_upsert", "db_path": self.db,
                          "subject": "Alice", "predicate": "manages",
                          "object": "ProjectAlpha"})
        res = tm.tiered_memory({"action": "entity_query",
                                "db_path": self.db,
                                "query": "ProjectAlpha"})
        self.assertEqual(res["data"]["match_count"], 1)
        self.assertEqual(res["data"]["triples"][0]["subject"], "Alice")


class TestExportPath(unittest.TestCase):
    """export_path: snapshot write within ALLOWED_ROOTS."""

    def test_export_writes_snapshot(self):
        with tempfile.TemporaryDirectory() as td:
            res = tm.tiered_memory({"action": "core_read",
                                    "block_name": "human_profile",
                                    "db_path": td + "/m.sqlite3",
                                    "export_path": td + "/snap.json"})
            self.assertTrue(res["ok"])
            self.assertEqual(res["data"]["exported_to"], td + "/snap.json")
            loaded = json.loads(open(td + "/snap.json",
                                     encoding="utf-8").read())
            self.assertEqual(loaded["block_name"], "human_profile")
            self.assertTrue(loaded["exists"])

    def test_export_outside_roots_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            res = tm.tiered_memory({"action": "core_read",
                                    "db_path": td + "/m.sqlite3",
                                    "export_path": "/proc/no/no.json"})
        self.assertFalse(res["ok"])
        self.assertIn("PathSecurityError", res["error"])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
