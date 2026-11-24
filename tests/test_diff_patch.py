"""Tests for operator_modules/diff_patch.py."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import operator_modules.diff_patch as diff_patch_mod


class TestDiffPatch(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_tool_declaration_contract(self):
        tool = diff_patch_mod.TOOL
        self.assertEqual(tool["name"], "diff_patch")
        self.assertTrue(tool["approval"])
        self.assertTrue(callable(tool["handler"]))
        self.assertLessEqual(len(tool["description"]), 1600)
        schema = tool["input_schema"]
        self.assertEqual(schema["type"], "object")
        self.assertFalse(schema["additionalProperties"])
        self.assertIn("action", schema["required"])

    def test_diff_identical_texts(self):
        res = diff_patch_mod.diff_patch({
            "action": "diff",
            "original": "hello\nworld\n",
            "modified": "hello\nworld\n",
        })
        self.assertTrue(res["ok"])
        self.assertTrue(res["success"])
        self.assertIsNone(res["error"])
        self.assertTrue(res["data"]["identical"])
        self.assertEqual(res["data"]["additions"], 0)
        self.assertEqual(res["data"]["deletions"], 0)
        self.assertEqual(res["data"]["similarity_ratio"], 1.0)
        self.assertEqual(res["result"], res["data"])

    def test_diff_modified_texts(self):
        orig = "line 1\nline 2\nline 3\n"
        mod = "line 1\nline 2 edited\nline 3\nline 4\n"
        res = diff_patch_mod.diff_patch({
            "action": "diff",
            "original": orig,
            "modified": mod,
            "context_lines": 2,
        })
        self.assertTrue(res["ok"])
        self.assertFalse(res["data"]["identical"])
        self.assertIn("-line 2", res["data"]["diff"])
        self.assertIn("+line 2 edited", res["data"]["diff"])
        self.assertIn("+line 4", res["data"]["diff"])
        self.assertGreater(res["data"]["additions"], 0)
        self.assertGreater(res["data"]["deletions"], 0)

    def test_diff_file_target(self):
        test_file = self.root / "orig.txt"
        test_file.write_text("alpha\nbeta\ngamma\n", encoding="utf-8")

        res = diff_patch_mod.diff_patch({
            "action": "diff",
            "target_file": str(test_file),
            "modified": "alpha\nbeta updated\ngamma\n",
        })
        self.assertTrue(res["ok"])
        self.assertIn("+beta updated", res["data"]["diff"])

    def test_diff_payload_exceeds_limit(self):
        oversized = "a" * (512 * 1024 + 10)
        res = diff_patch_mod.diff_patch({
            "action": "diff",
            "original": oversized,
            "modified": "test",
        })
        self.assertFalse(res["ok"])
        self.assertFalse(res["success"])
        self.assertIn("exceeds maximum limit", res["error"])

    def test_compare_ratio(self):
        res = diff_patch_mod.diff_patch({
            "action": "compare_ratio",
            "original": "The quick brown fox",
            "modified": "The quick brown dog",
        })
        self.assertTrue(res["ok"])
        self.assertFalse(res["data"]["identical"])
        self.assertGreater(res["data"]["ratio"], 0.7)
        self.assertLess(res["data"]["ratio"], 1.0)

    def test_patch_dry_run_text(self):
        orig = "first\nsecond\nthird\n"
        # Generate patch
        diff_res = diff_patch_mod.diff_patch({
            "action": "diff",
            "original": orig,
            "modified": "first\nsecond modified\nthird\n",
        })
        patch_text = diff_res["data"]["diff"]

        # Apply patch dry run
        res = diff_patch_mod.diff_patch({
            "action": "patch",
            "original": orig,
            "patch_text": patch_text,
            "in_place": False,
        })
        self.assertTrue(res["ok"])
        self.assertEqual(res["data"]["hunks_applied"], 1)
        self.assertEqual(res["data"]["hunks_failed"], 0)
        self.assertEqual(res["data"]["patched_text"], "first\nsecond modified\nthird\n")

    def test_patch_in_place_file(self):
        f = self.root / "code.py"
        f.write_text("def foo():\n    return 1\n", encoding="utf-8")

        diff_res = diff_patch_mod.diff_patch({
            "action": "diff",
            "original": "def foo():\n    return 1\n",
            "modified": "def foo():\n    return 2\n",
        })
        patch_text = diff_res["data"]["diff"]

        res = diff_patch_mod.diff_patch({
            "action": "patch",
            "target_file": str(f),
            "patch_text": patch_text,
            "in_place": True,
        })
        self.assertTrue(res["ok"])
        self.assertTrue(res["data"]["in_place"])
        self.assertEqual(f.read_text(encoding="utf-8"), "def foo():\n    return 2\n")

    def test_patch_in_place_without_target_file_fails(self):
        res = diff_patch_mod.diff_patch({
            "action": "patch",
            "original": "some text",
            "patch_text": "dummy patch",
            "in_place": True,
        })
        self.assertFalse(res["ok"])
        self.assertIn("target_file", res["error"])

    def test_patch_traversal_blocked(self):
        res = diff_patch_mod.diff_patch({
            "action": "patch",
            "target_file": "../../etc/shadow",
            "patch_text": "dummy",
            "in_place": True,
        })
        self.assertFalse(res["ok"])
        self.assertIn("traversal", res["error"].lower())

    def test_patch_sensitive_path_blocked(self):
        sensitive = Path.home() / ".ssh" / "id_rsa"
        res = diff_patch_mod.diff_patch({
            "action": "patch",
            "target_file": str(sensitive),
            "patch_text": "dummy",
            "in_place": True,
        })
        self.assertFalse(res["ok"])

    def test_merge3_clean(self):
        base = "line 1\nline 2\nline 3\nline 4\n"
        mine = "line 1 modified\nline 2\nline 3\nline 4\n"
        theirs = "line 1\nline 2\nline 3\nline 4 modified\n"

        res = diff_patch_mod.diff_patch({
            "action": "merge3",
            "base": base,
            "original": mine,
            "modified": theirs,
        })
        self.assertTrue(res["ok"])
        self.assertTrue(res["data"]["clean"])
        self.assertEqual(res["data"]["conflicts"], 0)
        expected = "line 1 modified\nline 2\nline 3\nline 4 modified\n"
        self.assertEqual(res["data"]["merged_text"], expected)

    def test_merge3_conflict(self):
        base = "line 1\nline 2\n"
        mine = "line 1 - mine\nline 2\n"
        theirs = "line 1 - theirs\nline 2\n"

        res = diff_patch_mod.diff_patch({
            "action": "merge3",
            "base": base,
            "original": mine,
            "modified": theirs,
        })
        self.assertTrue(res["ok"])
        self.assertFalse(res["data"]["clean"])
        self.assertGreater(res["data"]["conflicts"], 0)
        self.assertIn("<<<<<<< ORIGINAL", res["data"]["merged_text"])
        self.assertIn("line 1 - mine", res["data"]["merged_text"])
        self.assertIn("=======", res["data"]["merged_text"])
        self.assertIn("line 1 - theirs", res["data"]["merged_text"])
        self.assertIn(">>>>>>> MODIFIED", res["data"]["merged_text"])

    def test_merge3_embedded_changes_are_conflicts_not_dropped(self):
        # One side rewrites a range while the other edits inside that range:
        # the index jump used to skip the embedded change entirely (a silent
        # data loss with conflicts=0). It must surface as a conflict that
        # contains both sides of the overlapping region.
        base = "a\nb\nc\nd\ne\n"
        mine = base.replace("c", "C")                       # theirs-range embedded edit
        theirs = "a\nb2\nb3\nd\ne\n"                        # rewrites lines b..c

        res = diff_patch_mod.diff_patch({
            "action": "merge3",
            "base": base,
            "original": mine,
            "modified": theirs,
        })
        self.assertTrue(res["ok"])
        self.assertFalse(res["data"]["clean"])
        self.assertEqual(res["data"]["conflicts"], 1)
        self.assertIn("C", res["data"]["merged_text"])             # mine survives
        self.assertIn("b2\nb3", res["data"]["merged_text"])       # theirs survives
        self.assertIn("<<<<<<< ORIGINAL", res["data"]["merged_text"])
        self.assertIn(">>>>>>> MODIFIED", res["data"]["merged_text"])

    def test_merge3_identical_leaders_with_embedded_change_conflict(self):
        base = "a\nb\nc\nd\ne\n"
        mine = "a\nB\nC\nd\ne\n"                                # leader + embedded own edit
        theirs = "a\nB\nc\nd\ne\n"                              # identical leader only
        res = diff_patch_mod.diff_patch({
            "action": "merge3", "base": base,
            "original": mine, "modified": theirs,
        })
        self.assertTrue(res["ok"])
        self.assertFalse(res["data"]["clean"])
        self.assertGreaterEqual(res["data"]["conflicts"], 1)

    def test_pure_insertion_hunk_lands_after_line_n(self):
        # A context-free "-N,0" hunk inserts AFTER old line N. The generic
        # "- 1" placed it one line too early — and in_place wrote the
        # misplaced content into the file while reporting success_rate 1.0.
        orig = "first\nsecond\nthird\n"
        res = diff_patch_mod.diff_patch({
            "action": "patch",
            "original": orig,
            "patch_text": "@@ -1,0 +2 @@\n+inserted\n",
            "in_place": False,
        })
        self.assertTrue(res["ok"], res)
        self.assertEqual(res["data"]["hunks_applied"], 1)
        self.assertEqual(res["data"]["patched_text"], "first\ninserted\nsecond\nthird\n")

        res_top = diff_patch_mod.diff_patch({
            "action": "patch",
            "original": orig,
            "patch_text": "@@ -0,0 +1 @@\n+top\n",
            "in_place": False,
        })
        self.assertTrue(res_top["ok"], res_top)
        self.assertEqual(res_top["data"]["patched_text"], "top\nfirst\nsecond\nthird\n")

    def test_pure_insertion_hunk_in_place_writes_the_right_lines(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "code.py"
            target.write_text("def foo():\n    return 1\n", encoding="utf-8")
            res = diff_patch_mod.diff_patch({
                "action": "patch",
                "target_file": str(target),
                "patch_text": "@@ -1,0 +2 @@\n+# new line\n",
                "in_place": True,
            })
            self.assertTrue(res["ok"], res)
            self.assertEqual(
                target.read_text(encoding="utf-8"),
                "def foo():\n# new line\n    return 1\n",
            )

    def test_unsupported_action(self):
        res = diff_patch_mod.diff_patch({"action": "invalid_op"})
        self.assertFalse(res["ok"])
        self.assertIn("Unsupported action", res["error"])

    def test_missing_action(self):
        res = diff_patch_mod.diff_patch({})
        self.assertFalse(res["ok"])
        self.assertIn("Missing required 'action'", res["error"])
