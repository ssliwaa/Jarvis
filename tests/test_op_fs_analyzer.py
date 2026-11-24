"""Automated unit test suite for operator_modules/op_fs_analyzer.py.

Verifies:
1. Tool registration contract, input_schema (additionalProperties: False), and approval=False.
2. Standard 5-key return envelope (ok, success, data, result, error).
3. Tree summary on directory hierarchies and single files with depth bounding.
4. Disk usage profiling (partition metrics and top-level children breakdown).
5. Large file discovery with size threshold, glob patterns, and sorting.
6. Broken symlink detection (dangling and circular symlink loops).
7. Structural hygiene audit (empty dirs, zero-byte files, temp artifacts, stale locks, permission anomalies).
8. Path confinement to ALLOWED_ROOTS, sensitive path blocking, and graceful permission error handling.
"""

from __future__ import annotations

import os
SANDBOXED = os.environ.get("JARVIS_VERIFY_SANDBOX") == "1"
import tempfile
import time
import unittest
from pathlib import Path

import operator_modules.op_fs_analyzer as op_fs_analyzer


class TestOpFSAnalyzer(unittest.TestCase):
    def setUp(self):
        # Create an isolated temporary test sandbox in /tmp (guaranteed within ALLOWED_ROOTS)
        self.temp_dir = tempfile.TemporaryDirectory(dir="/tmp")
        self.root = Path(self.temp_dir.name).resolve()

        # Build directory tree for tests
        self.test_dir = self.root / "sandbox"
        self.test_dir.mkdir(parents=True, exist_ok=True)

        # Level 1 files
        (self.test_dir / "file1.txt").write_text("Hello World", encoding="utf-8")  # 11 bytes
        (self.test_dir / "script.py").write_text("print(123)\n", encoding="utf-8")  # 11 bytes

        # Level 1 subdir with Level 2 files
        self.sub_dir = self.test_dir / "subdir"
        self.sub_dir.mkdir(parents=True, exist_ok=True)
        (self.sub_dir / "nested.txt").write_text("Nested content here", encoding="utf-8")  # 19 bytes

        # Level 2 deep subdir (Level 3 files)
        self.deep_dir = self.sub_dir / "deep"
        self.deep_dir.mkdir(parents=True, exist_ok=True)
        (self.deep_dir / "deep.bin").write_bytes(b"\x00" * 100)  # 100 bytes

    def tearDown(self):
        # Restore permissions if any tests made subdirs unreadable
        for root, dirs, _ in os.walk(str(self.root)):
            for d in dirs:
                try:
                    os.chmod(os.path.join(root, d), 0o755)
                except OSError:
                    pass
        self.temp_dir.cleanup()

    def _assert_envelope(self, res: dict, expected_ok: bool):
        """Assert standard 5-key Jarvis operator envelope structure."""
        self.assertIsInstance(res, dict)
        self.assertIn("ok", res)
        self.assertIn("success", res)
        self.assertIn("data", res)
        self.assertIn("result", res)
        self.assertIn("error", res)
        self.assertEqual(res["ok"], expected_ok)
        self.assertEqual(res["success"], expected_ok)
        if expected_ok:
            self.assertIsNone(res["error"])
            self.assertEqual(res["data"], res["result"])
        else:
            self.assertIsNone(res["data"])
            self.assertIsNone(res["result"])
            self.assertIsInstance(res["error"], str)
            self.assertGreater(len(res["error"]), 0)

    # =========================================================================
    # Contract & Schema Conformance Tests
    # =========================================================================

    def test_01_tool_declaration_contract(self):
        tool = op_fs_analyzer.TOOL
        self.assertEqual(tool["name"], "fs_analyzer")
        self.assertFalse(tool["approval"], "fs_analyzer is read-only and must have approval=False")
        self.assertTrue(callable(tool["handler"]))
        self.assertEqual(tool["input_schema"]["type"], "object")
        self.assertFalse(tool["input_schema"]["additionalProperties"])
        self.assertIn("action", tool["input_schema"]["required"])

    def test_02_approval_is_false(self):
        self.assertIs(op_fs_analyzer.TOOL.get("approval"), False)

    def test_03_schema_additional_properties_false(self):
        schema = op_fs_analyzer.TOOL["input_schema"]
        self.assertFalse(schema.get("additionalProperties", True))
        actions = schema["properties"]["action"]["enum"]
        for expected in ["tree_summary", "disk_usage", "find_large", "find_broken_symlinks", "hygiene_audit"]:
            self.assertIn(expected, actions)

    def test_04_missing_action_rejected(self):
        res = op_fs_analyzer.fs_analyzer({})
        self._assert_envelope(res, expected_ok=False)
        self.assertIn("action", res["error"].lower())

    def test_05_invalid_action_rejected(self):
        res = op_fs_analyzer.fs_analyzer({"action": "wipe_everything"})
        self._assert_envelope(res, expected_ok=False)
        self.assertIn("wipe_everything", res["error"])

    def test_06_unknown_argument_rejected(self):
        res = op_fs_analyzer.fs_analyzer({
            "action": "tree_summary",
            "path": str(self.test_dir),
            "unauthorized_flag": 123,
        })
        self._assert_envelope(res, expected_ok=False)
        self.assertIn("unauthorized_flag", res["error"])

    # =========================================================================
    # Action: tree_summary
    # =========================================================================

    def test_07_tree_summary_directory(self):
        res = op_fs_analyzer.fs_analyzer({
            "action": "tree_summary",
            "path": str(self.test_dir),
            "max_depth": 3,
        })
        self._assert_envelope(res, expected_ok=True)
        data = res["data"]
        self.assertTrue(data["is_directory"])
        self.assertEqual(data["summary"]["total_files"], 4)
        self.assertEqual(data["summary"]["total_directories"], 2)  # subdir, deep
        self.assertEqual(data["summary"]["total_size_bytes"], 11 + 11 + 19 + 100)
        self.assertGreater(len(data["depth_breakdown"]), 0)
        self.assertGreater(len(data["first_level_entries"]), 0)

    def test_08_tree_summary_single_file(self):
        target_file = self.test_dir / "file1.txt"
        res = op_fs_analyzer.fs_analyzer({
            "action": "tree_summary",
            "path": str(target_file),
        })
        self._assert_envelope(res, expected_ok=True)
        data = res["data"]
        self.assertFalse(data["is_directory"])
        self.assertEqual(data["summary"]["total_files"], 1)
        self.assertEqual(data["summary"]["total_directories"], 0)
        self.assertEqual(data["summary"]["total_size_bytes"], 11)

    def test_09_tree_summary_max_depth_bounding(self):
        res_depth1 = op_fs_analyzer.fs_analyzer({
            "action": "tree_summary",
            "path": str(self.test_dir),
            "max_depth": 1,
        })
        self._assert_envelope(res_depth1, expected_ok=True)
        # At depth 1, deep_dir and its files are not recursed into
        self.assertEqual(len(res_depth1["data"]["depth_breakdown"]), 1)
        self.assertEqual(res_depth1["data"]["depth_breakdown"][0]["files"], 2)

    # =========================================================================
    # Action: disk_usage
    # =========================================================================

    def test_10_disk_usage_partition_and_children(self):
        res = op_fs_analyzer.fs_analyzer({
            "action": "disk_usage",
            "path": str(self.test_dir),
        })
        self._assert_envelope(res, expected_ok=True)
        data = res["data"]
        self.assertIn("partition", data)
        self.assertGreater(data["partition"]["total_bytes"], 0)
        self.assertIn("target_usage", data)
        self.assertEqual(data["target_usage"]["total_scanned_files"], 4)
        self.assertGreater(len(data["children"]), 0)
        # Children should be sorted by size descending
        sizes = [c["size_bytes"] for c in data["children"]]
        self.assertEqual(sizes, sorted(sizes, reverse=True))

    def test_11_disk_usage_single_file(self):
        target_file = self.test_dir / "file1.txt"
        res = op_fs_analyzer.fs_analyzer({
            "action": "disk_usage",
            "path": str(target_file),
        })
        self._assert_envelope(res, expected_ok=True)
        self.assertEqual(res["data"]["target_usage"]["total_scanned_files"], 1)

    # =========================================================================
    # Action: find_large
    # =========================================================================

    def test_12_find_large_threshold_filtering(self):
        # Create a 2 MB file and a 500 KB file
        big_file = self.test_dir / "big.dat"
        big_file.write_bytes(b"B" * (2 * 1024 * 1024))
        small_file = self.test_dir / "small.dat"
        small_file.write_bytes(b"S" * (500 * 1024))

        # Threshold 1.0 MB: should match only big_file
        res = op_fs_analyzer.fs_analyzer({
            "action": "find_large",
            "path": str(self.test_dir),
            "min_size_mb": 1.0,
        })
        self._assert_envelope(res, expected_ok=True)
        data = res["data"]
        self.assertEqual(data["total_matches"], 1)
        self.assertEqual(len(data["files"]), 1)
        self.assertEqual(data["files"][0]["name"], "big.dat")
        self.assertGreaterEqual(data["files"][0]["size_bytes"], 2 * 1024 * 1024)

    def test_13_find_large_pattern_and_limit(self):
        f1 = self.test_dir / "big_one.log"
        f1.write_bytes(b"L" * (1024 * 1024))
        f2 = self.test_dir / "big_two.log"
        f2.write_bytes(b"L" * (2 * 1024 * 1024))
        f3 = self.test_dir / "big_three.txt"
        f3.write_bytes(b"T" * (3 * 1024 * 1024))

        # Filter by pattern *.log and limit 1
        res = op_fs_analyzer.fs_analyzer({
            "action": "find_large",
            "path": str(self.test_dir),
            "min_size_mb": 0.5,
            "pattern": "*.log",
            "limit": 1,
        })
        self._assert_envelope(res, expected_ok=True)
        data = res["data"]
        self.assertEqual(data["total_matches"], 2)
        self.assertEqual(len(data["files"]), 1)
        self.assertTrue(data["truncated"])
        self.assertEqual(data["files"][0]["name"], "big_two.log")

    # =========================================================================
    # Action: find_broken_symlinks
    # =========================================================================

    def test_14_find_broken_symlinks_dangling_and_circular(self):
        # 1. Valid symlink
        valid_link = self.test_dir / "valid_link"
        valid_link.symlink_to(self.test_dir / "file1.txt")

        # 2. Dangling symlink
        dangling_link = self.test_dir / "dangling_link"
        dangling_link.symlink_to(self.test_dir / "nonexistent.txt")

        # 3. Circular symlink loop (a -> b, b -> a)
        cycle_a = self.test_dir / "cycle_a"
        cycle_b = self.test_dir / "cycle_b"
        cycle_a.symlink_to(cycle_b)
        cycle_b.symlink_to(cycle_a)

        res = op_fs_analyzer.fs_analyzer({
            "action": "find_broken_symlinks",
            "path": str(self.test_dir),
        })
        self._assert_envelope(res, expected_ok=True)
        data = res["data"]
        self.assertGreaterEqual(data["broken_count"], 1)
        self.assertGreaterEqual(data["circular_count"], 1)

        reasons = {b["reason"] for b in data["broken_symlinks"]}
        self.assertIn("dangling", reasons)
        self.assertIn("circular_loop", reasons)

    # =========================================================================
    # Action: hygiene_audit
    # =========================================================================

    def test_15_hygiene_audit_all_categories(self):
        # 1. Empty directory
        empty_dir = self.test_dir / "empty_folder"
        empty_dir.mkdir(parents=True, exist_ok=True)

        # 2. Zero-byte file
        zero_file = self.test_dir / "zero.bin"
        zero_file.touch()

        # 3. Temp artifact
        temp_file = self.test_dir / "backup.tmp"
        temp_file.write_text("temp", encoding="utf-8")

        # 4. Stale lock file (>24h old)
        stale_lock = self.test_dir / "old.lock"
        stale_lock.write_text("123", encoding="utf-8")
        old_time = time.time() - (36 * 3600)  # 36 hours ago
        os.utime(str(stale_lock), (old_time, old_time))

        # 5. Permission anomaly: world-writable file
        world_file = self.test_dir / "world_writable.txt"
        world_file.write_text("public", encoding="utf-8")
        world_file.chmod(0o666)

        res = op_fs_analyzer.fs_analyzer({
            "action": "hygiene_audit",
            "path": str(self.test_dir),
        })
        self._assert_envelope(res, expected_ok=True)
        data = res["data"]
        summary = data["summary"]
        self.assertGreaterEqual(summary["empty_directories_count"], 1)
        self.assertGreaterEqual(summary["zero_byte_files_count"], 1)
        self.assertGreaterEqual(summary["temp_artifacts_count"], 1)
        self.assertGreaterEqual(summary["stale_locks_count"], 1)
        self.assertGreaterEqual(summary["permission_anomalies_count"], 1)
        self.assertGreaterEqual(summary["total_hygiene_issues"], 5)
        self.assertGreaterEqual(len(data["recommendations"]), 4)

    # =========================================================================
    # Security, Boundaries & Confinement Tests
    # =========================================================================

    def test_16_security_confinement_allowed_roots(self):
        res = op_fs_analyzer.fs_analyzer({
            "action": "tree_summary",
            "path": "/etc",
        })
        self._assert_envelope(res, expected_ok=False)
        self.assertTrue("outside" in res["error"] or "allowed roots" in res["error"])

    @unittest.skipIf(SANDBOXED, "needs the developer's local env (vault/Hermes/Piper/desktop); skipped in CI")

    def test_17_security_parent_directory_escape(self):
        res = op_fs_analyzer.fs_analyzer({
            "action": "tree_summary",
            "path": "../../../etc",
        })
        self._assert_envelope(res, expected_ok=False)
        self.assertTrue("outside" in res["error"] or "allowed roots" in res["error"])

    def test_18_security_sensitive_path_block(self):
        sensitive_path = Path.home() / ".ssh"
        res = op_fs_analyzer.fs_analyzer({
            "action": "tree_summary",
            "path": str(sensitive_path),
        })
        self._assert_envelope(res, expected_ok=False)
        self.assertTrue("restricted" in res["error"].lower() or "sensitive" in res["error"].lower())

    def test_19_nonexistent_path_rejected(self):
        res = op_fs_analyzer.fs_analyzer({
            "action": "tree_summary",
            "path": str(self.root / "does_not_exist_xyz"),
        })
        self._assert_envelope(res, expected_ok=False)
        self.assertTrue("FileNotFoundError" in res["error"] or "not exist" in res["error"])

    def test_20_symlink_cycle_suppression(self):
        # Create a directory symlink loop: loop_dir -> test_dir
        loop_link = self.test_dir / "loop_link"
        loop_link.symlink_to(self.test_dir)

        # tree_summary should terminate cleanly and not crash or loop infinitely
        res = op_fs_analyzer.fs_analyzer({
            "action": "tree_summary",
            "path": str(self.test_dir),
            "max_depth": 5,
        })
        self._assert_envelope(res, expected_ok=True)

    def test_21_graceful_permission_error_handling(self):
        # Create an unreadable subdirectory
        locked_dir = self.test_dir / "locked"
        locked_dir.mkdir(parents=True, exist_ok=True)
        (locked_dir / "secret.txt").write_text("secret", encoding="utf-8")
        try:
            locked_dir.chmod(0o000)
            res = op_fs_analyzer.fs_analyzer({
                "action": "tree_summary",
                "path": str(self.test_dir),
            })
            # Scan should complete successfully for the rest of test_dir
            self._assert_envelope(res, expected_ok=True)
            # Locked dir should be recorded in permission_errors
            self.assertTrue(len(res["data"]["permission_errors"]) > 0 or res["data"]["ok"])
        finally:
            locked_dir.chmod(0o755)


if __name__ == "__main__":
    unittest.main()
