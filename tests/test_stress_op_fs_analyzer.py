"""Adversarial stress and edge-case testing suite for operator_modules/op_fs_analyzer.py.

Empirically tests:
1. Symlink cycle attacks (circular symlinks, self loops, parent loops) across all actions.
2. Broken symlink edge cases (deep dangling, circular chains, non-existent targets, Unicode).
3. Path confinement evasion (/etc, /sys, traversal, null bytes, symlinks escaping ALLOWED_ROOTS, sensitive paths).
4. Output bound overflow (600+ files, clamping of limit to [1, 200], truncation indicators).
5. Unhandled exceptions (unreadable directories/targets, vanished files in flight, schema violations).
"""

from __future__ import annotations

import errno
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from operator_modules.op_fs_analyzer import fs_analyzer


class TestOpFSAnalyzerStress(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory(dir="/tmp")
        self.root = Path(self.temp_dir.name).resolve()

    def tearDown(self):
        # Ensure clean permissions before cleanup
        for dirpath, dirnames, _ in os.walk(str(self.root)):
            for d in dirnames:
                try:
                    os.chmod(os.path.join(dirpath, d), 0o755)
                except OSError:
                    pass
        self.temp_dir.cleanup()

    def _assert_envelope(self, res: dict, expected_ok: bool):
        self.assertIsInstance(res, dict)
        self.assertEqual(set(res.keys()), {"ok", "success", "data", "result", "error"})
        self.assertEqual(res["ok"], expected_ok)
        self.assertEqual(res["success"], expected_ok)
        if expected_ok:
            self.assertIsNone(res["error"])
            self.assertEqual(res["data"], res["result"])
        else:
            self.assertIsNone(res["data"])
            self.assertIsNone(res["result"])
            self.assertIsInstance(res["error"], str)
            self.assertIn(":", res["error"])

    # =========================================================================
    # 1. Symlink Cycle Attacks
    # =========================================================================

    def test_symlink_cycle_mutual_recursion(self):
        """Test mutual circular symlinks (a -> b -> a) in subdirectories."""
        da = self.root / "dir_a"
        db = self.root / "dir_b"
        da.mkdir()
        db.mkdir()
        (da / "file_a.txt").write_text("content A", encoding="utf-8")
        (db / "file_b.txt").write_text("content B", encoding="utf-8")

        # Mutual symlinks
        (da / "to_b").symlink_to(db)
        (db / "to_a").symlink_to(da)

        # 1. tree_summary
        res_tree = fs_analyzer({"action": "tree_summary", "path": str(self.root), "max_depth": 10})
        self._assert_envelope(res_tree, expected_ok=True)
        self.assertFalse(res_tree["data"]["truncated"])
        self.assertEqual(res_tree["data"]["summary"]["total_files"], 2)
        self.assertEqual(res_tree["data"]["summary"]["total_directories"], 2)
        self.assertEqual(res_tree["data"]["summary"]["total_symlinks"], 2)

        # 2. disk_usage
        res_du = fs_analyzer({"action": "disk_usage", "path": str(self.root), "max_depth": 10})
        self._assert_envelope(res_du, expected_ok=True)
        self.assertEqual(res_du["data"]["target_usage"]["total_scanned_files"], 2)
        self.assertEqual(res_du["data"]["target_usage"]["total_scanned_dirs"], 2)

        # 3. find_large
        res_fl = fs_analyzer({"action": "find_large", "path": str(self.root), "min_size_mb": 0.0, "max_depth": 10})
        self._assert_envelope(res_fl, expected_ok=True)
        self.assertEqual(res_fl["data"]["total_matches"], 2)

    def test_symlink_cycle_self_loop_and_ancestor(self):
        """Test self-referencing symlink (self -> self) and loop to ancestor (child -> parent)."""
        (self.root / "self_link").symlink_to(self.root / "self_link")
        (self.root / "dot_link").symlink_to(self.root)

        nested = self.root / "level1" / "level2"
        nested.mkdir(parents=True)
        (nested / "back_to_root").symlink_to(self.root)

        for action in ["tree_summary", "disk_usage", "find_large", "find_broken_symlinks", "hygiene_audit"]:
            res = fs_analyzer({"action": action, "path": str(self.root), "max_depth": 8})
            self._assert_envelope(res, expected_ok=True)

    def test_symlink_cycle_target_path_itself(self):
        """Test invoking fs_analyzer directly on a circular symlink path."""
        p1 = self.root / "link_cycle_1"
        p2 = self.root / "link_cycle_2"
        p1.symlink_to(p2)
        p2.symlink_to(p1)

        res = fs_analyzer({"action": "tree_summary", "path": str(p1)})
        self._assert_envelope(res, expected_ok=True)
        self.assertTrue(len(res["data"]["permission_errors"]) > 0)
        self.assertIn("Too many levels of symbolic links", res["data"]["permission_errors"][0])

    # =========================================================================
    # 2. Broken Symlink Edge Cases
    # =========================================================================

    def test_broken_symlinks_deep_dangling_and_chains(self):
        """Test deep dangling symlinks, chain terminating in nonexistent, and loop chains."""
        # Deep dangling symlink (relative path navigation)
        d_deep = self.root / "d1" / "d2" / "d3" / "d4"
        d_deep.mkdir(parents=True)
        (d_deep / "dangling_rel").symlink_to("../../../../../nonexistent_leaf_999")

        # Absolute dangling symlink
        (self.root / "dangling_abs").symlink_to("/tmp/definitely_not_existing_jarvis_12345")

        # Chain ending in nonexistent: c1 -> c2 -> nonexistent
        (self.root / "chain2").symlink_to("target_missing_xyz")
        (self.root / "chain1").symlink_to("chain2")

        # Circular chain: loop1 -> loop2 -> loop1
        (self.root / "loop1").symlink_to("loop2")
        (self.root / "loop2").symlink_to("loop1")

        # Symlink pointing to itself
        (self.root / "self_loop").symlink_to("self_loop")

        # Symlink with Unicode and special characters in raw target
        (self.root / "unicode_symlink").symlink_to("ścieżka / z / błędem 🚀 .dat")

        res = fs_analyzer({"action": "find_broken_symlinks", "path": str(self.root), "max_depth": 6})
        self._assert_envelope(res, expected_ok=True)
        data = res["data"]

        self.assertGreaterEqual(data["broken_count"], 5)
        self.assertGreaterEqual(data["circular_count"], 3)
        self.assertEqual(data["total_issues"], data["broken_count"] + data["circular_count"])

        reasons = {item["reason"] for item in data["broken_symlinks"]}
        self.assertEqual(reasons, {"dangling", "circular_loop"})

    # =========================================================================
    # 3. Path Confinement & Evasion Vectors
    # =========================================================================

    def test_path_confinement_system_roots(self):
        """Verify strict rejection of system directories outside ALLOWED_ROOTS."""
        targets = [
            "/etc",
            "/etc/passwd",
            "/etc/shadow",
            "/sys",
            "/sys/kernel",
            "/proc",
            "/proc/cpuinfo",
            "/dev",
            "/dev/null",
            "/root",
            "/var",
            "/var/log",
            "/usr",
            "/bin",
            "/sbin",
            "/opt",
        ]
        for t in targets:
            for act in ["tree_summary", "disk_usage", "find_large", "find_broken_symlinks", "hygiene_audit"]:
                res = fs_analyzer({"action": act, "path": t})
                self._assert_envelope(res, expected_ok=False)
                self.assertIn("PathSecurityError", res["error"])
                self.assertIn("outside allowed roots", res["error"])

    def test_path_confinement_traversal_and_malformed(self):
        """Verify rejection of directory traversal and malformed inputs."""
        traversals = [
            "/tmp/../../etc",
            "/tmp/../etc/passwd",
            "../../../../etc",
            "/tmp/test\x00escape",
            "X" * 4097,
        ]
        for t in traversals:
            res = fs_analyzer({"action": "tree_summary", "path": t})
            self._assert_envelope(res, expected_ok=False)

    def test_path_confinement_symlink_escaping_allowed_roots(self):
        """Verify rejection when a symlink inside /tmp points outside ALLOWED_ROOTS."""
        link_dir = self.root / "sym_to_etc"
        link_dir.symlink_to("/etc")
        res = fs_analyzer({"action": "tree_summary", "path": str(link_dir)})
        self._assert_envelope(res, expected_ok=False)
        self.assertIn("PathSecurityError", res["error"])

        link_file = self.root / "sym_to_passwd"
        link_file.symlink_to("/etc/passwd")
        res_file = fs_analyzer({"action": "tree_summary", "path": str(link_file)})
        self._assert_envelope(res_file, expected_ok=False)
        self.assertIn("PathSecurityError", res_file["error"])

    def test_sensitive_path_blocking(self):
        """Verify that sensitive credential directories are blocked even within ALLOWED_ROOTS."""
        sensitive_dirs = [
            self.root / ".ssh",
            self.root / ".gnupg",
            self.root / ".aws",
            self.root / ".docker",
            self.root / ".kube",
            self.root / ".env",
            self.root / ".env.production",
            self.root / "config.json",
            self.root / "secrets.json",
            self.root / ".git-credentials",
            self.root / ".jarvis-tools",
        ]
        for s in sensitive_dirs:
            if s.suffix or s.name.startswith(".env") or "json" in s.name:
                s.touch()
            else:
                s.mkdir(exist_ok=True)
            res = fs_analyzer({"action": "tree_summary", "path": str(s)})
            self._assert_envelope(res, expected_ok=False)
            self.assertIn("SensitivePathError", res["error"])

    # =========================================================================
    # 4. Output Bound Overflow (500+ items & Limit Clamping)
    # =========================================================================

    def test_output_bound_tree_summary_and_disk_usage(self):
        """Verify that directory with 550 files is bounded by limit (max 200)."""
        for i in range(550):
            (self.root / f"test_file_{i:04d}.txt").write_bytes(b"A" * 10)

        # tree_summary with limit=500 -> should clamp to 200
        res_tree = fs_analyzer({"action": "tree_summary", "path": str(self.root), "limit": 500})
        self._assert_envelope(res_tree, expected_ok=True)
        data_tree = res_tree["data"]
        self.assertEqual(len(data_tree["first_level_entries"]), 200)
        self.assertTrue(data_tree["truncated"])
        self.assertEqual(data_tree["summary"]["total_files"], 550)

        # disk_usage with limit=300 -> should clamp to 200
        res_du = fs_analyzer({"action": "disk_usage", "path": str(self.root), "limit": 300})
        self._assert_envelope(res_du, expected_ok=True)
        data_du = res_du["data"]
        self.assertEqual(len(data_du["children"]), 200)
        self.assertEqual(data_du["returned_count"], 200)
        self.assertEqual(data_du["total_children_found"], 550)
        self.assertTrue(data_du["truncated"])
        self.assertEqual(data_du["limit"], 200)

    def test_output_bound_find_large_and_hygiene(self):
        """Verify that find_large, find_broken_symlinks, and hygiene_audit strictly clamp limit."""
        # 550 zero-byte files for hygiene_audit
        z_dir = self.root / "zero_dir"
        z_dir.mkdir()
        for i in range(520):
            (z_dir / f"zero_{i:04d}.bin").touch()

        res_hygiene = fs_analyzer({"action": "hygiene_audit", "path": str(z_dir), "limit": 999})
        self._assert_envelope(res_hygiene, expected_ok=True)
        data_h = res_hygiene["data"]
        self.assertEqual(len(data_h["issues"]), 200)
        self.assertEqual(data_h["returned_count"], 200)
        self.assertGreaterEqual(data_h["total_issues"], 520)
        self.assertTrue(data_h["truncated"])

        # 520 dangling symlinks
        s_dir = self.root / "sym_dir"
        s_dir.mkdir()
        for i in range(520):
            (s_dir / f"dangle_{i:04d}").symlink_to(f"missing_{i}")

        res_sym = fs_analyzer({"action": "find_broken_symlinks", "path": str(s_dir), "limit": 1000})
        self._assert_envelope(res_sym, expected_ok=True)
        data_s = res_sym["data"]
        self.assertEqual(len(data_s["broken_symlinks"]), 200)
        self.assertEqual(data_s["returned_count"], 200)
        self.assertGreaterEqual(data_s["total_issues"], 520)
        self.assertTrue(data_s["truncated"])

    def test_limit_boundary_clamping_lower_and_default(self):
        """Verify limit clamps lower values to 1 and defaults to 50."""
        # Lower bound: limit=0 -> 1, limit=-10 -> 1
        res_zero = fs_analyzer({"action": "tree_summary", "path": str(self.root), "limit": 0})
        self._assert_envelope(res_zero, expected_ok=True)

        res_neg = fs_analyzer({"action": "tree_summary", "path": str(self.root), "limit": -10})
        self._assert_envelope(res_neg, expected_ok=True)

    # =========================================================================
    # 5. Unhandled Exception & Fault Tolerance Checks
    # =========================================================================

    def test_unreadable_subdirectories_and_target(self):
        """Verify graceful error reporting when directories lack read permissions."""
        unreadable = self.root / "no_access"
        unreadable.mkdir()
        (unreadable / "hidden_file.txt").write_text("hidden")
        unreadable.chmod(0o000)

        try:
            for act in ["tree_summary", "disk_usage", "find_large", "find_broken_symlinks", "hygiene_audit"]:
                # When unreadable is a subdirectory
                res_sub = fs_analyzer({"action": act, "path": str(self.root)})
                self._assert_envelope(res_sub, expected_ok=True)
                self.assertGreater(len(res_sub["data"]["permission_errors"]), 0)

                # When unreadable is the target itself
                res_tgt = fs_analyzer({"action": act, "path": str(unreadable)})
                self._assert_envelope(res_tgt, expected_ok=True)
                self.assertGreater(len(res_tgt["data"]["permission_errors"]), 0)
        finally:
            unreadable.chmod(0o755)

    def test_vanished_files_during_traversal(self):
        """Verify race tolerance when files vanish between scandir and stat/is_file calls."""
        (self.root / "race1.txt").write_text("live 1")
        (self.root / "race2.txt").write_text("live 2")

        orig_stat = os.DirEntry.stat

        def vanishing_stat(entry_self, *args, **kwargs):
            if "race2" in entry_self.name:
                raise FileNotFoundError(errno.ENOENT, "No such file or directory")
            return orig_stat(entry_self, *args, **kwargs)

        with patch.object(os.DirEntry, "stat", vanishing_stat):
            for act in ["tree_summary", "disk_usage", "find_large", "find_broken_symlinks", "hygiene_audit"]:
                res = fs_analyzer({"action": act, "path": str(self.root)})
                self._assert_envelope(res, expected_ok=True)

    def test_schema_and_parameter_robustness(self):
        """Verify rejection of bad payloads, types, unknown arguments, and non-existent targets."""
        # Non-dict arguments
        self._assert_envelope(fs_analyzer(None), expected_ok=False)
        self._assert_envelope(fs_analyzer("invalid_string"), expected_ok=False)
        self._assert_envelope(fs_analyzer([1, 2, 3]), expected_ok=False)

        # Missing or invalid action
        self._assert_envelope(fs_analyzer({}), expected_ok=False)
        self._assert_envelope(fs_analyzer({"action": "unknown_action_xyz"}), expected_ok=False)

        # Unknown arguments (additionalProperties guard)
        self._assert_envelope(fs_analyzer({"action": "tree_summary", "bogus": "value"}), expected_ok=False)

        # Invalid types for arguments
        self._assert_envelope(fs_analyzer({"action": "tree_summary", "path": 12345}), expected_ok=False)
        self._assert_envelope(fs_analyzer({"action": "find_large", "min_size_mb": -1.0}), expected_ok=False)
        self._assert_envelope(fs_analyzer({"action": "find_large", "pattern": 123}), expected_ok=False)

        # Non-existent path
        self._assert_envelope(fs_analyzer({"action": "tree_summary", "path": str(self.root / "nonexistent_abc")}), expected_ok=False)


if __name__ == "__main__":
    unittest.main()
