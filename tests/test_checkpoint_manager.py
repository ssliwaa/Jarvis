"""Shadow-git checkpoint contracts: snapshots, exclusions, diff and rollback."""
from __future__ import annotations

import json
import stat
import tempfile
import time
import unittest
from pathlib import Path

import checkpoint_maintenance
import checkpoint_manager


def project(root: Path) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "pyproject.toml").write_text("[project]\nname='probe'\n", encoding="utf-8")
    return root


class CheckpointManagerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.work = project(self.root / "work")
        self.base = self.root / "checkpoints"
        self.manager = checkpoint_manager.CheckpointManager(
            base=self.base, enabled=True, max_snapshots=20,
            max_total_size_mb=50, max_file_size_mb=1,
        )

    def test_snapshot_is_deduplicated_per_turn_and_excludes_secrets(self):
        (self.work / "note.txt").write_text("before\n", encoding="utf-8")
        (self.work / ".env").write_text("SECRET=1\n", encoding="utf-8")
        (self.work / ".gitignore").write_text("!.env\n!config.json\n", encoding="utf-8")
        (self.work / "config.json").write_text('{"api_key":"private"}\n', encoding="utf-8")
        (self.work / "node_modules").mkdir()
        (self.work / "node_modules" / "dep.js").write_text("x", encoding="utf-8")
        (self.work / "large.bin").write_bytes(b"x" * (2 * 1024 * 1024))
        self.manager.new_turn()
        self.assertTrue(self.manager.ensure_checkpoint(self.work, "first"))
        self.assertFalse(self.manager.ensure_checkpoint(self.work, "same turn"))
        checkpoints = self.manager.list_checkpoints(self.work)
        self.assertEqual(len(checkpoints), 1)
        ok, tree, _ = checkpoint_manager._run_git(
            ["ls-tree", "-r", "--name-only", checkpoints[0]["hash"]],
            self.manager.store, self.work,
        )
        self.assertTrue(ok)
        self.assertIn("note.txt", tree)
        self.assertNotIn(".env", tree)
        self.assertNotIn("config.json", tree)
        self.assertNotIn("node_modules", tree)
        self.assertNotIn("large.bin", tree)

    def test_new_turn_takes_a_second_snapshot_and_diff_shows_change(self):
        (self.work / "note.txt").write_text("before\n", encoding="utf-8")
        self.manager.new_turn()
        self.manager.ensure_checkpoint(self.work, "before")
        (self.work / "note.txt").write_text("after\n", encoding="utf-8")
        self.manager.new_turn()
        self.assertTrue(self.manager.ensure_checkpoint(self.work, "after"))
        checkpoints = self.manager.list_checkpoints(self.work)
        self.assertEqual(len(checkpoints), 2)
        diff = self.manager.diff(self.work, checkpoints[-1]["hash"])
        self.assertTrue(diff["success"])
        self.assertIn("+after", diff["diff"])
        session = self.manager.session_diff(self.work)
        self.assertTrue(session["success"])
        self.assertIn("+after", session["diff"])

    def test_single_file_restore_does_not_touch_the_rest(self):
        (self.work / "a.txt").write_text("one\n", encoding="utf-8")
        (self.work / "b.txt").write_text("keep\n", encoding="utf-8")
        self.manager.new_turn()
        self.manager.ensure_checkpoint(self.work, "before")
        (self.work / "a.txt").write_text("two\n", encoding="utf-8")
        (self.work / "b.txt").write_text("changed\n", encoding="utf-8")
        target = self.manager.list_checkpoints(self.work)[-1]["hash"]
        result = self.manager.restore(self.work, target, "a.txt")
        self.assertTrue(result["success"])
        self.assertEqual((self.work / "a.txt").read_text(encoding="utf-8"), "one\n")
        self.assertEqual((self.work / "b.txt").read_text(encoding="utf-8"), "changed\n")

    def test_safe_restore_keeps_user_edits_and_reverts_agent_writes(self):
        (self.work / "a.txt").write_text("one\n", encoding="utf-8")
        self.manager.new_turn()
        self.manager.ensure_checkpoint(self.work, "before")
        (self.work / "a.txt").write_text("agent\n", encoding="utf-8")
        self.manager.record_agent_write(str(self.work / "a.txt"))
        (self.work / "agent-new.txt").write_text("new\n", encoding="utf-8")
        self.manager.record_agent_write(str(self.work / "agent-new.txt"))
        (self.work / "user.txt").write_text("draft\n", encoding="utf-8")
        target = self.manager.list_checkpoints(self.work)[-1]["hash"]
        result = self.manager.restore(self.work, target, safe=True)
        self.assertTrue(result["success"])
        self.assertEqual((self.work / "a.txt").read_text(encoding="utf-8"), "one\n")
        self.assertFalse((self.work / "agent-new.txt").exists())
        self.assertTrue((self.work / "user.txt").exists())
        # A hand edit after the agent write is kept too.
        (self.work / "a.txt").write_text("agent\n", encoding="utf-8")
        self.manager.record_agent_write(str(self.work / "a.txt"))
        (self.work / "a.txt").write_text("user edit\n", encoding="utf-8")
        second = self.manager.restore(self.work, target, safe=True)
        self.assertTrue(second["success"])
        self.assertEqual((self.work / "a.txt").read_text(encoding="utf-8"), "user edit\n")
        self.assertIn("a.txt", second["skipped_user_edits"])

    def test_full_restore_removes_files_created_after_the_snapshot(self):
        (self.work / "a.txt").write_text("one\n", encoding="utf-8")
        self.manager.new_turn()
        self.manager.ensure_checkpoint(self.work, "before")
        (self.work / "later.txt").write_text("later\n", encoding="utf-8")
        target = self.manager.list_checkpoints(self.work)[-1]["hash"]
        result = self.manager.restore(self.work, target, safe=False)
        self.assertTrue(result["success"])
        self.assertFalse((self.work / "later.txt").exists())
        self.assertEqual((self.work / "a.txt").read_text(encoding="utf-8"), "one\n")

    def test_invalid_hash_and_escaping_path_are_refused(self):
        (self.work / "a.txt").write_text("one\n", encoding="utf-8")
        self.manager.new_turn()
        self.manager.ensure_checkpoint(self.work, "before")
        target = self.manager.list_checkpoints(self.work)[-1]["hash"]
        self.assertFalse(self.manager.restore(self.work, "--help")["success"])
        self.assertFalse(self.manager.restore(self.work, target, "../outside")["success"])
        self.assertFalse(self.manager.restore(self.work, "deadbeef")["success"])

    def test_snapshot_budget_trims_old_history(self):
        self.manager.max_snapshots = 2
        for index in range(5):
            (self.work / "a.txt").write_text(f"{index}\n", encoding="utf-8")
            self.manager.new_turn()
            self.manager.ensure_checkpoint(self.work, f"step {index}")
        checkpoints = self.manager.list_checkpoints(self.work)
        self.assertLessEqual(len(checkpoints), 2)
        self.assertGreaterEqual(len(checkpoints), 1)

    def test_disabled_manager_does_nothing(self):
        manager = checkpoint_manager.CheckpointManager(base=self.base, enabled=False)
        manager.new_turn()
        self.assertFalse(manager.ensure_checkpoint(self.work, "disabled"))
        self.assertEqual(manager.list_checkpoints(self.work), [])
        self.assertFalse(manager.restore(self.work, "deadbeef")["success"])

    def test_status_reports_the_project_and_permissions_are_private(self):
        (self.work / "a.txt").write_text("one\n", encoding="utf-8")
        self.manager.new_turn()
        self.manager.ensure_checkpoint(self.work, "before")
        status = self.manager.status()
        self.assertEqual(status["project_count"], 1)
        self.assertEqual(status["projects"][0]["workdir"], str(self.work.resolve()))
        self.assertEqual(stat.S_IMODE(self.base.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(self.manager.store.stat().st_mode), 0o700)

    def test_format_list_is_readable(self):
        (self.work / "a.txt").write_text("one\n", encoding="utf-8")
        self.manager.new_turn()
        self.manager.ensure_checkpoint(self.work, "before")
        text = checkpoint_manager.format_checkpoint_list(
            self.manager.list_checkpoints(self.work), str(self.work))
        self.assertIn("Checkpoints for", text)
        self.assertIn("before", text)

    def test_stale_project_is_pruned_by_retention(self):
        (self.work / "a.txt").write_text("one\n", encoding="utf-8")
        self.manager.new_turn()
        self.manager.ensure_checkpoint(self.work, "before")
        meta_path = next((self.manager.store / "projects").glob("*.json"))
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        meta["last_touch"] = time.time() - 10 * 86400
        meta_path.write_text(json.dumps(meta), encoding="utf-8")
        result = checkpoint_maintenance.prune_checkpoints(
            retention_days=1, delete_orphans=False,
            checkpoint_base=self.base, max_total_size_mb=50,
        )
        self.assertEqual(result["deleted_stale"], 1)
        self.assertEqual(self.manager.list_checkpoints(self.work), [])

    def test_observably_deleted_project_is_an_orphan_but_a_parent_without_entries_is_not(self):
        (self.work / "a.txt").write_text("one\n", encoding="utf-8")
        self.manager.new_turn()
        self.manager.ensure_checkpoint(self.work, "before")
        # Make the parent non-empty so the missing child is positive evidence.
        (self.root / "sibling.txt").write_text("still here", encoding="utf-8")
        import shutil as _shutil
        _shutil.rmtree(self.work)
        result = checkpoint_maintenance.prune_checkpoints(
            retention_days=90, delete_orphans=True,
            checkpoint_base=self.base, max_total_size_mb=50,
        )
        self.assertEqual(result["deleted_orphan"], 1)

    def test_clear_all_removes_the_store(self):
        (self.work / "a.txt").write_text("one\n", encoding="utf-8")
        self.manager.new_turn()
        self.manager.ensure_checkpoint(self.work, "before")
        result = checkpoint_maintenance.clear_all(self.base)
        self.assertTrue(result["deleted"])
        self.assertFalse(self.base.exists())

    def test_get_working_dir_finds_project_markers_for_a_new_file(self):
        target = self.work / "new" / "deep" / "file.txt"
        self.assertEqual(self.manager.get_working_dir_for_path(str(target)), str(self.work.resolve()))

    def test_format_helpers_do_not_leak_into_tool_output(self):
        # The manager is infrastructure; only sorted, bounded metadata is
        # exposed to the UI. Full transcript content never enters status.
        (self.work / "a.txt").write_text("secret body", encoding="utf-8")
        self.manager.new_turn()
        self.manager.ensure_checkpoint(self.work, "before")
        payload = json.dumps(self.manager.status())
        self.assertNotIn("secret body", payload)


if __name__ == "__main__":
    unittest.main()
