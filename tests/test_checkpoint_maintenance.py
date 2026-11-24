"""checkpoint_maintenance: retention, orphan deletion and store status.

Real-integration suite: a scratch bare store with real refs, meta files and
_ref plumbing, no checkpoint_manager mocking. Pinned contracts: stale edges
leave nothing behind, orphan deletion only fires when the workdir's absence
is *positively observed* (identity + live parent or mountpoint) and honours
the allowlist, errors never raise into a caller, the auto-prune marker makes
the tick idempotent, env drives retention safely, clear_all deletes exactly
the base it was given.
"""
import json
import os
import shutil
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import checkpoint_maintenance as cm
from checkpoint_manager import (
    _index_path,
    _ledger_path,
    _project_meta_path,
    _ref_name,
)


def _git(cwd, args, extra_env=None):
    env = dict(os.environ)
    env.update({"GIT_AUTHOR_NAME": "j", "GIT_AUTHOR_EMAIL": "j@x",
                "GIT_COMMITTER_NAME": "j", "GIT_COMMITTER_EMAIL": "j@x"})
    if extra_env:
        env.update(extra_env)
    proc = subprocess.run(["git", *args], cwd=str(cwd), env=env, capture_output=True,
                           text=True, timeout=15, stdin=subprocess.DEVNULL)
    return proc.returncode == 0, proc.stdout.strip(), proc.stderr.strip()


class StoreFixture:
    """A bare store whose projects exist as real refs plus real side files."""

    def __init__(self, root: Path):
        self.base = root / "checkpoints"
        self.store = self.base / "store"
        for name in ("projects", "indexes", "ledgers"):
            (self.store / name).mkdir(parents=True)
        ok, _, err = _git(self.store.parent, ["init", "--bare", str(self.store)])
        assert ok, err
        ok, tree, err = _git(self.store, ["hash-object", "-w", "-t", "tree", "/dev/null"])
        assert ok, err
        self.tree = tree

    def add_project(self, dir_hash, commits=1, workdir="", last_touch=None,
                    parent_identity=None):
        if last_touch is None:
            last_touch = time.time()
        meta = {"workdir": workdir, "last_touch": last_touch,
                "created_at": last_touch - 10}
        if parent_identity:
            meta["workdir_parent_dev"], meta["workdir_parent_ino"] = parent_identity
        _project_meta_path(self.store, dir_hash).write_text(
            json.dumps(meta), encoding="utf-8")
        _index_path(self.store, dir_hash).write_text("idx", encoding="utf-8")
        _ledger_path(self.store, dir_hash).write_text("{}", encoding="utf-8")
        parent = None
        for i in range(commits):
            date = f"2026-01-0{min(i + 1, 9)}T10:00:00+00:00"
            args = ["commit-tree", self.tree, "-m", f"p {i}"]
            if parent:
                args += ["-p", parent]
            ok, parent, err = _git(self.store, args,
                                   extra_env={"GIT_AUTHOR_DATE": date,
                                              "GIT_COMMITTER_DATE": date})
            assert ok, err
        ok, _, err = _git(self.store, ["update-ref", _ref_name(dir_hash), parent])
        assert ok, err
        return _ref_name(dir_hash)

    def ref_exists(self, dir_hash):
        ok, out, _ = _git(self.store, ["rev-parse", "--verify", _ref_name(dir_hash)])
        return ok

    def side_files_exist(self, dir_hash):
        return (_index_path(self.store, dir_hash).exists()
                or _project_meta_path(self.store, dir_hash).exists()
                or _ledger_path(self.store, dir_hash).exists())


class MaintenanceTestCase(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name) / "deep" / "work"
        self.root.mkdir(parents=True)
        self.fx = StoreFixture(self.root)

    def a_live_parent_dir(self, name="parent"):
        parent = self.root / name
        parent.mkdir()
        (parent / "sibling.txt").write_text("here", encoding="utf-8")
        stat = parent.stat()
        return str(parent / "gone-project"), (stat.st_dev, stat.st_ino)


class WorkdirGoneTests(unittest.TestCase):
    """Orphan deletion only fires on positively observed absence."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)

    def test_existing_or_empty_workdir_is_never_orphaned(self):
        live = self.root / "live"
        live.mkdir()
        self.assertFalse(cm._workdir_is_observably_gone(str(live)))
        self.assertFalse(cm._workdir_is_observably_gone(""))
        self.assertFalse(cm._workdir_is_observably_gone(str(self.root / "missing")))

    def test_missing_workdir_without_identity_is_ambiguous(self):
        gone = self.root / "parent" / "gone"
        (self.root / "parent").mkdir()
        # No dev/ino recorded: unmounted volume vs deleted project is unknown.
        self.assertFalse(cm._workdir_is_observably_gone(str(gone)))

    def test_identity_mismatch_is_an_unmounted_volume(self):
        gone = self.root / "parent" / "gone"
        (self.root / "parent").mkdir()
        self.assertFalse(cm._workdir_is_observably_gone(str(gone), 1, 2))

    def test_identity_match_with_live_parent_confirms_absence(self):
        parent = self.root / "busy"
        parent.mkdir()
        (parent / "other.txt").write_text("x", encoding="utf-8")
        stat = parent.stat()
        gone = parent / "gone-project"
        self.assertTrue(cm._workdir_is_observably_gone(str(gone),
                                                        stat.st_dev, stat.st_ino))

    def test_empty_unmounted_parent_stays_ambiguous(self):
        parent = self.root / "empty"
        parent.mkdir()
        stat = parent.stat()
        gone = parent / "gone-project"
        self.assertFalse(cm._workdir_is_observably_gone(str(gone),
                                                        stat.st_dev, stat.st_ino))

    def test_dir_has_any_entry_tolerates_missing_dirs(self):
        self.assertFalse(cm._dir_has_any_entry(self.root / "nope"))
        empty = self.root / "empty"
        empty.mkdir()
        self.assertFalse(cm._dir_has_any_entry(empty))
        (empty / "f").write_text("x", encoding="utf-8")
        self.assertTrue(cm._dir_has_any_entry(empty))


class PruneCheckpointsTests(MaintenanceTestCase):
    def test_stale_project_is_fully_removed(self):
        self.fx.add_project("stale01", commits=2, workdir="/old/home",
                             last_touch=time.time() - 90 * 86400)
        self.fx.add_project("fresh01", last_touch=time.time())
        result = cm.prune_checkpoints(retention_days=30, checkpoint_base=self.fx.base)
        self.assertEqual(result["scanned"], 2)
        self.assertEqual(result["deleted_stale"], 1)
        self.assertEqual(result["deleted_orphan"], 0)
        self.assertEqual(result["errors"], 0)
        self.assertFalse(self.fx.ref_exists("stale01"))
        self.assertFalse(self.fx.side_files_exist("stale01"))
        self.assertTrue(self.fx.ref_exists("fresh01"))
        self.assertGreaterEqual(result["bytes_freed"], 0)

    def test_zero_retention_disables_staleness(self):
        self.fx.add_project("old1", last_touch=1.0)
        result = cm.prune_checkpoints(retention_days=0, checkpoint_base=self.fx.base)
        self.assertEqual(result["deleted_stale"], 0)
        self.assertTrue(self.fx.ref_exists("old1"))

    def test_orphan_deletion_requires_opt_in_and_positive_observation(self):
        workdir, identity = self.a_live_parent_dir()
        self.fx.add_project("orphan1", workdir=workdir, parent_identity=identity)
        # Opt-out: untouched even though the workdir is observably gone.
        result = cm.prune_checkpoints(retention_days=0, delete_orphans=False,
                                       checkpoint_base=self.fx.base)
        self.assertEqual(result["deleted_orphan"], 0)
        self.assertTrue(self.fx.ref_exists("orphan1"))
        # Opt-in: gone workdir + matching identity -> removed.
        result = cm.prune_checkpoints(retention_days=0, delete_orphans=True,
                                       checkpoint_base=self.fx.base)
        self.assertEqual(result["deleted_orphan"], 1)
        self.assertFalse(self.fx.ref_exists("orphan1"))
        self.assertFalse(self.fx.side_files_exist("orphan1"))

    def test_orphan_allowlist_gates_deletion(self):
        workdir, identity = self.a_live_parent_dir()
        self.fx.add_project("keepme", workdir=workdir, parent_identity=identity)
        self.fx.add_project("dropme", workdir=workdir, parent_identity=identity)
        result = cm.prune_checkpoints(retention_days=0, delete_orphans=True,
                                       checkpoint_base=self.fx.base,
                                       orphan_allowlist={"dropme"})
        self.assertEqual(result["deleted_orphan"], 1)
        self.assertTrue(self.fx.ref_exists("keepme"))
        self.assertFalse(self.fx.ref_exists("dropme"))

    def test_missing_parent_identity_blocks_orphan_deletion(self):
        gone = self.root / "maybe-unmounted" / "proj"
        (self.root / "maybe-unmounted").mkdir()
        self.fx.add_project("nowhere", workdir=str(gone))  # no dev/ino in meta
        result = cm.prune_checkpoints(retention_days=0, delete_orphans=True,
                                       checkpoint_base=self.fx.base)
        self.assertEqual(result["deleted_orphan"], 0)
        self.assertTrue(self.fx.ref_exists("nowhere"))

    def test_unshrinkable_store_reports_an_error_not_a_crash(self):
        self.fx.add_project("small", commits=1)
        with patch.object(cm, "_dir_size_bytes", lambda _p: 10**9):
            result = cm.prune_checkpoints(retention_days=30,
                                           checkpoint_base=self.fx.base,
                                           max_total_size_mb=1)
        self.assertEqual(result["errors"], 1)
        self.assertTrue(self.fx.ref_exists("small"))  # last snapshot kept

    def test_missing_base_returns_zeroes(self):
        result = cm.prune_checkpoints(checkpoint_base=self.root / "absent")
        self.assertEqual(result, {"scanned": 0, "deleted_orphan": 0,
                                  "deleted_stale": 0, "errors": 0,
                                  "bytes_freed": 0})


class AutoPruneTests(MaintenanceTestCase):
    def test_marker_makes_the_tick_idempotent(self):
        self.fx.add_project("fresh", last_touch=time.time())
        first = cm.maybe_auto_prune_checkpoints(min_interval_hours=24,
                                                 checkpoint_base=self.fx.base)
        self.assertFalse(first["skipped"])
        marker = self.fx.base / ".last_prune"
        self.assertTrue(marker.exists())
        second = cm.maybe_auto_prune_checkpoints(min_interval_hours=24,
                                                  checkpoint_base=self.fx.base)
        self.assertTrue(second["skipped"])
        # An old marker no longer blocks: the tick runs and overwrites it.
        marker.write_text("1.0", encoding="utf-8")
        third = cm.maybe_auto_prune_checkpoints(min_interval_hours=24,
                                                 checkpoint_base=self.fx.base)
        self.assertFalse(third["skipped"])

    def test_corrupt_marker_proceeds(self):
        self.fx.add_project("p", last_touch=time.time())
        self.fx.base.mkdir(exist_ok=True)
        (self.fx.base / ".last_prune").write_text("junk-timestamp", encoding="utf-8")
        run = cm.maybe_auto_prune_checkpoints(min_interval_hours=24,
                                               checkpoint_base=self.fx.base)
        self.assertFalse(run["skipped"])

    def test_missing_base_short_circuits_with_zero_result(self):
        out = cm.maybe_auto_prune_checkpoints(checkpoint_base=self.root / "absent")
        self.assertFalse(out["skipped"])
        self.assertEqual(out["result"]["scanned"], 0)
        self.assertFalse((self.root / "absent").exists())  # nothing was created


class EnvPruneTests(MaintenanceTestCase):
    def test_disabled_checkpoints_skip_with_reason(self):
        with patch.dict(os.environ, {"JARVIS_CHECKPOINTS": "0"}):
            out = cm.auto_prune_from_env(self.fx.base)
        self.assertTrue(out["skipped"])
        self.assertEqual(out["reason"], "checkpoints disabled")

    def run_env_tick(self, recording):
        with patch.object(cm, "maybe_auto_prune_checkpoints",
                          side_effect=recording):
            cm.auto_prune_from_env(self.fx.base)

    def test_valid_env_values_flow_through(self):
        captured = []

        def recording(**kwargs):
            captured.append(kwargs)
            return {"skipped": False, "result": {}}

        env = {"JARVIS_CHECKPOINT_RETENTION_DAYS": "7",
               "JARVIS_CHECKPOINT_PRUNE_HOURS": "6",
               "JARVIS_CHECKPOINT_MAX_TOTAL_MB": "2048"}
        with patch.dict(os.environ, env, clear=False):
            self.run_env_tick(recording)
        self.assertEqual(len(captured), 1)
        self.assertEqual(captured[0]["retention_days"], 7)
        self.assertEqual(captured[0]["min_interval_hours"], 6)
        self.assertEqual(captured[0]["max_total_size_mb"], 2048)
        self.assertFalse(captured[0]["delete_orphans"])

    def test_garbage_env_values_fall_back_to_defaults(self):
        captured = []

        def recording(**kwargs):
            captured.append(kwargs)
            return {"skipped": False, "result": {}}

        env = {"JARVIS_CHECKPOINT_RETENTION_DAYS": "abyrazka",
               "JARVIS_CHECKPOINT_PRUNE_HOURS": "jutro",
               "JARVIS_CHECKPOINT_MAX_TOTAL_MB": "zero"}
        with patch.dict(os.environ, env, clear=False):
            self.run_env_tick(recording)
        self.assertEqual(captured[0], {"retention_days": 30,
                                       "min_interval_hours": 24,
                                       "delete_orphans": False,
                                       "checkpoint_base": self.fx.base,
                                       "max_total_size_mb": 500})

    def test_negative_env_values_are_clamped(self):
        captured = []

        def recording(**kwargs):
            captured.append(kwargs)
            return {"skipped": False, "result": {}}

        env = {"JARVIS_CHECKPOINT_RETENTION_DAYS": "-3",
               "JARVIS_CHECKPOINT_PRUNE_HOURS": "0",
               "JARVIS_CHECKPOINT_MAX_TOTAL_MB": "-9"}
        with patch.dict(os.environ, env, clear=False):
            self.run_env_tick(recording)
        self.assertEqual(captured[0]["retention_days"], 1)
        self.assertEqual(captured[0]["min_interval_hours"], 1)
        self.assertEqual(captured[0]["max_total_size_mb"], 0)


class StoreStatusTests(MaintenanceTestCase):
    def test_status_over_a_real_store(self):
        live = self.root / "alive-project"
        live.mkdir()
        self.fx.add_project("proj1", commits=2, workdir=str(live))
        status = cm.store_status(self.fx.base)
        self.assertTrue(status["ok"])
        self.assertTrue(status["enabled"])
        self.assertEqual(status["project_count"], 1)
        row = status["projects"][0]
        self.assertEqual(row["hash"], "proj1")
        self.assertEqual(row["commits"], 2)
        self.assertTrue(row["exists"])
        self.assertGreater(status["total_size_bytes"], 0)

    def test_status_of_missing_base_and_disabled_flag(self):
        missing = cm.store_status(self.root / "absent")
        self.assertEqual(missing["project_count"], 0)
        self.assertEqual(missing["total_size_bytes"], 0)
        with patch.dict(os.environ, {"JARVIS_CHECKPOINTS": "0"}):
            disabled = cm.store_status(self.root / "absent")
        self.assertFalse(disabled["enabled"])


class ClearAllTests(MaintenanceTestCase):
    def test_clear_all_deletes_exactly_the_base(self):
        self.fx.add_project("gone", last_touch=time.time())
        outside = self.root / "sibling.txt"
        outside.write_text("keep", encoding="utf-8")
        result = cm.clear_all(self.fx.base)
        self.assertTrue(result["ok"])
        self.assertTrue(result["deleted"])
        self.assertFalse(self.fx.base.exists())
        self.assertTrue(outside.exists())     # nothing outside was touched

    def test_clear_all_on_missing_base_is_a_clean_noop(self):
        result = cm.clear_all(self.root / "absent")
        self.assertTrue(result["ok"])
        self.assertFalse(result["deleted"])
        self.assertEqual(result["bytes_freed"], 0)

    def test_clear_all_reports_os_errors_without_raising(self):
        self.fx.add_project("boom", last_touch=time.time())
        with patch.object(shutil, "rmtree", side_effect=OSError("locked")):
            result = cm.clear_all(self.fx.base)
        self.assertFalse(result["ok"])
        self.assertFalse(result["deleted"])
        self.assertIn("locked", result["error"])
        self.assertTrue(self.fx.base.exists())  # nothing was destroyed


if __name__ == "__main__":
    unittest.main()
