"""checkpoint_pruning: checked history rewrites over a bare git store.

Two layers, one contract. FakeGit pins the Pruner's decisions (what to keep,
when to refuse, CAS-against-racing updates) deterministically, while a real
scratch git repository proves the plumbing rebuilds chains whose trees, dates
and messages survive and that update-ref acts as a compare-and-swap, never a
clobber of a snapshot that landed in between.
"""
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import checkpoint_pruning as cp
from checkpoint_pruning import GC_PENDING_NAME, PruneError, Pruner, store_lock_path


def make_pruner(run_git, store, dir_size=None, refs_prefix="refs/jarvis/"):
    return Pruner(run_git, store, "", 5,
                  dir_size or (lambda _p: 0), refs_prefix)


class FakeGit:
    """An in-memory commit DAG covering exactly the plumbing the Pruner uses."""

    def __init__(self):
        self.commits: dict[str, dict] = {}
        self.refs: dict[str, str] = {}
        self.calls: list[list[str]] = []
        self.cas_fails = False

    def add_chain(self, ref, count):
        parent = None
        for i in range(count):
            sha = f"c{len(self.commits):04d}"
            self.commits[sha] = {"tree": "t", "parent": parent, "message": f"{ref}#{i}",
                                 "author_date": f"d{i}", "committer_date": f"d{i}"}
            parent = sha
            self.refs[ref] = sha
        return parent

    def run_git(self, args, store, cwd, timeout=None, extra_env=None):
        self.calls.append(args)
        cmd = args[0]
        if cmd == "rev-list":
            sha = self.refs.get(args[-1])
            chain = []
            while sha is not None:
                chain.append(sha)
                sha = self.commits[sha]["parent"]
            return True, "\n".join(reversed(chain)), ""
        if cmd == "log":
            meta = self.commits[args[-1]]
            return True, "\x00".join([meta["tree"], meta["author_date"],
                                      meta["committer_date"], meta["message"]]), ""
        if cmd == "commit-tree":
            sha = f"n{len(self.commits):04d}"
            env = extra_env or {}
            parent = args[args.index("-p") + 1] if "-p" in args else None
            self.commits[sha] = {"tree": args[1], "parent": parent,
                                 "message": args[args.index("-m") + 1],
                                 "author_date": env.get("GIT_AUTHOR_DATE", ""),
                                 "committer_date": env.get("GIT_COMMITTER_DATE", "")}
            return True, sha, ""
        if cmd == "update-ref":
            ref, new, old = args[1], args[2], args[3]
            if self.cas_fails or self.refs.get(ref) != old:
                return False, "", "cannot lock ref"
            self.refs[ref] = new
            return True, "", ""
        if cmd == "for-each-ref":
            prefix = args[-1]
            return True, "\n".join(r for r in sorted(self.refs) if r.startswith(prefix)), ""
        return True, "", ""


class PrunerDecisionTests(unittest.TestCase):
    def setUp(self):
        self.fake = FakeGit()

    def test_trim_cas_updates_against_the_original_tip(self):
        self.fake.add_chain("refs/jarvis/p", 5)
        make_pruner(self.fake.run_git, Path("/tmp/s")).trim("refs/jarvis/p", 2)
        updates = [c for c in self.fake.calls if c[0] == "update-ref"]
        self.assertEqual(len(updates), 1)
        self.assertEqual(updates[0][1], "refs/jarvis/p")
        self.assertEqual(updates[0][3], "c0004")   # the original tip, not a guess
        self.assertTrue(updates[0][2].startswith("n"))  # rebuilt chain tip

    def test_trim_rebuilds_the_requested_tail_only(self):
        self.fake.add_chain("refs/jarvis/p", 4)
        make_pruner(self.fake.run_git, Path("/tmp/s")).trim("refs/jarvis/p", 2)
        made = [c for c in self.fake.calls if c[0] == "commit-tree"]
        self.assertEqual(len(made), 2)
        # The kept tail is rebuilt as a fresh parent chain in original order.
        self.assertNotIn("-p", made[0])
        second_sha = self.fake.refs["refs/jarvis/p"]
        self.assertEqual(self.fake.commits[second_sha]["message"], "refs/jarvis/p#3")

    def test_noop_trim_writes_nothing(self):
        self.fake.add_chain("refs/jarvis/p", 2)
        make_pruner(self.fake.run_git, Path("/tmp/s")).trim("refs/jarvis/p", 9)
        writes = [c for c in self.fake.calls if c[0] in ("update-ref", "commit-tree")]
        self.assertEqual(writes, [])  # reading the history is not a write
        make_pruner(self.fake.run_git, Path("/tmp/s")).trim("refs/jarvis/p", 0)  # forced >=1
        self.assertTrue(any(c[0] == "update-ref" for c in self.fake.calls))

    def test_empty_history_is_refused(self):
        self.fake.refs["refs/jarvis/ghost"] = None
        pruner = make_pruner(self.fake.run_git, Path("/tmp/s"))
        with self.assertRaisesRegex(PruneError, "no readable history"):
            pruner.trim("refs/jarvis/ghost", 1)

    def test_last_snapshot_refusal(self):
        self.fake.add_chain("refs/jarvis/p", 1)
        pruner = make_pruner(self.fake.run_git, Path("/tmp/s"))
        with self.assertRaisesRegex(PruneError, "last snapshot"):
            pruner._rewrite("refs/jarvis/p", ["c0000"], [], gc=False)

    def test_cas_conflict_raises_and_never_clobbers(self):
        self.fake.add_chain("refs/jarvis/p", 3)
        self.fake.cas_fails = True
        pruner = make_pruner(self.fake.run_git, Path("/tmp/s"))
        with self.assertRaisesRegex(PruneError, "update-ref failed"):
            pruner.trim("refs/jarvis/p", 1)
        self.assertEqual(self.fake.refs["refs/jarvis/p"], "c0002")  # untouched

    def test_drop_one_round_drops_one_commit_per_ref(self):
        self.fake.add_chain("refs/jarvis/a", 3)
        self.fake.add_chain("refs/jarvis/b", 1)
        sizes = {"now": 100}
        pruner = make_pruner(self.fake.run_git, Path("/tmp/s"),
                             dir_size=lambda _p: sizes["now"])
        self.assertFalse(pruner.drop_one_round(0))       # a zero cap disables trimming
        self.assertFalse(pruner.drop_one_round(200))     # already under the cap
        self.assertTrue(pruner.drop_one_round(50))
        updates = [c for c in self.fake.calls if c[0] == "update-ref"]
        self.assertEqual(len(updates), 1)                # single-commit ref skipped

    def test_enforce_size_under_cap_is_free_and_over_cap_terminates(self):
        self.fake.add_chain("refs/jarvis/a", 2)
        pruner = make_pruner(self.fake.run_git, Path("/tmp/s"), dir_size=lambda _p: 5)
        self.assertTrue(pruner.enforce_size(100))        # under the cap: untouched
        self.assertEqual(self.fake.calls, [])
        over = make_pruner(self.fake.run_git, Path("/tmp/s"), dir_size=lambda _p: 999)
        self.assertFalse(over.enforce_size(10))         # exhausted rounds, gives up


class GcFlagTests(unittest.TestCase):
    def test_trim_marks_gc_and_reclaim_clears_it(self):
        fake = FakeGit()
        fake.add_chain("refs/jarvis/p", 3)
        with tempfile.TemporaryDirectory() as tmp:
            store = Path(tmp)
            pruner = make_pruner(fake.run_git, store)
            self.assertFalse(pruner.gc_pending())
            pruner.trim("refs/jarvis/p", 1)
            self.assertTrue(pruner.gc_pending())
            self.assertTrue((store / GC_PENDING_NAME).exists())
            pruner.reclaim()
            self.assertFalse(pruner.gc_pending())
            self.assertTrue((store / "refs/heads").is_dir())
            self.assertTrue((store / "branches").is_dir())


class StoreLockTests(unittest.TestCase):
    def test_lock_path_is_a_sibling_never_inside_the_store(self):
        base = Path("/srv/jarvis/checkpoints")
        self.assertEqual(store_lock_path(base), Path("/srv/jarvis/.checkpoints.lock"))

    def test_lock_creates_its_parent_and_releases(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp) / "deep" / "cp"
            with cp.store_lock(base):
                self.assertTrue(store_lock_path(base).exists())
            with cp.store_lock(base):  # sequential re-acquisition works
                pass

    def test_busy_lock_raises_pruneerror(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp) / "cp"
            with patch("fcntl.flock", side_effect=BlockingIOError()):
                with self.assertRaisesRegex(PruneError, "busy"):
                    with cp.store_lock(base):
                        pass


def _git(cwd, args, extra_env=None, timeout=15):
    env = dict(os.environ)
    if extra_env:
        env.update(extra_env)
    proc = subprocess.run(["git", *args], cwd=str(cwd), env=env, capture_output=True,
                           text=True, timeout=timeout, stdin=subprocess.DEVNULL)
    return proc.returncode == 0, proc.stdout.strip(), proc.stderr.strip()


def run_git(args, store, cwd, timeout=None, extra_env=None):
    return _git(store, args, extra_env=extra_env, timeout=timeout or 15)


class RealGitTests(unittest.TestCase):
    """Real plumbing over a scratch bare store: chains rebuilt safely."""

    REF = "refs/jarvis/proj"

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.base = Path(tmp.name) / "checkpoints"
        self.store = self.base / "proj.store"
        self.store.mkdir(parents=True)
        ok, _, err = _git(self.store.parent, ["init", "--bare", str(self.store)])
        self.assertTrue(ok, err)
        # identity local to the scratch store so the test never depends on the
        # runner's global git config (CI has none)
        ok, _, err = _git(self.store, ["config", "user.email", "j@x"])
        self.assertTrue(ok, err)
        ok, _, err = _git(self.store, ["config", "user.name", "j"])
        self.assertTrue(ok, err)
        self.size = 1_000_000_000
        self.prunner = Pruner(run_git, self.store, str(self.base), 15,
                              lambda _p: self.size, "refs/jarvis/")
        ok, sha, err = _git(self.store, ["hash-object", "-w", "-t", "tree", "/dev/null"],
                            extra_env={})
        self.assertTrue(ok, err)
        self.tree = sha
        self.identity = {"GIT_AUTHOR_NAME": "j", "GIT_AUTHOR_EMAIL": "j@x",
                         "GIT_COMMITTER_NAME": "j", "GIT_COMMITTER_EMAIL": "j@x"}

    def build_chain(self, ref, count, message="snap %d"):
        parent = None
        first_meta = None
        for i in range(count):
            date = f"2026-01-0{min(i + 1, 9)}T12:00:00+00:00"
            args = ["commit-tree", self.tree, "--no-gpg-sign", "-m", message % i]
            if parent:
                args += ["-p", parent]
            ok, sha, err = _git(self.store, args,
                                extra_env={**self.identity,
                                           "GIT_AUTHOR_DATE": date,
                                           "GIT_COMMITTER_DATE": date})
            self.assertTrue(ok, err)
            parent = sha
            if i == 0:
                first_meta = (date, message % 0)
        ok, _, err = _git(self.store, ["update-ref", ref, parent], extra_env=self.identity)
        self.assertTrue(ok, err)
        return parent, first_meta

    def rev_list(self, ref):
        ok, out, err = _git(self.store, ["rev-list", "--reverse", ref])
        self.assertTrue(ok, err)
        return out.splitlines()

    def snapshot_meta(self, sha):
        ok, meta, err = _git(self.store, ["log", "-1", "--format=%T%n%aI%n%s", sha])
        self.assertTrue(ok, err)
        return meta

    def test_trim_preserves_tree_dates_and_messages(self):
        self.build_chain(self.REF, 4)
        whole = self.rev_list(self.REF)
        # What the last two commits carry today (as git itself renders them).
        kept_source = whole[2:]
        wanted = [self.snapshot_meta(sha) for sha in kept_source]
        self.prunner.trim(self.REF, 2)
        kept = self.rev_list(self.REF)
        self.assertEqual(len(kept), 2)
        for rebuilt, original in zip(kept, wanted):
            self.assertEqual(self.snapshot_meta(rebuilt), original)
        # trim() itself defers gc: the pending marker says so.
        self.assertTrue((self.store / GC_PENDING_NAME).exists())

    def test_concurrent_snapshot_survives_the_cas(self):
        self.build_chain(self.REF, 3)
        commits = self.prunner._commits(self.REF)
        _, racing_tip = None, self.build_chain(self.REF, 1, message="raced %d")[0]
        with self.assertRaisesRegex(PruneError, "update-ref failed"):
            self.prunner._rewrite(self.REF, commits, commits[1:], gc=False)
        ok, out, err = _git(self.store, ["rev-parse", self.REF])
        self.assertEqual(out, racing_tip)

    def test_reclaim_clears_the_pending_marker(self):
        self.build_chain(self.REF, 3)
        self.prunner.trim(self.REF, 1)
        self.assertTrue((self.store / GC_PENDING_NAME).exists())
        self.prunner.reclaim()
        self.assertFalse((self.store / GC_PENDING_NAME).exists())
        self.assertEqual(len(self.rev_list(self.REF)), 1)

    def test_deleted_ref_is_refused(self):
        self.build_chain(self.REF, 2)
        ok, _, err = _git(self.store, ["update-ref", "-d", self.REF])
        self.assertTrue(ok, err)
        with self.assertRaises(PruneError):  # unreadable ref, whatever git says
            self.prunner.trim(self.REF, 1)

    def test_last_snapshot_survives_size_pressure(self):
        self.build_chain(self.REF, 1)
        self.prunner.trim(self.REF, 1)      # no-op: one commit, one kept
        self.size = 999                      # permanently over the cap
        self.assertFalse(self.prunner.enforce_size(10))
        self.assertEqual(len(self.rev_list(self.REF)), 1)

    def test_store_lock_wraps_whole_operation(self):
        self.build_chain(self.REF, 4)
        with cp.store_lock(self.base):
            self.prunner.trim(self.REF, 2)
        self.assertEqual(len(self.rev_list(self.REF)), 2)

    def test_enforce_size_gc_relief_needs_no_trim(self):
        # gc alone brings the store under the cap: the chain is untouched.
        self.build_chain(self.REF, 3)
        sizes = [999, 1]   # over at the gate, relieved right after reclaim
        self.prunner = Pruner(run_git, self.store, str(self.base), 15,
                              lambda _p: sizes.pop(0), "refs/jarvis/")
        self.assertTrue(self.prunner.enforce_size(10))
        self.assertEqual(len(self.rev_list(self.REF)), 3)


if __name__ == "__main__":
    unittest.main()
