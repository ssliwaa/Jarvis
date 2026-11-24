"""Unit tests for git_pr_bridge: real offline git in tmpdirs, faked live seams.

The bridge shells out to `git`, so these tests run a real git binary against
disposable tmp repositories (no network; local path remotes). The seams that
must stay hermetic are patched: `agent_review.apply_outbox`, `subprocess.run`
for the sandboxed lint/ast/unittest/gh children (a shim delegates plain git
calls to the real binary), and occasionally `shutil.which`.

`_GitShim.captured` records *every* subprocess argv; non-git argvs are the
sandboxed children, so tests filter them instead of assuming an index.

Polish error messages are compared via `fold` (NFKD -> ASCII) so this file
stays pure ASCII except em-dashes.
"""
import glob
import shutil
import subprocess
import tempfile
import unicodedata
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import git_pr_bridge as gpb

REAL_RUN = subprocess.run  # captured before any patching


def fold(text):
    """ASCII view of a Polish error message (tests stay pure-ASCII)."""
    return unicodedata.normalize("NFKD", str(text)).encode(
        "ascii", "ignore").decode()


class _GitShim:
    """Module-like object for gpb.subprocess: real git, faked children.

    argv[0] == "git": delegated to the real binary, except argvs that contain
    a "commit" token (the bridge's -c identity commit) which get
    `self.commit_result` so failure paths are testable. Any other argv (the
    bwrap-wrapped lint/ast/unittest children or `gh`) gets `self.child_result`.
    """

    def __init__(self, child_result):
        self.child_result = child_result
        self.commit_result = subprocess.CompletedProcess(
            [], 0, stdout="", stderr="")
        self.captured = []

    def run(self, args, *extra, **kwargs):
        args = list(args)
        self.captured.append(args)
        if args and args[0] == "git":
            if "commit" in args:
                return self.commit_result
            return REAL_RUN(args, *extra, **kwargs)
        return self.child_result

    @property
    def children(self):
        """Captured argvs that are not plain git calls."""
        return [argv for argv in self.captured
                if not (argv and argv[0] == "git")]


class _RepoCase(unittest.TestCase):
    """Shared helpers: tmp repos, git plumbing, worktree-slot snapshots."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.before = self._holders()
        self.addCleanup(self.assertNoLeftoverSlots)

    def _holders(self):
        return {p for pattern in ("jarvis-pr-*", "jarvis-branch-*")
                for p in glob.glob(f"/tmp/{pattern}")}

    def assertNoLeftoverSlots(self):
        """Every /tmp worktree slot created during the test was cleaned."""
        self.assertEqual(self._holders() - self.before, set(), (
            f"leftover worktree slots: "
            f"{sorted(self._holders() - self.before)}"))

    def git(self, cwd, *args):
        return REAL_RUN(["git", "-C", str(cwd), *args],
                        capture_output=True, text=True, timeout=30, check=False)

    def make_repo(self, name, files):
        """git init --with an initial commit carrying `files`."""
        path = self.base / name
        path.mkdir()
        self.git(path, "-c", "init.defaultBranch=main", "init", "-q")
        self.write_files(path, files)
        self.commit(path, "init")
        return path

    @staticmethod
    def write_files(path, files):
        for rel, content in files.items():
            target = path / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")

    def commit(self, path, message):
        self.git(path, "add", "-A")
        res = self.git(path, "-c", "user.name=T", "-c", "user.email=t@t",
                       "commit", "-q", "-m", message)
        assert res.returncode == 0, res.stderr
        return self.git(path, "rev-parse", "HEAD").stdout.strip()

    def fake_apply_outbox(self, files, applied=None, error=None):
        """Patch gpb.agent_review with a controllable apply_outbox."""
        seen = {}

        def fake(agent_id, target, *args, **kwargs):
            seen["agent_id"] = agent_id
            if error is not None:
                raise error
            self.write_files(target and Path(target), files)
            return {"applied": len(files) if applied is None else applied,
                    "files": sorted(files)}

        patcher = mock.patch.object(
            gpb, "agent_review", SimpleNamespace(apply_outbox=fake))
        patcher.start()
        self.addCleanup(patcher.stop)
        return seen


class TestValidateRef(unittest.TestCase):
    """_validate_ref: strip + strict character policy (no option injection)."""

    def test_valid_refs_roundtrip(self):
        for ref, expected in (("feature/JAR-123_x", "feature/JAR-123_x"),
                              ("123", "123"), ("v1.2.3", "v1.2.3"),
                              ("main", "main"), ("  padded  ", "padded"),
                              (5, "5"), (True, "True"), ("a" * 80, "a" * 80)):
            with self.subTest(ref=ref):
                self.assertEqual(gpb._validate_ref(ref), expected)

    def test_rejected_refs(self):
        for ref in (None, "", "   ", " -padded", "-flag", "foo..bar",
                    "a b", "x!", "foo^bar", "foo~1", "x" * 81, "t:est",
                    "rozszerzony poza osiemdziesiat znakow oraz wejscie jj"
                    "jj"):
            with self.subTest(ref=ref):
                with self.assertRaises(gpb.GitBridgeError):
                    gpb._validate_ref(ref)

    def test_rejection_message_mentions_git(self):
        with self.assertRaises(gpb.GitBridgeError) as ctx:
            gpb._validate_ref("-rf/tmp")
        self.assertIn("Git:", fold(ctx.exception))


class TestWorktreeSlot(unittest.TestCase):
    """_make_worktree_slot: mkdtemp holder + wt child, cleanup by caller."""

    def test_slot_layout(self):
        holder, wt = gpb._make_worktree_slot("bt-probe")
        self.addCleanup(lambda: shutil.rmtree(holder, ignore_errors=True))
        self.assertTrue(holder.is_dir())
        self.assertTrue(holder.name.startswith("jarvis-bt-probe-"))
        self.assertEqual(wt, holder / "wt")


class TestReviewRefInSandbox(_RepoCase):
    """review_ref_in_sandbox: real git plumbing, patched sandbox children."""

    @staticmethod
    def _ok_child():
        return subprocess.CompletedProcess([], 0, stdout="ok", stderr="")

    def make_remote(self, name, files, pr_number=None):
        """Local repository used as a path remote, with refs/pull/N/head."""
        remote = self.make_repo(name, files)
        if pr_number is not None:
            sha = self.git(remote, "rev-parse", "HEAD").stdout.strip()
            self.git(remote, "update-ref", f"refs/pull/{pr_number}/head", sha)
        return remote

    def test_pull_number_review_full_integration(self):
        """Local-path remote pays the PR number fetch end to end."""
        repo = self.make_repo("repo", {"readme.txt": "hello"})
        remote = self.make_remote("remote", {"pr.txt": "work"}, pr_number=123)
        remote_sha = self.git(remote, "rev-parse", "HEAD").stdout.strip()

        result = gpb.review_ref_in_sandbox(repo, "123", remote=str(remote))

        self.assertTrue(result["ok"])
        self.assertEqual(result["ref"], "123")
        self.assertEqual(result["commit"], remote_sha)
        self.assertEqual(result["changed_files"], ["pr.txt", "readme.txt"])
        self.assertIn("2 files changed", result["diff_stat"])
        self.assertEqual(result["checks"], [])  # no .py files -> no children
        listing = self.git(repo, "worktree", "list", "--porcelain").stdout
        self.assertNotIn("jarvis-pr-", listing)

    def test_ast_check_caps_files_at_30(self):
        """No lint file and no test_target: changed .py files hit ast_check."""
        files = {f"m{i:02}.py": "x = 1\n" for i in range(1, 36)}
        repo = self.make_repo("repo2", files)
        for stale in repo.glob("m*.py"):
            stale.unlink()
        self.write_files(repo, {"probe.txt": "data"})
        self.commit(repo, "second")
        base_sha = self.git(repo, "rev-parse", "HEAD~1").stdout.strip()

        shim = _GitShim(self._ok_child())
        with mock.patch.object(gpb, "subprocess", shim):
            result = gpb.review_ref_in_sandbox(repo, base_sha)

        self.assertEqual(result["commit"], base_sha)
        self.assertEqual(len(shim.children), 1)
        argv = shim.children[0]
        self.assertIn("-c", argv)  # the ast code bundle passed to python
        py_args = [a for a in argv if a.endswith(".py")]
        self.assertEqual(len(py_args), 30)  # capped at 30 files
        self.assertEqual(result["checks"],
                         [{"name": "ast_check", "ok": True, "output": "ok"}])
        self.assertTrue(result["ok"])

    def test_lint_check_single_child_when_no_py_diff(self):
        """scripts/lint.py on both sides: only the lint child runs."""
        lint_py = "print('x')\n"
        repo = self.make_repo("repo3", {"scripts/lint.py": lint_py,
                                        "readme.txt": "b"})
        remote = self.make_remote("remote3", {"scripts/lint.py": lint_py,
                                              "pr.txt": "w"}, pr_number=7)

        shim = _GitShim(self._ok_child())
        with mock.patch.object(gpb, "subprocess", shim):
            result = gpb.review_ref_in_sandbox(repo, "7", remote=str(remote))

        # lint.py content is identical on both sides, so the diff holds only
        # pr.txt and the ast branch is not taken.
        self.assertEqual(len(shim.children), 1)
        self.assertIn("scripts/lint.py", shim.children[0])
        self.assertEqual(result["checks"],
                         [{"name": "lint", "ok": True, "output": "ok"}])
        self.assertEqual(result["changed_files"], ["pr.txt", "readme.txt"])
        self.assertTrue(result["ok"])

    def test_lint_failure_marks_review_failed_and_trims_output(self):
        lint_py = "print('x')\n"
        repo = self.make_repo("repo4", {"scripts/lint.py": lint_py,
                                        "readme.txt": "b"})
        remote = self.make_remote("remote4", {"scripts/lint.py": lint_py,
                                              "pr.txt": "w"}, pr_number=9)
        # 800 chars stdout + 4 chars stderr -> output keeps the last 600.
        payload = ("x" * 500) + ("y" * 300)
        failing = subprocess.CompletedProcess(
            [], 1, stdout=payload, stderr="upsl")
        shim = _GitShim(failing)

        with mock.patch.object(gpb, "subprocess", shim):
            result = gpb.review_ref_in_sandbox(repo, "9", remote=str(remote))

        self.assertFalse(result["ok"])
        check, = result["checks"]
        self.assertEqual((check["name"], check["ok"]), ("lint", False))
        self.assertEqual(check["output"], "x" * 296 + "y" * 300 + "upsl")

    def test_unittest_check_when_test_target_given(self):
        """test_target takes the unittest branch and skips ast entirely."""
        repo = self.make_repo("repo5", {"readme.txt": "b"})
        remote = self.make_remote("remote5", {"probe_ok.py": "x = 1\n"},
                                  pr_number=11)

        shim = _GitShim(self._ok_child())
        with mock.patch.object(gpb, "subprocess", shim):
            result = gpb.review_ref_in_sandbox(
                repo, "11", remote=str(remote), test_target="probe_ok.py")

        argv = shim.children[0]
        self.assertEqual(argv[argv.index("-m") + 1], "unittest")
        self.assertIn("probe_ok.py", argv)
        self.assertEqual(result["checks"],
                         [{"name": "unittest", "ok": True, "output": "ok"}])
        self.assertTrue(result["ok"])

    def test_invalid_test_target_still_cleans_worktree(self):
        repo = self.make_repo("repo6", {"readme.txt": "b"})
        with self.assertRaises(gpb.GitBridgeError) as ctx:
            gpb.review_ref_in_sandbox(repo, "HEAD", test_target="a b")
        self.assertIn("Git:", fold(ctx.exception))

    def test_git_missing(self):
        with mock.patch.object(gpb.shutil, "which", lambda name: None):
            with self.assertRaises(gpb.GitBridgeError) as ctx:
                gpb.review_ref_in_sandbox(self.base, "main")
        self.assertIn("git", fold(ctx.exception))

    def test_not_a_repository(self):
        plain = self.base / "plain"
        plain.mkdir()
        with self.assertRaises(gpb.GitBridgeError) as ctx:
            gpb.review_ref_in_sandbox(plain, "main")
        self.assertIn("repozytorium", fold(ctx.exception))

    def test_invalid_ref_rejected_before_any_worktree(self):
        repo = self.make_repo("repo7", {"a.txt": "a"})
        with self.assertRaises(gpb.GitBridgeError) as ctx:
            gpb.review_ref_in_sandbox(repo, "abc..def")
        self.assertIn("Git:", fold(ctx.exception))

    def test_unknown_ref_error(self):
        repo = self.make_repo("repo8", {"a.txt": "a"})
        with self.assertRaises(gpb.GitBridgeError) as ctx:
            gpb.review_ref_in_sandbox(repo, "no-such-branch")
        msg = fold(ctx.exception)
        self.assertIn("no-such-branch", msg)
        self.assertTrue(msg.startswith("Nieznana ga"))

    def test_fetch_failure_error(self):
        repo = self.make_repo("repo9", {"a.txt": "a"})
        nowhere = self.base / "does-not-exist"
        with self.assertRaises(gpb.GitBridgeError) as ctx:
            gpb.review_ref_in_sandbox(repo, "123", remote=str(nowhere))
        self.assertIn("fetch", fold(ctx.exception))


class TestCreateBranchFromOutbox(_RepoCase):
    """create_branch_from_outbox: real git, patched apply_outbox / gh."""

    @staticmethod
    def _ok_child():
        return subprocess.CompletedProcess([], 0, stdout="ok", stderr="")

    def test_full_branch_flow_with_default_message(self):
        repo = self.make_repo("repoB", {"readme.txt": "hello"})
        seen = self.fake_apply_outbox({"out1.txt": "jeden", "out2.txt": "dwa"})

        result = gpb.create_branch_from_outbox(repo, "feature/x-1", "agent-7")

        self.assertTrue(result["ok"])
        self.assertEqual(result["branch"], "feature/x-1")
        self.assertEqual(result["files"], ["out1.txt", "out2.txt"])
        self.assertEqual(result["pr_url"], "")
        self.assertEqual(result["push_hint"], "git push -u origin feature/x-1")
        self.assertTrue(result["commit"])  # new commit sha
        self.assertEqual(seen.get("agent_id"), "agent-7")

        # The branch lives in the shared repo and carries the outbox files.
        self.assertEqual(self.git(repo, "rev-parse", "--verify",
                                  "feature/x-1").returncode, 0)
        tree = self.git(repo, "ls-tree", "-r", "--name-only",
                       "feature/x-1").stdout.split()
        self.assertIn("out1.txt", tree)
        self.assertIn("readme.txt", tree)
        log = self.git(repo, "log", "-1", "--pretty=%B",
                      "feature/x-1").stdout.strip()
        self.assertEqual(log, "jarvis(agent-7): apply verified outbox changes")

    def test_custom_message_truncated_to_240(self):
        repo = self.make_repo("repoC", {"readme.txt": "hello"})
        self.fake_apply_outbox({"f.txt": "1"})

        result = gpb.create_branch_from_outbox(
            repo, "feature/msg", "agent", commit_message="W" * 300)

        self.assertTrue(result["ok"])
        log = self.git(repo, "log", "-1", "--pretty=%B",
                      "feature/msg").stdout.strip()
        self.assertEqual(log, "W" * 240)

    def test_outbox_empty_raises(self):
        repo = self.make_repo("repoD", {"readme.txt": "hello"})
        self.fake_apply_outbox({}, applied=0)

        with self.assertRaises(gpb.GitBridgeError) as ctx:
            gpb.create_branch_from_outbox(repo, "feature/empty", "agent-8")
        msg = fold(ctx.exception)
        self.assertIn("outbox", msg)
        self.assertIn("agent-8", msg)

    def test_apply_outbox_exception_propagates(self):
        repo = self.make_repo("repoE", {"readme.txt": "hello"})
        self.fake_apply_outbox({}, error=RuntimeError("boom-application"))

        with self.assertRaises(RuntimeError):
            gpb.create_branch_from_outbox(repo, "feature/boom", "agent")

    def test_commit_failure_surfaced(self):
        repo = self.make_repo("repoF", {"readme.txt": "hello"})
        self.fake_apply_outbox({"f.txt": "1"})
        shim = _GitShim(self._ok_child())
        shim.commit_result = subprocess.CompletedProcess(
            [], 128, stdout="", stderr="identity missing (probe)")

        with mock.patch.object(gpb, "subprocess", shim):
            with self.assertRaises(gpb.GitBridgeError) as ctx:
                gpb.create_branch_from_outbox(repo, "feature/commit", "agent")

        msg = fold(ctx.exception)
        self.assertIn("commit", msg)
        self.assertIn("identity missing (probe)", msg)

    def test_git_missing(self):
        with mock.patch.object(gpb.shutil, "which", lambda name: None):
            with self.assertRaises(gpb.GitBridgeError):
                gpb.create_branch_from_outbox(self.base, "b", "agent")

    def test_invalid_branch_rejected_pre_worktree(self):
        repo = self.make_repo("repoG", {"readme.txt": "hello"})
        with self.assertRaises(gpb.GitBridgeError) as ctx:
            gpb.create_branch_from_outbox(repo, "- peligroso", "agent")
        self.assertIn("Git:", fold(ctx.exception))

    @staticmethod
    def _both_tools_installed(name, *args, **kwargs):
        """shutil.which stand-in: pretend git and gh both exist."""
        return f"/usr/bin/{name}" if name in ("git", "gh") else None

    def test_pr_url_captured_when_gh_succeeds(self):
        repo = self.make_repo("repoH", {"readme.txt": "hello"})
        self.fake_apply_outbox({"f.txt": "1"})
        shim = _GitShim(subprocess.CompletedProcess(
            [], 0, stdout="https://github.com/demo/pull/9", stderr=""))

        with mock.patch.object(gpb.shutil, "which",
                               self._both_tools_installed), \
                mock.patch.object(gpb, "subprocess", shim):
            result = gpb.create_branch_from_outbox(
                repo, "feature/gh", "agent-9",
                commit_message="PR title here", open_pr=True)

        self.assertTrue(result["ok"])
        self.assertEqual(result["pr_url"], "https://github.com/demo/pull/9")
        gh_calls = [argv for argv in shim.captured if argv and argv[0] == "gh"]
        self.assertEqual(len(gh_calls), 1)
        argv, = gh_calls
        self.assertEqual(argv[:3], ["gh", "pr", "create"])
        self.assertEqual(argv[argv.index("--head") + 1], "feature/gh")
        self.assertEqual(argv[argv.index("--title") + 1], "PR title here")
        self.assertEqual(argv[argv.index("--body") + 1],
                         "Automated branch from `agent-9`.")

    def test_pr_url_empty_when_gh_fails(self):
        repo = self.make_repo("repoI", {"readme.txt": "hello"})
        self.fake_apply_outbox({"f.txt": "1"})
        shim = _GitShim(subprocess.CompletedProcess(
            [], 1, stdout="", stderr="no gh auth probe"))

        with mock.patch.object(gpb.shutil, "which",
                               self._both_tools_installed), \
                mock.patch.object(gpb, "subprocess", shim):
            result = gpb.create_branch_from_outbox(
                repo, "feature/ghfail", "agent", open_pr=True)

        self.assertTrue(result["ok"])
        self.assertEqual(result["pr_url"], "")

    def test_open_pr_without_gh_binary_skips_pr_call(self):
        repo = self.make_repo("repoJ", {"readme.txt": "hello"})
        self.fake_apply_outbox({"f.txt": "1"})
        shim = _GitShim(self._ok_child())
        real_which = shutil.which

        def which(name, *args, **kwargs):
            return None if name == "gh" else real_which(name, *args, **kwargs)

        with mock.patch.object(gpb.shutil, "which", which), \
                mock.patch.object(gpb, "subprocess", shim):
            result = gpb.create_branch_from_outbox(
                repo, "feature/nogh", "agent", open_pr=True)

        self.assertTrue(result["ok"])
        self.assertEqual(result["pr_url"], "")
        self.assertFalse([a for a in shim.captured if a and a[0] == "gh"])


if __name__ == "__main__":
    unittest.main()
