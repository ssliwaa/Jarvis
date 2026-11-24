"""Tests for operator_modules/git_ops.py (Hardened Git Automation)."""

import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import operator_modules.git_ops as git_ops


class TestGitOps(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.repo_dir = Path(self.tmpdir.name)

        # Initialize temporary git repository
        subprocess.run(["git", "init"], cwd=self.repo_dir, capture_output=True, check=True)
        subprocess.run(["git", "config", "user.name", "Test User"], cwd=self.repo_dir, capture_output=True, check=True)
        subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=self.repo_dir, capture_output=True, check=True)

        # Initial commit
        readme = self.repo_dir / "README.md"
        readme.write_text("# Test Repo\nInitial content\n", encoding="utf-8")
        subprocess.run(["git", "add", "README.md"], cwd=self.repo_dir, capture_output=True, check=True)
        subprocess.run(["git", "commit", "-m", "Initial commit"], cwd=self.repo_dir, capture_output=True, check=True)

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_tool_declaration_contract(self):
        tool = git_ops.TOOL
        self.assertEqual(tool["name"], "git_ops")
        self.assertTrue(tool["approval"])
        self.assertTrue(callable(tool["handler"]))
        self.assertEqual(tool["input_schema"]["type"], "object")
        self.assertFalse(tool["input_schema"]["additionalProperties"])

    def test_hooks_disabled_and_no_pager_in_base_cmd(self):
        cmd = git_ops.BASE_GIT_CMD
        self.assertIn("-c", cmd)
        self.assertIn("core.hooksPath=/dev/null", cmd)
        self.assertIn("--no-pager", cmd)

    def test_status_clean_and_dirty(self):
        # 1. Clean repo
        res = git_ops.git_ops({"action": "status", "repo_path": str(self.repo_dir)})
        self.assertTrue(res["ok"])
        self.assertTrue(res["result"]["clean"])
        self.assertEqual(res["result"]["staged_count"], 0)
        self.assertEqual(res["result"]["unstaged_count"], 0)

        # 2. Add an untracked file
        untracked = self.repo_dir / "untracked.txt"
        untracked.write_text("untracked", encoding="utf-8")
        res2 = git_ops.git_ops({"action": "status", "repo_path": str(self.repo_dir)})
        self.assertTrue(res2["ok"])
        self.assertFalse(res2["result"]["clean"])
        self.assertIn("untracked.txt", res2["result"]["untracked"])

        # 3. Modify README (unstaged)
        readme = self.repo_dir / "README.md"
        readme.write_text("# Test Repo\nModified line\n", encoding="utf-8")
        res3 = git_ops.git_ops({"action": "status", "repo_path": str(self.repo_dir)})
        self.assertTrue(res3["ok"])
        unstaged_paths = [item["path"] for item in res3["result"]["unstaged"]]
        self.assertIn("README.md", unstaged_paths)

    def test_diff_unstaged_and_staged(self):
        readme = self.repo_dir / "README.md"
        readme.write_text("# Test Repo\nModified line for diff\n", encoding="utf-8")

        # Unstaged diff
        res = git_ops.git_ops({"action": "diff", "repo_path": str(self.repo_dir), "staged": False})
        self.assertTrue(res["ok"])
        self.assertIn("Modified line for diff", res["result"]["diff"])

        # Stage and check staged diff
        subprocess.run(["git", "add", "README.md"], cwd=self.repo_dir, capture_output=True, check=True)
        res_staged = git_ops.git_ops({"action": "diff", "repo_path": str(self.repo_dir), "staged": True})
        self.assertTrue(res_staged["ok"])
        self.assertIn("Modified line for diff", res_staged["result"]["diff"])

    def test_log(self):
        res = git_ops.git_ops({"action": "log", "repo_path": str(self.repo_dir), "max_count": 5})
        self.assertTrue(res["ok"])
        self.assertGreaterEqual(res["result"]["count"], 1)
        first_commit = res["result"]["commits"][0]
        self.assertEqual(first_commit["subject"], "Initial commit")
        self.assertEqual(first_commit["author"], "Test User")
        self.assertTrue(len(first_commit["hash"]) >= 7)

    def test_show(self):
        res = git_ops.git_ops({"action": "show", "repo_path": str(self.repo_dir), "revision": "HEAD"})
        self.assertTrue(res["ok"])
        self.assertIn("Initial commit", res["result"]["output"])

    def test_branch_list_and_create(self):
        # List branches
        res = git_ops.git_ops({"action": "branch", "branch_action": "list", "repo_path": str(self.repo_dir)})
        self.assertTrue(res["ok"])
        self.assertGreaterEqual(res["result"]["count"], 1)

        # Create new branch
        res_create = git_ops.git_ops({
            "action": "branch",
            "branch_action": "create",
            "branch_name": "feature-test",
            "repo_path": str(self.repo_dir),
        })
        self.assertTrue(res_create["ok"])
        self.assertEqual(res_create["result"]["created"], "feature-test")

        # Verify branch is now listed
        res_list = git_ops.git_ops({"action": "branch", "branch_action": "list", "repo_path": str(self.repo_dir)})
        names = {b["name"] for b in res_list["result"]["branches"]}
        self.assertIn("feature-test", names)

    def test_detached_head_is_not_a_branch_named_HEAD(self):
        # "git branch --list -v" prints "(HEAD detached at 1a2b3c)" — or its
        # localized form, e.g. Polish "(HEAD odłączone na 1a2b3c)"; the parser
        # must match the "(HEAD" marker, not the English phrase, or the
        # detached state is reported as a branch literally named "(HEAD".
        subprocess.run(["git", "commit", "--allow-empty", "-m", "x"],
                       cwd=self.repo_dir, capture_output=True, check=True)
        subprocess.run(["git", "checkout", "--detach"],
                       cwd=self.repo_dir, capture_output=True, check=True)
        res = git_ops.git_ops({"action": "branch", "branch_action": "list",
                               "repo_path": str(self.repo_dir)})
        self.assertTrue(res["ok"])
        names = [b["name"] for b in res["result"]["branches"]]
        self.assertFalse([n for n in names if n.startswith("(")], names)
        detached = [n for n in names if n.startswith("HEAD detached")]
        self.assertEqual(len(detached), 1, names)

    def test_branch_rejection_of_invalid_name(self):
        res = git_ops.git_ops({
            "action": "branch",
            "branch_action": "create",
            "branch_name": "-f",
            "repo_path": str(self.repo_dir),
        })
        self.assertFalse(res["ok"])
        self.assertIn("Invalid branch name", res["error"])

    def test_commit_flow(self):
        new_file = self.repo_dir / "code.py"
        new_file.write_text("print('hello world')\n", encoding="utf-8")

        res = git_ops.git_ops({
            "action": "commit",
            "repo_path": str(self.repo_dir),
            "files": ["code.py"],
            "message": "Add code.py module",
        })
        self.assertTrue(res["ok"])
        self.assertTrue(res["result"]["committed"])
        self.assertEqual(res["result"]["message"], "Add code.py module")
        self.assertIn("code.py", res["result"]["staged_files"])

    def test_commit_rejection_of_sensitive_file(self):
        env_file = self.repo_dir / ".env"
        env_file.write_text("SECRET_API_KEY=xyz123\n", encoding="utf-8")

        res = git_ops.git_ops({
            "action": "commit",
            "repo_path": str(self.repo_dir),
            "files": [".env"],
            "message": "Attempting to commit secret env",
        })
        self.assertFalse(res["ok"])
        self.assertIn("sensitive", res["error"].lower())

    def test_commit_rejection_of_already_staged_sensitive_file(self):
        secrets_file = self.repo_dir / "secrets.json"
        secrets_file.write_text('{"token": "leak"}', encoding="utf-8")
        subprocess.run(["git", "add", "secrets.json"], cwd=self.repo_dir, capture_output=True, check=True)

        res = git_ops.git_ops({
            "action": "commit",
            "repo_path": str(self.repo_dir),
            "message": "Commit with staged secrets",
        })
        self.assertFalse(res["ok"])
        self.assertIn("sensitive", res["error"].lower())

    def test_handling_non_git_directory(self):
        with tempfile.TemporaryDirectory() as empty_dir:
            res = git_ops.git_ops({"action": "status", "repo_path": empty_dir})
            self.assertFalse(res["ok"])
            self.assertIn("not a valid git repository", res["error"])

    def test_timeout_handling(self):
        with patch("operator_modules.git_ops.subprocess.run", side_effect=subprocess.TimeoutExpired(cmd=["git"], timeout=15.0)):
            res = git_ops.git_ops({"action": "status", "repo_path": str(self.repo_dir)})
            self.assertFalse(res["ok"])
            self.assertIn("timed out", res["error"].lower())


if __name__ == "__main__":
    unittest.main()
