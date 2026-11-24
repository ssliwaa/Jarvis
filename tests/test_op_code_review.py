"""Automated test suite for operator_modules/op_code_review.py.

Tests the dispatch contract, unified diff parsing (files, hunks,
additions/deletions accounting), security pattern scanning (eval,
os.system, shell=True, secrets: AWS keys, JWTs, private keys, hardcoded
credentials), code smell detection (debugger, wildcard import, silent
except, print, TODO), review scoring and recommendations, file hygiene
(syntax validity, formatting issues, docstring coverage), changelog
generation from diffs and from a dedicated temporary git repository,
patch dry-run verification, and path guardrails. 100% offline: the only
subprocess exercised is `git init/log` inside a purpose-built temp
repository; no network, no host-wide filesystem access.
"""

from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path

import operator_modules.op_code_review as cr


def _diff(*body_lines: str) -> str:
    """Wrap diff body lines into a minimal single-file unified diff."""
    header = [
        "diff --git a/src/app.py b/src/app.py",
        "index 1111111..2222222 100644",
        "--- a/src/app.py",
        "+++ b/src/app.py",
        "@@ -1,3 +1,4 @@",
        " context line",
    ]
    return "\n".join(header + list(body_lines))


class TestDispatch(unittest.TestCase):
    """Handler contract and required parameters."""

    def test_rejects_non_dict_arguments(self):
        res = cr.code_review("nope")
        self.assertFalse(res["ok"])
        self.assertIn("must be a dictionary", res["error"])

    def test_invalid_action(self):
        res = cr.code_review({"action": "detonate"})
        self.assertFalse(res["ok"])
        self.assertIn("Invalid or missing action 'detonate'", res["error"])
        self.assertIn("review_diff", res["error"])

    def test_review_diff_requires_diff_text(self):
        res = cr.code_review({"action": "review_diff"})
        self.assertFalse(res["ok"])
        self.assertIn("Missing required parameter 'diff_text'",
                      res["error"])

    def test_success_envelope_shape(self):
        res = cr.code_review({"action": "review_diff",
                              "diff_text": _diff(" x = 1")})
        self.assertEqual(set(res), {"ok", "success", "data",
                                    "result", "error"})
        self.assertTrue(res["ok"])
        self.assertEqual(res["data"], res["result"])
        self.assertIsNone(res["error"])


class TestReviewDiff(unittest.TestCase):
    """review_diff: parsing, scoring, findings, limits."""

    def test_clean_diff_full_approve(self):
        res = cr.code_review({"action": "review_diff",
                              "diff_text": _diff("+ value = compute(input)",
                                                 "- old = legacy(input)")})
        data = res["data"]
        self.assertEqual(data["files_changed_count"], 1)
        self.assertEqual(data["files_changed"], ["src/app.py"])
        self.assertEqual(data["total_additions"], 1)
        self.assertEqual(data["total_deletions"], 1)
        self.assertEqual(data["total_hunks"], 1)
        self.assertEqual(data["findings_count"], 0)
        self.assertEqual(data["review_score"], 100)
        self.assertEqual(data["recommendation"], "APPROVE")

    def test_critical_findings_force_changes(self):
        diff = _diff(
            "+ x = eval(user_input)",
            "+ os.system(cmd)",
            "+ key = 'AKIAAAAAAAAAAAAAAAAA'",
        )
        res = cr.code_review({"action": "audit_diff",
                              "diff_text": diff})
        data = res["data"]
        ids = {f["id"] for f in data["findings"]}
        self.assertIn("SEC-003", ids)   # eval
        self.assertIn("SEC-002", ids)   # os.system
        self.assertIn("SEC-007", ids)   # hardcoded AWS key
        self.assertEqual(data["critical_issues"], 3)
        self.assertEqual(data["review_score"], 100 - 3 * 30)
        self.assertEqual(data["recommendation"], "REQUEST_CHANGES")
        for finding in data["findings"]:
            self.assertEqual(finding["file"], "src/app.py")
            self.assertTrue(finding["remediation"])

    def test_smell_findings_and_comment_band(self):
        diff = _diff("+ import pdb; pdb.set_trace()",
                     "+ password = 'supersecret12'",
                     "+ print('debug value')")
        res = cr.code_review({"action": "review_diff",
                              "diff_text": diff})
        data = res["data"]
        ids = {f["id"] for f in data["findings"]}
        self.assertIn("SMELL-001", ids)   # breakpoint
        self.assertIn("SEC-009", ids)      # hardcoded secret (WARNING)
        self.assertIn("SMELL-004", ids)   # print (INFO)
        # 1 WARNING (10) + 2 INFO (2 each) => 100 - 14 = 86
        self.assertEqual(data["review_score"], 78)
        self.assertEqual(data["recommendation"], "COMMENT")

    def test_shell_true_and_silent_except_patterns(self):
        diff = _diff("+ subprocess.run(cmd, shell=True)",
                     "+ try: pass\\n",
                     "+ except Exception: pass")
        res = cr.code_review({"action": "audit_diff",
                              "diff_text": diff})
        ids = {f["id"] for f in res["data"]["findings"]}
        self.assertIn("SEC-001", ids)   # shell=True
        self.assertIn("SMELL-003", ids)   # except: pass

    def test_diff_size_limit_enforced(self):
        res = cr.code_review({"action": "review_diff",
                              "diff_text": "x" * (cr.MAX_DIFF_CHARS + 1)})
        self.assertFalse(res["ok"])
        self.assertIn("exceeds limit", res["error"])


class TestScanSecurityRisks(unittest.TestCase):
    """scan_security_risks: diff target and file target."""

    def test_scan_diff_security_only(self):
        res = cr.code_review({"action": "scan_security_risks",
                              "diff_text": _diff("+ v = eval(x)",
                                                 "+ print('hi')")})
        data = res["data"]
        self.assertEqual(data["target"], "diff_text")
        ids = {f["id"] for f in data["findings"]}
        self.assertIn("SEC-003", ids)
        self.assertNotIn("SMELL-004", ids)   # smells disabled in this scan
        self.assertFalse(data["is_safe"])
        self.assertEqual(data["critical_count"], 1)

    def test_scan_file_path(self):
        with tempfile.TemporaryDirectory() as td:
            target = Path(td) / "legacy.py"
            target.write_text(
                "import subprocess\n"
                "subprocess.run('ls', shell=True)\n"
                "key = 'AKIAAAAAAAAAAAAAAAAA'\n",
                encoding="utf-8")
            res = cr.code_review({"action": "scan_security_risks",
                                  "path": str(target)})
            data = res["data"]
            self.assertEqual(data["target"], str(target))
            self.assertGreaterEqual(data["findings_count"], 2)
            self.assertFalse(data["is_safe"])
            lines = {f["line"] for f in data["findings"]}
            self.assertIn(2, lines)
            self.assertIn(3, lines)

    def test_scan_requires_target(self):
        res = cr.code_review({"action": "scan_security_risks"})
        self.assertFalse(res["ok"])
        self.assertIn("Must provide either 'diff_text' or 'path'",
                      res["error"])


class TestCheckFileHygiene(unittest.TestCase):
    """check_file_hygiene: syntax, formatting, docstrings."""

    def test_clean_file_scores_high(self):
        with tempfile.TemporaryDirectory() as td:
            target = Path(td) / "clean.py"
            target.write_text(
                '"""Module doc."""\n\n\ndef add(a, b):\n'
                '    """Sum values."""\n    return a + b\n',
                encoding="utf-8")
            res = cr.code_review({"action": "check_file_hygiene",
                                  "path": str(target)})
            data = res["data"]
            self.assertTrue(data["syntax_valid"])
            self.assertIsNone(data["syntax_error"])
            self.assertEqual(data["missing_docstrings"], [])
            self.assertEqual(data["long_lines_count"], 0)
            self.assertEqual(data["hygiene_score"], 100)
            self.assertGreaterEqual(data["total_lines"], 5)

    def test_messy_file_reports_issues(self):
        with tempfile.TemporaryDirectory() as td:
            target = Path(td) / "messy.py"
            target.write_text(
                "mixed = 1\t    # tab and spaces\n"
                "line = '" + "a" * 130 + "'\n"
                "trailing = 1   \n"
                "def public_fn():\n"
                "    pass\n",
                encoding="utf-8")
            res = cr.code_review({"action": "check_file_hygiene",
                                  "path": str(target)})
            data = res["data"]
            issue_types = {i["type"] for i in data["issues_sample"]}
            self.assertIn("line_too_long", issue_types)
            self.assertIn("trailing_whitespace", issue_types)
            self.assertIn("missing_docstring", issue_types)
            self.assertEqual(data["missing_docstrings"],
                         ["module", "function public_fn"])
            self.assertLess(data["hygiene_score"], 100)

    def test_syntax_error_file(self):
        with tempfile.TemporaryDirectory() as td:
            target = Path(td) / "broken.py"
            target.write_text("def broken(:\n", encoding="utf-8")
            res = cr.code_review({"action": "check_file_hygiene",
                                  "path": str(target)})
            data = res["data"]
            self.assertFalse(data["syntax_valid"])
            self.assertIn("Line 1", data["syntax_error"])
            self.assertLessEqual(data["hygiene_score"], 50)


class TestGenerateChangelog(unittest.TestCase):
    """generate_changelog: diff categorization and git-log mode."""

    def test_categories_from_diff_paths(self):
        diff = "\n".join([
            "diff --git a/tests/test_x.py b/tests/test_x.py",
            "--- a/tests/test_x.py",
            "+++ b/tests/test_x.py",
            "@@ -1 +1 @@",
            "+assert True",
            "diff --git a/docs/guide.md b/docs/guide.md",
            "--- a/docs/guide.md",
            "+++ b/docs/guide.md",
            "@@ -1 +1 @@",
            "+docs line",
            "diff --git a/security_check.py b/security_check.py",
            "--- a/security_check.py",
            "+++ b/security_check.py",
            "@@ -1 +1 @@",
            "+new line",
        ])
        res = cr.code_review({"action": "generate_changelog",
                              "diff_text": diff})
        data = res["data"]
        cats = data["categorized"]
        self.assertTrue(any("test_x.py" in item
                            for item in cats["Chores & Maintenance"]))
        self.assertTrue(any("guide.md" in item
                            for item in cats["Documentation"]))
        self.assertTrue(any("security_check.py" in item
                            for item in cats["Security Hardening"]))
        self.assertEqual(data["total_entries"], 3)
        self.assertIn("### Documentation", data["changelog_markdown"])
        self.assertIn("# Release Changelog", data["changelog_markdown"])

    def test_git_log_mode_in_dedicated_repo(self):
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td)
            env_cfg = ["-c", "user.email=test@example.com",
                       "-c", "user.name=Test"]
            subprocess.run(["git", "init", "-q"], cwd=str(repo),
                           check=True, capture_output=True)
            (repo / "a.txt").write_text("1\n", encoding="utf-8")
            subprocess.run(["git"] + env_cfg + ["add", "."], cwd=str(repo),
                           check=True, capture_output=True)
            subprocess.run(["git"] + env_cfg + ["commit", "-q", "-m",
                           "feat: new launcher"], cwd=str(repo),
                           check=True, capture_output=True)
            (repo / "a.txt").write_text("2\n", encoding="utf-8")
            subprocess.run(["git"] + env_cfg + ["commit", "-q", "-a", "-m",
                           "fix: launcher crash"], cwd=str(repo),
                           check=True, capture_output=True)
            res = cr.code_review({"action": "generate_changelog",
                                  "path": str(repo), "commit_count": 5})
        data = res["data"]
        feats = data["categorized"]["Features"]
        fixes = data["categorized"]["Bug Fixes"]
        self.assertTrue(any("feat: new launcher" in f for f in feats))
        self.assertTrue(any("fix: launcher crash" in f for f in fixes))


class TestVerifyPatch(unittest.TestCase):
    """verify_patch: dry-run hunk line-range check."""

    def test_patch_within_range_applies(self):
        with tempfile.TemporaryDirectory() as td:
            target = Path(td) / "target.py"
            target.write_text("line1\nline2\nline3\n", encoding="utf-8")
            patch = "\n".join([
                "diff --git a/target.py b/target.py",
                "--- a/target.py",
                "+++ b/target.py",
                "@@ -2 +2 @@",
                "-line2",
                "+line2 patched",
            ])
            res = cr.code_review({"action": "verify_patch",
                                  "path": str(target),
                                  "patch_text": patch})
            data = res["data"]
            self.assertTrue(data["applies_cleanly"])
            self.assertEqual(data["total_hunks"], 1)
            self.assertIn("matched cleanly", data["reason"])

    def test_patch_out_of_range_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            target = Path(td) / "small.py"
            target.write_text("only\n", encoding="utf-8")
            patch = "\n".join([
                "diff --git a/small.py b/small.py",
                "--- a/small.py",
                "+++ b/small.py",
                "@@ -90 +90 @@",
                "-missing",
                "+replacement",
            ])
            res = cr.code_review({"action": "verify_patch",
                                  "path": str(target),
                                  "patch_text": patch})
            data = res["data"]
            self.assertFalse(data["applies_cleanly"])
            self.assertIn("exceeds file line count", data["reason"])

    def test_patch_without_hunks_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            target = Path(td) / "x.py"
            target.write_text("x = 1\n", encoding="utf-8")
            res = cr.code_review({"action": "verify_patch",
                                  "path": str(target),
                                  "patch_text": "not a diff at all"})
            data = res["data"]
            self.assertFalse(data["applies_cleanly"])
            self.assertEqual(data["reason"],
                             "No valid diff hunks found in patch_text")

    def test_verify_patch_requires_params(self):
        res = cr.code_review({"action": "verify_patch",
                              "patch_text": "x"})
        self.assertFalse(res["ok"])
        self.assertIn("'path' and 'patch_text' are required",
                      res["error"])


class TestPathGuardrails(unittest.TestCase):
    """Path validation through actions."""

    def test_outside_allowed_roots_rejected(self):
        res = cr.code_review({"action": "check_file_hygiene",
                              "path": "/proc/definitely/not.py"})
        self.assertFalse(res["ok"])
        self.assertIn("PathSecurityError", res["error"])

    def test_sensitive_path_rejected(self):
        res = cr.code_review({"action": "check_file_hygiene",
                              "path": "/tmp/cr_probe/.ssh/id_rsa"})
        self.assertFalse(res["ok"])
        self.assertIn("SensitivePathError", res["error"])

    def test_missing_file_rejected(self):
        res = cr.code_review({"action": "check_file_hygiene",
                              "path": "/tmp/cr_probe/missing_xyz.py"})
        self.assertFalse(res["ok"])
        self.assertIn("FileNotFoundError", res["error"])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
