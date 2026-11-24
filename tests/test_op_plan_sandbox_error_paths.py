"""Automated error-path suite for operator_modules/op_plan_sandbox.py.

Completes raise coverage for the transactional branching sandbox that
stages multi-file edits in disposable directories. Every test runs
against an isolated SANDBOX_BASE_DIR (unittest.mock.patch.object over a
tempfile.TemporaryDirectory), so no real /tmp/jarvis_plan_sandboxes
session is ever touched and no shared state leaks between tests.

Coverage map of the 15 previously unexecuted raise sites:
- dispatcher-driven via plan_sandbox(): 139, 141, 153, 159, 177, 186,
  190, 240, 284, 303, 306, 332, 394, 450
- direct validator call: 157 (is_dir=True is currently not requested by
  any action, so _resolve_and_validate_path is exercised directly --
  the same convention used for path-guard validators in the
  op_log_summarizer wave)

100% offline and deterministic: all staging targets are files and
directories created inside the test-private temporary directory.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

import operator_modules.op_plan_sandbox as ps


class BaseSandboxTest(unittest.TestCase):
    """Common isolation: private sandbox base + source files per test."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.base = self.root / "sandboxes"
        self.base.mkdir(parents=True)
        self.srcdir = self.root / "src"
        self.srcdir.mkdir()
        self._patcher = mock.patch.object(ps, "SANDBOX_BASE_DIR", self.base)
        self._patcher.start()

    def tearDown(self) -> None:
        self._patcher.stop()
        self._tmp.cleanup()

    def _run(self, **arguments) -> dict:
        return ps.plan_sandbox(arguments)

    def _create_sandbox(self, sid: str) -> dict:
        return self._run(action="create_stage", stage_id=sid)

    def _make_source(self, name: str = "source.txt",
                     text: str = "hello world") -> Path:
        path = self.srcdir / name
        path.write_text(text, encoding="utf-8")
        return path


class TestPathValidationRaises(unittest.TestCase):
    """_resolve_and_validate_path guards (absolute test isolation)."""

    def test_validator_directory_expected(self):
        # Line 157: is_dir=True is not reachable through any dispatcher
        # action today; the validator branch is verified directly.
        probe = self
        tmp = tempfile.TemporaryDirectory()
        try:
            srcdir = Path(tmp.name) / "src"
            srcdir.mkdir()
            srcdir.joinpath("regular.txt").write_text("x", encoding="utf-8")
            with probe.assertRaises(ValueError) as ctx:
                ps._resolve_and_validate_path(
                    str(srcdir / "regular.txt"),
                    must_exist=True,
                    is_dir=True,
                )
            probe.assertIn("is not a directory.", str(ctx.exception))
        finally:
            tmp.cleanup()

    def test_validator_non_string_path_rejected(self):
        # Line 139 isinstance guard: no dispatcher argument can reach
        # it because the entrypoint coerces with str(), so the branch
        # is verified directly.
        with self.assertRaises(ValueError) as ctx:
            ps._resolve_and_validate_path(123)
        self.assertIn("Path must be a non-empty string.", str(ctx.exception))


class TestStageFileRaises(BaseSandboxTest):
    """stage_file error paths through the dispatcher."""

    def test_unknown_sandbox_rejected(self):
        # Line 240.
        src = self._make_source()
        res = self._run(action="stage_file", stage_id="ghost",
                        file_path=str(src))
        self.assertFalse(res["ok"])
        self.assertIn("Sandbox 'ghost' does not exist.", res["error"])
        self.assertIn("Call create_stage first.", res["error"])

    def test_invalid_session_id_rejected(self):
        # Line 177: a session id whose characters are all stripped by
        # the alphanumeric cleaning regex becomes empty.
        src = self._make_source()
        res = self._run(action="stage_file", stage_id="?!*",
                        file_path=str(src))
        self.assertFalse(res["ok"])
        self.assertIn("ValueError", res["error"])
        self.assertIn("Invalid sandbox session ID: '?!*'", res["error"])

    def test_whitespace_path_rejected(self):
        # Line 139: '   ' is truthy for the dispatcher's presence check
        # but fails the validator's blank-string test.
        self._create_sandbox("good")
        res = self._run(action="stage_file", stage_id="good",
                        file_path="   ")
        self.assertFalse(res["ok"])
        self.assertIn("ValueError", res["error"])
        self.assertIn("Path must be a non-empty string.", res["error"])

    def test_null_byte_path_rejected(self):
        # Line 141.
        self._create_sandbox("good")
        res = self._run(action="stage_file", stage_id="good",
                        file_path="evil\0.txt")
        self.assertFalse(res["ok"])
        self.assertIn("PathSecurityError", res["error"])
        self.assertIn("Null bytes are prohibited in file paths.",
                      res["error"])

    def test_missing_source_file_rejected(self):
        # Line 153.
        self._create_sandbox("good")
        res = self._run(action="stage_file", stage_id="good",
                        file_path=str(self.srcdir / "missing.txt"))
        self.assertFalse(res["ok"])
        self.assertIn("FileNotFoundError", res["error"])
        self.assertIn("Path not found:", res["error"])

    def test_directory_source_rejected(self):
        # Line 159: staging target must be a regular file.
        self._create_sandbox("good")
        res = self._run(action="stage_file", stage_id="good",
                        file_path=str(self.srcdir))
        self.assertFalse(res["ok"])
        self.assertIn("ValueError", res["error"])
        self.assertIn("is not a regular file.", res["error"])

    def test_missing_manifest_rejected(self):
        # Line 186: session directory exists but has no manifest.json
        # (crashed or partially-created sandbox).
        (self.base / "nomf").mkdir()
        src = self._make_source()
        res = self._run(action="stage_file", stage_id="nomf",
                        file_path=str(src))
        self.assertFalse(res["ok"])
        self.assertIn("PlanSandboxError", res["error"])
        self.assertIn("session manifest not found", res["error"])

    def test_corrupted_manifest_rejected(self):
        # Line 190: manifest.json exists but is not valid JSON.
        (self.base / "badmf").mkdir()
        (self.base / "badmf" / "manifest.json").write_text(
            "{ not json", encoding="utf-8")
        src = self._make_source()
        res = self._run(action="stage_file", stage_id="badmf",
                        file_path=str(src))
        self.assertFalse(res["ok"])
        self.assertIn("PlanSandboxError", res["error"])
        self.assertIn("Failed to read sandbox manifest", res["error"])


class TestApplyEditRaises(BaseSandboxTest):
    """apply_edit error paths through the dispatcher."""

    def test_unknown_sandbox_rejected(self):
        # Line 284.
        src = self._make_source()
        res = self._run(action="apply_edit", stage_id="ghost",
                        file_path=str(src))
        self.assertFalse(res["ok"])
        self.assertIn("Sandbox 'ghost' does not exist.", res["error"])

    def test_search_block_not_found(self):
        # Line 303: staged file exists but lacks the searched block.
        self._create_sandbox("editsid")
        src = self._make_source(text="hello world")
        self._run(action="stage_file", stage_id="editsid",
                  file_path=str(src))
        res = self._run(action="apply_edit", stage_id="editsid",
                        file_path=str(src),
                        search_block="NEEDLE_MISSING", replace_block="X")
        self.assertFalse(res["ok"])
        self.assertIn("ValueError", res["error"])
        self.assertIn("search_block was not found in staged file",
                      res["error"])
        self.assertIn("source.txt", res["error"])

    def test_requires_content_or_search_replace(self):
        # Line 306: neither 'content' nor the search/replace pair.
        self._create_sandbox("editsid")
        src = self._make_source()
        self._run(action="stage_file", stage_id="editsid",
                  file_path=str(src))
        res = self._run(action="apply_edit", stage_id="editsid",
                        file_path=str(src))
        self.assertFalse(res["ok"])
        self.assertIn("ValueError", res["error"])
        self.assertIn("Must provide either 'content' or both "
                      "'search_block' and 'replace_block'.", res["error"])


class TestLifecycleRaises(BaseSandboxTest):
    """diff/commit/rollback error paths through the dispatcher."""

    def test_diff_unknown_sandbox_rejected(self):
        # Line 332.
        res = self._run(action="diff_sandbox", stage_id="ghost")
        self.assertFalse(res["ok"])
        self.assertIn("Sandbox 'ghost' does not exist.", res["error"])

    def test_commit_unknown_sandbox_rejected(self):
        # Line 394.
        res = self._run(action="commit_sandbox", stage_id="ghost")
        self.assertFalse(res["ok"])
        self.assertIn("Sandbox 'ghost' does not exist.", res["error"])

    def test_rollback_wipe_failure_reported(self):
        # Line 450: a regular file occupying the sandbox directory path
        # makes shutil.rmtree raise; the operator must report it as a
        # controlled PlanSandboxError instead of a raw traceback.
        self.base.joinpath("trap").write_text("not a dir", encoding="utf-8")
        res = self._run(action="rollback_sandbox", stage_id="trap")
        self.assertFalse(res["ok"])
        self.assertIn("PlanSandboxError", res["error"])
        self.assertIn("Failed to wipe sandbox directory", res["error"])

    def test_error_envelope_shape(self):
        res = self._run(action="diff_sandbox", stage_id="ghost")
        self.assertEqual(set(res), {"ok", "success", "data", "result",
                                    "error"})
        self.assertFalse(res["ok"])
        self.assertFalse(res["success"])
        self.assertIsNone(res["data"])
        self.assertIsNone(res["result"])
        self.assertIsInstance(res["error"], str)


if __name__ == "__main__":
    unittest.main()
