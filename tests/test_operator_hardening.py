"""Regression tests for the hardening taken from the Gemini patch set.

Each test drives the real class or module that ships in this tree; nothing here
re-implements the guard it is checking.
"""
from __future__ import annotations

import os
import stat
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

import operator_tools as ops
from browser_agent import RepeatGuard


class SensitiveReadTests(unittest.TestCase):
    def test_read_refuses_credential_files(self):
        with tempfile.TemporaryDirectory(dir="/tmp") as tmp:
            root = Path(tmp)
            secret = root / ".env"
            secret.write_text("DB_PASSWORD=hunter2\n", encoding="utf-8")
            files = ops.FileOps()
            with self.assertRaises(ops.ToolError):
                files.read(str(secret))

    def test_read_refuses_own_state_files(self):
        target = Path.home() / ".jarvis-tools" / "secrets.json"
        files = ops.FileOps()
        with self.assertRaises(ops.ToolError):
            files.read(str(target))

    def test_read_still_allows_plain_notes(self):
        with tempfile.TemporaryDirectory(dir="/tmp") as tmp:
            note = Path(tmp) / "note.md"
            note.write_text("zwykła notatka", encoding="utf-8")
            result = ops.FileOps().read(str(note))
            self.assertEqual(result["text"], "zwykła notatka")

    def test_operator_can_read_its_own_artifacts(self):
        artifact = Path.home() / ".jarvis-tools" / "agent" / "job-1" / "latest.png"
        self.assertFalse(ops.is_credential_target(artifact))
        self.assertTrue(ops.is_credential_target(
            Path.home() / ".jarvis-tools" / "secrets.json"))
        self.assertTrue(ops.is_credential_target(Path.home() / ".jarvis-tools" / "mcp.json"))
        self.assertTrue(ops.is_credential_target(Path.home() / ".ssh" / "id_ed25519"))

    def test_symlink_to_credential_file_is_refused(self):
        with tempfile.TemporaryDirectory(dir="/tmp") as tmp:
            root = Path(tmp)
            secret = root / ".ssh"
            secret.mkdir()
            (secret / "id_ed25519").write_text("PRIVATE", encoding="utf-8")
            link = root / "innocent.txt"
            link.symlink_to(secret / "id_ed25519")
            with self.assertRaises(ops.ToolError):
                ops.FileOps().read(str(link))


class SecretScrubbingTests(unittest.TestCase):
    def setUp(self):
        self.value = "value-0123456789abcdef"

    def test_env_secret_value_is_redacted(self):
        with mock.patch.dict(os.environ, {"FAKE_PROVIDER_API_KEY": self.value}):
            ops._SECRET_ENV_VALUES = None
            try:
                text = ops.redact(f"exported={self.value} and nothing else")
            finally:
                ops._SECRET_ENV_VALUES = None
        self.assertNotIn(self.value, text)
        self.assertIn("[REDACTED]", text)

    def test_short_or_unrelated_values_are_left_alone(self):
        with mock.patch.dict(os.environ, {"UNRELATED_SETTING": self.value}):
            ops._SECRET_ENV_VALUES = None
            try:
                text = ops.redact(self.value)
            finally:
                ops._SECRET_ENV_VALUES = None
        self.assertIn(self.value, text)


class RepeatGuardTests(unittest.TestCase):
    def test_third_identical_call_is_refused(self):
        guard = RepeatGuard()
        args = {"selector": "#submit"}
        self.assertEqual(guard.check("click_selector", args), "")
        self.assertEqual(guard.check("click_selector", args), "")
        self.assertIn("LOOP_GUARD", guard.check("click_selector", args))

    def test_different_arguments_reset_the_streak(self):
        guard = RepeatGuard()
        for _ in range(2):
            guard.check("click_selector", {"selector": "#submit"})
        self.assertEqual(guard.check("click_selector", {"selector": "#cancel"}), "")
        self.assertEqual(guard.check("click_selector", {"selector": "#submit"}), "")

    def test_other_tool_breaks_the_streak(self):
        guard = RepeatGuard()
        guard.check("eval", {"script": "1+1"})
        guard.check("eval", {"script": "1+1"})
        self.assertEqual(guard.check("tabs", {"action": "list"}), "")
        self.assertEqual(guard.check("eval", {"script": "1+1"}), "")


class ArchiveOpsTests(unittest.TestCase):
    def setUp(self):
        import operator_modules.archive_ops as module
        self.module = module

    def _zip(self, root: Path, entries: dict) -> Path:
        path = root / "sample.zip"
        with zipfile.ZipFile(path, "w") as archive:
            for name, data in entries.items():
                archive.writestr(name, data)
        return path

    def test_list_reports_entries_without_writing(self):
        with tempfile.TemporaryDirectory(dir="/tmp") as tmp:
            root = Path(tmp)
            archive = self._zip(root, {"a.txt": "hello", "d/b.txt": "world"})
            result = self.module.archive_ops({"action": "list", "archive": str(archive)})
            self.assertTrue(result["ok"], result)
            self.assertEqual(result["files"], 2)
            self.assertEqual(result["format"], "zip")

    def test_extract_writes_inside_destination(self):
        with tempfile.TemporaryDirectory(dir=Path.home()) as tmp:
            root = Path(tmp)
            archive = self._zip(root, {"a.txt": "hello", "d/b.txt": "world"})
            target = root / "out"
            result = self.module.archive_ops({"action": "extract", "archive": str(archive),
                                              "destination": str(target)})
            self.assertTrue(result["ok"], result)
            self.assertEqual((target / "a.txt").read_text(encoding="utf-8"), "hello")
            self.assertEqual((target / "d" / "b.txt").read_text(encoding="utf-8"), "world")
            self.assertEqual(stat.S_IMODE((target / "a.txt").stat().st_mode), 0o600)

    def test_traversal_entry_is_refused(self):
        with tempfile.TemporaryDirectory(dir=Path.home()) as tmp:
            root = Path(tmp)
            archive = self._zip(root, {"../escape.txt": "nope"})
            result = self.module.archive_ops({"action": "extract", "archive": str(archive),
                                              "destination": str(root / "out")})
            self.assertFalse(result["ok"])
            self.assertIn("traversal", result["error"])
            self.assertFalse((root / "escape.txt").exists())

    def test_symlink_entry_is_refused(self):
        with tempfile.TemporaryDirectory(dir=Path.home()) as tmp:
            root = Path(tmp)
            archive = root / "link.zip"
            with zipfile.ZipFile(archive, "w") as handle:
                info = zipfile.ZipInfo("link")
                info.external_attr = (stat.S_IFLNK | 0o777) << 16
                handle.writestr(info, "/etc/passwd")
            result = self.module.archive_ops({"action": "extract", "archive": str(archive),
                                              "destination": str(root / "out")})
            self.assertFalse(result["ok"])
            self.assertIn("symlink", result["error"])

    def test_destination_must_be_inside_home(self):
        with tempfile.TemporaryDirectory(dir="/tmp") as tmp:
            root = Path(tmp)
            archive = self._zip(root, {"a.txt": "hello"})
            result = self.module.archive_ops({"action": "extract", "archive": str(archive),
                                              "destination": str(root / "out")})
            self.assertFalse(result["ok"])
            self.assertIn("home", result["error"])

    def test_tool_declaration_matches_registry_contract(self):
        declaration = self.module.TOOL
        self.assertEqual(declaration["name"], "archive_ops")
        self.assertTrue(declaration["approval"])
        self.assertEqual(declaration["input_schema"]["type"], "object")

    def test_module_registers_in_the_operator_registry(self):
        import tool_registry
        registry = tool_registry.ToolRegistry()
        self.assertIn("archive_ops", registry.tools, registry.errors)
        self.assertFalse(registry.errors)


if __name__ == "__main__":
    unittest.main()
