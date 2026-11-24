"""Tests for modular tools, truthful outcomes and the undo stack."""
import importlib.util
import tempfile
import unittest
from pathlib import Path

import operator_verify
import tool_registry
import undo_center

ROOT = Path(__file__).resolve().parents[1]


class OperatorModuleTests(unittest.TestCase):
    def test_module_registry_discovers_and_runs_one_file_tool(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "echo.py").write_text(
                'def run(arguments, context=None):\n'
                '    return {"ok": True, "text": arguments.get("text", "")}\n'
                'TOOL = {"name": "echo_module", "description": "Echo a value",\n'
                '        "input_schema": {"type": "object", "properties": {"text": {"type": "string"}}},\n'
                '        "handler": run, "approval": True}\n', encoding="utf-8")
            registry = tool_registry.ToolRegistry(root, root / "state.json")
            self.assertTrue(registry.has("echo_module"))
            out = registry.run("echo_module", {"text": "hi"})
            # registry.run completes the output to the standardized envelope
            # of PROJECT.md; the legacy task keys survive as payload.
            self.assertEqual(out["ok"], True)
            self.assertEqual(out["text"], "hi")
            self.assertEqual(out["data"], {"text": "hi"})
            self.assertEqual(out["result"], {"text": "hi"})
            self.assertTrue(out["success"])
            self.assertIsNone(out["error"])
            self.assertIn("approval", registry.list()[0])
            self.assertTrue(registry.approval_reason("echo_module"))
            self.assertEqual(registry.declarations()[0]["name"], "echo_module")

    def test_system_status_module_declares_and_returns_its_contract(self):
        path = ROOT / "operator_modules" / "system_status.py"
        spec = importlib.util.spec_from_file_location("system_status_module", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.assertEqual(module.TOOL["name"], "system_status")
        self.assertFalse(module.TOOL["approval"])
        result = module.system_status({})
        self.assertTrue(result["ok"])
        self.assertEqual(result["memory"]["used_bytes"],
                         max(0, result["memory"]["total_bytes"] - result["memory"]["available_bytes"])
                         if result["memory"]["total_bytes"] else 0)
        self.assertGreater(result["disk_home"]["total_bytes"], 0)
        self.assertGreaterEqual(result["disk_home"]["used_bytes"], 0)

    def test_verification_observes_write_and_terminal(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "result.txt"
            write = operator_verify.verify("write_file", {"path": str(target), "content": "abc"},
                                           {"ok": True, "path": str(target)})
            self.assertEqual(write["outcome"], "failed")  # the claimed file does not exist yet
            target.write_text("abc", encoding="utf-8")
            write = operator_verify.verify("write_file", {"path": str(target), "content": "abc"},
                                           {"ok": True, "path": str(target)})
            self.assertEqual(write["outcome"], "done")
            failed = operator_verify.verify("terminal", {"command": "false"}, {"returncode": 1})
            self.assertEqual(failed["outcome"], "failed")
            done = operator_verify.verify("terminal", {"command": "true"}, {"returncode": 0})
            self.assertEqual(done["outcome"], "done")

    def test_undo_refuses_a_forged_backup_outside_its_storage(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target.txt"
            target.write_text("current", encoding="utf-8")
            outside = root / "outside.txt"
            outside.write_text("attack", encoding="utf-8")
            undo = undo_center.UndoCenter(root / "undo.json", backups=root / "backups")
            undo.push("write", str(target), backup=str(outside), existed=True)
            with self.assertRaises(undo_center.UndoError):
                undo.undo_last()
            self.assertEqual(target.read_text(), "current")

    def test_undo_restores_a_write_and_a_delete(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "note.txt"
            backup = root / "backup.txt"
            target.write_text("new", encoding="utf-8")
            backup.write_text("old", encoding="utf-8")
            undo = undo_center.UndoCenter(root / "undo.json", backups=root, trash=root)
            undo.push("write", str(target), backup=str(backup), existed=True)
            undo.undo_last()
            self.assertEqual(target.read_text(), "old")
            trashed = root / "trashed.txt"
            trash = root / "trash-copy.txt"
            trashed.write_text("restore me", encoding="utf-8")
            trash.write_text("restore me", encoding="utf-8")
            trashed.unlink()
            undo.push("delete", str(trashed), trash=str(trash))
            undo.undo_last()
            self.assertEqual(trashed.read_text(), "restore me")


if __name__ == "__main__":
    unittest.main()
