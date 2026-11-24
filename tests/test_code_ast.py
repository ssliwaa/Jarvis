"""Tests for operator_modules/code_ast.py (Static Python AST Inspector)."""

import tempfile
import unittest
from pathlib import Path

import operator_modules.code_ast as code_ast


class TestCodeAst(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tmpdir.name)

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_tool_declaration_contract(self):
        tool = code_ast.TOOL
        self.assertEqual(tool["name"], "code_ast")
        self.assertFalse(tool["approval"])
        self.assertTrue(callable(tool["handler"]))
        self.assertEqual(tool["input_schema"]["type"], "object")
        self.assertFalse(tool["input_schema"]["additionalProperties"])

    def test_outline_extraction_from_string(self):
        sample_code = '''"""Module docstring."""

API_KEY = "dummy"

class Calculator:
    """A sample calculator class."""

    @classmethod
    def create(cls):
        """Factory method."""
        return cls()

    async def compute_async(self, x: int, y: int = 10, *args, **kwargs) -> int:
        """Async computation."""
        return x + y

def standalone_func(val):
    """Standalone doc."""
    return val * 2
'''
        res = code_ast.code_ast({"action": "outline", "code": sample_code})
        self.assertTrue(res["ok"])
        result = res["result"]
        self.assertEqual(result["docstring"], "Module docstring.")
        self.assertEqual(result["class_count"], 1)
        self.assertEqual(result["function_count"], 1)
        self.assertIn("API_KEY", result["top_level_vars"])

        # Check class info
        cls = result["classes"][0]
        self.assertEqual(cls["name"], "Calculator")
        self.assertEqual(cls["docstring"], "A sample calculator class.")
        self.assertEqual(cls["method_count"], 2)

        methods = {m["name"]: m for m in cls["methods"]}
        self.assertIn("create", methods)
        self.assertIn("compute_async", methods)
        self.assertTrue(methods["compute_async"]["is_async"])
        self.assertIn("@classmethod", methods["create"]["decorators"][0])

        # Check standalone func
        func = result["functions"][0]
        self.assertEqual(func["name"], "standalone_func")
        self.assertFalse(func["is_async"])

    def test_outline_from_file(self):
        py_file = self.root / "sample.py"
        py_file.write_text("def hello():\n    return 'world'\n", encoding="utf-8")

        res = code_ast.code_ast({"action": "outline", "path": str(py_file)})
        self.assertTrue(res["ok"])
        funcs = res["result"]["functions"]
        self.assertEqual(len(funcs), 1)
        self.assertEqual(funcs[0]["name"], "hello")

    def test_check_syntax_valid_and_invalid(self):
        # 1. Valid syntax
        valid_res = code_ast.code_ast({"action": "check_syntax", "code": "x = 42\ny = x + 1\n"})
        self.assertTrue(valid_res["ok"])
        self.assertTrue(valid_res["result"]["valid"])
        self.assertEqual(valid_res["result"]["line_count"], 2)

        # 2. Invalid syntax
        invalid_res = code_ast.code_ast({"action": "check_syntax", "code": "def broken(\n  print('unclosed')"})
        self.assertTrue(invalid_res["ok"])
        self.assertFalse(invalid_res["result"]["valid"])
        self.assertIn("error", invalid_res["result"])
        self.assertIsNotNone(invalid_res["result"]["lineno"])

    def test_inspect_imports(self):
        sample_code = """
import os
import sys as system
from pathlib import Path
from typing import Any, Optional as Opt
import local_helper
"""
        res = code_ast.code_ast({"action": "inspect_imports", "code": sample_code})
        self.assertTrue(res["ok"])
        result = res["result"]
        self.assertIn("os", result["modules"])
        self.assertIn("sys", result["modules"])
        self.assertIn("pathlib", result["modules"])
        self.assertIn("typing", result["modules"])

        import_names = [imp["name"] if imp["type"] == "from_import" else imp["module"] for imp in result["imports"]]
        self.assertIn("os", import_names)
        self.assertIn("Path", import_names)
        self.assertIn("Any", import_names)

    def test_large_input_capping(self):
        oversized_code = "# " + ("A" * (code_ast.MAX_BYTES + 1000))
        res = code_ast.code_ast({"action": "check_syntax", "code": oversized_code})
        self.assertFalse(res["ok"])
        self.assertIn("exceeds maximum limit", res["error"])

        # Oversized file
        oversized_file = self.root / "huge.py"
        oversized_file.write_text(oversized_code, encoding="utf-8")
        res_file = code_ast.code_ast({"action": "check_syntax", "path": str(oversized_file)})
        self.assertFalse(res_file["ok"])
        self.assertIn("exceeds maximum limit", res_file["error"])

    def test_missing_input_error(self):
        res = code_ast.code_ast({"action": "outline"})
        self.assertFalse(res["ok"])
        self.assertIn("Either 'path' or 'code'", res["error"])

    def test_nonexistent_file_error(self):
        res = code_ast.code_ast({"action": "outline", "path": str(self.root / "missing.py")})
        self.assertFalse(res["ok"])
        self.assertIn("does not exist", res["error"].lower())

    def test_sensitive_target_rejection(self):
        sensitive_target = Path.home() / ".ssh" / "id_rsa"
        res = code_ast.code_ast({"action": "outline", "path": str(sensitive_target)})
        self.assertFalse(res["ok"])
        self.assertTrue("refused" in res["error"].lower() or "does not exist" in res["error"].lower())

    def test_tool_registry_catches_system_exit(self):
        import tool_registry
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "exit_tool.py").write_text(
                'import sys\n'
                'def run(arguments, context=None):\n'
                '    sys.exit(42)\n'
                'TOOL = {"name": "exit_tool", "description": "Throws SystemExit",\n'
                '        "input_schema": {"type": "object", "properties": {}},\n'
                '        "handler": run, "approval": False}\n', encoding="utf-8")
            registry = tool_registry.ToolRegistry(root, root / "state.json")
            self.assertTrue(registry.has("exit_tool"))
            with self.assertRaises(tool_registry.ToolRegistryError) as ctx:
                registry.run("exit_tool", {})
            self.assertIn("SystemExit", str(ctx.exception))

    def test_tool_registry_catches_import_base_exception(self):
        import tool_registry
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "bad_import.py").write_text('raise SystemExit(99)\n', encoding="utf-8")
            registry = tool_registry.ToolRegistry(root, root / "state.json")
            self.assertEqual(len(registry.tools), 0)
            self.assertTrue(any("SystemExit" in err for err in registry.errors))


if __name__ == "__main__":
    unittest.main()
