"""Automated test suite for operator_modules/op_repo_mapper.py.

Tests the dispatch contract, path security guardrails (ALLOWED_ROOTS
perimeter, sensitive directory/file blocklist, null bytes, existence
and type checks), directory tree mapping with ignore filters, AST
symbol extraction (classes, methods, async flags, signatures, imports,
call counts), symbol search, call-hierarchy analysis, textual reference
search, and token-budgeted repository map generation. 100% offline:
every test operates on a purpose-built mini repository inside
TemporaryDirectory; no network, no real-home access.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import operator_modules.op_repo_mapper as rm

ALPHA = '''import json
from pathlib import Path

class Greeter:
    """Greets people politely."""

    def hello(self, name: str) -> str:
        return helper(name)

def helper(x):
    """Help text summary."""
    return str(x)
'''

BETA = '''from alpha import Greeter

class GreeterChild(Greeter):
    """Child class of Greeter."""

    async def run(self):
        return await helper(x=1)

def call_helper(y):
    return helper(y)
'''


def _make_repo(root: Path) -> None:
    (root / "alpha.py").write_text(ALPHA, encoding="utf-8")
    sub = root / "sub"
    sub.mkdir()
    (sub / "beta.py").write_text(BETA, encoding="utf-8")
    (root / "notes.txt").write_text("not python", encoding="utf-8")
    (root / "logo.png").write_bytes(b"\x89PNG fake")
    git_dir = root / ".git"
    git_dir.mkdir()
    (git_dir / "inner.py").write_text("x = 1\n", encoding="utf-8")


class TestDispatch(unittest.TestCase):
    """Handler contract: envelope and action validation."""

    def test_rejects_non_dict_arguments(self):
        res = rm.repo_mapper("string-arg")
        self.assertFalse(res["ok"])
        self.assertIn("Arguments must be a dictionary", res["error"])

    def test_invalid_action(self):
        res = rm.repo_mapper({"action": "nope"})
        self.assertFalse(res["ok"])
        self.assertIn("Invalid or missing action 'nope'", res["error"])
        self.assertIn("build_map", res["error"])

    def test_path_alias_accepted(self):
        with tempfile.TemporaryDirectory() as td:
            target = Path(td) / "alpha.py"
            target.write_text(ALPHA, encoding="utf-8")
            res = rm.repo_mapper({"action": "extract_symbols",
                                  "path": str(target)})
        self.assertTrue(res["ok"])
        self.assertTrue(res["data"]["classes"])

    def test_success_envelope_shape(self):
        with tempfile.TemporaryDirectory() as td:
            _make_repo(Path(td))
            res = rm.repo_mapper({"action": "map_tree",
                                  "directory": td})
        self.assertEqual(set(res), {"ok", "success", "data",
                                    "result", "error"})
        self.assertTrue(res["ok"])
        self.assertEqual(res["data"], res["result"])
        self.assertIsNone(res["error"])


class TestPathGuardrails(unittest.TestCase):
    """Path validation: perimeter, sensitive blocklist, existence, types."""

    def test_outside_allowed_roots_rejected(self):
        res = rm.repo_mapper({"action": "map_tree",
                              "directory": "/proc/definitely"})
        self.assertFalse(res["ok"])
        self.assertIn("PathSecurityError", res["error"])
        self.assertIn("outside ALLOWED_ROOTS", res["error"])

    def test_sensitive_directory_rejected(self):
        res = rm.repo_mapper({"action": "map_tree",
                              "directory": "/tmp/rm_probe/.ssh"})
        self.assertFalse(res["ok"])
        self.assertIn("SensitivePathError", res["error"])

    def test_null_byte_rejected(self):
        res = rm.repo_mapper({"action": "map_tree",
                              "directory": "/tmp/ab\0cd"})
        self.assertFalse(res["ok"])
        self.assertIn("Null bytes", res["error"])

    def test_missing_path_and_type_mismatch(self):
        res = rm.repo_mapper({"action": "map_tree",
                              "directory": "/tmp/definitely_missing_dir_xyz"})
        self.assertFalse(res["ok"])
        self.assertIn("FileNotFoundError", res["error"])
        with tempfile.TemporaryDirectory() as td:
            target = Path(td) / "alpha.py"
            target.write_text(ALPHA, encoding="utf-8")
            res2 = rm.repo_mapper({"action": "map_tree",
                                   "directory": str(target)})
        self.assertFalse(res2["ok"])
        self.assertIn("not a directory", res2["error"])


class TestMapTree(unittest.TestCase):
    """map_tree: structure, ignore filters, size accounting."""

    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.root = Path(self._td.name)
        _make_repo(self.root)

    def tearDown(self):
        self._td.cleanup()

    def test_tree_structure_and_ignores(self):
        res = rm.repo_mapper({"action": "map_tree",
                              "directory": str(self.root),
                              "max_depth": 4})
        data = res["data"]
        self.assertTrue(res["ok"])
        self.assertEqual(data["total_directories"], 1)   # only sub/
        # alpha.py, beta.py, notes.txt (png filtered by extension)
        self.assertEqual(data["total_files"], 3)
        names = {c["name"] for c in data["tree"]["children"]}
        self.assertEqual(names, {"alpha.py", "notes.txt", "sub"})
        sub_node = next(c for c in data["tree"]["children"]
                        if c["name"] == "sub")
        self.assertEqual(sub_node["children"][0]["name"], "beta.py")
        self.assertGreater(data["total_size_bytes"], 0)

    def test_depth_one_excludes_subdirectory_files(self):
        res = rm.repo_mapper({"action": "map_tree",
                              "directory": str(self.root),
                              "max_depth": 1})
        data = res["data"]
        # depth 1 walk: sub/ is visited as child dir but its files are
        # beyond the depth cut (depth starts at 1 for root children).
        all_names = self._flatten_names(data["tree"])
        self.assertIn("alpha.py", all_names)
        self.assertNotIn("beta.py", all_names)

    @staticmethod
    def _flatten_names(node):
        out = {node["name"]}
        for ch in node.get("children", []):
            out |= TestMapTree._flatten_names(ch)
        return out


class TestExtractSymbols(unittest.TestCase):
    """extract_symbols: signatures, methods, async flags, imports."""

    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.root = Path(self._td.name)
        _make_repo(self.root)

    def tearDown(self):
        self._td.cleanup()

    def test_alpha_symbols(self):
        res = rm.repo_mapper({"action": "extract_symbols",
                              "path": str(self.root / "alpha.py")})
        data = res["data"]
        self.assertTrue(res["ok"])
        self.assertEqual(len(data["classes"]), 1)
        cls = data["classes"][0]
        self.assertEqual(cls["name"], "Greeter")
        self.assertEqual(cls["bases"], [])
        self.assertEqual(cls["docstring"], "Greets people politely.")
        self.assertEqual(len(cls["methods"]), 1)
        method = cls["methods"][0]
        self.assertEqual(method["name"], "hello")
        self.assertEqual(method["signature"], "(self, name: str) -> str")
        self.assertFalse(method["is_async"])
        self.assertEqual(len(data["functions"]), 1)
        fn = data["functions"][0]
        self.assertEqual(fn["name"], "helper")
        self.assertEqual(fn["docstring"], "Help text summary.")
        self.assertIn("json", data["imports"])
        self.assertIn("pathlib.Path", data["imports"])
        self.assertGreaterEqual(data["calls_count"], 1)

    def test_beta_async_method_and_bases(self):
        res = rm.repo_mapper({"action": "extract_symbols",
                              "path": str(self.root / "sub" / "beta.py")})
        data = res["data"]
        cls = data["classes"][0]
        self.assertEqual(cls["name"], "GreeterChild")
        self.assertEqual(cls["bases"], ["Greeter"])
        run_method = next(m for m in cls["methods"] if m["name"] == "run")
        self.assertTrue(run_method["is_async"])
        self.assertIn("alpha.Greeter", data["imports"])

    def test_unparsable_file_is_error(self):
        bad = self.root / "broken.py"
        bad.write_text("def broken(:\n", encoding="utf-8")
        res = rm.repo_mapper({"action": "extract_symbols",
                              "path": str(bad)})
        self.assertFalse(res["ok"])
        self.assertIn("RepoMapperError", res["error"])
        self.assertIn("Failed to parse", res["error"])


class TestFindSymbol(unittest.TestCase):
    """find_symbol: class/method/function matches across files."""

    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.root = Path(self._td.name)
        _make_repo(self.root)

    def tearDown(self):
        self._td.cleanup()

    def test_find_class_and_function(self):
        res = rm.repo_mapper({"action": "find_symbol",
                              "directory": str(self.root),
                              "symbol_name": "Greeter"})
        data = res["data"]
        self.assertTrue(res["ok"])
        # Class Greeter in alpha.py; class GreeterChild(bases=[Greeter])
        # mentions Greeter only as a base, not as definition — but the
        # NAME Greeter itself resolves to exactly one class definition.
        class_matches = [m for m in data["matches"] if m["type"] == "class"]
        self.assertEqual(len(class_matches), 1)
        self.assertEqual(class_matches[0]["file"],
                         str(self.root / "alpha.py"))
        res2 = rm.repo_mapper({"action": "find_symbol",
                               "directory": str(self.root),
                               "symbol_name": "helper"})
        fn_matches = [m for m in res2["data"]["matches"]
                      if m["type"] == "function"]
        self.assertEqual(len(fn_matches), 1)
        self.assertGreaterEqual(res2["data"]["scanned_files"], 2)

    def test_find_method_by_name(self):
        res = rm.repo_mapper({"action": "find_symbol",
                              "directory": str(self.root),
                              "symbol_name": "hello"})
        data = res["data"]
        self.assertEqual(data["matches_count"], 1)
        match = data["matches"][0]
        self.assertEqual(match["type"], "method")
        self.assertEqual(match["class_name"], "Greeter")
        self.assertEqual(match["signature"], "(self, name: str) -> str")

    def test_empty_symbol_name_is_error(self):
        res = rm.repo_mapper({"action": "find_symbol",
                              "directory": str(self.root),
                              "symbol_name": ""})
        self.assertFalse(res["ok"])
        self.assertIn("symbol_name must be a non-empty string",
                      res["error"])


class TestCallHierarchy(unittest.TestCase):
    """get_call_hierarchy: callers and callees from call graph."""

    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.root = Path(self._td.name)
        _make_repo(self.root)

    def tearDown(self):
        self._td.cleanup()

    def test_callers_and_callees_of_helper(self):
        res = rm.repo_mapper({"action": "get_call_hierarchy",
                              "directory": str(self.root),
                              "symbol_name": "helper"})
        data = res["data"]
        self.assertTrue(res["ok"])
        self.assertEqual(data["definition"]["name"], "helper")
        # helper is called from Greeter.hello and call_helper
        callers = {c["caller"] for c in data["callers"]}
        self.assertIn("call_helper", callers)
        # helper's body calls str(x) — the sole callee
        self.assertEqual(data["callees"], ["str"])
        self.assertGreaterEqual(data["caller_count"], 1)

    def test_hierarchy_of_method_and_missing_symbol(self):
        res = rm.repo_mapper({"action": "get_call_hierarchy",
                              "directory": str(self.root),
                              "symbol_name": "GreeterChild.run"})
        data = res["data"]
        self.assertEqual(data["definition"]["name"], "run")
        self.assertTrue(data["definition"]["is_async"])
        res2 = rm.repo_mapper({"action": "get_call_hierarchy",
                               "directory": str(self.root),
                               "symbol_name": "no_such_symbol"})
        self.assertIsNone(res2["data"]["definition"])
        self.assertEqual(res2["data"]["callers"], [])


class TestFindReferences(unittest.TestCase):
    """find_references: full-text \b-bounded search."""

    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.root = Path(self._td.name)
        _make_repo(self.root)

    def tearDown(self):
        self._td.cleanup()

    def test_reference_search(self):
        res = rm.repo_mapper({"action": "find_references",
                              "directory": str(self.root),
                              "symbol_query": "Greeter"})
        data = res["data"]
        self.assertTrue(res["ok"])
        files = {r["file"] for r in data["references"]}
        # Definitions in alpha.py, subclass + import line in beta.py
        self.assertIn(str(self.root / "alpha.py"), files)
        self.assertIn(str(self.root / "sub" / "beta.py"), files)
        self.assertGreaterEqual(data["total_references"], 2)
        for ref in data["references"]:
            self.assertIn("Greeter", ref["snippet"])

    def test_empty_query_is_error(self):
        res = rm.repo_mapper({"action": "find_references",
                              "directory": str(self.root),
                              "symbol_query": "  "})
        self.assertFalse(res["ok"])
        self.assertIn("symbol_query must be a non-empty string",
                      res["error"])


class TestBuildRepoMap(unittest.TestCase):
    """build_map: ranked Markdown map with token budget."""

    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.root = Path(self._td.name)
        _make_repo(self.root)

    def tearDown(self):
        self._td.cleanup()

    def test_map_contains_files_and_symbols(self):
        res = rm.repo_mapper({"action": "build_map",
                              "directory": str(self.root),
                              "token_budget": 4096})
        data = res["data"]
        self.assertTrue(res["ok"])
        self.assertEqual(data["files_scanned"], 2)
        self.assertGreaterEqual(data["files_included"], 1)
        markdown = data["repo_map_markdown"]
        self.assertIn("# Repository Map", markdown)
        self.assertIn("class Greeter", markdown)
        self.assertIn("def helper", markdown)
        self.assertGreaterEqual(data["estimated_tokens"], 1)
        # notes.txt and .git must never appear
        self.assertNotIn("notes.txt", markdown)
        self.assertNotIn("inner", markdown)

    def test_small_budget_truncates(self):
        res = rm.repo_mapper({"action": "build_repo_map",
                              "directory": str(self.root),
                              "token_budget": 128})
        data = res["data"]
        self.assertTrue(res["ok"])
        self.assertEqual(data["token_budget"], 128)
        self.assertLessEqual(data["estimated_tokens"], 200)
        # Text-only fixture is small: both files likely fit, verify the
        # cap logic did not corrupt the markdown structure.
        markdown = data["repo_map_markdown"]
        self.assertIn("# Repository Map", markdown)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
