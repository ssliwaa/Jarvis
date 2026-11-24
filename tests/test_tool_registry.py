"""tool_registry: module discovery, validation and run-isolation contracts.

The envelope completion is pinned by test_tool_registry_envelope.py; this
suite pins the registry mechanics around it: handler signature dispatch
(single argument, named context, positional context), TOOL dict validation
(name shape, collisions, description, object schema, callable handler),
loading isolation (a broken module never takes down its neighbours), the
disabled-state persistence across instances, declaration filtering against
existing and disabled names, approval reasons, and the error wrapping of
ToolRegistry.run (including the SystemExit and KeyboardInterrupt paths).
"""
import json
import tempfile
import unittest
from pathlib import Path

from tool_registry import ModuleTool, ToolRegistry, ToolRegistryError, normalize_envelope

GOOD_MODULE = '''
def handler(arguments):
    return {"ok": True, "note": "ran"}

TOOL = {
    "name": "good_tool",
    "description": "A well-formed module tool.",
    "input_schema": {"type": "object", "properties": {}},
    "handler": handler,
    "approval": True,
}
'''


class RegistryTestCase(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.directory = self.root / "operator_modules"
        self.state = self.root / "state" / "operator-modules.json"
        self.registry = None  # built by write_and_load()

    def write_module(self, filename: str, body: str) -> Path:
        self.directory.mkdir(parents=True, exist_ok=True)
        path = self.directory / filename
        path.write_text(body, encoding="utf-8")
        return path

    def write_and_load(self) -> ToolRegistry:
        self.registry = ToolRegistry(directory=self.directory, state_path=self.state)
        return self.registry


class HandlerDispatchTests(RegistryTestCase):
    def test_single_argument_handler_receives_arguments(self):
        seen = {}

        def handler(arguments):
            seen["arguments"] = arguments
            return {"ok": True}
        tool = ModuleTool("t1", "d", {"type": "object"}, handler,
                          Path("/nowhere/t1.py"))
        envelope = tool.run({"a": 1})
        self.assertEqual(seen["arguments"], {"a": 1})
        self.assertTrue(envelope["ok"])

    def test_named_context_parameter_is_passed_as_keyword(self):
        seen = {}

        def handler(arguments, context=None):
            seen["context"] = context
            seen["arguments"] = arguments
            return {"ok": True, "saw": context}
        tool = ModuleTool("t2", "d", {"type": "object"}, handler,
                          Path("/nowhere/t2.py"))
        tool.run({"a": 1}, context={"caller": "operator"})
        self.assertEqual(seen["context"], {"caller": "operator"})
        self.assertEqual(seen["arguments"], {"a": 1})

    def test_positional_second_parameter_receives_context(self):
        seen = {}

        def handler(arguments, whatever):
            seen["whatever"] = whatever
            return {"ok": True}
        tool = ModuleTool("t3", "d", {"type": "object"}, handler,
                          Path("/nowhere/t3.py"))
        tool.run({}, context={"ctx": 7})
        self.assertEqual(seen["whatever"], {"ctx": 7})


class ModuleValidationTests(RegistryTestCase):
    def test_wellformed_module_loads_with_approval_flag(self):
        self.write_module("mod_good.py", GOOD_MODULE)
        registry = self.write_and_load()
        self.assertEqual(registry.errors, [])
        self.assertTrue(registry.has("good_tool"))
        tool = registry.get("good_tool")
        self.assertTrue(tool.approval)
        self.assertEqual(registry.approval_reason("good_tool"),
                         "Module tool good_tool asks for approval.")
        declaration = registry.declarations()[0]
        self.assertEqual(declaration["name"], "good_tool")
        self.assertEqual(declaration["input_schema"], {"type": "object", "properties": {}})

    def test_invalid_modules_are_named_and_isolated(self):
        self.write_module("mod_broken.py", "raise RuntimeError('import boom')\n")
        self.write_module("mod_good.py", GOOD_MODULE)
        registry = self.write_and_load()
        self.assertTrue(registry.has("good_tool"))
        self.assertEqual(len(registry.errors), 1)
        self.assertIn("mod_broken.py", registry.errors[0])
        self.assertIn("RuntimeError", registry.errors[0])

    def test_tool_dict_shape_is_enforced(self):
        cases = {
            "mod_noname.py": 'TOOL = {"description": "d", "handler": lambda a: None}',
            "mod_badname.py": 'TOOL = {"name": "invalid-name", "description": "d", "handler": lambda a: None}',
            "mod_notool.py": 'OTHER = {}',
            "mod_nodesc.py": 'TOOL = {"name": "t_desc", "handler": lambda a: None}',
            "mod_noschema.py": 'TOOL = {"name": "t_schema", "description": "d", '
                               '"input_schema": {"type": "array"}, "handler": lambda a: None}',
            "mod_nohandler.py": 'TOOL = {"name": "t_handler", "description": "d"}',
        }
        for filename, body in cases.items():
            self.write_module(filename, body)
        registry = self.write_and_load()
        self.assertEqual(registry.list(), [])
        self.assertEqual(len(registry.errors), len(cases))

    def test_duplicate_names_and_ignored_files(self):
        self.write_module("mod_first.py", GOOD_MODULE)
        self.write_module("mod_second.py", GOOD_MODULE)   # same name -> collision
        self.write_module("__init__.py", "raise RuntimeError('must not load')")
        self.write_module("_private.py", "raise RuntimeError('must not load')")
        registry = self.write_and_load()
        self.assertTrue(registry.has("good_tool"))
        self.assertEqual(len(registry.errors), 1)
        self.assertIn("collides", registry.errors[0])


class RunIsolationTests(RegistryTestCase):
    def test_unknown_and_disabled_tools_raise_cleanly(self):
        self.write_module("mod_good.py", GOOD_MODULE)
        registry = self.write_and_load()
        with self.assertRaisesRegex(ToolRegistryError, "No module tool"):
            registry.run("nonexistent", {})
        # set_enabled answers with the new state, not with success.
        self.assertFalse(registry.set_enabled("good_tool", False))
        self.assertIn("good_tool", registry.disabled)
        with self.assertRaisesRegex(ToolRegistryError, "disabled"):
            registry.run("good_tool", {})
        # Disabled tools disappear from declarations until re-enabled.
        self.assertEqual(registry.declarations(), [])
        self.assertTrue(registry.set_enabled("good_tool", True))
        self.assertEqual(len(registry.declarations()), 1)

    def test_handler_exceptions_are_wrapped_with_the_tool_name(self):
        self.write_module("mod_boom.py", '''
def handler(arguments):
    raise ValueError("bad input inside handler")

TOOL = {"name": "boom_tool", "description": "d",
        "input_schema": {"type": "object"}, "handler": handler}
''')
        registry = self.write_and_load()
        with self.assertRaises(ToolRegistryError) as caught:
            registry.run("boom_tool", {})
        self.assertIn("Module tool boom_tool failed", str(caught.exception))
        self.assertIn("bad input inside handler", str(caught.exception))

    def test_systemexit_is_wrapped_and_keyboardinterrupt_is_not(self):
        self.write_module("mod_exit.py", '''
import sys

def handler(arguments):
    sys.exit(0)

TOOL = {"name": "exit_tool", "description": "d",
        "input_schema": {"type": "object"}, "handler": handler}
''')
        registry = self.write_and_load()
        with self.assertRaises(ToolRegistryError) as caught:
            registry.run("exit_tool", {})
        self.assertIn("Module tool exit_tool failed", str(caught.exception))
        self.assertIn("SystemExit", str(caught.exception))

        def interrupted(arguments):
            raise KeyboardInterrupt
        tool = ModuleTool("interrupt", "d", {"type": "object"}, interrupted,
                          Path("/nowhere/i.py"))
        with self.assertRaises(KeyboardInterrupt):
            tool.run({})

    def test_run_completes_the_envelope_after_dispatch(self):
        self.write_module("mod_good.py", GOOD_MODULE)
        registry = self.write_and_load()
        envelope = registry.run("good_tool", {})
        self.assertEqual(envelope, {"ok": True, "success": True,
                                    "data": {"note": "ran"},
                                    "result": {"note": "ran"},
                                    "error": None, "note": "ran"})


class StatePersistenceTests(RegistryTestCase):
    def test_disabled_state_survives_a_new_instance(self):
        self.write_module("mod_good.py", GOOD_MODULE)
        first = ToolRegistry(directory=self.directory, state_path=self.state)
        first.set_enabled("good_tool", False)
        second = ToolRegistry(directory=self.directory, state_path=self.state)
        self.assertIn("good_tool", second.disabled)
        with self.assertRaisesRegex(ToolRegistryError, "disabled"):
            second.run("good_tool", {})
        # A re-enable persists too.
        second.set_enabled("good_tool", True)
        third = ToolRegistry(directory=self.directory, state_path=self.state)
        self.assertNotIn("good_tool", third.disabled)

    def test_corrupt_state_resets_to_empty(self):
        self.state.parent.mkdir(parents=True, exist_ok=True)
        self.state.write_text("{not json", encoding="utf-8")
        registry = ToolRegistry(directory=self.directory, state_path=self.state)
        self.assertEqual(registry.disabled, set())

    def test_state_file_is_owner_only(self):
        self.write_module("mod_good.py", GOOD_MODULE)
        registry = self.write_and_load()
        registry.set_enabled("good_tool", False)
        if self.state.exists():
            mode = self.state.stat().st_mode & 0o777
            self.assertEqual(mode, 0o600)
        payload = json.loads(self.state.read_text(encoding="utf-8"))
        self.assertEqual(payload, {"disabled": ["good_tool"]})


class EnvelopeEdgeTests(RegistryTestCase):
    def test_failed_dict_without_error_gets_one_named(self):
        normalized = normalize_envelope("mood", {"ok": False, "data": {"x": 1}})
        self.assertEqual(normalized["error"], "unspecified error in module tool mood")
        self.assertFalse(normalized["success"])
        # Original keys always survive the completion.
        self.assertEqual(normalized["data"], {"x": 1})

    def test_data_only_and_result_only_mirror_each_other(self):
        data_only = normalize_envelope("mod", {"ok": True, "data": {"a": 1}, "z": 2})
        self.assertEqual(data_only["result"], {"a": 1})
        self.assertEqual(data_only["z"], 2)
        result_only = normalize_envelope("mod", {"ok": True, "result": "plain"})
        self.assertEqual(result_only["data"], "plain")


if __name__ == "__main__":
    unittest.main()
