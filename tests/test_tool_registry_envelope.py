"""ToolRegistry.run completes every module output to the PROJECT.md envelope.

Legacy modules return partial dicts (``{"ok": True, ...payload}``, sometimes
with ``result``/``error``); op-tier modules already return the full 5-key
envelope. The registry normalizes at the boundary — additively, so legacy task
keys survive and full-envelope modules pass through untouched.
"""
import tempfile
import unittest
from pathlib import Path

import tool_registry


class _Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.modules_dir = Path(self.tmp.name) / "modules"
        self.modules_dir.mkdir(parents=True)
        self.state = Path(self.tmp.name) / "state.json"
        self.state.write_text("{}", encoding="utf-8")

    def _write_module(self, name: str, body: str):
        (self.modules_dir / f"{name}.py").write_text(body, encoding="utf-8")
        return tool_registry.ToolRegistry(directory=self.modules_dir, state_path=self.state)


class EnvelopeNormalizationTests(_Base):
    def test_legacy_ok_only_dict_gets_the_five_keys_and_payload(self):
        reg = self._write_module("legacy_ok", (
            "TOOL = {'name': 'legacy_ok', 'description': 'd',\n"
            "        'input_schema': {'type': 'object', 'properties': {},\n"
            "                          'additionalProperties': False},\n"
            "        'handler': lambda a: {'ok': True, 'temperature': 18}}\n"
        ))
        out = reg.run("legacy_ok", {})
        self.assertEqual(out["ok"], True)
        self.assertEqual(out["success"], True)
        self.assertIsNone(out["error"])
        self.assertEqual(out["data"], {"temperature": 18})
        self.assertEqual(out["result"], {"temperature": 18})
        self.assertEqual(out["temperature"], 18)  # legacy keys never removed

    def test_legacy_result_dict_gets_data_mirror(self):
        reg = self._write_module("legacy_result", (
            "TOOL = {'name': 'legacy_result', 'description': 'd',\n"
            "        'input_schema': {'type': 'object', 'properties': {},\n"
            "                          'additionalProperties': False},\n"
            "        'handler': lambda a: {'ok': True, 'result': {'branches': 2}}}\n"
        ))
        out = reg.run("legacy_result", {})
        self.assertEqual(out["data"], {"branches": 2})
        self.assertEqual(out["result"], {"branches": 2})
        self.assertIsNone(out["error"])

    def test_legacy_error_gets_normalized_null_payload(self):
        reg = self._write_module("legacy_err", (
            "TOOL = {'name': 'legacy_err', 'description': 'd',\n"
            "        'input_schema': {'type': 'object', 'properties': {},\n"
            "                          'additionalProperties': False},\n"
            "        'handler': lambda a: {'ok': False, 'error': 'ValueError: bad'}}\n"
        ))
        out = reg.run("legacy_err", {})
        self.assertFalse(out["ok"] or out["success"])
        self.assertIn("ValueError", out["error"])
        self.assertIsNone(out["data"])
        self.assertIsNone(out["result"])

    def test_full_envelope_module_passes_through_identical(self):
        full = {"ok": True, "success": True, "data": {"x": 1}, "result": {"x": 1}, "error": None}
        source = ("import json\n"
                  "FULL = " + repr(full) + "\n"
                  "TOOL = {'name': 'full_env', 'description': 'd',\n"
                  "        'input_schema': {'type': 'object', 'properties': {},\n"
                  "                          'additionalProperties': False},\n"
                  "        'handler': lambda a: dict(FULL)}\n")
        reg = self._write_module("full_env", source)
        out = reg.run("full_env", {})
        self.assertEqual(out, full)
        self.assertEqual(tool_registry.normalize_envelope("x", dict(full)), full)

    def test_non_dict_output_is_wrapped_as_success_payload(self):
        reg = self._write_module("plain_str", (
            "TOOL = {'name': 'plain_str', 'description': 'd',\n"
            "        'input_schema': {'type': 'object', 'properties': {},\n"
                  "                  'additionalProperties': False},\n"
                  "        'handler': lambda a: 'hello'}\n"
        ))
        out = reg.run("plain_str", {})
        self.assertEqual(out["data"], "hello")
        self.assertEqual(out["result"], "hello")
        self.assertTrue(out["ok"] and out["success"])
        self.assertIsNone(out["error"])

    def test_ok_missing_plus_error_is_still_reported(self):
        reg = self._write_module("no_status", (
            "def handler(a):\n"
            "    return {'outcome': 'done'}\n"
            "TOOL = {'name': 'no_status', 'description': 'd',\n"
            "        'input_schema': {'type': 'object', 'properties': {},\n"
            "                          'additionalProperties': False},\n"
            "        'handler': handler}\n"
        ))
        out = reg.run("no_status", {})
        self.assertTrue(out["ok"] and out["success"])
        self.assertIsNone(out["error"])
        self.assertEqual(out["data"], {"outcome": "done"})


if __name__ == "__main__":
    unittest.main()
