"""Automated error-path suite for operator_modules/op_schema_guard.py.

Completes raise coverage for the schema/regex guard operator:
path-validation branches behind audit_schema (non-string, blank,
null-byte and over-long module paths), the repair_json type guard for
json_text, and the module-spec loading guards.

Two raises need simulated environment failures because no natural
argument can trigger them on this platform:
- line 148 (Path resolution error): os.path.realpath is patched to
  raise OSError, proving the validator degrades into a controlled
  ValueError instead of a raw traceback when the resolution layer
  fails (pathological filesystems, ELOOP-style errors).
- line 535 (Cannot load module spec): importlib.util.spec_from_file_location
  is patched to return None, covering an unusable loader state for an
  otherwise valid .py file.

100% offline and deterministic; all paths live in test-private
temporary directories under /tmp (inside ALLOWED_ROOTS).
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

import operator_modules.op_schema_guard as sg


class TestModulePathValidationRaises(unittest.TestCase):
    """_validate_path guards reached via audit_schema."""

    def test_non_string_module_path_rejected(self):
        # Line 135: int is truthy for the dispatcher, so it reaches
        # the validator's isinstance guard.
        res = sg.schema_guard({"action": "audit_schema", "module_path": 123})
        self.assertFalse(res["ok"])
        self.assertIn("ValueError", res["error"])
        self.assertIn("File path must be a valid string or Path.",
                      res["error"])

    def test_whitespace_module_path_rejected(self):
        # Line 138: '   ' passes the dispatcher's truthiness check but
        # fails the validator's blank-string test.
        res = sg.schema_guard({"action": "audit_schema",
                               "module_path": "   "})
        self.assertFalse(res["ok"])
        self.assertIn("ValueError", res["error"])
        self.assertIn("File path cannot be empty.", res["error"])

    def test_null_byte_module_path_rejected(self):
        # Line 140 (null-byte variant).
        res = sg.schema_guard({"action": "audit_schema",
                               "module_path": "evil\x00.py"})
        self.assertFalse(res["ok"])
        self.assertIn("ValueError", res["error"])
        self.assertIn("Invalid path string:", res["error"])

    def test_overlong_module_path_rejected(self):
        # Line 140 (length limit variant, > 4096 chars).
        res = sg.schema_guard({"action": "audit_schema",
                               "module_path": "y" * 5000})
        self.assertFalse(res["ok"])
        self.assertIn("ValueError", res["error"])
        self.assertIn("exceeds length limit", res["error"])


class TestRepairJsonRaises(unittest.TestCase):
    """repair_json type guard."""

    def test_non_string_json_text_rejected(self):
        # Line 329: dict/list payloads are accepted and dumped, but any
        # other non-string type is rejected.
        res = sg.schema_guard({"action": "repair_json", "json_text": 12345,
                               "schema": {"type": "object"}})
        self.assertFalse(res["ok"])
        self.assertIn("SchemaGuardError", res["error"])
        self.assertIn("Parameter 'json_text' must be a string.",
                      res["error"])

    def test_dict_payload_accepted_for_contrast(self):
        # Contrast anchor: dict payloads take the dump path, proving
        # the raise guards only genuinely unsupported types.
        res = sg.schema_guard({"action": "repair_json",
                               "json_text": {"a": 1},
                               "schema": {"type": "object"}})
        self.assertTrue(res["ok"])
        self.assertIsNone(res["error"])


class TestModuleLoadingRaises(unittest.TestCase):
    """Module spec loading guards for audit_schema."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.mod_path = Path(self._tmp.name) / "audit_target.py"
        self.mod_path.write_text("TOOL = {'name': 'x'}\n",
                                 encoding="utf-8")

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_unusable_module_spec_reported(self):
        # Line 535: unusable spec state (loader missing) must surface
        # as a controlled SchemaGuardError.
        with mock.patch("importlib.util.spec_from_file_location",
                        return_value=None):
            res = sg.schema_guard({"action": "audit_schema",
                                   "module_path": str(self.mod_path)})
        self.assertFalse(res["ok"])
        self.assertIn("SchemaGuardError", res["error"])
        self.assertIn("Cannot load module spec", res["error"])
        self.assertIn("audit_target.py", res["error"])

    def test_realpath_failure_reported(self):
        # Line 148: resolution-layer failure surfaces as a controlled
        # ValueError, chained from the original error.
        with mock.patch.object(sg.os.path, "realpath",
                               side_effect=OSError("simulated ELOOP")):
            res = sg.schema_guard({"action": "audit_schema",
                                   "module_path": str(self.mod_path)})
        self.assertFalse(res["ok"])
        self.assertIn("ValueError", res["error"])
        self.assertIn("Path resolution error:", res["error"])
        self.assertIn("simulated ELOOP", res["error"])

    def test_control_audit_without_mocks(self):
        # Contrast anchor: the same module audited without mocks runs
        # past both guards (it fails later on schema quality with the
        # expected envelope, proving the guards are not omnipresent).
        res = sg.schema_guard({"action": "audit_schema",
                               "module_path": str(self.mod_path)})
        self.assertTrue(
            res["ok"]
            or "Target schema must be a dictionary." in res["error"]
            or "does not export a TOOL dictionary." in res["error"],
            f"unexpected control outcome: {res['error']!r}",
        )


class TestErrorEnvelopeShape(unittest.TestCase):
    """Error envelope contract shared by all schema_guard failures."""

    def test_error_envelope_shape(self):
        res = sg.schema_guard({"action": "repair_json",
                               "json_text": 7, "schema": {}})
        self.assertEqual(set(res), {"ok", "success", "data", "result",
                                    "error"})
        self.assertFalse(res["ok"])
        self.assertFalse(res["success"])
        self.assertIsNone(res["data"])
        self.assertIsNone(res["result"])
        self.assertIsInstance(res["error"], str)


if __name__ == "__main__":
    unittest.main()
