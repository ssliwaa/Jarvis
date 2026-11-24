"""Automated test suite for operator_modules/op_schema_guard.py.

Tests the dispatch contract, 5-key envelope, recursive schema validation
(types, required, additionalProperties, numeric/string constraints),
heuristic JSON repair (fences, trailing commas, single quotes, unquoted
keys, embedded extraction, schema-driven pruning + defaults), regex FSM
prefix conformance, deterministic repair-prompt generation, operator
schema auditing (inline schema and module_path TOOL inspection), and
export_path write + security guardrails. 100% offline: pure stdlib
computation, filesystem limited to a test tmpdir.
"""

from __future__ import annotations

import json
import tempfile
import os
import unittest
SANDBOXED = os.environ.get("JARVIS_VERIFY_SANDBOX") == "1"
from pathlib import Path

import operator_modules.op_schema_guard as sg

GOOD_SCHEMA = {
    "type": "object",
    "properties": {
        "name": {"type": "string", "description": "entity name"},
        "port": {"type": "integer", "description": "listen port"},
    },
    "required": ["name", "port"],
    "additionalProperties": False,
}


class TestDispatch(unittest.TestCase):
    """Handler contract: argument validation and success/error envelopes."""

    def test_rejects_non_dict_arguments(self):
        res = sg.schema_guard("not-a-dict")
        self.assertFalse(res["ok"])
        self.assertIsNone(res["data"])
        self.assertIn("JSON dictionary", res["error"])

    def test_rejects_disallowed_extra_keys(self):
        res = sg.schema_guard({"action": "validate_json",
                               "json_text": "{}", "rogue": 1})
        self.assertFalse(res["ok"])
        self.assertIn("Disallowed additional arguments", res["error"])
        self.assertIn("rogue", res["error"])

    def test_rejects_invalid_action(self):
        res = sg.schema_guard({"action": "nope"})
        self.assertFalse(res["ok"])
        self.assertIn("Invalid or missing action 'nope'", res["error"])
        self.assertIn("validate_json", res["error"])

    def test_success_envelope_shape(self):
        res = sg.schema_guard({"action": "validate_json",
                               "json_text": '{"a": 1}'})
        self.assertEqual(set(res), {"ok", "success", "data", "result", "error"})
        self.assertTrue(res["ok"])
        self.assertTrue(res["success"])
        self.assertIsNone(res["error"])
        self.assertEqual(res["data"], res["result"])


class TestValidateJson(unittest.TestCase):
    """validate_json: required params, syntax branch, recursive checks."""

    def test_missing_payload_is_error(self):
        res = sg.schema_guard({"action": "validate_json"})
        self.assertFalse(res["ok"])
        self.assertIn("Missing required parameter", res["error"])

    def test_invalid_payload_type_is_error(self):
        res = sg.schema_guard({"action": "validate_json", "payload": 42})
        self.assertFalse(res["ok"])
        self.assertIn("must be a JSON string, object, or array", res["error"])

    def test_syntax_check_without_schema(self):
        res = sg.schema_guard({"action": "validate_json",
                               "json_text": '{"alpha": [1, 2]}'})
        data = res["data"]
        self.assertTrue(data["valid"])
        self.assertIsNone(data["syntax_error"])
        self.assertEqual(data["parsed_data"], {"alpha": [1, 2]})
        self.assertEqual(data["errors"], [])

    def test_syntax_error_branch(self):
        res = sg.schema_guard({"action": "validate_json",
                               "json_text": '{"broken": '})
        data = res["data"]
        self.assertFalse(data["valid"])
        self.assertIn("JSONDecodeError at line", data["syntax_error"])
        self.assertIsNone(data["parsed_data"])
        self.assertTrue(data["errors"])

    def test_valid_payload_full_check(self):
        res = sg.schema_guard({
            "action": "validate_json",
            "payload": {"name": "jarvis", "port": 4700},
            "schema": GOOD_SCHEMA,
        })
        data = res["data"]
        self.assertTrue(data["valid"])
        self.assertEqual(data["missing_required"], [])
        self.assertEqual(data["disallowed_extra_keys"], [])
        self.assertEqual(data["type_mismatches"], [])

    def test_missing_disallowed_and_boolean_as_integer(self):
        schema = {
            "type": "object",
            "properties": {
                "count": {"type": "integer"},
                "label": {"type": "string"},
            },
            "required": ["count", "label"],
            "additionalProperties": False,
        }
        res = sg.schema_guard({
            "action": "validate_json",
            "payload": {"count": True, "extra_key": "x"},
            "schema": schema,
        })
        data = res["data"]
        self.assertFalse(data["valid"])
        self.assertEqual(data["missing_required"], ["label"])
        self.assertEqual(data["disallowed_extra_keys"], ["extra_key"])
        self.assertEqual(len(data["type_mismatches"]), 1)
        tm = data["type_mismatches"][0]
        self.assertEqual(tm["expected"], "integer")
        self.assertEqual(tm["got"], "boolean")
        self.assertTrue(any("boolean" in e for e in data["errors"]))

    def test_nested_array_item_type_mismatch(self):
        schema = {
            "type": "object",
            "properties": {
                "tags": {"type": "array", "items": {"type": "string"}},
            },
            "required": ["tags"],
        }
        res = sg.schema_guard({
            "action": "validate_json",
            "payload": {"tags": ["ok", 5]},
            "schema": schema,
        })
        data = res["data"]
        self.assertFalse(data["valid"])
        tm = data["type_mismatches"][0]
        self.assertEqual(tm["path"], "tags[1]")
        self.assertEqual(tm["expected"], "string")


class TestConstraints(unittest.TestCase):
    """Numeric and string constraint enforcement inside the validator."""

    def test_numeric_bounds_reported(self):
        schema = {
            "type": "object",
            "properties": {
                "port": {"type": "integer", "minimum": 1, "maximum": 65535},
            },
            "required": ["port"],
        }
        res = sg.schema_guard({"action": "validate_json",
                               "payload": {"port": 99999},
                               "schema": schema})
        errors = res["data"]["errors"]
        self.assertFalse(res["data"]["valid"])
        self.assertTrue(any("greater than maximum" in e for e in errors))
        res2 = sg.schema_guard({"action": "validate_json",
                                "payload": {"port": 0},
                                "schema": schema})
        self.assertTrue(any("less than minimum" in e
                            for e in res2["data"]["errors"]))

    def test_string_constraints_reported(self):
        schema = {
            "type": "object",
            "properties": {
                "code": {"type": "string", "minLength": 3, "maxLength": 6,
                         "pattern": "^[A-Z]+$", "enum": ["ABC", "XYZ"]},
            },
            "required": ["code"],
        }
        res = sg.schema_guard({"action": "validate_json",
                               "payload": {"code": "ab"},
                               "schema": schema})
        errors = res["data"]["errors"]
        self.assertFalse(res["data"]["valid"])
        self.assertTrue(any("less than minLength" in e for e in errors))
        self.assertTrue(any("does not match pattern" in e for e in errors))
        self.assertTrue(any("not in allowed enum" in e for e in errors))
        res2 = sg.schema_guard({"action": "validate_json",
                                "payload": {"code": "ABCDEFG"},
                                "schema": schema})
        self.assertTrue(any("exceeds maxLength" in e
                            for e in res2["data"]["errors"]))


class TestRepairJson(unittest.TestCase):
    """repair_json: heuristic fixes and schema-driven structural repair."""

    def test_fences_trailing_commas_and_single_quotes(self):
        raw = "```json\n{'a': 1, 'b': 'x',}\n```"
        res = sg.schema_guard({"action": "repair_json", "json_text": raw})
        data = res["data"]
        self.assertTrue(data["repaired"])
        self.assertEqual(data["parsed_data"], {"a": 1, "b": "x"})
        fixes = data["applied_fixes"]
        self.assertTrue(any("code fences" in f for f in fixes))
        self.assertTrue(any("trailing commas" in f for f in fixes))
        self.assertTrue(any("single quotes" in f for f in fixes))

    def test_embedded_json_extraction(self):
        raw = "Sure, here is the result: {\"ok\": true, \"n\": 2} hope it helps"
        res = sg.schema_guard({"action": "repair_json", "json_text": raw})
        data = res["data"]
        self.assertTrue(data["repaired"])
        self.assertEqual(data["parsed_data"], {"ok": True, "n": 2})
        self.assertTrue(any("embedded JSON" in f for f in data["applied_fixes"]))

    def test_unquoted_keys_fallback(self):
        # Key needs quoting (fallback pass); value quotes get normalized
        # in the single-quote pass first, so both fixes apply in one repair.
        raw = "{status: 'ready'}"
        res = sg.schema_guard({"action": "repair_json", "json_text": raw})
        data = res["data"]
        self.assertTrue(data["repaired"])
        self.assertEqual(data["parsed_data"], {"status": "ready"})
        fixes = data["applied_fixes"]
        self.assertTrue(any("unquoted object keys" in f for f in fixes))
        self.assertTrue(any("single quotes" in f for f in fixes))

    def test_unrepairable_reports_instruction(self):
        raw = "totally not json @@ ["
        res = sg.schema_guard({"action": "repair_json", "json_text": raw})
        data = res["data"]
        self.assertFalse(data["repaired"])
        self.assertIsNone(data["parsed_data"])
        self.assertIn("Failed to repair JSON syntax", data["error"])
        self.assertIn("repair_instruction", data)

    def test_schema_prunes_extra_and_inserts_default(self):
        schema = {
            "type": "object",
            "properties": {
                "name": {"type": "string"},
                "mode": {"type": "string", "default": "auto"},
            },
            "required": ["name", "mode"],
            "additionalProperties": False,
        }
        raw = '{"name": "unit", "junk": 1}'
        res = sg.schema_guard({"action": "repair_json",
                               "json_text": raw, "schema": schema})
        data = res["data"]
        self.assertTrue(data["repaired"])
        self.assertEqual(data["parsed_data"], {"name": "unit", "mode": "auto"})
        fixes = data["applied_fixes"]
        self.assertTrue(any("Pruned disallowed additional property 'junk'" in f
                            for f in fixes))
        self.assertTrue(any("declared default for required property 'mode'" in f
                            for f in fixes))
        self.assertIn("conforms to schema", data["repair_instruction"])


class TestEnforceRegex(unittest.TestCase):
    """enforce_regex: full match, search, FSM prefix conformance."""

    def test_missing_or_invalid_pattern_is_error(self):
        res = sg.schema_guard({"action": "enforce_regex",
                               "payload": "ABC"})
        self.assertFalse(res["ok"])
        self.assertIn("regex_pattern", res["error"])
        res2 = sg.schema_guard({"action": "enforce_regex",
                                "payload": "ABC", "regex_pattern": "("})
        self.assertFalse(res2["ok"])
        self.assertIn("Invalid regex_pattern", res2["error"])

    def test_full_match_and_length(self):
        res = sg.schema_guard({"action": "enforce_regex",
                               "payload": "ABC-1234",
                               "regex_pattern": r"[A-Z]{3}-\d{4}"})
        data = res["data"]
        self.assertTrue(data["full_match"])
        self.assertTrue(data["search_match"])
        self.assertTrue(data["is_valid_prefix"])
        self.assertEqual(data["matched_length"], 8)

    def test_partial_string_is_valid_prefix(self):
        res = sg.schema_guard({"action": "enforce_regex",
                               "payload": "AB",
                               "regex_pattern": r"[A-Z]{3}-\d{4}"})
        data = res["data"]
        self.assertFalse(data["full_match"])
        self.assertFalse(data["search_match"])
        self.assertTrue(data["is_valid_prefix"])
        self.assertEqual(data["matched_length"], 0)

    def test_mismatching_candidate_rejected(self):
        res = sg.schema_guard({"action": "enforce_regex",
                               "payload": "12ab",
                               "regex_pattern": r"\d{3}"})
        data = res["data"]
        self.assertFalse(data["full_match"])
        self.assertFalse(data["search_match"])
        self.assertFalse(data["is_valid_prefix"])


class TestRepairPrompt(unittest.TestCase):
    """generate_repair_prompt: deterministic, actionable LLM feedback."""

    def test_missing_schema_is_error(self):
        res = sg.schema_guard({"action": "generate_repair_prompt",
                               "json_text": '{"a": 1}'})
        self.assertFalse(res["ok"])
        self.assertIn("'schema' dictionary is required", res["error"])

    def test_valid_payload_prompt(self):
        res = sg.schema_guard({
            "action": "generate_repair_prompt",
            "json_text": json.dumps({"name": "jarvis", "port": 4700}),
            "schema": GOOD_SCHEMA,
        })
        data = res["data"]
        self.assertTrue(data["is_valid"])
        self.assertEqual(data["validation_errors"], [])
        self.assertIn("already fully valid", data["repair_prompt"])

    def test_invalid_payload_prompt_contains_instructions(self):
        res = sg.schema_guard({
            "action": "generate_repair_prompt",
            "json_text": json.dumps({"name": 5, "rogue": True}),
            "schema": GOOD_SCHEMA,
        })
        data = res["data"]
        self.assertFalse(data["is_valid"])
        prompt = data["repair_prompt"]
        self.assertIn("violated the schema contract", prompt)
        self.assertIn("['port']", prompt)          # missing required
        self.assertIn("['rogue']", prompt)         # disallowed extra key
        self.assertTrue(any("must be of type 'string'" in e or "string" in e
                            for e in data["validation_errors"]))


@unittest.skipIf(SANDBOXED, "needs the developer's local env (vault/Hermes/Piper/desktop); skipped in CI")
class TestAuditSchema(unittest.TestCase):
    """audit_schema: inline schema checks and module_path TOOL inspection."""

    def test_neither_schema_nor_module_is_error(self):
        res = sg.schema_guard({"action": "audit_schema"})
        self.assertFalse(res["ok"])
        self.assertIn("Target schema must be a dictionary", res["error"])

    def test_bad_inline_schema_is_non_compliant(self):
        bad = {"type": "object", "properties": {"action": {"type": "string"}},
               "required": []}
        res = sg.schema_guard({"action": "audit_schema", "schema": bad})
        data = res["data"]
        self.assertFalse(data["compliant"])
        findings = " ".join(data["findings"])
        self.assertIn("additionalProperties", findings)
        self.assertIn("'action' must be listed", findings)
        self.assertIn("missing a 'description'", findings)

    def test_module_without_tool_dict_is_error(self):
        with tempfile.TemporaryDirectory() as td:
            target = Path(td) / "no_tool.py"
            target.write_text("X = 1\n", encoding="utf-8")
            res = sg.schema_guard({"action": "audit_schema",
                                  "module_path": str(target)})
        self.assertFalse(res["ok"])
        self.assertIn("does not export a TOOL dictionary", res["error"])

    def test_module_path_must_be_python_file(self):
        with tempfile.TemporaryDirectory() as td:
            target = Path(td) / "notes.txt"
            target.write_text("not python", encoding="utf-8")
            res = sg.schema_guard({"action": "audit_schema",
                                  "module_path": str(target)})
        self.assertFalse(res["ok"])
        self.assertIn("not an existing Python file", res["error"])

    def test_repo_module_audit_is_compliant(self):
        # The module audited by this very suite exports a standards-
        # compliant TOOL (object, additionalProperties False, action
        # documented in properties + required).
        repo_module = Path(sg.__file__)
        res = sg.schema_guard({"action": "audit_schema",
                               "module_path": str(repo_module)})
        data = res["data"]
        self.assertTrue(res["ok"])
        self.assertEqual(data["tool_name"], "schema_guard")
        self.assertTrue(data["compliant"])
        self.assertEqual(data["findings_count"], 0)
        self.assertTrue(data["has_approval_gate"])
        self.assertTrue(data["has_callable_handler"])


class TestExportPath(unittest.TestCase):
    """export_path: report write inside tmpdir + security guardrails."""

    def test_export_writes_report_file(self):
        with tempfile.TemporaryDirectory() as td:
            target = Path(td) / "report.json"
            res = sg.schema_guard({"action": "validate_json",
                                   "json_text": '{"a": 1}',
                                   "export_path": str(target)})
            self.assertTrue(res["ok"])
            self.assertEqual(res["data"]["exported_to"], str(target))
            self.assertTrue(target.exists())
            loaded = json.loads(target.read_text(encoding="utf-8"))
            self.assertTrue(loaded["valid"])

    def test_export_outside_roots_and_sensitive_rejected(self):
        res = sg.schema_guard({"action": "validate_json",
                               "json_text": "{}",
                               "export_path": "/proc/definitely/no.json"})
        self.assertFalse(res["ok"])
        self.assertIn("PathSecurityError", res["error"])
        res2 = sg.schema_guard({"action": "validate_json",
                                "json_text": "{}",
                                "export_path": "/tmp/sg_test/.ssh/config.json"})
        self.assertFalse(res2["ok"])
        self.assertIn("SensitivePathError", res2["error"])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
