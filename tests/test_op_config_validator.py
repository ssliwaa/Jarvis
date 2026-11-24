"""Automated unit test suite for operator_modules/op_config_validator.py.

Verifies:
1. Tool registration contract, input_schema (additionalProperties: False), and approval=False.
2. Standard 5-key return envelope (ok, success, data, result, error).
3. Feature 21: validate_json (syntax, schema, duplicate keys, ReDoS defenses, type verification).
4. Feature 22: validate_ini (sections, options, interpolation safety, duplicates).
5. Feature 23: validate_dotenv (syntax, variable naming, quoting, template comparison, placeholders).
6. Feature 24: lint_config (trailing whitespace, missing EOF newline, indentation, control characters).
7. Path confinement to ALLOWED_ROOTS, sensitive path blocking, and input size limits.
8. Integration with ToolRegistry dynamic discovery.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import operator_modules.op_config_validator as op_config_validator
from tool_registry import ToolRegistry


class TestOpConfigValidator(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory(dir="/tmp")
        self.root = Path(self.temp_dir.name).resolve()

        # Build sample files
        self.json_path = self.root / "config.json"
        self.json_path.write_text('{"name": "test-app", "port": 8080, "active": true}\n', encoding="utf-8")

        self.ini_path = self.root / "settings.ini"
        self.ini_path.write_text(
            "[DEFAULT]\napp_name = Jarvis\n\n[server]\nhost = 127.0.0.1\nport = 8080\n\n[database]\nhost = 127.0.0.1\nport = 5432\nname = %(app_name)s_db\n",
            encoding="utf-8",
        )

        self.env_path = self.root / ".env"
        self.env_path.write_text("PORT=8080\nDB_URL=localhost:5432\n", encoding="utf-8")

        self.tmpl_path = self.root / ".env.example"
        self.tmpl_path.write_text("PORT=8080\nDB_URL=CHANGEME\nAPI_KEY=YOUR_KEY_HERE\n", encoding="utf-8")

    def tearDown(self):
        self.temp_dir.cleanup()

    def _assert_envelope(self, res: dict, expected_ok: bool):
        """Assert the standard 5-key Jarvis operator envelope structure."""
        self.assertIsInstance(res, dict)
        self.assertIn("ok", res)
        self.assertIn("success", res)
        self.assertIn("data", res)
        self.assertIn("result", res)
        self.assertIn("error", res)
        self.assertEqual(res["ok"], expected_ok)
        self.assertEqual(res["success"], expected_ok)
        if expected_ok:
            self.assertIsNone(res["error"])
            self.assertEqual(res["data"], res["result"])
        else:
            self.assertIsNone(res["data"])
            self.assertIsNone(res["result"])
            self.assertIsInstance(res["error"], str)
            self.assertGreater(len(res["error"]), 0)

    # =========================================================================
    # Contract & Schema Conformance Tests
    # =========================================================================

    def test_01_tool_declaration_contract(self):
        tool = op_config_validator.TOOL
        self.assertEqual(tool["name"], "config_validator")
        self.assertFalse(tool["approval"], "config_validator is an analytical validator and must have approval=False")
        self.assertTrue(callable(tool["handler"]))
        self.assertEqual(tool["input_schema"]["type"], "object")
        self.assertFalse(tool["input_schema"]["additionalProperties"])
        self.assertIn("action", tool["input_schema"]["required"])

    def test_02_schema_actions_enum(self):
        actions = op_config_validator.TOOL["input_schema"]["properties"]["action"]["enum"]
        expected = ["validate_json", "validate_ini", "validate_dotenv", "lint_config"]
        for exp in expected:
            self.assertIn(exp, actions)

    def test_03_unknown_argument_rejected(self):
        res = op_config_validator.config_validator({
            "action": "validate_json",
            "content": "{}",
            "unexpected_arg": "malicious",
        })
        self._assert_envelope(res, False)
        self.assertIn("Unknown argument", res["error"])

    def test_04_missing_or_invalid_action(self):
        res = op_config_validator.config_validator({"action": "invalid_action"})
        self._assert_envelope(res, False)
        self.assertIn("Invalid or missing action", res["error"])

        res_empty = op_config_validator.config_validator({})
        self._assert_envelope(res_empty, False)
        self.assertIn("Invalid or missing action", res_empty["error"])

    def test_05_missing_content_and_path(self):
        res = op_config_validator.config_validator({"action": "validate_json"})
        self._assert_envelope(res, False)
        self.assertIn("Either 'content'", res["error"])

    # =========================================================================
    # Security Perimeter & Path Confinement Tests
    # =========================================================================

    def test_06_path_confinement_outside_allowed_roots(self):
        res = op_config_validator.config_validator({
            "action": "validate_json",
            "path": "/etc/passwd",
        })
        self._assert_envelope(res, False)
        self.assertIn("PathSecurityError", res["error"])

    def test_07_path_traversal_escape_rejected(self):
        res = op_config_validator.config_validator({
            "action": "validate_ini",
            "path": str(self.root / ".." / ".." / "etc" / "passwd"),
        })
        self._assert_envelope(res, False)
        self.assertIn("PathSecurityError", res["error"])

    def test_08_null_byte_in_path_rejected(self):
        res = op_config_validator.config_validator({
            "action": "validate_dotenv",
            "path": str(self.root / "file\0.env"),
        })
        self._assert_envelope(res, False)
        self.assertIn("PathSecurityError", res["error"])

    def test_09_sensitive_path_blocked(self):
        ssh_dir = self.root / ".ssh"
        ssh_dir.mkdir(parents=True, exist_ok=True)
        key_file = ssh_dir / "id_rsa"
        key_file.write_text("private key content", encoding="utf-8")

        res = op_config_validator.config_validator({
            "action": "validate_dotenv",
            "path": str(key_file),
        })
        self._assert_envelope(res, False)
        self.assertIn("SensitivePathError", res["error"])

    def test_10_file_size_limit_exceeded(self):
        huge_content = "x" * (6 * 1024 * 1024)  # 6 MB > 5 MB limit
        res = op_config_validator.config_validator({
            "action": "validate_json",
            "content": huge_content,
        })
        self._assert_envelope(res, False)
        self.assertIn("ConfigSizeError", res["error"])

    # =========================================================================
    # Feature 21: validate_json Tests
    # =========================================================================

    def test_11_validate_json_valid_syntax_no_schema(self):
        res = op_config_validator.config_validator({
            "action": "validate_json",
            "content": '{"name": "Jarvis", "version": 1}',
        })
        self._assert_envelope(res, True)
        self.assertTrue(res["data"]["valid"])
        self.assertEqual(res["data"]["errors_count"], 0)

    def test_12_validate_json_syntax_error_diagnostics(self):
        res = op_config_validator.config_validator({
            "action": "validate_json",
            "content": '{"name": "Jarvis", unclosed',
        })
        self._assert_envelope(res, True)
        self.assertFalse(res["data"]["valid"])
        self.assertGreater(res["data"]["errors_count"], 0)
        diag = res["data"]["diagnostics"][0]
        self.assertEqual(diag["field"], "<syntax>")
        self.assertIsNotNone(diag["line"])

    def test_13_validate_json_duplicate_keys_detected(self):
        res = op_config_validator.config_validator({
            "action": "validate_json",
            "content": '{"port": 8080, "port": 9000}',
            "allow_duplicate_keys": False,
        })
        self._assert_envelope(res, True)
        self.assertFalse(res["data"]["valid"])
        self.assertIn("port", res["data"]["details"]["duplicate_keys"])

    def test_14_validate_json_allow_duplicate_keys(self):
        res = op_config_validator.config_validator({
            "action": "validate_json",
            "content": '{"port": 8080, "port": 9000}',
            "allow_duplicate_keys": True,
        })
        self._assert_envelope(res, True)
        self.assertTrue(res["data"]["valid"])
        self.assertGreater(res["data"]["warnings_count"], 0)

    def test_15_validate_json_schema_types(self):
        schema = {
            "type": "object",
            "properties": {
                "name": {"type": "string"},
                "count": {"type": "integer"},
                "ratio": {"type": "number"},
                "active": {"type": "boolean"},
                "tags": {"type": "array"},
                "extra": {"type": "null"},
            },
        }
        good_payload = {
            "name": "foo",
            "count": 42,
            "ratio": 3.14,
            "active": True,
            "tags": ["a", "b"],
            "extra": None,
        }
        res_good = op_config_validator.config_validator({
            "action": "validate_json",
            "content": json.dumps(good_payload),
            "schema": schema,
        })
        self._assert_envelope(res_good, True)
        self.assertTrue(res_good["data"]["valid"])

        # In Python, bool inherits from int. Test that True is rejected for "integer" field!
        bad_payload = {"count": True}
        res_bad = op_config_validator.config_validator({
            "action": "validate_json",
            "content": json.dumps(bad_payload),
            "schema": schema,
        })
        self._assert_envelope(res_bad, True)
        self.assertFalse(res_bad["data"]["valid"])

    def test_16_validate_json_schema_required_and_forbidden(self):
        schema = {
            "type": "object",
            "required": ["api_key"],
            "forbidden": ["password"],
        }
        payload = {"username": "admin", "password": "secret"}
        res = op_config_validator.config_validator({
            "action": "validate_json",
            "content": json.dumps(payload),
            "schema": schema,
        })
        self._assert_envelope(res, True)
        self.assertFalse(res["data"]["valid"])
        errors_str = " ".join(res["data"]["errors"])
        self.assertIn("api_key", errors_str)
        self.assertIn("password", errors_str)

    def test_17_validate_json_schema_additional_properties_false(self):
        schema = {
            "type": "object",
            "properties": {"host": {"type": "string"}},
            "additionalProperties": False,
        }
        payload = {"host": "localhost", "unexpected_field": 123}
        res = op_config_validator.config_validator({
            "action": "validate_json",
            "content": json.dumps(payload),
            "schema": schema,
        })
        self._assert_envelope(res, True)
        self.assertFalse(res["data"]["valid"])
        self.assertIn("unexpected_field", res["data"]["errors"][0])

    def test_18_validate_json_schema_enum_values(self):
        schema = {
            "type": "object",
            "properties": {"env": {"enum": ["dev", "staging", "prod"]}},
        }
        res_bad = op_config_validator.config_validator({
            "action": "validate_json",
            "content": '{"env": "testing"}',
            "schema": schema,
        })
        self._assert_envelope(res_bad, True)
        self.assertFalse(res_bad["data"]["valid"])

        res_good = op_config_validator.config_validator({
            "action": "validate_json",
            "content": '{"env": "prod"}',
            "schema": schema,
        })
        self._assert_envelope(res_good, True)
        self.assertTrue(res_good["data"]["valid"])

    def test_19_validate_json_schema_numeric_bounds(self):
        schema = {
            "type": "object",
            "properties": {
                "port": {"type": "integer", "minimum": 1024, "maximum": 65535},
            },
        }
        res_low = op_config_validator.config_validator({
            "action": "validate_json",
            "content": '{"port": 80}',
            "schema": schema,
        })
        self.assertFalse(res_low["data"]["valid"])

        res_high = op_config_validator.config_validator({
            "action": "validate_json",
            "content": '{"port": 70000}',
            "schema": schema,
        })
        self.assertFalse(res_high["data"]["valid"])

        res_ok = op_config_validator.config_validator({
            "action": "validate_json",
            "content": '{"port": 8080}',
            "schema": schema,
        })
        self.assertTrue(res_ok["data"]["valid"])

    def test_20_validate_json_schema_length_bounds(self):
        schema = {
            "type": "object",
            "properties": {
                "username": {"type": "string", "minLength": 3, "maxLength": 10},
                "items": {"type": "array", "minItems": 1, "uniqueItems": True},
            },
        }
        res = op_config_validator.config_validator({
            "action": "validate_json",
            "content": '{"username": "a", "items": [1, 1]}',
            "schema": schema,
        })
        self._assert_envelope(res, True)
        self.assertFalse(res["data"]["valid"])
        self.assertEqual(res["data"]["errors_count"], 2)

    def test_21_validate_json_schema_regex_pattern(self):
        schema = {
            "type": "object",
            "properties": {
                "email": {"type": "string", "pattern": r"^[^@]+@[^@]+\.[^@]+$"},
            },
        }
        res_bad = op_config_validator.config_validator({
            "action": "validate_json",
            "content": '{"email": "not-an-email"}',
            "schema": schema,
        })
        self.assertFalse(res_bad["data"]["valid"])

        res_good = op_config_validator.config_validator({
            "action": "validate_json",
            "content": '{"email": "user@example.com"}',
            "schema": schema,
        })
        self.assertTrue(res_good["data"]["valid"])

    def test_22_validate_json_redos_nested_quantifiers_rejected(self):
        schema = {
            "type": "object",
            "properties": {
                "evil": {"type": "string", "pattern": r"(a+)+"},
            },
        }
        res = op_config_validator.config_validator({
            "action": "validate_json",
            "content": '{"evil": "aaaa"}',
            "schema": schema,
        })
        self._assert_envelope(res, False)
        self.assertIn("ReDoSSecurityError", res["error"])

    def test_23_validate_json_recursion_depth_limit(self):
        # Create deeply nested object and schema: {"a": {"a": {"a": ...}}}
        deep_obj: dict = {}
        curr = deep_obj
        curr_schema = {"type": "object", "properties": {}}
        root_schema = curr_schema
        for _ in range(30):
            curr["a"] = {}
            curr = curr["a"]
            next_schema = {"type": "object", "properties": {}}
            curr_schema["properties"]["a"] = next_schema
            curr_schema = next_schema

        res = op_config_validator.config_validator({
            "action": "validate_json",
            "content": json.dumps(deep_obj),
            "schema": root_schema,
            "max_depth": 20,
        })
        self._assert_envelope(res, True)
        self.assertFalse(res["data"]["valid"])
        errors_str = " ".join(res["data"]["errors"])
        self.assertIn("Maximum nesting depth", errors_str)

    def test_23b_validate_json_disallowed_constants(self):
        res = op_config_validator.config_validator({
            "action": "validate_json",
            "content": '{"value": NaN}',
        })
        self._assert_envelope(res, True)
        self.assertFalse(res["data"]["valid"])
        self.assertIn("syntax", res["data"]["diagnostics"][0]["field"])

    # =========================================================================
    # Feature 22: validate_ini Tests
    # =========================================================================

    def test_24_validate_ini_valid_syntax(self):
        res = op_config_validator.config_validator({
            "action": "validate_ini",
            "path": str(self.ini_path),
        })
        self._assert_envelope(res, True)
        self.assertTrue(res["data"]["valid"])
        self.assertIn("server", res["data"]["details"]["sections"])
        self.assertIn("database", res["data"]["details"]["sections"])

    def test_25_validate_ini_missing_section_header(self):
        bad_ini = "key_without_section = value\n[sec]\nk=v\n"
        res = op_config_validator.config_validator({
            "action": "validate_ini",
            "content": bad_ini,
        })
        self._assert_envelope(res, True)
        self.assertFalse(res["data"]["valid"])
        self.assertIn("Missing section header", res["data"]["errors"][0])

    def test_26_validate_ini_duplicate_sections_and_options(self):
        dup_sec = "[section1]\na=1\n[section1]\nb=2\n"
        res_sec = op_config_validator.config_validator({
            "action": "validate_ini",
            "content": dup_sec,
        })
        self.assertFalse(res_sec["data"]["valid"])
        self.assertIn("Duplicate section", res_sec["data"]["errors"][0])

        dup_opt = "[section1]\na=1\na=2\n"
        res_opt = op_config_validator.config_validator({
            "action": "validate_ini",
            "content": dup_opt,
        })
        self.assertFalse(res_opt["data"]["valid"])
        self.assertIn("Duplicate option", res_opt["data"]["errors"][0])

    def test_27_validate_ini_required_and_forbidden_sections(self):
        res = op_config_validator.config_validator({
            "action": "validate_ini",
            "path": str(self.ini_path),
            "required_sections": ["server", "security"],
            "forbidden_sections": ["database"],
        })
        self._assert_envelope(res, True)
        self.assertFalse(res["data"]["valid"])
        errors_str = " ".join(res["data"]["errors"])
        self.assertIn("security", errors_str)
        self.assertIn("database", errors_str)

    def test_28_validate_ini_required_and_forbidden_options(self):
        res = op_config_validator.config_validator({
            "action": "validate_ini",
            "path": str(self.ini_path),
            "required_options": {"server": ["host", "timeout"]},
            "forbidden_options": ["server.port"],
        })
        self._assert_envelope(res, True)
        self.assertFalse(res["data"]["valid"])
        errors_str = " ".join(res["data"]["errors"])
        self.assertIn("timeout", errors_str)
        self.assertIn("port", errors_str)

    def test_29_validate_ini_interpolation_errors(self):
        broken_interp = "[sec]\na = %(missing_var)s\n"
        res = op_config_validator.config_validator({
            "action": "validate_ini",
            "content": broken_interp,
            "check_interpolation": True,
        })
        self._assert_envelope(res, True)
        self.assertFalse(res["data"]["valid"])
        self.assertIn("Interpolation error", res["data"]["errors"][0])

    def test_30_validate_ini_interpolation_modes(self):
        raw_pct = "[sec]\nmessage = %not_interpolated%\n"
        res_none = op_config_validator.config_validator({
            "action": "validate_ini",
            "content": raw_pct,
            "interpolation": "none",
        })
        self.assertTrue(res_none["data"]["valid"])

        res_basic = op_config_validator.config_validator({
            "action": "validate_ini",
            "content": raw_pct,
            "interpolation": "basic",
        })
        self.assertFalse(res_basic["data"]["valid"])

    # =========================================================================
    # Feature 23: validate_dotenv Tests
    # =========================================================================

    def test_31_validate_dotenv_valid_syntax(self):
        res = op_config_validator.config_validator({
            "action": "validate_dotenv",
            "content": "# Comment\nexport PORT=8080\nDB_NAME='my_db'\n",
        })
        self._assert_envelope(res, True)
        self.assertTrue(res["data"]["valid"])
        self.assertEqual(res["data"]["details"]["variables_count"], 2)

    def test_32_validate_dotenv_variable_naming_compliance(self):
        res = op_config_validator.config_validator({
            "action": "validate_dotenv",
            "content": "1INVALID=value\nINVALID-NAME=value2\n",
            "strict_naming": True,
        })
        self._assert_envelope(res, True)
        self.assertFalse(res["data"]["valid"])
        self.assertEqual(res["data"]["errors_count"], 2)

    def test_33_validate_dotenv_unquoted_multiline_detected(self):
        res = op_config_validator.config_validator({
            "action": "validate_dotenv",
            "content": "KEY=val\nunquoted line without equals\n",
        })
        self._assert_envelope(res, True)
        self.assertFalse(res["data"]["valid"])
        self.assertIn("no '=' assignment delimiter", res["data"]["errors"][0])

    def test_34_validate_dotenv_unclosed_quotes(self):
        res = op_config_validator.config_validator({
            "action": "validate_dotenv",
            "content": 'SECRET="unclosed string at end\n',
        })
        self._assert_envelope(res, True)
        self.assertFalse(res["data"]["valid"])
        self.assertIn("Unclosed quote", res["data"]["errors"][0])

    def test_35_validate_dotenv_duplicate_variables(self):
        res = op_config_validator.config_validator({
            "action": "validate_dotenv",
            "content": "KEY=val1\nKEY=val2\n",
            "allow_duplicate_keys": False,
        })
        self._assert_envelope(res, True)
        self.assertFalse(res["data"]["valid"])
        self.assertIn("Duplicate variable 'KEY'", res["data"]["errors"][0])

    def test_36_validate_dotenv_template_comparison(self):
        res = op_config_validator.config_validator({
            "action": "validate_dotenv",
            "path": str(self.env_path),
            "template_path": str(self.tmpl_path),
        })
        self._assert_envelope(res, True)
        self.assertFalse(res["data"]["valid"])
        self.assertIn("API_KEY", res["data"]["details"]["missing_template_variables"])

    # =========================================================================
    # Feature 24: lint_config Tests
    # =========================================================================

    def test_37_lint_config_structural_rules(self):
        dirty_json = '{\n  "key": "value"   \n}\n'  # Trailing whitespace on line 2
        res = op_config_validator.config_validator({
            "action": "lint_config",
            "content": dirty_json,
            "format": "json",
        })
        self._assert_envelope(res, True)
        self.assertTrue(res["data"]["valid"])
        self.assertGreater(res["data"]["warnings_count"], 0)
        self.assertIn("trailing_whitespace", [d["field"] for d in res["data"]["diagnostics"]])

        # Missing trailing newline
        no_nl = '{"a": 1}'
        res_no_nl = op_config_validator.config_validator({
            "action": "lint_config",
            "content": no_nl,
            "format": "json",
        })
        self.assertIn("missing_eof_newline", [d["field"] for d in res_no_nl["data"]["diagnostics"]])

    def test_38_lint_config_control_characters_and_null_bytes(self):
        corrupt = '{"key": "val\0hidden"}\n'
        res = op_config_validator.config_validator({
            "action": "lint_config",
            "content": corrupt,
            "format": "json",
        })
        self._assert_envelope(res, True)
        self.assertFalse(res["data"]["valid"])
        self.assertIn("Null byte", res["data"]["errors"][0])

    def test_39_lint_config_format_auto_detection(self):
        res_json = op_config_validator.config_validator({
            "action": "lint_config",
            "path": str(self.json_path),
        })
        self.assertEqual(res_json["data"]["format"], "json")

        res_ini = op_config_validator.config_validator({
            "action": "lint_config",
            "path": str(self.ini_path),
        })
        self.assertEqual(res_ini["data"]["format"], "ini")

        res_env = op_config_validator.config_validator({
            "action": "lint_config",
            "path": str(self.env_path),
        })
        self.assertEqual(res_env["data"]["format"], "dotenv")

    # =========================================================================
    # ToolRegistry Integration Tests
    # =========================================================================

    def test_40_tool_registry_discovery(self):
        registry = ToolRegistry()
        self.assertIn("config_validator", registry.tools)
        tool = registry.tools["config_validator"]
        decl = tool.declaration()
        self.assertEqual(decl["name"], "config_validator")
        self.assertFalse(tool.approval)

        # Run invocation through registry
        res = registry.run("config_validator", {
            "action": "validate_json",
            "content": '{"ok": true}',
        })
        self._assert_envelope(res, True)
        self.assertTrue(res["data"]["valid"])


if __name__ == "__main__":
    unittest.main()
