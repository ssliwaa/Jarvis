"""Adversarial stress and edge-case test suite for operator_modules/op_config_validator.py.

Empirically probes:
1. ReDoS static screening (nested quantifiers, pattern and text length limits).
2. Deep schema recursion bounds (>50 levels) and deep JSON data parsing without stack overflow.
3. JSON duplicate key attacks (top-level, nested, inside arrays, allow_duplicate_keys toggle).
4. RFC 8259 disallowed constants (NaN, Infinity, -Infinity) rejection.
5. INI cyclic interpolation (basic, extended, cross-section) and missing variables.
6. Corrupted and malformed .env files (unclosed quotes, multiline unquoted, invalid identifiers, placeholders).
7. Path traversal escapes (../, symlinks to /etc, sensitive credentials, null bytes, non-regular files).
8. Input size limits (5 MB boundaries).
9. Interface contracts and standard 5-key return envelopes.
"""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

import operator_modules.op_config_validator as op_config_validator


class TestStressOpConfigValidator(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory(dir="/tmp")
        self.root = Path(self.temp_dir.name).resolve()

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
    # 1. ReDoS Static Screening & Bounds Tests
    # =========================================================================

    def test_01_redos_static_nested_quantifiers_rejected(self):
        patterns = [
            r"(a+)+",
            r"(a*)*",
            r"([a-z]+)+",
            r"(.*a)+",
            r"([a-zA-Z0-9]+_?)+",
        ]
        for pat in patterns:
            with self.subTest(pattern=pat):
                res = op_config_validator.config_validator({
                    "action": "validate_json",
                    "content": '{"text": "test"}',
                    "schema": {
                        "type": "object",
                        "properties": {"text": {"type": "string", "pattern": pat}},
                    },
                })
                self._assert_envelope(res, False)
                self.assertIn("ReDoSSecurityError", res["error"])

    def test_02_redos_pattern_length_bound_exceeded(self):
        huge_pattern = "a" * (op_config_validator.MAX_REGEX_PATTERN_LEN + 10)
        res = op_config_validator.config_validator({
            "action": "validate_json",
            "content": '{"text": "test"}',
            "schema": {
                "type": "object",
                "properties": {"text": {"type": "string", "pattern": huge_pattern}},
            },
        })
        self._assert_envelope(res, False)
        self.assertIn("ReDoSSecurityError", res["error"])

    def test_03_redos_target_text_length_bound_exceeded(self):
        huge_target = "a" * (op_config_validator.MAX_REGEX_STRING_LEN + 10)
        res = op_config_validator.config_validator({
            "action": "validate_json",
            "content": json.dumps({"text": huge_target}),
            "schema": {
                "type": "object",
                "properties": {"text": {"type": "string", "pattern": r"^a+$"}},
            },
        })
        self._assert_envelope(res, False)
        self.assertIn("ReDoSSecurityError", res["error"])

    # =========================================================================
    # 2. Deep Schema Recursion & Deep Data Tests
    # =========================================================================

    def test_04_deep_schema_recursion_depth_cutoff(self):
        curr_schema = {"type": "object", "properties": {}}
        root_schema = curr_schema
        curr_data: dict = {}
        root_data = curr_data

        for _ in range(70):
            curr_data["nested"] = {}
            curr_data = curr_data["nested"]
            next_schema = {"type": "object", "properties": {}}
            curr_schema["properties"]["nested"] = next_schema
            curr_schema = next_schema

        res = op_config_validator.config_validator({
            "action": "validate_json",
            "content": json.dumps(root_data),
            "schema": root_schema,
            "max_depth": 50,
        })
        self._assert_envelope(res, True)
        self.assertFalse(res["data"]["valid"])
        self.assertIn("Maximum nesting depth (50) exceeded", res["data"]["errors"][0])

    def test_05_deep_json_data_parsing_without_crash(self):
        deep_json = '{"level":' * 300 + '1' + '}' * 300
        res = op_config_validator.config_validator({
            "action": "validate_json",
            "content": deep_json,
        })
        self._assert_envelope(res, True)
        self.assertTrue(res["data"]["valid"])

    # =========================================================================
    # 3. JSON Duplicate Key Attacks
    # =========================================================================

    def test_06_json_duplicate_keys_nested_and_arrays(self):
        payload_nested = '{"outer": {"key": 1, "key": 2}}'
        res_nested = op_config_validator.config_validator({
            "action": "validate_json",
            "content": payload_nested,
            "allow_duplicate_keys": False,
        })
        self._assert_envelope(res_nested, True)
        self.assertFalse(res_nested["data"]["valid"])
        self.assertIn("key", res_nested["data"]["details"]["duplicate_keys"])

        payload_array = '[{"item": 1, "item": 2}]'
        res_array = op_config_validator.config_validator({
            "action": "validate_json",
            "content": payload_array,
            "allow_duplicate_keys": False,
        })
        self._assert_envelope(res_array, True)
        self.assertFalse(res_array["data"]["valid"])
        self.assertIn("item", res_array["data"]["details"]["duplicate_keys"])

    def test_07_json_duplicate_keys_toggle(self):
        payload = '{"dup": "first", "dup": "second"}'
        res_strict = op_config_validator.config_validator({
            "action": "validate_json",
            "content": payload,
            "allow_duplicate_keys": False,
        })
        self.assertFalse(res_strict["data"]["valid"])
        self.assertEqual(res_strict["data"]["errors_count"], 1)

        res_lax = op_config_validator.config_validator({
            "action": "validate_json",
            "content": payload,
            "allow_duplicate_keys": True,
        })
        self.assertTrue(res_lax["data"]["valid"])
        self.assertEqual(res_lax["data"]["warnings_count"], 1)

    # =========================================================================
    # 4. RFC 8259 Disallowed Constants Tests
    # =========================================================================

    def test_08_rfc_8259_disallowed_constants(self):
        for const in ["NaN", "Infinity", "-Infinity"]:
            with self.subTest(constant=const):
                res = op_config_validator.config_validator({
                    "action": "validate_json",
                    "content": f'{{"metric": {const}}}',
                })
                self._assert_envelope(res, True)
                self.assertFalse(res["data"]["valid"])
                self.assertIn(f"Disallowed RFC 8259 constant: {const}", res["data"]["errors"][0])

    # =========================================================================
    # 5. INI Cyclic Interpolation & Missing Option Tests
    # =========================================================================

    def test_09_ini_basic_cyclic_interpolation(self):
        ini_text = "[sec]\na = %(b)s\nb = %(a)s\n"
        res = op_config_validator.config_validator({
            "action": "validate_ini",
            "content": ini_text,
            "interpolation": "basic",
        })
        self._assert_envelope(res, True)
        self.assertFalse(res["data"]["valid"])
        errors = " ".join(res["data"]["errors"])
        self.assertIn("Circular interpolation recursion detected", errors)

    def test_10_ini_extended_cyclic_interpolation(self):
        ini_text = "[sec1]\na = ${sec2:b}\n[sec2]\nb = ${sec1:a}\n"
        res = op_config_validator.config_validator({
            "action": "validate_ini",
            "content": ini_text,
            "interpolation": "extended",
        })
        self._assert_envelope(res, True)
        self.assertFalse(res["data"]["valid"])
        errors = " ".join(res["data"]["errors"])
        self.assertIn("Circular interpolation recursion detected", errors)

    def test_11_ini_missing_option_interpolation(self):
        ini_text = "[service]\nurl = http://%(missing_host)s:8080\n"
        res = op_config_validator.config_validator({
            "action": "validate_ini",
            "content": ini_text,
            "interpolation": "basic",
        })
        self._assert_envelope(res, True)
        self.assertFalse(res["data"]["valid"])
        self.assertIn("missing referenced option 'missing_host'", res["data"]["errors"][0])

    def test_12_ini_interpolation_none_mode(self):
        ini_text = "[pricing]\ntax = 20%\n"
        res = op_config_validator.config_validator({
            "action": "validate_ini",
            "content": ini_text,
            "interpolation": "none",
        })
        self._assert_envelope(res, True)
        self.assertTrue(res["data"]["valid"])

    # =========================================================================
    # 6. Corrupted & Malformed .env Files Tests
    # =========================================================================

    def test_13_dotenv_unclosed_quotes(self):
        single_quote = "A='unclosed single quote\nB=2\n"
        res_sq = op_config_validator.config_validator({
            "action": "validate_dotenv",
            "content": single_quote,
        })
        self._assert_envelope(res_sq, True)
        self.assertFalse(res_sq["data"]["valid"])
        self.assertIn("Unclosed quote '", res_sq["data"]["errors"][0])

        double_quote = 'A="unclosed double quote\nB=2\n'
        res_dq = op_config_validator.config_validator({
            "action": "validate_dotenv",
            "content": double_quote,
        })
        self._assert_envelope(res_dq, True)
        self.assertFalse(res_dq["data"]["valid"])
        self.assertIn('Unclosed quote "', res_dq["data"]["errors"][0])

    def test_14_dotenv_unquoted_multiline_syntax_error(self):
        content = "VAR=first line\nsecond line without equals\n"
        res = op_config_validator.config_validator({
            "action": "validate_dotenv",
            "content": content,
        })
        self._assert_envelope(res, True)
        self.assertFalse(res["data"]["valid"])
        self.assertIn("no '=' assignment delimiter", res["data"]["errors"][0])

    def test_15_dotenv_invalid_identifier_naming(self):
        content = "1NUM=val\nHYPHEN-VAR=val\nSPACE VAR=val\n.DOT=val\n"
        res = op_config_validator.config_validator({
            "action": "validate_dotenv",
            "content": content,
            "strict_naming": True,
        })
        self._assert_envelope(res, True)
        self.assertFalse(res["data"]["valid"])
        self.assertEqual(res["data"]["errors_count"], 4)

    def test_16_dotenv_missing_variable_name_before_delimiter(self):
        content = "=value_without_name\n"
        res = op_config_validator.config_validator({
            "action": "validate_dotenv",
            "content": content,
        })
        self._assert_envelope(res, True)
        self.assertFalse(res["data"]["valid"])
        self.assertIn("missing variable name before '='", res["data"]["errors"][0])

    def test_17_dotenv_multiline_quoted_values_parsed(self):
        content = "CERT='line1\nline2'\nKEY=\"key1\nkey2\"\n"
        res = op_config_validator.config_validator({
            "action": "validate_dotenv",
            "content": content,
        })
        self._assert_envelope(res, True)
        self.assertTrue(res["data"]["valid"])
        self.assertEqual(res["data"]["details"]["variables_count"], 2)

    def test_18_dotenv_placeholder_values_flagged(self):
        content = "DB_PASS=changeme\nAPI_KEY=YOUR_KEY_HERE\nSECRET=todo\nREAL_TOKEN=my_secret_token_12345\n"
        res = op_config_validator.config_validator({
            "action": "validate_dotenv",
            "content": content,
        })
        self._assert_envelope(res, True)
        self.assertTrue(res["data"]["valid"])
        self.assertEqual(len(res["data"]["details"]["placeholder_warnings"]), 3)

    # =========================================================================
    # 7. Path Confinement & Traversal Attacks
    # =========================================================================

    def test_19_path_traversal_outside_allowed_roots(self):
        res = op_config_validator.config_validator({
            "action": "validate_json",
            "path": str(self.root / ".." / ".." / "etc" / "passwd"),
        })
        self._assert_envelope(res, False)
        self.assertIn("PathSecurityError", res["error"])

    def test_20_null_byte_path_injection(self):
        res = op_config_validator.config_validator({
            "action": "validate_json",
            "path": "/tmp/test\0evil.json",
        })
        self._assert_envelope(res, False)
        self.assertIn("PathSecurityError", res["error"])

    def test_21_symlink_escape_outside_allowed_roots(self):
        sym_file = self.root / "escape.ini"
        try:
            os.symlink("/etc/passwd", sym_file)
        except OSError:
            self.skipTest("Symlink creation not supported")

        res = op_config_validator.config_validator({
            "action": "validate_ini",
            "path": str(sym_file),
        })
        self._assert_envelope(res, False)
        self.assertIn("PathSecurityError", res["error"])

    def test_22_symlink_to_sensitive_directory(self):
        ssh_dir = Path.home() / ".ssh"
        if not ssh_dir.exists():
            self.skipTest("~/.ssh directory does not exist on host")

        sym_ssh = self.root / "ssh_leak.env"
        try:
            os.symlink(ssh_dir, sym_ssh)
        except OSError:
            self.skipTest("Symlink creation not supported")

        res = op_config_validator.config_validator({
            "action": "validate_dotenv",
            "path": str(sym_ssh),
        })
        self._assert_envelope(res, False)
        self.assertIn("SensitivePathError", res["error"])

    def test_23_template_path_traversal_escape(self):
        res = op_config_validator.config_validator({
            "action": "validate_dotenv",
            "content": "PORT=8080\n",
            "template_path": "/etc/shadow",
        })
        self._assert_envelope(res, False)
        self.assertIn("PathSecurityError", res["error"])

    def test_24_directory_path_target_rejected(self):
        res = op_config_validator.config_validator({
            "action": "validate_json",
            "path": str(self.root),
        })
        self._assert_envelope(res, False)
        self.assertIn("not a regular file", res["error"])

    # =========================================================================
    # 8. Input Size Limits (5 MB Bounds)
    # =========================================================================

    def test_25_content_size_boundary(self):
        exact_bytes = " " * op_config_validator.MAX_CONFIG_BYTES
        res_exact = op_config_validator.config_validator({
            "action": "validate_json",
            "content": exact_bytes,
        })
        self._assert_envelope(res_exact, True)

        over_bytes = " " * (op_config_validator.MAX_CONFIG_BYTES + 1)
        res_over = op_config_validator.config_validator({
            "action": "validate_json",
            "content": over_bytes,
        })
        self._assert_envelope(res_over, False)
        self.assertIn("ConfigSizeError", res_over["error"])

    def test_26_file_size_boundary(self):
        huge_file = self.root / "huge_config.ini"
        with open(huge_file, "wb") as fp:
            fp.seek(op_config_validator.MAX_CONFIG_BYTES)
            fp.write(b"x")

        res = op_config_validator.config_validator({
            "action": "validate_ini",
            "path": str(huge_file),
        })
        self._assert_envelope(res, False)
        self.assertIn("ConfigSizeError", res["error"])

    # =========================================================================
    # 9. Lint Config Edge Cases
    # =========================================================================

    def test_27_lint_config_control_characters(self):
        corrupt = '{\n  "key": "val\x01\x7f"\n}\n'
        res = op_config_validator.config_validator({
            "action": "lint_config",
            "content": corrupt,
            "format": "json",
        })
        self._assert_envelope(res, True)
        self.assertFalse(res["data"]["valid"])
        fields = [d["field"] for d in res["data"]["diagnostics"]]
        self.assertIn("control_characters", fields)

    def test_28_lint_config_mixed_tabs_spaces(self):
        mixed = '{\n \t"key": 1\n}\n'
        res = op_config_validator.config_validator({
            "action": "lint_config",
            "content": mixed,
            "format": "json",
        })
        self._assert_envelope(res, True)
        self.assertFalse(res["data"]["valid"])
        self.assertIn("inconsistent_indentation", [d["field"] for d in res["data"]["diagnostics"]])

    def test_29_lint_config_strict_mode(self):
        trailing_ws = '{\n  "key": "val"   \n}\n'
        res_lax = op_config_validator.config_validator({
            "action": "lint_config",
            "content": trailing_ws,
            "format": "json",
            "strict": False,
        })
        self.assertTrue(res_lax["data"]["valid"])
        self.assertGreater(res_lax["data"]["warnings_count"], 0)

        res_strict = op_config_validator.config_validator({
            "action": "lint_config",
            "content": trailing_ws,
            "format": "json",
            "strict": True,
        })
        self.assertFalse(res_strict["data"]["valid"])
        self.assertGreater(res_strict["data"]["errors_count"], 0)


if __name__ == "__main__":
    unittest.main()
