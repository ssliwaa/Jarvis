"""ERROR-path coverage tests for operator_modules/op_config_validator.py.

Second wave of the sys.settrace audit, module three: config
validation (JSON/INI/dotenv/lint) with 7 of 19 raise lines never
executed. Writing the missing ReDoS test surfaced a real bug: the
old worker-thread timeout could never fire, because the C-level
regex engine holds the GIL for the whole match, so the timeout
check in the joining thread only ran after the match finished. A
34-character "(a|aa)+b" payload measured 3.62 s with timeout=0.1 s
and no raise. fixed in the module: the search now runs in a
short-lived subprocess with a hard wall-clock kill.

The suite drives the ReDoS breaker with a real exponential pattern
that passes the static nested-quantifier check. Three raise lines
in the new subprocess pipeline (worker exit failure, malformed
worker output, worker-side regex error) are defensive-only: they
need an externally crashed or corrupted worker process, which
cannot be triggered honestly offline.
"""
import tempfile
import unittest
from pathlib import Path

import operator_modules.op_config_validator as cv


class ConfigValidatorCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(self._tmp.name)

    def call(self, **kwargs):
        return cv.config_validator(kwargs)

    def bad(self, fragment, **kwargs):
        result = self.call(**kwargs)
        self.assertFalse(result["ok"], msg=str(result.get("error")))
        self.assertIn(fragment, result["error"])
        return result


class PathGuardTests(ConfigValidatorCase):
    def test_empty_path_is_rejected(self):
        # Unlike the other loaders, this one dispatches the empty
        # string straight into the validator (no or-chain swallow).
        self.bad("File path must be a non-empty string.",
                 action="validate_json", path="")

    def test_missing_config_file(self):
        self.bad("Configuration file not found",
                 action="validate_json",
                 path=str(self.tmp / "absent.json"))


class ContentGuardTests(ConfigValidatorCase):
    def test_non_string_content_is_rejected(self):
        self.bad("'content' must be a string.",
                 action="validate_ini", content=12345)


class SchemaGuardTests(ConfigValidatorCase):
    def test_non_dict_schema_is_rejected(self):
        self.bad("'schema' must be a dictionary.",
                 action="validate_json", content='{"a": 1}',
                 schema=["not", "a", "dict"])


class RegexSafetyTests(ConfigValidatorCase):
    def test_non_string_pattern_is_rejected(self):
        with self.assertRaises(ValueError) as ctx:
            cv._check_regex_safety(12345)
        self.assertIn("Pattern must be a string.", str(ctx.exception))

    def test_malformed_pattern_is_resurfaced(self):
        with self.assertRaises(Exception) as ctx:
            cv._safe_regex_match("[", "some text")
        self.assertEqual(type(ctx.exception).__name__, "PatternError")

    def test_redos_timeout_fires_on_exponential_pattern(self):
        # (a|aa)+b passes the static nested-quantifier check (the guard
        # does not look through alternation overlap) but backtracks
        # exponentially: the wall-clock breaker must fire, not the old
        # thread-join which the GIL-holding regex engine deadlocked.
        with self.assertRaises(cv.ReDoSSecurityError) as ctx:
            cv._safe_regex_match("(a|aa)+b", "a" * 40, timeout=0.5)
        message = str(ctx.exception)
        self.assertIn("timed out after 0.5s", message)
        self.assertIn("ReDoS", message)

    def test_safe_pattern_matches_for_contrast(self):
        self.assertTrue(cv._safe_regex_match("a.*b", "xxaxxb"))
        self.assertFalse(cv._safe_regex_match("q{2}", "single-q"))


if __name__ == "__main__":
    unittest.main()
