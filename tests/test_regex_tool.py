"""Tests for operator_modules/regex_tool.py."""

from __future__ import annotations

import unittest

import operator_modules.regex_tool as regex_tool_mod


class TestRegexTool(unittest.TestCase):
    def test_tool_declaration_contract(self):
        tool = regex_tool_mod.TOOL
        self.assertEqual(tool["name"], "regex_tool")
        self.assertFalse(tool["approval"])
        self.assertTrue(callable(tool["handler"]))
        self.assertLessEqual(len(tool["description"]), 1600)
        schema = tool["input_schema"]
        self.assertEqual(schema["type"], "object")
        self.assertFalse(schema["additionalProperties"])
        self.assertIn("action", schema["required"])
        self.assertIn("pattern", schema["required"])

    def test_check_pattern_safe_and_named_groups(self):
        res = regex_tool_mod.regex_tool({
            "action": "check_pattern",
            "pattern": r"^(?P<year>\d{4})-(?P<month>\d{2})-(?P<day>\d{2})$",
        })
        self.assertTrue(res["ok"])
        self.assertTrue(res["success"])
        self.assertTrue(res["data"]["valid"])
        self.assertTrue(res["data"]["is_safe"])
        self.assertEqual(res["data"]["num_groups"], 3)
        self.assertEqual(res["data"]["named_groups"], ["year", "month", "day"])
        self.assertEqual(len(res["data"]["warnings"]), 0)

    def test_check_pattern_detects_redos_risk(self):
        res = regex_tool_mod.regex_tool({
            "action": "check_pattern",
            "pattern": r"(a+)+$",
        })
        self.assertTrue(res["ok"])
        self.assertTrue(res["data"]["valid"])
        self.assertFalse(res["data"]["is_safe"])
        self.assertGreater(len(res["data"]["warnings"]), 0)

    def test_check_pattern_invalid_syntax(self):
        res = regex_tool_mod.regex_tool({
            "action": "check_pattern",
            "pattern": r"[a-z(",
        })
        self.assertFalse(res["ok"])
        self.assertIn("Invalid regular expression", res["error"])

    def test_match_action(self):
        res = regex_tool_mod.regex_tool({
            "action": "match",
            "pattern": r"hello\s+(\w+)",
            "text": "hello world!",
        })
        self.assertTrue(res["ok"])
        self.assertTrue(res["data"]["matched"])
        self.assertEqual(res["data"]["match"], "hello world")
        self.assertEqual(res["data"]["groups"], ["world"])
        self.assertEqual(res["data"]["span"], [0, 11])

    def test_match_failure(self):
        res = regex_tool_mod.regex_tool({
            "action": "match",
            "pattern": r"^world",
            "text": "hello world",
        })
        self.assertTrue(res["ok"])
        self.assertFalse(res["data"]["matched"])
        self.assertIsNone(res["data"]["match"])

    def test_search_action(self):
        res = regex_tool_mod.regex_tool({
            "action": "search",
            "pattern": r"(?P<id>[A-Z]{3}-\d{4})",
            "text": "Order reference: ABC-1234 for processing.",
        })
        self.assertTrue(res["ok"])
        self.assertTrue(res["data"]["found"])
        self.assertEqual(res["data"]["match"], "ABC-1234")
        self.assertEqual(res["data"]["groupdict"], {"id": "ABC-1234"})

    def test_findall_with_limit(self):
        text = "apple, banana, avocado, blueberry, apricot"
        res = regex_tool_mod.regex_tool({
            "action": "findall",
            "pattern": r"\ba\w+",
            "text": text,
            "limit": 2,
        })
        self.assertTrue(res["ok"])
        self.assertEqual(res["data"]["matches_count"], 2)
        self.assertTrue(res["data"]["truncated"])
        matches = [m["match"] for m in res["data"]["matches"]]
        self.assertEqual(matches, ["apple", "avocado"])

    def test_sub_action(self):
        text = "foo 123 bar 456 baz 789"
        res = regex_tool_mod.regex_tool({
            "action": "sub",
            "pattern": r"\d+",
            "text": text,
            "replacement": "[NUM]",
            "limit": 2,
        })
        self.assertTrue(res["ok"])
        self.assertEqual(res["data"]["new_text"], "foo [NUM] bar [NUM] baz 789")
        self.assertEqual(res["data"]["replacements_count"], 2)

    def test_flags_ignorecase_and_multiline(self):
        text = "LINE 1\nline 2\nLine 3"
        res = regex_tool_mod.regex_tool({
            "action": "findall",
            "pattern": r"^line \d+",
            "text": text,
            "flags": ["IGNORECASE", "MULTILINE"],
        })
        self.assertTrue(res["ok"])
        self.assertEqual(res["data"]["matches_count"], 3)

    def test_timeout_guard_on_redos(self):
        # Classic catastrophic backtracking pattern: (a+)+$ on 26 'a's followed by '!'
        redos_pattern = r"^(a+)+$"
        hostile_text = "a" * 27 + "!"
        res = regex_tool_mod.regex_tool({
            "action": "match",
            "pattern": redos_pattern,
            "text": hostile_text,
        })
        self.assertFalse(res["ok"])
        self.assertIn("timed out", res["error"].lower())

    def test_text_exceeds_limit(self):
        oversized = "x" * (512 * 1024 + 10)
        res = regex_tool_mod.regex_tool({
            "action": "match",
            "pattern": r"\w+",
            "text": oversized,
        })
        self.assertFalse(res["ok"])
        self.assertIn("exceeds maximum limit", res["error"])

    def test_pattern_length_limit(self):
        long_pat = "a" * 1025
        res = regex_tool_mod.regex_tool({
            "action": "match",
            "pattern": long_pat,
            "text": "a",
        })
        self.assertFalse(res["ok"])
        self.assertIn("Pattern exceeds maximum length", res["error"])

    def test_unsupported_action(self):
        res = regex_tool_mod.regex_tool({
            "action": "invalid_action",
            "pattern": r"\w+",
        })
        self.assertFalse(res["ok"])
        self.assertIn("Unsupported action", res["error"])

    def test_missing_pattern(self):
        res = regex_tool_mod.regex_tool({
            "action": "match",
            "text": "test",
        })
        self.assertFalse(res["ok"])
        self.assertIn("pattern", res["error"].lower())
