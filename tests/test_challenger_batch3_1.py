"""Adversarial stress and correctness verification test suite for Jarvis Operator Modules 1-5.

Target Modules:
1. diff_patch.py
2. cron_scheduler.py
3. log_parser.py
4. regex_tool.py
5. hash_checksum.py

Focuses on hostile inputs, quadratic/cubic algorithmic complexity vectors, ReDoS timeout guards,
corrupted patch hunks, leap year and impossible calendar boundaries, malformed logs,
streaming chunk bounds, permission errors, and strict dual-compatible return envelope compliance.
"""

from __future__ import annotations

import hashlib
import os
import tempfile
import time
import unittest
from pathlib import Path

import operator_modules.cron_scheduler as cron_scheduler_mod
import operator_modules.diff_patch as diff_patch_mod
import operator_modules.hash_checksum as hash_checksum_mod
import operator_modules.log_parser as log_parser_mod
import operator_modules.regex_tool as regex_tool_mod


def assert_standard_envelope(res: dict, expect_ok: bool | None = None) -> None:
    """Validate that the response conforms strictly to the Jarvis operator return contract."""
    assert isinstance(res, dict), f"Expected dict response, got {type(res)}"
    assert "ok" in res and isinstance(res["ok"], bool), f"'ok' key missing or not bool: {res}"
    assert "success" in res and isinstance(res["success"], bool), f"'success' key missing or not bool: {res}"
    assert res["ok"] == res["success"], f"'ok' ({res['ok']}) does not equal 'success' ({res['success']})"
    assert "data" in res, f"'data' key missing: {res}"
    assert "result" in res, f"'result' key missing: {res}"
    assert "error" in res, f"'error' key missing: {res}"
    assert res["data"] == res["result"], f"'data' does not equal 'result': {res}"

    if expect_ok is not None:
        assert res["ok"] is expect_ok, f"Expected ok={expect_ok}, got {res['ok']}. Error: {res.get('error')}"

    if res["ok"]:
        assert res["error"] is None, f"Expected error=None on ok=True, got {res['error']}"
        assert res["data"] is not None, "Expected non-None data on ok=True"
    else:
        assert isinstance(res["error"], str) and len(res["error"].strip()) > 0, (
            f"Expected non-empty string in 'error' on ok=False, got {res['error']!r}"
        )


class TestDiffPatchAdversarial(unittest.TestCase):
    """Stress tests and boundary checks for diff_patch module."""

    def test_empty_and_minimal_inputs(self):
        # Empty original and modified
        r = diff_patch_mod.diff_patch({"action": "diff", "original": "", "modified": ""})
        assert_standard_envelope(r, expect_ok=True)
        self.assertTrue(r["data"]["identical"])
        self.assertEqual(r["data"]["similarity_ratio"], 1.0)
        self.assertEqual(r["data"]["diff"], "")

        # Empty compare_ratio
        r2 = diff_patch_mod.diff_patch({"action": "compare_ratio", "original": "", "modified": ""})
        assert_standard_envelope(r2, expect_ok=True)
        self.assertEqual(r2["data"]["ratio"], 1.0)

        # Empty patch_text with original text
        r3 = diff_patch_mod.diff_patch({"action": "patch", "original": "hello\nworld\n", "patch_text": ""})
        # Empty patch_text should return error because patch_text must be non-empty
        assert_standard_envelope(r3, expect_ok=False)

        # Clean 3-way merge with empty inputs
        r4 = diff_patch_mod.diff_patch({"action": "merge3", "base": "", "original": "", "modified": ""})
        assert_standard_envelope(r4, expect_ok=True)
        self.assertTrue(r4["data"]["clean"])
        self.assertEqual(r4["data"]["conflicts"], 0)

    def test_line_and_byte_boundary_limits(self):
        # Exceeds max lines limit (10,000 lines)
        huge_lines = "item\n" * 10001
        r = diff_patch_mod.diff_patch({"action": "diff", "original": huge_lines, "modified": huge_lines})
        assert_standard_envelope(r, expect_ok=False)
        self.assertIn("maximum line limit", r["error"])

        # Exceeds max byte limit (512 KB)
        huge_bytes = "a" * (512 * 1024 + 1)
        r2 = diff_patch_mod.diff_patch({"action": "diff", "original": huge_bytes, "modified": "b"})
        assert_standard_envelope(r2, expect_ok=False)
        self.assertIn("exceeds maximum limit", r2["error"])

    def test_quadratic_sequence_runtime_bounds(self):
        # Sequence of repeated sub-patterns designed to challenge sequence matchers
        s1 = ("abcde" * 2000) + "\n"
        s2 = ("abXde" * 2000) + "\n"
        t0 = time.time()
        r = diff_patch_mod.diff_patch({"action": "compare_ratio", "original": s1, "modified": s2})
        elapsed = time.time() - t0
        assert_standard_envelope(r, expect_ok=True)
        self.assertLess(elapsed, 2.0, f"diff compare_ratio took {elapsed:.2f}s, exceeding 2s bound")

    def test_corrupted_and_adversarial_patches(self):
        orig = "line1\nline2\nline3\n"

        # Completely unparseable garbage patch text
        r_garbage = diff_patch_mod.diff_patch({
            "action": "patch",
            "original": orig,
            "patch_text": "NOT_A_VALID_DIFF\nsome random text\n",
        })
        assert_standard_envelope(r_garbage, expect_ok=False)
        self.assertIn("Could not parse", r_garbage["error"])

        # Corrupted hunk header with negative/malformed numbers
        malformed_patch = "@@ -garbage +foo @@\n-line1\n+line1_mod\n"
        r_malformed = diff_patch_mod.diff_patch({
            "action": "patch",
            "original": orig,
            "patch_text": malformed_patch,
        })
        # Gracefully handled without unhandled exception
        assert_standard_envelope(r_malformed)

        # Hunk pointing far beyond end of file
        oob_patch = "--- a/f\n+++ b/f\n@@ -9999,1 +9999,1 @@\n-old\n+new\n"
        r_oob = diff_patch_mod.diff_patch({
            "action": "patch",
            "original": orig,
            "patch_text": oob_patch,
        })
        assert_standard_envelope(r_oob, expect_ok=True)
        self.assertEqual(r_oob["data"]["hunks_applied"], 0)
        self.assertEqual(r_oob["data"]["hunks_failed"], 1)

    def test_multi_hunk_patch_application_with_offsets(self):
        orig = "line1\nline2\nline3\nline4\nline5\nline6\nline7\nline8\n"
        patch = (
            "--- a/f\n+++ b/f\n"
            "@@ -2,2 +2,4 @@\n"
            "-line2\n"
            "-line3\n"
            "+line2_new\n"
            "+inserted_A\n"
            "+inserted_B\n"
            "+line3_new\n"
            "@@ -6,2 +8,2 @@\n"
            "-line6\n"
            "-line7\n"
            "+line6_new\n"
            "+line7_new\n"
        )
        r = diff_patch_mod.diff_patch({"action": "patch", "original": orig, "patch_text": patch})
        assert_standard_envelope(r, expect_ok=True)
        self.assertEqual(r["data"]["hunks_applied"], 2)
        self.assertEqual(r["data"]["hunks_failed"], 0)
        patched = r["data"]["patched_text"]
        self.assertIn("inserted_A", patched)
        self.assertIn("inserted_B", patched)
        self.assertIn("line6_new", patched)

    def test_binary_and_special_characters_resilience(self):
        # Null bytes, UTF-8 emoji, BOM, CRLF
        orig = "\ufeffhello\x00world\r\nline2 \U0001f680\n"
        mod = "\ufeffhello\x00JARVIS\r\nline2 \U0001f680\n"
        r = diff_patch_mod.diff_patch({"action": "diff", "original": orig, "modified": mod})
        assert_standard_envelope(r, expect_ok=True)
        self.assertGreater(r["data"]["additions"], 0)

        # Patch containing '\ No newline at end of file'
        orig_noeol = "hello"
        patch_noeol = (
            "--- a/f\n+++ b/f\n"
            "@@ -1,1 +1,1 @@\n"
            "-hello\n"
            "\\ No newline at end of file\n"
            "+world\n"
            "\\ No newline at end of file\n"
        )
        r_noeol = diff_patch_mod.diff_patch({"action": "patch", "original": orig_noeol, "patch_text": patch_noeol})
        assert_standard_envelope(r_noeol, expect_ok=True)
        self.assertEqual(r_noeol["data"]["patched_text"], "world")

    def test_in_place_safety_and_path_security(self):
        with tempfile.TemporaryDirectory() as td:
            safe_file = Path(td) / "safe.txt"
            safe_file.write_text("before\n")

            patch = "--- a/f\n+++ b/f\n@@ -1,1 +1,1 @@\n-before\n+after\n"
            r = diff_patch_mod.diff_patch({
                "action": "patch",
                "target_file": str(safe_file),
                "patch_text": patch,
                "in_place": True,
            })
            assert_standard_envelope(r, expect_ok=True)
            self.assertEqual(safe_file.read_text(), "after\n")

            # Traversal attempt
            r_traversal = diff_patch_mod.diff_patch({
                "action": "patch",
                "target_file": str(Path(td) / ".." / ".." / "etc" / "passwd"),
                "patch_text": patch,
                "in_place": True,
            })
            assert_standard_envelope(r_traversal, expect_ok=False)

            # In place without target_file
            r_nofile = diff_patch_mod.diff_patch({
                "action": "patch",
                "original": "foo",
                "patch_text": patch,
                "in_place": True,
            })
            assert_standard_envelope(r_nofile, expect_ok=False)


class TestCronSchedulerAdversarial(unittest.TestCase):
    """Stress tests and boundary checks for cron_scheduler module."""

    def test_invalid_and_malformed_expressions(self):
        vectors = [
            "",  # empty
            "* * * *",  # 4 tokens
            "* * * * * *",  # 6 tokens
            "*/0 * * * *",  # step 0
            "*/-5 * * * *",  # negative step
            "*/step * * * *",  # non-numeric step
            "10-5 * * * *",  # inverted range
            "60 * * * *",  # minute out of bounds
            "* 24 * * *",  # hour out of bounds
            "* * 0 * *",  # dom 0
            "* * 32 * *",  # dom 32
            "* * * 0 *",  # month 0
            "* * * 13 *",  # month 13
            "* * * * 8",  # dow 8
            "* * * * MON-INVALID",  # invalid token
            "1-2-3 * * * *",  # multiple dashes
            "1,2, * * * *",  # trailing comma
            ",1,2 * * * *",  # leading comma
        ]
        for expr in vectors:
            r = cron_scheduler_mod.cron_scheduler({"action": "validate", "expression": expr})
            assert_standard_envelope(r, expect_ok=False)

    def test_impossible_dates_and_bounded_horizon(self):
        # February 31st (impossible date)
        t0 = time.time()
        r = cron_scheduler_mod.cron_scheduler({
            "action": "next_runs",
            "expression": "0 0 31 2 *",
            "count": 5,
        })
        elapsed = time.time() - t0
        assert_standard_envelope(r, expect_ok=False)
        self.assertIn("5-year search horizon", r["error"])
        self.assertLess(elapsed, 0.2, f"Impossible date search took {elapsed:.3f}s, expected <0.2s")

        # April 31st (impossible date, April has 30 days)
        r_apr = cron_scheduler_mod.cron_scheduler({
            "action": "next_runs",
            "expression": "0 0 31 4 *",
            "count": 1,
        })
        assert_standard_envelope(r_apr, expect_ok=False)

    def test_leap_year_boundary_resolution(self):
        # Feb 29 starting from non-leap year 2023
        r = cron_scheduler_mod.cron_scheduler({
            "action": "next_runs",
            "expression": "0 0 29 2 *",
            "from_time": "2023-01-01T00:00:00Z",
            "count": 2,
        })
        assert_standard_envelope(r, expect_ok=True)
        runs = r["data"]["runs"]
        self.assertEqual(len(runs), 2)
        # 2024 and 2028 are leap years
        self.assertTrue(runs[0].startswith("2024-02-29"))
        self.assertTrue(runs[1].startswith("2028-02-29"))

    def test_step_overflow_and_boundary_expressions(self):
        # Step larger than range (e.g. */100)
        r = cron_scheduler_mod.cron_scheduler({
            "action": "validate",
            "expression": "*/100 * * * *",
        })
        assert_standard_envelope(r, expect_ok=True)
        # Should contain only the starting minute 0
        self.assertEqual(r["data"]["fields"]["minute"], [0])

        # Step overflow on day of month (1-31/50)
        r2 = cron_scheduler_mod.cron_scheduler({
            "action": "validate",
            "expression": "* * 1-31/50 * *",
        })
        assert_standard_envelope(r2, expect_ok=True)
        self.assertEqual(r2["data"]["fields"]["day_of_month"], [1])

    def test_high_count_next_and_prev_runs_performance(self):
        # Calculate 100 next occurrences of every 15 minutes
        t0 = time.time()
        r_next = cron_scheduler_mod.cron_scheduler({
            "action": "next_runs",
            "expression": "*/15 * * * *",
            "count": 100,
        })
        t_next = time.time() - t0
        assert_standard_envelope(r_next, expect_ok=True)
        self.assertEqual(r_next["data"]["count"], 100)
        self.assertLess(t_next, 0.5)

        # Calculate 100 previous occurrences of daily schedule
        t0 = time.time()
        r_prev = cron_scheduler_mod.cron_scheduler({
            "action": "prev_runs",
            "expression": "0 12 * * *",
            "count": 100,
        })
        t_prev = time.time() - t0
        assert_standard_envelope(r_prev, expect_ok=True)
        self.assertEqual(r_prev["data"]["count"], 100)
        self.assertLess(t_prev, 0.5)

    def test_timezone_validation_and_safety(self):
        # Valid timezones
        for tz in ["UTC", "Europe/Warsaw", "America/New_York", "Asia/Tokyo"]:
            r = cron_scheduler_mod.cron_scheduler({
                "action": "next_runs",
                "expression": "0 0 * * *",
                "timezone": tz,
                "count": 1,
            })
            assert_standard_envelope(r, expect_ok=True)

        # Invalid timezone
        r_inv = cron_scheduler_mod.cron_scheduler({
            "action": "next_runs",
            "expression": "0 0 * * *",
            "timezone": "NonExistent/Zone",
        })
        assert_standard_envelope(r_inv, expect_ok=False)

        # Traversal in timezone
        r_trav = cron_scheduler_mod.cron_scheduler({
            "action": "next_runs",
            "expression": "0 0 * * *",
            "timezone": "../../etc/timezone",
        })
        assert_standard_envelope(r_trav, expect_ok=False)


class TestLogParserAdversarial(unittest.TestCase):
    """Stress tests and boundary checks for log_parser module."""

    def test_malformed_and_fuzz_lines(self):
        fuzz_payload = (
            "{\n"  # unclosed JSON
            "{'single': 'quotes'}\n"  # invalid JSON
            "[1, 2, 3]\n"  # JSON list instead of dict
            "null\n"
            "   \n"  # whitespace
            "\x00\x01\x02\n"  # control chars
            "Oct 99 99:99:99 host broken[abc]: msg\n"  # broken syslog
            '127.0.0.1 - - [bad date] "BAD REQUEST" 999 0\n'
        )
        r = log_parser_mod.log_parser({"action": "parse", "text": fuzz_payload, "format": "auto"})
        assert_standard_envelope(r, expect_ok=True)
        # Should not crash, and should report unparsed lines
        self.assertGreater(r["data"]["unparsed_count"], 0)

    def test_huge_line_and_payload_limits(self):
        # 100 KB line
        huge_line = "INFO:test_module:" + ("Z" * 100_000)
        r = log_parser_mod.log_parser({"action": "parse", "text": huge_line, "format": "python"})
        assert_standard_envelope(r, expect_ok=True)
        self.assertEqual(r["data"]["parsed_count"], 1)

        # Payload exceeding 4 MB
        oversized = "A" * (4 * 1024 * 1024 + 10)
        r_over = log_parser_mod.log_parser({"action": "parse", "text": oversized})
        assert_standard_envelope(r_over, expect_ok=False)
        self.assertIn("exceeds maximum limit", r_over["error"])

    def test_truncated_and_nested_tracebacks(self):
        # Abruptly truncated traceback
        truncated = (
            "2024-01-01 10:00:00 [ERROR] Crash occurred\n"
            "Traceback (most recent call last):\n"
            '  File "/var/app/worker.py", line 123, in execute_task\n'
            "    res = client.send(payload)\n"
        )
        r = log_parser_mod.log_parser({"action": "extract_traces", "text": truncated})
        assert_standard_envelope(r, expect_ok=True)
        self.assertEqual(r["data"]["traces_count"], 1)
        trace = r["data"]["traces"][0]
        self.assertEqual(trace["frames_count"], 1)
        self.assertEqual(trace["frames"][0]["file"], "/var/app/worker.py")
        self.assertEqual(trace["frames"][0]["line"], 123)

        # Traceback with no frames
        no_frames = (
            "Traceback (most recent call last):\n"
            "ZeroDivisionError: division by zero\n"
        )
        r2 = log_parser_mod.log_parser({"action": "extract_traces", "text": no_frames})
        assert_standard_envelope(r2, expect_ok=True)
        self.assertEqual(r2["data"]["traces_count"], 1)
        self.assertEqual(r2["data"]["traces"][0]["exception_type"], "ZeroDivisionError")

    def test_mixed_format_streams_and_detection(self):
        mixed = (
            '{"level": "INFO", "message": "JSON 1"}\n'
            '{"level": "WARN", "message": "JSON 2"}\n'
            "Oct 11 22:14:15 srv app[123]: Syslog event\n"
            '127.0.0.1 - - [10/Oct/2000:13:55:36 -0700] "GET / HTTP/1.0" 200 123 "-" "-"\n'
            "Garbage line that matches nothing\n"
        )
        # Format detection
        r_det = log_parser_mod.log_parser({"action": "detect_format", "text": mixed})
        assert_standard_envelope(r_det, expect_ok=True)
        self.assertIn(r_det["data"]["detected_format"], ["json", "syslog", "nginx_combined"])

        # Aggregation
        r_agg = log_parser_mod.log_parser({"action": "aggregate", "text": mixed, "format": "json"})
        assert_standard_envelope(r_agg, expect_ok=True)
        self.assertEqual(r_agg["data"]["total_records"], 2)
        self.assertIn("INFO", r_agg["data"]["by_level"])
        self.assertIn("WARN", r_agg["data"]["by_level"])

    def test_credential_and_secret_redaction(self):
        log_with_secrets = (
            '{"level": "INFO", "message": "User auth: Bearer secret_jwt_token_12345."}\n'
            '{"level": "INFO", "message": "Params: password=MySecretP@ss&apikey=AKIA123456789"}\n'
            '{"level": "INFO", "message": "Connecting to https://admin:SuperSecretPass@db.internal:5432/main"}\n'
        )
        r = log_parser_mod.log_parser({"action": "parse", "text": log_with_secrets, "format": "json"})
        assert_standard_envelope(r, expect_ok=True)
        records = r["data"]["records"]
        self.assertNotIn("secret_jwt_token_12345", records[0]["message"])
        self.assertIn("Bearer [REDACTED]", records[0]["message"])
        self.assertNotIn("MySecretP@ss", records[1]["message"])
        self.assertIn("password=[REDACTED]", records[1]["message"])
        self.assertNotIn("SuperSecretPass", records[2]["message"])
        self.assertIn(":[REDACTED]@", records[2]["message"])


class TestRegexToolAdversarial(unittest.TestCase):
    """Stress tests and boundary checks for regex_tool module."""

    def test_redos_static_detection(self):
        dangerous_patterns = [
            r"^(a+)+$",
            r"(a*)*b",
            r"([0-9]+)+$",
            r"(x|y+)+",
            r"a{1,}a{2,}",
        ]
        for pat in dangerous_patterns:
            r = regex_tool_mod.regex_tool({"action": "check_pattern", "pattern": pat})
            assert_standard_envelope(r, expect_ok=True)
            self.assertFalse(r["data"]["is_safe"], f"Pattern {pat!r} was falsely marked safe")
            self.assertGreater(len(r["data"]["warnings"]), 0)

    def test_nested_subgroup_redos_runtime_containment(self):
        # Multi-level nested group ReDoS pattern that bypasses shallow static regex heuristic:
        # e.g. ((a|b)+)+$
        pattern = r"((a|b)+)+$"
        hostile_text = ("a" * 28) + "!"
        t0 = time.time()
        r = regex_tool_mod.regex_tool({
            "action": "search",
            "pattern": pattern,
            "text": hostile_text,
        })
        elapsed = time.time() - t0
        assert_standard_envelope(r, expect_ok=False)
        self.assertIn("timed out", r["error"].lower())
        self.assertLess(elapsed, 2.5, f"Runtime timeout guard took {elapsed:.2f}s, expected <=2.5s")

    def test_redos_execution_timeout_guard(self):
        # Catastrophic backtracking input
        pattern = r"^(a+)+$"
        hostile_text = ("a" * 28) + "!"
        t0 = time.time()
        r = regex_tool_mod.regex_tool({
            "action": "search",
            "pattern": pattern,
            "text": hostile_text,
        })
        elapsed = time.time() - t0
        assert_standard_envelope(r, expect_ok=False)
        self.assertIn("timed out", r["error"].lower())
        # The timeout is set to 1.0s, so it must complete in ~1.0-1.5s
        self.assertLess(elapsed, 2.5, f"Timeout took {elapsed:.2f}s, expected <=2.5s")

    def test_invalid_syntax_and_duplicate_groups(self):
        invalid_patterns = [
            r"(abc",  # unclosed parenthesis
            r"*abc",  # nothing to repeat
            r"[z-a]",  # bad range
            r"(?P<name>abc)(?P<name>def)",  # duplicate group name
        ]
        for pat in invalid_patterns:
            r = regex_tool_mod.regex_tool({"action": "check_pattern", "pattern": pat})
            assert_standard_envelope(r, expect_ok=False)
            self.assertIn("Invalid regular expression", r["error"])

    def test_length_and_byte_limits(self):
        # Pattern exceeding 1024 characters
        long_pattern = "a" * 1025
        r = regex_tool_mod.regex_tool({"action": "check_pattern", "pattern": long_pattern})
        assert_standard_envelope(r, expect_ok=False)
        self.assertIn("maximum length", r["error"])

        # Text exceeding 512 KB
        oversized_text = "b" * (512 * 1024 + 1)
        r2 = regex_tool_mod.regex_tool({
            "action": "match",
            "pattern": "b+",
            "text": oversized_text,
        })
        assert_standard_envelope(r2, expect_ok=False)
        self.assertIn("exceeds maximum limit", r2["error"])

    def test_match_limit_enforcement(self):
        # findall with limit=10 on 100 matches
        text = " ".join(f"item_{i}" for i in range(100))
        r = regex_tool_mod.regex_tool({
            "action": "findall",
            "pattern": r"item_\d+",
            "text": text,
            "limit": 10,
        })
        assert_standard_envelope(r, expect_ok=True)
        self.assertEqual(r["data"]["matches_count"], 10)
        self.assertTrue(r["data"]["truncated"])

        # sub with limit=3
        r_sub = regex_tool_mod.regex_tool({
            "action": "sub",
            "pattern": r"item_\d+",
            "replacement": "REPLACED",
            "text": text,
            "limit": 3,
        })
        assert_standard_envelope(r_sub, expect_ok=True)
        self.assertEqual(r_sub["data"]["replacements_count"], 3)
        self.assertEqual(r_sub["data"]["new_text"].count("REPLACED"), 3)

    def test_flags_handling_and_validation(self):
        # Valid flags as list
        r = regex_tool_mod.regex_tool({
            "action": "search",
            "pattern": "hello",
            "text": "HELLO WORLD",
            "flags": ["IGNORECASE"],
        })
        assert_standard_envelope(r, expect_ok=True)
        self.assertTrue(r["data"]["found"])

        # Valid flags as pipe-separated string
        r2 = regex_tool_mod.regex_tool({
            "action": "search",
            "pattern": "^world",
            "text": "hello\nworld",
            "flags": "MULTILINE",
        })
        assert_standard_envelope(r2, expect_ok=True)
        self.assertTrue(r2["data"]["found"])

        # Invalid flag
        r_inv = regex_tool_mod.regex_tool({
            "action": "search",
            "pattern": "test",
            "text": "test",
            "flags": ["BOGUS_FLAG"],
        })
        assert_standard_envelope(r_inv, expect_ok=False)
        self.assertIn("Unsupported regex flag", r_inv["error"])


class TestHashChecksumAdversarial(unittest.TestCase):
    """Stress tests and boundary checks for hash_checksum module."""

    def test_nonexistent_and_permission_denied_files(self):
        with tempfile.TemporaryDirectory() as td:
            # Non-existent file
            r = hash_checksum_mod.hash_checksum({
                "action": "hash_file",
                "path": str(Path(td) / "does_not_exist.bin"),
            })
            assert_standard_envelope(r, expect_ok=False)
            self.assertIn("FileNotFoundError", r["error"])

            # Permission denied file (chmod 000)
            noperm = Path(td) / "noperm.txt"
            noperm.write_text("secret content")
            os.chmod(noperm, 0o000)
            try:
                r_perm = hash_checksum_mod.hash_checksum({
                    "action": "hash_file",
                    "path": str(noperm),
                })
                assert_standard_envelope(r_perm, expect_ok=False)
                self.assertIn("PermissionError", r_perm["error"])
            finally:
                os.chmod(noperm, 0o644)

    def test_zero_byte_file_and_empty_text(self):
        # Zero byte file hashing
        with tempfile.TemporaryDirectory() as td:
            empty_file = Path(td) / "empty.dat"
            empty_file.write_bytes(b"")

            r_file = hash_checksum_mod.hash_checksum({
                "action": "hash_file",
                "path": str(empty_file),
                "algorithm": "sha256",
            })
            assert_standard_envelope(r_file, expect_ok=True)
            empty_sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            self.assertEqual(r_file["data"]["hash"], empty_sha256)
            self.assertEqual(r_file["data"]["size_bytes"], 0)

            # Zero byte text hashing
            r_text = hash_checksum_mod.hash_checksum({
                "action": "hash_text",
                "text": "",
                "algorithm": "sha256",
            })
            assert_standard_envelope(r_text, expect_ok=True)
            self.assertEqual(r_text["data"]["hash"], empty_sha256)
            self.assertEqual(r_text["data"]["length_bytes"], 0)

    def test_multi_chunk_streaming_integrity(self):
        # File larger than 64 KB chunk size (e.g. 250 KB)
        with tempfile.TemporaryDirectory() as td:
            chunked_file = Path(td) / "large.bin"
            data = b"0123456789ABCDEF" * (16 * 1024)  # 256 KB
            chunked_file.write_bytes(data)

            r = hash_checksum_mod.hash_checksum({
                "action": "hash_file",
                "path": str(chunked_file),
                "algorithm": "sha512",
            })
            assert_standard_envelope(r, expect_ok=True)
            expected_sha512 = hashlib.sha512(data).hexdigest()
            self.assertEqual(r["data"]["hash"], expected_sha512)
            self.assertEqual(r["data"]["size_bytes"], len(data))

    def test_hmac_correct_vs_incorrect_keys(self):
        secret_key = "correct_secret_key"
        wrong_key = "incorrect_secret_key"
        message = "Jarvis mission dispatch payload"

        r_correct = hash_checksum_mod.hash_checksum({
            "action": "hmac",
            "key": secret_key,
            "text": message,
            "algorithm": "sha256",
        })
        assert_standard_envelope(r_correct, expect_ok=True)
        correct_hmac = r_correct["data"]["hmac"]

        r_wrong = hash_checksum_mod.hash_checksum({
            "action": "hmac",
            "key": wrong_key,
            "text": message,
            "algorithm": "sha256",
        })
        assert_standard_envelope(r_wrong, expect_ok=True)
        wrong_hmac = r_wrong["data"]["hmac"]

        self.assertNotEqual(correct_hmac, wrong_hmac)

        # Empty key error
        r_empty_key = hash_checksum_mod.hash_checksum({
            "action": "hmac",
            "key": "",
            "text": message,
        })
        assert_standard_envelope(r_empty_key, expect_ok=False)

    def test_manifest_verification_edge_cases(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            f1 = base / "file1.txt"
            f1.write_text("content of file 1")
            h1 = hashlib.sha256(f1.read_bytes()).hexdigest()

            f2 = base / "file2.txt"
            f2.write_text("content of file 2")
            h2 = hashlib.md5(f2.read_bytes()).hexdigest()

            manifest = (
                f"# Standard sha256 checksum\n"
                f"{h1}  file1.txt\n"
                f"# BSD md5 checksum\n"
                f"MD5 (file2.txt) = {h2}\n"
                f"# Mismatched hash\n"
                f"{'0' * 64}  file1.txt\n"
                f"# Missing file\n"
                f"{h1}  missing.txt\n"
                f"# Malformed line\n"
                f"this line is not a valid checksum line\n"
            )

            r = hash_checksum_mod.hash_checksum({
                "action": "verify_checksums",
                "checksums_text": manifest,
                "path": str(base / "manifest.sha256"),
            })
            assert_standard_envelope(r, expect_ok=True)
            self.assertEqual(r["data"]["total"], 5)
            self.assertEqual(r["data"]["passed"], 2)
            self.assertEqual(r["data"]["failed"], 3)
            self.assertFalse(r["data"]["all_ok"])

    def test_algorithm_whitelist_enforcement(self):
        for bad_algo in ["sha3", "shake_128", "ripemd160", "custom_hash"]:
            r = hash_checksum_mod.hash_checksum({
                "action": "hash_text",
                "text": "test",
                "algorithm": bad_algo,
            })
            assert_standard_envelope(r, expect_ok=False)
            self.assertIn("Unsupported algorithm", r["error"])


if __name__ == "__main__":
    unittest.main()
