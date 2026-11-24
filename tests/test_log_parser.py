"""Tests for operator_modules/log_parser.py."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import operator_modules.log_parser as log_parser_mod


class TestLogParser(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_tool_declaration_contract(self):
        tool = log_parser_mod.TOOL
        self.assertEqual(tool["name"], "log_parser")
        self.assertFalse(tool["approval"])
        self.assertTrue(callable(tool["handler"]))
        self.assertLessEqual(len(tool["description"]), 1600)
        schema = tool["input_schema"]
        self.assertEqual(schema["type"], "object")
        self.assertFalse(schema["additionalProperties"])
        self.assertIn("action", schema["required"])

    def test_parse_json_lines(self):
        lines = [
            json.dumps({"timestamp": "2026-11-20T10:00:00Z", "level": "INFO", "message": "Server started"}),
            json.dumps({"timestamp": "2026-11-20T10:01:00Z", "level": "ERROR", "message": "Database connection lost"}),
        ]
        text = "\n".join(lines)
        res = log_parser_mod.log_parser({
            "action": "parse",
            "text": text,
            "format": "json",
        })
        self.assertTrue(res["ok"])
        self.assertTrue(res["success"])
        self.assertEqual(res["data"]["parsed_count"], 2)
        records = res["data"]["records"]
        self.assertEqual(records[0]["level"], "INFO")
        self.assertEqual(records[0]["message"], "Server started")
        self.assertEqual(records[1]["level"], "ERROR")
        self.assertEqual(records[1]["message"], "Database connection lost")

    def test_parse_syslog_rfc3164(self):
        log_text = "Oct 11 22:14:15 server1 sshd[1234]: Failed password for root from 192.168.1.1\n"
        res = log_parser_mod.log_parser({
            "action": "parse",
            "text": log_text,
            "format": "syslog",
        })
        self.assertTrue(res["ok"])
        self.assertEqual(res["data"]["parsed_count"], 1)
        rec = res["data"]["records"][0]
        self.assertEqual(rec["host"], "server1")
        self.assertEqual(rec["program"], "sshd")
        self.assertEqual(rec["pid"], 1234)
        self.assertIn("Failed password", rec["message"])

    def test_parse_nginx_combined(self):
        log_line = (
            '192.168.1.100 - user1 [20/Nov/2026:14:32:10 +0000] "GET /api/v1/users HTTP/1.1" '
            '200 4523 "https://example.com" "Mozilla/5.0"\n'
        )
        res = log_parser_mod.log_parser({
            "action": "parse",
            "text": log_line,
            "format": "nginx_combined",
        })
        self.assertTrue(res["ok"])
        rec = res["data"]["records"][0]
        self.assertEqual(rec["client_ip"], "192.168.1.100")
        self.assertEqual(rec["user"], "user1")
        self.assertEqual(rec["status"], 200)
        self.assertEqual(rec["bytes"], 4523)
        self.assertEqual(rec["level"], "INFO")

    def test_parse_python_logger(self):
        log_lines = (
            "2026-11-20 14:02:00,123 - my_app - INFO - Application initialized\n"
            "2026-11-20 14:02:05,456 - my_app - ERROR - Failed to bind port 8080\n"
        )
        res = log_parser_mod.log_parser({
            "action": "parse",
            "text": log_lines,
            "format": "python",
        })
        self.assertTrue(res["ok"])
        self.assertEqual(res["data"]["parsed_count"], 2)
        records = res["data"]["records"]
        self.assertEqual(records[0]["level"], "INFO")
        self.assertEqual(records[1]["level"], "ERROR")
        self.assertEqual(records[1]["logger"], "my_app")

    def test_auto_detect_format(self):
        nginx_sample = (
            '127.0.0.1 - - [20/Nov/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 612 "-" "curl/7.88.1"\n'
            '127.0.0.1 - - [20/Nov/2026:10:00:01 +0000] "GET /index.html HTTP/1.1" 200 612 "-" "curl/7.88.1"\n'
        )
        res = log_parser_mod.log_parser({
            "action": "detect_format",
            "text": nginx_sample,
        })
        self.assertTrue(res["ok"])
        self.assertIn(res["data"]["detected_format"], ("nginx_combined", "apache_common"))
        self.assertGreater(res["data"]["confidence"], 0.5)

    def test_min_level_filter(self):
        log_lines = (
            "2026-11-20 14:02:00,123 - app - DEBUG - Verbose debug info\n"
            "2026-11-20 14:02:01,123 - app - INFO - Processing task\n"
            "2026-11-20 14:02:02,123 - app - WARNING - High memory usage\n"
            "2026-11-20 14:02:03,123 - app - ERROR - Task timeout\n"
        )
        res = log_parser_mod.log_parser({
            "action": "parse",
            "text": log_lines,
            "format": "python",
            "min_level": "WARNING",
        })
        self.assertTrue(res["ok"])
        self.assertEqual(res["data"]["parsed_count"], 2)
        levels = [r["level"] for r in res["data"]["records"]]
        self.assertEqual(levels, ["WARNING", "ERROR"])

    def test_aggregate_action(self):
        lines = [
            json.dumps({"level": "INFO", "message": "Worker 1 started"}),
            json.dumps({"level": "INFO", "message": "Worker 2 started"}),
            json.dumps({"level": "ERROR", "message": "Worker 3 crashed"}),
            json.dumps({"level": "CRITICAL", "message": "Master out of memory"}),
        ]
        res = log_parser_mod.log_parser({
            "action": "aggregate",
            "text": "\n".join(lines),
            "format": "json",
        })
        self.assertTrue(res["ok"])
        agg = res["data"]
        self.assertEqual(agg["total_records"], 4)
        self.assertEqual(agg["by_level"]["INFO"], 2)
        self.assertEqual(agg["by_level"]["ERROR"], 1)
        self.assertEqual(agg["by_level"]["CRITICAL"], 1)
        self.assertEqual(agg["error_count"], 2)

    def test_extract_traces(self):
        log_text = """
2026-11-20 12:00:00 INFO Normal operation
2026-11-20 12:01:00 ERROR An unhandled error occurred:
Traceback (most recent call last):
  File "/app/handler.py", line 42, in process_request
    result = compute_total(items)
  File "/app/math.py", line 15, in compute_total
    return 100 / count
ZeroDivisionError: division by zero
2026-11-20 12:02:00 INFO Resumed operations
"""
        res = log_parser_mod.log_parser({
            "action": "extract_traces",
            "text": log_text,
        })
        self.assertTrue(res["ok"])
        self.assertEqual(res["data"]["traces_count"], 1)
        trace = res["data"]["traces"][0]
        self.assertEqual(trace["exception_type"], "ZeroDivisionError")
        self.assertEqual(trace["message"], "division by zero")
        self.assertEqual(trace["frames_count"], 2)
        self.assertEqual(trace["frames"][0]["file"], "/app/handler.py")
        self.assertEqual(trace["frames"][0]["line"], 42)

    def test_secret_sanitization(self):
        log_text = json.dumps({
            "level": "INFO",
            "message": "Auth request with Bearer eyJhbGciOiJIUzI1NiJ9.test and password=SuperSecretPassword123",
        })
        res = log_parser_mod.log_parser({
            "action": "parse",
            "text": log_text,
            "format": "json",
        })
        self.assertTrue(res["ok"])
        msg = res["data"]["records"][0]["message"]
        self.assertNotIn("SuperSecretPassword123", msg)
        self.assertNotIn("eyJhbGciOiJIUzI1NiJ9.test", msg)
        self.assertIn("Bearer [REDACTED]", msg)
        self.assertIn("password=[REDACTED]", msg)

    def test_path_read_file(self):
        log_file = self.root / "app.log"
        log_file.write_text("INFO:root:Hello from log file\n", encoding="utf-8")

        res = log_parser_mod.log_parser({
            "action": "parse",
            "path": str(log_file),
            "format": "python",
        })
        self.assertTrue(res["ok"])
        self.assertEqual(res["data"]["parsed_count"], 1)
        self.assertEqual(res["data"]["records"][0]["message"], "Hello from log file")

    def test_oversized_payload_rejected(self):
        oversized = "a\n" * (2 * 1024 * 1024 + 10)
        res = log_parser_mod.log_parser({
            "action": "parse",
            "text": oversized,
        })
        self.assertFalse(res["ok"])
        self.assertIn("exceeds maximum limit", res["error"])

    def test_traversal_path_blocked(self):
        res = log_parser_mod.log_parser({
            "action": "parse",
            "path": "../../../etc/shadow",
        })
        self.assertFalse(res["ok"])
        self.assertIn("traversal", res["error"].lower())

    def test_missing_input_error(self):
        res = log_parser_mod.log_parser({"action": "parse"})
        self.assertFalse(res["ok"])
        self.assertIn("Either 'text' or 'path'", res["error"])

    def test_unsupported_action(self):
        res = log_parser_mod.log_parser({"action": "bad_action", "text": "foo"})
        self.assertFalse(res["ok"])
        self.assertIn("Unsupported action", res["error"])
