"""Tests for operator_modules/cron_scheduler.py."""

from __future__ import annotations

import unittest

import operator_modules.cron_scheduler as cron_scheduler_mod


class TestCronScheduler(unittest.TestCase):
    def test_tool_declaration_contract(self):
        tool = cron_scheduler_mod.TOOL
        self.assertEqual(tool["name"], "cron_scheduler")
        self.assertFalse(tool["approval"])
        self.assertTrue(callable(tool["handler"]))
        self.assertLessEqual(len(tool["description"]), 1600)
        schema = tool["input_schema"]
        self.assertEqual(schema["type"], "object")
        self.assertFalse(schema["additionalProperties"])
        self.assertIn("action", schema["required"])
        self.assertIn("expression", schema["required"])

    def test_validate_standard_expression(self):
        res = cron_scheduler_mod.cron_scheduler({
            "action": "validate",
            "expression": "*/15 9-17 * * 1-5",
        })
        self.assertTrue(res["ok"])
        self.assertTrue(res["success"])
        self.assertIsNone(res["error"])
        self.assertTrue(res["data"]["valid"])
        self.assertEqual(res["data"]["fields"]["minute"], [0, 15, 30, 45])
        self.assertEqual(res["data"]["fields"]["hour"], list(range(9, 18)))
        self.assertEqual(res["data"]["fields"]["day_of_week"], [1, 2, 3, 4, 5])
        self.assertEqual(res["result"], res["data"])

    def test_validate_aliases(self):
        for alias in ["@daily", "@weekly", "@monthly", "@yearly", "@hourly"]:
            res = cron_scheduler_mod.cron_scheduler({
                "action": "validate",
                "expression": alias,
            })
            self.assertTrue(res["ok"], f"Failed for alias {alias}")
            self.assertTrue(res["data"]["valid"])

    def test_validate_month_and_dow_names(self):
        res = cron_scheduler_mod.cron_scheduler({
            "action": "validate",
            "expression": "0 12 1 JAN,JUN,DEC MON,FRI",
        })
        self.assertTrue(res["ok"])
        self.assertEqual(res["data"]["fields"]["month"], [1, 6, 12])
        self.assertEqual(res["data"]["fields"]["day_of_week"], [1, 5])

    def test_validate_invalid_expressions(self):
        invalid_cases = [
            "60 * * * *",        # minute > 59
            "* 24 * * *",        # hour > 23
            "* * 32 * *",        # dom > 31
            "* * * 13 *",        # month > 12
            "* * * * 8",         # dow > 7
            "* * * *",           # only 4 fields
            "* * * * * *",       # 6 fields
            "10-5 * * * *",      # range start > end
            "*/0 * * * *",       # step 0
            "invalid_text",      # unparseable
        ]
        for expr in invalid_cases:
            res = cron_scheduler_mod.cron_scheduler({
                "action": "validate",
                "expression": expr,
            })
            self.assertFalse(res["ok"], f"Should have failed for: {expr}")
            self.assertFalse(res["success"])
            self.assertIsNotNone(res["error"])

    def test_describe_schedule(self):
        res = cron_scheduler_mod.cron_scheduler({
            "action": "describe",
            "expression": "* * * * *",
        })
        self.assertTrue(res["ok"])
        self.assertEqual(res["data"]["description"], "Every minute")

        res2 = cron_scheduler_mod.cron_scheduler({
            "action": "describe",
            "expression": "0 0 * * *",
        })
        self.assertTrue(res2["ok"])
        self.assertIn("00:00", res2["data"]["description"])

    def test_next_runs_calculation(self):
        res = cron_scheduler_mod.cron_scheduler({
            "action": "next_runs",
            "expression": "0 12 * * *",
            "from_time": "2026-11-20T10:00:00Z",
            "count": 3,
            "timezone": "UTC",
        })
        self.assertTrue(res["ok"])
        self.assertEqual(res["data"]["count"], 3)
        runs = res["data"]["runs"]
        self.assertEqual(len(runs), 3)
        self.assertEqual(runs[0], "2026-11-20T12:00:00+00:00")
        self.assertEqual(runs[1], "2026-11-21T12:00:00+00:00")
        self.assertEqual(runs[2], "2026-11-22T12:00:00+00:00")

    def test_prev_runs_calculation(self):
        res = cron_scheduler_mod.cron_scheduler({
            "action": "prev_runs",
            "expression": "0 12 * * *",
            "from_time": "2026-11-20T10:00:00Z",
            "count": 2,
            "timezone": "UTC",
        })
        self.assertTrue(res["ok"])
        runs = res["data"]["runs"]
        self.assertEqual(len(runs), 2)
        self.assertEqual(runs[0], "2026-11-19T12:00:00+00:00")
        self.assertEqual(runs[1], "2026-11-18T12:00:00+00:00")

    def test_impossible_schedule_bounded_horizon(self):
        # Feb 31st never exists
        res = cron_scheduler_mod.cron_scheduler({
            "action": "next_runs",
            "expression": "0 0 31 2 *",
            "from_time": "2026-11-20T10:00:00Z",
            "count": 1,
        })
        self.assertFalse(res["ok"])
        self.assertIn("search horizon", res["error"].lower())

    def test_matches_action(self):
        res_match = cron_scheduler_mod.cron_scheduler({
            "action": "matches",
            "expression": "30 14 * * *",
            "from_time": "2026-11-20T14:30:15Z",
            "timezone": "UTC",
        })
        self.assertTrue(res_match["ok"])
        self.assertTrue(res_match["data"]["matches"])

        res_no_match = cron_scheduler_mod.cron_scheduler({
            "action": "matches",
            "expression": "30 14 * * *",
            "from_time": "2026-11-20T14:31:00Z",
            "timezone": "UTC",
        })
        self.assertTrue(res_no_match["ok"])
        self.assertFalse(res_no_match["data"]["matches"])

    def test_timezone_handling(self):
        res = cron_scheduler_mod.cron_scheduler({
            "action": "next_runs",
            "expression": "0 9 * * *",
            "from_time": "2026-11-20T06:00:00Z",
            "timezone": "Europe/Warsaw",
            "count": 1,
        })
        self.assertTrue(res["ok"])
        self.assertIn("+01:00", res["data"]["runs"][0])

    def test_invalid_timezone_handling(self):
        res = cron_scheduler_mod.cron_scheduler({
            "action": "next_runs",
            "expression": "* * * * *",
            "timezone": "Invalid/Fake_Zone_123",
        })
        self.assertFalse(res["ok"])
        self.assertIn("timezone", res["error"].lower())

    def test_unsupported_action(self):
        res = cron_scheduler_mod.cron_scheduler({
            "action": "unknown_action",
            "expression": "* * * * *",
        })
        self.assertFalse(res["ok"])
        self.assertIn("Unsupported action", res["error"])

    def test_missing_parameters(self):
        res = cron_scheduler_mod.cron_scheduler({})
        self.assertFalse(res["ok"])
        self.assertIn("action", res["error"].lower())

        res2 = cron_scheduler_mod.cron_scheduler({"action": "validate"})
        self.assertFalse(res2["ok"])
        self.assertIn("expression", res2["error"].lower())
