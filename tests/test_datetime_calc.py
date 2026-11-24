"""Comprehensive test suite for operator_modules/datetime_calc.py."""

from __future__ import annotations

import unittest

import operator_modules.datetime_calc as datetime_calc


class TestDatetimeCalc(unittest.TestCase):
    def test_tool_contract(self):
        tool = datetime_calc.TOOL
        self.assertEqual(tool["name"], "datetime_calc")
        self.assertFalse(tool["approval"])
        self.assertTrue(callable(tool["handler"]))
        self.assertEqual(tool["input_schema"]["type"], "object")
        self.assertFalse(tool["input_schema"]["additionalProperties"])
        self.assertIn("action", tool["input_schema"]["required"])

    def test_action_now(self):
        res = datetime_calc.datetime_calc({"action": "now", "timezone": "Europe/Warsaw"})
        self.assertTrue(res["ok"])
        data = res["data"]
        self.assertIn("iso8601", data)
        self.assertIn("unix_timestamp", data)
        self.assertEqual(data["timezone"], "Europe/Warsaw")
        self.assertIn("day_of_week", data)
        self.assertGreaterEqual(data["year"], 2024)

    def test_action_parse_formats(self):
        # 1. ISO8601
        res1 = datetime_calc.datetime_calc({
            "action": "parse",
            "timestamp": "2026-11-20T19:30:00Z",
        })
        self.assertTrue(res1["ok"])
        self.assertEqual(res1["data"]["year"], 2026)
        self.assertEqual(res1["data"]["month"], 11)
        self.assertEqual(res1["data"]["day"], 20)
        self.assertEqual(res1["data"]["hour"], 19)

        # 2. Date-only YYYY-MM-DD
        res2 = datetime_calc.datetime_calc({
            "action": "parse",
            "timestamp": "2026-05-15",
        })
        self.assertTrue(res2["ok"])
        self.assertEqual(res2["data"]["year"], 2026)
        self.assertEqual(res2["data"]["month"], 5)
        self.assertEqual(res2["data"]["day"], 15)

        # 3. Unix epoch seconds
        res3 = datetime_calc.datetime_calc({
            "action": "parse",
            "timestamp": "1700000000",
        })
        self.assertTrue(res3["ok"])
        self.assertEqual(res3["data"]["unix_timestamp"], 1700000000.0)

        # 4. Unix epoch milliseconds
        res4 = datetime_calc.datetime_calc({
            "action": "parse",
            "timestamp": "1700000000000",
        })
        self.assertTrue(res4["ok"])
        self.assertEqual(res4["data"]["unix_timestamp"], 1700000000.0)

        # 5. RFC2822
        res5 = datetime_calc.datetime_calc({
            "action": "parse",
            "timestamp": "Fri, 20 Nov 2026 12:00:00 +0000",
        })
        self.assertTrue(res5["ok"])
        self.assertEqual(res5["data"]["year"], 2026)
        self.assertEqual(res5["data"]["hour"], 12)

    def test_action_diff_duration_and_business_days(self):
        # From Friday 2026-11-20 10:00:00 to Monday 2026-11-23 15:30:00
        # Calendar diff: 3 days, 5 hours, 30 minutes
        # Business days between them: Monday 23rd is 1 business day (Sat and Sun skipped)
        res = datetime_calc.datetime_calc({
            "action": "diff",
            "timestamp": "2026-11-20T10:00:00Z",
            "timestamp_b": "2026-11-23T15:30:00Z",
        })
        self.assertTrue(res["ok"])
        data = res["data"]
        self.assertEqual(data["days"], 3)
        self.assertEqual(data["hours"], 5)
        self.assertEqual(data["minutes"], 30)
        self.assertEqual(data["business_days"], 1)
        self.assertIn("3 days, 5 hours, 30 minutes", data["humanized"])

        # Negative difference (timestamp_b is before timestamp)
        res_neg = datetime_calc.datetime_calc({
            "action": "diff",
            "timestamp": "2026-11-23T15:30:00Z",
            "timestamp_b": "2026-11-20T10:00:00Z",
        })
        self.assertTrue(res_neg["ok"])
        self.assertLess(res_neg["data"]["total_seconds"], 0)
        self.assertEqual(res_neg["data"]["business_days"], -1)

    def test_action_add_and_subtract_business_days(self):
        # Start at Friday 2026-11-20
        # Adding 1 business day should skip Saturday 21st and Sunday 22nd -> Monday 2026-11-23
        res_add = datetime_calc.datetime_calc({
            "action": "add",
            "timestamp": "2026-11-20T10:00:00Z",
            "business_days": 1,
        })
        self.assertTrue(res_add["ok"])
        self.assertEqual(res_add["data"]["day"], 23)
        self.assertEqual(res_add["data"]["day_of_week"], "Monday")

        # Start at Monday 2026-11-23
        # Subtracting 1 business day should return to Friday 2026-11-20
        res_sub = datetime_calc.datetime_calc({
            "action": "subtract",
            "timestamp": "2026-11-23T10:00:00Z",
            "business_days": 1,
        })
        self.assertTrue(res_sub["ok"])
        self.assertEqual(res_sub["data"]["day"], 20)
        self.assertEqual(res_sub["data"]["day_of_week"], "Friday")

    def test_action_convert_tz(self):
        # 12:00:00 UTC -> 13:00:00 in Europe/Warsaw (winter UTC+1)
        res = datetime_calc.datetime_calc({
            "action": "convert_tz",
            "timestamp": "2026-01-15T12:00:00Z",
            "timezone": "Europe/Warsaw",
        })
        self.assertTrue(res["ok"])
        data = res["data"]
        self.assertEqual(data["hour"], 13)
        self.assertEqual(data["utc_offset"], "+01:00")
        self.assertEqual(data["timezone"], "Europe/Warsaw")

    def test_security_timezone_validation(self):
        # Path traversal timezone name
        res1 = datetime_calc.datetime_calc({
            "action": "now",
            "timezone": "../../../../etc/passwd",
        })
        self.assertFalse(res1["ok"])
        self.assertIn("Invalid timezone", res1["error"])

        # Null byte injection
        res2 = datetime_calc.datetime_calc({
            "action": "now",
            "timezone": "UTC\x00malicious",
        })
        self.assertFalse(res2["ok"])

        # Non-existent timezone
        res3 = datetime_calc.datetime_calc({
            "action": "now",
            "timezone": "NonExistent/Fantasy_Zone_123",
        })
        self.assertFalse(res3["ok"])
        self.assertIn("Unknown timezone", res3["error"])

    def test_security_year_overflow_bounds(self):
        # Year beyond 2100
        res = datetime_calc.datetime_calc({
            "action": "add",
            "timestamp": "2099-01-01T00:00:00Z",
            "days": 1000,
        })
        self.assertFalse(res["ok"])
        self.assertIn("outside safe operating range", res["error"])

    def test_business_day_step_limit(self):
        # Huge business day request exceeds horizon limit (3650 days)
        res = datetime_calc.datetime_calc({
            "action": "add",
            "timestamp": "2026-01-01T00:00:00Z",
            "business_days": 5000,
        })
        self.assertFalse(res["ok"])
        self.assertIn("exceeded step limit", res["error"])

    def test_error_handling(self):
        res1 = datetime_calc.datetime_calc({})
        self.assertFalse(res1["ok"])

        res2 = datetime_calc.datetime_calc({"action": "unknown_action"})
        self.assertFalse(res2["ok"])

        res3 = datetime_calc.datetime_calc({"action": "parse", "timestamp": "invalid-datetime-string"})
        self.assertFalse(res3["ok"])


if __name__ == "__main__":
    unittest.main()
