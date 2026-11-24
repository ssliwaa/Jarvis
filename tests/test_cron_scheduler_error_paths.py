"""Automated error-path suite for operator_modules/cron_scheduler.py.

Completes raise coverage for the crontab scheduling operator:
- cron-expression parse guards (invalid step expressions, invalid
  tokens) reached through the dispatcher's validate action
- ISO8601 from_time parsing guard for next_runs
- the empty-field guard of _parse_field, which cannot be reached
  through the dispatcher because the expression tokenizer's split()
  never produces empty fields -- verified directly on the parser, the
  convention used for validator branches in previous error-path waves
- a characterization test documenting that the "No valid values
  produced" guard (line 99) is invariant-only defense: for every real
  caller (min_val <= max_val), any part that passes the preceding
  guards contributes at least its start value, so values can never be
  empty; the test pins that nearest-neighbour inputs ("*/70", "1/5")
  succeed with a non-empty value set instead of raising

100% offline and deterministic; no time or timezone dependence.
"""

from __future__ import annotations

import unittest

import operator_modules.cron_scheduler as cs


class TestCronParseGuards(unittest.TestCase):
    """CronParseError branches of _parse_field and _parse_expression."""

    def test_invalid_step_expression_rejected(self):
        # Line 70: a field part with two slashes cannot form a
        # range/step pair.
        res = cs.cron_scheduler({"action": "validate",
                                 "expression": "0 0 1/2/3 * *"})
        self.assertFalse(res["ok"])
        self.assertIn("CronParseError", res["error"])
        self.assertIn("Invalid step expression: '1/2/3'", res["error"])

    def test_invalid_token_rejected(self):
        # Line 90: '?' is a Quartz-style token that Vixie cron fields
        # do not accept; the dom field has no name map, so it stays a
        # literal and must be rejected.
        res = cs.cron_scheduler({"action": "validate",
                                 "expression": "0 0 ? * *"})
        self.assertFalse(res["ok"])
        self.assertIn("CronParseError", res["error"])
        self.assertIn("Invalid token in field: '?'", res["error"])

    def test_empty_field_rejected_directly(self):
        # Line 50: the dispatcher tokenizes with split(), which never
        # produces empty fields, so the guard is verified directly on
        # the parser.
        with self.assertRaises(cs.CronParseError) as ctx:
            cs._parse_field("   ", 0, 59)
        self.assertIn("Empty field encountered in cron expression.",
                      str(ctx.exception))

    def test_no_valid_values_guard_is_invariant_defense(self):
        # Line 99 characterization: any part passing the preceding
        # guards contributes at least its start value (range semantics
        # with start <= end and positive step), so 'values' can only be
        # empty for hypothetical min>max callers that do not exist.
        # Nearest-neighbour inputs therefore succeed with non-empty
        # field values instead of raising.
        res = cs.cron_scheduler({"action": "validate",
                                 "expression": "*/70 * * * *"})
        self.assertTrue(res["ok"])
        self.assertEqual(res["data"]["fields"]["minute"], [0])

        res2 = cs.cron_scheduler({"action": "validate",
                                  "expression": "1/5 * * * *"})
        self.assertTrue(res2["ok"])
        # Updated in iteration CS alongside the vixie-cron "N/step"
        # fix: the pre-fix module parsed "1/5" to [1]; the
        # characterization was superseded by the deliberate semantics
        # change (now N/step == N-max/step), not to force a green run.
        self.assertEqual(res2["data"]["fields"]["minute"],
                         [1, 6, 11, 16, 21, 26, 31, 36, 41, 46, 51, 56])


class TestFromTimeGuard(unittest.TestCase):
    """ISO8601 parsing guard for reference timestamps."""

    def test_invalid_iso_timestamp_rejected(self):
        # Line 251: fromisoformat failure surfaces as a controlled
        # ValueError inside the error envelope.
        res = cs.cron_scheduler({"action": "next_runs",
                                 "expression": "@daily",
                                 "from_time": "not-a-date"})
        self.assertFalse(res["ok"])
        self.assertIn("ValueError", res["error"])
        self.assertIn("Invalid ISO8601 timestamp for 'from_time': "
                      "'not-a-date'", res["error"])

    def test_valid_iso_timestamp_accepted_for_contrast(self):
        # Contrast anchor: a valid ISO timestamp parses and the run
        # calculation proceeds.
        res = cs.cron_scheduler({"action": "next_runs",
                                 "expression": "@daily",
                                 "from_time": "2026-11-24T12:00:00+00:00"})
        self.assertTrue(res["ok"])
        self.assertIsNone(res["error"])
        self.assertTrue(res["data"]["runs"])


class TestErrorEnvelopeShape(unittest.TestCase):
    """Error envelope contract shared by cron_scheduler failures."""

    def test_error_envelope_shape(self):
        res = cs.cron_scheduler({"action": "validate",
                                 "expression": "0 0 ? * *"})
        self.assertEqual(set(res), {"ok", "success", "data", "result",
                                    "error"})
        self.assertFalse(res["ok"])
        self.assertFalse(res["success"])
        self.assertIsNone(res["data"])
        self.assertIsNone(res["result"])
        self.assertIsInstance(res["error"], str)


if __name__ == "__main__":
    unittest.main()
