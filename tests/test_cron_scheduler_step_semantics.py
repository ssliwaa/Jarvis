"""Regression suite for crontab N/step semantics in cron_scheduler.

Pins the fix that aligns single-value-with-step fields with
mainstream vixie-cron implementations: "N/step" expands to
"N-max/step" (Wikipedia/cron: "15/XX is the same as a vixie-cron
schedule of 15-59/10 in the minutes section"; Debian crontab(5)
documents ranges-with-steps as "1-9/2 is the same as 1,3,5,7,9").
Research content is treated as data; no external code was adapted.

Guards the unchanged neighbours too: plain values, wildcards with
steps, and ranges with steps keep their exact previous semantics.

100% offline and deterministic (fixed ISO from_time, UTC timezone).
"""

from __future__ import annotations

import unittest

import operator_modules.cron_scheduler as cs


class TestSingleValueStepSemantics(unittest.TestCase):
    """'N/step' == 'N-max/step' per vixie-cron."""

    def test_single_value_with_step_expands_to_field_max(self):
        res = cs.cron_scheduler({"action": "validate",
                                 "expression": "1/5 * * * *"})
        self.assertTrue(res["ok"])
        self.assertEqual(
            res["data"]["fields"]["minute"],
            [1, 6, 11, 16, 21, 26, 31, 36, 41, 46, 51, 56],
        )

        res_hours = cs.cron_scheduler({"action": "validate",
                                       "expression": "0 5/15 * * *"})
        self.assertTrue(res_hours["ok"])
        self.assertEqual(res_hours["data"]["fields"]["hour"], [5, 20])

        res_dom = cs.cron_scheduler({"action": "validate",
                                     "expression": "0 0 1/7 * *"})
        self.assertTrue(res_dom["ok"])
        self.assertEqual(res_dom["data"]["fields"]["day_of_month"],
                         [1, 8, 15, 22, 29])

    def test_step_from_field_edge_yields_single_value(self):
        # Starting at the field maximum leaves only the start value.
        res = cs.cron_scheduler({"action": "validate",
                                 "expression": "59/5 * * * *"})
        self.assertTrue(res["ok"])
        self.assertEqual(res["data"]["fields"]["minute"], [59])

    def test_next_run_honors_expanded_step(self):
        # Before the fix this expression matched only minute 1; now
        # every 5th minute from 1 belongs to the schedule.
        res = cs.cron_scheduler({
            "action": "next_runs",
            "expression": "1/5 * * * *",
            "from_time": "2026-11-24T12:00:00+00:00",
            "count": 3,
            "timezone": "UTC",
        })
        self.assertTrue(res["ok"])
        self.assertEqual(res["data"]["runs"][0],
                         "2026-11-24T12:01:00+00:00")
        self.assertEqual(res["data"]["runs"][1],
                         "2026-11-24T12:06:00+00:00")


class TestUnchangedNeighbours(unittest.TestCase):
    """Neighbors of the change keep their exact previous semantics."""

    def test_plain_single_value_unchanged(self):
        res = cs.cron_scheduler({"action": "validate",
                                 "expression": "5 * * * *"})
        self.assertTrue(res["ok"])
        self.assertEqual(res["data"]["fields"]["minute"], [5])

    def test_wildcard_step_unchanged(self):
        res = cs.cron_scheduler({"action": "validate",
                                 "expression": "*/5 * * * *"})
        self.assertTrue(res["ok"])
        self.assertEqual(res["data"]["fields"]["minute"],
                         [0, 5, 10, 15, 20, 25, 30, 35, 40, 45, 50, 55])

    def test_wildcard_step_overflow_keeps_start(self):
        # Oversized step over a wildcard still yields the start value
        # only (pinned by tests/test_challenger_batch3_1.py too).
        res = cs.cron_scheduler({"action": "validate",
                                 "expression": "*/70 * * * *"})
        self.assertTrue(res["ok"])
        self.assertEqual(res["data"]["fields"]["minute"], [0])

    def test_range_step_unchanged(self):
        # Debian crontab(5) example: 1-9/2 == 1,3,5,7,9.
        res = cs.cron_scheduler({"action": "validate",
                                 "expression": "1-9/2 * * * *"})
        self.assertTrue(res["ok"])
        self.assertEqual(res["data"]["fields"]["minute"],
                         [1, 3, 5, 7, 9])

    def test_aliases_still_resolve(self):
        res = cs.cron_scheduler({"action": "validate",
                                 "expression": "@daily"})
        self.assertTrue(res["ok"])
        self.assertEqual(res["data"]["fields"]["minute"], [0])
        self.assertEqual(res["data"]["fields"]["hour"], [0])

    def test_range_with_oversized_step_unchanged(self):
        # Pinned by tests/test_challenger_batch3_1.py: 1-31/50 -> [1].
        res = cs.cron_scheduler({"action": "validate",
                                 "expression": "* * 1-31/50 * *"})
        self.assertTrue(res["ok"])
        self.assertEqual(res["data"]["fields"]["day_of_month"], [1])


if __name__ == "__main__":
    unittest.main()
