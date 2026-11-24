"""Token meter: normalization, accumulation and optional cost."""
import os
import unittest
from unittest import mock

import usage_meter


class UsageTests(unittest.TestCase):
    def setUp(self):
        usage_meter.reset()
        self.addCleanup(usage_meter.reset)

    def test_openai_and_anthropic_shapes_normalise(self):
        openai = usage_meter.normalize({"prompt_tokens": 10, "completion_tokens": 4, "total_tokens": 14})
        anthropic = usage_meter.normalize({"input_tokens": 10, "output_tokens": 4})
        self.assertEqual(openai, {"prompt_tokens": 10, "completion_tokens": 4, "total_tokens": 14})
        self.assertEqual(anthropic["total_tokens"], 14)

    def test_empty_usage_is_never_counted(self):
        usage_meter.record({}, "model")
        self.assertEqual(usage_meter.snapshot()["calls"], 0)

    def test_records_accumulate_per_model(self):
        usage_meter.record({"prompt_tokens": 100, "completion_tokens": 20}, "deepseek-flash")
        usage_meter.record({"prompt_tokens": 50, "completion_tokens": 10}, "deepseek-flash")
        snap = usage_meter.snapshot()
        self.assertEqual(snap["calls"], 2)
        self.assertEqual(snap["prompt_tokens"], 150)
        self.assertEqual(snap["by_model"]["deepseek-flash"]["total_tokens"], 180)

    def test_cost_is_none_unless_prices_are_configured(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("JARVIS_PRICE_INPUT", None)
            os.environ.pop("JARVIS_PRICE_OUTPUT", None)
            usage_meter.record({"prompt_tokens": 1_000_000, "completion_tokens": 0})
            snap = usage_meter.snapshot()
        self.assertIsNone(snap["cost_usd"])
        self.assertFalse(snap["priced"])

    def test_cost_uses_the_configured_rates(self):
        with mock.patch.dict(os.environ, {"JARVIS_PRICE_INPUT": "0.28",
                                          "JARVIS_PRICE_OUTPUT": "0.42"}):
            usage_meter.record({"prompt_tokens": 1_000_000, "completion_tokens": 1_000_000})
            snap = usage_meter.snapshot()
        self.assertTrue(snap["priced"])
        self.assertAlmostEqual(snap["cost_usd"], 0.70, places=6)

    def test_bad_price_config_is_ignored(self):
        with mock.patch.dict(os.environ, {"JARVIS_PRICE_INPUT": "abc",
                                          "JARVIS_PRICE_OUTPUT": "1"}):
            self.assertIsNone(usage_meter.price())


if __name__ == "__main__":
    unittest.main()
