"""Context budget: bounded tool payloads for the Operator."""
import json
import unittest

import context_budget


class CompressTextTests(unittest.TestCase):
    def test_ansi_and_blank_runs_are_removed(self):
        raw = "\x1b[31mred\x1b[0m\n\n\n\ntext"
        self.assertEqual(context_budget.compress_text(raw), "red\n\ntext")

    def test_repeated_lines_are_collapsed(self):
        raw = "\n".join(["same"] * 20 + ["end"])
        out = context_budget.compress_text(raw)
        self.assertLessEqual(out.count("same"), 3)
        self.assertTrue(out.endswith("end"))

    def test_long_text_keeps_head_and_tail(self):
        raw = "A" * 5000 + "MIDDLE" + "B" * 5000
        out = context_budget.compress_text(raw, 2000)
        self.assertLessEqual(len(out), 2060)
        self.assertIn("chars omitted", out)
        self.assertTrue(out.startswith("A") and out.endswith("B"))
        self.assertNotIn("MIDDLE", out)


class CompressPayloadTests(unittest.TestCase):
    def test_control_fields_survive(self):
        payload = {"ok": True, "status": "done", "ids": [1, 2, 3],
                   "output": "x" * 20000}
        out = context_budget.compress_payload(payload, 1000)
        self.assertIs(out["ok"], True)
        self.assertEqual(out["status"], "done")
        self.assertEqual(out["ids"], [1, 2, 3])
        self.assertLessEqual(len(out["output"]), 1060)

    def test_invalid_json_schema_is_not_invented(self):
        payload = {"elements": [{"index": i, "label": "x" * 50} for i in range(300)]}
        out = context_budget.compress_payload(payload, 800, max_items=20)
        self.assertEqual(len(out["elements"]), 21)
        self.assertIsInstance(out["elements"][-1], str)
        json.dumps(out)

    def test_nested_dict_is_walked(self):
        payload = {"a": {"b": {"text": "y" * 9000}}}
        out = context_budget.compress_payload(payload, 500)
        self.assertLessEqual(len(out["a"]["b"]["text"]), 530)

    def test_stats_reports_savings(self):
        stats = context_budget.stats("x" * 8000, "x" * 400)
        self.assertEqual(stats["chars_before"], 8000)
        self.assertGreater(stats["tokens_saved"], 0)


if __name__ == "__main__":
    unittest.main()
