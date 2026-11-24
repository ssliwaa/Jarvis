"""Paid-endpoint rate limiting and daily budget."""
import unittest
from datetime import datetime, timezone
from unittest import mock

import server
import usage_meter


class EnvGuardTests(unittest.TestCase):
    def test_malformed_chat_deadline_falls_back(self):
        for value in ("soon", "", "0", "-5"):
            with self.subTest(value=value), mock.patch.dict("os.environ", {
                    "JARVIS_CHAT_DEADLINE": value}):
                self.assertEqual(server._chat_deadline(), 120.0)
        with mock.patch.dict("os.environ", {"JARVIS_CHAT_DEADLINE": "45"}):
            self.assertEqual(server._chat_deadline(), 45.0)


class RateLimitTests(unittest.TestCase):
    def test_zero_rate_disables_the_bucket(self):
        bucket = server._RateBucket(0)
        for _ in range(100):
            self.assertTrue(bucket.allow())

    def test_bucket_refuses_after_capacity(self):
        bucket = server._RateBucket(1)
        self.assertTrue(bucket.allow())
        self.assertFalse(bucket.allow())

    def test_fractional_rate_still_allows_one_request(self):
        bucket = server._RateBucket(0.5)
        self.assertTrue(bucket.allow())
        self.assertFalse(bucket.allow())

    def test_refund_returns_a_token_for_work_that_never_happened(self):
        bucket = server._RateBucket(1)
        self.assertTrue(bucket.allow())
        self.assertFalse(bucket.allow())
        bucket.refund()
        self.assertTrue(bucket.allow())

    def test_paid_paths_are_mapped(self):
        self.assertEqual(server.paid_endpoint("/chat"), "chat")
        self.assertEqual(server.paid_endpoint("/agent/run"), "agent")
        self.assertEqual(server.paid_endpoint("/agent/schedules/run"), "agent")
        self.assertEqual(server.paid_endpoint("/self/heal"), "selfmod")
        self.assertEqual(server.paid_endpoint("/voice/transcribe"), "stt")
        self.assertIsNone(server.paid_endpoint("/health"))

    def test_daily_reservation_is_bounded(self):
        original = dict(usage_meter.DAILY)
        try:
            usage_meter.DAILY.update({"day": "2000-01-01", "calls": 0})
            with mock.patch.dict("os.environ", {"JARVIS_TEST_CALL_LIMIT": "1"}):
                self.assertTrue(usage_meter.reserve_call("JARVIS_TEST_CALL_LIMIT"))
                self.assertFalse(usage_meter.reserve_call("JARVIS_TEST_CALL_LIMIT"))
        finally:
            usage_meter.DAILY.update(original)

    def test_daily_reservation_can_be_released(self):
        original = dict(usage_meter.DAILY)
        try:
            usage_meter.DAILY.update(
                {"day": datetime.now(timezone.utc).date().isoformat(), "calls": 0})
            with mock.patch.dict("os.environ", {"JARVIS_TEST_CALL_LIMIT": "1"}):
                self.assertTrue(usage_meter.reserve_call("JARVIS_TEST_CALL_LIMIT"))
                self.assertFalse(usage_meter.reserve_call("JARVIS_TEST_CALL_LIMIT"))
                usage_meter.release_call()
                self.assertTrue(usage_meter.reserve_call("JARVIS_TEST_CALL_LIMIT"))
        finally:
            usage_meter.DAILY.update(original)


if __name__ == "__main__":
    unittest.main()
