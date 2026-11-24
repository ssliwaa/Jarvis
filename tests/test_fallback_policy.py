"""Model fallback policy: availability errors fall through, auth/credit never do."""
import unittest

from provider_client import ProviderError
from server import can_fallback


class ProviderErrorPolicyTests(unittest.TestCase):
    def test_transport_and_availability_errors_may_fall_through(self):
        for status in (0, 404, 408, 429, 500, 503):
            self.assertTrue(can_fallback(ProviderError(status, message="down")), status)

    def test_auth_and_credit_errors_never_fall_through(self):
        for status in (401, 402, 403):
            self.assertFalse(can_fallback(ProviderError(status, message="nope")), status)

    def test_timeout_falls_through(self):
        self.assertTrue(can_fallback(TimeoutError("slow")))

    def test_unknown_errors_stay_put(self):
        self.assertFalse(can_fallback(ValueError("bad json")))


if __name__ == "__main__":
    unittest.main()
