"""REA operational ceilings are tunable but still bounded."""
import importlib
import os
import unittest
from unittest.mock import patch

import browser_bay
import rea_limits
import teardown
import teardown_brain


class ReaLimitsTests(unittest.TestCase):
    def test_number_reads_and_clamps_the_environment(self):
        with patch.dict(os.environ, {"JARVIS_TEST_LIMIT": "999999"}):
            self.assertEqual(rea_limits._number("JARVIS_TEST_LIMIT", 10, 1, 100), 100)
        with patch.dict(os.environ, {"JARVIS_TEST_LIMIT": "0"}):
            self.assertEqual(rea_limits._number("JARVIS_TEST_LIMIT", 10, 1, 100), 1)
        with patch.dict(os.environ, {"JARVIS_TEST_LIMIT": "nope"}):
            self.assertEqual(rea_limits._number("JARVIS_TEST_LIMIT", 10, 1, 100), 10)
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(rea_limits._number("JARVIS_TEST_LIMIT", 10, 1, 100), 10)

    def test_defaults_are_lifted_and_internally_consistent(self):
        saved = {name: os.environ.pop(name) for name in list(os.environ)
                 if name.startswith("JARVIS_REA_")}
        try:
            module = importlib.reload(rea_limits)
            self.assertGreaterEqual(module.REA_TIMEOUT_DEFAULT, 1800)
            self.assertGreaterEqual(module.REA_TIMEOUT_MAX, module.REA_TIMEOUT_DEFAULT)
            self.assertGreaterEqual(module.REA_STDOUT_BYTES, 128 * 1024 * 1024)
            self.assertGreaterEqual(module.BROWSER_LOAD_TIMEOUT, 90)
            self.assertGreaterEqual(module.INSPECT_MS, 15000)
            self.assertGreaterEqual(module.ANALYZE_MS, 5000)
            self.assertGreaterEqual(module.SCROLL_STEPS, 32)
            self.assertGreaterEqual(module.MAX_FALLBACK_FETCHES, 24)
            self.assertGreaterEqual(module.DIGEST_CHARS, 40000)
        finally:
            os.environ.update(saved)
            importlib.reload(rea_limits)

    def test_the_bays_read_the_shared_limits(self):
        self.assertEqual(teardown.DEFAULT_TIMEOUT, rea_limits.REA_TIMEOUT_DEFAULT)
        self.assertEqual(teardown.MAX_TIMEOUT, rea_limits.REA_TIMEOUT_MAX)
        self.assertEqual(teardown.MAX_STDOUT, rea_limits.REA_STDOUT_BYTES)
        self.assertEqual(browser_bay.LOAD_TIMEOUT, rea_limits.BROWSER_LOAD_TIMEOUT)
        self.assertEqual(teardown_brain.MAX_DIGEST_CHARS, rea_limits.DIGEST_CHARS)

    def test_digest_truncation_names_the_active_cap(self):
        evidence = {"digest_text": "x" * 200, "url_requested": "https://example.test/",
                    "url": "https://example.test/"}
        with patch.object(teardown_brain, "MAX_DIGEST_CHARS", 80):
            digest = teardown_brain.build_digest(evidence, "example.test", "How?")
        self.assertLessEqual(len(digest.splitlines()[-1]), 80)
        self.assertIn("TRUNCATED AT 80 CHARACTERS", digest)

    def test_diagnostics_expose_the_limits(self):
        limits = rea_limits.snapshot()
        for key in ("rea_timeout_seconds", "stdout_mb", "inspect_ms", "scroll_steps",
                    "digest_chars", "fallback_fetches"):
            self.assertIn(key, limits)
            self.assertGreater(limits[key], 0)


if __name__ == "__main__":
    unittest.main()
