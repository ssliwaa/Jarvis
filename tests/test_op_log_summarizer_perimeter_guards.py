"""Perimeter-guard repair suite for operator_modules/op_log_summarizer.py.

The iteration-CN wave reported this module at 16/16 executed raise
sites, but the reproducible tracer state after CN is 14/16: two raise
sites in the shared input loader were never actually triggered by any
suite (line 212, path resolving outside ALLOWED_ROOTS; line 248,
inline text exceeding MAX_LOG_BYTES). This suite closes that gap for
real:

- a path under /proc resolves outside the allowed roots perimeter and
  must be rejected with PathSecurityError before any file access
- oversized inline text must be rejected with PayloadSizeError against
  a patched MAX_LOG_BYTES (mirroring the file-size ceiling test from
  the CN wave), with an under-ceiling contrast anchor proving the
  guard rejects only genuine overruns
- the 5-key error envelope contract is asserted on a failure

100% offline and deterministic; no real files outside the test-private
temporary directory are touched.
"""

from __future__ import annotations

import unittest
from unittest.mock import patch

import operator_modules.op_log_summarizer as ls


class TestAllowedRootsPerimeter(unittest.TestCase):
    """Guard: paths outside ALLOWED_ROOTS (loader line 212)."""

    def test_path_outside_allowed_roots_rejected(self):
        # /proc is not among ALLOWED_ROOTS (HOME, /tmp, /mnt, /media),
        # so any /proc path must be refused before existence checks.
        res = ls.log_summarizer({
            "action": "cluster_errors",
            "path": "/proc/self/definitely_missing_guard_probe",
        })
        self.assertFalse(res["ok"])
        self.assertIn("PathSecurityError", res["error"])
        self.assertIn("resolves outside ALLOWED_ROOTS", res["error"])
        self.assertIn("/proc/self/definitely_missing_guard_probe",
                      res["error"])


class TestInlineTextCeiling(unittest.TestCase):
    """Guard: inline text exceeding MAX_LOG_BYTES (loader line 248)."""

    def test_inline_text_over_ceiling_rejected(self):
        with patch.object(ls, "MAX_LOG_BYTES", 8):
            res = ls.log_summarizer({"action": "cluster_errors",
                                     "text": "123456789"})
        self.assertFalse(res["ok"])
        self.assertIn("PayloadSizeError", res["error"])
        self.assertIn("Content size (9 bytes) exceeds maximum limit "
                      "(8 bytes)", res["error"])

    def test_inline_text_under_ceiling_ok_contrast(self):
        # Contrast anchor: the same dispatcher path with in-ceiling
        # inline text succeeds, proving the guard rejects only real
        # overruns rather than all inline input.
        inline = "2026-11-24T10:00:01 ERROR disk full\n"
        self.assertLess(len(inline.encode("utf-8")), 64)
        with patch.object(ls, "MAX_LOG_BYTES", 64):
            res = ls.log_summarizer({"action": "cluster_errors",
                                     "text": inline})
        self.assertTrue(res["ok"])
        self.assertIsNone(res["error"])


class TestErrorEnvelopeShape(unittest.TestCase):
    """Error envelope contract shared by perimeter failures."""

    def test_error_envelope_shape(self):
        res = ls.log_summarizer({
            "action": "cluster_errors",
            "path": "/proc/self/definitely_missing_guard_probe",
        })
        self.assertEqual(set(res), {"ok", "success", "data", "result",
                                    "error"})
        self.assertFalse(res["ok"])
        self.assertFalse(res["success"])
        self.assertIsNone(res["data"])
        self.assertIsNone(res["result"])
        self.assertIsInstance(res["error"], str)


if __name__ == "__main__":
    unittest.main()
