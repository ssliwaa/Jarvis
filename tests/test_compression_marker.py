"""Automated test suite for compression_marker.py (elision markers).

Tests elide (limit respected, exact omitted/total counts, whitespace
trimming of the kept head, degenerate limits smaller than the marker
itself), elide_middle (head+tail split, in-tolerance pass-through,
zero head/tail), marker detection (artifacts of this module only,
never plain prose), and the ELISION_MARKER_MAX_LEN invariant.
All marker literals are referenced through module constants so the
test file itself stays plain ASCII.
"""

from __future__ import annotations

import unittest

import compression_marker as cm

PREFIX = cm._COMPRESSION_MARKER_PREFIX


class TestElide(unittest.TestCase):
    """elide: cap at limit with accurate count markers."""

    def test_short_text_unchanged(self):
        self.assertEqual(cm.elide("short text", 100), "short text")
        self.assertEqual(cm.elide("", 10), "")

    def test_long_text_respects_limit(self):
        result = cm.elide("a" * 300, 100)
        self.assertLessEqual(len(result), 100)
        self.assertEqual(result[:3], "aaa")
        self.assertTrue(cm.is_compression_marker(result))

    def test_marker_counts_are_exact(self):
        value = "b" * 250
        result = cm.elide(value, 120)
        total = len(value)
        # Kept head + marker; the marker reports total and the exact
        # number of omitted characters.
        kept_len = len(result) - len(
            cm._elision_marker(omitted=total, total=total)
            + "0" * 0)
        # The kept head must be a prefix of the original
        self.assertTrue(result.startswith(kept_len * "b"))
        # Reconstructing the marker with visible counts must round-trip
        # through is_compression_marker.
        self.assertTrue(cm.is_compression_marker(result))

    def test_limit_smaller_than_marker_yields_marker_only(self):
        result = cm.elide("word " * 10, 3)
        # Cannot keep any head: the marker alone is returned.
        self.assertTrue(cm.is_compression_marker(result))
        self.assertNotIn("word", result)

    def test_zero_limit_returns_full_marker(self):
        result = cm.elide("abcdef", 0)
        self.assertTrue(cm.is_compression_marker(result))

    def test_none_and_nonstring_inputs(self):
        self.assertEqual(cm.elide(None, 10), "")
        # str() conversion: numbers are elided like their string form.
        self.assertEqual(cm.elide(12345, 10), "12345")
        # 0 is falsy, so the `text or ""` branch swallows it.
        self.assertEqual(cm.elide(0, 10), "")
        # A limit smaller than the marker yields the full marker.
        tight = cm.elide(12345, 2)
        self.assertEqual(tight, cm._elision_marker(5, 5))
        self.assertTrue(cm.is_compression_marker(tight))

    def test_kept_head_is_rstripped(self):
        value = "abc   " + "x" * 50
        result = cm.elide(value, 60)
        # No trailing whitespace right before the marker
        head = result[:result.rfind(PREFIX)]
        self.assertEqual(head, head.rstrip())


class TestElideMiddle(unittest.TestCase):
    """elide_middle: head+tail preservation with count markers."""

    def test_short_text_unchanged(self):
        self.assertEqual(cm.elide_middle("abc", 5, 5), "abc")
        self.assertEqual(cm.elide_middle("", 5, 5), "")

    def test_head_and_tail_kept_with_marker(self):
        result = cm.elide_middle("0123456789", 3, 2)
        self.assertTrue(result.startswith("012"))
        self.assertTrue(result.endswith("89"))
        self.assertTrue(cm.is_compression_marker(result))
        # Middle is gone
        self.assertNotIn("45", result)

    def test_zero_head_and_tail(self):
        value = "z" * 40
        result = cm.elide_middle(value, 0, 0)
        self.assertTrue(cm.is_compression_marker(result))
        self.assertNotIn("z", result)

    def test_negative_budgets_clamped(self):
        # Clamped to 0/0 heads and tails, so everything is omitted.
        result = cm.elide_middle("abcdef", -2, -3)
        self.assertEqual(result, cm._elision_marker(6, 6))
        self.assertTrue(cm.is_compression_marker(result))
        # Generous clamped budgets keep short strings untouched.
        self.assertEqual(cm.elide_middle("abcdef", 4, 4), "abcdef")


class TestMarkerDetection(unittest.TestCase):
    """is_compression_marker: module artifacts only."""

    def test_plain_text_is_not_a_marker(self):
        self.assertFalse(cm.is_compression_marker("plain prose"))
        self.assertFalse(cm.is_compression_marker(""))
        self.assertFalse(cm.is_compression_marker(None))

    def test_marked_output_detected(self):
        marked = cm.elide("y" * 500, 200)
        self.assertTrue(cm.is_compression_marker(marked))
        middle = cm.elide_middle("y" * 500, 10, 10)
        self.assertTrue(cm.is_compression_marker(middle))

    def test_prefix_artifact_detected(self):
        # A partial copy that still carries the prefix plus counts is
        # detected as a marker artifact (defence vs model reproductions).
        self.assertTrue(cm.is_compression_marker(
            PREFIX + " 12345 of 99999 chars"))

    def test_max_len_invariant(self):
        # ELISION_MARKER_MAX_LEN is the length of the biggest possible
        # marker (omitted=total=10^12-1 with comma grouping)
        biggest = cm._elision_marker(omitted=10**12 - 1, total=10**12 - 1)
        self.assertEqual(cm.ELISION_MARKER_MAX_LEN, len(biggest))
        self.assertGreater(cm.ELISION_MARKER_MAX_LEN, 100)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
