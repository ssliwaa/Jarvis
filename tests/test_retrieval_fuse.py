"""Reciprocal rank fusion between BM25 and vector candidates."""
import unittest

from retrieval import fuse


class FuseTests(unittest.TestCase):
    def test_a_note_in_both_lists_outscores_a_single_list_hit(self):
        merged = fuse([[1, 2], [2, 3]], limit=3)
        self.assertEqual(merged[0], 2)

    def test_order_within_one_list_is_preserved(self):
        self.assertEqual(fuse([[5, 4, 3], []], limit=3), [5, 4, 3])

    def test_duplicates_do_not_appear_twice(self):
        merged = fuse([[1, 2, 3], [1, 2, 3]], limit=10)
        self.assertEqual(sorted(merged), [1, 2, 3])

    def test_non_integer_ids_are_ignored(self):
        self.assertEqual(fuse([[1, "x", None]], limit=5), [1])

    def test_limit_is_respected(self):
        self.assertEqual(len(fuse([list(range(10)), list(range(10, 20))], limit=4)), 4)

    def test_weights_let_bm25_beat_a_semantic_only_hit(self):
        # bm25 = [7], semantic = [1, 2, 3]; with a light semantic weight the
        # single BM25 hit still wins the top slot.
        merged = fuse([[7], [1, 2, 3]], limit=4, weights=[1.0, 0.2])
        self.assertEqual(merged[0], 7)


if __name__ == "__main__":
    unittest.main()
