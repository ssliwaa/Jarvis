"""BM25/FTS5 retrieval regression tests; synthetic notes only."""
import os
import tempfile
import unittest
from pathlib import Path

from retrieval import BM25Index


class RetrievalTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR'))
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.notes = [
            {'id': 0, 'title': 'Orbit notes', 'content': 'Mars is red and quiet.'},
            {'id': 1, 'title': 'Other', 'content': 'orbit ' * 12},
            {'id': 2, 'title': 'Lifting', 'content': 'Strength training for runners.'},
            {'id': 3, 'title': 'Zażółć', 'content': 'Polish diacritics with zażółć.'},
            {'id': 4, 'title': 'Unrelated', 'content': 'water and weather'},
            {'id': 5, 'title': 'Pojazd', 'content': 'Samochód jest szybki.'},
        ]
        for note in self.notes:
            path = self.root / f"{note['id']}.md"
            path.write_text(note['content'], encoding='utf-8')
            note['path'] = str(path)

    def test_title_match_outranks_a_body_frequency_match(self):
        index = BM25Index(self.notes, root=self.root)
        self.assertEqual(index.search('orbit')[0], 0)
        self.assertNotIn(1, index.search('orbit')[:1])

    def test_body_terms_and_unicode_tokenization(self):
        index = BM25Index(self.notes, root=self.root)
        self.assertEqual(index.search('strength'), [2])
        self.assertIn(3, index.search('zazolc'))
        self.assertEqual(index.search('zygotequartz'), [])
        self.assertEqual(index.search(''), [])

    def test_polish_inflection_matches_the_shorter_note_form(self):
        index = BM25Index(self.notes, root=self.root)
        self.assertEqual(index.search('samochodu'), [5])
        self.assertEqual(index.search('samochód'), [5])

    def test_a_three_letter_polish_ending_still_reaches_the_stem(self):
        # "utorrencie" (10 letters) needed word[:-3] to reach the note's
        # "utorrent"; the old two-letter window matched nothing and the note was
        # invisible for a normal inflected question.
        self.notes.append({'id': 6, 'title': 'utorrent-automatyzacja',
                           'content': 'Auto-load z folderu Pobrane uruchamia uTorrent.',
                           'path': str(self.root / '6.md')})
        (self.root / '6.md').write_text(self.notes[-1]['content'], encoding='utf-8')
        index = BM25Index(self.notes, root=self.root)
        self.assertIn(6, index.search('Co notatki mówią o auto-load w uTorrencie?'))
        self.assertEqual(index.search('utorrencie')[0], 6)

    def test_top_k_and_previous_query_fallback(self):
        index = BM25Index(self.notes, root=self.root)
        self.assertLessEqual(len(index.search('orbit', top_k=2)), 2)
        self.assertEqual(index.search('zygotequartz', previous=('strength',)), [2])


if __name__ == '__main__':
    unittest.main()
