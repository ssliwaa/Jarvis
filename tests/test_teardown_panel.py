"""Panel/reader metadata, async job state, and teardown tag parsing."""
import tempfile
import unittest
from pathlib import Path

from server import TEARDOWN_TAG, Application, TeardownJob, note_meta


class PanelMetaTests(unittest.TestCase):
    def test_note_meta_reads_stack_and_totals_without_paths(self):
        note = '''---
snapshot: "assets/site-2026-10-20.png"
---
# Teardown · example.com — 2026-10-20

**Verdict:** One line.

## The stack
- Vue — inferred.
- Three.js r186 — constant.
- GSAP 3.15.0 — banner.

## What it loads
- [Jarvis] 141 resource entries, 14.65 MB reported size, 16 unknown.
- REA: 17 routes.
'''
        meta = note_meta(note)
        self.assertEqual(meta['site'], 'example.com')
        self.assertEqual(meta['date'], '2026-10-20')
        self.assertEqual(meta['stack'][0], {'name': 'Vue', 'version': None, 'category': ''})
        self.assertEqual(meta['stack'][1]['name'], 'Three.js')
        self.assertEqual(meta['stack'][1]['version'], '186')
        self.assertEqual(meta['stack'][2]['version'], '3.15.0')
        self.assertEqual(meta['totals'], {'resources': 141, 'known_bytes_label': '14.65 MB', 'routes': 17})

    def test_tag_requires_exact_site_and_question_shape(self):
        self.assertIsNotNone(TEARDOWN_TAG.fullmatch('[TEARDOWN:stripe.com|how does it work]'))
        self.assertIsNone(TEARDOWN_TAG.fullmatch('prefix [TEARDOWN:stripe.com|x]'))
        self.assertIsNone(TEARDOWN_TAG.fullmatch('[TEARDOWN:stripe.com]'))

    def test_job_progress_and_terminal_state(self):
        job = TeardownJob('https://example.com/', 'How?', 'example.com')
        self.assertEqual([step['state'] for step in job.steps], ['pending'] * 8)
        job.progress(2)
        self.assertEqual([step['state'] for step in job.steps[:3]], ['done', 'done', 'active'])
        job.finish(result={'ok': True})
        snapshot = job.snapshot()
        self.assertEqual(snapshot['status'], 'done')
        self.assertEqual(snapshot['result'], {'ok': True})
        self.assertEqual(snapshot['steps'][2]['state'], 'done')


class TagHandlingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name) / 'app'
        notes = Path(self.temp.name) / 'vault'
        (root / 'viewer').mkdir(parents=True)
        notes.mkdir()
        (notes / 'seed.md').write_text('# Seed\n\nSeed.\n')
        self.app = Application(root, notes, state_root=Path(self.temp.name) / 'state',
                               enable_memory_capture=False)

    def test_address_from_tag_supports_addresses_and_possessive_homepage(self):
        self.assertEqual(self.app.address_from_tag('stripe.com'), ('https://stripe.com', None))
        self.assertEqual(self.app.address_from_tag("Stripe's homepage"), (None, None))
        self.assertEqual(self.app.address_from_tag('localhost:4700'), ('http://localhost:4700', None))
        self.assertEqual(self.app.address_from_tag('this'), (None, 'this'))

    def test_tag_without_address_asks_and_does_not_start(self):
        result = self.app.start_from_tag('Stripe', 'reverse engineer Stripe')
        self.assertTrue(result['ask_site'])
        self.assertIn('address', result['answer'])
        self.assertNotIn('teardown', result)

    def test_current_site_asks_outside_macos(self):
        result = self.app.resolve_current_site()
        if __import__('sys').platform != 'darwin':
            self.assertFalse(result['ok'])
            self.assertTrue(result['ask'])

    def test_tag_start_uses_short_ack_and_job_id(self):
        self.app.start_teardown = lambda url, question=None: {
            'ok': True, 'busy': False, 'status': 'running', 'job_id': 'td-0123456789abcdef',
            'site': 'stripe.com', 'ack': 'Very good, sir.', 'steps': [],
        }
        result = self.app.start_from_tag('stripe.com', 'how does it work')
        self.assertEqual(result['answer'], 'Very good, sir.')
        self.assertEqual(result['teardown']['job_id'], 'td-0123456789abcdef')
        self.assertEqual(result['teardown']['site'], 'stripe.com')

    def test_async_start_is_busy_when_slot_held(self):
        self.app.teardown_busy.acquire()
        try:
            result = self.app.start_teardown('https://example.com/')
        finally:
            self.app.teardown_busy.release()
        self.assertEqual(result, {'ok': False, 'busy': True, 'answer': "I'm already taking one apart, sir."})

    def test_last_teardown_reads_newest_note_and_hides_paths_in_metadata(self):
        directory = self.app.notes_root / 'NOTES/captures/teardowns'
        directory.mkdir(parents=True)
        note = directory / 'example.com-2026-10-20.md'
        note.write_text('# Teardown · example.com — 2026-10-20\n\n## The stack\n- Three.js r186 — x\n\n## What it loads\n- [Jarvis] 2 resource entries, 1.2 MB, 0 unknown\n')
        later = directory / 'later.com-2026-10-21.md'
        later.write_text('# Teardown · later.com — 2026-10-21\n\n## The stack\n- Vue — inferred\n\n## What it loads\n- [Jarvis] 4 resource entries, 2.0 MB, 0 unknown\n')
        result = self.app.last_teardown()
        self.assertEqual(result['site'], 'later.com')
        self.assertEqual(result['note_name'], 'later.com-2026-10-21')
        self.assertTrue(result['obsidian_uri'].startswith('obsidian://open?path='))
        self.assertNotIn(str(self.app.notes_root), result['markdown'])
        self.assertNotIn('note_path', result)


if __name__ == '__main__':
    unittest.main()
