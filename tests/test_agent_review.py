"""Outbox comparison: read-only diff, bounded, and never a write path."""
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import agent_cli
import agent_review


class ReviewTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        base = Path(self.tmp.name)
        self.agents = base / 'agents'
        self.target = base / 'project'
        self.target.mkdir(parents=True, exist_ok=True)
        env = patch.object(agent_cli, 'ROOT', self.agents)
        env.start()
        self.addCleanup(env.stop)
        self.outbox = agent_cli.outbox_path('claude')
        self.outbox.mkdir(parents=True, exist_ok=True)

    def test_a_changed_file_shows_a_unified_diff(self):
        (self.target / 'app.py').write_text('print("old")\n', encoding='utf-8')
        (self.outbox / 'app.py').write_text('print("new")\nprint("more")\n', encoding='utf-8')
        result = agent_review.diff_outbox('claude', str(self.target))
        row = result['files'][0]
        self.assertEqual(row['status'], 'changed')
        self.assertIn('print("old")', row['diff'])
        self.assertIn('print("new")', row['diff'])
        self.assertEqual(result['changed'], 1)
        self.assertIn('Nothing was written', result['note'])

    def test_a_new_file_is_previewed_not_written(self):
        (self.outbox / 'new.py').write_text('x = 1\n', encoding='utf-8')
        result = agent_review.diff_outbox('claude', str(self.target))
        self.assertEqual(result['files'][0]['status'], 'new')
        self.assertIn('x = 1', result['files'][0]['preview'])
        self.assertFalse((self.target / 'new.py').exists(), 'the diff must not write anything')

    def test_an_identical_file_is_reported_unchanged(self):
        (self.target / 'same.py').write_text('x = 1\n', encoding='utf-8')
        (self.outbox / 'same.py').write_text('x = 1\n', encoding='utf-8')
        result = agent_review.diff_outbox('claude', str(self.target))
        self.assertEqual(result['files'][0]['status'], 'unchanged')
        self.assertEqual(result['changed'], 0)

    def test_a_large_file_is_skipped_not_truncated_silently(self):
        (self.outbox / 'big.py').write_text('x' * (agent_review.MAX_FILE_BYTES + 10), encoding='utf-8')
        result = agent_review.diff_outbox('claude', str(self.target))
        self.assertEqual(result['files'][0]['status'], 'skipped')
        self.assertIn('too large', result['files'][0]['reason'])

    def test_the_target_must_be_absolute_and_permitted(self):
        for target in ('relative/path', '/root', '/etc', '', None, '/tmp/../etc'):
            with self.subTest(target=target):
                with self.assertRaises(agent_review.ReviewError):
                    agent_review.diff_outbox('claude', target)

    def test_an_empty_outbox_is_explained(self):
        (self.outbox / 'stale.txt').unlink(missing_ok=True)
        result = agent_review.diff_outbox('claude', str(self.target))
        self.assertEqual(result['files'], [])
        self.assertEqual(result['changed'], 0)

    def test_apply_hint_cannot_escape_the_outbox(self):
        (self.outbox / 'ok.py').write_text('x = 1', encoding='utf-8')
        self.assertTrue(agent_review.apply_hint('claude', 'ok.py')['ok'])
        for path in ('../config.json', '/etc/passwd', '', 'nope.py'):
            with self.subTest(path=path):
                with self.assertRaises(agent_review.ReviewError):
                    agent_review.apply_hint('claude', path)

    def test_apply_outbox_copies_files_safely(self):
        (self.outbox / 'sub').mkdir(parents=True, exist_ok=True)
        (self.outbox / 'sub' / 'module.py').write_text('content = True\n', encoding='utf-8')
        result = agent_review.apply_outbox('claude', str(self.target))
        self.assertTrue(result['ok'])
        self.assertEqual(result['applied'], 1)
        self.assertEqual(result['files'], ['sub/module.py'])
        self.assertEqual((self.target / 'sub' / 'module.py').read_text(encoding='utf-8'), 'content = True\n')

    def test_apply_outbox_selective_files(self):
        (self.outbox / 'file1.txt').write_text('one', encoding='utf-8')
        (self.outbox / 'file2.txt').write_text('two', encoding='utf-8')
        result = agent_review.apply_outbox('claude', str(self.target), files=['file1.txt'])
        self.assertTrue(result['ok'])
        self.assertEqual(result['applied'], 1)
        self.assertEqual(result['files'], ['file1.txt'])
        self.assertTrue((self.target / 'file1.txt').is_file())
        self.assertFalse((self.target / 'file2.txt').is_file())


    def test_apply_outbox_skips_run_reports_and_keeps_target_mode(self):
        # outbox.md / TEAM_SUMMARY.md are receipts for the owner, not deliverables.
        (self.outbox / 'module.py').write_text('content = True\n', encoding='utf-8')
        (self.outbox / 'outbox.md').write_text('# raport\n', encoding='utf-8')
        (self.outbox / 'TEAM_SUMMARY.md').write_text('# podsumowanie\n', encoding='utf-8')
        (self.target / 'module.py').write_text('content = False\n', encoding='utf-8')
        (self.target / 'module.py').chmod(0o640)

        result = agent_review.apply_outbox('claude', str(self.target))
        self.assertTrue(result['ok'])
        self.assertEqual(result['files'], ['module.py'])
        self.assertEqual(sorted(result['skipped_reports']), ['TEAM_SUMMARY.md', 'outbox.md'])
        self.assertFalse((self.target / 'outbox.md').exists())
        self.assertFalse((self.target / 'TEAM_SUMMARY.md').exists())
        self.assertEqual((self.target / 'module.py').stat().st_mode & 0o777, 0o640)


class ProtectedTargetTests(unittest.TestCase):
    """Deploying a pack into Jarvis itself is an owner decision, not an agent's."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        base = Path(self.tmp.name)
        self.agents = base / 'agents'
        self.app = base / 'app'
        self.app.mkdir(parents=True)
        self.target = base / 'project'
        self.target.mkdir(parents=True)
        env = patch.object(agent_cli, 'ROOT', self.agents)
        env.start()
        self.addCleanup(env.stop)
        roots = patch.object(agent_review, '_protected_roots', lambda: [self.app])
        roots.start()
        self.addCleanup(roots.stop)
        outbox = agent_cli.outbox_path('claude')
        outbox.mkdir(parents=True, exist_ok=True)
        (outbox / 'server_patch.py').write_text('x = 1\n', encoding='utf-8')

    def test_protected_target_requires_explicit_confirmation(self):
        with self.assertRaises(agent_review.ConfirmationRequired):
            agent_review.apply_outbox('claude', str(self.app))
        self.assertFalse((self.app / 'server_patch.py').exists())

    def test_confirmed_apply_writes_into_the_app(self):
        result = agent_review.apply_outbox('claude', str(self.app), confirm=True)
        self.assertEqual(result['applied'], 1)
        self.assertTrue((self.app / 'server_patch.py').is_file())

    def test_an_ordinary_target_needs_no_confirmation(self):
        result = agent_review.apply_outbox('claude', str(self.target))
        self.assertEqual(result['applied'], 1)
        self.assertTrue((self.target / 'server_patch.py').is_file())


if __name__ == '__main__':
    unittest.main()
