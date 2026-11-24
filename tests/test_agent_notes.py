"""The per-agent knowledge base: one note per run, readable and path-safe."""
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import agent_cli
import agent_notes


class AgentNoteTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        env = patch.object(agent_cli, 'ROOT', Path(self.tmp.name) / 'agents')
        env.start()
        self.addCleanup(env.stop)

    def _record(self, **overrides):
        record = {'id': 'run-abc123', 'agent': 'claude', 'task': 'napraw test',
                  'status': 'done', 'exit_code': 0, 'seconds': 12.5,
                  'started_at': 1793130000, 'consent': 'spoken'}
        record.update(overrides)
        return record

    def test_a_note_records_the_task_result_and_outbox(self):
        outbox = agent_cli.outbox_path('claude')
        outbox.mkdir(parents=True, exist_ok=True)
        (outbox / 'patch.py').write_text('print(1)')
        path = agent_notes.write_run_note('claude', self._record(), 'agent output here')
        self.assertTrue(path.endswith('.md'))
        text = Path(path).read_text(encoding='utf-8')
        self.assertIn('agent: claude', text)
        self.assertIn('run_id: run-abc123', text)
        self.assertIn('status: done', text)
        self.assertIn('napraw test', text)
        self.assertIn('patch.py', text)
        self.assertIn('agent output here', text)
        self.assertIn('dane niezaufane', text)

    def test_an_empty_outbox_is_stated_plainly(self):
        path = agent_notes.write_run_note('claude', self._record(status='failed', exit_code=2), '')
        text = Path(path).read_text(encoding='utf-8')
        self.assertIn('Outbox jest pusty', text)
        self.assertIn('status: failed', text)

    def test_notes_are_private_and_listed_newest_first(self):
        agent_notes.write_run_note('claude', self._record(id='run-1'))
        agent_notes.write_run_note('claude', self._record(id='run-2', task='drugie'))
        rows = agent_notes.notes('claude')
        self.assertEqual(len(rows), 2)
        for row in rows:
            path = agent_notes.vault('claude') / row['name']
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_a_note_cannot_be_read_through_a_traversal(self):
        agent_notes.write_run_note('claude', self._record())
        for name in ('../config.json', 'passwd', 'a/b.md', '', None, 'x' * 200 + '.md'):
            with self.subTest(name=name):
                with self.assertRaises(agent_notes.NoteError):
                    agent_notes.read_note(name)

    def test_a_note_can_be_read_back_by_name(self):
        path = agent_notes.write_run_note('claude', self._record())
        result = agent_notes.read_note(Path(path).name)
        self.assertEqual(result['agent'], 'claude')
        self.assertIn('napraw test', result['text'])

    def test_summary_counts_runs_notes_and_outbox(self):
        agent_notes.write_run_note('claude', self._record())
        data = agent_notes.summary()
        self.assertEqual(data['claude']['notes'], 1)
        self.assertIn('outbox', data['claude'])

    def test_a_finished_run_writes_a_note_and_a_failing_note_does_not_break_the_run(self):
        process = type('P', (), {'pid': 11, 'returncode': 0, 'wait': lambda self, timeout=None: 0})()
        closer = type('C', (), {'close': lambda self: None})()
        with patch.object(agent_cli, '_spawn', return_value=(process, closer)), \
             patch.object(agent_cli, 'binary_present', return_value=True):
            agent_cli.run('claude', 'zadanie', approved=True, timeout=60)
        self.assertEqual(len(agent_notes.notes('claude')), 1)
        with patch.object(agent_cli, '_spawn', return_value=(process, closer)), \
             patch.object(agent_cli, 'binary_present', return_value=True), \
             patch.object(agent_notes, 'write_run_note', side_effect=OSError('disk')):
            result = agent_cli.run('claude', 'drugie', approved=True, timeout=60)
        self.assertTrue(result['ok'], 'a note failure must not fail the run')


if __name__ == '__main__':
    unittest.main()
