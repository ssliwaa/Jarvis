"""Tests for new studio routes: reminders, watch, and agent apply."""
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import agent_cli
import agent_review
import studio_routes


class StudioRoutesExpansionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.state = self.root / 'state'
        self.state.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.app = MagicMock()
        self.app.state_root = self.state

    def test_reminders_get_and_post(self):
        handler = MagicMock()
        handler.server.app = self.app
        handler.read_json_body.return_value = {
            'action': 'create',
            'text': 'Kupić mleko',
            'due_at': '2026-11-01T10:00:00Z',
        }
        # POST /reminders
        handled = studio_routes.post_p2(handler, '/reminders')
        self.assertTrue(handled)
        handler.send_json.assert_called()
        call_args = handler.send_json.call_args[0]
        self.assertEqual(call_args[0], 200)
        self.assertTrue(call_args[1].get('ok'))
        self.assertEqual(call_args[1]['reminder']['text'], 'Kupić mleko')

        # GET /reminders
        get_handler = MagicMock()
        get_handler.server.app = self.app
        parsed = MagicMock()
        parsed.path = '/reminders'
        parsed.query = ''
        handled = studio_routes.get_p2(get_handler, parsed)
        self.assertTrue(handled)
        get_args = get_handler.send_json.call_args[0]
        self.assertEqual(get_args[0], 200)
        self.assertEqual(len(get_args[1].get('reminders', [])), 1)

    def test_watch_pages_get_and_post(self):
        handler = MagicMock()
        handler.server.app = self.app
        parsed = MagicMock()
        parsed.path = '/watch'
        parsed.query = ''
        handled = studio_routes.get_p2(handler, parsed)
        self.assertTrue(handled)
        call_args = handler.send_json.call_args[0]
        self.assertEqual(call_args[0], 200)
        self.assertIn('watches', call_args[1])

    def test_agent_apply_endpoint(self):
        agents_dir = self.root / 'agents'
        project_dir = self.root / 'project'
        project_dir.mkdir(parents=True, exist_ok=True)
        env = patch.object(agent_cli, 'ROOT', agents_dir)
        env.start()
        self.addCleanup(env.stop)

        outbox = agent_cli.outbox_path('claude')
        outbox.mkdir(parents=True, exist_ok=True)
        (outbox / 'patch.txt').write_text('applied content\n', encoding='utf-8')

        result = agent_review.apply_outbox('claude', str(project_dir))
        self.assertTrue(result['ok'])
        self.assertEqual(result['applied'], 1)
        self.assertEqual((project_dir / 'patch.txt').read_text(encoding='utf-8'), 'applied content\n')


if __name__ == '__main__':
    unittest.main()
