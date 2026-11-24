"""Captures must be real, indexed immediately, and preserve positional ids."""
import json
import os
import subprocess
import tempfile
import threading
import unittest
from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock, patch
from urllib.request import Request

ROOT = Path(__file__).resolve().parents[1]


class CaptureTests(unittest.TestCase):
    def setUp(self):
        import build
        import server
        self.server, self.build = server, build
        self.temp = tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR'))
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.notes = self.root / 'notes'
        (self.notes / 'ideas').mkdir(parents=True)
        (self.notes / 'ideas/Finish window.md').write_text('The finish window measures speech pauses. [[Speech]]')
        (self.notes / 'ideas/Speech.md').write_text('Voice recognition and [[Finish window]] are related.')
        (self.root / 'viewer').mkdir()
        self.build.write_graph(self.build.make_graph(self.notes), self.root / 'viewer/graph-data.js')
        self.client = MagicMock()
        self.factory = MagicMock(return_value=self.client)
        self.app = server.Application(self.root, self.notes, self.factory,
                                      state_root=self.root / "state",
                                      enable_memory_capture=False)

    def test_single_capture_door_writes_dated_markdown_and_indexes_without_rebuild(self):
        self.assertTrue(callable(getattr(self.app, 'capture_note', None)), 'one capture_note function must own the complete write/index path')
        before = self.app.load_graph()
        result = self.app.capture_note('the finish window should be 900 milliseconds')
        self.assertEqual(result['index'], len(before['nodes']))
        self.assertEqual(result['node']['id'], result['index'])
        self.assertTrue(result['node']['label'].startswith('The finish window'), 'capture titles should be readable, not UUID-dominated')
        self.assertNotIn('capture_sha256', result['node']['excerpt'])
        path = self.notes / result['node']['path']
        self.assertEqual(path.parent, self.notes / 'captures')
        body = path.read_text()
        self.assertIn(datetime.now().astimezone().date().isoformat(), body)
        self.assertIn('the finish window should be 900 milliseconds', body)
        graph = self.app.load_graph()
        self.assertEqual(graph['nodes'][:len(before['nodes'])], before['nodes'])
        self.assertEqual(graph['nodes'][result['index']], result['node'])
        self.assertEqual(result['receipt']['status'], 'completed')
        self.assertEqual(result['receipt']['details']['index'], result['index'])
        self.assertIn(result['index'], [note['index'] for note in self.app.retrieve('finish window 900 milliseconds')])
        # Same graph rules, modulo the deliberately preserved existing ids/order.
        batch = self.build.make_graph(self.notes)
        def edges_by_path(g):
            return {tuple(sorted((g['nodes'][e['source']]['path'], g['nodes'][e['target']]['path']))) for e in g['links']}
        self.assertEqual(edges_by_path(graph), edges_by_path(batch))
        self.assertTrue(any(result['index'] in (e['source'], e['target']) for e in graph['links']))
        self.assertIn(result['related'], range(len(before['nodes'])))
        self.factory.assert_not_called()

    def test_remember_http_immediately_feeds_next_chat_and_keeps_followup_topic(self):
        from types import SimpleNamespace
        (self.root / 'config.json').write_text(json.dumps({'aOPENROUTER_API_KEY': 'sk-or-v1-' + 'a' * 64, 'model': 'openai/gpt-6.1-sol'}))
        state = self.root / 'state'
        state.mkdir(exist_ok=True)
        httpd = self.server.create_server(root=self.root, notes_root=self.notes, port=0,
                                          client_factory=self.factory, state_root=state,
                                          enable_agent=False, enable_scheduler=False,
                                          enable_memory_capture=False)
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(lambda: (httpd.shutdown(), httpd.server_close(), thread.join()))
        from http.cookiejar import CookieJar
        from urllib.request import HTTPCookieProcessor, build_opener
        client = build_opener(HTTPCookieProcessor(CookieJar()))
        url = f'http://127.0.0.1:{httpd.server_port}'
        with client.open(Request(url + '/remember', data=json.dumps({'text': 'the finish window should be 900 milliseconds'}).encode(), headers={'Content-Type':'application/json'})) as response:
            self.assertEqual(response.status, 201)
            result = json.load(response)
        self.factory.assert_not_called()
        index = result['index']
        self.client.messages.create.return_value = SimpleNamespace(content=[SimpleNamespace(type='text', text=f'The finish window should be 900 milliseconds [{index}].')])
        with client.open(Request(url + '/chat', data=json.dumps({'question':'What did I just ask you to remember?'}).encode(), headers={'Content-Type':'application/json'})) as response:
            answer = json.load(response)
        self.assertIn(index, answer['nodes'])
        evidence = json.loads(self.client.messages.create.call_args.kwargs['messages'][0]['content'])['untrusted_notes']
        self.assertIn(index, [n['index'] for n in evidence])

    def test_capture_index_failure_rolls_back_file_and_never_returns_success(self):
        before = self.app.load_graph()
        with patch('server.os.replace', side_effect=OSError('synthetic full disk')):
            with self.assertRaises(self.server.AppError) as raised:
                self.app.capture_note('A thought which must not be quietly lost')
        self.assertEqual(raised.exception.code, 'CAPTURE_FAILED')
        self.assertIn('could not save and index', raised.exception.message)
        self.assertEqual(self.app.load_graph(), before)
        self.assertEqual(list((self.notes / 'captures').glob('*.md')), [])

    def test_capture_retry_is_idempotent_even_after_application_restart(self):
        request_id = '142bc235-0dc2-4166-9780-ac2da946de16'
        first = self.app.capture_note('Finish window is 900 milliseconds', request_id)
        restarted = self.server.Application(self.root, self.notes, self.factory,
                                            state_root=self.root / "state",
                                            enable_memory_capture=False)
        second = restarted.capture_note('Finish window is 900 milliseconds', request_id)
        self.assertEqual(first['index'], second['index'])
        self.assertFalse(second['receipt']['details']['created'])
        self.assertEqual(len(list((self.notes / 'captures').glob('*.md'))), 1)
        with self.assertRaises(self.server.AppError) as raised:
            restarted.capture_note('Different text', request_id)
        self.assertEqual(raised.exception.code, 'CAPTURE_CONFLICT')

    def test_capture_directory_symlink_cannot_escape_vault(self):
        outside = self.root / 'outside'
        outside.mkdir()
        (self.notes / 'captures').symlink_to(outside, target_is_directory=True)
        with self.assertRaises(self.server.AppError) as raised:
            self.app.capture_note('Do not write outside the vault')
        self.assertEqual(raised.exception.code, 'CAPTURE_FAILED')
        self.assertEqual(list(outside.iterdir()), [])

    def test_capture_never_deletes_a_preexisting_staging_file(self):
        request_id = '142bc235-0dc2-4166-9780-ac2da946de16'
        temporary = self.root / 'viewer' / f'.capture-{request_id}.tmp'
        temporary.write_text('not owned by this capture')
        with self.assertRaises(self.server.AppError):
            self.app.capture_note('A capture with an occupied staging name', request_id)
        self.assertTrue(temporary.exists(), 'failed O_EXCL must not delete someone else\'s file')
        self.assertEqual(temporary.read_text(), 'not owned by this capture')

    def test_parallel_captures_keep_contiguous_ids_and_no_lost_notes(self):
        from concurrent.futures import ThreadPoolExecutor
        base = len(self.app.load_graph()['nodes'])
        with ThreadPoolExecutor(max_workers=4) as executor:
            results = list(executor.map(self.app.capture_note, [f'Parallel capture number {i}' for i in range(6)]))
        self.assertEqual(sorted(r['index'] for r in results), list(range(base, base + len(results))))
        self.assertEqual(len(list((self.notes / 'captures').glob('*.md'))), len(results))

    def test_readback_failure_after_publication_restores_previous_index(self):
        before = self.app.load_graph()
        read = self.app.load_notes
        count = [0]
        def fail_verification():
            count[0] += 1
            if count[0] == 3:
                raise OSError('synthetic readback failure')
            return read()
        with patch.object(self.app, 'load_notes', side_effect=fail_verification):
            with self.assertRaises(self.server.AppError):
                self.app.capture_note('A note whose index cannot be verified')
        self.assertEqual(self.app.load_graph(), before)
        self.assertEqual(list((self.notes / 'captures').glob('*.md')), [])

    def test_capture_ui_contract(self):
        from tests.node_support import node_binary
        node = node_binary()
        if node is None:
            self.skipTest("Node is used only as a test runner; set JARVIS_NODE or install Node")
        result = subprocess.run([node, str(ROOT / 'tests/test_capture_ui.js')],
                                capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_preflight_cleanup_only_removes_its_owned_probe_and_index(self):
        capture_id = '142bc235-0dc2-4166-9780-ac2da946de16'
        probe_id = 'a182ef78-467d-46a4-9d9d-b08f97580629'
        before = self.app.load_graph()
        probe = self.app.capture_note(f'Temporary preflight probe {probe_id}: the verification word is amberfox.', capture_id)
        self.assertTrue(callable(getattr(self.app, 'remove_preflight_capture', None)), 'preflight needs a scoped live cleanup door')
        receipt = self.app.remove_preflight_capture(probe['index'], capture_id, probe_id)
        self.assertTrue(receipt['removed'])
        self.assertFalse((self.notes / probe['node']['path']).exists())
        self.assertEqual(self.app.load_graph(), before)

    def test_preflight_cleanup_refuses_user_notes_wrong_proof_and_non_tail(self):
        capture_id = '142bc235-0dc2-4166-9780-ac2da946de16'
        probe_id = 'a182ef78-467d-46a4-9d9d-b08f97580629'
        note = self.app.capture_note('A real user memory must survive this test', capture_id)
        with self.assertRaises(self.server.AppError):
            self.app.remove_preflight_capture(note['index'], capture_id, probe_id)
        self.assertTrue((self.notes / note['node']['path']).exists())
        probe = self.app.capture_note(f'Temporary preflight probe {probe_id}: the verification word is amberfox.')
        self.app.capture_note('A later user memory must not be renumbered')
        with self.assertRaises(self.server.AppError):
            self.app.remove_preflight_capture(probe['index'], capture_id, probe_id)
        self.assertTrue((self.notes / probe['node']['path']).exists())


if __name__ == '__main__':
    unittest.main()
