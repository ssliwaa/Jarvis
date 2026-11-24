"""Regression tests for the optional REA bay (diagnosis and safe invocation)."""
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import teardown


class VersionGateTests(unittest.TestCase):
    def test_node_engine_boundaries(self):
        cases = {
            '22.18.9': False, '22.19.0': True, '22.20.1': True,
            '23.11.0': False, '24.10.9': False, '24.11.0': True,
            '25.0.0': False, '26.0.0': True, '26.7.0': True,
            'not-a-version': False,
        }
        for version, expected in cases.items():
            with self.subTest(version=version):
                self.assertEqual(teardown.node_supported(version), expected)


class DiagTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.package = self.root / 'node_modules' / 'rea-agents'
        (self.package / 'scripts').mkdir(parents=True)
        (self.package / 'scripts' / 'rea.mjs').write_text('')
        (self.package / 'package.json').write_text(json.dumps({
            'version': '6.7.0',
            'repository': {'url': 'git+https://github.com/morluto/rea.git'},
        }))
        (self.root / 'package.json').write_text(json.dumps({
            'dependencies': {'rea-agents': '6.7.0'}}))
        self.patches = [
            patch.object(teardown, 'REA_ROOT', self.root),
            patch.object(teardown, 'PACKAGE_ROOT', self.package),
            patch.object(teardown, 'REA_SCRIPT', self.package / 'scripts' / 'rea.mjs'),
            patch.object(teardown, '_CACHE_SECONDS', 0),
        ]
        for item in self.patches:
            item.start()
            self.addCleanup(item.stop)

    def diagnose(self, node=None, chrome=None):
        node = node or {'path': '/fake/node', 'version': '26.7.0', 'supported': True}
        chrome = chrome or {'found': True, 'path': '/fake/chrome', 'kind': 'google-chrome', 'version': 'Chrome 1'}
        with patch.object(teardown, 'find_node', return_value=node), \
             patch.object(teardown, 'find_chrome', return_value=chrome):
            return teardown.diag()

    def test_ready_when_all_real_pieces_agree(self):
        data = self.diagnose()
        self.assertTrue(data['ready'])
        self.assertEqual(data['rea']['installed'], '6.7.0')
        self.assertEqual(data['rea']['pinned'], '6.7.0')
        self.assertTrue(data['rea']['pinned_exact'])
        self.assertEqual(data['problems'], [])

    def test_missing_node_and_chrome_are_plain_english_and_one_line(self):
        data = self.diagnose(node={'path': None, 'version': None, 'supported': False},
                             chrome={'found': False, 'path': None, 'kind': None, 'version': None})
        self.assertFalse(data['ready'])
        text = ' '.join(data['problems'])
        self.assertIn('Node.js is not installed', text)
        self.assertIn('Google Chrome was not found', text)
        answer = teardown.one_line_answer(data)
        self.assertNotIn('\n', answer)
        self.assertIn('Not yet, sir', answer)

    def test_version_mismatch_names_reexecuted_install(self):
        (self.root / 'package.json').write_text(json.dumps({'dependencies': {'rea-agents': '6.6.0'}}))
        data = self.diagnose()
        self.assertFalse(data['ready'])
        joined = ' '.join(data['problems'])
        self.assertIn('6.6.0', joined)
        self.assertIn('npm install rea-agents@6.6.0 --save-exact --ignore-scripts', joined)

    def test_missing_install_prints_pinned_commands_not_latest(self):
        (self.root / 'package.json').unlink()
        (self.package / 'package.json').unlink()
        data = self.diagnose()
        joined = ' '.join(data['problems'])
        self.assertIn('npm install rea-agents@6.7.0 --save-exact --ignore-scripts', joined)
        self.assertNotIn('@latest', joined)

    def test_untrusted_repository_is_flagged(self):
        (self.package / 'package.json').write_text(json.dumps({
            'version': '6.7.0', 'repository': {'url': 'https://github.com/copycat/fake.git'}}))
        data = self.diagnose()
        self.assertFalse(data['ready'])
        self.assertIn('github.com/morluto/rea', ' '.join(data['problems']))

    def test_not_ready_run_raises_one_line_without_executing(self):
        data = self.diagnose(node={'path': None, 'version': None, 'supported': False})
        with patch.object(teardown, 'diag', return_value=data):
            with self.assertRaises(teardown.NotReady) as raised:
                teardown.run('capabilities')
        self.assertNotIn('\n', str(raised.exception))
        self.assertIn('Not yet, sir', str(raised.exception))

    def test_invalid_command_and_arguments_never_reach_subprocess(self):
        data = self.diagnose()
        with patch.object(teardown, 'diag', return_value=data), \
             patch.object(teardown.subprocess, 'Popen') as runner:
            self.assertFalse(teardown.run('--help')['ok'])
            self.assertFalse(teardown.run('capabilities', arguments=['bad\narg'])['ok'])
            self.assertFalse(teardown.run('capabilities', arguments='--danger')['ok'])
            self.assertFalse(teardown.run('decompile', target='x\x00y')['ok'])
            runner.assert_not_called()

    @staticmethod
    def fake_popen(stdout_text="", stderr_text="", code=0, stay_pending=False):
        """A Popen double that writes into the temp files `run` passes in."""
        class FakeProcess:
            def __init__(self):
                self.returncode = code
                self.pid = 123
                self.pending = stay_pending

            def poll(self):
                if self.pending:
                    self.pending = False
                    return None
                return self.returncode

            def wait(self, timeout=None):
                return self.returncode

        def spawn(_argv, **kwargs):
            for name, text in (("stdout", stdout_text), ("stderr", stderr_text)):
                handle = kwargs.get(name)
                if handle is not None:
                    handle.write(text.encode("utf-8"))
                    handle.flush()
            return FakeProcess()
        return spawn

    def test_run_builds_exact_node_argv_and_parses_json(self):
        data = self.diagnose()
        completed = self.fake_popen('{"ok":true}')
        with patch.object(teardown, 'diag', return_value=data), \
             patch.object(teardown.subprocess, 'Popen', side_effect=completed) as runner:
            result = teardown.run('capabilities', timeout=30)
        self.assertTrue(result['ok'])
        argv = runner.call_args.args[0]
        self.assertEqual(argv[0], data['node']['path'])
        self.assertEqual(argv[1], str(self.package / 'scripts' / 'rea.mjs'))
        self.assertEqual(argv[2], 'capabilities')
        self.assertEqual(argv[-1], '--json')
        self.assertEqual(result['result'], {'ok': True})

    def test_bad_json_and_nonzero_exit_are_reported_without_crashing(self):
        data = self.diagnose()
        with patch.object(teardown, 'diag', return_value=data), \
             patch.object(teardown.subprocess, 'Popen',
                          side_effect=self.fake_popen('not json')):
            result = teardown.run('capabilities')
        self.assertFalse(result['ok'])
        self.assertEqual(result['error'], 'json_parse')
        with patch.object(teardown, 'diag', return_value=data), \
             patch.object(teardown.subprocess, 'Popen',
                          side_effect=self.fake_popen('', 'boom', code=2)):
            result = teardown.run('capabilities')
        self.assertFalse(result['ok'])
        self.assertEqual(result['receipt']['exit_code'], 2)

    def test_full_output_larger_than_the_tail_cap_still_parses(self):
        # --full-output captures script sources; the JSON must be parsed from the
        # whole capture, not from a truncated tail that is not valid on its own.
        data = self.diagnose()
        body = '{"ok":true,"sources":["' + 'x' * (teardown.MAX_OUTPUT + 5000) + '"]}'
        with patch.object(teardown, 'diag', return_value=data), \
             patch.object(teardown.subprocess, 'Popen',
                          side_effect=self.fake_popen(body)):
            result = teardown.run('inspect-web-page', timeout=30)
        self.assertTrue(result['ok'])
        self.assertEqual(len(result['result']['sources']), 1)

    def test_oversized_stdout_is_refused_before_it_is_buffered(self):
        data = self.diagnose()
        body = '{"ok":true,"x":"' + 'y' * 200 + '"}'
        with patch.object(teardown, 'diag', return_value=data), \
             patch.object(teardown, 'MAX_STDOUT', 100), \
             patch.object(teardown.subprocess, 'Popen',
                          side_effect=self.fake_popen(body, stay_pending=True)):
            result = teardown.run('inspect-web-page', timeout=30)
        self.assertFalse(result['ok'])
        self.assertEqual(result['error'], 'output_too_large')


if __name__ == '__main__':
    unittest.main()
