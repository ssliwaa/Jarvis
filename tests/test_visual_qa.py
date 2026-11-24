"""visual_qa: DOM/asset parser, web-entry discovery, ephemeral HTTP QA loop.

The module is a small pipeline of pure units (HTML parser, `find_web_entry`,
JS-error regex) plus an integration loop (`run_visual_qa`) that serves a repo on
a real ephemeral 127.0.0.1:0 socket — that localhost server is exercised for
real in tests, while `shutil.which`, `subprocess.run` and `_find_browser` are
faked (this host actually ships a chromium at /snap/bin, so browser lookup is
patched in every test). Pinned: asset/inline-script extraction rules, candidate
priority of `find_web_entry`, skip-dir semantics, the server's 404 ledger with
its favicon exemption, node --check reporting and caps, exact chromium argv,
timeout clamps (falsy 0 -> 20), console-error dedupe/clip, the 404 double-entry
from asset fetch vs server ledger, empty-render threshold and the Polish
output lines.
"""
import os
import shutil
import subprocess
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import visual_qa as vq
from visual_qa import (
    BROWSER_CANDIDATES,
    WEB_ENTRY_SKIP_DIRS,
    _AssetParser,
    _check_inline_js,
    find_web_entry,
    run_visual_qa,
)


class VisualBase(unittest.TestCase):
    def setUp(self):
        import tempfile
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def make_repo(self, files: dict, name: str = 'repo') -> Path:
        repo = self.tmp / name
        repo.mkdir()
        for name, data in files.items():
            path = repo / name
            path.parent.mkdir(parents=True, exist_ok=True)
            if isinstance(data, bytes):
                path.write_bytes(data)
            else:
                path.write_text(data, encoding='utf-8')
        return repo


class AssetParser(unittest.TestCase):
    BROKEN_PAGE = (
        '<html><head>'
        '<script SRC="app.js"></script>'
        '<script src="  spaced.js "></script>'
        '<script type="application/ld+json">{"json": "not js"}</script>'
        '<link rel="stylesheet" href="style.css">'
        '<link REL="SHORTCUT ICON" href="favicon.ico">'
        '<link rel="preload" href="pre.js">'
        '</head><body>'
        '<img src="pic.png"><img src="data:image/png;base64,AAAA">'
        '<script type="module">export const x = 1</script>'
        '</body></html>'
    )

    def test_asset_matrix(self):
        parser = _AssetParser()
        parser.feed(self.BROKEN_PAGE)
        parser.close()
        # script src (case-insensitive attr, spaces stripped), stylesheet + icon
        # rel, plain img — preload and data: URIs are ignored
        self.assertEqual(parser.assets, ['app.js', 'spaced.js', 'style.css',
                                          'favicon.ico', 'pic.png'])
        # ld+json is not JavaScript; module scripts are inline code
        self.assertEqual(parser.inline_scripts, ['export const x = 1'])

    def test_inline_type_whitelist(self):
        page = ('<script>plain()</script>'
                '<script type="text/javascript">a()</script>'
                '<script type="application/javascript">b()</script>')
        parser = _AssetParser()
        parser.feed(page)
        parser.close()
        self.assertEqual(parser.inline_scripts, ['plain()', 'a()', 'b()'])

    def test_unclosed_script_dropped_and_no_inline_from_remote_src(self):
        parser = _AssetParser()
        parser.feed('<script src="x.js">this buffer belongs to a remote script')
        parser.close()
        self.assertEqual(parser.assets, ['x.js'])
        self.assertEqual(parser.inline_scripts, [])   # endtag never fired

    def test_js_error_regex(self):
        for line, expected in (('Uncaught TypeError: x is not a function', True),
                               ('uncaught referenceerror: y nope', True),
                               ('uncaught syntaxerror: bad', True),
                               ('CONSOLE ERROR offline', True),
                               ('console error lowercase matches too', True),
                               ('[INFO] plain log line', False),
                               ('SyntaxError: unexpected token', False)):
            with self.subTest(line=line):
                self.assertEqual(bool(vq.JS_ERROR_RE.search(line)), expected)


class FindWebEntry(VisualBase):
    def test_candidate_priority_chain(self):
        repo = self.make_repo({'dist/index.html': 'dist', 'web/index.html': 'web'})
        self.assertEqual(find_web_entry(repo)[1].parent.name, 'dist')
        (repo / 'viewer' / 'index.html').parent.mkdir(parents=True, exist_ok=True)
        (repo / 'viewer' / 'index.html').write_text('viewer', encoding='utf-8')
        self.assertEqual(find_web_entry(repo)[1].parent.name, 'viewer')
        # public is checked AFTER viewer: adding it changes nothing yet
        repo.joinpath('public').mkdir()
        repo.joinpath('public', 'index.html').write_text('public', encoding='utf-8')
        self.assertEqual(find_web_entry(repo)[1].parent.name, 'viewer')
        # root index.html beats everything
        repo.joinpath('index.html').write_text('root', encoding='utf-8')
        self.assertEqual(find_web_entry(repo)[1].parent.name, repo.name)
        self.assertEqual(find_web_entry(repo)[1].name, 'index.html')

    def test_rglob_fallback_prefers_first_sorted_path(self):
        repo = self.make_repo({'alpha/page.html': 'a', 'beta/page.html': 'b'})
        serve_root, entry = find_web_entry(repo)
        self.assertEqual((serve_root.name, entry.name), ('alpha', 'page.html'))

    def test_skip_dirs_and_git(self):
        repo = self.make_repo({'fixtures/x.html': 'x', 'testdata/y.html': 'y',
                               'mocks/z.html': 'z', '.git/g.html': 'g'})
        self.assertEqual(find_web_entry(repo), (None, None))
        self.assertEqual(WEB_ENTRY_SKIP_DIRS & {'fixtures', 'testdata', 'test',
                                                'examples', 'demo', 'mocks'},
                         {'fixtures', 'testdata', 'test', 'examples', 'demo', 'mocks'})

    def test_skip_dirs_apply_only_to_parents_not_filename(self):
        repo = self.make_repo({'fixtures/index.html': 'x'})  # under fixtures/ -> skipped
        self.assertEqual(find_web_entry(repo), (None, None))
        repo2 = self.make_repo({'fixtures.html': 'x'}, name='repo2')  # file named fixtures.html
        root, entry = find_web_entry(repo2)
        self.assertEqual((root, entry.name), (repo2, 'fixtures.html'))

    def test_missing_dir_yields_no_entry(self):
        self.assertEqual(find_web_entry(self.tmp / 'nope'), (None, None))


class EphemeralServer(VisualBase):
    def test_records_404s_except_favicon(self):
        serve = self.make_repo({'index.html': '<html>hello</html>'})
        with vq._ephemeral_http_server(serve) as (base, ledger):
            with urllib.request.urlopen(base + '/index.html', timeout=5) as resp:
                self.assertEqual(resp.status, 200)
            for path in ('/missing.css', '/favicon.ico'):
                with self.assertRaises(urllib.error.HTTPError):
                    urllib.request.urlopen(base + path, timeout=5)
            self.assertEqual(ledger, ['404 /missing.css'])
            port = base.rsplit(':', 1)[1]
            self.assertEqual(base, f'http://127.0.0.1:{port}')
        # the ledger list survives the context and the server is closed after it
        self.assertEqual(ledger, ['404 /missing.css'])
        with self.assertRaises(Exception):
            urllib.request.urlopen(base + '/index.html', timeout=2)


class InlineJsCheck(VisualBase):
    def fake_node(self, seen):
        def run(argv, **kwargs):
            seen.append(argv)
            snippet = Path(argv[2]).read_text(encoding='utf-8')
            return SimpleNamespace(
                returncode=1 if 'BAD' in snippet else 0,
                stderr='node: SyntaxError: ' + ('u' * 300) if 'BAD' in snippet else '')
        return run

    def test_reports_bad_scripts_with_240_clip_and_12_cap(self):
        seen = []
        scripts = ['ok();'] + ['BAD'] * 1 + [f'good{i}();' for i in range(11)]
        run = self.fake_node(seen)
        long_stderr = 'node: SyntaxError: ' + ('u' * 300)
        with patch.object(vq.shutil, 'which', lambda n: '/usr/bin/node' if n == 'node' else None), \
                patch.object(vq.subprocess, 'run', run):
            errors = _check_inline_js(scripts)
        # the 240-char clip applies to the node message itself, before the prefix
        self.assertEqual(errors, ['inline script #2: ' + long_stderr[:240]])
        self.assertEqual(len(seen), 12)          # the 13th script is beyond the cap
        self.assertTrue(all(a[1] == '--check' and a[2].endswith('.mjs') for a in seen))
        # a 14th script is silently beyond the cap
        seen.clear()
        with patch.object(vq.shutil, 'which', lambda n: '/usr/bin/node' if n == 'node' else None), \
                patch.object(vq.subprocess, 'run', run):
            _check_inline_js(['s%d' % i for i in range(20)])
        self.assertEqual(len(seen), 12)

    def test_no_node_or_no_scripts_is_a_no_op(self):
        with patch.object(vq.shutil, 'which', lambda n: None):
            self.assertEqual(_check_inline_js(['var a = 1;']), [])
        with patch.object(vq.shutil, 'which', lambda n: '/usr/bin/node' if n == 'node' else None):
            self.assertEqual(_check_inline_js([]), [])


class BrowserRender(VisualBase):
    """Chromium invocation is faked end to end (a real chromium exists on this host)."""

    def make_web(self):
        return self.make_repo({'index.html': '<html><body>rendered page</body></html>'})

    def fake_chromium(self, calls, stderr='', stdout='DOMDUMP ' + 'd' * 40, write_shot=False):
        def run(argv, **kwargs):
            calls.append((argv, kwargs))
            if '--dump-dom' in argv:
                return SimpleNamespace(returncode=0, stdout=stdout, stderr=stderr)
            shot = next(a for a in argv if a.startswith('--screenshot='))
            if write_shot:
                Path(shot.split('=', 1)[1]).write_bytes(b'PNGDATA')
            return SimpleNamespace(returncode=0, stdout='', stderr='')
        return run

    def expected_common(self, browser):
        return [browser, '--headless=new', '--disable-gpu', '--no-sandbox',
                '--disable-dev-shm-usage', '--no-first-run', '--virtual-time-budget=2000']

    def test_dump_dom_argv_and_console_extraction(self):
        repo = self.make_web()
        calls = []
        stderr = ('Uncaught TypeError: boom at q.js:1\n'
                  'CONSOLE ERROR offline\n'
                  'Uncaught TypeError: boom at q.js:1\n'
                  'info line kept out\n'
                  'uncaught syntaxerror: bad\n'
                  'Uncaught ReferenceError: ' + 'z' * 300 + '\n')
        run = self.fake_chromium(calls, stderr=stderr)
        with patch.object(vq, '_find_browser', lambda: '/usr/bin/chromium-fake'), \
                patch.object(vq.subprocess, 'run', run):
            res = run_visual_qa(repo)
        argv, kwargs = calls[0]
        self.assertEqual(argv[:7], self.expected_common('/usr/bin/chromium-fake'))
        self.assertEqual(argv[7:9], ['--enable-logging=stderr', '--dump-dom'])
        self.assertTrue(argv[-1].startswith('http://127.0.0.1:'))
        self.assertTrue(argv[-1].endswith('/index.html'))
        self.assertEqual(kwargs, {'capture_output': True, 'text': True,
                                  'timeout': 20, 'check': False})
        self.assertEqual(res['dom_length'], len('DOMDUMP ' + 'd' * 40))
        self.assertEqual(res['console_errors'],
                         ['Uncaught TypeError: boom at q.js:1', 'CONSOLE ERROR offline',
                          'uncaught syntaxerror: bad',
                          ('Uncaught ReferenceError: ' + 'z' * 300)[:260]])   # clipped to 260
        self.assertEqual(res['missing_assets'], [])

    def test_screenshot_flow(self):
        repo = self.make_web()
        calls = []
        shot = self.tmp / 'subdir' / 'shot.png'
        run = self.fake_chromium(calls, write_shot=True)
        with patch.object(vq, '_find_browser', lambda: '/usr/bin/chromium-fake'), \
                patch.object(vq.subprocess, 'run', run):
            res = run_visual_qa(repo, screenshot_path=shot)
        self.assertEqual(res['screenshot'], str(shot.resolve()))
        self.assertEqual(shot.read_bytes(), b'PNGDATA')
        shot_argv, shot_kwargs = calls[1]
        self.assertEqual(shot_argv[7:9], ['--window-size=1280,800',
                                          f'--screenshot={shot.resolve()}'])
        self.assertEqual(shot_kwargs['timeout'], 15)      # fixed, ignores page timeout
        # process that writes nothing leaves 'screenshot' empty
        calls.clear()
        run = self.fake_chromium(calls, write_shot=False)
        with patch.object(vq, '_find_browser', lambda: '/usr/bin/chromium-fake'), \
                patch.object(vq.subprocess, 'run', run):
            res2 = run_visual_qa(repo, screenshot_path=self.tmp / 'ghost.png')
        self.assertEqual(res2['screenshot'], '')
        self.assertFalse((self.tmp / 'ghost.png').exists())

    def test_timeout_clamps(self):
        repo = self.make_web()
        for given, expected in ((0, 20), (None, 20), (99, 35), (-3, 5), (12, 12)):
            with self.subTest(timeout=given):
                calls = []
                run = self.fake_chromium(calls)
                with patch.object(vq, '_find_browser', lambda: '/fake'), \
                        patch.object(vq.subprocess, 'run', run):
                    run_visual_qa(repo, timeout=given)
                self.assertEqual(calls[0][1]['timeout'], expected)

    def test_browser_timeouts_and_crashes_fall_back_to_static_dom(self):
        repo = self.make_web()
        html_len = len((repo / 'index.html').read_text().strip())

        def te(argv, **kwargs):
            raise subprocess.TimeoutExpired(cmd='b', timeout=5)

        def ose(argv, **kwargs):
            raise OSError('no display')

        for name, fake in (('TimeoutExpired', te), ('OSError', ose)):
            with self.subTest(failure=name), \
                    patch.object(vq, '_find_browser', lambda: '/fake'), \
                    patch.object(vq.subprocess, 'run', fake):
                res = run_visual_qa(repo)
            self.assertEqual(res['dom_length'], html_len)
            self.assertTrue(res['ok'])

    def test_browser_candidates_constant(self):
        self.assertEqual(BROWSER_CANDIDATES[0], 'chromium')
        self.assertEqual(len(BROWSER_CANDIDATES), 5)
        self.assertIn('google-chrome', BROWSER_CANDIDATES)


class RunVisualQa(VisualBase):
    """Integration over a real ephemeral localhost server, with the browser off."""

    BROKEN_PAGE = (
        '<html><head>'
        '<script src="app.js"></script>'
        '<script src="missing.js"></script>'
        '<link rel="stylesheet" href="style.css">'
        '<link rel="stylesheet" href="https://cdn.example.org/x.css">'
        '<link rel="icon" href="favicon.ico">'
        '</head><body>'
        '<img src="pic.png"><img src="data:image/png;base64,AA">'
        '<script>console.log("a")</script>'
        '</body></html>'
    )

    def broken_repo(self):
        return self.make_repo({'index.html': self.BROKEN_PAGE, 'app.js': 'ok',
                               'style.css': 'body{}', 'pic.png': b'PNG'})

    def test_broken_page_reports_assets_console_and_dom(self):
        repo = self.broken_repo()
        with patch.object(vq, '_find_browser', lambda: ''), \
                patch.object(vq, '_check_inline_js', lambda s: ['inline script #1: boom']):
            res = run_visual_qa(repo)
        self.assertFalse(res['ok'])
        self.assertTrue(res['applicable'])
        self.assertEqual(res['entry'], 'index.html')
        # a missing asset is reported twice: once by the fetch loop (raw ref)
        # and once by the server ledger (url path) — pinned as-is
        self.assertEqual(res['missing_assets'],
                         ['404 missing.js', '404 favicon.ico', '404 /missing.js'])
        self.assertEqual(res['console_errors'], ['inline script #1: boom'])
        self.assertEqual(res['dom_length'], len(self.BROKEN_PAGE.strip()))
        self.assertEqual(res['screenshot'], '')
        self.assertEqual(res['output'],
                         'Brakujące zasoby HTTP: 404 missing.js, 404 favicon.ico, '
                         '404 /missing.js\nBłędy JS/konsoli: inline script #1: boom')

    def test_happy_path_is_green(self):
        repo = self.broken_repo()
        (repo / 'missing.js').write_text('x', encoding='utf-8')
        (repo / 'favicon.ico').write_bytes(b'IC')
        with patch.object(vq, '_find_browser', lambda: ''), \
                patch.object(vq, '_check_inline_js', lambda s: []):
            res = run_visual_qa(repo)
        self.assertEqual(sorted(res), ['applicable', 'console_errors', 'dom_length',
                                       'entry', 'missing_assets', 'ok', 'output',
                                       'screenshot'])
        self.assertTrue(res['ok'])
        self.assertEqual(res['missing_assets'], [])
        self.assertEqual(res['console_errors'], [])
        self.assertEqual(res['output'], '')

    def test_empty_render_threshold(self):
        repo = self.make_repo({'index.html': '<p>hi</p>'})    # 9 chars < 20
        with patch.object(vq, '_find_browser', lambda: ''), \
                patch.object(vq, '_check_inline_js', lambda s: []):
            res = run_visual_qa(repo)
        self.assertFalse(res['ok'])
        self.assertEqual(res['dom_length'], 9)
        self.assertEqual(res['output'], 'Pusty wyrenderowany DOM (9 znaków) w index.html')

    def test_no_web_entry_is_not_applicable(self):
        empty = self.tmp / 'just-a-dir'
        empty.mkdir()
        for target in (empty, self.tmp / 'not-there'):
            with self.subTest(target=target):
                self.assertEqual(run_visual_qa(target),
                                 {'ok': True, 'applicable': False, 'checks': [],
                                  'output': ''})

    @unittest.skipUnless(os.geteuid() != 0, 'chmod 000 only blocks non-root readers')
    def test_unreadable_entry_reports_fetch_failure(self):
        repo = self.make_repo({'index.html': 'secret'})
        (repo / 'index.html').chmod(0)      # SimpleHTTPRequestHandler: 404 File not found
        self.addCleanup((repo / 'index.html').chmod, 0o644)
        with patch.object(vq, '_find_browser', lambda: ''), \
                patch.object(vq, '_check_inline_js', lambda s: []):
            res = run_visual_qa(repo)
        self.assertFalse(res['ok'])
        self.assertTrue(res['applicable'])
        self.assertEqual(res['entry'], 'index.html')
        self.assertTrue(res['output'].startswith(
            'Nie udało się pobrać strony index.html: HTTP Error'))
        self.assertNotIn('dom_length', res)


if __name__ == '__main__':
    unittest.main()
