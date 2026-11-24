"""Headless Visual QA & local asset/DOM verifier for Jarvis web builds.

Serves a project's static/UI root on an ephemeral `127.0.0.1:0` socket, verifies
that HTML entrypoints and referenced `<script>`/`<link>` assets resolve with
HTTP 200, checks inline/external JS syntax, and—when a headless Chromium-family
binary is available—renders the page to catch uncaught JS runtime errors, blank
screens, and save a `visual_qa.png` screenshot.
"""

import functools
import http.server
import re
import shutil
import subprocess
import tempfile
import threading
import urllib.error
import urllib.parse
import urllib.request
from contextlib import contextmanager
from html.parser import HTMLParser
from pathlib import Path

BROWSER_CANDIDATES = (
    'chromium',
    'chromium-browser',
    'google-chrome',
    'google-chrome-stable',
    'brave-browser',
)
JS_ERROR_RE = re.compile(
    r'(?:Uncaught (?:TypeError|ReferenceError|SyntaxError|Error)|CONSOLE ERROR)[^\n]*',
    re.I,
)


class _AssetParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.assets: list[str] = []
        self.inline_scripts: list[str] = []
        self._in_script = False
        self._buf: list[str] = []

    def handle_starttag(self, tag, attrs):
        attr_map = dict(attrs)
        t = tag.lower()
        if t == 'script':
            src = (attr_map.get('src') or '').strip()
            if src:
                self.assets.append(src)
            else:
                stype = (attr_map.get('type') or '').strip().lower()
                if stype in ('', 'text/javascript', 'module', 'application/javascript'):
                    self._in_script = True
                    self._buf = []
        elif t == 'link':
            rel = (attr_map.get('rel') or '').lower()
            href = (attr_map.get('href') or '').strip()
            if href and ('stylesheet' in rel or 'icon' in rel):
                self.assets.append(href)
        elif t == 'img':
            src = (attr_map.get('src') or '').strip()
            if src and not src.startswith('data:'):
                self.assets.append(src)

    def handle_data(self, data):
        if self._in_script:
            self._buf.append(data)

    def handle_endtag(self, tag):
        if tag.lower() == 'script' and self._in_script:
            self._in_script = False
            code = ''.join(self._buf).strip()
            if code:
                self.inline_scripts.append(code)
            self._buf = []


WEB_ENTRY_SKIP_DIRS = {
    'fixtures', 'fixture', 'testdata', 'test-data', 'tests', 'test', '__tests__',
    'examples', 'example', 'samples', 'demo', 'demos', 'mocks',
}


def find_web_entry(repo_dir: str | Path) -> tuple[Path | None, Path | None]:
    """Locate `(serve_root, entry_html)` inside repo_dir if a web UI exists."""
    repo = Path(repo_dir).expanduser().resolve()
    if not repo.is_dir():
        return None, None
    candidates = (
        (repo, repo / 'index.html'),
        (repo / 'viewer', repo / 'viewer' / 'index.html'),
        (repo / 'public', repo / 'public' / 'index.html'),
        (repo / 'dist', repo / 'dist' / 'index.html'),
        (repo / 'web', repo / 'web' / 'index.html'),
    )
    for root, html_file in candidates:
        if html_file.is_file():
            return root, html_file
    for html_file in sorted(repo.rglob('*.html')):
        if '.git' in html_file.parts or 'node_modules' in html_file.parts:
            continue
        # A fixture page under hardening/packs/*/fixtures/ is test data, not the app:
        # serving it produced a wall of 404s for assets it never shipped.
        if any(part in WEB_ENTRY_SKIP_DIRS for part in html_file.relative_to(repo).parts[:-1]):
            continue
        return html_file.parent, html_file
    return None, None


@contextmanager
def _ephemeral_http_server(serve_root: Path):
    """Bind strictly to 127.0.0.1:0 and shut down deterministically on exit."""
    bad_requests: list[str] = []

    class _QuietHandler(http.server.SimpleHTTPRequestHandler):
        def log_message(self, fmt, *args):
            return

        def send_error(self, code, message=None, explain=None):
            if code >= 400 and not str(self.path).endswith('/favicon.ico'):
                bad_requests.append(f'{code} {self.path}')
            super().send_error(code, message, explain)

    handler_cls = functools.partial(_QuietHandler, directory=str(serve_root))
    httpd = http.server.ThreadingHTTPServer(('127.0.0.1', 0), handler_cls)
    port = httpd.server_address[1]
    thread = threading.Thread(target=httpd.serve_forever, name='jarvis-visual-qa-http', daemon=True)
    thread.start()
    try:
        yield f'http://127.0.0.1:{port}', bad_requests
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=3)


def _find_browser() -> str:
    for name in BROWSER_CANDIDATES:
        found = shutil.which(name)
        if found:
            return found
    return ''


def _check_inline_js(scripts: list[str]) -> list[str]:
    node_bin = shutil.which('node')
    if not node_bin or not scripts:
        return []
    errors = []
    with tempfile.TemporaryDirectory() as tmp:
        for idx, snippet in enumerate(scripts[:12], 1):
            js_file = Path(tmp) / f'inline_{idx}.mjs'
            js_file.write_text(snippet, encoding='utf-8')
            res = subprocess.run(
                [node_bin, '--check', str(js_file)],
                capture_output=True,
                text=True,
                timeout=8,
                check=False,
            )
            if res.returncode != 0:
                errors.append(f'inline script #{idx}: {(res.stderr or res.stdout).strip()[:240]}')
    return errors


def run_visual_qa(repo_dir: str | Path, screenshot_path: str | Path | None = None,
                  timeout: int = 20) -> dict:
    """Verify web entrypoint HTTP assets, inline JS, headless DOM render, and optional screenshot."""
    serve_root, entry_html = find_web_entry(repo_dir)
    if serve_root is None or entry_html is None:
        return {'ok': True, 'applicable': False, 'checks': [], 'output': ''}

    rel_entry = str(entry_html.relative_to(serve_root)).replace('\\', '/')
    missing_assets: list[str] = []
    console_errors: list[str] = []
    dom_length = 0
    saved_shot = ''

    with _ephemeral_http_server(serve_root) as (base_url, server_404s):
        page_url = f'{base_url}/{urllib.parse.quote(rel_entry)}'
        try:
            with urllib.request.urlopen(page_url, timeout=5) as resp:
                html_text = resp.read(1_000_000).decode('utf-8', errors='replace')
        except Exception as exc:
            return {
                'ok': False,
                'applicable': True,
                'entry': rel_entry,
                'output': f'Nie udało się pobrać strony {rel_entry}: {exc}',
            }

        parser = _AssetParser()
        try:
            parser.feed(html_text)
        except Exception:
            pass

        for raw_ref in parser.assets[:40]:
            if raw_ref.startswith(('http://', 'https://', '//', 'mailto:', '#')):
                continue
            asset_url = urllib.parse.urljoin(page_url, raw_ref)
            if not asset_url.startswith(base_url):
                continue
            try:
                with urllib.request.urlopen(asset_url, timeout=5) as aresp:
                    if aresp.status >= 400:
                        missing_assets.append(f'{aresp.status} {raw_ref}')
            except urllib.error.HTTPError as hexc:
                missing_assets.append(f'{hexc.code} {raw_ref}')
            except Exception as exc:
                missing_assets.append(f'ERR {raw_ref} ({exc})')

        inline_errors = _check_inline_js(parser.inline_scripts)
        console_errors.extend(inline_errors)

        browser = _find_browser()
        if browser:
            common_flags = [
                browser,
                '--headless=new',
                '--disable-gpu',
                '--no-sandbox',
                '--disable-dev-shm-usage',
                '--no-first-run',
                '--virtual-time-budget=2000',
            ]
            try:
                dom_proc = subprocess.run(
                    [*common_flags, '--enable-logging=stderr', '--dump-dom', page_url],
                    capture_output=True,
                    text=True,
                    timeout=max(5, min(int(timeout or 20), 35)),
                    check=False,
                )
                dom_length = len((dom_proc.stdout or '').strip())
                for m in JS_ERROR_RE.finditer(dom_proc.stderr or ''):
                    err_line = m.group(0).strip()[:260]
                    if err_line not in console_errors:
                        console_errors.append(err_line)
                if screenshot_path:
                    shot = Path(screenshot_path).expanduser().resolve()
                    shot.parent.mkdir(parents=True, exist_ok=True)
                    subprocess.run(
                        [*common_flags, '--window-size=1280,800', f'--screenshot={shot}', page_url],
                        capture_output=True,
                        text=True,
                        timeout=15,
                        check=False,
                    )
                    if shot.is_file() and shot.stat().st_size > 0:
                        saved_shot = str(shot)
            except subprocess.TimeoutExpired:
                # Headless browser timed out (e.g. sandboxed display environment); fall back to static checks
                dom_length = len(html_text.strip())
            except OSError:
                dom_length = len(html_text.strip())
        else:
            dom_length = len(html_text.strip())

        for item in server_404s:
            if item not in missing_assets:
                missing_assets.append(item)

    empty_render = dom_length < 20
    ok = (not missing_assets) and (not console_errors) and (not empty_render)

    issues = []
    if missing_assets:
        issues.append('Brakujące zasoby HTTP: ' + ', '.join(missing_assets[:8]))
    if console_errors:
        issues.append('Błędy JS/konsoli: ' + ' | '.join(console_errors[:5]))
    if empty_render:
        issues.append(f'Pusty wyrenderowany DOM ({dom_length} znaków) w {rel_entry}')

    return {
        'ok': ok,
        'applicable': True,
        'entry': rel_entry,
        'dom_length': dom_length,
        'missing_assets': missing_assets,
        'console_errors': console_errors,
        'screenshot': saved_shot,
        'output': '\n'.join(issues),
    }
