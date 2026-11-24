#!/usr/bin/env python3
"""Live teardown drill with exact snapshot/restore and crash cleanup proof."""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import signal
import socket
import time
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parent
NOTES = Path(os.environ.get('JARVIS_VAULT', str(Path.home() / 'notes'))).expanduser()
GRAPH = ROOT / 'viewer/graph-data.js'
EPISODES = ROOT / 'artifacts/teardown-episodes.jsonl'
TEARDOWNS = NOTES / 'NOTES/captures/teardowns'
CONCEPT = NOTES / 'NOTES/concepts/REA.md'
STEP_LABELS = [
    'Opening the site in a clean browser',
    'Waiting for it to load',
    'REA is watching while I scroll',
    'REA is reading the code',
    'Taking a snapshot',
    'Listing everything it loaded',
    'Identifying the stack',
    'Writing the teardown',
]


class Snapshot:
    def __init__(self):
        self.graph = GRAPH.read_bytes()
        self.episode = EPISODES.read_bytes() if EPISODES.is_file() else None
        self.concept = CONCEPT.read_bytes() if CONCEPT.is_file() else None
        self.teardowns_existed = TEARDOWNS.is_dir()
        self.teardown_files, self.teardown_dirs = {}, []
        if self.teardowns_existed:
            for path in sorted(TEARDOWNS.rglob('*')):
                rel = path.relative_to(TEARDOWNS).as_posix()
                if path.is_dir():
                    self.teardown_dirs.append(rel)
                elif path.is_file():
                    self.teardown_files[rel] = path.read_bytes()
        self.evidence_dirs = {path.name for path in (ROOT / 'artifacts/evidence').iterdir()
                              if path.is_dir()} if (ROOT / 'artifacts/evidence').is_dir() else set()

    def restore(self):
        GRAPH.write_bytes(self.graph)
        if self.episode is None:
            EPISODES.unlink(missing_ok=True)
        else:
            EPISODES.write_bytes(self.episode)
        if self.concept is None:
            CONCEPT.unlink(missing_ok=True)
        else:
            CONCEPT.parent.mkdir(parents=True, exist_ok=True)
            CONCEPT.write_bytes(self.concept)
        if TEARDOWNS.exists():
            shutil.rmtree(TEARDOWNS)
        if self.teardowns_existed:
            TEARDOWNS.mkdir(parents=True, exist_ok=True)
            for rel in self.teardown_dirs:
                (TEARDOWNS / rel).mkdir(parents=True, exist_ok=True)
            for rel, data in self.teardown_files.items():
                target = TEARDOWNS / rel
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(data)
        current = {path.name for path in (ROOT / 'artifacts/evidence').iterdir()
                   if path.is_dir()} if (ROOT / 'artifacts/evidence').is_dir() else set()
        for name in current - self.evidence_dirs:
            shutil.rmtree(ROOT / 'artifacts/evidence' / name, ignore_errors=True)


def no_redirect_open(url):
    request = Request(url, headers={'Accept': 'application/json'})
    return urlopen(request, timeout=20)


def expect_refusal(path):
    try:
        with no_redirect_open('http://127.0.0.1:4700' + path) as response:
            body = response.read(200)
            raise AssertionError(f'{path} returned HTTP {response.status}: {body!r}')
    except HTTPError as error:
        if error.code not in (400, 403, 404):
            raise AssertionError(f'{path} refused with unexpected HTTP {error.code}') from None
        return error.code


def no_chrome_left():
    profile_root = Path.home() / '.jarvis-tools/rea/profiles'
    pids = []
    for entry in Path('/proc').iterdir():
        if not entry.name.isdigit():
            continue
        try:
            argv = (entry / 'cmdline').read_bytes().split(b'\0')
        except OSError:
            continue
        if any(b'.jarvis-tools/rea/profiles' in arg or b'--remote-debugging-port=9333' in arg for arg in argv):
            pids.append(int(entry.name))
    folders = sorted(path.name for path in profile_root.iterdir()
                     if path.name != '.browser.lock') if profile_root.is_dir() else []
    sock = socket.socket()
    try:
        port_open = sock.connect_ex(('127.0.0.1', 9333)) == 0
    finally:
        sock.close()
    if pids or folders or port_open:
        raise AssertionError(f'Chrome cleanup failed: pids={pids}, profiles={folders}, port9333={port_open}')


def crash_cleanup():
    import teardown
    job = teardown.browser_job('https://example.com/', headless=True, scroll=False)
    job.start()
    try:
        pid = job.process.pid
        os.kill(pid, signal.SIGKILL)
        time.sleep(0.4)
    finally:
        cleanup = job.close(raise_on_error=False)
    if not cleanup.get('profile_removed') or not cleanup.get('port_released'):
        raise AssertionError(f'Crash cleanup did not prove itself: {cleanup}')
    no_chrome_left()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--url', default='https://www.monogrid.com/')
    parser.add_argument('--timeout', type=int, default=420)
    parser.add_argument('--keep', action='store_true', help='leave the test note for inspection')
    args = parser.parse_args()
    snapshot = Snapshot()
    report = {'url': args.url, 'steps': [], 'panel': {}, 'note': {}, 'births': [], 'safety': {}}
    page = None
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True, args=['--no-sandbox', '--mute-audio'])
            page = browser.new_page(viewport={'width': 1440, 'height': 900}, bypass_csp=True)
            page.goto('http://127.0.0.1:4700/?mute=1', wait_until='networkidle', timeout=90000)
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline:
                if page.evaluate('() => Boolean(window.galaxy && galaxy.ready)'):
                    break
                page.wait_for_timeout(100)
            page.evaluate('url => galaxy.runTeardown(url)', args.url)
            deadline = time.monotonic() + args.timeout
            seen_steps = []
            while time.monotonic() < deadline:
                state = page.evaluate('''() => ({
                  status: galaxy.teardown?.status || null,
                  steps: [...document.querySelectorAll('#td-steps .td-step')].map(node => ({
                    label: node.textContent, state: node.className
                  })),
                  fold: document.getElementById('td-fold').textContent
                })''')
                for step in state['steps']:
                    if step not in seen_steps:
                        seen_steps.append(step)
                if state['status'] in ('done', 'error', 'cancelled'):
                    break
                page.wait_for_timeout(250)
            if state.get('status') != 'done':
                raise AssertionError(f'Teardown did not finish: {state}')
            page.locator('#td-result').wait_for(state='visible', timeout=20000)
            page.wait_for_timeout(600)
            result = page.evaluate('() => galaxy.teardown.result')
            panel = page.evaluate('''() => ({
              site: document.getElementById('td-site').textContent,
              fold: document.getElementById('td-fold').textContent,
              chips: [...document.querySelectorAll('.td-chip')].map(node => node.textContent),
              totals: document.getElementById('td-totals').textContent,
              image: document.getElementById('td-snapshot').getAttribute('src'),
              imageLoaded: document.getElementById('td-snapshot').complete && document.getElementById('td-snapshot').naturalWidth > 0,
              steps: [...document.querySelectorAll('#td-steps .td-step')].map(node => node.textContent)
            })''')
            report['panel'] = panel
            labels = panel['steps']
            if labels != STEP_LABELS:
                raise AssertionError(f'Panel steps are wrong: {labels!r}')
            if not panel['fold'].startswith('Taken apart in'):
                raise AssertionError(f'Panel did not fold with elapsed time: {panel["fold"]!r}')
            if not panel['imageLoaded'] or not panel['image']:
                raise AssertionError('Panel snapshot did not load')
            if not (1 <= len(panel['chips']) <= 10):
                raise AssertionError(f'Panel stack chip count is outside 1–10: {len(panel["chips"])}')
            if not isinstance(result.get('spoken'), str) or not result['spoken'].strip():
                raise AssertionError('No spoken line returned')
            spoken_sentences = [s for s in re.split(r'(?<=[.!?])\s+', result['spoken'].strip()) if s.strip()]
            if not 2 <= len(spoken_sentences) <= 3:
                raise AssertionError(f'Spoken line is not two or three sentences: {result["spoken"]!r}')
            if 'http://' in result['spoken'] or 'https://' in result['spoken']:
                raise AssertionError('Spoken line contains a web address')
            if not isinstance(result.get('elapsed_seconds'), (int, float)) or result['elapsed_seconds'] <= 0:
                raise AssertionError('No positive elapsed time')
            note_name = result.get('note_name')
            if not note_name:
                raise AssertionError('No note name returned')
            note_path = TEARDOWNS / f'{note_name}.md'
            image_path = TEARDOWNS / 'assets' / f'{note_name}.png'
            markdown = note_path.read_text(encoding='utf-8')
            required = ['# Teardown ·', '## The answer', '## The stack', '## How the effect works',
                        '## What it loads', '## Rebuild it', "## What the evidence can't show", '## Evidence']
            missing = [section for section in required if section not in markdown]
            if missing:
                raise AssertionError(f'Note sections missing: {missing}')
            if not image_path.is_file() or image_path.read_bytes()[:8] != b'\x89PNG\r\n\x1a\n':
                raise AssertionError('Note snapshot is missing or not a PNG')
            births = result.get('births') or []
            labels_birth = [birth.get('node', {}).get('label') for birth in births]
            if labels_birth != ['REA', note_name]:
                raise AssertionError(f'Births are not REA-first plus the note: {labels_birth}')
            if births[0]['node']['id'] != 198 or births[1]['node']['id'] != 199:
                raise AssertionError(f'Birth ids are not the first free positions: {[b["node"]["id"] for b in births]}')
            if births[1].get('related') != 198:
                raise AssertionError('The teardown birth is not anchored to REA')
            time.sleep(0.4)
            episode_lines = EPISODES.read_text(encoding='utf-8').splitlines() if EPISODES.is_file() else []
            episode = next((json.loads(line) for line in reversed(episode_lines) if json.loads(line).get('job_id') == result.get('job_id')), None)
            if not episode or episode.get('status') != 'done' or episode.get('note_name') != note_name:
                raise AssertionError(f'Episode log did not record the completed teardown: {episode}')
            report['episode'] = episode
            report['note'] = {'name': note_name, 'sections': required, 'bytes': len(markdown)}
            report['births'] = [{'id': b['node']['id'], 'label': b['node']['label'], 'related': b.get('related')} for b in births]
            report['spoken'] = result['spoken']
            report['elapsed_seconds'] = result['elapsed_seconds']
            report['steps_seen'] = seen_steps
            page.evaluate('() => galaxy.closeTeardown()')
            browser.close()
            page = None
        no_chrome_left()
        crash_cleanup()
        report['safety']['traversal_note'] = expect_refusal('/teardown/note?name=../config.json')
        report['safety']['traversal_snapshot'] = expect_refusal('/teardown/snapshot?name=../config.json')
        report['safety']['chrome_clean'] = True
    finally:
        if page is not None:
            try:
                page.context.browser.close()
            except Exception:
                pass
        if not args.keep:
            snapshot.restore()
            # The server reads graph-data.js and /teardown/last from disk on each request.
            if not TEARDOWNS.exists() or not any(TEARDOWNS.glob('*.md')):
                report['restored_last_404'] = expect_refusal('/teardown/last')
            no_chrome_left()
    report['restored'] = not args.keep
    report_path = ROOT / 'artifacts/teardown-drill.json'
    report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps(report, ensure_ascii=False, indent=2))
    print('DRILL PASS; report', report_path)


if __name__ == '__main__':
    main()
