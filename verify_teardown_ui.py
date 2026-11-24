#!/usr/bin/env python3
"""Live voice-route and teardown-card check at 1440x900.

By default this reads the newest teardown note on disk. Pass --run URL to run
one real headless teardown through the viewer first. The browser is muted with
?mute=1; no speech is emitted.
"""
from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parent
SENTENCES = [
    'reverse engineer igloo dot inc',
    'tear down linear.app',
    'how does stripe.com do that',
    'what is example.com built with',
    'reverse engineer this site',
    'how does this page work',
    'tear down the old shed',
    'how should I reverse engineer my pricing',
    "reverse engineer Stripe's homepage",
    'show me the last teardown',
    'open the full teardown',
    'cancel the teardown',
]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', metavar='URL', help='run one real teardown through the viewer')
    parser.add_argument('--base', default='http://127.0.0.1:4700')
    parser.add_argument('--timeout', type=int, default=360)
    args = parser.parse_args()
    output = {'routes': [], 'panel': None, 'reader': None, 'screenshots': []}
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True, args=['--no-sandbox', '--mute-audio'])
        page = browser.new_page(viewport={'width': 1440, 'height': 900}, bypass_csp=True)
        errors, responses = [], []
        page.on('pageerror', lambda error: errors.append(str(error)))
        page.on('response', lambda response: responses.append(response.status))
        page.goto(args.base + '/?mute=1', wait_until='networkidle', timeout=90000)
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            if page.evaluate('() => Boolean(window.galaxy && galaxy.ready)'):
                break
            page.wait_for_timeout(100)
        else:
            raise SystemExit('viewer did not become ready')
        for sentence in SENTENCES:
            result = page.evaluate('sentence => galaxy.voice.inspect(sentence)', sentence)
            output['routes'].append({'sentence': sentence, **result})
        if page.evaluate('() => galaxy.voice.speak("Muted UI check.")') is not False:
            raise SystemExit('?mute=1 did not refuse speech')
        if args.run:
            page.evaluate('url => galaxy.runTeardown(url)', args.run)
            deadline = time.monotonic() + args.timeout
            while time.monotonic() < deadline:
                state = page.evaluate('() => galaxy.teardown?.status || null')
                if state in ('done', 'error', 'cancelled'):
                    break
                page.wait_for_timeout(1000)
            if state != 'done':
                raise SystemExit(f'teardown did not finish: {state}')
        else:
            page.evaluate('() => galaxy.showLastTeardown()')
        page.locator('#td-result').wait_for(state='visible', timeout=30000)
        page.wait_for_timeout(700)
        panel_path = ROOT / 'artifacts/teardown-panel-1440x900.png'
        page.locator('#teardown-panel').screenshot(path=str(panel_path))
        page_path = ROOT / 'artifacts/teardown-page-1440x900.png'
        page.screenshot(path=str(page_path), full_page=False)
        output['screenshots'].extend([str(panel_path), str(page_path)])
        if args.run:
            # The answer card can be closed by the user; the teardown card keeps
            # its full result and must reveal the snapshot once space permits.
            page.locator('#close-answer').click()
            page.wait_for_timeout(500)
            live_path = ROOT / 'artifacts/teardown-panel-1440x900-live.png'
            page.locator('#teardown-panel').screenshot(path=str(live_path))
            output['screenshots'].append(str(live_path))
            page.screenshot(path=str(ROOT / 'artifacts/teardown-page-1440x900-live.png'), full_page=False)
            output['screenshots'].append(str(ROOT / 'artifacts/teardown-page-1440x900-live.png'))
        output['panel'] = page.evaluate('''() => {
          const panel = document.getElementById('teardown-panel');
          const p = panel.getBoundingClientRect();
          const atlas = document.getElementById('atlas-panel').getBoundingClientRect();
          const note = document.getElementById('note-panel');
          const n = note.hidden ? null : note.getBoundingClientRect();
          const dock = document.getElementById('chat-dock').getBoundingClientRect();
          return {hidden: panel.hidden, site: document.getElementById('td-site').textContent,
            fold: document.getElementById('td-fold').textContent,
            chips: [...document.querySelectorAll('.td-chip')].map(node => node.textContent),
            totals: document.getElementById('td-totals').textContent,
            image: document.getElementById('td-snapshot').getAttribute('src'),
            imageLoaded: document.getElementById('td-snapshot').complete && document.getElementById('td-snapshot').naturalWidth > 0,
            steps: document.querySelectorAll('#td-steps .td-step').length,
            readDisabled: document.getElementById('td-read').disabled,
            rect: [p.left, p.top, p.right, p.bottom],
            atlasRight: atlas.right, noteLeft: n ? n.left : null, dockTop: dock.top,
            spoken: galaxy.teardown?.result?.spoken || null};
        }''')
        if output['panel']['hidden'] or not output['panel']['imageLoaded']:
            raise SystemExit('panel is not showing a loaded snapshot')
        page.locator('#td-read').click()
        page.locator('#td-reader:not([hidden])').wait_for(state='visible', timeout=10000)
        reader_path = ROOT / 'artifacts/teardown-reader-1440x900.png'
        page.screenshot(path=str(reader_path), full_page=False)
        output['screenshots'].append(str(reader_path))
        output['reader'] = page.evaluate('''() => ({title:document.getElementById('td-reader-title').textContent,
          text:document.getElementById('td-reader-body').innerText,
          images:document.querySelectorAll('#td-reader-body img').length,
          obsidian:document.getElementById('td-obsidian').getAttribute('href')})''')
        if 'snapshot:' in output['reader']['text'] or 'created:' in output['reader']['text']:
            raise SystemExit('reader leaked front-matter/file paths')
        page.locator('#td-reader-close').click()
        output['errors'] = errors
        output['non_2xx_responses'] = sorted({status for status in responses if status >= 300})
        browser.close()
    report = ROOT / 'artifacts/teardown-ui-verification.json'
    report.write_text(json.dumps(output, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps(output, ensure_ascii=False, indent=2))
    print('REPORT', report)


if __name__ == '__main__':
    main()
