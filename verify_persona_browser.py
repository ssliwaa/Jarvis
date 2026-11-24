"""Live browser acceptance: boot/reload, graph-derived count, executed receipt, unknown."""
import json
from pathlib import Path

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parent
report = {}
with sync_playwright() as p:
    browser = p.chromium.launch(headless=True, args=['--enable-unsafe-swiftshader', '--use-angle=swiftshader'])
    page = browser.new_page(viewport={'width': 1440, 'height': 900})
    errors = []
    page.on('pageerror', lambda error: errors.append(str(error)))
    page.goto('http://127.0.0.1:4700/?mute=1', wait_until='networkidle', timeout=90000)
    page.wait_for_function('galaxy.ready && !!galaxy.voice')
    assert page.locator('#boot-greeting').inner_text() == 'Hello, sir.'
    assert page.locator('#node-count').inner_text() == str(page.evaluate('galaxy.nodes.length'))
    count = page.evaluate('galaxy.nodes.length')
    page.reload(wait_until='networkidle')
    page.wait_for_function('galaxy.ready && !!galaxy.voice')
    assert page.locator('#boot-greeting').inner_text() == 'Hello, sir.'
    assert page.locator('#node-count').inner_text() == str(count)
    report['boot_and_refresh'] = {'greeting': page.locator('#boot-greeting').inner_text(), 'graph_derived_count': count}
    questions = [
        'Explain the 80/20 running rule without pretending I enjoy restraint.',
        'Count my indexed notes, please.',
        'What number am I thinking of right now?',
    ]
    report['live_replies'] = []
    for question in questions:
        page.locator('#question').fill(question)
        with page.expect_response(lambda response: response.url.endswith('/chat'), timeout=195000) as pending:
            page.locator('#ask-button').click()
        response = pending.value
        payload = response.json()
        assert response.status == 200, payload
        page.wait_for_function('!galaxy.busy', timeout=10000)
        assert page.locator('#chat-answer').inner_text() == payload['answer']
        if 'receipt' in payload:
            assert payload['receipt']['status'] == 'completed'
            assert payload['receipt']['details']['count'] == count
            assert page.locator('#action-receipt').is_visible()
            assert payload['receipt']['id'] in page.locator('#action-receipt').inner_text()
            page.screenshot(path=str(ROOT / 'artifacts/butler-receipt.png'))
        elif question == questions[-1]:
            assert payload['nodes'] == [] and 'notes do not cover' in payload['answer']
            assert page.locator('#action-receipt').is_hidden()
        else:
            assert payload['nodes']
        report['live_replies'].append({'question': question, 'response': payload})
    assert not errors, errors
    report['page_errors'] = errors
    browser.close()
(ROOT / 'artifacts/persona-browser-verification.json').write_text(json.dumps(report, ensure_ascii=False, indent=2))
print(json.dumps(report, ensure_ascii=False, indent=2))
