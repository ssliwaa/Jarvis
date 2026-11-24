"""Exercise the real local server and Chromium. No credentials are printed."""
import http.client
import json
import tempfile
import threading
from pathlib import Path

from playwright.sync_api import sync_playwright

from server import create_server

ROOT = Path(__file__).resolve().parent
OUT = ROOT / 'artifacts'
OUT.mkdir(exist_ok=True)
report = {}


def request(path='/', payload=None, port=4700):
    connection = http.client.HTTPConnection('127.0.0.1', port, timeout=195)
    connection.request('POST' if payload is not None else 'GET', path,
                       body=json.dumps(payload) if payload is not None else None,
                       headers={'Content-Type': 'application/json'})
    response = connection.getresponse()
    status, raw = response.status, response.read()
    connection.close()
    return status, raw


static = {}
for path in ['/', '/index.html', '/app.js', '/style.css', '/graph-data.js',
             '/config.json', '/../config.json', '/%2e%2e/config.json', '/server.py']:
    status, raw = request(path)
    expected = 404 if path in ['/config.json', '/../config.json', '/%2e%2e/config.json', '/server.py'] else 200
    assert status == expected, (path, status, raw[:200])
    static[path] = status
report['static'] = static

# Exercise a real placeholder config without modifying the user's private config.
with tempfile.TemporaryDirectory(dir=__import__('os').environ.get('TMPDIR')) as temp:
    fixture = Path(temp)
    (fixture / 'config.json').write_text(json.dumps({'aOPENROUTER_API_KEY': 'PASTE_YOUR_OPENROUTER_API_KEY_HERE', 'model': 'openai/gpt-6.1-sol'}))
    (fixture / 'viewer').mkdir()
    (fixture / 'viewer/index.html').write_text('<title>Placeholder verification</title>')
    httpd = create_server(root=fixture, port=0, state_root=fixture / 'state',
                          enable_agent=False, enable_scheduler=False,
                          enable_memory_capture=False)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        status, raw = request('/chat', {'question': 'plan-treningowy-bieg'}, httpd.server_port)
        payload = json.loads(raw)
        assert status == 401 and payload['error']['code'] == 'INVALID_API_KEY', (status, payload)
        assert request('/', port=httpd.server_port)[0] == 200
        report['placeholder_key'] = {'status': status, 'body': payload, 'server_alive': True}
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join()

with sync_playwright() as p:
    browser = p.chromium.launch(headless=True, args=['--enable-unsafe-swiftshader', '--use-angle=swiftshader'])
    page = browser.new_page(viewport={'width': 1440, 'height': 900})
    errors, console_errors = [], []
    page.on('pageerror', lambda error: errors.append(str(error)))
    page.on('console', lambda message: console_errors.append(message.text) if message.type == 'error' else None)
    page.goto('http://127.0.0.1:4700/?mute=1', wait_until='networkidle', timeout=90000)
    page.wait_for_function('window.galaxy && (galaxy.ready || galaxy.error)', timeout=30000)
    state = page.evaluate('''() => ({ready:galaxy.ready,error:galaxy.error,nodes:galaxy.nodes.length,links:galaxy.links.length,sprites:galaxy.sprites.size,groups:galaxy.groups.length,stars:galaxy.graph?.scene().getObjectByName('orbit-starfield')?.geometry.attributes.position.count,calls:galaxy.graph?.renderer().info.render.calls})''')
    assert state['ready'] and state['sprites'] == 198 and state['stars'] == 1500, state
    page.wait_for_timeout(1800)
    page.screenshot(path=str(OUT / 'galaxy-desktop.png'))
    # Real canvas picking, not just direct function invocation.
    page.evaluate('if(galaxy.rotating) galaxy.toggleRotation()')
    chosen = page.evaluate('''() => {const n=galaxy.nodes.find(n=>{const p=galaxy.graph.graph2ScreenCoords(n.x,n.y,n.z);return p.x>430&&p.x<1000&&p.y>250&&p.y<600}); if(!n) return null;const p=galaxy.graph.graph2ScreenCoords(n.x,n.y,n.z);return {id:n.id,x:p.x,y:p.y}}''')
    assert chosen
    before = page.evaluate('galaxy.graph.cameraPosition()')
    page.mouse.click(chosen['x'], chosen['y'])
    page.wait_for_timeout(1600)
    picked = page.evaluate('({selected:galaxy.selectedId,neighbours:galaxy.neighbourIds.length,panel:!document.getElementById("note-panel").hidden,camera:galaxy.graph.cameraPosition()})')
    assert picked['panel'] and picked['selected'] is not None and picked['camera'] != before, picked
    page.screenshot(path=str(OUT / 'galaxy-selected.png'))
    page.evaluate('galaxy.resetView()')
    page.locator('#note-search').fill('plan-treningowy-bieg')
    page.locator('#note-search').press('Enter')
    assert page.locator('#note-title').inner_text() == 'plan-treningowy-bieg'
    assert page.evaluate('document.activeElement.id') == 'note-panel'
    viewports = []
    for width in (320, 768, 1024, 1440):
        page.set_viewport_size({'width': width, 'height': 900})
        page.evaluate('galaxy.resetView(); galaxy.selectNode(0)')
        page.wait_for_timeout(150)
        bounds = page.evaluate('''() => ({width:innerWidth,scrollWidth:document.documentElement.scrollWidth,chat:document.getElementById('chat-form').getBoundingClientRect().toJSON(),note:document.getElementById('note-panel').getBoundingClientRect().toJSON()})''')
        assert bounds['scrollWidth'] == width and bounds['chat']['x'] >= 0 and bounds['chat']['right'] <= width, bounds
        assert bounds['note']['x'] >= 0 and bounds['note']['right'] <= width, bounds
        viewports.append(width)
        if width == 320:
            page.screenshot(path=str(OUT / 'galaxy-mobile.png'))
    page.emulate_media(reduced_motion='reduce')
    page.wait_for_timeout(100)
    assert page.evaluate('galaxy.reducedMotion && !galaxy.rotating && !galaxy.graph.controls().autoRotate')
    assert not errors, errors
    # Live UI request reaches the actual configured provider, not a fabricated reply.
    page.evaluate('galaxy.resetView()')
    with page.expect_response(lambda response: response.url.endswith('/chat'), timeout=195000) as live_response:
        page.locator('#question').fill('Co notatka plan-treningowy-bieg mówi o zasadzie 80/20?')
        page.locator('#ask-button').click()
    response = live_response.value
    payload = response.json()
    page.wait_for_function('!galaxy.busy', timeout=10000)
    assert page.locator('#chat-answer').inner_text() == payload['answer']
    assert payload.get('nodes') is not None
    report['live_chat'] = {'status': response.status, 'body': payload}
    page.screenshot(path=str(OUT / 'galaxy-chat.png'))
    report['browser'] = {'state': state, 'canvas_pick': picked, 'viewports': viewports,
                         'keyboard_selection': True, 'reduced_motion': True, 'page_errors': errors,
                         'console_errors': console_errors}
    browser.close()

assert request('/')[0] == 200
report['server_alive_after_tests'] = True
(OUT / 'verification.json').write_text(json.dumps(report, ensure_ascii=False, indent=2))
print(json.dumps(report, ensure_ascii=False, indent=2))
