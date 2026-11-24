"""Real Chromium UI with deterministic speech doubles; never emits actual audio.

This verifies browser wiring, not a physical microphone or audible OS voice.
"""
import json
import time
from pathlib import Path
from urllib.request import urlopen

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parent
OUT = ROOT / 'artifacts'
OUT.mkdir(exist_ok=True)
URL = 'http://127.0.0.1:4700/'
DOUBLES = r"""
window.__voiceTest = { spoken: [], canceled: 0 };
const fakeSynthesis = {
 getVoices: () => [{name:'US test voice',lang:'en-US'},{name:'UK test voice',lang:'en-GB'}],
 cancel(){window.__voiceTest.canceled++;},
 speak(utterance){window.__voiceTest.spoken.push({text:utterance.text,lang:utterance.lang}); window.__voiceTest.utterance=utterance; utterance.onstart?.();}
};
Object.defineProperty(window,'speechSynthesis',{value:fakeSynthesis,configurable:true});
window.SpeechSynthesisUtterance = class {constructor(text){this.text=text;}};
window.webkitSpeechRecognition = class {
 constructor(){window.__voiceTest.recognition=this;this.results=[];}
 start(){this.results=[];this.onstart?.();}
 abort(){this.onend?.();}
 emit(text,final=true){let i=this.results.length;if(i&&!this.results[i-1].isFinal)i--;this.results[i]=Object.assign([{transcript:text}],{isFinal:final});this.onresult({resultIndex:i,results:this.results});}
};
"""


def attach(context):
    context.add_init_script(DOUBLES)
    page = context.new_page()
    errors = []
    page.on('pageerror', lambda error: errors.append(str(error)))
    pending, bodies = [], []
    def intercept(route):
        bodies.append(route.request.post_data_json)
        pending.append(route)
    page.route('**/chat', intercept)
    return page, errors, pending, bodies


def emit(page, text, final=True):
    page.evaluate('([text,final]) => __voiceTest.recognition.emit(text,final)', [text, final])


def settle(page):
    page.wait_for_timeout(150)


def wait_for(page, predicate, timeout=5.0):
    """Poll a Python-side condition without depending on the page's fake clock."""
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        try:
            if predicate():
                return
        except Exception:
            pass
        page.wait_for_timeout(50)
    assert predicate()


def reply(route):
    route.fulfill(status=200, content_type='application/json', body=json.dumps({
        'answer': 'A browser voice test answer [0]. This response is a test fixture [0].', 'nodes': [0]}))


report = {'provider_responses': 'Explicit test fixtures; no claim of physical audio or real recognition.'}
# Bounded like every other verify_* precheck (teardown drill uses 20s):
# a silent local hang must fail this acceptance script fast, not stall it.
with urlopen(URL, timeout=20) as response:
    policy = response.headers['Permissions-Policy']
    assert 'microphone=(self)' in policy
    report['permissions_policy'] = policy

with sync_playwright() as p:
    browser = p.chromium.launch(headless=True, args=['--enable-unsafe-swiftshader', '--use-angle=swiftshader'])
    context = browser.new_context(viewport={'width': 1440, 'height': 900})
    page, errors, pending, bodies = attach(context)
    page.goto(URL, wait_until='networkidle', timeout=90000)
    page.wait_for_function('galaxy.ready && !!galaxy.voice')
    assert page.locator('#boot-greeting').inner_text() == 'Hello, sir.'
    assert page.locator('#node-count').inner_text() == str(page.evaluate('galaxy.nodes.length'))
    assert page.locator('#voice-output').count() == 1
    assert page.locator('#mic-level').count() == 1
    assert page.locator('.ptt-hint').count() == 1
    assert page.evaluate("galaxy.voice.chooseVoice().name") == 'UK test voice'
    # This acceptance suite exercises the browser fallback; Edge's real endpoint
    # is covered by preflight's live `tts` check and the Edge voice test.
    page.evaluate("document.getElementById('voice-output').value = 'browser:auto'")
    assert page.evaluate('__voiceTest.spoken.length') == 0
    page.locator('#note-search').click()
    assert page.evaluate('__voiceTest.spoken.length') == 1
    assert page.evaluate('__voiceTest.spoken[0].text') == 'Hello, sir.'
    assert page.evaluate('__voiceTest.spoken[0].lang') == 'en-GB'
    assert 'Speaking' in page.locator('#voice-status').inner_text()
    page.evaluate('__voiceTest.utterance.onend()')
    page.locator('#mic-button').click()
    assert page.locator('#mic-button').get_attribute('aria-pressed') == 'true'
    assert 'Listening' in page.locator('#voice-status').inner_text()
    page.clock.install()
    # pause_at cannot move backwards; evaluate a point safely in the future.
    page.clock.pause_at(page.evaluate('new Date(Date.now() + 1000).toISOString()'))
    emit(page, 'What do my notes say')
    page.clock.fast_forward(600)
    assert not bodies
    emit(page, 'about running training?')
    page.clock.fast_forward(899)
    assert not bodies
    page.clock.fast_forward(1)
    settle(page)
    wait_for(page, lambda: bool(bodies))
    assert bodies == [{'question': 'What do my notes say about running training?'}], bodies
    assert 'Thinking' in page.locator('#voice-status').inner_text()
    reply(pending.pop(0))
    settle(page)
    wait_for(page, lambda: not page.evaluate('galaxy.busy'))
    wait_for(page, lambda: 'Speaking' in page.locator('#voice-status').inner_text())
    wait_for(page, lambda: page.evaluate('__voiceTest.spoken.length') == 2)
    emit(page, 'stop', False)
    assert not page.evaluate('galaxy.voice.speaking')
    emit(page, 'stop', True)
    page.clock.fast_forward(2000)
    settle(page)
    assert len(bodies) == 1
    page.evaluate("galaxy.voice.routes.push({pattern:/^show atlas$/i,handler:()=>{window.__localRouteWorked=true;}}); galaxy.askQuestion('show atlas')")
    assert page.evaluate('window.__localRouteWorked')
    assert len(bodies) == 1
    page.locator('#question').fill('Another question')
    page.locator("#question").press("Enter")
    settle(page)
    wait_for(page, lambda: page.evaluate('galaxy.busy'))
    emit(page, "wait", False)
    settle(page)
    wait_for(page, lambda: not page.evaluate('galaxy.busy'))
    assert not page.evaluate('galaxy.voice.speaking')
    wait_for(page, lambda: page.locator('#chat-answer').inner_text() == 'Answer interrupted.')
    # A late response must never restart speech or replace the interrupted UI.
    try:
        reply(pending.pop(0))
    except Exception:
        pass  # The browser may already have canceled the intercepted network request.
    settle(page)
    wait_for(page, lambda: page.evaluate('__voiceTest.spoken.length') == 2)
    wait_for(page, lambda: page.locator('#chat-answer').inner_text() == 'Answer interrupted.')
    emit(page, 'wait', True)
    page.screenshot(path=str(OUT / 'voice-desktop.png'))
    widths = []
    for width in (320, 768, 1024, 1440):
        page.set_viewport_size({'width': width, 'height': 900})
        bounds = page.evaluate('''() => ({width:innerWidth,scroll:document.documentElement.scrollWidth,mic:document.getElementById('mic-button').getBoundingClientRect().toJSON(),dock:document.getElementById('chat-dock').getBoundingClientRect().toJSON()})''')
        assert bounds['scroll'] == width and bounds['mic']['left'] >= 0 and bounds['mic']['right'] <= width, bounds
        assert bounds['dock']['bottom'] <= 900 and bounds['dock']['left'] >= 0, bounds
        widths.append(width)
        if width == 320:
            page.screenshot(path=str(OUT / 'voice-mobile.png'))
    assert not errors, errors
    report['browser_events'] = {'first_click_only': True, 'british_preference': True,
        'one_combined_request_after_600ms_pause_plus_900ms_finish': True,
        'interim_stop_instant': True, 'wait_aborts_thinking_and_suppresses_late_speech': True,
        'custom_route_before_brain': True, 'status_phases': True, 'viewport_widths': widths, 'page_errors': errors}
    context.close()

    muted_context = browser.new_context()
    muted, muted_errors, muted_pending, muted_bodies = attach(muted_context)
    muted.goto(URL + '?mute=1', wait_until='networkidle', timeout=90000)
    muted.wait_for_function('!!galaxy.voice')
    muted.clock.install()
    muted.locator('#mic-button').click()
    muted.evaluate("galaxy.voice.speak('This must never be spoken')")
    emit(muted, 'A muted voice question')
    muted.clock.fast_forward(1000)
    settle(muted)
    wait_for(muted, lambda: len(muted_bodies) == 1)
    reply(muted_pending.pop(0))
    settle(muted)
    wait_for(muted, lambda: muted.locator('#chat-answer').inner_text().startswith('A browser voice test answer'))
    assert muted.evaluate('__voiceTest.spoken.length') == 0
    assert 'Muted' in muted.locator('#voice-status').inner_text()
    assert not muted_errors
    report['muted_tab'] = {'speech_calls': 0, 'greeting_direct_and_answer_blocked': True, 'microphone_chat_still_works': True}
    muted_context.close()

    # Native capability inventory, without opening a mic or ever emitting audio.
    native = browser.new_page()
    native.goto(URL + '?mute=1', wait_until='networkidle', timeout=90000)
    native.wait_for_function('!!galaxy.voice')
    report['native_headless_capabilities'] = native.evaluate('''() => ({synthesis:'speechSynthesis' in window,recognition:typeof webkitSpeechRecognition==='function',voices:speechSynthesis.getVoices().map(v=>v.lang),secureContext:isSecureContext,microphonePolicy:document.featurePolicy?.allowsFeature('microphone')})''')
    assert report['native_headless_capabilities']['microphonePolicy'] is True
    browser.close()

(OUT / 'voice-verification.json').write_text(json.dumps(report, indent=2))
print(json.dumps(report, indent=2))
