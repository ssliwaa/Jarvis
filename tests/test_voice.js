'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const sourcePath = path.join(__dirname, '../viewer/voice.js');
assert.ok(fs.existsSync(sourcePath), 'viewer/voice.js must implement browser-native voice');
const source = fs.readFileSync(sourcePath, 'utf8');

function harness(search = '', options = {}) {
  let now = 0, serial = 0;
  const timers = new Map(), listeners = new Map(), elements = new Map();
  class Element {
    constructor() { this.textContent = ''; this.value = ''; this.dataset = {}; this.listeners = {}; this.disabled = false; this.attrs = {}; this.style = { setProperty() {} }; }
    addEventListener(type, fn) { this.listeners[type] = fn; }
    setAttribute(key, value) { this.attrs[key] = String(value); }
  }
  const document = {
    hidden: false,
    getElementById(id) { if (!elements.has(id)) elements.set(id, new Element()); return elements.get(id); },
    addEventListener(type, fn) { if (!listeners.has(type)) listeners.set(type, []); listeners.get(type).push(fn); }
  };
  const spoken = [], submitted = [], interruptedListeners = [], submitLanguages = [];
  const storage = options.storage || new Map();
  const localStorage = {
    getItem: key => storage.has(key) ? storage.get(key) : null,
    setItem: (key, value) => storage.set(key, String(value)),
    removeItem: key => storage.delete(key),
  };
  const voices = options.voices || [{ name: 'American', lang: 'en-US' }, { name: 'British', lang: 'en-GB' }];
  const synth = { getVoices: () => voices, cancelCount: 0, cancel() { this.cancelCount++; },
    speak(utterance) { spoken.push(utterance); if (utterance.onstart) utterance.onstart(); }, addEventListener() {} };
  class Recognition {
    constructor() { context.recognition = this; }
    start() { this.started = (this.started || 0) + 1; if (this.onstart) this.onstart(); }
    stop() { this.stopped = true; if (this.onend) this.onend(); }
    abort() { this.stop(); }
  }
  const context = { document, GALAXY_PERSONA: { greeting: 'Hello, sir.' }, location: { search },
    navigator: { language: options.language || 'en-GB' }, URLSearchParams, localStorage,
    SpeechSynthesisUtterance: class { constructor(text) { this.text = text; } }, speechSynthesis: synth,
    webkitSpeechRecognition: options.unsupported ? undefined : Recognition,
    setTimeout(fn, delay) { const id = ++serial; timers.set(id, { at: now + delay, fn }); return id; },
    clearTimeout(id) { timers.delete(id); }, console };
  context.window = context;
  if (options.desktop) {
    context.jarvisDesktop = {
      onPushToTalk(callback) { context.desktopPushToTalk = callback; }
    };
  }
  vm.createContext(context);
  vm.runInContext(source, context);
  const voice = context.createGalaxyVoice({ submit: (text, language) => { submitted.push(text); submitLanguages.push(language); return true; }, interrupt: () => interruptedListeners.push(true) });
  function click() { for (const fn of listeners.get('click') || []) fn({ isTrusted: true }); }
  function press(type, event = {}) { for (const fn of listeners.get(type) || []) fn(event); }
  function advance(ms) { const end = now + ms; while (true) { const next = [...timers].filter(([, t]) => t.at <= end).sort((a, b) => a[1].at - b[1].at)[0]; if (!next) break; now = next[1].at; timers.delete(next[0]); next[1].fn(); } now = end; }
  function result(rows, index = 0) { const results = rows.map(([text, final]) => Object.assign([{ transcript: text }], { isFinal: final })); context.recognition.onresult({ resultIndex: index, results }); }
  return { voice, context, spoken, submitted, interrupted: interruptedListeners, submitLanguages, synth, elements, storage,
    click, press, advance, result };
}

const scenario = process.argv[2] || 'speaking';
if (scenario === 'speaking') {
  const h = harness();
  assert.equal(h.spoken.length, 0, 'never speak on load');
  h.voice.speak('An answer before interaction.');
  assert.equal(h.spoken.length, 0, 'programmatic answers cannot bypass activation');
  h.click();
  assert.equal(h.spoken.length, 1, 'first click synchronously unlocks pending speech');
  assert.equal(h.spoken[0].text, 'Hello, sir.', 'the boot greeting is always exactly one short line');
  assert.equal(h.spoken[0].voice.lang, 'en-GB');
  assert.match(h.elements.get('voice-status').textContent, /speaking/i);
  h.spoken[0].onend();
  assert.doesNotMatch(h.elements.get('voice-status').textContent, /speaking/i);
  h.click();
  assert.equal(h.spoken.length, 1, 'greeting fires once only');
  h.voice.speak('**Answer** from my notes [116].');
  assert.equal(h.spoken.length, 2);
  assert.equal(h.spoken[1].text, 'Answer from my notes .');
  h.voice.speak('See [W2] and https://example.com/x for details.');
  assert.equal(h.spoken.length, 3);
  assert.equal(h.spoken[2].text, 'See and link for details.',
    'web citations and URLs are not read aloud');
  const greet = harness(); greet.click();
  assert.equal(greet.spoken.length, 1, 'first click must speak a welcome even without pending answer');
  const mute = harness('?mute=1'); mute.click(); mute.voice.speak('Never say this');
  assert.equal(mute.spoken.length, 0, 'mute blocks welcome and direct speech');
  const muteAfter = harness(); muteAfter.click(); muteAfter.context.location.search = '?mute=1'; muteAfter.voice.speak('Never say this either');
  assert.equal(muteAfter.spoken.length, 1, 'mute is checked inside every speaking call');
  const delayed = harness('', { voices: [] }); delayed.click();
  assert.equal(delayed.spoken.length, 1, 'do not wait for async voices to miss the user gesture');
  assert.equal(delayed.spoken[0].lang, 'en-GB');
}
if (scenario === 'language') {
  const polish = harness('', { language: 'pl-PL' });
  assert.equal(polish.elements.get('voice-language').value, 'pl-PL',
    'a Polish system starts with Polish recognition');
  polish.elements.get('voice-language').value = 'en-GB';
  polish.elements.get('voice-language').listeners.change({ target: { value: 'en-GB' } });
  assert.equal(polish.storage.get('galaxy.lang'), 'en-GB', 'an explicit choice is persisted');
  const restored = harness('', { language: 'pl-PL', storage: polish.storage });
  assert.equal(restored.elements.get('voice-language').value, 'en-GB',
    'the stored recognition language survives a reload');
  const english = harness('', { language: 'en-US' });
  assert.equal(english.elements.get('voice-language').value, 'en-GB',
    'other locales keep the British recognition default');
}
if (scenario === 'listening') {
  assert.match(source, /const FINISH_MS = 900;/);
  const h = harness('?mute=1'); h.click(); h.voice.startListening();
  assert.equal(h.context.recognition.continuous, true);
  assert.equal(h.context.recognition.interimResults, true);
  assert.match(h.elements.get('voice-status').textContent, /listening/i);
  h.result([['What do my notes say', true]]);
  h.advance(600);
  assert.equal(h.submitted.length, 0, 'a mid-sentence final is buffered');
  h.result([['What do my notes say', true], ['about running?', true]], 1);
  h.advance(899);
  assert.equal(h.submitted.length, 0, 'new phrase restarts the whole finish window');
  h.advance(1);
  assert.deepEqual(h.submitted, ['What do my notes say about running?']);
  h.result([['What do my notes say', true], ['about running?', true]], 1);
  h.advance(900);
  assert.equal(h.submitted.length, 1, 'repeated final results must not duplicate phrases');
  const interim = harness('?mute=1'); interim.voice.startListening();
  interim.result([['Tell me', true]]); interim.advance(800);
  interim.context.recognition.onspeechstart();
  interim.advance(500);
  assert.equal(interim.submitted.length, 0, 'speech restarting cancels a pending final timer');
  interim.result([['Tell me', true], ['about', false]], 1); interim.advance(1200);
  assert.equal(interim.submitted.length, 0, 'interim speech cannot dispatch an old fragment');
  interim.result([['Tell me', true], ['about my notes', true]], 1); interim.advance(900);
  assert.deepEqual(interim.submitted, ['Tell me about my notes']);
  const ended = harness('?mute=1'); ended.voice.startListening();
  ended.result([['Keep this phrase', true]]); ended.advance(300);
  ended.context.recognition.onend(); ended.advance(599);
  assert.equal(ended.submitted.length, 0, 'recognition ending is not permission to flush early');
  ended.advance(1);
  assert.deepEqual(ended.submitted, ['Keep this phrase']);
  const speechEnd = harness('?mute=1'); speechEnd.voice.startListening();
  speechEnd.result([['Exactly one finish window', true]]); speechEnd.advance(400);
  speechEnd.context.recognition.onspeechend(); speechEnd.advance(500);
  assert.deepEqual(speechEnd.submitted, ['Exactly one finish window'], 'speechend without more words must not extend the timer');
}
if (scenario === 'routes') {
  const h = harness(); h.click(); h.voice.startListening();
  h.result([['An unfinished question', true]]); h.advance(200);
  h.result([['An unfinished question', true], ['stop', false]], 1);
  assert.equal(h.interrupted.length, 1, 'stop interrupts on an interim result, with no delay');
  assert.equal(h.voice.speaking, false);
  h.result([['An unfinished question', true], ['stop', true]], 1);
  assert.equal(h.interrupted.length, 1, 'interim plus final is one command');
  h.advance(2000);
  assert.equal(h.submitted.length, 0, 'stop discards the pending question, never contacts the brain');
  const wait = harness('?mute=1'); wait.voice.startListening();
  wait.result([['wait!', true]]);
  assert.equal(wait.interrupted.length, 1);
  assert.equal(wait.submitted.length, 0);
  let custom = '';
  wait.voice.routes.push({pattern: /^find (.+)$/i, handler: (text, match) => { custom = match[1]; }});
  wait.voice.dispatch('find Running');
  assert.equal(custom, 'Running', 'later extensions only append pattern/handler pairs');
  assert.equal(wait.submitted.length, 0, 'local route runs before brain dispatch');
  wait.voice.dispatch('What do my notes say?');
  assert.deepEqual(wait.submitted, ['What do my notes say?']);
}
if (scenario === 'errors') {
  const missing = harness('?mute=1', {unsupported:true});
  assert.equal(missing.elements.get('mic-button').disabled, true);
  assert.equal(missing.voice.startListening(), false);
  assert.match(missing.elements.get('voice-status').textContent, /unavailable/i);
  const denied = harness('?mute=1'); denied.voice.startListening();
  denied.result([['Unfinished', true]]);
  denied.context.recognition.onerror({error:'not-allowed'});
  denied.context.recognition.onend(); denied.advance(2000);
  assert.equal(denied.submitted.length, 0);
  assert.match(denied.elements.get('voice-status').textContent, /permission denied/i);
  assert.equal(denied.elements.get('mic-button').attrs['aria-pressed'], 'false');
  const status = harness('?mute=1'); status.voice.setThinking(true);
  assert.match(status.elements.get('voice-status').textContent, /thinking/i);
  status.voice.setThinking(false);
  assert.doesNotMatch(status.elements.get('voice-status').textContent, /thinking/i);
}
if (scenario === 'addresses') {
  const h = harness('?mute=1');
  const cases = [
    ['igloo dot inc', 'igloo.inc'],
    ['stripe.com slash pricing', 'stripe.com/pricing'],
    ['localhost:5001', 'localhost:5001'],
    ['make it pop', null],
    ['wikipedia.org', 'wikipedia.org'],
    ['https colon slash slash example dot com', 'https://example.com'],
  ];
  for (const [spoken, expected] of cases) {
    assert.equal(h.voice.parseAddress(spoken), expected, spoken);
  }
  console.log('Voice addresses: passed');
}
if (scenario === 'teardown-routes') {
  const h = harness('?mute=1');
  const cases = [
    ['reverse engineer igloo dot inc', true, 'site', 'igloo.inc'],
    ['tear down linear.app', true, 'site', 'linear.app'],
    ['how does stripe.com do that', true, 'site', 'stripe.com'],
    ['what is example.com built with', true, 'site', 'example.com'],
    ['reverse engineer this site', true, 'site', 'this'],
    ['how does this page work', true, 'site', 'this'],
    ['tear down the old shed', false, null, null],
    ['how should I reverse engineer my pricing', false, null, null],
    ["reverse engineer Stripe's homepage", false, null, null],
    ['show me the last teardown', true, 'last', null],
    ['open the full teardown', true, 'open', null],
    ['cancel the teardown', true, 'cancel', null],
  ];
  for (const [sentence, triggered, route, site] of cases) {
    const result = h.voice.inspect(sentence);
    assert.equal(result.triggered, triggered, sentence);
    assert.equal(result.route, route, sentence);
    if (site) assert.equal(result.site, site, sentence);
  }
  assert.equal(h.voice.inspect('close the teardown').route, 'close');
  assert.equal(h.voice.inspect('stop the teardown').route, 'cancel');
  assert.equal(h.voice.inspect('localhost colon 4700').triggered, false);
  assert.equal(h.submitted.length, 0, 'inspection must not contact the brain');
}
if (scenario === 'echo') {
  const h = harness(); h.click(); h.voice.startListening();
  h.voice.speak('The notes say the finish window is nine hundred milliseconds.');
  h.result([['The notes say the finish window is nine hundred milliseconds', true]]);
  h.advance(2000);
  assert.equal(h.submitted.length, 0, 'the assistant must not answer its own spoken sentence');
  h.result([['The notes say the finish window is nine hundred milliseconds', true], ['What about the running plan?', true]], 1);
  h.advance(900);
  assert.deepEqual(h.submitted, ['What about the running plan?'], 'a genuinely different question still passes');
  const tail = harness(); tail.click(); tail.voice.startListening();
  tail.voice.speak('A short answer.');
  tail.spoken[1].onend();
  tail.result([['A short answer', true]]);
  tail.advance(1000);
  assert.equal(tail.submitted.length, 0, 'the echo tail remains guarded after speech ends');
  const interrupt = harness(); interrupt.click(); interrupt.voice.startListening();
  interrupt.voice.speak('The notes say something.');
  interrupt.result([['stop', false]], 0);
  assert.equal(interrupt.interrupted.length, 1, 'a short user interrupt survives the echo guard');
  interrupt.result([['stop', false], ['The notes say something', true]], 1);
  interrupt.advance(1000);
  assert.equal(interrupt.submitted.length, 0);
}
if (scenario === 'parity') {
  const h = harness({}); h.click();
  h.elements.get('voice-output').value = 'British';
  h.voice.speak('Choose the British voice.');
  assert.equal(h.spoken[1].voice.name, 'British', 'the selected voice overrides automatic choice');

  const hearing = harness('', { voices: [{ name: 'Polish', lang: 'pl-PL' }, { name: 'British', lang: 'en-GB' }] });
  hearing.elements.get('voice-language').value = 'pl-PL';
  hearing.click();
  hearing.voice.speak('This answer is in English.');
  assert.equal(hearing.spoken[1].voice.name, 'British', 'Auto voice must not follow the hearing language');

  const variant = harness('', { voices: [
    { name: 'English (Great Britain)+Demonic espeak-ng', lang: 'en-GB' },
    { name: 'British', lang: 'en-GB' }
  ] });
  variant.click();
  variant.voice.speak('Keep the base voice.');
  assert.equal(variant.spoken[1].voice.name, 'British', 'espeak-ng variants must not be auto-selected');

  const ptt = harness(); ptt.click();
  const down = { ctrlKey: true, code: 'Space', repeat: false, target: { tagName: 'BODY' }, preventDefault() {} };
  const up = { ctrlKey: false, code: 'Space', key: ' ', target: { tagName: 'BODY' }, preventDefault() {} };
  ptt.press('keydown', down);
  assert.equal(ptt.voice.listening, true, 'Ctrl+Space starts push-to-talk');
  ptt.result([['Push to talk question', true]]);
  ptt.press('keyup', up);
  ptt.advance(900);
  assert.deepEqual(ptt.submitted, ['Push to talk question'], 'PTT release still delivers the final phrase');
  assert.equal(ptt.voice.listening, false, 'PTT release stops capture');

  const ignored = harness(); ignored.click();
  ignored.press('keydown', { ...down, target: { tagName: 'INPUT' } });
  assert.equal(ignored.voice.listening, false, 'PTT must not hijack typing in an input');
}
if (scenario === 'reply-language') {
  // The selected output voice — not the microphone — decides the reply
  // language: an English voice earns English answers (the model translates
  // Polish note content), a Polish voice keeps Polish.
  const polishMicEnglishVoice = harness();
  polishMicEnglishVoice.click();
  polishMicEnglishVoice.elements.get('voice-language').value = 'pl-PL';
  assert.ok(polishMicEnglishVoice.voice.dispatch('Jaki jest mój plan treningowy?'),
    'dispatch passes the transcript on');
  assert.deepEqual(polishMicEnglishVoice.submitted, ['Jaki jest mój plan treningowy?']);
  assert.deepEqual(polishMicEnglishVoice.submitLanguages, ['en'],
    'a Polish microphone with the default British voice earns an English answer');

  const polishVoice = harness('', { voices: [{ name: 'Marek', lang: 'pl-PL' }, { name: 'British', lang: 'en-GB' }] });
  polishVoice.click();
  polishVoice.elements.get('voice-language').value = 'en-GB';
  polishVoice.elements.get('voice-output').value = 'edge:pl-PL-ZofiaNeural';
  polishVoice.voice.dispatch('Keep this one Polish');
  assert.deepEqual(polishVoice.submitLanguages, ['pl'],
    'an explicit Polish Edge voice keeps the Polish reply');

  const browserPolish = harness('', { voices: [{ name: 'Marek', lang: 'pl-PL' }, { name: 'British', lang: 'en-GB' }] });
  browserPolish.click();
  browserPolish.elements.get('voice-output').value = 'browser:Marek';
  browserPolish.voice.dispatch('Rozmawiaj po polsku');
  assert.deepEqual(browserPolish.submitLanguages, ['pl'], 'a Polish browser voice also keeps Polish');

  const browserAuto = harness();
  browserAuto.click();
  browserAuto.elements.get('voice-output').value = 'browser:auto';
  browserAuto.voice.dispatch('Summarize my training plan');
  assert.deepEqual(browserAuto.submitLanguages, ['en'], 'browser Auto prefers British English');

  const fromStore = harness('', {
    storage: new Map([['galaxy.voice', 'edge:pl-PL-MarekNeural']]),
  });
  fromStore.click();
  fromStore.voice.dispatch('Niech to będzie po polsku');
  assert.deepEqual(fromStore.submitLanguages, ['pl'], 'a stored voice wins when the picker is empty');
}
if (scenario === 'desktop') {
  const toggle = harness('?mute=1', { desktop: true });
  assert.equal(typeof toggle.context.desktopPushToTalk, 'function');
  toggle.context.desktopPushToTalk();
  assert.equal(toggle.voice.listening, true, 'the desktop talk key starts listening');
  toggle.context.desktopPushToTalk();
  assert.equal(toggle.voice.listening, false, 'the second tap stops capture');
  const barge = harness('', { desktop: true });
  barge.click();
  barge.voice.speak('A long answer that should be interrupted.');
  assert.equal(barge.voice.speaking, true);
  barge.context.desktopPushToTalk();
  assert.equal(barge.voice.speaking, false, 'the talk key stops the answer first');
  assert.equal(barge.voice.listening, true, 'and immediately listens for the new question');
}
if (scenario === 'wake-contract') {
  const h = harness('?mute=1');
  assert.equal(typeof h.voice.wakeRecord, 'function', 'wake trigger starts the same voice recorder');
  assert.equal(typeof h.voice.thinking, 'boolean');
}
console.log(`Voice ${scenario}: passed`);
