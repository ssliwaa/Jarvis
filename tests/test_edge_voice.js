'use strict';
// Offline browser-side tests for the Edge TTS path. No network and no audio.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const source = fs.readFileSync(path.join(__dirname, '../viewer/voice.js'), 'utf8');

function harness(search = '') {
  const elements = new Map();
  const listeners = new Map();
  const spoken = [];
  const fetches = [];
  const audios = [];
  let pendingFetch = null;

  class Element {
    constructor() { this.textContent = ''; this.value = ''; this.dataset = {}; this.attrs = {}; this.style = { setProperty() {} }; }
    addEventListener() {}
    setAttribute(key, value) { this.attrs[key] = String(value); }
  }
  const document = {
    hidden: false,
    getElementById(id) { if (!elements.has(id)) elements.set(id, new Element()); return elements.get(id); },
    addEventListener(type, fn) { if (!listeners.has(type)) listeners.set(type, []); listeners.get(type).push(fn); }
  };
  const synth = {
    getVoices: () => [{ name: 'US test voice', lang: 'en-US' }, { name: 'UK test voice', lang: 'en-GB' }],
    cancel() {},
    speak(utterance) { spoken.push(utterance); utterance.onstart?.(); },
    addEventListener() {}
  };
  class FakeAudio {
    constructor(src) { this.src = src; this.paused = false; audios.push(this); }
    play() { this.paused = false; return Promise.resolve(); }
    pause() { this.paused = true; }
    removeAttribute() {}
    load() {}
  }
  const context = {
    document,
    GALAXY_PERSONA: { greeting: 'Hello, sir.' },
    location: { search },
    navigator: { language: 'en-GB' },
    URLSearchParams,
    SpeechSynthesisUtterance: class { constructor(text) { this.text = text; } },
    speechSynthesis: synth,
    webkitSpeechRecognition: undefined,
    Audio: FakeAudio,
    URL: { createObjectURL: () => 'blob:edge-test', revokeObjectURL() {} },
    setTimeout(fn, ms) { return global.setTimeout(fn, ms); },
    clearTimeout(id) { global.clearTimeout(id); },
    console,
    fetch(url, options = {}) {
      // voice.js probes /voice/status during construction; it has no body and
      // expects JSON, unlike the /tts call this harness is about.
      if (url === '/voice/status') {
        return Promise.resolve({ ok: true, status: 200, json: async () => ({ available: false }) });
      }
      fetches.push({ url, options, body: typeof options.body === 'string' ? JSON.parse(options.body) : null });
      if (pendingFetch) return pendingFetch;
      return Promise.resolve({ ok: true, status: 200, blob: async () => ({ size: 4096 }) });
    }
  };
  context.window = context;
  vm.createContext(context);
  vm.runInContext(source, context);
  const voice = context.createGalaxyVoice({ submit: () => true, interrupt: () => {} });
  function click() { for (const fn of listeners.get('click') || []) fn({ isTrusted: true }); }
  return { voice, elements, context, click, spoken, fetches, audios, synth };
}

async function settle() { await new Promise(resolve => setTimeout(resolve, 20)); }

(async () => {
  const h = harness();
  h.elements.get('voice-output').value = 'edge:en-GB-RyanNeural';
  h.click();
  await settle();
  assert.equal(h.fetches.length, 1, 'the greeting must request Edge audio');
  assert.deepEqual(h.fetches[0].body, { text: 'Hello, sir.', voice: 'en-GB-RyanNeural' });
  assert.equal(h.audios.length, 1, 'the returned blob must become one audio element');
  assert.equal(h.audios[0].src, 'blob:edge-test');
  assert.equal(h.audios[0].paused, false, 'Edge audio must start playing');
  assert.match(h.elements.get('voice-status').textContent, /Speaking/);
  h.audios[0].onended();
  assert.doesNotMatch(h.elements.get('voice-status').textContent, /Speaking/);

  const mute = harness('?mute=1');
  mute.elements.get('voice-output').value = 'edge:en-GB-RyanNeural';
  mute.click();
  await settle();
  assert.equal(mute.fetches.length, 0, 'mute must prevent the Edge request');
  assert.equal(mute.spoken.length, 0, 'mute must prevent browser fallback too');

  const fallback = harness();
  fallback.elements.get('voice-output').value = 'edge:en-GB-RyanNeural';
  fallback.context.fetch = () => Promise.resolve({ ok: false, status: 503, blob: async () => ({ size: 0 }) });
  fallback.click();
  await settle();
  assert.equal(fallback.spoken.length, 1, 'a failed Edge request must fall back to the browser voice');
  assert.equal(fallback.spoken[0].text, 'Hello, sir.');

  const stopped = harness();
  stopped.elements.get('voice-output').value = 'edge:en-GB-RyanNeural';
  let release;
  stopped.context.fetch = () => new Promise(resolve => { release = resolve; });
  stopped.click();
  stopped.voice.stopSpeaking();
  release({ ok: true, status: 200, blob: async () => ({ size: 4096 }) });
  await settle();
  assert.equal(stopped.audios.length, 0, 'a stopped Edge request must not play late audio');

  // A long answer is synthesized sentence by sentence: the first audio starts
  // while the next sentence is still being fetched.
  const multi = harness();
  multi.elements.get('voice-output').value = 'edge:en-GB-RyanNeural';
  multi.click();
  await settle();
  multi.audios[0].onended();
  await settle();
  assert.equal(multi.fetches.length, 1);
  assert.ok(multi.voice.speak('First sentence. Second sentence.'));
  await settle();
  assert.equal(multi.fetches.length, 3, 'both sentences are fetched up front');
  assert.deepEqual(multi.fetches.slice(1).map(item => item.body.text),
    ['First sentence.', 'Second sentence.']);
  assert.equal(multi.audios.length, 2, 'only the first chunk starts immediately');
  assert.equal(multi.audios[1].paused, false);
  multi.audios[1].onended();
  await settle();
  assert.equal(multi.audios.length, 3, 'the second chunk plays after the first ends');
  assert.equal(multi.audios[2].paused, false);
  multi.audios[2].onended();
  await settle();
  assert.doesNotMatch(multi.elements.get('voice-status').textContent, /Speaking/);

  // Early speech during /chat/stream: a complete sentence is spoken before the
  // final answer exists; finishStream appends only the tail.
  const stream = harness();
  stream.elements.get('voice-output').value = 'edge:en-GB-RyanNeural';
  stream.click();
  await settle();
  stream.audios[0].onended();
  await settle();
  assert.equal(stream.voice.speakStream('The first sentence is ready. And the second'), true);
  await settle();
  assert.equal(stream.fetches.length, 2, 'the streamed sentence is synthesized early');
  assert.equal(stream.fetches[1].body.text, 'The first sentence is ready.');
  assert.equal(stream.audios.length, 2, 'early speech starts before the final answer');
  assert.ok(stream.voice.finishStream('The first sentence is ready. And the second is done.'));
  await settle();
  assert.equal(stream.fetches.length, 3, 'the final answer contributes only its tail');
  assert.equal(stream.fetches[2].body.text, 'And the second is done.');
  stream.audios[1].onended();
  await settle();
  assert.equal(stream.audios.length, 3);
  stream.audios[2].onended();
  await settle();

  // A Polish stream bound for an English voice is held for the server's
  // translation instead of being spoken with English phonetics.
  const held = harness();
  held.elements.get('voice-output').value = 'edge:en-GB-RyanNeural';
  held.click();
  await settle();
  held.audios[0].onended();
  await settle();
  assert.equal(held.voice.speakStream('Skrócenie Lorenza to skrócenie długości obiektu.'), false);
  await settle();
  assert.equal(held.fetches.length, 1, 'Polish text is not synthesized for an English voice');
  assert.ok(held.voice.finishStream('Lorentz contraction is the shortening of a moving object.'));
  await settle();
  assert.equal(held.fetches.length, 2, 'the translated final answer is synthesized instead');
  assert.equal(held.fetches[1].body.text,
    'Lorentz contraction is the shortening of a moving object.');

  console.log('Edge voice: passed');
})().catch(error => { console.error(error); process.exit(1); });
