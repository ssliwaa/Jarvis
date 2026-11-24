'use strict';
const assert = require('node:assert/strict');
const vm = require('node:vm');
const fs = require('node:fs');
const path = require('node:path');

const root = path.join(__dirname, '..');

class Element {
  constructor(id = '') {
    this.id = id;
    this.children = [];
    this._textContent = '';
    this.value = '';
    this.hidden = id === 'agent-panel' || id === 'chat-operator-card' || id === 'chat-operator-pending';
    this.dataset = {};
    this.style = { setProperty() {} };
    this.listeners = {};
    this.classList = {
      _classes: new Set(),
      toggle(c, force) {
        if (force === undefined) {
          if (this._classes.has(c)) this._classes.delete(c);
          else this._classes.add(c);
        } else if (force) this._classes.add(c);
        else this._classes.delete(c);
      },
      add(c) { this._classes.add(c); },
      remove(c) { this._classes.delete(c); },
      contains(c) { return this._classes.has(c); },
    };
  }
  get textContent() {
    return this._textContent + this.children.map(c => c.textContent).join(' ');
  }
  set textContent(v) {
    this._textContent = String(v);
  }
  setAttribute(k, v) { this[k] = String(v); }
  removeAttribute(k) { delete this[k]; }
  getAttribute(k) { return this[k] ?? null; }
  append(...c) { this.children.push(...c); }
  replaceChildren(...c) { this.children = c; }
  addEventListener(name, fn) { this.listeners[name] = fn; }
  focus() {}
  matches() { return false; }
  get firstElementChild() { return this.children[0] || null; }
  get lastElementChild() { return this.children[this.children.length - 1] || null; }
  set innerHTML(_) { throw Error('Unsafe markup'); }
}

const elements = new Map();
function getEl(id) {
  if (!elements.has(id)) elements.set(id, new Element(id));
  return elements.get(id);
}

const spoken = [];
const requests = [];
let mockJob = {
  id: 'job-fusion-1',
  mode: 'standard',
  status: 'running',
  steps: [{ n: 1, kind: 'say', text: 'Analyzing disk storage' }],
};

const document = {
  hidden: false,
  activeElement: null,
  getElementById: getEl,
  createElement(tag) { return new Element(tag); },
  addEventListener() {}
};

const context = {
  console,
  document,
  URLSearchParams,
  location: { search: '' },
  GALAXY_PERSONA: { greeting: 'Hello, sir.' },
  crypto: require('node:crypto').webcrypto,
  Set, Map, Math, JSON, Number, String, Array, Object, Promise, Error, AbortController,
  setTimeout, clearTimeout, Date,
  requestAnimationFrame() { return 1; },
  ResizeObserver: class { observe() {} },
  matchMedia() { return { matches: true, addEventListener() {} }; },
  innerWidth: 1024, innerHeight: 768,
  SpeechSynthesisUtterance: class { constructor(text) { this.text = text; } },
  speechSynthesis: {
    getVoices() { return [{ lang: 'en-GB' }]; },
    cancel() {},
    speak(u) { spoken.push(u.text); u.onstart?.(); },
  },
  fetch: async (url, options = {}) => {
    requests.push({ url, options });
    if (url.startsWith('/agent/status')) {
      return { ok: true, json: async () => ({ mode: 'standard', job: mockJob }) };
    }
    if (url === '/agent/stop') {
      mockJob = { ...mockJob, status: 'stopped' };
      return { ok: true, json: async () => ({ mode: 'standard', job: mockJob }) };
    }
    if (url === '/agent/approve') {
      mockJob = { ...mockJob, status: 'running', pending: null };
      return { ok: true, json: async () => ({ mode: 'standard', job: mockJob }) };
    }
    if (url === '/agent/run') {
      return { ok: true, json: async () => ({ job: mockJob }) };
    }
    return { ok: true, json: async () => ({}) };
  }
};

context.window = context;
context.window.galaxy = {
  voice: {
    speaking: false,
    speak(t) { spoken.push(t); },
    replyLanguage: 'en'
  }
};
vm.createContext(context);

// Load voice.js, app.js, agent.js
const voiceCode = fs.readFileSync(path.join(root, 'viewer/voice.js'), 'utf8');
const agentCode = fs.readFileSync(path.join(root, 'viewer/agent.js'), 'utf8');

vm.runInContext(voiceCode, context);
vm.runInContext(agentCode, context);

(async () => {
  const agent = context.window.galaxyAgent;
  assert.ok(agent, 'galaxyAgent must be defined on window');

  const chatCard = getEl('chat-operator-card');
  const chatStatus = getEl('chat-operator-status');
  const chatSteps = getEl('chat-operator-steps');
  const agentPanel = getEl('agent-panel');

  // Verify initial state
  assert.equal(agentPanel.hidden, true, 'agent-panel starts hidden');
  assert.equal(chatCard.hidden, true, 'chat-operator-card starts hidden');

  // Attach job from chat
  agent.attach('job-fusion-1', { fromChat: true });

  // Let poll resolve
  await new Promise(r => setTimeout(r, 20));

  // Operator card must be visible, but sidebar panel must remain hidden!
  assert.equal(chatCard.hidden, false, 'chat-operator-card must become visible when attached from chat');
  assert.equal(agentPanel.hidden, true, 'agent-panel must remain hidden when attached from chat');

  // Steps must be rendered into chatSteps
  assert.equal(chatSteps.children.length, 1, 'step should be rendered into chatSteps');
  assert.ok(chatSteps.children[0].textContent.includes('Analyzing disk storage'), 'chat step has correct text');

  // Narration must have spoken despite panel.hidden === true
  assert.ok(spoken.some(s => s.includes('Analyzing disk storage')), 'pumpNarration must speak step even when sidebar is hidden');

  // Test approval in chat card
  mockJob = {
    ...mockJob,
    status: 'awaiting_approval',
    pending: { token: 'tok-123', reason: 'Needs root privilege', name: 'df -h' }
  };
  // Trigger poll
  await context.fetch('/agent/status?job_id=job-fusion-1');
  agent.attach('job-fusion-1', { fromChat: true });
  await new Promise(r => setTimeout(r, 20));

  const chatPending = getEl('chat-operator-pending');
  assert.equal(chatPending.hidden, false, 'chatPending must be visible when approval is pending');
  assert.ok(getEl('chat-operator-pending-text').textContent.includes('Needs root privilege'));

  // Click chatApprove
  const approveBtn = getEl('chat-operator-approve');
  assert.ok(typeof approveBtn.listeners['click'] === 'function', 'chat-operator-approve must have click listener');
  approveBtn.listeners['click']();
  await new Promise(r => setTimeout(r, 20));

  const approveReq = requests.find(r => r.url === '/agent/approve');
  assert.ok(approveReq, 'approval request was sent');
  assert.equal(JSON.parse(approveReq.options.body).token, 'tok-123');

  // Test completion and chat-answer update
  mockJob = {
    ...mockJob,
    status: 'done',
    summary: 'Disk has 45.2 GB available.'
  };
  agent.attach('job-fusion-1', { fromChat: true });
  await new Promise(r => setTimeout(r, 20));

  assert.equal(chatStatus.textContent, 'Done');
  const chatAnswer = getEl('chat-answer');
  assert.ok(chatAnswer.textContent.includes('Disk has 45.2 GB available.'), 'chat-answer should be updated with final job summary');
  assert.ok(spoken.some(s => s.includes('45.2 GB available')), 'final summary should be spoken by voice');

  console.log('Fusion UI tests passed: embedded card, silent sidebar, unmuted narration, in-chat approval, and completion update verified');
  process.exit(0);
})().catch(err => {
  console.error(err);
  process.exit(1);
});
