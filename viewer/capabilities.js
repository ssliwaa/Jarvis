'use strict';
// Capability map: makes the live manifest discoverable without turning the
// atlas into a settings page. All text is rendered with textContent.
(() => {
  const $ = id => document.getElementById(id);
  const overlay = $('capability-overlay');
  const toggle = $('capability-toggle');
  const link = $('capability-link');
  if (!overlay || !toggle) return;

  let lastFocus = null;

  async function get(path) {
    const response = await fetch(path, { cache: 'no-store', credentials: 'same-origin', headers: { Accept: 'application/json' } });
    const body = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(body.answer || body.error?.message || `HTTP ${response.status}`);
    return body;
  }

  function el(tag, cls, text) {
    const node = document.createElement(tag);
    if (cls) node.className = cls;
    if (text !== undefined) node.textContent = text;
    return node;
  }

  function setInput(value, focus = true) {
    const input = $('question');
    if (!input) return;
    input.value = value;
    input.focus();
    input.setSelectionRange(value.length, value.length);
  }

  function close() {
    overlay.hidden = true;
    toggle.setAttribute('aria-expanded', 'false');
    if (lastFocus && typeof lastFocus.focus === 'function') lastFocus.focus();
  }

  function open() {
    lastFocus = document.activeElement;
    overlay.hidden = false;
    toggle.setAttribute('aria-expanded', 'true');
    load();
    document.getElementById('capability-close')?.focus();
  }

  function card(title, description, tag, options = {}) {
    const item = el('div', 'capability-item');
    item.append(el('span', 'capability-tag', tag));
    item.append(el('b', '', title));
    item.append(el('span', '', description));
    if (options.tab) {
      const button = el('button', 'capability-open', `Open ${options.label || 'studio'} →`);
      button.type = 'button';
      button.addEventListener('click', () => {
        close();
        window.galaxyStudio?.openTab?.(options.tab);
      });
      item.append(button);
    } else if (options.command !== undefined) {
      const button = el('button', 'capability-open', options.label || 'Use it →');
      button.type = 'button';
      button.addEventListener('click', () => { close(); setInput(options.command); });
      item.append(button);
    } else if (options.action) {
      const button = el('button', 'capability-open', options.label || 'Open →');
      button.type = 'button';
      button.addEventListener('click', () => { close(); options.action(); });
      item.append(button);
    }
    return item;
  }

  function render(capabilities, status) {
    const grid = $('capability-grid');
    const limits = $('capability-limits');
    grid.replaceChildren();
    limits.replaceChildren();
    const tools = Number(status.tool_count) || 0;
    const mode = status.mode || 'standard';
    const capabilityRows = Array.isArray(capabilities.capabilities) ? capabilities.capabilities : [];
    const available = capabilityRows.filter(row => row.available !== false).length;
    $('capability-status').dataset.state = '';
    $('capability-status').textContent = `${available} live capabilities · ${tools} Operator tools · ${mode} autonomy · local only`;

    grid.append(
      card('Grounded notes', 'Ask about your vault. Answers cite the actual note indexes or admit the gap.', 'ASK', { command: 'What do my notes say about ', label: 'Ask from notes →' }),
      card('General DeepSeek', 'When the notes do not cover a question, Jarvis answers from general knowledge with no fake citations.', 'ASK', { command: 'What is ', label: 'Ask generally →' }),
      card('Remember', 'Capture a new markdown note into the vault, index it and place its star in the atlas.', 'VAULT', { command: 'remember that ', label: 'Remember →' }),
      card('REA MCP Engine', 'Reverse engineering across binaries, Electron apps, APKs, and runtime behavior (207 MCP tools).', 'REA', { action: () => window.galaxyAgent?.open?.(), label: 'Open REA Tools →' }),
      card('Operator', 'Run shell, PTY, files, PDF/OCR, Chromium, desktop, HTTP and credentials in a separate job.', 'COMPUTER', { action: () => window.galaxyAgent?.open?.(), label: 'Open Operator →' }),
      card('Voice', 'Speak questions with Ctrl + Space; Edge TTS is the quality voice, Web Speech is the fallback.', 'VOICE', { action: () => document.getElementById('voice-output')?.focus(), label: 'Voice controls →' }),
      card('Memory & sessions', 'Durable personal facts, FTS5 session search and a compressed conversation summary.', 'P1', { tab: 'memory', label: 'Memory' }),
      card('Skills & MCP', 'Read SKILL.md procedures and call configured MCP tools with a confirmation gate.', 'P1', { tab: 'skills', label: 'Skills' }),
      card('Web research', 'Price, availability and current-fact questions are checked against public web results automatically; real URLs, never invented sources.', 'P1', { tab: 'research', label: 'Web' }),
      card('Briefing & system', 'Local daily briefing plus live CPU, memory, disk, uptime and process metrics.', 'P2', { tab: 'briefing', label: 'Briefing' }),
      card('Documents', 'Generate DOCX, XLSX, PPTX and PDF under ~/.jarvis-tools/documents.', 'P2', { tab: 'docs', label: 'Docs' }),
      card('Apps & files', 'Focus/close desktop apps and scan or quarantine duplicate and old files with restore.', 'P2', { tab: 'apps', label: 'Apps' }),
      card('Clipboard', 'Read the local clipboard without logging or persisting its text.', 'P2', { tab: 'clipboard', label: 'Clipboard' }),
      card('Self-modification', 'Generate skills, apply verified source patches and keep learned rules; approval outside Full.', 'P0/P1', { tab: 'selfmod', label: 'Selfmod' }),
    );

    const guard = (capabilities.limits || []).slice(0, 12);
    guard.forEach(text => limits.append(el('li', '', text)));
    if (!guard.length) limits.append(el('li', '', 'The manifest returned no limits. Treat that as a warning, not a permission.'));
  }

  async function load() {
    const status = $('capability-status');
    status.dataset.state = '';
    status.textContent = 'Reading the live capability manifest…';
    try {
      const [capabilities, agent] = await Promise.all([get('/capabilities'), get('/agent/status')]);
      render(capabilities, agent);
    } catch (error) {
      status.dataset.state = 'error';
      status.textContent = `Capability map unavailable: ${error.message}`;
    }
  }

  function openWith(value) {
    open();
    if (value !== undefined) setInput(value);
  }

  toggle.addEventListener('click', () => overlay.hidden ? open() : close());
  link?.addEventListener('click', open);
  $('capability-close')?.addEventListener('click', close);
  $('capability-backdrop')?.addEventListener('click', close);
  document.querySelectorAll('[data-cap-action]').forEach(button => {
    button.addEventListener('click', () => {
      const action = button.dataset.capAction;
      if (action === 'ask') { close(); setInput(''); }
      else if (action === 'remember') { close(); setInput('remember that '); }
      else if (action === 'operator') { close(); window.galaxyAgent?.open?.(); }
      else if (action === 'studio') { close(); window.galaxyStudio?.openTab?.('memory'); }
    });
  });
  document.addEventListener('keydown', event => {
    const target = event.target;
    const typing = target && ['INPUT', 'TEXTAREA', 'SELECT'].includes(target.tagName);
    if (event.key === 'Escape' && !overlay.hidden) { event.preventDefault(); close(); return; }
    if (!typing && event.key === '?') { event.preventDefault(); overlay.hidden ? open() : close(); return; }
    // Ctrl+K belongs to the command palette in app.js; handling it here too
    // opened two modals at once.
    if (event.key === 'Tab' && !overlay.hidden) {
      const focusable = [...overlay.querySelectorAll(
        'button:not([disabled]), [href], input:not([disabled]), [tabindex]:not([tabindex="-1"])')]
        .filter(node => node.offsetParent !== null);
      if (!focusable.length) return;
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    }
  });

  window.galaxyCapabilities = { open, close, openWith };
})();
