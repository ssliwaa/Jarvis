'use strict';
// Jarvis Studio: the visible controls for the P1 memory/session/skill/web/MCP
// and scheduler lanes. Every panel talks to a real local endpoint; nothing is
// faked when a lane is empty or unavailable.
(() => {
  const $ = id => document.getElementById(id);
  const panel = $('studio-panel');
  const toggle = $('studio-toggle');
  const tabs = [...document.querySelectorAll('[data-studio-tab]')];
  const views = [...document.querySelectorAll('[data-studio-view]')];
  if (!panel || !toggle) return;

  let active = 'memory';
  let loaded = new Set();

  function setStatus(text, state = '') {
    const node = $('studio-status');
    if (!node) return;
    node.textContent = text;
    node.dataset.state = state;
  }

  async function api(path, options = {}) {
    if (window.JarvisAPI && typeof window.JarvisAPI.request === 'function') {
      return window.JarvisAPI.request(path, options);
    }
    // Fallback: the original implementation, kept for the case where the
    // api.js patch is not present (zero regression without JarvisAPI).
    const response = await fetch(path, {
      credentials: 'same-origin',
      cache: 'no-store',
      ...options,
      headers: { Accept: 'application/json', ...(options.headers || {}) },
    });
    let body = {};
    try { body = await response.json(); }
    catch (_) { throw new Error(`The local service returned an unreadable response (${response.status}).`); }
    if (!response.ok || body.error) {
      const message = body.error?.message || body.answer || `Request failed (${response.status}).`;
      throw new Error(message);
    }
    return body;
  }

  function post(path, payload) {
    if (window.JarvisAPI && typeof window.JarvisAPI.post === 'function') {
      return window.JarvisAPI.post(path, payload);
    }
    // Fallback: the original implementation, kept for the case where the
    // api.js patch is not present (zero regression without JarvisAPI).
    return api(path, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
  }

  function node(tag, className, text) {
    const item = document.createElement(tag);
    if (className) item.className = className;
    if (text !== undefined) item.textContent = text;
    return item;
  }

  function replaceList(id, rows, emptyText) {
    const list = $(id);
    if (!list) return;
    list.replaceChildren();
    if (!rows.length) {
      list.append(node('li', 'empty-state', emptyText));
      return;
    }
    rows.forEach(row => list.append(row));
  }

  const LIVE_VIEWS = new Set(['overview', 'system', 'sessions', 'schedules', 'selfmod', 'clipboard', 'reminders', 'watch']);

  function showView(name) {
    if (name === 'briefing') name = 'overview';
    active = name;
    tabs.forEach(tab => tab.setAttribute('aria-selected', String(tab.dataset.studioTab === name)));
    views.forEach(view => { view.hidden = view.dataset.studioView !== name; });
    if (!loaded.has(name) || LIVE_VIEWS.has(name)) {
      loaded.add(name);
      loadTab(name);
    }
  }

  async function loadTab(name) {
    if (name === 'briefing') name = 'overview';
    if (name === 'memory') return loadMemory();
    if (name === 'selfmod') return loadSelfmod();
    if (name === 'sessions') return loadSessions();
    if (name === 'skills') return loadSkills();
    if (name === 'mcp') return loadMcp();
    if (name === 'schedules') return loadSchedules();
    if (name === 'overview') { loadServices(); return loadBriefing(); }
    if (name === 'system') return loadSystem();
    if (name === 'apps') return loadApps();
    if (name === 'docs') return loadDocuments();
    if (name === 'files') { loadFiles(); return loadCheckpoints(); }
    if (name === 'clipboard') return loadClipboard();
    if (name === 'reminders') return loadReminders();
    if (name === 'watch') return loadWatch();
    return undefined;
  }

  /* -------------------- memory -------------------- */

  function renderMemory(rows, title = 'Stored memories') {
    const items = (rows || []).map(row => {
      const item = node('li', 'studio-memory');
      item.append(node('b', '', `${row.category || 'notes'}/${row.key || ''}`));
      item.append(node('span', '', row.value || ''));
      const forget = node('button', '', 'Forget');
      forget.type = 'button';
      forget.addEventListener('click', async () => {
        if (!window.confirm(`Forget "${row.key}"?`)) return;
        forget.disabled = true;
        try {
          await post('/memory', { action: 'forget', id: row.id, confirm: true });
          setStatus(`Forgot ${row.key}.`);
          await loadMemory();
        } catch (error) {
          forget.disabled = false;
          setStatus(error.message, 'error');
        }
      });
      item.append(forget);
      return item;
    });
    replaceList('memory-list', items, 'No stored memories yet.');
    setStatus(`${items.length} memor${items.length === 1 ? 'y' : 'ies'} · ${title}`);
  }

  async function loadMemory(recall = '') {
    setStatus(recall ? 'Recalling…' : 'Loading memory…', 'working');
    try {
      const body = recall
        ? await post('/memory', { action: 'recall', value: recall })
        : await api('/memory');
      const rows = recall ? (body.result?.memories || []) : (body.memories || []);
      renderMemory(rows, recall ? `recall “${recall}”` : 'all categories');
      await loadMemorySuggestions();
    } catch (error) {
      setStatus(error.message, 'error');
      replaceList('memory-list', [], 'Memory is unavailable.');
    }
  }

  $('memory-form')?.addEventListener('submit', async event => {
    event.preventDefault();
    const category = $('memory-category')?.value || 'notes';
    const key = $('memory-key')?.value.trim() || '';
    const value = $('memory-value')?.value.trim() || '';
    if (!key || !value) { setStatus('A memory needs a key and a value.', 'error'); return; }
    setStatus('Saving memory…', 'working');
    try {
      await post('/memory', { action: 'add', category, key, value, confirm: true });
      if ($('memory-key')) $('memory-key').value = '';
      if ($('memory-value')) $('memory-value').value = '';
      setStatus(`Remembered ${category}/${key}.`);
      await loadMemory();
    } catch (error) {
      setStatus(error.message, 'error');
    }
  });
  $('memory-refresh')?.addEventListener('click', () => loadMemory());
  $('memory-recall-button')?.addEventListener('click', () => loadMemory($('memory-recall')?.value.trim() || ''));

  function renderMemorySuggestions(rows) {
    const items = (rows || []).map(row => {
      const item = node('li', 'studio-memory suggestion');
      item.append(node('b', '', `${row.category || 'notes'}/${row.key || ''}`));
      item.append(node('span', '', row.value || ''));
      const accept = node('button', '', 'Accept');
      accept.type = 'button';
      const reject = node('button', '', 'Reject');
      reject.type = 'button';
      const decide = async accepted => {
        accept.disabled = reject.disabled = true;
        try {
          await post('/memory/suggestions', { action: accepted ? 'accept' : 'reject', id: row.id });
          setStatus(accepted ? 'Suggestion saved to memory.' : 'Suggestion rejected.');
          await loadMemorySuggestions();
        } catch (error) {
          accept.disabled = reject.disabled = false;
          setStatus(error.message, 'error');
        }
      };
      accept.addEventListener('click', () => decide(true));
      reject.addEventListener('click', () => decide(false));
      item.append(accept, reject);
      return item;
    });
    replaceList('memory-suggestions', items, 'No pending suggestions. Explicit facts you state in chat appear here.');
  }

  async function loadMemorySuggestions() {
    try {
      const body = await api('/memory/suggestions');
      renderMemorySuggestions(body.suggestions || []);
    } catch (error) {
      replaceList('memory-suggestions', [], 'Suggestions are unavailable.');
    }
  }

  /* -------------------- self-modification -------------------- */

  let selfmodSelected = '';
  let selfmodKind = '';
  let selfmodToken = '';

  function updateSelfmodApply() {
    const button = $('selfmod-apply');
    if (button) button.disabled = !(selfmodSelected && ($('selfmod-token')?.value.trim() || selfmodToken));
    const label = $('selfmod-selected');
    if (label) label.textContent = selfmodSelected
      ? `Selected ${selfmodKind || 'proposal'} ${selfmodSelected}. Paste its one-time token and apply.`
      : 'No proposal selected.';
  }

  function renderSelfmodProposals(rows) {
    const items = (rows || []).map(row => {
      const item = node('li', 'studio-file');
      item.append(node('b', '', `${row.kind || 'proposal'} · ${row.id || ''}`));
      const fullPreview = String(row.preview || '');
      const preview = node('span', '', fullPreview.slice(0, 4000)
        + (fullPreview.length > 4000 ? '\n… preview truncated; ask Jarvis for the full diff.' : ''));
      preview.style.whiteSpace = 'pre-wrap';
      item.append(preview);
      const expiry = Number(row.expires_at || 0);
      item.append(node('small', '', expiry ? `expires ${new Date(expiry * 1000).toLocaleTimeString()}` : ''));
      const select = node('button', '', 'Select');
      select.type = 'button';
      select.addEventListener('click', () => {
        selfmodSelected = String(row.id || '');
        selfmodKind = String(row.kind || '');
        selfmodToken = '';
        if ($('selfmod-token')) $('selfmod-token').value = '';
        updateSelfmodApply();
      });
      item.append(select);
      return item;
    });
    replaceList('selfmod-proposals', items, 'No pending proposals. Generate one above.');
  }

  function renderSelfmodRules(rows) {
    const items = (rows || []).map(row => {
      const item = node('li', 'studio-skill');
      item.append(node('b', '', `${row.category || 'general'} · ${row.active === false ? 'paused' : 'active'}`));
      item.append(node('span', '', row.rule || ''));
      const toggle = node('button', '', row.active === false ? 'Enable' : 'Pause');
      toggle.type = 'button';
      toggle.addEventListener('click', async () => {
        try {
          await post('/self/rules', { action: 'toggle', rule_id: row.id, confirm: true });
          setStatus('Rule updated.');
          await loadSelfmod();
        } catch (error) { setStatus(error.message, 'error'); }
      });
      const remove = node('button', '', 'Remove');
      remove.type = 'button';
      remove.addEventListener('click', async () => {
        if (!window.confirm('Remove this learned rule?')) return;
        try {
          await post('/self/rules', { action: 'remove', rule_id: row.id, confirm: true });
          setStatus('Rule removed.');
          await loadSelfmod();
        } catch (error) { setStatus(error.message, 'error'); }
      });
      item.append(toggle, remove);
      return item;
    });
    replaceList('selfmod-rules', items, 'No learned rules.');
  }

  function renderSelfmodPatches(rows) {
    const items = (rows || []).map(row => {
      const item = node('li', 'studio-file');
      item.append(node('b', '', `${row.patch_id || 'patch'} · ${row.status || ''}`));
      item.append(node('span', '', `${row.file || ''} — ${row.explanation || ''}`));
      if (row.status === 'applied') {
        const rollback = node('button', '', 'Rollback');
        rollback.type = 'button';
        rollback.addEventListener('click', async () => {
          if (!window.confirm('Rollback this patch?')) return;
          try {
            await post('/self/rollback', { patch_id: row.patch_id, confirm: true });
            setStatus('Patch rolled back.');
            await loadSelfmod();
          } catch (error) { setStatus(error.message, 'error'); }
        });
        item.append(rollback);
      }
      return item;
    });
    replaceList('selfmod-patches', items, 'No source patches recorded.');
  }

  async function loadSelfmod() {
    setStatus('Loading self-modification state…', 'working');
    try {
      const [status, rules, patches] = await Promise.all([
        api('/self/status'), api('/self/rules'), api('/self/patches'),
      ]);
      const metrics = $('selfmod-metrics');
      if (metrics) {
        metrics.replaceChildren(
          metric('Skills', String((status.skills || []).length), 'generated'),
          metric('Rules', String((rules.rules || []).length), 'style directives'),
          metric('Proposals', String((status.proposals || []).length), 'pending'),
          metric('Patches', String((patches.patches || []).length), 'history'),
        );
      }
      renderSelfmodProposals(status.proposals || []);
      renderSelfmodRules(rules.rules || []);
      renderSelfmodPatches(patches.patches || []);
      updateSelfmodApply();
      const drift = status.bench_drift || {};
      if ($('selfmod-drift')) {
        const dirty = (drift.changed || []).length + (drift.added || []).length + (drift.removed || []).length;
        $('selfmod-drift').textContent = drift.sealed
          ? (dirty ? `Benchmark drift: ${(drift.changed || []).length} changed, ${(drift.added || []).length} added, ${(drift.removed || []).length} removed.`
                   : 'Benchmark sealed; no drift.')
          : 'Benchmark is not sealed yet.';
      }
      if ($('selfmod-curriculum')) {
        $('selfmod-curriculum').replaceChildren(...(status.curriculum || []).map(row => {
          const item = document.createElement('li');
          item.textContent = `${row.module}: ${row.failed}/${row.cases} failing, top level ${row.max_level}`;
          return item;
        }));
      }
      if ($('selfmod-lessons')) {
        $('selfmod-lessons').replaceChildren(...(status.failures || []).map(row => {
          const item = document.createElement('li');
          item.textContent = `${row.module || 'general'}: ${row.lesson} (x${row.count || 1})`;
          return item;
        }));
      }

      setStatus('Self-modification state loaded; proposals are not applied automatically.');
    } catch (error) {
      setStatus(error.message, 'error');
      replaceList('selfmod-proposals', [], 'Self-modification is unavailable.');
      replaceList('selfmod-rules', [], 'Rules are unavailable.');
      replaceList('selfmod-patches', [], 'Patch history is unavailable.');
    }
  }
  $('selfmod-refresh')?.addEventListener('click', loadSelfmod);
  $('selfmod-watch')?.addEventListener('click', async () => {
    const button = $('selfmod-watch');
    const on = !button.textContent.endsWith('on');
    try {
      await post('/self/watch', { action: on ? 'on' : 'off' });
      button.textContent = `Runtime watch: ${on ? 'on' : 'off'}`;
      setStatus(on ? 'Watcher will scan the journal every two minutes.' : 'Watcher stopped.');
    } catch (error) { setStatus(error.message, 'error'); }
  });
  $('selfmod-draft')?.addEventListener('click', async () => {
    const module = prompt('Module name (e.g. router):');
    if (!module) return;
    setStatus('Drafting held-out cases…', 'working');
    try {
      const body = await post('/self/bench/draft', { module });
      const list = $('selfmod-suggestions');
      if (list) list.replaceChildren(...(body.cases || []).map(row => {
        const item = document.createElement('li');
        item.textContent = `${row.draft_ok ? 'OK' : 'FAIL'} ${row.call}(${JSON.stringify(row.kwargs)}) -> ${JSON.stringify(row.expect ?? 'error')}`;
        return item;
      }));
      setStatus(`Draft: ${body.passing}/${body.total} cases already pass. Save to bench/${module}.json, then re-seal.`);
    } catch (error) { setStatus(error.message, 'error'); }
  });
  $('selfmod-seal')?.addEventListener('click', async () => {
    try { await post('/self/bench/seal', {}); setStatus('Benchmark sealed.'); await loadSelfmod(); }
    catch (error) { setStatus(error.message, 'error'); }
  });
  $('selfmod-suggest')?.addEventListener('click', async () => {
    setStatus('Planning the next changes…', 'working');
    try {
      const body = await post('/self/suggest', { limit: 3 });
      const list = $('selfmod-suggestions');
      if (list) list.replaceChildren(...(body.suggestions || []).map(row => {
        const item = document.createElement('li');
        item.textContent = `${row.file}: ${row.instruction}`;
        return item;
      }));
      setStatus('Suggestions ready.');
    } catch (error) { setStatus(error.message, 'error'); }
  });
  $('selfmod-token')?.addEventListener('input', () => { selfmodToken = $('selfmod-token').value.trim(); updateSelfmodApply(); });
  $('selfmod-apply')?.addEventListener('click', async () => {
    const token = $('selfmod-token')?.value.trim() || '';
    if (!selfmodSelected || !token) { setStatus('Select a proposal and paste its one-time token.', 'error'); return; }
    const target = selfmodKind === 'heal' ? '/self/heal/apply' : '/self/forge/apply';
    setStatus('Applying self-modification proposal…', 'working');
    try {
      await post(target, { proposal_id: selfmodSelected, token });
      selfmodSelected = ''; selfmodKind = ''; selfmodToken = '';
      if ($('selfmod-token')) $('selfmod-token').value = '';
      setStatus('Proposal applied and verified.');
      await loadSelfmod();
    } catch (error) { setStatus(error.message, 'error'); }
  });

  async function proposeSelfmod(path, payload, kind) {
    setStatus(kind === 'skill' ? 'Generating skill proposal…'
      : kind === 'change' ? 'Generating change proposal…' : 'Generating patch proposal…', 'working');
    try {
      const body = await post(path, payload);
      const proposal = body.proposal || {};
      selfmodSelected = String(proposal.proposal_id || '');
      selfmodKind = String(proposal.kind || kind);
      // Do not pre-fill the one-time token or enable Apply: the point of the
      // gate is an explicit human review and confirmation, not one click.
      selfmodToken = '';
      if ($('selfmod-token')) $('selfmod-token').value = '';
      updateSelfmodApply();
      await loadSelfmod();
      const oneTime = String(proposal.token || '');
      setStatus(`Proposal ${selfmodSelected} ready.${oneTime ? ` One-time token: ${oneTime}.` : ''} `
        + 'Review the preview, then paste its token to apply.');
    } catch (error) { setStatus(error.message, 'error'); }
  }

  $('selfmod-forge')?.addEventListener('click', () => {
    const goal = $('selfmod-goal')?.value.trim() || '';
    if (goal.length < 3) { setStatus('A skill goal of at least 3 characters is required.', 'error'); return; }
    proposeSelfmod('/self/forge', { goal }, 'skill');
  });
  $('selfmod-change')?.addEventListener('click', () => {
    const instruction = $('selfmod-instruction')?.value.trim() || '';
    const file = $('selfmod-file')?.value.trim() || '';
    if (instruction.length < 5) { setStatus('An instruction of at least 5 characters is required.', 'error'); return; }
    proposeSelfmod('/self/change', file ? { instruction, file } : { instruction }, 'change');
  });
  $('selfmod-heal')?.addEventListener('click', () => {
    const traceback = $('selfmod-traceback')?.value.trim() || '';
    if (!traceback) { setStatus('Paste a real traceback first.', 'error'); return; }
    proposeSelfmod('/self/heal', { traceback }, 'heal');
  });
  $('selfmod-rule-form')?.addEventListener('submit', async event => {
    event.preventDefault();
    const text = $('selfmod-rule-text')?.value.trim() || '';
    if (!text) { setStatus('A rule needs text.', 'error'); return; }
    try {
      await post('/self/rules', { action: 'add', text, confirm: true });
      if ($('selfmod-rule-text')) $('selfmod-rule-text').value = '';
      setStatus('Rule added.');
      await loadSelfmod();
    } catch (error) { setStatus(error.message, 'error'); }
  });

  /* -------------------- sessions -------------------- */

  function renderSessions(rows) {
    const items = (rows || []).map(row => {
      const item = node('li', 'studio-session');
      const kind = row.role ? `${row.role} · ${String(row.token || '').slice(0, 10)}` : `session · ${String(row.token || '').slice(0, 12)}`;
      item.append(node('b', '', kind));
      item.append(node('span', '', row.content || (row.updated_at ? `updated ${new Date(row.updated_at * 1000).toLocaleString()}` : 'archived session')));
      return item;
    });
    replaceList('session-list', items, 'No matching conversations yet.');
    setStatus(`${items.length} session ${items.length === 1 ? 'result' : 'results'}.`);
  }

  async function loadSessions(query = '') {
    setStatus(query ? 'Searching conversations…' : 'Loading sessions…', 'working');
    try {
      const body = query
        ? await api(`/sessions/search?q=${encodeURIComponent(query)}`)
        : await api('/sessions');
      renderSessions(query ? (body.hits || []) : (body.sessions || []));
    } catch (error) {
      setStatus(error.message, 'error');
      replaceList('session-list', [], 'Sessions are unavailable.');
    }
  }

  $('session-search-form')?.addEventListener('submit', event => {
    event.preventDefault();
    loadSessions($('session-query')?.value.trim() || '');
  });

  /* -------------------- skills -------------------- */

  function renderSkills(rows) {
    const items = (rows || []).map(row => {
      const item = node('li', 'studio-skill');
      item.append(node('b', '', row.name || 'skill'));
      item.append(node('span', '', row.description || 'No description.'));
      const open = node('button', '', 'Read skill');
      open.type = 'button';
      open.addEventListener('click', () => viewSkill(row.name));
      item.append(open);
      return item;
    });
    replaceList('skill-list', items, 'No skills found.');
    setStatus(`${items.length} skill${items.length === 1 ? '' : 's'} available.`);
  }

  async function loadSkills(query = '') {
    setStatus(query ? 'Searching skills…' : 'Loading skills…', 'working');
    try {
      const body = await api('/skills' + (query ? `?q=${encodeURIComponent(query)}` : ''));
      renderSkills(body.skills || []);
    } catch (error) {
      setStatus(error.message, 'error');
      replaceList('skill-list', [], 'The skill library is unavailable.');
    }
  }

  async function viewSkill(name) {
    try {
      const body = await api(`/skills/view?name=${encodeURIComponent(name)}`);
      const skill = body.skill || {};
      $('skill-view-name').textContent = skill.name || name;
      $('skill-view-content').textContent = skill.content || '';
      $('skill-view').hidden = false;
      setStatus(`Reading ${skill.name || name}.`);
    } catch (error) {
      setStatus(error.message, 'error');
    }
  }

  $('skill-search-form')?.addEventListener('submit', event => {
    event.preventDefault();
    loadSkills($('skill-query')?.value.trim() || '');
  });
  $('skill-view-close')?.addEventListener('click', () => { $('skill-view').hidden = true; });

  /* -------------------- web research -------------------- */

  function renderResearch(rows) {
    const list = $('research-results');
    if (!list) return;
    list.replaceChildren();
    if (!rows.length) {
      list.append(node('li', 'empty-state', 'No public results found.'));
      setStatus('No public results found.');
      return;
    }
    rows.forEach(row => {
      const item = node('li', 'studio-result');
      const link = node('a', '', row.title || row.url || 'Result');
      link.href = row.url || '#';
      link.target = '_blank';
      link.rel = 'noopener noreferrer';
      item.append(link, node('span', '', row.snippet || ''));
      item.append(node('small', '', row.url || ''));
      list.append(item);
    });
    setStatus(`${rows.length} public result${rows.length === 1 ? '' : 's'} · sources open in a new tab.`);
  }

  $('research-form')?.addEventListener('submit', async event => {
    event.preventDefault();
    const query = $('research-query')?.value.trim() || '';
    if (!query) { setStatus('Enter a research query.', 'error'); return; }
    setStatus('Searching the public web…', 'working');
    try {
      const body = await api(`/research?q=${encodeURIComponent(query)}`);
      renderResearch(body.results || []);
    } catch (error) {
      setStatus(error.message, 'error');
      $('research-results')?.replaceChildren(node('li', 'empty-state', 'Web research failed; no sources were invented.'));
    }
  });

  /* -------------------- MCP -------------------- */

  function renderMcp(servers) {
    const items = (servers || []).map(row => {
      const item = node('li', 'studio-skill');
      item.append(node('b', '', row.name || 'server'));
      const state = [row.running ? 'running' : 'not started', row.transport || 'stdio'];
      if (row.tools) state.push(row.tools + ' tools');
      if (row.cooldown_seconds > 0) state.push('cooldown ' + Math.ceil(row.cooldown_seconds) + 's');
      if (row.auth && row.auth !== 'not_configured' && row.auth !== 'authorized') state.push('auth: ' + row.auth);
      const detail = node('span', '', state.join(' · '));
      if (row.last_error) detail.title = row.last_error;
      item.append(detail);
      return item;
    });
    replaceList('mcp-servers', items, 'No MCP servers configured. Add ~/.jarvis-tools/mcp.json.');
    setStatus(`${(servers || []).length} MCP server${(servers || []).length === 1 ? '' : 's'} configured.`);
  }

  async function loadMcp() {
    setStatus('Loading MCP status…', 'working');
    try {
      const body = await api('/mcp');
      renderMcp(body.servers || []);
    } catch (error) {
      setStatus(error.message, 'error');
      replaceList('mcp-servers', [], 'MCP status is unavailable.');
    }
  }

  $('mcp-refresh')?.addEventListener('click', loadMcp);
  $('mcp-discover')?.addEventListener('click', async () => {
    setStatus('Discovering MCP tools…', 'working');
    try {
      const body = await api('/mcp/tools?refresh=1');
      const pre = $('mcp-tools-list');
      pre.hidden = false;
      pre.textContent = JSON.stringify(body.tools || [], null, 2);
      setStatus(`${(body.tools || []).length} MCP tool${(body.tools || []).length === 1 ? '' : 's'} discovered.`);
    } catch (error) {
      setStatus(error.message, 'error');
    }
  });
  $('mcp-confirm')?.addEventListener('change', event => {
    const call = $('mcp-call');
    if (call) call.disabled = !event.target.checked;
  });
  $('mcp-call-form')?.addEventListener('submit', async event => {
    event.preventDefault();
    if (!$('mcp-confirm')?.checked) { setStatus('Confirm the external MCP call first.', 'error'); return; }
    const server = $('mcp-server')?.value.trim() || '';
    const tool = $('mcp-tool')?.value.trim() || '';
    if (!server || !tool) { setStatus('An MCP call needs a server and a tool.', 'error'); return; }
    let args = {};
    try { args = JSON.parse($('mcp-arguments')?.value || '{}'); }
    catch (_) { setStatus('MCP arguments must be valid JSON.', 'error'); return; }
    if (!args || typeof args !== 'object' || Array.isArray(args)) { setStatus('MCP arguments must be a JSON object.', 'error'); return; }
    const call = $('mcp-call');
    if (call) call.disabled = true;
    setStatus('Calling the MCP tool…', 'working');
    try {
      const body = await post('/mcp/call', { server, tool, arguments: args, confirm: true });
      const result = $('mcp-call-result');
      result.hidden = false;
      result.textContent = JSON.stringify(body.result ?? body, null, 2);
      setStatus('MCP call completed; the receipt is below.');
    } catch (error) {
      setStatus(error.message, 'error');
    } finally {
      // One confirmation is one external call: leaving the box checked made
      // every later click a one-click side effect.
      const confirm = $('mcp-confirm');
      if (confirm) confirm.checked = false;
      if (call) call.disabled = true;
    }
  });

  /* -------------------- schedules -------------------- */

  function renderSchedules(rows) {
    const items = (rows || []).map(row => {
      const state = row.last_status || (row.enabled === false ? 'paused' : 'scheduled');
      const item = node('li', `studio-schedule ${state === 'error' ? 'error' : state === 'done' ? 'done' : ''}`);
      item.append(node('b', '', row.name || row.task?.slice(0, 60) || 'Scheduled task'));
      item.append(node('span', '', row.task || ''));
      const meta = [
        `every ${row.every_seconds || '?'} s`,
        `runs ${row.runs || 0}`,
        `retries ${row.retry_count || 0}/${row.max_retries ?? 1}`,
        row.last_status ? `last ${row.last_status}` : 'not run yet',
        row.last_error ? `error: ${row.last_error}` : '',
      ].filter(Boolean).join(' · ');
      item.append(node('span', 'studio-schedule-meta', meta));
      const run = node('button', '', 'Run now');
      run.type = 'button';
      run.addEventListener('click', async () => {
        run.disabled = true;
        try {
          await post('/agent/schedules/run', { id: row.id });
          setStatus('Schedule queued; refreshing when it finishes.');
          window.setTimeout(loadSchedules, 3000);
        } catch (error) {
          run.disabled = false;
          setStatus(error.message, 'error');
        }
      });
      item.append(run);
      const remove = node('button', '', 'Remove');
      remove.type = 'button';
      remove.addEventListener('click', async () => {
        if (!window.confirm('Remove this schedule?')) return;
        remove.disabled = true;
        try {
          await post('/agent/schedules/remove', { id: row.id });
          setStatus('Schedule removed.');
          await loadSchedules();
        } catch (error) {
          remove.disabled = false;
          setStatus(error.message, 'error');
        }
      });
      item.append(remove);
      return item;
    });
    replaceList('schedule-list', items, 'No scheduled jobs.');
    setStatus(`${items.length} scheduled job${items.length === 1 ? '' : 's'}.`);
  }

  async function loadSchedules() {
    setStatus('Loading schedules…', 'working');
    try {
      const body = await api('/agent/schedules');
      renderSchedules(body.schedules || []);
    } catch (error) {
      setStatus(error.message, 'error');
      replaceList('schedule-list', [], 'Schedules are unavailable.');
    }
  }

  $('schedule-refresh')?.addEventListener('click', loadSchedules);
  $('schedule-form')?.addEventListener('submit', async event => {
    event.preventDefault();
    const task = $('schedule-task')?.value.trim() || '';
    if (!task) { setStatus('A scheduled task cannot be empty.', 'error'); return; }
    const every = Number($('schedule-every')?.value || 3600);
    const maxRetries = Number($('schedule-retries')?.value || 1);
    setStatus('Adding schedule…', 'working');
    try {
      await post('/agent/schedules', {
        task,
        every_seconds: every,
        name: $('schedule-name')?.value.trim() || undefined,
        max_retries: maxRetries,
      });
      if ($('schedule-task')) $('schedule-task').value = '';
      if ($('schedule-name')) $('schedule-name').value = '';
      setStatus('Schedule added.');
      await loadSchedules();
    } catch (error) {
      setStatus(error.message, 'error');
    }
  });

  /* -------------------- briefing -------------------- */

  function renderServices(data) {
    const box = $('studio-services');
    if (!box) return;
    box.replaceChildren(
      metric('Service', data.active || 'unknown', data.enabled || 'unknown'),
      metric('PID', String(data.pid || '—'), data.substate || ''),
      metric('Unit', data.unit ? 'jarvis.service' : 'not installed', data.available ? 'systemd --user' : 'unavailable'),
    );
  }

  async function loadServices() {
    try {
      const body = await api('/services');
      renderServices(body);
      setStatus(body.active === 'active' ? 'Supervisor active.' : 'Supervisor is not active.', body.active === 'active' ? '' : 'error');
    } catch (error) {
      setStatus(error.message, 'error');
    }
    try {
      const queue = await api('/agent/queue');
      const rows = (queue.queue || []).map(row => {
        const item = node('li', 'studio-file');
        item.append(node('b', '', row.id || 'queued'));
        item.append(node('span', '', row.task || ''));
        return item;
      });
      replaceList('agent-queue-list', rows, 'Operator queue is empty.');
    } catch (_) {}
  }

  async function loadBriefing() {
    setStatus('Building local briefing…', 'working');
    try {
      const body = await api('/briefing');
      const pre = $('briefing-text');
      if (pre) pre.textContent = body.text || 'No briefing content.';
      setStatus('Briefing ready · weather from Open-Meteo when available.');
    } catch (error) {
      setStatus(error.message, 'error');
    }
  }

  $('briefing-refresh')?.addEventListener('click', () => { loadBriefing(); loadServices(); });
  $('services-refresh')?.addEventListener('click', loadServices);
  $('services-install')?.addEventListener('click', async () => {
    try {
      await post('/services', { action: 'install' });
      setStatus('Supervisor unit installed and enabled.');
      await loadServices();
    } catch (error) { setStatus(error.message, 'error'); }
  });
  $('services-restart')?.addEventListener('click', async () => {
    if (!window.confirm('Restart the local Jarvis service?')) return;
    try {
      await post('/services', { action: 'restart' });
      setStatus('Service restart requested.');
      await loadServices();
    } catch (error) { setStatus(error.message, 'error'); }
  });
  $('agent-queue-resume')?.addEventListener('click', async () => {
    try {
      const body = await post('/agent/queue/resume', {});
      setStatus(body.started ? `Started queued job ${body.started.id}.` : 'The queue is empty.');
      await loadServices();
    } catch (error) { setStatus(error.message, 'error'); }
  });

  /* -------------------- system -------------------- */

  function formatBytes(value) {
    const number = Number(value) || 0;
    if (number >= 1024 ** 3) return `${(number / 1024 ** 3).toFixed(1)} GB`;
    if (number >= 1024 ** 2) return `${(number / 1024 ** 2).toFixed(1)} MB`;
    if (number >= 1024) return `${(number / 1024).toFixed(1)} kB`;
    return `${number} B`;
  }

  function metric(label, value, note = '') {
    const box = node('div', 'studio-metric');
    box.append(node('b', '', label), node('span', '', value));
    if (note) box.append(node('small', '', note));
    return box;
  }

  async function loadSystem() {
    setStatus('Reading /proc…', 'working');
    try {
      const data = await api('/system');
      const metrics = $('system-metrics');
      if (metrics) {
        metrics.replaceChildren(
          metric('Load', (data.load || []).join(' / '), `${data.cpu_count || '?'} CPUs`),
          metric('Memory', `${data.memory?.percent ?? '?'}%`, `${formatBytes(data.memory?.used)} / ${formatBytes(data.memory?.total)}`),
          metric('Disk', `${data.disk?.percent ?? '?'}%`, `${formatBytes(data.disk?.free)} free`),
          metric('Uptime', `${Math.floor((data.uptime || 0) / 3600)} h`, data.host || ''),
          metric('Kernel', data.kernel || 'unknown'),
          metric('Battery', data.battery ? `${data.battery.percent}%` : 'n/a', data.battery?.status || ''),
        );
      }
      const rows = (data.processes || []).map(row => {
        const item = node('li', 'studio-file');
        item.append(node('b', '', `${row.name} · pid ${row.pid}`));
        item.append(node('span', '', `RSS ${formatBytes(row.rss)} · state ${row.state || '?'}`));
        return item;
      });
      replaceList('system-processes', rows, 'No process data.');
      const memory = Number(data.memory?.percent || 0), disk = Number(data.disk?.percent || 0);
      const load = Number((data.load || [0])[0] || 0), cpus = Number(data.cpu_count || 1);
      const alerts = [];
      if (memory >= 90) alerts.push(`memory ${memory}%`);
      if (disk >= 90) alerts.push(`disk ${disk}%`);
      if (load > cpus * 1.5) alerts.push(`load ${load}`);
      setStatus(alerts.length ? `Attention: ${alerts.join(' · ')}` : 'System metrics refreshed.', alerts.length ? 'error' : '');
    } catch (error) {
      setStatus(error.message, 'error');
    }
  }

  $('system-refresh')?.addEventListener('click', loadSystem);

  /* -------------------- desktop apps -------------------- */

  function renderApps(data) {
    const rows = [];
    for (const win of data.windows || []) {
      const item = node('li', 'studio-skill studio-app-window');
      item.append(node('b', '', win.title || win.class || 'window'));
      item.append(node('span', '', `${win.class || ''} · ${win.id || ''}`));
      const focus = node('button', '', 'Focus');
      focus.type = 'button';
      focus.addEventListener('click', () => appAction('focus', win.title || win.class || ''));
      const close = node('button', '', 'Close');
      close.type = 'button';
      close.addEventListener('click', () => {
        if (globalThis.confirm(`Ask ${win.title || win.class} to close?`)) appAction('close', win.title || win.class || '');
      });
      item.append(focus, close);
      rows.push(item);
    }
    for (const app of data.apps || []) {
      const item = node('li', 'studio-skill');
      item.append(node('b', '', app.name || app.id || 'app'));
      item.append(node('span', '', app.exec || ''));
      const focus = node('button', '', 'Focus');
      focus.type = 'button';
      focus.addEventListener('click', () => appAction('focus', app.name || app.id || ''));
      const launch = node('button', '', 'Launch');
      launch.type = 'button';
      launch.addEventListener('click', () => appAction('launch', app.name || app.id || ''));
      item.append(focus, launch);
      rows.push(item);
    }
    replaceList('apps-list', rows, 'No matching app or window.');
    setStatus(`${rows.length} desktop match${rows.length === 1 ? '' : 'es'}.`);
  }

  async function appAction(action, query) {
    setStatus(`${action === 'close' ? 'Closing' : action === 'launch' ? 'Starting' : 'Focusing'} ${query}…`, 'working');
    try {
      const body = await post('/apps', { action, query, ...(action === 'close' ? { confirm: true } : {}) });
      if (body.result?.outcome === 'failed' || body.result?.outcome === 'unverified') {
        setStatus(body.result.error || 'The app action could not be verified.', 'error');
      } else {
        setStatus(`${action} completed for ${query}.`);
      }
      await loadApps(query);
    } catch (error) {
      setStatus(error.message, 'error');
    }
  }

  async function loadApps(query = '') {
    setStatus(query ? 'Finding app…' : 'Listing apps…', 'working');
    try {
      const body = await api('/apps' + (query ? `?q=${encodeURIComponent(query)}` : ''));
      renderApps(body);
    } catch (error) {
      setStatus(error.message, 'error');
      replaceList('apps-list', [], 'App identity is unavailable.');
    }
  }

  $('apps-form')?.addEventListener('submit', event => {
    event.preventDefault();
    loadApps($('apps-query')?.value.trim() || '');
  });

  /* -------------------- documents -------------------- */

  function renderDocuments(rows) {
    const items = (rows || []).map(row => {
      const item = node('li', 'studio-file');
      item.append(node('b', '', row.name || 'document'));
      item.append(node('span', '', `${formatBytes(row.bytes)} · ${new Date((row.modified || 0) * 1000).toLocaleString()}`));
      item.append(node('span', '', row.path || ''));
      const open = node('button', '', 'Open');
      open.type = 'button';
      open.addEventListener('click', async () => {
        try {
          await post('/documents/open', { name: row.name, confirm: true });
          setStatus(`Opened ${row.name}.`);
        } catch (error) { setStatus(error.message, 'error'); }
      });
      item.append(open);
      return item;
    });
    replaceList('documents-list', items, 'No generated documents yet.');
    setStatus(`${items.length} document${items.length === 1 ? '' : 's'} in the local library.`);
  }

  async function loadDocuments() {
    try {
      const body = await api('/documents');
      renderDocuments(body.documents || []);
    } catch (error) {
      setStatus(error.message, 'error');
      replaceList('documents-list', [], 'The document library is unavailable.');
    }
  }

  $('documents-refresh')?.addEventListener('click', loadDocuments);
  $('document-form')?.addEventListener('submit', async event => {
    event.preventDefault();
    const kind = $('document-kind')?.value || 'docx';
    const title = $('document-title')?.value.trim() || '';
    if (!title) { setStatus('A document title is required.', 'error'); return; }
    const rawRows = $('document-rows')?.value.trim() || '';
    let rows = [];
    if (rawRows) {
      try { rows = JSON.parse(rawRows); }
      catch (_) { setStatus('Rows must be valid JSON.', 'error'); return; }
    }
    setStatus(`Generating ${kind.toUpperCase()}…`, 'working');
    try {
      const body = await post('/documents', { kind, title, body: $('document-body')?.value || '', rows, template: $('document-template')?.value || 'plain' });
      const doc = body.document || {};
      setStatus(`${doc.kind?.toUpperCase() || kind.toUpperCase()} written: ${doc.path || ''} (${formatBytes(doc.bytes)})`);
      await loadDocuments();
    } catch (error) {
      setStatus(error.message, 'error');
    }
  });

  /* -------------------- files -------------------- */

  // Batch ids were module state, so a reload hid the only restore path even
  // though the server still held the batch. Persist the id, not the files.
  const batchStore = {
    get(name) {
      try { return String(window.localStorage?.getItem(`galaxy.files.${name}`) || ''); }
      catch (_) { return ''; }
    },
    set(name, value) {
      try {
        if (value) window.localStorage?.setItem(`galaxy.files.${name}`, value);
        else window.localStorage?.removeItem(`galaxy.files.${name}`);
      } catch (_) { /* storage may be blocked */ }
    },
  };
  let lastQuarantineBatch = batchStore.get('quarantine');
  let lastArchiveBatch = batchStore.get('archive');

  function fileItem(row, kind = '') {
    const item = node('li', `studio-file ${kind}`);
    item.append(node('b', '', row.path || row.name || 'file'));
    item.append(node('span', '', kind === 'duplicate'
      ? `${formatBytes(row.size)} · ${row.age_days ?? '?'} days old`
      : `${formatBytes(row.size)} · ${row.age_days ?? '?'} days old`));
    return item;
  }

  function renderFiles(data) {
    // Show every member of a duplicate group, not just the keeper: the
    // quarantine action moves group.slice(1), so those were exactly the
    // paths the user could not see before approving.
    const duplicates = (data.duplicates || []).flatMap(group => group.map((row, index) => {
      const item = fileItem(row, 'duplicate');
      if (index > 0) item.append(node('em', 'duplicate-copy', 'copy — will be quarantined'));
      return item;
    }));
    const empty = (data.empty_dirs || []).map(path => {
      const item = node('li', 'studio-file');
      item.append(node('b', '', path));
      item.append(node('span', '', 'empty directory'));
      return item;
    });
    const old = (data.old || []).map(row => fileItem(row, 'old'));
    replaceList('files-duplicates', duplicates, 'No duplicate groups.');
    replaceList('files-empty', empty, 'No empty directories.');
    replaceList('files-old', old, 'No old files.');
    const summary = $('files-summary');
    if (summary) summary.textContent = `${data.files || 0} files · ${(data.duplicates || []).length} duplicate groups · ${formatBytes(data.duplicate_waste)} reclaimable · ${(data.empty_dirs || []).length} empty dirs`;
    const quarantine = $('files-quarantine');
    if (quarantine) quarantine.disabled = !(data.duplicates || []).length;
    const restore = $('files-restore');
    if (restore) restore.disabled = !lastQuarantineBatch;
    const restoreArchive = $('files-restore-archive');
    if (restoreArchive) restoreArchive.disabled = !lastArchiveBatch;
    setStatus('Files scanned; nothing was changed.');
  }

  async function loadFiles() {
    const root = $('files-root')?.value.trim() || '~/Desktop';
    const older = Number($('files-older')?.value || 365);
    setStatus('Scanning files…', 'working');
    try {
      const body = await api(`/organizer?root=${encodeURIComponent(root)}&older_days=${encodeURIComponent(older)}`);
      renderFiles(body);
    } catch (error) {
      setStatus(error.message, 'error');
      replaceList('files-duplicates', [], 'The file scan failed.');
    }
  }

  $('files-form')?.addEventListener('submit', event => { event.preventDefault(); loadFiles(); });
  $('files-quarantine')?.addEventListener('click', async () => {
    const root = $('files-root')?.value.trim() || '~/Desktop';
    const body = await api(`/organizer?root=${encodeURIComponent(root)}`);
    const paths = [];
    for (const group of body.duplicates || []) {
      for (const row of group.slice(1)) paths.push(row.path);
    }
    if (!paths.length) { setStatus('No duplicate copies to quarantine.', 'error'); return; }
    if (!window.confirm(`Move ${paths.length} duplicate copies to the restoreable trash?`)) return;
    try {
      const moved = await post('/organizer', { action: 'trash', paths, confirm: true });
      lastQuarantineBatch = moved.result?.batch || '';
      batchStore.set('quarantine', lastQuarantineBatch);
      setStatus(`Quarantined ${paths.length} file(s); batch ${lastQuarantineBatch}.`);
      await loadFiles();
      if ($('files-restore')) $('files-restore').disabled = !lastQuarantineBatch;
    } catch (error) {
      setStatus(error.message, 'error');
    }
  });
  $('files-restore')?.addEventListener('click', async () => {
    if (!lastQuarantineBatch) return;
    if (!window.confirm(`Restore quarantine batch ${lastQuarantineBatch}?`)) return;
    try {
      const restored = await post('/organizer', { action: 'restore', batch: lastQuarantineBatch, confirm: true });
      setStatus(`Restored ${restored.result?.restored?.length || 0} file(s).`);
      lastQuarantineBatch = '';
      batchStore.set('quarantine', '');
      await loadFiles();
    } catch (error) {
      setStatus(error.message, 'error');
    }
  });

  $('files-preview')?.addEventListener('click', async () => {
    const root = $('files-root')?.value.trim() || '~/Desktop';
    const older = Number($('files-older')?.value || 365);
    setStatus('Building archive preview…', 'working');
    try {
      const body = await post('/organizer', { action: 'preview', root, older_days: older });
      const old = (body.result?.old || []).map(row => fileItem(row, 'old'));
      replaceList('files-old', old, 'No archive candidates.');
      if ($('files-summary')) $('files-summary').textContent = `Preview: ${body.result?.count || 0} old file(s) and empty folders. Nothing moved.`;
      if ($('files-archive')) $('files-archive').disabled = !(body.result?.count);
      setStatus('Archive preview ready; nothing was changed.');
    } catch (error) {
      setStatus(error.message, 'error');
    }
  });
  $('files-archive')?.addEventListener('click', async () => {
    const root = $('files-root')?.value.trim() || '~/Desktop';
    const older = Number($('files-older')?.value || 365);
    if (!window.confirm('Move old files into the restorable archive?')) return;
    try {
      const body = await post('/organizer', { action: 'archive', root, older_days: older, confirm: true });
      lastArchiveBatch = body.result?.batch || '';
      batchStore.set('archive', lastArchiveBatch);
      if ($('files-restore-archive')) $('files-restore-archive').disabled = !lastArchiveBatch;
      setStatus(`Archived ${body.result?.count || 0} item(s); batch ${lastArchiveBatch}.`);
      await loadFiles();
    } catch (error) {
      setStatus(error.message, 'error');
    }
  });

  $('files-restore-archive')?.addEventListener('click', async () => {
    if (!lastArchiveBatch) return;
    if (!window.confirm(`Restore archived batch ${lastArchiveBatch}?`)) return;
    try {
      const body = await post('/organizer', { action: 'restore_archive', batch: lastArchiveBatch, confirm: true });
      setStatus(`Restored ${body.result?.restored?.length || 0} archived file(s).`);
      lastArchiveBatch = '';
      batchStore.set('archive', '');
      if ($('files-restore-archive')) $('files-restore-archive').disabled = true;
      await loadFiles();
    } catch (error) {
      setStatus(error.message, 'error');
    }
  });

  /* -------------------- file checkpoints -------------------- */

  function checkpointItem(checkpoint, path) {
    const item = node('li', 'studio-memory');
    const workdir = checkpoint.workdir || path || '';
    item.append(node('b', '', checkpoint.short_hash || '?'));
    const when = String(checkpoint.timestamp || '').replace('T', ' ').slice(0, 16);
    item.append(node('span', '', `${when} · ${checkpoint.reason || 'snapshot'}${workdir ? ' · ' + workdir : ''}`));
    const actions = node('span', 'studio-actions');
    const diff = node('button', 'studio-button', 'Diff');
    diff.type = 'button';
    diff.addEventListener('click', async () => {
      if (!workdir) { setStatus('This checkpoint has no project path.', 'error'); return; }
      diff.disabled = true;
      try {
        const body = await post('/checkpoints/diff', { path: workdir, hash: checkpoint.hash });
        const result = body.result || {};
        if (!body.ok) throw new Error(result.error || 'The diff failed.');
        const pre = $('checkpoints-diff');
        if (pre) {
          pre.hidden = false;
          pre.textContent = `${result.stat || ''}\n${result.diff || 'No changes.'}`.trim();
        }
        setStatus(`Diff for ${checkpoint.short_hash}.`);
      } catch (error) {
        setStatus(error.message, 'error');
      } finally {
        diff.disabled = false;
      }
    });
    const safe = node('button', 'studio-button', 'Restore safe');
    safe.type = 'button';
    safe.addEventListener('click', async () => {
      if (!workdir) { setStatus('This checkpoint has no project path.', 'error'); return; }
      if (!window.confirm(`Restore ${workdir} to ${checkpoint.short_hash}? Files you edited yourself are kept.`)) return;
      safe.disabled = true;
      try {
        const body = await post('/checkpoints/restore', {
          path: workdir, hash: checkpoint.hash, safe: true, confirm: true,
        });
        const result = body.result || {};
        if (!body.ok) throw new Error(result.error || 'The restore failed.');
        setStatus(`Restored ${result.restored_files?.length || 0} file(s); ${result.deleted_files?.length || 0} removed.`);
        await loadCheckpoints();
      } catch (error) {
        setStatus(error.message, 'error');
      } finally {
        safe.disabled = false;
      }
    });
    const full = node('button', 'studio-button danger', 'Full restore');
    full.type = 'button';
    full.addEventListener('click', async () => {
      if (!workdir) { setStatus('This checkpoint has no project path.', 'error'); return; }
      if (!window.confirm(`FULL restore of ${workdir} to ${checkpoint.short_hash}? Files created after the snapshot will be deleted.`)) return;
      full.disabled = true;
      try {
        const body = await post('/checkpoints/restore', {
          path: workdir, hash: checkpoint.hash, safe: false, confirm: true,
        });
        const result = body.result || {};
        if (!body.ok) throw new Error(result.error || 'The restore failed.');
        setStatus(`Full restore done: ${result.restored_files?.length || 0} restored, ${result.deleted_files?.length || 0} deleted.`);
        await loadCheckpoints();
      } catch (error) {
        setStatus(error.message, 'error');
      } finally {
        full.disabled = false;
      }
    });
    actions.append(diff, safe, full);
    item.append(actions);
    return item;
  }

  async function loadCheckpoints(path = null) {
    const requested = path === null ? ($('checkpoints-path')?.value.trim() || '') : path;
    setStatus('Reading file checkpoints…', 'working');
    try {
      const query = requested ? `?path=${encodeURIComponent(requested)}` : '';
      const body = await api(`/checkpoints${query}`);
      const rows = (body.checkpoints || []).map(row => checkpointItem(row, requested));
      replaceList('checkpoints-list', rows, 'No file checkpoints yet.');
      const status = body.status || {};
      setStatus(`${rows.length} checkpoint(s) · ${Math.round((status.total_size_bytes || 0) / 1024)} KiB store`);
    } catch (error) {
      replaceList('checkpoints-list', [], 'The checkpoint store is unavailable.');
      setStatus(error.message, 'error');
    }
  }

  $('checkpoints-refresh')?.addEventListener('click', () => loadCheckpoints());
  $('checkpoints-all')?.addEventListener('click', () => {
    if ($('checkpoints-path')) $('checkpoints-path').value = '';
    loadCheckpoints('');
  });

  /* -------------------- clipboard -------------------- */

  async function loadClipboard() {
    setStatus('Reading clipboard…', 'working');
    try {
      const body = await api('/clipboard');
      const text = $('clipboard-text');
      if (text) text.value = body.text || '';
      setStatus(`${body.chars || 0} characters read from the local clipboard.`);
    } catch (error) {
      setStatus(error.message, 'error');
    }
  }

  $('clipboard-read')?.addEventListener('click', loadClipboard);
  $('clipboard-copy')?.addEventListener('click', async () => {
    const text = $('clipboard-text')?.value || '';
    try {
      await navigator.clipboard.writeText(text);
      setStatus('Copied to the browser clipboard.');
    } catch (error) {
      setStatus('The browser refused clipboard access; select the text and copy it manually.', 'error');
    }
  });

  /* -------------------- reminders -------------------- */

  async function loadReminders() {
    setStatus('Loading reminders…', 'working');
    try {
      const data = await api('/reminders');
      const items = data.reminders || [];
      const list = $('reminders-list');
      if (list) {
        list.replaceChildren();
        if (!items.length) {
          list.append(node('li', 'empty-state', 'No reminders stored.'));
        } else {
          items.forEach(item => {
            const li = node('li', 'studio-row');
            const main = node('div', 'row-main');
            const title = node('strong', '', item.text);
            const dueStr = (item.due_at || '').slice(0, 16).replace('T', ' ');
            const meta = node('span', 'studio-hint', `Due: ${dueStr} · ${item.status}`);
            main.append(title, meta);
            li.append(main);

            if (item.status === 'pending') {
              const actions = node('div', 'row-actions');
              const doneBtn = node('button', 'studio-button', 'Complete');
              doneBtn.type = 'button';
              doneBtn.addEventListener('click', async () => {
                await post('/reminders', { action: 'complete', id: item.id });
                loadReminders();
              });
              const snoozeBtn = node('button', 'studio-button', '+1h');
              snoozeBtn.type = 'button';
              snoozeBtn.addEventListener('click', async () => {
                const later = new Date(Date.now() + 3600000).toISOString();
                await post('/reminders', { action: 'snooze', id: item.id, due_at: later });
                loadReminders();
              });
              const cancelBtn = node('button', 'studio-button danger', 'Cancel');
              cancelBtn.type = 'button';
              cancelBtn.addEventListener('click', async () => {
                await post('/reminders', { action: 'cancel', id: item.id });
                loadReminders();
              });
              actions.append(doneBtn, snoozeBtn, cancelBtn);
              li.append(actions);
            }
            list.append(li);
          });
        }
      }
      setStatus(`${items.length} reminders.`);
    } catch (err) {
      setStatus(err.message, 'error');
    }
  }

  $('reminder-create-form')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const text = $('reminder-text')?.value.trim();
    const due = $('reminder-due')?.value.trim();
    if (!text || !due) return;
    setStatus('Creating reminder…', 'working');
    try {
      await post('/reminders', { action: 'create', text, due_at: due });
      if ($('reminder-text')) $('reminder-text').value = '';
      loadReminders();
    } catch (err) {
      setStatus(err.message, 'error');
    }
  });

  /* -------------------- watch -------------------- */

  async function loadWatch() {
    setStatus('Loading page & price watches…', 'working');
    try {
      const data = await api('/watch');
      const items = data.watches || [];
      const list = $('watch-list');
      if (list) {
        list.replaceChildren();
        if (!items.length) {
          list.append(node('li', 'empty-state', 'No pages currently watched.'));
        } else {
          items.forEach(item => {
            const li = node('li', 'studio-row');
            const main = node('div', 'row-main');
            const urlNode = node('strong', '', item.url);
            const obs = item.observation || {};
            const price = obs.price !== undefined ? ` · ${obs.price} ${obs.currency || ''}` : '';
            const checkedTime = obs.observed_at ? new Date(obs.observed_at * 1000).toLocaleString() : 'never';
            const meta = node('span', 'studio-hint', `Checked: ${checkedTime}${price}`);
            main.append(urlNode, meta);
            li.append(main);

            const actions = node('div', 'row-actions');
            const checkBtn = node('button', 'studio-button', 'Check now');
            checkBtn.type = 'button';
            checkBtn.addEventListener('click', async () => {
              setStatus(`Checking ${item.url}…`, 'working');
              try {
                await post('/watch', { action: 'check', id: item.id });
                loadWatch();
              } catch (err) { setStatus(err.message, 'error'); }
            });
            const removeBtn = node('button', 'studio-button danger', 'Remove');
            removeBtn.type = 'button';
            removeBtn.addEventListener('click', async () => {
              await post('/watch', { action: 'remove', id: item.id });
              loadWatch();
            });
            actions.append(checkBtn, removeBtn);
            li.append(actions);
            list.append(li);
          });
        }
      }
      setStatus(`${items.length} watched pages.`);
    } catch (err) {
      setStatus(err.message, 'error');
    }
  }

  $('watch-create-form')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const url = $('watch-url')?.value.trim();
    if (!url) return;
    setStatus('Creating page watch…', 'working');
    try {
      await post('/watch', { action: 'create', url, conditions: [{ type: 'page_change' }], notify: true, interval_seconds: 3600 });
      if ($('watch-url')) $('watch-url').value = '';
      loadWatch();
    } catch (err) {
      setStatus(err.message, 'error');
    }
  });

  /* -------------------- panel -------------------- */

  function openPanel() {
    try { window.galaxyAgent?.close?.(); } catch (_) {}
    try { window.galaxyTeam?.close?.(); } catch (_) {}
    panel.hidden = false;
    toggle.setAttribute('aria-expanded', 'true');
    showView(active);
    setStatus('Local studio ready.');
  }

  function closePanel() {
    panel.hidden = true;
    toggle.setAttribute('aria-expanded', 'false');
  }

  toggle.addEventListener('click', () => panel.hidden ? openPanel() : closePanel());
  $('studio-close')?.addEventListener('click', closePanel);
  tabs.forEach(tab => tab.addEventListener('click', () => showView(tab.dataset.studioTab)));
  document.addEventListener('keydown', event => {
    if (event.key === 'Escape' && !panel.hidden) closePanel();
  });

  window.galaxyStudio = {
    open: openPanel,
    close: closePanel,
    openTab(name) { openPanel(); showView(String(name || 'memory')); },
    isOpen: () => !panel.hidden,
  };
})();
