// External agents: tiles in the rail with settings, a task box and consent.
// Every server value is rendered with textContent — never innerHTML.
'use strict';

(function () {
  const LIST = document.getElementById('agent-list');
  const REFRESH = document.getElementById('agents-refresh');
  if (!LIST) return;

  const POLL_MS = 8000;
  const CONSENT_URL = '/agents/consent';
  const SETTING_LABELS = {
    provider: 'Provider',
    model: 'Model',
    effort: 'Poziom myślenia',
    reasoning: 'Reasoning',
    mode: 'Tryb pracy',
  };
  const ICONS = {
    claude: 'M12 3l7 4v10l-7 4-7-4V7z',
    opencode: 'M4 6h16M4 12h10M4 18h13',
    hermes: 'M12 3l2.5 5.5L20 11l-5.5 2.5L12 19l-2.5-5.5L4 11l5.5-2.5z',
    antigravity: 'M5 20c0-6 2.5-11 7-11s7 5 7 11M9 15h6M12 5v3',
  };

  let busy = false;
  let timer = null;
  const OPEN = new Set();   // which tiles the owner has expanded

  function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
  }

  function icon(name) {
    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    svg.setAttribute('viewBox', '0 0 24 24');
    svg.setAttribute('aria-hidden', 'true');
    svg.classList.add('agent-icon');
    const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
    path.setAttribute('d', ICONS[name] || ICONS.hermes);
    path.setAttribute('fill', 'none');
    path.setAttribute('stroke', 'currentColor');
    path.setAttribute('stroke-width', '1.6');
    path.setAttribute('stroke-linecap', 'round');
    path.setAttribute('stroke-linejoin', 'round');
    svg.appendChild(path);
    return svg;
  }

  function stateOf(agent) {
    if (!agent.installed) return 'missing';
    if (agent.running) return 'running';
    const last = agent.last_run || {};
    return last.status === 'failed' || last.status === 'timeout' ? 'failed' : 'idle';
  }

  function stateText(state) {
    return { running: 'pracuje', failed: 'błąd', missing: 'nie zainstalowany', idle: 'gotowy' }[state] || state;
  }

  async function post(path, body) {
    const response = await fetch(path, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body || {}),
    });
    let payload = {};
    try { payload = await response.json(); } catch (_) { payload = {}; }
    return { status: response.status, ok: response.ok, payload };
  }

  async function getJSON(path) {
    const response = await fetch(path);
    return response.ok ? response.json() : {};
  }

  async function getChecked(path) {
    // getJSON() turns a 400 into {}, which made a failed diff look like
    // "no differences". Callers that must tell the two apart use this.
    const response = await fetch(path);
    let payload = {};
    try { payload = await response.json(); } catch (_) { payload = {}; }
    return { ok: response.ok, status: response.status, payload };
  }

  function buildSettings(agent) {
    const form = el('div', 'agent-settings');
    const draft = Object.assign({}, agent.settings || {});
    const fields = {};
    const inputs = {};
    const extras = {};

    const missing = [];
    Object.keys(SETTING_LABELS).forEach(function (key) {
      const supported = (agent.supported || {})[key];
      if (!supported) { missing.push(SETTING_LABELS[key]); return; }
      const row = el('label', 'agent-field');
      row.appendChild(el('span', 'agent-field-label', SETTING_LABELS[key]));
      const choices = (agent.choices || {})[key] || [];
      const customAllowed = (agent.allow_custom || {})[key] === true;
      let input;
      let extra = null;
      if (choices.length) {
        input = document.createElement('select');
        input.appendChild(new Option('— domyślne —', ''));
        choices.forEach(function (choice) { input.appendChild(new Option(choice, choice)); });
        const stored = draft[key] || '';
        if (stored && choices.indexOf(stored) === -1) {
          // A hand-typed id must never disappear from the dropdown.
          input.appendChild(new Option(stored + ' (zapisany)', stored));
        }
        if (customAllowed) input.appendChild(new Option('＋ inny (wpisz)', '__custom__'));
        input.value = stored;
        if (customAllowed) {
          extra = document.createElement('input');
          extra.type = 'text';
          extra.className = 'agent-custom';
          extra.placeholder = (agent.hints || {})[key] || (key === 'provider' ? 'własny provider' : 'własny identyfikator modelu');
          extra.hidden = input.value !== '__custom__';
          extra.value = stored;
          input.addEventListener('change', function () {
            const custom = input.value === '__custom__';
            extra.hidden = !custom;
            if (custom) extra.focus();
          });
        }
      } else {
        input = document.createElement('input');
        input.type = 'text';
        input.placeholder = (agent.hints || {})[key] || '';
        input.value = draft[key] || '';
      }
      inputs[key] = input;
      extras[key] = extra;
      fields[key] = {
        value: function () {
          if (input.tagName === 'SELECT' && input.value === '__custom__') return extra ? extra.value.trim() : '';
          return input.value;
        },
      };
      row.appendChild(input);
      if (extra) row.appendChild(extra);
      form.appendChild(row);
    });

    // Wire up provider -> model dependency if both are supported
    if (inputs.provider && inputs.model && inputs.model.tagName === 'SELECT') {
      const provSelect = inputs.provider;
      const provExtra = extras.provider;
      const modelSelect = inputs.model;
      const modelExtra = extras.model;

      function getSelectedProvider() {
        if (provSelect.tagName === 'SELECT' && provSelect.value === '__custom__') {
          return provExtra ? provExtra.value.trim() : '';
        }
        return provSelect.value.trim();
      }

      function updateModelsForProvider(provName, isInitial) {
        const modelsByProv = agent.models_by_provider || {};
        let cleanProv = (provName || '').trim();
        if (cleanProv.startsWith('custom:')) {
          if (!modelsByProv[cleanProv] && modelsByProv[cleanProv.slice(7)]) {
            cleanProv = cleanProv.slice(7);
          }
        }

        let choices = modelsByProv[cleanProv];
        if (!choices || !choices.length) {
          if (!cleanProv) {
            choices = (agent.choices || {}).model || [];
          } else {
            choices = [];
          }
        }

        const currentModel = isInitial ? (draft.model || '') : (fields.model ? fields.model.value() : '');
        modelSelect.textContent = '';
        modelSelect.appendChild(new Option('— domyślne —', ''));
        choices.forEach(function (choice) {
          modelSelect.appendChild(new Option(choice, choice));
        });

        const customAllowed = (agent.allow_custom || {}).model === true;
        let targetValue = '';

        if (isInitial) {
          const stored = draft.model || '';
          if (stored) {
            if (choices.indexOf(stored) === -1) {
              modelSelect.appendChild(new Option(stored + ' (zapisany)', stored));
            }
            targetValue = stored;
          }
        } else {
          if (currentModel && choices.indexOf(currentModel) !== -1) {
            targetValue = currentModel;
          } else if (choices.length > 0) {
            targetValue = choices[0];
          } else {
            targetValue = '';
          }
        }

        if (customAllowed) {
          modelSelect.appendChild(new Option('＋ inny (wpisz)', '__custom__'));
        }

        modelSelect.value = targetValue;
        if (modelExtra) {
          const isCustom = modelSelect.value === '__custom__';
          modelExtra.hidden = !isCustom;
          if (!isCustom) {
            modelExtra.value = targetValue;
          }
        }
      }

      provSelect.addEventListener('change', function () {
        updateModelsForProvider(getSelectedProvider(), false);
      });

      if (provExtra) {
        provExtra.addEventListener('input', function () {
          if (provSelect.value === '__custom__') {
            updateModelsForProvider(provExtra.value.trim(), false);
          }
        });
      }

      updateModelsForProvider(getSelectedProvider(), true);
    }

    if (missing.length) {
      // One honest line instead of four dead rows: the owner still learns what this
      // CLI cannot do, without the panel looking broken.
      form.appendChild(el('p', 'agent-unsupported',
                          'niewspierane: ' + missing.join(', ').toLowerCase()));
    }

    const save = el('button', 'agent-action', 'Zapisz ustawienia');
    save.type = 'button';
    const note = el('span', 'agent-note', '');
    save.addEventListener('click', async function () {
      const settings = {};
      Object.keys(fields).forEach(function (key) { settings[key] = fields[key].value(); });
      save.disabled = true;
      const result = await post('/agents/config', { agent: agent.id, settings: settings });
      save.disabled = false;
      const err = result.payload && result.payload.error;
      const errMsg = typeof err === 'string' ? err : ((err && err.message) || 'błąd zapisu');
      const warnings = (result.payload && result.payload.warnings) || [];
      note.textContent = result.ok
        ? ('zapisane' + (warnings.length ? ' — ' + warnings.join(' ') : ''))
        : errMsg;
      if (result.ok) load();
    });
    form.appendChild(save);
    form.appendChild(note);
    return form;
  }

  function buildRun(agent) {
    const box = el('div', 'agent-run');
    const task = document.createElement('textarea');
    task.rows = 3;
    task.placeholder = 'Co ma zrobić ' + agent.label + '?';
    box.appendChild(task);

    const row = el('div', 'agent-run-actions');
    const click = el('button', 'agent-action primary', 'Uruchom (klik)');
    click.type = 'button';
    const mic = el('button', 'agent-action agent-mic', '🎤 powiedz „zgadzam się”');
    mic.type = 'button';
    const stop = el('button', 'agent-action agent-stop danger', 'Zatrzymaj');
    stop.type = 'button';
    const note = el('p', 'agent-note', '');
    row.appendChild(click);
    row.appendChild(mic);
    row.appendChild(stop);
    box.appendChild(row);
    box.appendChild(note);

    function tell(text, isError) {
      note.textContent = text;
      note.dataset.error = isError ? '1' : '0';
    }

    async function startWith(token, how) {
      const text = task.value.trim();
      let consent = token;
      if (!consent) {
        // A plain click is consent: the server issues the one-time grant that
        // /agents/run then consumes. Sending an empty token got a 403 and the
        // button never started anything.
        const grant = await post('/agents/consent', { agent: agent.id, task: text, confirmed: true });
        if (!grant.ok || !(grant.payload && grant.payload.token)) {
          const err = (grant.payload && grant.payload.error) || {};
          tell(err.message || 'Nie udało się potwierdzić zgody — nic nie uruchomiono.', true);
          return;
        }
        consent = grant.payload.token;
      }
      const result = await post('/agents/run', { agent: agent.id, task: text, consent: consent });
      if (result.ok) {
        tell('Uruchomiono (' + how + '). Jarvis nie nazwie tego gotowym, dopóki nie sprawdzi outboxa.');
        load();
      } else {
        tell(((result.payload.error || {}).message) || 'Nie udało się uruchomić.', true);
      }
    }

    click.addEventListener('click', async function () {
      const text = task.value.trim();
      if (!text) { tell('Najpierw wpisz zadanie.', true); return; }
      click.disabled = true;
      try {
        await startWith('', 'bezpośrednio');
      } finally {
        click.disabled = false;
      }
    });

    mic.addEventListener('click', async function () {
      const text = task.value.trim();
      if (!text) { tell('Najpierw wpisz zadanie, potem potwierdź głosem.', true); return; }
      if (!navigator.mediaDevices || !window.MediaRecorder) {
        tell('Ta przeglądarka nie nagrywa dźwięku.', true);
        return;
      }
      mic.disabled = true;
      tell('Mów teraz: „zgadzam się”.');
      let stream = null;
      try {
        stream = await navigator.mediaDevices.getUserMedia({ audio: true });
        const recorder = new MediaRecorder(stream);
        const chunks = [];
        recorder.ondataavailable = function (event) { if (event.data.size) chunks.push(event.data); };
        const done = new Promise(function (resolve) { recorder.onstop = resolve; });
        recorder.start();
        await new Promise(function (resolve) { setTimeout(resolve, 2600); });
        recorder.stop();
        await done;
        const blob = new Blob(chunks, { type: 'audio/webm' });
        const response = await fetch('/agents/consent?agent=' + encodeURIComponent(agent.id) +
          '&task=' + encodeURIComponent(text), {
          method: 'POST',
          headers: { 'Content-Type': 'audio/webm' },
          body: blob,
        });
        const payload = await response.json().catch(function () { return {}; });
        if (response.ok && payload.token) {
          tell('Usłyszałem: „' + (payload.heard || '') + '”. Zgoda przyjęta.');
          await startWith(payload.token, 'głos');
        } else {
          tell('Odmowa: usłyszałem „' + (payload.heard || '') + '”. Powiedz samo „zgadzam się”.', true);
        }
      } catch (error) {
        tell('Mikrofon niedostępny: ' + error.name, true);
      } finally {
        if (stream) stream.getTracks().forEach(function (track) { track.stop(); });
        mic.disabled = false;
      }
    });

    stop.addEventListener('click', async function () {
      const result = await post('/agents/stop', { agent: agent.id });
      tell(result.payload.stopped ? 'Zatrzymano.' : 'Nic nie działa.', !result.ok);
      load();
    });

    return box;
  }

  function buildDetail(agent) {
    // A <details> element toggles itself, so no click handler can be lost when the
    // poll re-renders the tiles.
    const details = document.createElement('details');
    details.className = 'agent-details';
    if (OPEN.has(agent.id)) details.open = true;
    details.addEventListener('toggle', function () {
      if (details.open) OPEN.add(agent.id); else OPEN.delete(agent.id);
    });
    details.appendChild(el('summary', 'agent-expand', 'Ustawienia agenta'));

    const detail = el('div', 'agent-detail');
    detail.appendChild(buildSettings(agent));
    detail.appendChild(buildRun(agent));

    const outboxButton = el('button', 'agent-action', 'Pokaż outbox');
    outboxButton.type = 'button';
    const logButton = el('button', 'agent-action', 'Pokaż log');
    logButton.type = 'button';
    const applyButton = el('button', 'agent-action', 'Zastosuj outbox');
    applyButton.type = 'button';
    const output = el('pre', 'agent-output', '');
    const actions = el('div', 'agent-run-actions');
    actions.appendChild(outboxButton);
    actions.appendChild(logButton);
    actions.appendChild(applyButton);
    detail.appendChild(actions);
    detail.appendChild(output);

    outboxButton.addEventListener('click', async function () {
      const res = await getChecked('/agents/outbox?agent=' + encodeURIComponent(agent.id));
      if (!res.ok) {
        const err = res.payload && res.payload.error;
        output.textContent = 'Błąd odczytu outboxa: ' + (typeof err === 'string' ? err : ((err && err.message) || ('HTTP ' + res.status)));
        return;
      }
      const files = res.payload.files || [];
      output.textContent = files.length
        ? files.map(function (file) { return file.path + '  ' + file.bytes + ' B'; }).join('\n')
        : 'Outbox jest pusty — agent nic nie odłożył.';
    });
    logButton.addEventListener('click', async function () {
      const res = await getChecked('/agents/logs?agent=' + encodeURIComponent(agent.id));
      if (!res.ok) {
        const err = res.payload && res.payload.error;
        output.textContent = 'Błąd odczytu logu: ' + (typeof err === 'string' ? err : ((err && err.message) || ('HTTP ' + res.status)));
        return;
      }
      output.textContent = (res.payload.log || '').slice(-3000) || 'Brak logu.';
    });
    applyButton.addEventListener('click', async function () {
      const target = window.prompt('Docelowy katalog do wdrożenia plików z outboxa:', '~/Jarvis');
      if (!target) return;
      const res = await post('/agents/apply', { agent: agent.id, target: target.trim(), confirm: true });
      if (res.ok && res.payload.ok) {
        const skipped = res.payload.skipped_reports || [];
        output.textContent = 'Zastosowano ' + res.payload.applied + ' plików z outboxa:\n' +
          (res.payload.files || []).join('\n') +
          (skipped.length ? '\n\nPominięto raporty (nie są plikami projektu): ' + skipped.join(', ') : '');
      } else {
        const err = res.payload && res.payload.error;
        const errMsg = typeof err === 'string' ? err : ((err && err.message) || 'Nieznany błąd');
        output.textContent = 'Błąd wdrażania: ' + errMsg;
      }
    });
    details.appendChild(detail);
    return details;
  }

  function tile(agent) {
    const state = stateOf(agent);
    const wrap = el('article', 'agent-tile');
    wrap.dataset.agent = agent.id;
    wrap.dataset.state = state;

    const head = el('div', 'agent-head');
    head.appendChild(icon(agent.id));

    const identity = el('div', 'agent-identity');
    identity.appendChild(el('span', 'agent-name', agent.label));
    const rawVersion = (agent.version || 'brak w PATH').split(' · ')[0];
    // "Hermes Agent v0.23.1 (2026.9.24)" in a 150 px line only ever showed an
    // ellipsis; the agent's own name is already above it.
    const version = rawVersion.startsWith(agent.label)
      ? rawVersion.slice(agent.label.length).trim()
      : rawVersion;
    identity.appendChild(el('span', 'agent-meta', version));
    head.appendChild(identity);

    const chip = el('span', 'agent-state', stateText(state));
    head.appendChild(chip);
    wrap.appendChild(head);

    const detail = buildDetail(agent);
    wrap.appendChild(detail);
    return wrap;
  }

  let selectedTeamProject = '';
  let teamRoomBuilt = false;
  let teamAgentsCache = [];
  let lastTeamStatus = 'zespół';
  let teamTouched = false;   // the owner picked a project (or "new") themselves

  function teamChip() {
    return document.querySelector('#agent-list .agent-tile[data-team-panel] .agent-state');
  }

  function openTeamRoom() {
    const panel = document.getElementById('team-panel');
    if (!panel) return;
    // One drawer at a time, like Operator and Studio already do for each other.
    try { window.galaxyStudio?.close?.(); } catch (_) {}
    try { window.galaxyAgent?.close?.(); } catch (_) {}
    if (!teamRoomBuilt) buildTeamRoom(teamAgentsCache);
    panel.hidden = false;
    const openBtn = document.getElementById('team-open');
    if (openBtn) openBtn.setAttribute('aria-expanded', 'true');
    if (typeof panel.__refresh === 'function') panel.__refresh();
    const sel = document.getElementById('team-project');
    if (sel) sel.focus();
  }

  function closeTeamRoom() {
    const panel = document.getElementById('team-panel');
    if (!panel) return;
    panel.hidden = true;
    const openBtn = document.getElementById('team-open');
    if (openBtn) openBtn.setAttribute('aria-expanded', 'false');
  }

  window.galaxyTeam = { open: openTeamRoom, close: closeTeamRoom };

  function buildTeamTile(agents) {
    // The room lives in its own drawer (like Operator/Studio); the tile is only a
    // launcher, so the 220 px rail never has to host a 570 px control panel.
    teamAgentsCache = agents;
    const wrap = el('article', 'agent-tile');
    wrap.dataset.teamPanel = '1';
    wrap.dataset.state = 'ready';

    const head = el('div', 'agent-head');
    const identity = el('div', 'agent-identity');
    identity.appendChild(el('span', 'agent-name', 'Zespół agentów'));
    identity.appendChild(el('span', 'agent-meta', 'worktree · czat · bramka testów'));
    head.appendChild(identity);
    head.appendChild(el('span', 'agent-state', lastTeamStatus));
    wrap.appendChild(head);

    const panel = document.getElementById('team-panel');
    const row = el('div', 'agent-run-actions');
    const openBtn = el('button', 'agent-action primary', 'Otwórz pokój projektu');
    openBtn.type = 'button';
    openBtn.id = 'team-open';
    openBtn.setAttribute('aria-expanded', String(!!panel && !panel.hidden));
    openBtn.setAttribute('aria-controls', 'team-panel');
    openBtn.addEventListener('click', openTeamRoom);
    row.appendChild(openBtn);
    wrap.appendChild(row);
    return wrap;
  }

  function buildTeamRoom(agents) {
    const room = document.getElementById('team-room');
    if (!room) return;
    teamRoomBuilt = true;
    room.textContent = '';

    const projRow = el('div', 'team-row');
    const projSelect = document.createElement('select');
    projSelect.id = 'team-project';
    projSelect.setAttribute('aria-label', 'Projekt zespołowy');
    const newOpt = document.createElement('option');
    newOpt.value = '';
    newOpt.textContent = '+ Nowy projekt zespołowy';
    projSelect.appendChild(newOpt);
    const refreshProjBtn = el('button', 'text-button', 'Odśwież');
    refreshProjBtn.type = 'button';
    projRow.appendChild(projSelect);
    projRow.appendChild(refreshProjBtn);
    room.appendChild(projRow);

    const membersRow = el('div', 'team-members');
    const memberChecks = [];
    agents.forEach(function (ag) {
      const lbl = document.createElement('label');
      const cb = document.createElement('input');
      cb.type = 'checkbox';
      cb.value = ag.id;
      cb.checked = !!ag.installed;
      cb.disabled = !ag.installed;
      memberChecks.push(cb);
      lbl.appendChild(cb);
      lbl.appendChild(document.createTextNode(ag.id));
      membersRow.appendChild(lbl);
    });
    room.appendChild(membersRow);

    const optsRow = el('div', 'team-row');
    const planLbl = document.createElement('label');
    const planCb = document.createElement('input');
    planCb.type = 'checkbox';
    planCb.checked = true;
    planLbl.appendChild(planCb);
    planLbl.appendChild(document.createTextNode(' Faza Architekta (PLAN.json)'));

    const wtLbl = document.createElement('label');
    const wtCb = document.createElement('input');
    wtCb.type = 'checkbox';
    wtCb.checked = true;
    wtLbl.appendChild(wtCb);
    wtLbl.appendChild(document.createTextNode(' Izolacja git worktree'));

    const revSelect = document.createElement('select');
    revSelect.id = 'team-reviewer';
    revSelect.setAttribute('aria-label', 'Recenzent');
    const noRev = document.createElement('option');
    noRev.value = '';
    noRev.textContent = 'Recenzent: brak';
    revSelect.appendChild(noRev);
    agents.forEach(function (ag) {
      if (!ag.installed) return;
      const opt = document.createElement('option');
      opt.value = ag.id;
      opt.textContent = 'Recenzent: ' + ag.id;
      revSelect.appendChild(opt);
    });

    optsRow.appendChild(planLbl);
    optsRow.appendChild(wtLbl);
    optsRow.appendChild(revSelect);
    room.appendChild(optsRow);

    const goalInput = document.createElement('textarea');
    goalInput.id = 'team-goal';
    goalInput.rows = 3;
    goalInput.placeholder = 'Opisz wspólny cel projektu dla zespołu agentów…';
    goalInput.setAttribute('aria-label', 'Cel projektu zespołowego');
    room.appendChild(goalInput);

    const actionsRow = el('div', 'team-row');
    const startBtn = el('button', 'agent-action primary', 'Uruchom zespół');
    startBtn.type = 'button';
    const stopBtn = el('button', 'agent-action danger', 'Zatrzymaj');
    stopBtn.type = 'button';
    const diffBtn = el('button', 'agent-action', 'Diff outbox');
    diffBtn.type = 'button';
    const applyBtn = el('button', 'agent-action', 'Wdróż outbox');
    applyBtn.type = 'button';
    actionsRow.appendChild(startBtn);
    actionsRow.appendChild(stopBtn);
    actionsRow.appendChild(diffBtn);
    actionsRow.appendChild(applyBtn);
    room.appendChild(actionsRow);

    const chatRow = el('div', 'team-row');
    const chatInput = document.createElement('input');
    chatInput.type = 'text';
    chatInput.id = 'team-chat';
    chatInput.placeholder = 'Napisz na czat zespołu (np. @hermes dodaj testy)';
    chatInput.setAttribute('aria-label', 'Wiadomość do zespołu');
    const sendChatBtn = el('button', 'agent-action', 'Wyślij');
    sendChatBtn.type = 'button';
    chatRow.appendChild(chatInput);
    chatRow.appendChild(sendChatBtn);
    room.appendChild(chatRow);

    const output = el('pre', 'agent-output team-log', 'Wybierz istniejący projekt lub uruchom nową falę zespołową.');
    room.appendChild(output);

    const status = document.getElementById('team-status');

    async function refreshTeamView() {
      try {
        const listData = await getJSON('/agents/team');
        const projects = listData.projects || [];
        const currentVal = selectedTeamProject || projSelect.value;
        projSelect.textContent = '';
        const baseOpt = document.createElement('option');
        baseOpt.value = '';
        baseOpt.textContent = '+ Nowy projekt zespołowy';
        projSelect.appendChild(baseOpt);
        projects.forEach(function (p) {
          const o = document.createElement('option');
          o.value = p.id;
          // The drawer is wide, but a slug still eats the row: keep the title head
          // and put the full id, status and round in the tooltip.
          const label = (p.title || p.id);
          o.textContent = label.length > 48 ? label.slice(0, 47) + '…' : label;
          o.title = p.id + ' — ' + label + ' [' + p.status + ' • r' + p.current_round + ']';
          projSelect.appendChild(o);
        });
        if (currentVal && projects.some(function (p) { return p.id === currentVal; })) {
          projSelect.value = currentVal;
        } else if (!currentVal && !teamTouched && projects.length) {
          // Only the very first load picks a project for you; an explicit choice of
          // "+ Nowy projekt zespołowy" must survive the refresh.
          projSelect.value = projects[0].id;
          selectedTeamProject = projects[0].id;
        }
        const pid = projSelect.value;
        const chip = teamChip();
        if (!pid) {
          lastTeamStatus = 'zespół';
          if (chip) chip.textContent = lastTeamStatus;
          if (status) status.textContent = 'Nowy projekt: wybierz członków, wpisz cel i uruchom falę.';
          output.textContent = 'Tryb tworzenia nowego projektu zespołowego.';
          return;
        }
        const st = await getJSON('/agents/team?project_id=' + encodeURIComponent(pid));
        lastTeamStatus = st.status || 'gotowy';
        if (chip) chip.textContent = lastTeamStatus;
        const budget = st.budget || {};
        const gate = st.last_gate ? (st.last_gate.ok ? 'PASS' : 'FAIL') : 'brak';
        const locks = Object.keys(st.locks || {}).map(function (k) {
          return k + ' -> ' + st.locks[k].agent;
        }).join(', ') || 'brak';
        if (status) {
          status.textContent = st.phase + ' · runda ' + st.current_round + '/' + st.max_rounds
            + ' · bramka ' + gate
            + ' · budżet ' + (budget.used_runs || 0) + '/' + (budget.max_total_runs || 12)
            + ' · blokady: ' + locks;
        }
        const lines = (st.messages || []).slice(-30).map(function (m) {
          const target = m.to && m.to !== 'all' ? (' -> ' + m.to) : '';
          return '[' + (m.iso || '').slice(11) + '] ' + m.sender + target + ': ' + m.text;
        });
        output.textContent = lines.length ? lines.join('\n') : 'Czat jest pusty — napisz pierwszą wiadomość.';
      } catch (e) {
        if (status) status.textContent = 'Nie udało się pobrać stanu zespołu.';
        output.textContent = 'Nie udało się pobrać stanu zespołu.';
      }
    }

    const panel = document.getElementById('team-panel');
    if (panel) panel.__refresh = refreshTeamView;

    projSelect.addEventListener('change', function () {
      selectedTeamProject = projSelect.value;
      teamTouched = true;
      refreshTeamView();
    });
    refreshProjBtn.addEventListener('click', refreshTeamView);

    startBtn.addEventListener('click', async function () {
      const chosen = memberChecks.filter(function (c) { return c.checked; }).map(function (c) { return c.value; });
      const goal = goalInput.value.trim();
      const pid = projSelect.value;
      if (!pid && !goal) {
        output.textContent = 'Podaj opis celu projektu dla zespołu.';
        return;
      }
      const res = await post('/agents/team/start', {
        project_id: pid && !goal ? pid : '',
        goal: goal,
        participants: chosen,
        review_agent: revSelect.value,
        plan_first: planCb.checked,
        use_worktrees: wtCb.checked
      });
      if (res.ok && res.payload && res.payload.ok) {
        selectedTeamProject = res.payload.project_id || pid;
        teamTouched = true;
        goalInput.value = '';
        await refreshTeamView();
      } else {
        const err = res.payload && res.payload.error;
        output.textContent = 'Błąd startu zespołu: ' + ((err && err.message) || err || 'nieznany');
      }
    });

    stopBtn.addEventListener('click', async function () {
      if (!projSelect.value) return;
      await post('/agents/team/stop', { project_id: projSelect.value });
      await refreshTeamView();
    });

    sendChatBtn.addEventListener('click', async function () {
      const pid = projSelect.value;
      const msg = chatInput.value.trim();
      if (!pid || !msg) return;
      const res = await post('/agents/team/chat', { project_id: pid, message: msg });
      if (res.ok) {
        chatInput.value = '';
        await refreshTeamView();
      }
    });

    diffBtn.addEventListener('click', async function () {
      const pid = projSelect.value;
      if (!pid) return;
      const target = window.prompt('Katalog docelowy do porównania diffa z outboxem zespołu:', '~/Jarvis');
      if (!target) return;
      try {
        const res = await getChecked('/agents/diff?agent=' + encodeURIComponent('team:' + pid) +
          '&target=' + encodeURIComponent(target.trim()));
        if (!res.ok) {
          const err = res.payload && res.payload.error;
          output.textContent = 'Błąd diffa: ' + (typeof err === 'string' ? err : ((err && err.message) || ('HTTP ' + res.status)));
          return;
        }
        const rows = (res.payload.files || []).map(function (f) {
          return '[' + f.status + '] ' + f.path + (f.diff ? '\n' + f.diff : '');
        });
        const skipped = res.payload.skipped_reports || [];
        output.textContent = (rows.length ? rows.join('\n\n') : 'Brak różnic w outboxie zespołu.') +
          (skipped.length ? '\n\nPominięto raporty: ' + skipped.join(', ') : '');
      } catch (_) {
        output.textContent = 'Nie udało się wyliczyć diffa dla zespołu.';
      }
    });

    applyBtn.addEventListener('click', async function () {
      const pid = projSelect.value;
      if (!pid) return;
      const target = window.prompt('Docelowy katalog do wdrożenia outboxa zespołu:', '~/Jarvis');
      if (!target) return;
      const res = await post('/agents/apply', { agent: 'team:' + pid, target: target.trim(), confirm: true });
      if (res.ok && res.payload && res.payload.ok) {
        const skipped = res.payload.skipped_reports || [];
        output.textContent = 'Wdrożono ' + res.payload.applied + ' plików zespołu:\n' +
          (res.payload.files || []).join('\n') +
          (skipped.length ? '\n\nPominięto raporty (nie są plikami projektu): ' + skipped.join(', ') : '');
      } else {
        const err = res.payload && res.payload.error;
        output.textContent = 'Błąd wdrożenia: ' + ((err && err.message) || err || 'nieznany');
      }
    });

    // A running wave changes state on its own: keep the room live while it is open.
    setInterval(function () {
      if (!document.hidden && !panel.hidden) refreshTeamView();
    }, 8000);
  }

  function renderStateOnly(payload) {
    // An open panel must not be rebuilt (it would wipe a half-typed task), but the
    // chips still have to tell the truth while a run finishes.
    (payload.agents || []).forEach(function (agent) {
      const tile = LIST.querySelector('.agent-tile[data-agent="' + agent.id + '"]');
      if (!tile) return;
      const state = stateOf(agent);
      tile.dataset.state = state;
      const chip = tile.querySelector('.agent-state');
      if (chip) chip.textContent = stateText(state);
    });
  }

  function render(payload) {
    const agents = payload.agents || [];
    LIST.textContent = '';
    LIST.setAttribute('aria-busy', 'false');
    if (!agents.length) {
      LIST.appendChild(el('p', 'agent-empty', 'Serwer nie zwrócił żadnego agenta.'));
      return;
    }
    LIST.appendChild(buildTeamTile(agents));
    agents.forEach(function (agent) { LIST.appendChild(tile(agent)); });
  }

  async function load(forced) {
    if (busy) return;
    busy = true;
    if (!LIST.children.length) {
      LIST.setAttribute('aria-busy', 'true');
      LIST.textContent = '';
      LIST.appendChild(el('p', 'agent-empty', 'Wczytywanie agentów...'));
    }
    try {
      const payload = await getJSON(forced ? '/agents?refresh=1' : '/agents');
      if (LIST.querySelector('.agent-details[open]')) renderStateOnly(payload);
      else render(payload);
    } catch (_) {
      LIST.setAttribute('aria-busy', 'false');
      LIST.textContent = '';
      LIST.appendChild(el('p', 'agent-empty', 'Nie mogę odczytać agentów — sprawdź, czy serwer działa.'));
    } finally {
      busy = false;
    }
  }

  if (REFRESH) REFRESH.addEventListener('click', function () { load(true); });
  const teamClose = document.getElementById('team-close');
  if (teamClose) teamClose.addEventListener('click', closeTeamRoom);
  document.addEventListener('keydown', function (ev) {
    const panel = document.getElementById('team-panel');
    if (ev.key === 'Escape' && panel && !panel.hidden) closeTeamRoom();
  });
  // Coming back to the window should show the real state at once instead of the
  // snapshot from before the tab went hidden.
  document.addEventListener('visibilitychange', function () {
    if (!document.hidden) load();
  });
  load();
  timer = setInterval(function () {
    if (document.hidden) return;
    load(); // an open panel is refreshed chip-only, never rebuilt
  }, POLL_MS);
  window.addEventListener('beforeunload', function () { if (timer) clearInterval(timer); });
})();
