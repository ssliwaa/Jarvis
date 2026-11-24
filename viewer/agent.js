'use strict';
// Browser-agent panel. The server owns the agent thread; this file only starts,
// polls, renders narration and sends explicit approvals/stops.
(() => {
  const $ = id => document.getElementById(id);
  const panel = $('agent-panel');
  const toggle = $('agent-toggle');
  const form = $('agent-form');
  const task = $('agent-task');
  const status = $('agent-status');
  const steps = $('agent-steps');
  const subagents = $('agent-subagents');
  const subagentsWrap = $('agent-subagents-wrap');
  const pending = $('agent-pending');
  const pendingText = $('agent-pending-text');
  const shot = $('agent-shot');
  const start = $('agent-start');
  const stop = $('agent-stop');
  const approve = $('agent-approve');
  const deny = $('agent-deny');
  const modeSelect = $('agent-mode');
  const modeNote = $('agent-mode-note');
  const historyList = $('agent-history-list');
  const ocrButton = $('agent-ocr');
  const ocrText = $('agent-ocr-text');
  const chatCard = $('chat-operator-card');
  const chatStatus = $('chat-operator-status');
  const chatSteps = $('chat-operator-steps');
  const chatStop = $('chat-operator-stop');
  const chatPending = $('chat-operator-pending');
  const chatPendingText = $('chat-operator-pending-text');
  const chatApprove = $('chat-operator-approve');
  const chatDeny = $('chat-operator-deny');
  const chatPlan = $('chat-operator-plan');
  const planBox = $('task-plan-box');
  const planTask = $('task-plan-task');
  const planCounter = $('task-plan-counter');
  const planFill = $('task-plan-progress-fill');
  const planList = $('task-plan-list');
  const planState = $('task-plan-state');
  const planClose = $('task-plan-close');
  if (planClose && planBox) {
    planClose.addEventListener('click', () => { planBox.hidden = true; });
  }
  let chatCardActive = false;
  let approvalToken = null;
  const MAX_AGENT_STEPS = 18;
  const MAX_CHAT_STEPS = 14;
  const MODE_NOTES = {
    safe: 'Safe: reads are free; writes, shell, desktop input and credentials ask first.',
    standard: 'Standard: shell and files are live; destructive actions, deletion and credentials ask first.',
    full: 'Full: autonomous operator. It can run destructive commands and use credentials without asking. You have been warned.',
  };
  let jobId = null;
  let timer = null;
  let lastStep = 0;
  let lastSay = 0;
  let lastJobState = null;
  let sayQueue = [];
  let statusSequence = 0;
  let pollFailures = 0;
  let shotKey = '';

  function setStatus(text, state = 'idle') {
    if (status) {
      status.textContent = text;
      status.dataset.state = state;
    }
    if (chatStatus) {
      chatStatus.textContent = text;
      chatStatus.dataset.state = state;
    }
  }

  function active(status) {
    return ['queued', 'running', 'awaiting_approval'].includes(status);
  }

  function post(path, body) {
    return fetch(path, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    }).then(async response => {
      const payload = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(payload.answer || payload.error?.message || `Request failed (${response.status}).`);
      return payload;
    });
  }

  function renderSteps(snapshot) {
    const rows = Array.isArray(snapshot.steps) ? snapshot.steps : [];
    const fresh = rows.filter(row => row.n > lastStep);
    if (fresh.length) {
      for (const row of fresh) {
        if (steps) {
          const item = document.createElement('li');
          item.className = `agent-step ${row.kind || ''}`;
          const number = document.createElement('b');
          number.textContent = String(row.n).padStart(2, '0');
          const text = document.createElement('span');
          text.textContent = row.text || row.kind || '';
          item.append(number, text);
          steps.append(item);
        }
        if (chatSteps) {
          const chatItem = document.createElement('li');
          chatItem.className = `chat-operator-step ${row.kind || ''}`;
          const chatNumber = document.createElement('b');
          chatNumber.textContent = String(row.n).padStart(2, '0');
          const chatText = document.createElement('span');
          chatText.textContent = row.text || row.kind || '';
          chatItem.append(chatNumber, chatText);
          chatSteps.append(chatItem);
        }
        if (row.n > lastStep) lastStep = row.n;
      }
      if (steps) {
        while (steps.children.length > MAX_AGENT_STEPS) steps.firstElementChild.remove();
        steps.scrollTop = steps.scrollHeight;
      }
      if (chatSteps) {
        while (chatSteps.children.length > MAX_CHAT_STEPS) chatSteps.firstElementChild.remove();
        chatSteps.scrollTop = chatSteps.scrollHeight;
      }
    }
    const voice = window.galaxy?.voice;
    for (const row of fresh) {
      if (row.kind !== 'say' || row.n <= lastSay) continue;
      lastSay = row.n;
      // Keep narration short and never bypass the mute/echo guard. A Polish
      // step must not reach an English voice when translation was unavailable.
      const readable = !row.lang || row.lang === voice?.replyLanguage;
      if (readable && row.text) sayQueue.push(row.text);
    }
    pumpNarration();
  }

  function renderSubagents(job) {
    if (!subagents || !subagentsWrap) return;
    const rows = Array.isArray(job.subagents) ? job.subagents : [];
    subagentsWrap.hidden = rows.length === 0;
    subagents.replaceChildren();
    for (const row of rows.slice(-8)) {
      const item = document.createElement('li');
      const title = document.createElement('b');
      title.textContent = `${row.subagent_id || 'subagent'} · ${row.status || '?'}`;
      const goal = document.createElement('span');
      goal.textContent = row.goal || '';
      const meta = document.createElement('small');
      const usage = row.usage || {};
      const stepSuffix = row.last_step ? ` · ${row.last_step}` : '';
      meta.textContent = `${row.running_seconds ?? 0}s · ${row.tool_count || 0} tools · ${usage.total_tokens || 0} tokens${stepSuffix}`;
      item.append(title, goal, meta);
      subagents.append(item);
    }
  }

  function pumpNarration() {
    if (!sayQueue.length) return;
    const voice = window.galaxy?.voice;
    if (!voice || typeof voice.speak !== 'function') {
      sayQueue = [];
      return;
    }
    if (voice.speaking) {
      // A step that arrived while the voice was busy used to be marked as
      // read and silently dropped. Keep it queued and poll the voice.
      setTimeout(pumpNarration, 1200);
      return;
    }
    const text = sayQueue.shift();
    try { voice.speak(text); } catch (_) {}
    if (sayQueue.length) setTimeout(pumpNarration, 1400);
  }

  function showMode(mode) {
    if (!modeSelect || !mode || !MODE_NOTES[mode]) return;
    modeSelect.value = mode;
    modeNote.textContent = MODE_NOTES[mode];
    modeSelect.classList.toggle('danger', mode === 'full');
  }

  function renderPlan(plan, taskText, statusState) {
    if (!planBox) return;
    if (!plan || !Array.isArray(plan.phases) || plan.phases.length === 0) {
      if (statusState === 'idle' || !statusState) {
        planBox.hidden = true;
      }
      return;
    }
    planBox.hidden = false;
    if (planTask && taskText) {
      planTask.textContent = taskText;
    }
    const total = plan.total || plan.phases.length;
    const done = plan.done != null ? plan.done : plan.phases.filter(p => p.done).length;
    const pct = total > 0 ? Math.round((done / total) * 100) : 0;

    if (planCounter) planCounter.textContent = `${done}/${total} (${pct}%)`;
    if (planFill) planFill.style.width = `${pct}%`;
    if (planState) {
      if (done === total && total > 0) {
        planState.textContent = 'UKOŃCZONE';
        planState.style.background = 'rgba(16, 185, 129, 0.25)';
      } else {
        planState.textContent = 'W TOKU';
        planState.style.background = 'rgba(56, 189, 248, 0.15)';
      }
    }

    const frag = document.createDocumentFragment();
    let foundActive = false;
    plan.phases.forEach((phase, idx) => {
      const item = document.createElement('li');
      const isDone = Boolean(phase.done);
      let isActive = false;
      if (!isDone && !foundActive) {
        isActive = true;
        foundActive = true;
      }
      item.className = `task-plan-item ${isDone ? 'is-done' : (isActive ? 'is-active' : '')}`;

      const check = document.createElement('span');
      check.className = 'task-plan-check';
      check.textContent = isDone ? '✔' : (isActive ? '●' : '○');

      const text = document.createElement('span');
      text.className = 'task-plan-text';
      text.textContent = phase.text || `Punkt ${idx + 1}`;

      item.append(check, text);
      frag.append(item);
    });

    if (planList) {
      planList.replaceChildren(frag);
    }
  }

  function render(snapshot) {
    showMode(snapshot.mode);
    const job = snapshot.job;
    if (!job) {
      if (subagents) subagents.replaceChildren();
      if (subagentsWrap) subagentsWrap.hidden = true;
      if (planBox) planBox.hidden = true;
      if (chatPlan) chatPlan.hidden = true;
      setStatus(snapshot.available === false ? 'Operator lane unavailable.' : 'Idle. Give me a task.', 'idle');
      if (start) start.disabled = snapshot.available === false;
      if (stop) stop.hidden = true;
      if (chatStop) chatStop.hidden = true;
      return;
    }
    jobId = job.id;
    showMode(job.mode);
    renderSteps(job);
    renderSubagents(job);
    const state = job.status || 'idle';
    renderPlan(job.plan, job.task, state);
    if (lastJobState && lastJobState !== state && ['done', 'error', 'stopped'].includes(state)) {
      try {
        if ('Notification' in window && Notification.permission === 'granted') {
          new Notification('Jarvis Operator', {
            body: state === 'done' ? (job.summary || 'Task finished.') : (job.error || `Task ${state}.`),
          });
        }
      } catch (_) {}
      if (chatCardActive) {
        const chatAns = $('chat-answer');
        const chatSt = $('chat-state');
        if (state === 'done') {
          const outcome = job.summary ? `Operator completed: ${job.summary}` : 'Operator finished the task.';
          if (chatAns) chatAns.textContent = outcome;
          if (chatSt) chatSt.textContent = 'Done · Operator task finished';
          const voice = window.galaxy?.voice;
          if (voice && typeof voice.speak === 'function' && job.summary) {
            try { voice.speak(job.summary); } catch (_) {}
          }
        } else if (state === 'error') {
          const errText = job.error || 'The Operator stopped with an error.';
          if (chatAns) chatAns.textContent = errText;
          if (chatSt) chatSt.textContent = 'Error · Operator task failed';
        } else if (state === 'stopped') {
          if (chatAns) chatAns.textContent = 'The Operator task was stopped.';
          if (chatSt) chatSt.textContent = 'Stopped · task cancelled';
        }
      }
    }
    lastJobState = state;
    const label = state === 'awaiting_approval' ? 'Waiting for approval'
      : state === 'running' ? 'Working'
        : state === 'done' ? 'Done' : state === 'error' ? 'Stopped with an error' : state === 'stopped' ? 'Stopped' : 'Starting';
    const display = state === 'done' ? `Done — ${job.summary || 'finished.'}`
      : state === 'error' ? (job.error || 'The agent stopped with an error.')
        : (job.summary || job.error || label);
    setStatus(display, state);
    if (chatStatus) {
      chatStatus.textContent = label;
      chatStatus.dataset.state = state;
    }
    if (start) start.disabled = active(state);
    if (stop) stop.hidden = !active(state);
    if (chatStop) chatStop.hidden = !active(state);
    if (job.pending) {
      if (pending) pending.hidden = false;
      if (chatPending) chatPending.hidden = false;
      approvalToken = job.pending.token || null;
      const approvalMsg = `${job.pending.risk === 'critical' ? 'CRITICAL · ' : ''}${job.pending.reason} The agent wants to ${job.pending.name}.` +
        (job.pending.args ? `\nRequest: ${job.pending.args}` : '') +
        (job.pending.detail ? `\n\n${job.pending.detail}` : '') +
        '\nOne-time approval token is attached to this decision.';
      if (pendingText) pendingText.textContent = approvalMsg;
      if (chatPendingText) chatPendingText.textContent = approvalMsg;
    } else {
      if (pending) pending.hidden = true;
      if (chatPending) chatPending.hidden = true;
      approvalToken = null;
    }
    if (job.has_screenshot && shot) {
      shot.hidden = false;
      // A new Date.now() on every 900 ms poll made the PNG reload constantly.
      // Refresh only when the job or its last recorded step changes.
      const stepCount = Array.isArray(job.steps) ? job.steps.length : 0;
      const nextKey = `${job.id}:${stepCount}`;
      if (shotKey !== nextKey) {
        shotKey = nextKey;
        shot.src = `/agent/screenshot?job_id=${encodeURIComponent(job.id)}&t=${Date.now()}`;
      }
    }
    if (active(state)) schedule();
    else { clearTimeout(timer); loadHistory(); }
  }

  function schedule() {
    clearTimeout(timer);
    const activeInChat = chatCardActive && chatCard && !chatCard.hidden;
    if (panel.hidden && !activeInChat) return;
    timer = setTimeout(poll, 900);
  }

  function poll() {
    const activeInChat = chatCardActive && chatCard && !chatCard.hidden;
    if (!jobId || (panel.hidden && !activeInChat)) return;
    fetch(`/agent/status?job_id=${encodeURIComponent(jobId)}`, { cache: 'no-store' })
      .then(async response => {
        const payload = await response.json().catch(() => ({}));
        if (!response.ok) throw new Error(payload.answer || 'Agent status unavailable.');
        pollFailures = 0;
        render(payload);
      })
      .catch(error => {
        setStatus(error.message || 'Agent status unavailable.', 'error');
        clearTimeout(timer);
        // One transient blip used to stop the panel forever while the job
        // kept running. Retry a few times before giving up.
        pollFailures += 1;
        if (pollFailures <= 3 && (!panel.hidden || activeInChat)) schedule();
      });
  }

  function resetView() {
    lastStep = 0;
    lastSay = 0;
    sayQueue = [];
    shotKey = '';
    if (steps) steps.replaceChildren();
    if (chatSteps) chatSteps.replaceChildren();
    if (pending) pending.hidden = true;
    if (chatPending) chatPending.hidden = true;
    if (shot) {
      shot.hidden = true;
      shot.removeAttribute('src');
    }
  }

  function renderHistory(rows) {
    if (!historyList) return;
    historyList.replaceChildren();
    for (const row of rows || []) {
      const item = document.createElement('li');
      const state = String(row.status || 'done');
      item.className = `agent-history-row ${state}`;
      const label = document.createElement('b');
      label.textContent = `${state} · ${row.id || ''}`;
      const text = document.createElement('span');
      text.textContent = row.summary || row.error || '';
      item.append(label, text);
      historyList.append(item);
    }
  }

  function loadHistory() {
    if (!historyList) return;
    const filter = $('agent-history-filter')?.value || '';
    fetch('/agent/history' + (filter ? `?status=${encodeURIComponent(filter)}` : ''), { cache: 'no-store' })
      .then(response => response.ok ? response.json() : { history: [] })
      .then(payload => renderHistory(payload.history))
      .catch(() => renderHistory([]));
  }

  $('agent-history-filter')?.addEventListener('change', loadHistory);

  function openPanel() {
    try { window.galaxyStudio?.close?.(); } catch (_) {}
    try { window.galaxyTeam?.close?.(); } catch (_) {}
    try {
      if ('Notification' in window && Notification.permission === 'default') Notification.requestPermission();
    } catch (_) {}
    panel.hidden = false;
    toggle.setAttribute('aria-expanded', 'true');
    task.focus();
    loadHistory();
    const sequence = ++statusSequence;
    fetch('/agent/status', { cache: 'no-store' })
      .then(response => response.json())
      .then(payload => {
        if (sequence !== statusSequence) return;  // a newer job owns the panel
        const id = payload.job?.id || null;
        if (id !== jobId) {
          jobId = id;
          lastJobState = null;
          resetView();
        }
        render(payload);
      })
      .catch(() => setStatus('The browser agent is unavailable.', 'error'));
  }

  function closePanel() {
    panel.hidden = true;
    toggle.setAttribute('aria-expanded', 'false');
    if (!chatCardActive) {
      statusSequence += 1;
      sayQueue = [];
      clearTimeout(timer);
    }
  }

  toggle?.addEventListener('click', () => panel.hidden ? openPanel() : closePanel());
  $('agent-close')?.addEventListener('click', closePanel);
  modeSelect?.addEventListener('change', () => {
    const mode = modeSelect.value;
    setStatus(`Switching to ${mode} autonomy…`, 'running');
    post('/agent/mode', { mode })
      .then(render)
      .catch(error => setStatus(error.message, 'error'));
  });
  ocrButton?.addEventListener('click', () => {
    if (ocrButton.disabled) return;
    ocrButton.disabled = true;
    if (ocrText) { ocrText.hidden = false; ocrText.textContent = 'Reading the latest screenshot with local OCR…'; }
    fetch('/agent/ocr', { cache: 'no-store' })
      .then(response => response.json().then(body => ({ ok: response.ok, body })))
      .then(({ ok, body }) => {
        if (ocrText) ocrText.textContent = ok
          ? (body.text || 'The screenshot contains no readable text.')
          : (body.answer || 'The screenshot could not be read.');
      })
      .catch(error => { if (ocrText) ocrText.textContent = error.message; })
      .finally(() => { ocrButton.disabled = false; });
  });
  form?.addEventListener('submit', event => {
    event.preventDefault();
    const value = task.value.trim();
    if (!value) return;
    start.disabled = true;
    statusSequence += 1;  // invalidate a status fetch already in flight
    pollFailures = 0;
    setStatus('Starting a separate Chromium window…', 'running');
    resetView();
    // Speak the steps in the same language as the selected output voice.
    const language = window.galaxy?.voice?.replyLanguage;
    post('/agent/run', { task: value, queue: true, ...(language ? { language } : {}) })
      .then(snapshot => { jobId = snapshot.job?.id || snapshot.id; render({ job: snapshot }); })
      .catch(error => { start.disabled = false; setStatus(error.message, 'error'); });
  });
  function handleStop() {
    if (!jobId) return;
    post('/agent/stop', { job_id: jobId })
      .then(snapshot => render({ job: snapshot }))
      .catch(error => setStatus(error.message, 'error'));
  }

  function handleDecision(decision) {
    if (!jobId) return;
    post('/agent/approve', { job_id: jobId, approve: decision, token: approvalToken })
      .then(poll)
      .catch(error => setStatus(error.message, 'error'));
  }

  stop?.addEventListener('click', handleStop);
  chatStop?.addEventListener('click', handleStop);
  approve?.addEventListener('click', () => handleDecision(true));
  chatApprove?.addEventListener('click', () => handleDecision(true));
  deny?.addEventListener('click', () => handleDecision(false));
  chatDeny?.addEventListener('click', () => handleDecision(false));

  window.galaxyAgent = {
    open: openPanel,
    close: closePanel,
    start(value, opts = {}) {
      const val = String(value || '').trim();
      if (!val) return false;
      task.value = val;
      chatCardActive = true;
      if (chatCard) chatCard.hidden = false;
      if (opts.openPanel || (!opts.fromChat && panel.hidden && !chatCard)) {
        openPanel();
      }
      if (start) start.disabled = true;
      statusSequence += 1;
      pollFailures = 0;
      setStatus('Starting Operator…', 'running');
      resetView();
      const language = window.galaxy?.voice?.replyLanguage;
      post('/agent/run', { task: val, queue: true, ...(language ? { language } : {}) })
        .then(snapshot => { jobId = snapshot.job?.id || snapshot.id; render({ job: snapshot }); })
        .catch(error => { if (start) start.disabled = false; setStatus(error.message, 'error'); });
      return true;
    },
    attach(id, opts = {}) {
      if (!id) return false;
      statusSequence += 1;
      jobId = String(id);
      chatCardActive = true;
      if (chatCard) chatCard.hidden = false;
      if (opts.openPanel || (!opts.fromChat && panel.hidden && !chatCard)) {
        openPanel();
      }
      resetView();
      poll();
      return true;
    },
    status: () => jobId,
    renderPlan: (plan, task, state) => renderPlan(plan, task, state),
  };
})();
