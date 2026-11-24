'use strict';

(() => {
  const $ = id => document.getElementById(id);
  const motion = window.matchMedia('(prefers-reduced-motion: reduce)');
  const REMEMBER_PATTERN = /^remember\s+that\b[\s:,-]*([\s\S]*)$/i;
  const TEARDOWN_PATTERN = /^(?:tear\s*down|teardown)\s+((?:https?:\/\/)?[^\s]+)(?:\s+([\s\S]*))?$/i;
  const TEARDOWN_STEP_LABELS = [
    'Opening the site in a clean browser',
    'Waiting for it to load',
    'REA is watching while I scroll',
    'REA is reading the code',
    'Taking a snapshot',
    'Listing everything it loaded',
    'Identifying the stack',
    'Writing the teardown'
  ];
  const BIRTH_PULSE_MS = 650;
  const SETTINGS_KEY = 'galaxy.display';
  const DISPLAY_DEFAULTS = Object.freeze({
    repel: 42, linkLength: 40, labels: true, particles: true, rotate: true, stars: true,
    connections: true, linkWeight: 30, nodeScale: 100, menuScale: 100, theme: 'emerald', colorMode: 'type'
  });
  const palette = ['#3ddc97', '#f5b942', '#f472b6', '#60a5fa', '#a78bfa', '#22d3ee', '#fb923c', '#2dd4bf'];
  const source = typeof GRAPH !== 'undefined' ? GRAPH : { nodes: [], links: [] };
  const nodes = Array.isArray(source.nodes) ? source.nodes.map(node => ({ ...node })) : [];
  const byId = new Map(nodes.map(node => [node.id, node]));
  const endpointId = endpoint => typeof endpoint === 'object' && endpoint !== null ? endpoint.id : endpoint;
  const links = Array.isArray(source.links) ? source.links
    .map(link => ({ source: endpointId(link.source), target: endpointId(link.target) }))
    .filter(link => byId.has(link.source) && byId.has(link.target)) : [];
  const adjacency = new Map(nodes.map(node => [node.id, new Set()]));
  links.forEach(link => {
    if (link.source !== link.target) {
      adjacency.get(link.source).add(link.target);
      adjacency.get(link.target).add(link.source);
    }
  });
  const groups = [...new Set(nodes.map(node => node.group))].sort((a, b) => String(a).localeCompare(String(b)));
  const colors = new Map(groups.map((group, i) => [group, palette[i % palette.length]]));
  const sprites = new Map();
  let graph = null;
  let selectedId = null;
  let neighbourIds = new Set();
  let sourceIds = new Set();
  let activeGroup = null;
  let rotating = !motion.matches;
  let ready = false;
  let graphError = null;
  let busy = false;
  let lastInteraction = 0;
  // The 3D loop is decorative. Running it while the window sits unfocused on a
  // desk held a whole core and spun the fan, so it pauses when nobody is looking.
  let graphLoopPaused = false;
  let graphHostObserver = null;
  let voice = null;
  let activeRequest = null;
  let requestSequence = 0;
  let captureTail = Promise.resolve();
  let capturePending = 0;
  let teardownPending = false;
  let teardownJob = null;
  let teardownLast = null;
  let teardownPollTimer = null;
  let teardownPollSequence = 0;
  let teardownLayoutFrame = null;
  let captureRetry = null;
  let lastBirth = null;
  const groupButtons = new Map();

  let maxDegree = Math.max(1, ...nodes.map(node => adjacency.get(node.id).size));
  let colorMode = 'type';
  let particlesOn = true;
  let connectionsOn = true;
  let linkWeight = .3;
  let nodeScale = 1;
  let menuScale = 1;
  let themeName = 'emerald';
  let starfieldLayer = null;
  let followAgent = false;

  function heatColor(node) {
    const ratio = Math.min(1, adjacency.get(node.id).size / maxDegree);
    const hue = Math.round(210 - 200 * ratio);
    // three.js Color.set() only parses the comma form: "hsl(210 85% 58%)" became
    // pure white, so Heatmap mode painted every node white.
    return `hsl(${hue}, 85%, 58%)`;
  }

  function colorFor(node) {
    if (colorMode === 'heat') return heatColor(node);
    return colors.get(node.group) || palette[0];
  }

  function notice(title, detail) {
    $('notice-title').textContent = title;
    $('notice-detail').textContent = detail;
    $('graph-notice').hidden = false;
  }

  function setBrowser(open) {
    $('note-browser').hidden = !open;
    const toggle = $('browse-toggle');
    if (toggle) toggle.setAttribute('aria-expanded', String(open));
    if (open) renderSearch();
  }

  function searchNotes(query = '') {
    const normalized = String(query).trim().toLocaleLowerCase();
    return nodes.filter(node => (activeGroup === null || node.group === activeGroup)
      && String(node.label).toLocaleLowerCase().includes(normalized))
      .sort((a, b) => a.label.localeCompare(b.label));
  }

  function noteButton(node, onSelect = selectNode) {
    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'note-button';
    button.dataset.nodeId = String(node.id);
    button.setAttribute('aria-current', String(selectedId === node.id));
    const dot = document.createElement('span');
    dot.className = 'group-dot';
    dot.style.setProperty('--group-color', colorFor(node));
    dot.setAttribute('aria-hidden', 'true');
    const label = document.createElement('span');
    label.className = 'note-button-text';
    label.textContent = node.label;
    const arrow = document.createElement('span');
    arrow.className = 'note-arrow';
    arrow.textContent = '↗';
    arrow.setAttribute('aria-hidden', 'true');
    button.append(dot, label, arrow);
    button.addEventListener('click', () => onSelect(node.id, { focus: true }));
    return button;
  }

  function renderSearch() {
    const matches = searchNotes($('note-search').value);
    $('search-count').textContent = `${matches.length} ${matches.length === 1 ? 'note' : 'notes'}`;
    $('note-results').replaceChildren();
    matches.forEach(node => {
      const item = document.createElement('li');
      item.append(noteButton(node));
      $('note-results').append(item);
    });
    if (!matches.length) {
      const empty = document.createElement('li');
      empty.className = 'empty-state';
      empty.textContent = 'No notes in this part of the universe. Try another title or collection.';
      $('note-results').append(empty);
    }
  }

  function renderGroups() {
    groupButtons.clear();
    const legend = $('group-legend');
    if (!legend) return;   // filtry grup są w panelu FILTER po prawej
    legend.replaceChildren();
    function addGroup(group, label, total) {
      const button = document.createElement('button');
      button.type = 'button';
      button.className = 'group-button';
      button.setAttribute('aria-pressed', String(activeGroup === group));
      const dot = document.createElement('span');
      dot.className = 'group-dot';
      dot.style.setProperty('--group-color', group === null ? '#cfdbdf' : colors.get(group));
      dot.setAttribute('aria-hidden', 'true');
      const name = document.createElement('span');
      name.className = 'group-name';
      name.textContent = label;
      const count = document.createElement('span');
      count.className = 'group-total';
      count.textContent = String(total);
      button.append(dot, name, count);
      button.addEventListener('click', () => setGroup(group));
      groupButtons.set(group, button);
      $('group-legend').append(button);
    }
    addGroup(null, 'All collections', nodes.length);
    // Biggest hubs first: a flat alphabetical list hides the structure the graph shows.
    groups
      .map(group => [group, nodes.filter(node => node.group === group).length])
      .sort((a, b) => b[1] - a[1] || String(a[0]).localeCompare(String(b[0])))
      .forEach(([group, total]) => addGroup(group, group || 'Unfiled', total));
    renderFilters();
  }

  function setGroup(group) {
    activeGroup = groups.includes(group) ? group : null;
    groupButtons.forEach((button, key) => button.setAttribute('aria-pressed', String(key === activeGroup)));
    const summary = $('filter-summary');
    if (summary) summary.textContent = activeGroup === null ? `${groups.length} collections · one connected universe` : `Viewing ${activeGroup} · choose All collections to return`;
    if (selectedId !== null && activeGroup !== null && byId.get(selectedId).group !== activeGroup) closeNote();
    renderSearch();
    renderFilters();
    if (graph) {
      graph.nodeVisibility(node => activeGroup === null || node.group === activeGroup);
      graph.linkVisibility(linkVisibleByGroup);
    }
  }

  function isRelated(id) { return id === selectedId || neighbourIds.has(id) || sourceIds.has(id); }
  function isHighlightedLink(link) {
    const a = endpointId(link.source), b = endpointId(link.target);
    return a === selectedId || b === selectedId || (sourceIds.has(a) && sourceIds.has(b));
  }

  function linkVisibleByGroup(link) {
    if (!connectionsOn) return false;
    if (activeGroup === null) return true;
    return byId.get(endpointId(link.source)).group === activeGroup
      && byId.get(endpointId(link.target)).group === activeGroup;
  }

  function applyLinkVisibility() {
    if (graph) graph.linkVisibility(linkVisibleByGroup);
  }

  function updateHighlights() {
    const hasFocus = selectedId !== null || sourceIds.size > 0;
    sprites.forEach((sprite, id) => {
      const node = byId.get(id);
      const baseSize = (11 + Math.min(adjacency.get(id).size, 12) * .8) * nodeScale;
      const strong = id === selectedId || sourceIds.has(id);
      sprite.scale.setScalar(baseSize * (strong ? 1.75 : neighbourIds.has(id) ? 1.22 : 1));
      sprite.material.opacity = !hasFocus || isRelated(id) ? .98 : .18;
      sprite.material.color.set(strong ? '#e8faff' : colorFor(node));
    });
    if (!graph) return;
    if (!connectionsOn) {
      graph.linkOpacity(0);
      graph.linkWidth(0);
      graph.linkDirectionalParticles(0);
      return;
    }
    graph.linkOpacity(hasFocus ? .5 : .12);
    graph.linkColor(link => isHighlightedLink(link) ? '#8af0c4' : hasFocus ? '#0f241c' : '#2f5a4a');
    graph.linkWidth(link => isHighlightedLink(link) ? Math.max(.25, linkWeight * 2) : hasFocus ? 0 : linkWeight);
    graph.linkDirectionalParticles(link => !motion.matches && particlesOn && isHighlightedLink(link) ? 2 : 0);
  }

  function selectNode(idOrNode, options = {}) {
    const id = typeof idOrNode === 'object' && idOrNode !== null ? idOrNode.id : idOrNode;
    const node = byId.get(id);
    if (!node) return false;
    if (activeGroup !== null && node.group !== activeGroup) setGroup(null);
    selectedId = node.id;
    neighbourIds = new Set(adjacency.get(node.id));
    lastInteraction = performanceNow();
    $('note-title').textContent = node.label;
    $('note-group').textContent = node.group || 'Unfiled';
    $('note-group').style.color = colorFor(node);
    $('note-path').textContent = node.path;
    $('note-excerpt').textContent = node.excerpt || 'This note has no text excerpt yet.';
    $('note-panel').hidden = false;
    $('neighbour-count').textContent = String(neighbourIds.size);
    $('neighbour-list').replaceChildren();
    [...neighbourIds].sort((a, b) => byId.get(a).label.localeCompare(byId.get(b).label)).forEach(id => {
      const item = document.createElement('li');
      item.append(noteButton(byId.get(id)));
      $('neighbour-list').append(item);
    });
    if (!neighbourIds.size) {
      const empty = document.createElement('li');
      empty.className = 'empty-state';
      empty.textContent = 'An undiscovered connection. This note has no linked neighbours yet.';
      $('neighbour-list').append(empty);
    }
    if (window.innerWidth <= 600) setBrowser(false);
    renderSearch();
    updateHighlights();
    if (graph && Number.isFinite(node.x) && Number.isFinite(node.y) && Number.isFinite(node.z)) {
      const distance = window.innerWidth < 700 ? 210 : 175;
      const length = Math.hypot(node.x, node.y, node.z) || 1;
      const ratio = 1 + distance / length;
      const position = length <= 1 ? { x: node.x, y: node.y + 40, z: node.z + distance }
        : { x: node.x * ratio, y: node.y * ratio + 25, z: node.z * ratio };
      graph.cameraPosition(position, node, motion.matches ? 0 : 1350);
      graph.controls().autoRotate = false;
    }
    if (options.focus) $('note-panel').focus({ preventScroll: true });
    return true;
  }

  function closeNote() {
    selectedId = null;
    neighbourIds.clear();
    $('note-panel').hidden = true;
    updateHighlights();
  }

  function performanceNow() { return Date.now(); }

  async function addNote(capture) {
    // ONE DOOR for every future birth: merge, link, pulse, then fly/select.
    const id = capture?.node?.id;
    if (!Number.isInteger(id)) throw new Error('INVALID_CAPTURE_GRAPH');
    const snapshot = capture.graph || { nodes: [...nodes, capture.node], links: [...links, ...(capture.links || [])] };
    if (!Array.isArray(snapshot.nodes) || !Array.isArray(snapshot.links) || snapshot.nodes.length < nodes.length) throw new Error('INVALID_CAPTURE_GRAPH');
    snapshot.nodes.forEach((node, index) => {
      if (node.id !== index || !['label', 'group', 'excerpt', 'path'].every(key => typeof node[key] === 'string')
          || (byId.has(index) && byId.get(index).path !== node.path)) throw new Error('GRAPH_RELOAD_REQUIRED');
    });
    const incomingLinks = snapshot.links.map(link => ({ source: endpointId(link.source), target: endpointId(link.target) }));
    if (!snapshot.nodes[id] || incomingLinks.some(link => !Number.isInteger(link.source) || !Number.isInteger(link.target)
        || link.source < 0 || link.target < 0 || link.source >= snapshot.nodes.length || link.target >= snapshot.nodes.length)) throw new Error('INVALID_CAPTURE_GRAPH');
    const alreadyPresent = byId.has(id);
    const anchor = byId.get(capture.related) || nodes.find(node => node.id !== id);
    const position = { x: Number.isFinite(anchor?.x) ? anchor.x : 0, y: Number.isFinite(anchor?.y) ? anchor.y : 0, z: Number.isFinite(anchor?.z) ? anchor.z : 0 };
    const additions = [];
    snapshot.nodes.forEach(row => {
      if (!byId.has(row.id)) {
        const node = { ...row, ...position, fx: position.x, fy: position.y, fz: position.z };
        nodes.push(node);
        additions.push(node);
        byId.set(node.id, node);
        adjacency.set(node.id, new Set());
      }
      if (!colors.has(row.group)) {
        colors.set(row.group, palette[groups.length % palette.length]);
        groups.push(row.group);
      }
    });
    groups.sort((a, b) => String(a).localeCompare(String(b)));
    links.splice(0, links.length, ...incomingLinks);
    adjacency.forEach(neighbours => neighbours.clear());
    links.forEach(link => {
      if (link.source !== link.target) {
        adjacency.get(link.source).add(link.target);
        adjacency.get(link.target).add(link.source);
      }
    });
    maxDegree = Math.max(1, ...nodes.map(node => adjacency.get(node.id).size));
    renderGroups();
    setGroup(null);
    $('node-count').textContent = String(nodes.length);
    $('link-count').textContent = String(links.length);
    $('system-state').textContent = `${nodes.length} notes in orbit`;
    if (graph) {
      // The engine mutates endpoints and ticks asynchronously: never share arrays.
      graph.warmupTicks(0).graphData({ nodes: [...nodes], links: links.map(link => ({ source: endpointId(link.source), target: endpointId(link.target) })) });
      graph.d3ReheatSimulation();
    }
    const node = byId.get(id);
    const releaseAndSelect = () => {
      // Release all snapshot additions, including captures from another open tab.
      additions.forEach(n => { delete n.fx; delete n.fy; delete n.fz; });
      updateHighlights();
      selectNode(id, { focus: true });
      if (graph) graph.d3ReheatSimulation();
    };
    if (alreadyPresent) { releaseAndSelect(); return node; }
    lastBirth = { id, related: anchor?.id ?? null, position, pulseActive: Boolean(graph && !motion.matches) };
    if (graph && !motion.matches) {
      await new Promise(resolve => {
        const start = performanceNow();
        let finished = false;
        const finish = () => {
          if (finished) return;
          finished = true;
          lastBirth.pulseActive = false;
          releaseAndSelect();
          resolve();
        };
        // The timeout also completes captures in background tabs where RAF pauses.
        setTimeout(finish, BIRTH_PULSE_MS);
        const pulse = () => {
          if (finished) return;
          const sprite = sprites.get(id);
          if (sprite) {
            const phase = Math.min(1, (performanceNow() - start) / BIRTH_PULSE_MS);
            sprite.scale.setScalar(24 + Math.sin(phase * Math.PI) * 28);
            sprite.material.opacity = 1;
            sprite.material.color.set('#ffffff');
          }
          requestAnimationFrame(pulse);
        };
        requestAnimationFrame(pulse);
      });
    } else releaseAndSelect();
    return node;
  }

  function rememberNote(text) {
    const content = String(text || '').trim();
    const key = captureRetry?.text === content ? captureRetry.key : window.crypto?.randomUUID?.();
    capturePending++;
    const operation = captureTail.then(async () => {
      if (activeRequest) cancelQuestion();
      if (voice) { voice.stopSpeaking(); voice.setThinking(true); }
      $('ask-button').disabled = true;
      $('ask-label').textContent = 'Saving';
      $('chat-form').setAttribute('aria-busy', 'true');
      $('answer-panel').hidden = false;
      $('answer-panel').classList.remove('is-error');
      $('action-receipt').hidden = true;
      setAnswerMode(null);
      renderWebSources([]);
      $('asked-question').textContent = `remember that ${content}`;
      $('chat-answer').textContent = 'Filing your note and bringing it into orbit…';
      $('chat-state').textContent = 'Saving and indexing · no confirmation until committed';
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 30000);
      let committed = false;
      try {
        const headers = { 'Content-Type': 'application/json', 'Accept': 'application/json' };
        if (key) headers['Idempotency-Key'] = key;
        const response = await fetch('/remember', { method: 'POST', credentials: 'same-origin', headers,
          body: JSON.stringify({ text: content }), signal: controller.signal });
        const payload = await response.json();
        if (!response.ok || payload.error) {
          const failure = new Error('CAPTURE_REJECTED');
          failure.captureAnswer = typeof payload.answer === 'string' ? payload.answer : null;
          throw failure;
        }
        if (payload.receipt?.status !== 'completed' || !Number.isInteger(payload.index) || payload.index !== payload.node?.id) throw new Error('INVALID_CAPTURE_RESPONSE');
        committed = true;
        await addNote(payload);
        captureRetry = null;
        $('chat-answer').textContent = payload.answer;
        $('action-receipt').textContent = `Receipt ${payload.receipt.id} · ${payload.receipt.outcome || payload.receipt.status}`;
        $('action-receipt').hidden = false;
        renderSources(payload.nodes || [payload.index]);
        setAnswerMode('notes', sourceIds.size);
        $('chat-state').textContent = `Saved and indexed · new note ${payload.index}`;
        if (voice) voice.speak(payload.answer);
        return true;
      } catch (error) {
        captureRetry = { text: content, key };
        const message = committed
          ? 'The note was saved and indexed, but I could not update this view; reload to see it.'
          : error.captureAnswer || 'I could not confirm that capture; it may have been saved, so please retry the same text.';
        $('chat-answer').textContent = message;
        $('answer-panel').classList.add('is-error');
        setAnswerMode(null);
        $('chat-state').textContent = 'Capture needs attention · your text has not been discarded';
        if (voice) voice.speak(message);
        return false;
      } finally {
        clearTimeout(timeout);
        capturePending--;
        $('ask-button').disabled = capturePending > 0;
        $('ask-label').textContent = capturePending ? 'Saving' : 'Ask';
        $('chat-form').setAttribute('aria-busy', String(capturePending > 0));
        if (voice) voice.setThinking(capturePending > 0 || busy);
      }
    });
    captureTail = operation.then(() => undefined, () => undefined);
    return operation;
  }

  function normalizeAddress(target) {
    let value = String(target || '').trim().replace(/[.,!?]+$/, '');
    if (!/^https?:\/\//i.test(value)) value = /^(?:localhost|127\.)/i.test(value) ? `http://${value}` : `https://${value}`;
    return value;
  }

  function siteFromAddress(target) {
    try {
      return new URL(normalizeAddress(target)).hostname.replace(/^www\./, '') || target;
    } catch (_) {
      return String(target || '').replace(/^https?:\/\//i, '').replace(/^www\./, '').split('/')[0] || 'site';
    }
  }

  function formatDuration(seconds) {
    const total = Math.max(0, Math.round(Number(seconds) || 0));
    return total < 60 ? `${total} s` : `${Math.floor(total / 60)} min ${total % 60} s`;
  }

  function humanBytes(value) {
    const number = Number(value) || 0;
    if (number >= 1024 * 1024) return `${(number / 1024 / 1024).toFixed(2)} MB`;
    if (number >= 1024) return `${(number / 1024).toFixed(1)} kB`;
    return `${number} B`;
  }

  function teardownStepsFrom(steps) {
    return Array.isArray(steps) && steps.length ? steps : TEARDOWN_STEP_LABELS.map(label => ({ label, state: 'pending' }));
  }

  function renderTeardownSteps(steps, status = 'running') {
    const list = $('td-steps');
    list.replaceChildren();
    teardownStepsFrom(steps).forEach(step => {
      const item = document.createElement('li');
      const state = step.state === 'done' || status === 'done' ? 'done'
        : step.state === 'failed' || status === 'error' ? 'failed'
          : step.state === 'active' && status === 'running' ? 'active' : 'pending';
      item.className = `td-step ${state}`;
      const dot = document.createElement('span');
      dot.className = 'td-step-dot';
      dot.setAttribute('aria-hidden', 'true');
      const label = document.createElement('span');
      label.textContent = step.label || '';
      item.append(dot, label);
      list.append(item);
    });
    $('teardown-panel').classList.toggle('is-done', status === 'done');
  }

  function placeTeardownPanel() {
    {
      const panel = $('teardown-panel');
      if (!panel || panel.hidden) return;
      const margin = 16, gap = 14;
      const atlas = $('atlas-panel');
      const note = $('note-panel');
      const dock = $('chat-dock');
      const atlasRect = atlas?.getBoundingClientRect();
      const noteRect = note && !note.hidden ? note.getBoundingClientRect() : null;
      const dockRect = dock?.getBoundingClientRect();
      let left;
      let top;
      let width;
      let bottomLimit = window.innerHeight - margin;
      if (window.innerWidth <= 800 && atlasRect) {
        left = margin;
        top = Math.max(88, atlasRect.bottom + gap);
        width = Math.min(360, window.innerWidth - margin * 2);
      } else {
        left = Math.max(margin, (atlasRect?.right || margin) + gap);
        top = Math.max(96, atlasRect?.top || 110);
        width = Math.min(380, window.innerWidth - left - margin);
      }
      // The note lives in the left rail, so a note "to the left" of the card is not
      // an obstacle; only a note docked to its right squeezes the card.
      if (noteRect && noteRect.left > left + 40) {
        const maxRight = noteRect.left - gap;
        if (maxRight - left >= 240) width = Math.min(width, maxRight - left);
        else {
          left = margin;
          width = Math.min(320, maxRight - margin);
        }
      }
      if (dockRect && dockRect.top > 100) bottomLimit = Math.min(bottomLimit, dockRect.top - gap);
      const maxHeight = Math.max(190, bottomLimit - top);
      panel.style.left = `${Math.round(Math.max(margin, left))}px`;
      panel.style.top = `${Math.round(Math.max(84, top))}px`;
      panel.style.width = `${Math.round(Math.max(240, width))}px`;
      panel.style.maxHeight = `${Math.round(maxHeight)}px`;
      panel.classList.toggle('no-snapshot', maxHeight < 430);
    }
  }

  function layoutTeardownPanel() {
    if (teardownLayoutFrame) return;
    teardownLayoutFrame = requestAnimationFrame(() => {
      teardownLayoutFrame = null;
      placeTeardownPanel();
    });
  }

  function renderTeardownResult(result, elapsed = 0, foldText = '') {
    const panel = $('teardown-panel');
    panel.classList.add('is-done');
    $('td-result').hidden = false;
    const seconds = elapsed || result?.elapsed_seconds || 0;
    $('td-fold').textContent = foldText || `Taken apart in ${formatDuration(seconds)}`;
    const snapshot = $('td-snapshot');
    if (result?.snapshot_url) {
      snapshot.src = result.snapshot_url;
      snapshot.alt = `Snapshot of ${result.site || 'the site'}`;
      $('td-snapshot-wrap').hidden = false;
      snapshot.onerror = () => { $('td-snapshot-wrap').hidden = true; layoutTeardownPanel(); };
    } else {
      snapshot.removeAttribute('src');
      $('td-snapshot-wrap').hidden = true;
    }
    const chips = $('td-chips');
    chips.replaceChildren();
    const seen = new Set();
    (Array.isArray(result?.stack) ? result.stack : []).slice(0, 10).forEach(item => {
      if (!item) return;
      const name = typeof item === 'string' ? item : item.name;
      const version = typeof item === 'object' ? item.version : null;
      if (!name || seen.has(`${name}|${version || ''}`)) return;
      seen.add(`${name}|${version || ''}`);
      const chip = document.createElement('span');
      chip.className = 'td-chip';
      chip.textContent = name;
      if (version) {
        const small = document.createElement('small');
        small.textContent = version;
        chip.append(small);
      }
      chips.append(chip);
    });
    const totals = result?.totals || {};
    const parts = [];
    if (Number(totals.resources)) parts.push(`${Number(totals.resources).toLocaleString()} files`);
    if (Number(totals.known_bytes)) parts.push(humanBytes(totals.known_bytes));
    else if (totals.known_bytes_label) parts.push(totals.known_bytes_label);
    if (Number(totals.routes)) parts.push(`${Number(totals.routes)} routes`);
    if (Number(totals.unknown_sizes)) parts.push(`${Number(totals.unknown_sizes)} sizes unknown`);
    $('td-totals').textContent = parts.join(' · ') || 'Evidence captured.';
    $('td-read').disabled = false;
    $('td-note').textContent = '';
    $('td-note').classList.remove('is-error');
    panel.classList.remove('no-snapshot');
    layoutTeardownPanel();
  }

  function showTeardownCard(site, note = '') {
    teardownLast = null;
    $('td-site').textContent = site || 'site';
    $('td-note').textContent = note;
    $('td-note').classList.remove('is-error');
    $('td-result').hidden = true;
    $('td-read').disabled = true;
    $('td-snapshot').removeAttribute('src');
    $('td-chips').replaceChildren();
    $('td-totals').textContent = '';
    const panel = $('teardown-panel');
    panel.hidden = false;
    panel.classList.remove('is-done', 'no-snapshot');
    renderTeardownSteps(TEARDOWN_STEP_LABELS.map(label => ({ label, state: 'pending' })), 'running');
    placeTeardownPanel();
    layoutTeardownPanel();
  }

  function setTeardownMessage(message, error = false) {
    $('td-note').textContent = message;
    $('td-note').classList.toggle('is-error', error);
    layoutTeardownPanel();
  }

  async function startTeardownJob(url, question = '') {
    const target = String(url || '').trim().replace(/[.,!?]+$/, '');
    if (!target) return false;
    const address = normalizeAddress(target);
    const site = siteFromAddress(address);
    if (teardownPending || teardownJob?.status === 'running' || teardownJob?.status === 'cancelling') {
      const message = "I'm already taking one apart, sir.";
      $('chat-answer').textContent = message;
      $('answer-panel').hidden = false;
      if (voice) voice.speak(message);
      return false;
    }
    if (capturePending) await captureTail;
    if (activeRequest) cancelQuestion();
    teardownPending = true;
    if (voice) { voice.stopSpeaking(); voice.setThinking(false); }
    showTeardownCard(site, 'Opening a clean browser; the steps will update as they happen.');
    $('answer-panel').hidden = false;
    $('answer-panel').classList.remove('is-error');
    $('action-receipt').hidden = true;
    if ($('chat-operator-card')) $('chat-operator-card').hidden = true;
    setAnswerMode(null);
    renderWebSources([]);
    $('asked-question').textContent = `teardown ${site}`;
    $('chat-answer').textContent = `I'm opening ${site} in a clean browser. Watch the card; I'll keep the steps honest.`;
    $('chat-state').textContent = 'Teardown running · panel stays open';
    renderSources([]);
    try {
      const response = await fetch('/teardown/run', {
        method: 'POST', credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
        body: JSON.stringify({ url: address, question: question || undefined })
      });
      let payload;
      try { payload = await response.json(); }
      catch (_) { throw new Error('INVALID_TEARDOWN_RESPONSE'); }
      if (!response.ok || payload.busy || payload.error) {
        const message = typeof payload.answer === 'string' ? payload.answer
          : 'I could not start that teardown; nothing was captured.';
        teardownPending = false;
        setTeardownMessage(message, true);
        renderTeardownSteps(payload.steps || [], 'error');
        $('chat-answer').textContent = message;
        $('answer-panel').classList.add('is-error');
        $('chat-state').textContent = 'Teardown needs attention';
        if (voice) voice.speak(message);
        return false;
      }
      teardownJob = { job_id: payload.job_id, site: payload.site || site, status: 'running', result: null };
      teardownPollSequence += 1;  // invalidate a poll from a previous job
      setTeardownMessage(payload.ack || 'Very good, sir; I have started.');
      renderTeardownSteps(payload.steps, 'running');
      teardownPollTimer = setTimeout(pollTeardown, 350);
      if (voice) voice.speak(payload.ack || `Very good, sir. I'm taking ${site} apart.`);
      return true;
    } catch (error) {
      teardownPending = false;
      const message = 'I could not start that teardown; no note was filed.';
      setTeardownMessage(message, true);
      $('chat-answer').textContent = message;
      $('answer-panel').classList.add('is-error');
      $('chat-state').textContent = 'Teardown needs attention';
      if (voice) voice.speak(message);
      return false;
    }
  }

  async function pollTeardown() {
    if (!teardownJob?.job_id || !['running', 'cancelling'].includes(teardownJob.status)) return;
    const sequence = teardownPollSequence;
    const job = teardownJob;
    teardownPollTimer = null;
    try {
      const response = await fetch(`/teardown/status?job_id=${encodeURIComponent(job.job_id)}`, {
        credentials: 'same-origin', headers: { 'Accept': 'application/json' }
      });
      const payload = await response.json();
      // A cancel/new job may have started its own chain while this fetch was
      // in flight; the older response must not overwrite the newer state.
      if (sequence !== teardownPollSequence || teardownJob !== job) return;
      if (!response.ok) throw new Error(payload.answer || 'INVALID_TEARDOWN_STATUS');
      renderTeardownSteps(payload.steps, payload.status);
      if (payload.status === 'done') {
        const result = payload.result;
        if (!result || !Array.isArray(result.births)) throw new Error('INVALID_TEARDOWN_RESULT');
        teardownJob.status = 'done';
        teardownJob.result = result;
        renderTeardownResult(result, payload.elapsed_seconds);
        let birthFailed = false;
        try {
          for (const birth of result.births) await addNote(birth);
        } catch (_) {
          birthFailed = true;
          $('chat-answer').textContent = 'The note was filed, but this view could not show its new stars; reload to see it.';
          $('answer-panel').classList.add('is-error');
        }
        if (!birthFailed) $('chat-answer').textContent = result.summary || result.spoken || 'Teardown filed.';
        $('chat-state').textContent = 'Teardown filed · the card has the evidence';
        renderSources(result.nodes || []);
        setAnswerMode('notes', sourceIds.size);
        if (voice) voice.speak(result.spoken || result.summary || '');
        teardownPending = false;
        return;
      }
      if (payload.status === 'error' || payload.status === 'cancelled') {
        teardownJob.status = payload.status;
        teardownPending = false;
        const message = payload.answer || 'The teardown could not finish; no note was filed.';
        setTeardownMessage(message, true);
        $('chat-answer').textContent = message;
        $('answer-panel').classList.add('is-error');
        $('chat-state').textContent = payload.status === 'cancelled' ? 'Teardown cancelled' : 'Teardown failed';
        if (voice) voice.speak(message);
        return;
      }
      setTeardownMessage(payload.status === 'cancelling' ? 'Cancelling; closing the browser cleanly.' : 'Working through the evidence; no shortcuts.');
      teardownPollTimer = setTimeout(pollTeardown, 650);
    } catch (error) {
      if (sequence !== teardownPollSequence || teardownJob !== job) return;
      teardownPending = false;
      teardownJob.status = 'error';
      const message = 'I lost sight of that teardown; no success is being claimed.';
      setTeardownMessage(message, true);
      $('chat-answer').textContent = message;
      $('answer-panel').classList.add('is-error');
      $('chat-state').textContent = 'Teardown status unavailable';
      if (voice) voice.speak(message);
    }
  }

  async function showLastTeardown() {
    if (teardownJob?.status === 'running' || teardownJob?.status === 'cancelling') {
      setTeardownMessage('One teardown is still running, sir; let it finish first.', true);
      return true;
    }
    try {
      const response = await fetch('/teardown/last', { credentials: 'same-origin', headers: { 'Accept': 'application/json' } });
      const payload = await response.json();
      if (!response.ok || !payload.ok) throw new Error(payload.answer || 'NO_TEARDOWN');
      teardownJob = null;
      showTeardownCard(payload.site, 'Last teardown, read from the vault.');
      teardownLast = payload;
      renderTeardownResult({ ...payload, births: [] }, 0,
        `Taken apart · ${payload.date || 'last note'}`);
      $('td-note').textContent = 'Last teardown on disk; no live job was started.';
      $('chat-answer').textContent = 'The last teardown is on the card, sir.';
      $('answer-panel').hidden = false;
      $('answer-panel').classList.remove('is-error');
      $('chat-state').textContent = 'Last teardown · read from disk';
      renderSources([]);
      if (voice) voice.speak('The last teardown is on the card, sir.');
      return true;
    } catch (error) {
      const message = 'I have no teardown note to show, sir.';
      $('chat-answer').textContent = message;
      $('answer-panel').hidden = false;
      $('answer-panel').classList.add('is-error');
      $('chat-state').textContent = 'No teardown on disk';
      if (voice) voice.speak(message);
      return false;
    }
  }

  function inlineMarkdown(parent, text) {
    const pattern = /(\*\*[^*]+\*\*|`[^`]+`|\[[^\]]+\]\((?:https?:\/\/|obsidian:\/\/)[^)]+\))/g;
    let last = 0;
    for (const match of text.matchAll(pattern)) {
      if (match.index > last) parent.append(document.createTextNode(text.slice(last, match.index)));
      const token = match[0];
      if (token.startsWith('**')) {
        const strong = document.createElement('strong');
        strong.textContent = token.slice(2, -2);
        parent.append(strong);
      } else if (token.startsWith('`')) {
        const code = document.createElement('code');
        code.textContent = token.slice(1, -1);
        parent.append(code);
      } else {
        const linkMatch = token.match(/^\[([^\]]+)\]\(([^)]+)\)$/);
        if (linkMatch) {
          const anchor = document.createElement('a');
          anchor.textContent = linkMatch[1];
          anchor.href = linkMatch[2];
          anchor.rel = 'noreferrer noopener';
          anchor.target = '_blank';
          parent.append(anchor);
        } else parent.append(document.createTextNode(token));
      }
      last = match.index + token.length;
    }
    if (last < text.length) parent.append(document.createTextNode(text.slice(last)));
  }

  function renderMarkdown(markdown, snapshotUrl) {
    const body = $('td-reader-body');
    body.replaceChildren();
    const withoutFrontMatter = String(markdown || '').replace(/^---\r?\n[\s\S]*?\r?\n---\r?\n?/, '');
    const lines = withoutFrontMatter.split(/\r?\n/);
    let list = null;
    let listKind = null;
    let code = false;
    let codeLines = [];
    const closeList = () => { list = null; listKind = null; };
    for (const line of lines) {
      if (line.trim().startsWith('```')) {
        if (code) {
          const pre = document.createElement('pre');
          pre.textContent = codeLines.join('\n');
          body.append(pre);
          codeLines = [];
          code = false;
        } else { closeList(); code = true; }
        continue;
      }
      if (code) { codeLines.push(line); continue; }
      const heading = line.match(/^(#{1,3})\s+(.+)$/);
      if (heading) {
        closeList();
        const node = document.createElement(`h${heading[1].length}`);
        inlineMarkdown(node, heading[2]);
        body.append(node);
        continue;
      }
      const image = line.match(/^!\[([^\]]*)\]\(([^)]+)\)\s*$/);
      if (image) {
        closeList();
        if (snapshotUrl) {
          const img = document.createElement('img');
          img.src = snapshotUrl;
          img.alt = image[1] || 'Teardown snapshot';
          body.append(img);
        }
        continue;
      }
      const bullet = line.match(/^\s*[-*]\s+(.+)$/);
      const numbered = line.match(/^\s*\d+[.)]\s+(.+)$/);
      if (bullet || numbered) {
        const kind = bullet ? 'ul' : 'ol';
        if (!list || listKind !== kind) {
          list = document.createElement(kind);
          listKind = kind;
          body.append(list);
        }
        const item = document.createElement('li');
        inlineMarkdown(item, (bullet || numbered)[1]);
        list.append(item);
        continue;
      }
      if (!line.trim()) { closeList(); continue; }
      closeList();
      const p = document.createElement('p');
      inlineMarkdown(p, line);
      body.append(p);
    }
    if (code && codeLines.length) {
      const pre = document.createElement('pre');
      pre.textContent = codeLines.join('\n');
      body.append(pre);
    }
    if (!body.childNodes.length) {
      const empty = document.createElement('p');
      empty.className = 'td-reader-empty';
      empty.textContent = 'This note is empty.';
      body.append(empty);
    }
  }

  async function openTeardownReader() {
    let url = null;
    if (teardownJob?.status === 'done' && teardownJob.job_id) {
      url = `/teardown/note?job_id=${encodeURIComponent(teardownJob.job_id)}`;
    } else if (teardownLast?.note_name) {
      url = `/teardown/note?name=${encodeURIComponent(teardownLast.note_name)}`;
    }
    if (!url) {
      const message = 'There is no finished teardown to read, sir.';
      $('chat-answer').textContent = message;
      if (voice) voice.speak(message);
      return false;
    }
    try {
      const response = await fetch(url, { credentials: 'same-origin', headers: { 'Accept': 'application/json' } });
      const payload = await response.json();
      if (!response.ok || !payload.ok) throw new Error(payload.answer || 'NO_NOTE');
      $('td-reader-title').textContent = `${payload.site || 'Teardown'} · ${payload.date || ''}`.trim();
      $('td-obsidian').href = payload.obsidian_uri || '#';
      renderMarkdown(payload.markdown, payload.snapshot_url);
      $('td-reader').hidden = false;
      $('td-reader-close').focus({ preventScroll: true });
      return true;
    } catch (error) {
      const message = 'I could not open that teardown note, sir.';
      $('chat-answer').textContent = message;
      if (voice) voice.speak(message);
      return false;
    }
  }

  function closeTeardownReader() {
    $('td-reader').hidden = true;
    $('td-read').focus({ preventScroll: true });
  }

  async function cancelTeardown() {
    if (!teardownJob?.job_id || !['running', 'cancelling'].includes(teardownJob.status)) {
      setTeardownMessage('No teardown is running, sir.');
      if (voice) voice.speak('No teardown is running, sir.');
      return false;
    }
    const job = teardownJob;
    teardownPollSequence += 1;
    if (teardownPollTimer) { clearTimeout(teardownPollTimer); teardownPollTimer = null; }
    try {
      const response = await fetch('/teardown/cancel', {
        method: 'POST', credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
        body: JSON.stringify({ job_id: job.job_id })
      });
      const payload = await response.json();
      if (!response.ok) throw new Error(payload.answer || 'CANCEL_FAILED');
      if (teardownJob !== job) return true;
      job.status = 'cancelling';
      setTeardownMessage(payload.answer || 'Cancelling it now, sir; the browser will close cleanly.');
      if (voice) voice.speak(payload.answer || 'Cancelling it now, sir.');
      teardownPollTimer = setTimeout(pollTeardown, 400);
      return true;
    } catch (error) {
      const message = 'I could not cancel that teardown; it may still be running.';
      setTeardownMessage(message, true);
      if (voice) voice.speak(message);
      if (teardownJob === job) teardownPollTimer = setTimeout(pollTeardown, 650);
      return false;
    }
  }

  async function closeTeardown() {
    if (teardownJob?.status === 'running' || teardownJob?.status === 'cancelling') await cancelTeardown();
    teardownPollSequence += 1;
    if (teardownPollTimer) { clearTimeout(teardownPollTimer); teardownPollTimer = null; }
    teardownPending = false;
    $('teardown-panel').hidden = true;
    if (!$('td-reader').hidden) $('td-reader').hidden = true;
    return true;
  }

  async function teardownCurrent(question = '') {
    try {
      const response = await fetch('/site/current', { credentials: 'same-origin', headers: { 'Accept': 'application/json' } });
      const payload = await response.json();
      if (!response.ok || !payload.ok) {
        const message = payload.answer || 'Which site, sir?';
        $('chat-answer').textContent = message;
        $('answer-panel').hidden = false;
        $('chat-state').textContent = 'Name the site';
        if (voice) voice.speak(message);
        return false;
      }
      return startTeardownJob(payload.url, question);
    } catch (_) {
      const message = 'Which site, sir? I could not read the current tab.';
      $('chat-answer').textContent = message;
      $('answer-panel').hidden = false;
      if (voice) voice.speak(message);
      return false;
    }
  }

  function runTeardown(url, question = '') {
    return startTeardownJob(url, question);
  }

  function updateRotation() {
    $('rotate-toggle').setAttribute('aria-pressed', String(rotating));
    $('rotate-label').textContent = rotating ? 'Pause orbit' : 'Resume orbit';
    $('rotate-icon').textContent = rotating ? 'Ⅱ' : '▷';
    if (graph) graph.controls().autoRotate = rotating && selectedId === null && !document.hidden && !graphLoopPaused;
  }

  function toggleRotation() {
    rotating = !rotating;
    const box = $('display-rotate');
    if (box && box.checked !== rotating) box.checked = rotating;
    updateRotation();
    saveSettings();
    return rotating;
  }

  function resetView() {
    closeNote();
    sourceIds.clear();
    setGroup(null);
    updateHighlights();
    if (graph) graph.cameraPosition(homePosition(), { x: 0, y: 0, z: 0 }, motion.matches ? 0 : 1200);
    updateRotation();
  }

  function homePosition() {
    return window.innerWidth <= 600 ? { x: 0, y: 190, z: 780 } : { x: 0, y: 130, z: 470 };
  }

  function renderSources(ids) {
    sourceIds = new Set(ids.filter(id => Number.isInteger(id) && byId.has(id)));
    $('source-list').replaceChildren();
    [...sourceIds].forEach((id, index) => {
      const node = byId.get(id);
      const item = document.createElement('li');
      const button = document.createElement('button');
      button.type = 'button';
      button.className = 'source-button';
      button.dataset.nodeId = String(id);
      const number = document.createElement('span');
      number.className = 'source-number';
      number.textContent = String(index + 1).padStart(2, '0');
      const label = document.createElement('span');
      label.textContent = node.label;
      button.append(number, label);
      button.addEventListener('click', () => {
        if (window.innerWidth <= 600) $('answer-panel').hidden = true;
        selectNode(id, { focus: true });
      });
      item.append(button);
      $('source-list').append(item);
    });
    $('sources-section').hidden = sourceIds.size === 0;
    if (sourceIds.size && activeGroup !== null) setGroup(null);
    updateHighlights();
  }

  function renderWebSources(rows) {
    const list = $('web-source-list');
    const section = $('web-sources-section');
    if (!list || !section) return;
    list.replaceChildren();
    const seen = new Set();
    (Array.isArray(rows) ? rows : []).forEach(row => {
      if (!row || typeof row.url !== 'string' || !/^https?:\/\//i.test(row.url) || seen.has(row.url)) return;
      seen.add(row.url);
      const item = document.createElement('li');
      const link = document.createElement('a');
      link.className = 'web-source-button';
      link.href = row.url;
      link.target = '_blank';
      link.rel = 'noopener noreferrer';
      const title = document.createElement('b');
      title.textContent = row.title || row.url;
      const snippet = document.createElement('span');
      const price = row.price && row.price.price ? `${row.price.price} ${row.price.currency || ''}`.trim() : '';
      snippet.textContent = [price ? `${price} ·` : '', row.snippet || ''].filter(Boolean).join(' ');
      const url = document.createElement('small');
      const stamp = row.fetched_at ? ` · fetched ${new Date(row.fetched_at * 1000).toLocaleTimeString()}` : '';
      url.textContent = row.url + stamp;
      link.append(title, snippet, url);
      item.append(link);
      list.append(item);
    });
    section.hidden = list.children.length === 0;
  }

  function setAnswerMode(mode, sourceCount = 0) {
    const label = $('answer-mode');
    if (!label) return;
    if (!mode) { label.hidden = true; label.textContent = ''; return; }
    const general = mode === 'general';
    const web = mode === 'general-web';
    label.hidden = false;
    label.classList.toggle('is-general', general || web);
    label.classList.toggle('is-notes', !general && !web && sourceCount > 0);
    label.textContent = web ? 'WEB RESEARCH · PUBLIC SOURCES BELOW'
      : general ? 'GENERAL KNOWLEDGE · NOT FROM YOUR NOTES'
        : sourceCount > 0 ? 'FROM YOUR NOTES' : 'NO NOTE SOURCE';
  }

  async function consumeChatStream(stream, onDelta) {
    // Reads the /chat/stream SSE body: "data: {json}\n\n" frames. Returns the
    // final result payload, or null when the stream ended without one (the
    // caller then decides between the batch fallback and showing truncation).
    const reader = stream.body?.getReader?.();
    if (!reader) return null;
    const decoder = new TextDecoder();
    let buffer = '';
    let result = null;
    while (result === null) {
      const chunk = await reader.read();
      if (chunk.done) break;
      buffer += decoder.decode(chunk.value, { stream: true });
      let boundary = buffer.indexOf('\n\n');
      while (boundary !== -1) {
        const frame = buffer.slice(0, boundary);
        buffer = buffer.slice(boundary + 2);
        boundary = buffer.indexOf('\n\n');
        const data = frame.split('\n')
          .filter((line) => line.startsWith('data:'))
          .map((line) => line.slice(5).trim()).join('');
        if (!data) continue;
        let event;
        try { event = JSON.parse(data); } catch (_) { continue; }
        if (event.event === 'delta' && typeof event.text === 'string') {
          onDelta(event.text);
        } else if (event.event === 'result' && event.payload) {
          result = event.payload;
        } else if (event.event === 'error') {
          result = { answer: event.error?.message || '', nodes: [], error: event.error || {} };
        }
      }
    }
    return result;
  }

  async function askQuestion(question, language) {
    if (capturePending) await captureTail;
    const query = String(question || '').trim();
    if (!query || busy) return false;
    busy = true;
    setCoreState('thinking');
    const sequence = ++requestSequence;
    const controller = new AbortController();
    activeRequest = controller;
    if (voice) { voice.stopSpeaking(); voice.setThinking(true); }
    const timeout = setTimeout(() => controller.abort(), 195000);
    $('ask-button').disabled = true;
    $('ask-label').textContent = 'Thinking';
    $('chat-form').setAttribute('aria-busy', 'true');
    $('answer-panel').hidden = false;
    $('answer-panel').classList.remove('is-error');
    $('action-receipt').hidden = true;
    if ($('chat-operator-card')) $('chat-operator-card').hidden = true;
    setAnswerMode(null);
    $('asked-question').textContent = query;
    renderWebSources([]);
    $('chat-answer').textContent = 'Following the connections in your notes…';
    $('chat-state').textContent = 'Reading your constellation…';
    renderSources([]);
    const ackTimer = setTimeout(() => {
      if (activeRequest === controller && busy && voice && !voice.speaking) voice.speak('One moment, sir.');
    }, 700);
    try {
      let response = null;
      let payload = null;
      // Streaming lane: text is rendered while the model writes it; the final
      // result frame then replaces the preview exactly like a batch answer.
      // Any failing stream falls back to the batch request below, so the
      // behaviour never regresses when the server is older or offline.
      let streamOpened = false;
      let streamed = '';
      // Do not announce every streamed chunk to a screen reader; the final
      // answer is announced once when the request settles.
      $('chat-answer').setAttribute('aria-live', 'off');
      const streamTruncated = () => ({
        answer: 'The answer stream was cut short. Please ask again, sir.',
        nodes: [],
        error: { code: 'STREAM_TRUNCATED',
                 message: 'The answer stream was cut short. Please ask again, sir.' }
      });
      try {
        const stream = await fetch('/chat/stream', {
          method: 'POST',
          credentials: 'same-origin',
          headers: { 'Content-Type': 'application/json', 'Accept': 'text/event-stream' },
          // A voice-only hint: an English microphone earns an English answer.
          body: JSON.stringify(language === 'en' ? { question: query, language: 'en' }
                                                 : { question: query }),
          signal: controller.signal
        });
        if (stream.ok && String(stream.headers.get('content-type') || '').includes('text/event-stream')) {
          // Once the SSE headers arrive the server has already routed the
          // message: a broken channel must not be re-asked in batch, because
          // the first attempt may have started an Operator job.
          streamOpened = true;
          response = { ok: true, status: 200 };
          payload = await consumeChatStream(stream, (partial) => {
            if (sequence !== requestSequence) return;
            // The server sends growing text in chunks; accumulate them so the
            // panel (and the early voice) always sees the full answer so far.
            streamed = partial.startsWith(streamed) ? partial : streamed + partial;
            $('chat-answer').textContent = streamed;
            $('chat-state').textContent = 'Answering…';
            if (voice && voice.speakStream) voice.speakStream(streamed);
          });
          if (payload === null) {
            // A partial answer must never be silently re-asked in batch:
            // the second run could repeat an Operator action.
            payload = streamTruncated();
            response = { ok: false, status: 524 };
          }
          if (payload && payload.error) response = { ok: false, status: 502 };
        }
      } catch (streamError) {
        if (sequence !== requestSequence) return false;
        if (streamOpened) {
          // The server accepted the request before the channel broke; retrying
          // in batch could start the same Operator job a second time.
          payload = streamTruncated();
          response = { ok: false, status: 524 };
        } else {
          response = null;   // no SSE support or a broken channel — batch fallback below
        }
      }
      if (payload === null) {
        response = await fetch('/chat', {
          method: 'POST',
          credentials: 'same-origin',
          headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
          // A voice-only hint: an English microphone earns an English answer.
          body: JSON.stringify(language === 'en' ? { question: query, language: 'en' }
                                                 : { question: query }),
          signal: controller.signal
        });
        try { payload = await response.json(); }
        catch (_) { throw new Error('INVALID_RESPONSE'); }
      }
      if (sequence !== requestSequence) return false;
      if (!payload || typeof payload.answer !== 'string') throw new Error('INVALID_RESPONSE');
      if (payload.outcome === 'needs_target') {
        $('chat-answer').textContent = payload.answer;
        $('answer-panel').classList.remove('is-error');
        setAnswerMode(null);
        renderSources([]);
        renderWebSources([]);
        $('chat-state').textContent = 'Needs a target · no Operator tool was started';
        if (voice && payload.answer) voice.speak(payload.answer);
        return true;
      }
      if (payload.operator?.id) {
        const job = payload.operator;
        $('chat-answer').textContent = payload.answer;
        $('answer-panel').classList.remove('is-error');
        setAnswerMode(null);
        renderSources([]);
        $('chat-state').textContent = payload.plan ? `Operator · ${payload.plan}` : 'Operator job started · watch its steps';
        if (window.operator?.renderPlan && (job.plan || payload.plan)) {
          window.operator.renderPlan(job.plan || { phases: [{ text: payload.plan, done: false }] }, job.task || payload.task, 'running');
        }
        if (window.galaxyAgent?.attach) window.galaxyAgent.attach(job.id, { fromChat: true });
        else if (window.galaxyAgent?.open) window.galaxyAgent.open();
        if (voice) voice.speak(payload.answer);
        return true;
      }
      if (payload.teardown?.job_id) {
        const started = payload.teardown;
        showTeardownCard(started.site || '', payload.answer);
        teardownJob = { job_id: started.job_id, site: started.site || '', status: 'running', result: null };
        renderTeardownSteps(started.steps, 'running');
        setTeardownMessage(payload.answer);
        teardownPending = true;
        $('chat-answer').textContent = payload.answer;
        $('answer-panel').hidden = false;
        $('answer-panel').classList.remove('is-error');
        setAnswerMode(null);
        $('chat-state').textContent = 'Teardown running · panel stays open';
        renderSources([]);
        if (voice) voice.speak(payload.answer);
        teardownPollTimer = setTimeout(pollTeardown, 350);
        return true;
      }
      $('chat-answer').textContent = payload.answer;
      if (payload.receipt && typeof payload.receipt.id === 'string' && typeof payload.receipt.status === 'string') {
        $('action-receipt').textContent = `Receipt ${payload.receipt.id} · ${payload.receipt.outcome || payload.receipt.status}`;
        $('action-receipt').hidden = false;
      }
      const failed = !response.ok || Boolean(payload.error);
      const sourceCount = !failed && Array.isArray(payload.nodes) ? payload.nodes.length : 0;
      $('answer-panel').classList.toggle('is-error', failed);
      const mode = payload.mode === 'general-web' ? 'general-web' : payload.mode === 'general' ? 'general' : 'notes';
      setAnswerMode(failed ? null : mode, sourceCount);
      renderSources(!failed && Array.isArray(payload.nodes) ? payload.nodes : []);
      renderWebSources(!failed && Array.isArray(payload.web_sources) ? payload.web_sources : []);
      $('chat-state').textContent = failed ? 'Unable to answer · please try again'
        : mode === 'general-web' ? `Web research · ${(payload.web_sources || []).length} public source${(payload.web_sources || []).length === 1 ? '' : 's'}`
          : mode === 'general' ? 'General knowledge · no vault citations'
            : `${sourceIds.size} source ${sourceIds.size === 1 ? 'note' : 'notes'} · click to explore`;
      if (voice) {
        // A failed lane replaces any early partial speech with its error; a
        // good one only appends the tail that the streamed voice has not read.
        // The method check keeps a stale cached voice.js from breaking chat.
        if (failed || !voice.finishStream) voice.speak(payload.answer);
        else voice.finishStream(payload.answer);
      }
      return !failed;
    } catch (error) {
      if (sequence !== requestSequence) return false;
      const message = error.name === 'AbortError'
        ? 'This answer is taking longer than expected. Please try again in a moment.'
        : error.message === 'INVALID_RESPONSE'
          ? 'The notes service sent an unexpected response. Please try again.'
          : 'We couldn’t reach the notes service. Check your connection and try again.';
      $('chat-answer').textContent = message;
      $('answer-panel').classList.add('is-error');
      setAnswerMode(null);
      $('chat-state').textContent = 'Connection interrupted · your question is saved above';
      renderSources([]);
      renderWebSources([]);
      if (voice) voice.speak(message);
      return false;
    } finally {
      clearTimeout(timeout);
      clearTimeout(ackTimer);
      $('chat-answer').setAttribute('aria-live', 'polite');
      if (sequence === requestSequence) {
        activeRequest = null;
        busy = false;
        setCoreState('online');
        if (voice) voice.setThinking(false);
        $('ask-button').disabled = false;
        $('ask-label').textContent = 'Ask';
        $('chat-form').setAttribute('aria-busy', 'false');
      }
    }
  }

  function cancelQuestion() {
    if (!activeRequest) return;
    ++requestSequence;
    activeRequest.abort();
    activeRequest = null;
    busy = false;
    setCoreState('online');
    if (voice) voice.setThinking(false);
    $('ask-button').disabled = false;
    $('ask-label').textContent = 'Ask';
    $('chat-form').setAttribute('aria-busy', 'false');
    $('chat-answer').textContent = 'Answer interrupted.';
    $('chat-state').textContent = 'Interrupted · ready for your next question';
  }

  function sendQuestion(question) {
    const text = String(question || '').trim();
    const operator = text.match(/^(?:\/operator|operator:)\s+(.+)$/i);
    if (operator) {
      $('answer-panel').hidden = false;
      $('answer-panel').classList.remove('is-error');
      if ($('chat-operator-card')) $('chat-operator-card').hidden = true;
      $('asked-question').textContent = text;
      $('chat-state').textContent = 'Operator job started · watch its steps';
      renderSources([]);
      if (window.galaxyAgent && typeof window.galaxyAgent.start === 'function') {
        $('chat-answer').textContent = 'I am handing that to the Operator, sir. Watch its steps; I will not call it done until it is.';
        window.galaxyAgent.start(operator[1], { fromChat: true });
      } else {
        $('chat-answer').textContent = 'The Operator is unavailable; nothing was started.';
        $('answer-panel').classList.add('is-error');
      }
      return true;
    }
    if (voice) return voice.dispatch(question);
    const teardown = String(question || '').trim().match(TEARDOWN_PATTERN);
    if (teardown && /(?:https?:\/\/|[a-z0-9-]+\.[a-z]{2,})/i.test(teardown[1])) return runTeardown(teardown[1], teardown[2] || '');
    const capture = String(question || '').trim().match(REMEMBER_PATTERN);
    return capture ? rememberNote(capture[1]) : askQuestion(question);
  }

  function makeGlowTexture(THREE) {
    const canvas = document.createElement('canvas');
    canvas.width = canvas.height = 128;
    const context = canvas.getContext('2d');
    const gradient = context.createRadialGradient(64, 64, 0, 64, 64, 64);
    gradient.addColorStop(0, 'rgba(255,255,255,1)');
    gradient.addColorStop(.055, 'rgba(255,255,255,1)');
    gradient.addColorStop(.13, 'rgba(255,255,255,.85)');
    gradient.addColorStop(.28, 'rgba(255,255,255,.22)');
    gradient.addColorStop(.58, 'rgba(255,255,255,.045)');
    gradient.addColorStop(1, 'rgba(255,255,255,0)');
    context.fillStyle = gradient;
    context.fillRect(0, 0, 128, 128);
    return new THREE.CanvasTexture(canvas);
  }

  function addStarfield(THREE) {
    let seed = 8297;
    const random = () => { seed = (seed * 16807) % 2147483647; return (seed - 1) / 2147483646; };
    const positions = new Float32Array(1500 * 3);
    for (let i = 0; i < positions.length; i += 3) {
      const angle = random() * Math.PI * 2;
      const height = random() * 2 - 1;
      const radius = 1000 + random() * 1200;
      const ring = Math.sqrt(1 - height * height);
      positions[i] = Math.cos(angle) * ring * radius;
      positions[i + 1] = height * radius;
      positions[i + 2] = Math.sin(angle) * ring * radius;
    }
    const geometry = new THREE.BufferGeometry();
    geometry.setAttribute('position', new THREE.BufferAttribute(positions, 3));
    const stars = new THREE.Points(geometry, new THREE.PointsMaterial({ color: '#adc3d4', size: 1.5, transparent: true, opacity: .58, depthWrite: false, sizeAttenuation: true }));
    stars.name = 'orbit-starfield';
    // One group owns the stars and both guide rings, so the toggle hides the
    // complete layer instead of leaving two rings visible in empty space.
    const layer = new THREE.Group();
    layer.name = 'orbit-starfield-layer';
    layer.add(stars);
    graph.scene().add(layer);
    starfieldLayer = layer;
    [240, 360].forEach((radius, index) => {
      const points = Array.from({ length: 200 }, (_, i) => new THREE.Vector3(Math.cos(i / 200 * Math.PI * 2) * radius, -65, Math.sin(i / 200 * Math.PI * 2) * radius));
      const ring = new THREE.LineLoop(new THREE.BufferGeometry().setFromPoints(points), new THREE.LineBasicMaterial({ color: '#5c99a7', transparent: true, opacity: index ? .035 : .055, depthWrite: false }));
      ring.name = 'orbit-guide';
      layer.add(ring);
    });
  }

  function seedPositions() {
    nodes.forEach((node, index) => {
      const group = groups.indexOf(node.group);
      const angle = group / Math.max(groups.length, 1) * Math.PI * 2;
      const spiral = index * 2.399963229728653;
      const radius = 18 + Math.sqrt(index + 1) * 5;
      node.x = Math.cos(angle) * 95 + Math.cos(spiral) * radius;
      node.y = Math.sin(index * 7.13) * 45;
      node.z = Math.sin(angle) * 95 + Math.sin(spiral) * radius;
    });
  }

  const hubLabels = new Map();

  function makeTextSprite(THREE, text) {
    const canvas = document.createElement('canvas');
    const context = canvas.getContext('2d');
    const label = String(text || '').slice(0, 44);
    const font = '500 30px Inter, "Segoe UI", Arial, sans-serif';
    context.font = font;
    const width = Math.ceil(context.measureText(label).width) + 18;
    canvas.width = Math.max(width, 24);
    canvas.height = 34;
    context.font = font;
    context.textBaseline = 'middle';
    context.fillStyle = 'rgba(233,239,243,.8)';
    context.fillText(label, 9, 18);
    const texture = new THREE.CanvasTexture(canvas);
    texture.minFilter = THREE.LinearFilter;
    const sprite = new THREE.Sprite(new THREE.SpriteMaterial({
      map: texture, transparent: true, opacity: .88, depthWrite: false
    }));
    sprite.scale.set(canvas.width * .15, canvas.height * .15, 1);
    sprite.userData.isLabel = true;
    return sprite;
  }

  function addHubLabels(THREE) {
    const average = links.length / Math.max(nodes.length, 1);
    const threshold = Math.max(10, Math.round(Math.sqrt(average) * 6));
    nodes
      .filter(node => adjacency.get(node.id).size >= threshold)
      .sort((a, b) => adjacency.get(b.id).size - adjacency.get(a.id).size)
      .slice(0, 14)
      .forEach(node => {
        const sprite = makeTextSprite(THREE, node.label);
        hubLabels.set(node.id, sprite);
        graph.scene().add(sprite);
      });
  }

  function positionHubLabels() {
    hubLabels.forEach((sprite, id) => {
      const node = byId.get(id);
      if (!node) return;
      const radius = (10 + Math.min(adjacency.get(id).size, 12) * .7) * nodeScale;
      sprite.position.set(node.x, node.y - radius * .95, node.z);
    });
  }

  function initGraph() {
    if (!nodes.length) {
      graphError = 'NO_DATA';
      $('system-state').textContent = 'Waiting for notes';
      notice('Your atlas is waiting', 'No notes were loaded. Generate graph-data.js, then reload. The note index will appear here.');
      setBrowser(true);
      return;
    }
    if (typeof window.ForceGraph3D !== 'function' || !window.THREE) {
      graphError = 'CDN_UNAVAILABLE';
      notice('3D view is unavailable', 'The graphics libraries couldn’t load. You can still search, open notes, and ask questions. Check your connection and reload to restore the map.');
      $('system-state').textContent = 'Note index available';
      setBrowser(true);
      return;
    }
    try {
      const THREE = window.THREE;
      seedPositions();
      const texture = makeGlowTexture(THREE);
      graph = window.ForceGraph3D({ controlType: 'orbit', rendererConfig: { alpha: true, antialias: true } })($('graph'));
      graph.width(window.innerWidth).height(window.innerHeight)
        .backgroundColor('#00000000')
        .showNavInfo(false)
        .nodeLabel(node => {
          const tooltip = document.createElement('div');
          tooltip.className = 'node-tooltip';
          tooltip.textContent = node.label;
          return tooltip;
        })
        .nodeThreeObject(node => {
          if (sprites.has(node.id)) return sprites.get(node.id);
          const sprite = new THREE.Sprite(new THREE.SpriteMaterial({ map: texture, color: colorFor(node), transparent: true, opacity: .98, depthWrite: false, blending: THREE.AdditiveBlending }));
          const size = (11 + Math.min(adjacency.get(node.id).size, 12) * .8) * nodeScale;
          sprite.scale.setScalar(size);
          sprite.userData.nodeId = node.id;
          sprites.set(node.id, sprite);
          return sprite;
        })
        .nodeVal(node => 2.1 + Math.min(adjacency.get(node.id).size, 10) * .2)
        .linkColor(() => '#2f5a4a').linkOpacity(.12).linkWidth(.3)
        .linkDirectionalParticleWidth(.9).linkDirectionalParticleSpeed(.003)
        .onNodeClick(node => selectNode(node))
        .onNodeHover(node => { $('graph').style.cursor = node ? 'pointer' : 'grab'; })
        .onBackgroundClick(() => { closeNote(); updateRotation(); })
        .warmupTicks(65).cooldownTicks(150).d3AlphaDecay(.025)
        .graphData({ nodes: [...nodes], links: links.map(link => ({ source: endpointId(link.source), target: endpointId(link.target) })) });
      const charge = graph.d3Force('charge');
      if (charge) charge.strength(-42);
      const linkForce = graph.d3Force('link');
      if (linkForce) linkForce.distance(40);
      graph.cameraPosition(homePosition(), { x: 0, y: 0, z: 0 }, 0);
      addHubLabels(THREE);
      graph.onEngineTick(positionHubLabels);
      const controls = graph.controls();
      controls.autoRotateSpeed = .22;
      controls.enableDamping = true;
      controls.dampingFactor = .07;
      controls.minDistance = 40;
      controls.maxDistance = 2400;
      controls.addEventListener('start', () => { lastInteraction = performanceNow(); controls.autoRotate = false; });
      controls.addEventListener('end', () => { lastInteraction = performanceNow(); });
      graph.renderer().setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));
      addStarfield(THREE);
      applyGraphSettings();
      graph.renderer().domElement.addEventListener('webglcontextlost', event => {
        event.preventDefault();
        ready = false;
        graphError = 'WEBGL_CONTEXT_LOST';
        notice('3D view was interrupted', 'Your browser paused the graphics context. Notes and chat still work; reload to restore the map.');
      });
      graphHostObserver = new ResizeObserver(() => {
        graph.width(window.innerWidth).height(window.innerHeight);
      });
      graphHostObserver.observe($('graph'));
      ready = true;
      $('graph-notice').hidden = true;
      $('system-state').textContent = `${nodes.length} notes in orbit`;
      updateRotation();
      let idleTimer = null;
      const scheduleIdle = () => {
        if (idleTimer !== null) clearTimeout(idleTimer);
        idleTimer = setTimeout(() => {
          idleTimer = null;
          if (rotating && selectedId === null && !document.hidden && performanceNow() - lastInteraction >= 5500) {
            controls.autoRotate = true;
          }
        }, 5550);
      };
      controls.addEventListener('end', scheduleIdle);
      scheduleIdle();
    } catch (error) {
      graphError = 'WEBGL_UNAVAILABLE';
      ready = false;
      if (graph) { try { graph.pauseAnimation(); } catch (_) { /* Keep the accessible index usable. */ } }
      graph = null;
      notice('3D view is unavailable', 'WebGL couldn’t start on this device. Browse your notes below or ask a question — your knowledge is still here.');
      $('system-state').textContent = 'Note index available';
      setBrowser(true);
    }
  }

  /* -------------------- command palette -------------------- */

  const COMMANDS = [
    { id: 'ask', label: 'Ask a question', hint: 'Enter', run: query => query && sendQuestion(query) },
    { id: 'operator', label: 'Run a task in the Operator', hint: 'Operator', run: query => {
      if (!query) return window.galaxyAgent?.open?.();
      if (window.galaxyAgent?.start) window.galaxyAgent.start(query);
    } },
    { id: 'memory', label: 'Open Studio · Memory', hint: 'Studio', run: () => window.galaxyStudio?.openTab?.('memory') },
    { id: 'sessions', label: 'Open Studio · Sessions', hint: 'Studio', run: () => window.galaxyStudio?.openTab?.('sessions') },
    { id: 'system', label: 'Open Studio · System', hint: 'Studio', run: () => window.galaxyStudio?.openTab?.('system') },
    { id: 'docs', label: 'Open Studio · Documents', hint: 'Studio', run: () => window.galaxyStudio?.openTab?.('docs') },
    { id: 'files', label: 'Open Studio · Files', hint: 'Studio', run: () => window.galaxyStudio?.openTab?.('files') },
    { id: 'services', label: 'Open Studio · Services', hint: 'Studio', run: () => window.galaxyStudio?.openTab?.('overview') },
    { id: 'selfmod', label: 'Open Studio · Selfmod', hint: 'Studio', run: () => window.galaxyStudio?.openTab?.('selfmod') },
    { id: 'capabilities', label: 'Show capabilities', hint: '?', run: () => $('capability-toggle')?.click() },
    { id: 'rotate', label: 'Toggle galaxy rotation', hint: 'View', run: () => toggleRotation() },
    { id: 'connections', label: 'Toggle connections between orbs', hint: 'View', run: () => {
      const box = $('display-connections');
      box.checked = !(box.checked !== false);
      setConnections(box.checked);
      saveSettings();
    } },
    { id: 'reset', label: 'Reset camera', hint: 'View', run: () => resetView() },
    { id: 'reset-display', label: 'Reset view settings', hint: 'View', run: () => resetDisplaySettings() },
  ];

  function renderCommands(query = '') {
    const list = $('command-results');
    if (!list) return;
    const needle = String(query || '').toLocaleLowerCase();
    const matches = COMMANDS.filter(item => !needle || (item.label + ' ' + item.hint).toLocaleLowerCase().includes(needle));
    list.replaceChildren();
    matches.forEach((item, index) => {
      const button = document.createElement('button');
      button.type = 'button';
      button.className = 'command-result';
      button.setAttribute('role', 'option');
      button.dataset.command = item.id;
      const label = document.createElement('span');
      label.textContent = item.label;
      const hint = document.createElement('small');
      hint.textContent = index === 0 && $('command-input')?.value.trim() ? 'Enter' : item.hint;
      button.append(label, hint);
      button.addEventListener('click', () => executeCommand(item));
      list.append(button);
    });
    if (!matches.length) {
      const empty = document.createElement('p');
      empty.className = 'empty-state';
      empty.textContent = 'No command; press Enter to ask it instead.';
      list.append(empty);
    }
  }

  function executeCommand(item) {
    const query = $('command-input')?.value.trim() || '';
    closeCommands();
    if (!item) { if (query) sendQuestion(query); return; }
    item.run(query);
  }

  let commandReturnFocus = null;
  function openCommands() {
    const overlay = $('command-overlay');
    if (!overlay) return;
    commandReturnFocus = document.activeElement;
    overlay.hidden = false;
    $('command-input').value = '';
    renderCommands('');
    setTimeout(() => $('command-input')?.focus(), 0);
  }

  function closeCommands() {
    const overlay = $('command-overlay');
    if (overlay) overlay.hidden = true;
    if (commandReturnFocus && typeof commandReturnFocus.focus === 'function') {
      commandReturnFocus.focus({ preventScroll: true });
    }
    commandReturnFocus = null;
  }

  $('command-overlay')?.addEventListener('keydown', event => {
    if (event.key !== 'Tab') return;
    const focusable = [...event.currentTarget.querySelectorAll(
      'button:not([disabled]), input:not([disabled]), [href], [tabindex]:not([tabindex="-1"])')]
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
  });

  $('command-close')?.addEventListener('click', closeCommands);
  $('command-backdrop')?.addEventListener('click', closeCommands);
  $('command-input')?.addEventListener('input', event => renderCommands(event.target.value));
  $('command-input')?.addEventListener('keydown', event => {
    if (event.key === 'Enter') {
      event.preventDefault();
      const query = event.target.value.trim();
      const first = COMMANDS.find(item => !query || (item.label + ' ' + item.hint).toLocaleLowerCase().includes(query.toLocaleLowerCase()));
      executeCommand(first || null);
    }
    if (event.key === 'ArrowDown') {
      event.preventDefault();
      $('command-results')?.querySelector('button')?.focus();
    }
  });

  /* -------------------- HUD: rail, forces, display, theme, core -------------------- */

  function setCoreState(state) {
    const dial = $('dial');
    const pill = $('status-pill');
    const label = pill && pill.querySelector ? pill.querySelector('span') : null;
    if (dial) dial.dataset.state = state;
    if (pill) pill.dataset.state = state;
    if (label) label.textContent = state === 'thinking' ? 'THINKING' : state === 'speaking' ? 'SPEAKING' : 'ONLINE';
  }

  function setRepel(value) {
    const strength = Math.max(5, Number(value) || 42);
    const input = $('force-repel');
    if (input) input.value = String(strength);
    const charge = graph && graph.d3Force ? graph.d3Force('charge') : null;
    if (!charge) return;
    charge.strength(-strength);
    if (graph.d3ReheatSimulation) graph.d3ReheatSimulation();
  }

  function setLinkLength(value) {
    const distance = Math.max(6, Number(value) || 40);
    const input = $('force-link');
    if (input) input.value = String(distance);
    const link = graph && graph.d3Force ? graph.d3Force('link') : null;
    if (!link) return;
    link.distance(distance);
    if (graph.d3ReheatSimulation) graph.d3ReheatSimulation();
  }

  function setHubLabels(on) {
    const box = $('display-labels');
    if (box) box.checked = !!on;
    hubLabels.forEach(sprite => { sprite.visible = !!on; });
  }

  function setParticles(on) {
    particlesOn = !!on;
    const box = $('display-particles');
    if (box) box.checked = particlesOn;
    updateHighlights();
  }

  function setStarfield(on) {
    const box = $('display-stars');
    if (box) box.checked = !!on;
    if (starfieldLayer) starfieldLayer.visible = !!on;
  }

  function setConnections(on) {
    connectionsOn = !!on;
    const box = $('display-connections');
    if (box) box.checked = connectionsOn;
    updateHighlights();
    applyLinkVisibility();
  }

  function setLinkWeight(value) {
    const numeric = Number(value);
    linkWeight = Math.max(.05, (Number.isFinite(numeric) && numeric > 0 ? numeric : DISPLAY_DEFAULTS.linkWeight) / 100);
    const input = $('link-weight');
    if (input) input.value = String(Math.round(linkWeight * 100));
    updateHighlights();
  }

  function setNodeScale(value) {
    const numeric = Number(value);
    nodeScale = Math.max(.4, (Number.isFinite(numeric) && numeric > 0 ? numeric : DISPLAY_DEFAULTS.nodeScale) / 100);
    const input = $('node-scale');
    if (input) input.value = String(Math.round(nodeScale * 100));
    updateHighlights();
  }

  function setMenuScale(value) {
    const numeric = Number(value);
    menuScale = Math.max(.85, Math.min(1.4, (Number.isFinite(numeric) && numeric > 0 ? numeric : DISPLAY_DEFAULTS.menuScale) / 100));
    const input = $('menu-scale');
    if (input) input.value = String(Math.round(menuScale * 100));
    const root = document.documentElement;
    if (root && root.style) root.style.setProperty('--menu-scale', String(menuScale));
  }

  function setColorMode(mode) {
    colorMode = mode === 'heat' ? 'heat' : 'type';
    updateHighlights();
  }

  function readSettings() {
    try {
      const raw = window.localStorage?.getItem(SETTINGS_KEY);
      const parsed = raw ? JSON.parse(raw) : null;
      return parsed && typeof parsed === 'object' ? parsed : {};
    } catch (_) { return {}; }
  }

  function saveSettings() {
    try {
      window.localStorage?.setItem(SETTINGS_KEY, JSON.stringify({
        repel: Number($('force-repel').value) || DISPLAY_DEFAULTS.repel,
        linkLength: Number($('force-link').value) || DISPLAY_DEFAULTS.linkLength,
        labels: $('display-labels').checked !== false,
        particles: $('display-particles').checked !== false,
        rotate: $('display-rotate').checked !== false,
        stars: $('display-stars').checked !== false,
        connections: $('display-connections').checked !== false,
        linkWeight: Number($('link-weight').value) || DISPLAY_DEFAULTS.linkWeight,
        nodeScale: Number($('node-scale').value) || DISPLAY_DEFAULTS.nodeScale,
        menuScale: Number($('menu-scale').value) || DISPLAY_DEFAULTS.menuScale,
        theme: themeName,
        colorMode
      }));
    } catch (_) { /* Storage may be blocked; the live view still honours this change. */ }
  }

  function applySettings(settings = {}) {
    const next = { ...DISPLAY_DEFAULTS, ...settings };
    $('force-repel').value = String(next.repel);
    $('force-link').value = String(next.linkLength);
    $('display-labels').checked = next.labels !== false;
    $('display-particles').checked = next.particles !== false;
    $('display-rotate').checked = next.rotate !== false;
    $('display-stars').checked = next.stars !== false;
    $('display-connections').checked = next.connections !== false;
    $('link-weight').value = String(next.linkWeight);
    $('node-scale').value = String(next.nodeScale);
    $('menu-scale').value = String(next.menuScale);
    setRepel(next.repel);
    setLinkLength(next.linkLength);
    setHubLabels(next.labels !== false);
    setParticles(next.particles !== false);
    setStarfield(next.stars !== false);
    setConnections(next.connections !== false);
    setLinkWeight(next.linkWeight);
    setNodeScale(next.nodeScale);
    setMenuScale(next.menuScale);
    setColorMode(next.colorMode);
    setModeButtons(next.colorMode);
    setTheme(next.theme);
    rotating = next.rotate !== false && !motion.matches;
    updateRotation();
  }

  function applyGraphSettings() {
    // Set the simulation forces directly: reheating from inside initGraph runs
    // before the force engine's first tick and crashes 3d-force-graph 1.79.
    const charge = graph && graph.d3Force ? graph.d3Force('charge') : null;
    if (charge) charge.strength(-(Number($('force-repel').value) || DISPLAY_DEFAULTS.repel));
    const linkForce = graph && graph.d3Force ? graph.d3Force('link') : null;
    if (linkForce) linkForce.distance(Number($('force-link').value) || DISPLAY_DEFAULTS.linkLength);
    setHubLabels($('display-labels').checked !== false);
    setParticles($('display-particles').checked !== false);
    setStarfield($('display-stars').checked !== false);
    setConnections($('display-connections').checked !== false);
    setLinkWeight($('link-weight').value);
    setNodeScale($('node-scale').value);
  }

  function resetDisplaySettings() {
    try { window.localStorage?.removeItem(SETTINGS_KEY); } catch (_) { /* Nothing stored to clear. */ }
    applySettings({});
  }

  function accentRgba(hex, alpha) {
    const value = hex.replace('#', '');
    const int = parseInt(value.length === 3 ? value.split('').map(c => c + c).join('') : value, 16);
    return `rgba(${(int >> 16) & 255}, ${(int >> 8) & 255}, ${int & 255}, ${alpha})`;
  }

  const THEMES = {
    emerald: ['#10b981', '#06b6d4'],
    violet: ['#8b5cf6', '#a78bfa'],
    matrix: ['#22c55e', '#4ade80'],
    cyan: ['#06b6d4', '#22d3ee']
  };

  function setTheme(name) {
    themeName = THEMES[name] ? name : 'emerald';
    const pair = THEMES[themeName];
    const root = document.documentElement;
    if (root && root.style) {
      root.style.setProperty('--accent', pair[0]);
      root.style.setProperty('--accent-2', pair[1]);
      root.style.setProperty('--accent-line', accentRgba(pair[0], .32));
    }
    swatches.forEach(button => {
      const active = button.dataset.accent === name;
      button.classList.toggle('is-active', active);
      button.setAttribute('aria-pressed', String(active));
    });
  }

  function renderFilters() {
    const list = $('filter-list');
    if (!list || !list.replaceChildren) return;
    list.replaceChildren();
    const counts = new Map(groups.map(group => [group, nodes.filter(node => node.group === group).length]));
    [...groups]
      .sort((a, b) => counts.get(b) - counts.get(a) || String(a).localeCompare(String(b)))
      .slice(0, 9)
      .forEach(group => {
        const button = document.createElement('button');
        button.type = 'button';
        button.className = 'filter-row';
        button.setAttribute('aria-pressed', String(activeGroup === group));
        const dot = document.createElement('span');
        dot.className = 'filter-dot';
        dot.style.setProperty('--group-color', colors.get(group) || palette[0]);
        const name = document.createElement('span');
        name.className = 'filter-name';
        name.textContent = group || 'Unfiled';
        const count = document.createElement('span');
        count.className = 'filter-count';
        count.textContent = String(counts.get(group));
        button.append(dot, name, count);
        button.addEventListener('click', () => setGroup(activeGroup === group ? null : group));
        list.append(button);
      });
  }

  function focusNode(node) {
    if (!graph || !node || !Number.isFinite(node.x)) return;
    const length = Math.hypot(node.x, node.y, node.z) || 1;
    const ratio = 1 + 120 / length;
    graph.cameraPosition({ x: node.x * ratio, y: node.y * ratio, z: node.z * ratio }, node, 900);
  }

  function on(input, event, handler) {
    if (input && typeof input.addEventListener === 'function') input.addEventListener(event, handler);
  }

  const swatches = typeof document.querySelectorAll === 'function'
    ? Array.from(document.querySelectorAll('.swatch')) : [];
  const coreButtons = typeof document.querySelectorAll === 'function'
    ? Array.from(document.querySelectorAll('[data-core-mode]')) : [];

  on($('rail-toggle'), 'click', () => {
    const rail = $('rail');
    const toggle = $('rail-toggle');
    if (!rail) return;
    const collapsed = !rail.classList.contains('is-collapsed');
    rail.classList.toggle('is-collapsed', collapsed);
    // The rail slid off-screen but stayed in the tab order and its width kept
    // every stage element offset. Inert + a zero rail width fixes both.
    rail.inert = collapsed;
    if (collapsed) document.documentElement.style.setProperty('--rail', '0px');
    else document.documentElement.style.removeProperty('--rail');
    if (toggle) {
      toggle.classList.toggle('is-collapsed', collapsed);
      toggle.textContent = collapsed ? '›' : '‹';
      toggle.setAttribute('aria-expanded', String(!collapsed));
      toggle.setAttribute('aria-label', collapsed ? 'Show panel' : 'Collapse panel');
    }
    layoutTeardownPanel();
  });

  on($('force-repel'), 'input', event => { setRepel(event.target.value); saveSettings(); });
  on($('force-link'), 'input', event => { setLinkLength(event.target.value); saveSettings(); });
  on($('display-labels'), 'change', event => { setHubLabels(event.target.checked); saveSettings(); });
  on($('display-particles'), 'change', event => { setParticles(event.target.checked); saveSettings(); });
  on($('display-stars'), 'change', event => { setStarfield(event.target.checked); saveSettings(); });
  on($('display-connections'), 'change', event => { setConnections(event.target.checked); saveSettings(); });
  on($('link-weight'), 'input', event => { setLinkWeight(event.target.value); saveSettings(); });
  on($('node-scale'), 'input', event => { setNodeScale(event.target.value); saveSettings(); });
  on($('menu-scale'), 'input', event => { setMenuScale(event.target.value); saveSettings(); });
  on($('display-rotate'), 'change', event => {
    if (event.target.checked !== rotating) toggleRotation();
    saveSettings();
  });
  on($('reset-display'), 'click', () => resetDisplaySettings());

  swatches.forEach(button => on(button, 'click', () => { setTheme(button.dataset.accent); saveSettings(); }));

  const setModeButtons = mode => {
    const typed = $('mode-type');
    const heat = $('mode-heat');
    [[typed, mode === 'type'], [heat, mode === 'heat']].forEach(([button, active]) => {
      if (!button) return;
      button.classList.toggle('is-active', active);
      button.setAttribute('aria-pressed', String(active));
    });
  };
  on($('mode-type'), 'click', () => { setColorMode('type'); setModeButtons('type'); saveSettings(); });
  on($('mode-heat'), 'click', () => { setColorMode('heat'); setModeButtons('heat'); saveSettings(); });

  coreButtons.forEach(button => on(button, 'click', () => {
    const dial = $('dial');
    if (dial) dial.dataset.core = button.dataset.coreMode;
    coreButtons.forEach(other => {
      const active = other === button;
      other.classList.toggle('is-active', active);
      other.setAttribute('aria-pressed', String(active));
    });
  }));

  on($('follow-toggle'), 'click', event => {
    followAgent = !followAgent;
    const button = event.currentTarget;
    if (button) button.setAttribute('aria-pressed', String(followAgent));
    if (followAgent) {
      const first = [...sourceIds][0];
      if (first !== undefined) focusNode(byId.get(first));
    }
  });

  on($('vault-toggle'), 'click', () => {
    if (typeof showLastTeardown === 'function') showLastTeardown();
    else notice('No saved teardown', 'Run a teardown first; the card is saved in the vault.');
  });

  const click = id => {
    const node = $(id);
    if (node && typeof node.click === 'function') node.click();
  };
  on($('quick-mute'), 'click', () => { click('stop-voice'); setCoreState('online'); });
  on($('quick-log'), 'click', () => window.galaxyStudio?.openTab?.('sessions'));
  on($('quick-screen'), 'click', () => window.galaxyAgent?.open?.());
  on($('quick-agents'), 'click', () => click('capability-toggle'));
  on($('quick-skills'), 'click', () => window.galaxyStudio?.openTab?.('skills'));

  if (document.querySelectorAll) {
    document.querySelectorAll('.dock-example').forEach(example => {
      on(example, 'click', () => {
        $('question').value = example.dataset.q || example.textContent || '';
        $('question').focus();
      });
    });
  }

  window.galaxy = {
    get graph() { return graph; }, get ready() { return ready; }, get error() { return graphError; },
    get selectedId() { return selectedId; }, get neighbourIds() { return [...neighbourIds]; },
    get sourceIds() { return [...sourceIds]; }, get activeGroup() { return activeGroup; },
    get rotating() { return rotating; }, get reducedMotion() { return motion.matches; },
    get busy() { return busy || capturePending > 0 || teardownPending; }, nodes, links, groups, sprites,
    get lastBirth() { return lastBirth; }, get teardown() { return teardownJob; },
    selectNode, searchNotes, setGroup, resetView, toggleRotation, askQuestion: sendQuestion, addNote, colorFor,
    focusNode, setRepel, setLinkLength, setHubLabels, setParticles, setStarfield, setColorMode, setTheme,
    setConnections, setLinkWeight, setNodeScale, resetDisplaySettings, saveSettings,
    get connectionsOn() { return connectionsOn; }, get linkWeight() { return linkWeight; },
    get nodeScale() { return nodeScale; }, get menuScale() { return menuScale; },
    get theme() { return themeName; },
    setCoreState, renderFilters, get colorMode() { return colorMode; },
    runTeardown, showLastTeardown, openTeardownReader, closeTeardown, cancelTeardown, teardownCurrent,
    layoutTeardownPanel,
    get voice() { return voice; }
  };
  if (typeof window.createGalaxyVoice === 'function') {
    voice = window.createGalaxyVoice({ submit: askQuestion, interrupt: cancelQuestion });
    voice.routes.push({ pattern: REMEMBER_PATTERN, handler: (_sentence, match) => rememberNote(match[1]) });
    $('stop-voice').addEventListener('click', () => voice.dispatch('stop'));
  }

  $('node-count').textContent = String(nodes.length);
  $('boot-greeting').textContent = window.GALAXY_PERSONA?.greeting || '';
  $('link-count').textContent = String(links.length);
  applySettings(readSettings());
  renderGroups();
  setGroup(null);
  renderSearch();
  updateRotation();
  $('note-search').addEventListener('input', () => { setBrowser(true); renderSearch(); });
  $('note-search').addEventListener('focus', () => setBrowser(true));
  $('search-form').addEventListener('submit', event => {
    event.preventDefault();
    const first = searchNotes($('note-search').value)[0];
    if (first) selectNode(first.id, { focus: true });
  });
  if ($('browse-toggle')) $('browse-toggle').addEventListener('click', () => setBrowser($('note-browser').hidden));
  $('close-browser').addEventListener('click', () => { setBrowser(false); const toggle = $('browse-toggle'); if (toggle) toggle.focus(); });
  $('close-note').addEventListener('click', () => { closeNote(); updateRotation(); $('note-search').focus({ preventScroll: true }); });
  $('td-close').addEventListener('click', () => { closeTeardown(); });
  $('td-read').addEventListener('click', () => { openTeardownReader(); });
  $('td-reader-close').addEventListener('click', () => { closeTeardownReader(); });
  $('td-reader-backdrop').addEventListener('click', () => { closeTeardownReader(); });
  window.addEventListener?.('resize', layoutTeardownPanel);
  if (typeof MutationObserver === 'function') {
    const teardownObserver = new MutationObserver(() => layoutTeardownPanel());
    [$('atlas-panel'), $('note-panel'), $('answer-panel')].filter(Boolean)
      .forEach(node => teardownObserver.observe(node, { attributes: true, attributeFilter: ['hidden'] }));
  }
  if (typeof ResizeObserver === 'function') {
    const teardownResize = new ResizeObserver(() => layoutTeardownPanel());
    [$('atlas-panel'), $('note-panel'), $('answer-panel'), $('chat-dock')].filter(Boolean)
      .forEach(node => teardownResize.observe(node));
  }
  $('rotate-toggle').addEventListener('click', toggleRotation);
  $('reset-view').addEventListener('click', resetView);
  $('close-answer').addEventListener('click', () => { $('answer-panel').hidden = true; $('question').focus(); });
  $('chat-form').addEventListener('submit', event => { event.preventDefault(); sendQuestion($('question').value); });
  document.addEventListener('keydown', event => {
    if ((event.ctrlKey || event.metaKey) && event.key.toLocaleLowerCase() === 'k') {
      event.preventDefault();
      openCommands();
      return;
    }
    if (event.key === 'Escape' && !$('command-overlay').hidden) { closeCommands(); return; }
    const editing = document.activeElement && document.activeElement.matches('input,textarea,[contenteditable=true]');
    if (event.key === '/' && !editing && !event.ctrlKey && !event.metaKey && !event.altKey) {
      event.preventDefault();
      setBrowser(true);
      $('note-search').focus();
    }
    if (event.key === 'Escape') {
      if (!$('td-reader').hidden) { closeTeardownReader(); return; }
      closeNote();
      setBrowser(false);
      $('answer-panel').hidden = true;
      updateRotation();
    }
  });
  document.addEventListener('visibilitychange', () => {
    updateRotation();
    if (!graph) return;
    try {
      if (document.hidden && typeof graph.pauseAnimation === 'function') graph.pauseAnimation();
      else if (!document.hidden && typeof graph.resumeAnimation === 'function') graph.resumeAnimation();
    } catch (_) {}
  });

  // An unfocused window keeps document.hidden === false and Electron reports
  // document.hasFocus() === true even behind another window, so neither signal is
  // usable. Idle input is: after a minute without a pointer or a key the graph
  // stops rendering, and the first interaction brings it back.
  const GRAPH_IDLE_PAUSE_MS = 60000;
  // The Node harnesses that load this file provide a partial fake window, so every
  // listener goes through one guard instead of assuming addEventListener exists.
  const onWindow = (name, handler, options) => {
    if (typeof window.addEventListener === 'function') window.addEventListener(name, handler, options);
  };
  ['pointermove', 'pointerdown', 'keydown', 'wheel', 'touchstart', 'scroll'].forEach((name) => {
    onWindow(name, () => { lastInteraction = performanceNow(); }, { passive: true });
  });
  function syncGraphLoop() {
    if (!graph) return;
    const idle = performanceNow() - lastInteraction;
    const shouldPause = document.hidden || idle >= GRAPH_IDLE_PAUSE_MS;
    try {
      if (shouldPause && !graphLoopPaused && typeof graph.pauseAnimation === 'function') {
        graph.pauseAnimation();
        graphLoopPaused = true;
        updateRotation();
      } else if (!shouldPause && graphLoopPaused && typeof graph.resumeAnimation === 'function') {
        graph.resumeAnimation();
        graphLoopPaused = false;
        updateRotation();
      }
    } catch (_) { /* a paused graph must never block the rest of the UI */ }
  }
  if (typeof setInterval === 'function') setInterval(syncGraphLoop, 4000);
  onWindow('blur', syncGraphLoop);
  onWindow('focus', syncGraphLoop);
  ['pointerdown', 'pointermove', 'keydown', 'wheel', 'touchstart'].forEach((name) => {
    onWindow(name, () => {
      if (!graphLoopPaused) return;
      graphLoopPaused = false;
      try { graph.resumeAnimation(); } catch (_) {}
      updateRotation();
    }, { passive: true });
  });
  document.addEventListener('visibilitychange', syncGraphLoop);
  // Read-only diagnostic so a live check can prove the loop is paused or resumed
  // without guessing from CPU sampling.
  window.__jarvisGraph = () => ({ paused: graphLoopPaused, rotating,
                                  selected: selectedId !== null,
                                  focused: document.hasFocus() });
  motion.addEventListener('change', () => { rotating = !motion.matches; updateRotation(); updateHighlights(); });
  async function updateSubsystems() {
    try {
      const res = await fetch('/modules', { credentials: 'same-origin', headers: { 'Accept': 'application/json' } });
      if (!res.ok) return;
      const data = await res.json();
      const mods = new Set((data.modules || []).filter(m => m.enabled).map(m => m.name));
      const setMod = (id, enabled) => {
        const el = document.getElementById(id);
        if (el) {
          el.textContent = enabled ? 'on' : 'off';
          el.style.color = enabled ? 'var(--accent)' : 'var(--dim)';
        }
      };
      setMod('mod-eyes-state', mods.has('vision_analyze'));
      setMod('mod-watch-state', mods.has('watch_pages'));
      setMod('mod-files-state', mods.has('file_watch'));
      setMod('mod-beat-state', mods.has('heartbeat'));
      setMod('mod-agents-state', mods.has('agents'));
    } catch (_) {}
  }
  if (typeof window !== 'undefined' && window.location && window.location.protocol && window.location.protocol.startsWith('http')) {
    updateSubsystems();
  }
  initGraph();
})();
