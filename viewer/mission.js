'use strict';
// Jarvis Mission Control: live UI cockpit for multi-agent teams, cloud budget
// guard, MAP-Elites evolution, Night Shift, owner questions, macros, time-travel,
// and encrypted backups.
(() => {
  const $ = id => document.getElementById(id);

  function el(tag, cls, text) {
    const node = document.createElement(tag);
    if (cls) node.className = cls;
    if (text !== undefined) node.textContent = text;
    return node;
  }

  function setStatus(msg) {
    const st = $('studio-status');
    if (st) st.textContent = msg;
    const mst = $('mission-status-line');
    if (mst) mst.textContent = msg;
  }

  async function apiGet(path) {
    if (window.JarvisAPI && typeof window.JarvisAPI.get === 'function') {
      return window.JarvisAPI.get(path);
    }
    // Fallback: the original implementation, kept for the case where the
    // api.js patch is not present (zero regression without JarvisAPI).
    const res = await fetch(path, {
      credentials: 'same-origin',
      cache: 'no-store',
      headers: { Accept: 'application/json' },
    });
    const body = await res.json();
    if (!res.ok || body.error) {
      throw new Error(body.error?.message || `Błąd żądania (${res.status})`);
    }
    return body;
  }

  async function apiPost(path, payload) {
    if (window.JarvisAPI && typeof window.JarvisAPI.post === 'function') {
      return window.JarvisAPI.post(path, payload);
    }
    // Fallback: the original implementation, kept for the case where the
    // api.js patch is not present (zero regression without JarvisAPI).
    const res = await fetch(path, {
      method: 'POST',
      credentials: 'same-origin',
      cache: 'no-store',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      body: JSON.stringify(payload),
    });
    const body = await res.json();
    if (!res.ok || body.error) {
      throw new Error(body.error?.message || `Błąd akcji (${res.status})`);
    }
    return body;
  }

  function fillList(id, items, emptyLabel) {
    const list = $(id);
    if (!list) return;
    list.replaceChildren();
    if (!items.length) {
      list.append(el('li', 'empty-state', emptyLabel));
      return;
    }
    items.forEach(item => list.append(item));
  }

  async function loadMissionControl() {
    const root = $('studio-mission');
    if (!root) return;
    try {
      setStatus('Odświeżanie Mission Control…');
      const data = await apiGet('/mission/status');

      // 1. Metrics cards (Cloud Budget + Router Circuits + Watchdog + MAP-Elites)
      const metricsWrap = $('mission-metrics');
      if (metricsWrap) {
        metricsWrap.replaceChildren();
        const b = data.budget || {};
        const circuits = Object.keys((data.router || {}).active_circuits || {});
        const incCount = ((data.watchdog || {}).recent_incidents || []).length;
        const elitesCount = Object.keys(data.map_elites || {}).length;
        const brief = data.briefing || {};
        const tel = brief.telemetry || {};
        const epStats = data.episodic_memory || {};
        const semCache = data.semantic_cache || {};
        const tempPart = tel.peak_temp_c !== null && tel.peak_temp_c !== undefined ? `${tel.peak_temp_c}°C · ` : '';

        const cards = [
          [`$${Number(b.spent_today_usd || 0).toFixed(2)} / $${Number(b.daily_limit_usd || 5).toFixed(2)}`, `Budżet dziś (${b.state || 'ok'}) · cache -$${Number(semCache.saved_usd || 0).toFixed(2)}`],
          [String(circuits.length), circuits.length ? `Kwarantanna 429: ${circuits.join(', ')}` : 'Bezpiecznik 429: czysto'],
          [tel.process_rss_mb ? `${tempPart}${tel.process_rss_mb} MB` : 'n/d', `Temp / RAM Jarvisa · wolne ${tel.disk_free_gb ?? '?'} GB`],
          [String(epStats.total || 0), `Epizody w pamięci · ${elitesCount} MAP-Elites · ${incCount} inc.`],
        ];
        cards.forEach(([val, label]) => {
          const card = el('div', 'studio-metric studio-metric-value');
          card.append(el('strong', '', val), el('span', '', label));
          metricsWrap.append(card);
        });

        let intelBox = $('mission-intel-panel');
        if (!intelBox) {
          intelBox = el('div', 'studio-card');
          intelBox.id = 'mission-intel-panel';
          metricsWrap.after(intelBox);
        }
        intelBox.replaceChildren();
        intelBox.append(
          el('strong', '', 'Poranny Briefing, Bezpieczeństwo & Pamięć Epizodyczna'),
          el('p', 'studio-hint', brief.spoken_summary || 'Brak podsumowania.')
        );

        const toolRow = el('div', 'studio-actions');
        const secBtn = el('button', 'studio-button', 'Skanuj sekrety i AST');
        secBtn.type = 'button';
        secBtn.addEventListener('click', async () => {
          try {
            const sres = await apiPost('/mission/action', { action: 'security_scan' });
            setStatus(sres.ok
              ? `Skan bezpieczeństwa: czysto (${sres.scanned_files} plików).`
              : `Wykryto ${sres.findings_count} zagrożeń w kodzie!`);
          } catch (err) {
            setStatus(err.message);
          }
        });

        const qaBtn = el('button', 'studio-button', 'Audyt QA Viewer');
        qaBtn.type = 'button';
        qaBtn.addEventListener('click', async () => {
          try {
            const qres = await apiPost('/mission/action', { action: 'qa_audit' });
            setStatus(qres.ok
              ? `Bramka QA Viewer: OK (${qres.checked_js} plików JS).`
              : `Bramka QA wykryła uwagi: ${(qres.issues || []).join('; ')}`);
          } catch (err) {
            setStatus(err.message);
          }
        });

        const timerBtn = el('button', 'studio-button', 'Zapisz timer 03:30');
        timerBtn.type = 'button';
        timerBtn.addEventListener('click', async () => {
          try {
            const tres = await apiPost('/mission/action', { action: 'install_night_timer', enable: false });
            setStatus(`Zapisano jednostki systemd Night Shift (${(tres.files || []).length} pliki).`);
          } catch (err) {
            setStatus(err.message);
          }
        });

        const docBtn = el('button', 'studio-button primary', 'Autodiagnostyka i Naprawa');
        docBtn.type = 'button';
        docBtn.addEventListener('click', async () => {
          try {
            const dres = await apiPost('/mission/action', { action: 'run_doctor', auto_heal: true });
            const healed = (dres.healed_actions || []).length;
            setStatus(`Zdrowie systemu: ${dres.health_score}/100 · naprawiono automatycznie: ${healed}.`);
            loadMissionControl();
          } catch (err) {
            setStatus(err.message);
          }
        });

        const diskBtn = el('button', 'studio-button', 'Dyski i kopie');
        diskBtn.type = 'button';
        diskBtn.addEventListener('click', async () => {
          try {
            const srep = await apiPost('/mission/action', { action: 'storage_report' });
            const drv = (srep.drives || []).map(d => `${d.device}(${d.media} ${d.size_gb}GB${d.temp_c ? ` ${d.temp_c}°C` : ''})`).join(', ') || 'brak';
            const bkp = srep.mcp_backups || {};
            if ((bkp.count || 0) > 30) {
              const pr = await apiPost('/mission/action', { action: 'prune_backups', keep_latest: 30 });
              setStatus(`Dyski: ${drv} · oczyszczono ${pr.removed} starych kopii (-${pr.freed_mb} MB).`);
            } else {
              setStatus(`Dyski: ${drv} · kopie .bak: ${bkp.count || 0} (${bkp.total_mb || 0} MB).`);
            }
          } catch (err) {
            setStatus(err.message);
          }
        });

        toolRow.append(docBtn, secBtn, qaBtn, diskBtn, timerBtn);
        intelBox.append(toolRow);

        const planRow = el('div', 'studio-row');
        const planInput = el('input', '');
        planInput.type = 'text';
        planInput.placeholder = 'Cel zadania dla planera AST (np. Dodaj eksport raportu w viewer/)…';
        const planBtn = el('button', 'studio-button', 'Zaplanuj fale');
        planBtn.type = 'button';
        const planOut = el('div', '');
        planBtn.addEventListener('click', async () => {
          const goalText = planInput.value.trim();
          if (!goalText) return;
          try {
            const pres = await apiPost('/mission/action', { action: 'plan_task', goal: goalText });
            planOut.replaceChildren();
            planOut.append(el(
              'p',
              'studio-hint',
              `Złożoność: ${pres.complexity} · Koszt ~ $${pres.est_total_usd} · Fale: ${(pres.waves || []).length} (max równolegle: ${pres.max_parallel_agents})`
            ));
            const streamList = el('ul', 'studio-list');
            (pres.assignments || []).forEach(asg => {
              const li = el('li', 'studio-item');
              li.append(
                el('strong', '', `[${asg.role}] ${asg.agent} ($${asg.est_usd})`),
                el('span', 'studio-hint', (asg.paths || []).join(', '))
              );
              streamList.append(li);
            });
            const launchBtn = el('button', 'studio-button primary', 'Uruchom ten plan w zespole');
            launchBtn.type = 'button';
            launchBtn.addEventListener('click', async () => {
              try {
                const started = await apiPost('/agents/team/start', {
                  goal: goalText,
                  assignments: pres.assignments,
                });
                setStatus(`Uruchomiono zespół ${started.id || ''} z rozłącznym planem AST.`);
                loadMissionControl();
              } catch (err) {
                setStatus(err.message);
              }
            });
            planOut.append(streamList, launchBtn);
          } catch (err) {
            setStatus(err.message);
          }
        });
        planRow.append(planInput, planBtn);
        intelBox.append(planRow, planOut);

        let cortexCard = $('mission-cortex-card');
        if (!cortexCard) {
          cortexCard = el('div', 'studio-card');
          cortexCard.id = 'mission-cortex-card';
          intelBox.after(cortexCard);
        }
        cortexCard.replaceChildren();
        const cx = data.cortex || {};
        cortexCard.append(
          el('strong', '', `Jarvis Cortex & 7-Etapowy Autopilot (${cx.total_nodes || 0} węzłów · ${cx.total_edges || 0} relacji)`),
          el('p', 'studio-hint', 'Graf topologii modułów, tras HTTP i tematów SSE oraz autonomiczna maszyna stanów Spec -> Testy -> Bezpieczeństwo -> Pamięć.')
        );

        const cxOut = el('div', '');
        const cxRow = el('div', 'studio-row');
        const cxGoal = el('input', '');
        cxGoal.type = 'text';
        cxGoal.placeholder = 'Cel dla 7-etapowego Autopilota lub zapytanie do grafu Cortex…';

        const graphBtn = el('button', 'studio-button', 'Zbuduj graf Cortex');
        graphBtn.type = 'button';
        graphBtn.addEventListener('click', async () => {
          try {
            const gres = await apiPost('/mission/action', { action: 'build_graph' });
            const cyc = ((gres.anomalies || {}).circular_imports || []).length;
            const kinds = gres.by_kind || {};
            setStatus(`Cortex: ${gres.total_nodes} węzłów (moduły: ${kinds.module || 0}, trasy: ${kinds.http_route || 0}, SSE: ${kinds.sse_topic || 0}) · cykle: ${cyc}.`);
            loadMissionControl();
          } catch (err) {
            setStatus(err.message);
          }
        });

        const renderAutopilotResult = ares => {
          cxOut.replaceChildren();
          cxOut.append(el('p', 'studio-hint', `Przebieg ${ares.run_id} (${ares.status}) — wykonano ${(ares.stages || []).length}/7 etapów:`));
          const stList = el('ul', 'studio-list');
          (ares.stages || []).forEach(st => {
            const li = el('li', 'studio-item');
            li.append(
              el('strong', '', `[${st.status.toUpperCase()}] ${st.stage}`),
              el('span', 'studio-hint', st.detail || '')
            );
            stList.append(li);
          });
          const specPre = el('pre', 'studio-hint', ares.spec_markdown || '');
          cxOut.append(stList, specPre);
        };

        const apDryBtn = el('button', 'studio-button primary', 'Autopilot: Spec + Bramki');
        apDryBtn.type = 'button';
        apDryBtn.addEventListener('click', async () => {
          const g = cxGoal.value.trim();
          if (!g) return;
          try {
            setStatus('Uruchamianie 7-etapowego Autopilota (weryfikacja lokalna)…');
            const ares = await apiPost('/mission/action', { action: 'autopilot_run', goal: g, execute_team: false });
            renderAutopilotResult(ares);
            setStatus(`Autopilot ${ares.run_id}: ${ares.ok ? 'wszystkie bramki zielone' : 'wykryto uwagi'}.`);
          } catch (err) {
            setStatus(err.message);
          }
        });

        const apTeamBtn = el('button', 'studio-button', 'Autopilot: Start Zespołu');
        apTeamBtn.type = 'button';
        apTeamBtn.addEventListener('click', async () => {
          const g = cxGoal.value.trim();
          if (!g) return;
          try {
            setStatus('Uruchamianie Autopilota wraz z zespołem agentów…');
            const ares = await apiPost('/mission/action', { action: 'autopilot_run', goal: g, execute_team: true });
            renderAutopilotResult(ares);
            loadMissionControl();
          } catch (err) {
            setStatus(err.message);
          }
        });

        cxRow.append(cxGoal, graphBtn, apDryBtn, apTeamBtn);
        cortexCard.append(cxRow, cxOut);

        let connCard = $('mission-connectors-card');
        if (!connCard) {
          connCard = el('div', 'studio-card');
          connCard.id = 'mission-connectors-card';
          cortexCard.after(connCard);
        }
        connCard.replaceChildren();
        const cdig = data.connectors || {};
        connCard.append(
          el('strong', '', `Rejestr Narzędzi i Integracji (${cdig.configured_count || 0} podpięte · ${cdig.active_tools_count || 0} aktywnych funkcji · ${cdig.catalog_total || 18} w katalogu)`),
          el('p', 'studio-hint', 'Przełączaj całe zestawy (Toolsets) oraz podpinaj Kalendarz, Gmail, Notion, Todoist, Obsidian, Home Assistant, GitHub, Linear, Slack, Discord, Telegram, ntfy, Spotify, Web, Cron i MCP.')
        );

        const tsBar = el('div', 'studio-row');
        const dynForm = el('div', '');
        const connOut = el('div', '');

        apiGet('/mission/connectors').then(reg => {
          tsBar.replaceChildren();
          (reg.toolsets || []).forEach(ts => {
            const b = el('button', ts.enabled ? 'studio-button primary' : 'studio-button', `${ts.enabled ? '✓ ' : '○ '}${ts.label}`);
            b.type = 'button';
            b.title = ts.description || '';
            b.addEventListener('click', async () => {
              try {
                await apiPost('/mission/action', { action: 'toolset_toggle', toolset: ts.id, enabled: !ts.enabled });
                setStatus(`${!ts.enabled ? 'Włączono' : 'Wyłączono'} zestaw: ${ts.label}`);
                loadMissionControl();
              } catch (err) {
                setStatus(err.message);
              }
            });
            tsBar.append(b);
          });

          const catList = reg.catalog || [];
          const selRow = el('div', 'studio-row');
          const provSelect = el('select', '');
          catList.forEach(item => {
            const badge = item.status === 'connected' ? '[POŁĄCZONO] ' : (item.status === 'ready_zero_key' ? '[GOTOWE] ' : (item.status === 'disabled' ? '[WYŁ.] ' : ''));
            const opt = el('option', '', `${badge}${item.title}`);
            opt.value = item.provider;
            provSelect.append(opt);
          });

          const fieldsBox = el('div', 'studio-row');
          const hintEl = el('p', 'studio-hint', '');
          let currentInputs = [];

          const renderSelectedProvider = () => {
            const meta = catList.find(c => c.provider === provSelect.value) || catList[0];
            fieldsBox.replaceChildren();
            currentInputs = [];
            if (!meta) return;
            const toolNames = (meta.tools || []).map(t => t.name).join(', ');
            hintEl.textContent = `${meta.setup_hint} · Udostępniane narzędzia: ${toolNames}`;
            (meta.fields || []).forEach(f => {
              const inp = el('input', '');
              inp.type = f.secret ? 'password' : 'text';
              inp.placeholder = f.label;
              inp.dataset.fieldKey = f.key;
              currentInputs.push(inp);
              fieldsBox.append(inp);
            });
            if ((meta.fields || []).length > 0) {
              const saveBtn = el('button', 'studio-button primary', 'Podłącz i zapisz (0600)');
              saveBtn.type = 'button';
              saveBtn.addEventListener('click', async () => {
                const settings = {};
                currentInputs.forEach(inp => {
                  const val = inp.value.trim();
                  if (val) settings[inp.dataset.fieldKey] = val;
                });
                try {
                  await apiPost('/mission/action', {
                    action: 'connector_configure',
                    provider: meta.provider,
                    connector_id: meta.provider,
                    settings,
                  });
                  setStatus(`Zapisano integrację ${meta.title} w sejfie 0600.`);
                  loadMissionControl();
                } catch (err) {
                  setStatus(err.message);
                }
              });
              fieldsBox.append(saveBtn);
            }
          };

          provSelect.addEventListener('change', renderSelectedProvider);
          selRow.append(provSelect);
          dynForm.replaceChildren(selRow, hintEl, fieldsBox);
          renderSelectedProvider();
        }).catch(() => {});

        const actRow = el('div', 'studio-row');
        const quickActions = [
          ['Kalendarz (7 dni)', { connector_action: 'calendar_events', days_ahead: 7 }, res => `Spotkania (${res.count || 0}): ${(res.events || []).map(e => `${e.summary} (${e.start})`).join(' · ') || 'brak'}`],
          ['Skrzynka Gmail', { connector_action: 'gmail_inbox', limit: 6 }, res => `Gmail (${res.count || 0}): ${(res.messages || []).map(m => m.subject).join(' · ') || 'brak'}`],
          ['Pogoda teraz', { connector_action: 'weather_forecast' }, res => `Pogoda (${res.coords}): ${(res.current || {}).temperature_2m ?? '?'}°C · wiatr ${(res.current || {}).wind_speed_10m ?? '?'} km/h`],
          ['Home Assistant', { connector_action: 'ha_list_entities' }, res => `Home Assistant: ${res.count || 0} encji`],
          ['Zadania Cron', { connector_action: 'cron_list' }, res => `Harmonogram Cron (${res.count || 0}): ${(res.jobs || []).map(j => `${j.name} [${j.schedule}]`).join(' · ') || 'brak'}`],
        ];
        quickActions.forEach(([label, payload, fmt]) => {
          const btn = el('button', 'studio-button', label);
          btn.type = 'button';
          btn.addEventListener('click', async () => {
            try {
              const res = await apiPost('/mission/action', { action: 'connector_exec', ...payload });
              connOut.replaceChildren(el('p', 'studio-hint', fmt(res)));
            } catch (err) {
              setStatus(err.message);
            }
          });
          actRow.append(btn);
        });

        connCard.append(tsBar, dynForm, actRow, connOut);

        let autoCard = $('mission-automations-card');
        if (!autoCard) {
          autoCard = el('div', 'studio-card');
          autoCard.id = 'mission-automations-card';
          connCard.after(autoCard);
        }
        autoCard.replaceChildren();
        autoCard.append(
          el('strong', '', 'Automatyzacje, Harmonogram Cron & Reguły Reaktywne'),
          el('p', 'studio-hint', 'Obsługuje wyrażenia 5-polowe Cron (np. */30 * * * *) oraz skróty (every 15m, daily 08:00, weekdays 09:00) z dostarczaniem do SSE, Obsidian, Telegram, Slack, Discord i ntfy.')
        );

        const presetRow = el('div', 'studio-row');
        const autoListBox = el('div', '');

        apiPost('/mission/action', { action: 'automation_status' }).then(ast => {
          presetRow.replaceChildren();
          (ast.presets || []).forEach(pr => {
            const pb = el('button', 'studio-button', `+ Szablon: ${pr.name} (${pr.schedule})`);
            pb.type = 'button';
            pb.addEventListener('click', async () => {
              try {
                await apiPost('/mission/action', { action: 'automation_preset', preset_id: pr.id });
                setStatus(`Zainstalowano rutynę: ${pr.name}`);
                loadMissionControl();
              } catch (err) {
                setStatus(err.message);
              }
            });
            presetRow.append(pb);
          });

          autoListBox.replaceChildren();
          const ul = el('ul', 'studio-list');
          (ast.jobs || []).forEach(job => {
            const li = el('li', 'studio-item');
            li.append(
              el('strong', '', `${job.name} [${job.schedule}] -> ${job.deliver || 'local'}`),
              el('span', 'studio-hint', `Uruchomień: ${job.run_count || 0} · Ostatnio: ${job.last_summary || 'oczekuje'}`)
            );
            const runBtn = el('button', 'studio-button primary', 'Uruchom teraz');
            runBtn.type = 'button';
            runBtn.addEventListener('click', async () => {
              try {
                const rres = await apiPost('/mission/action', { action: 'automation_run_now', job_id: job.id });
                setStatus(`Wykonano ${job.name}: ${(rres.execution || {}).summary || 'OK'}`);
                loadMissionControl();
              } catch (err) {
                setStatus(err.message);
              }
            });
            li.append(runBtn);
            ul.append(li);
          });
          if ((ast.jobs || []).length > 0) autoListBox.append(ul);
        }).catch(() => {});

        const newAutoRow = el('div', 'studio-row');
        const aName = el('input', '');
        aName.type = 'text';
        aName.placeholder = 'Nazwa rutyny…';
        const aSched = el('input', '');
        aSched.type = 'text';
        aSched.placeholder = 'Harmonogram (np. daily 08:15 lub */30 * * * *)';
        const aDeliver = el('select', '');
        ['local', 'obsidian', 'ntfy', 'telegram', 'discord', 'slack'].forEach(ch => {
          const o = el('option', '', `Kanał: ${ch}`);
          o.value = ch;
          aDeliver.append(o);
        });
        const aAddBtn = el('button', 'studio-button primary', 'Dodaj automatyzację');
        aAddBtn.type = 'button';
        aAddBtn.addEventListener('click', async () => {
          if (!aName.value.trim() || !aSched.value.trim()) return;
          try {
            await apiPost('/mission/action', {
              action: 'automation_create',
              name: aName.value.trim(),
              schedule: aSched.value.trim(),
              action_type: 'briefing',
              deliver: aDeliver.value,
            });
            setStatus(`Dodano automatyzację: ${aName.value.trim()}`);
            loadMissionControl();
          } catch (err) {
            setStatus(err.message);
          }
        });
        newAutoRow.append(aName, aSched, aDeliver, aAddBtn);
        autoCard.append(presetRow, newAutoRow, autoListBox);

        const nextActs = brief.next_actions || [];
        if (nextActs.length) {
          const actList = el('ul', 'studio-list');
          nextActs.slice(0, 4).forEach(act => {
            const li = el('li', 'studio-item');
            li.append(
              el('strong', '', `[${act.priority}] ${act.title}`),
              el('span', 'studio-hint', act.detail || '')
            );
            actList.append(li);
          });
          intelBox.append(actList);
        }
      }

      // 2. Pending Owner Questions (`jarvis-team ask owner`)
      const qRows = (data.owner_questions || []).map(q => {
        const li = el('li', 'studio-item');
        li.append(el('strong', '', `[${q.from || 'agent'}] ${q.question || ''}`));
        const row = el('div', 'studio-row');
        const inp = el('input', '');
        inp.type = 'text';
        inp.placeholder = 'Odpowiedź dla agenta…';
        const btn = el('button', 'studio-button primary', 'Wyślij');
        btn.type = 'button';
        btn.addEventListener('click', async () => {
          if (!inp.value.trim()) return;
          await apiPost('/agents/owner-reply', { req_id: q.id, project_id: q.project_id, answer: inp.value.trim() });
          setStatus(`Wysłano odpowiedź do ${q.from}.`);
          loadMissionControl();
        });
        row.append(inp, btn);
        li.append(row);
        return li;
      });
      fillList('mission-questions', qRows, 'Brak oczekujących pytań od agentów.');

      // 3. Multi-Agent Team Projects
      const pRows = (data.projects || []).map(p => {
        const li = el('li', 'studio-item');
        li.append(
          el('strong', '', `${p.id} — ${p.status} (${p.phase || 'build'}, runda ${p.current_round})`),
          el('span', 'studio-hint', `Uruchomienia: ${p.total_runs || 0} · Uczestnicy: ${(p.participants || []).join(', ')}`)
        );
        const actions = el('div', 'studio-actions');
        const applyBtn = el('button', 'studio-button primary', 'Wdróż z checkpointem');
        applyBtn.type = 'button';
        applyBtn.addEventListener('click', async () => {
          try {
            const res = await apiPost('/agents/apply', { agent: `team:${p.id}`, target: '' });
            setStatus(`Wdrożono ${res.applied || 0} plików z zespołu ${p.id}.`);
            loadMissionControl();
          } catch (err) {
            setStatus(err.message);
          }
        });
        actions.append(applyBtn);
        li.append(actions);
        return li;
      });
      fillList('mission-projects', pRows, 'Brak aktywnych projektów zespołowych.');

      // 4. Night Shift Report
      const nsNode = $('mission-nightshift-summary');
      if (nsNode) {
        nsNode.textContent = (data.night_shift && data.night_shift.summary_text)
          ? data.night_shift.summary_text
          : 'Jeszcze nie uruchamiano Nocnej Zmiany.';
      }

      // 5. Mined Desktop Macros
      const wf = data.workflows || {};
      const mRows = (wf.patterns || []).map(pat => {
        const li = el('li', 'studio-item');
        li.append(el('strong', '', `${pat.title} (${pat.support}x)`));
        const btn = el('button', 'studio-button', 'Kompiluj w makro');
        btn.type = 'button';
        btn.addEventListener('click', async () => {
          const out = await apiPost('/mission/action', { action: 'compile_macro', pattern_id: pat.id });
          setStatus(`Skompilowano makro: ${out.macro?.name || pat.id}`);
          loadMissionControl();
        });
        li.append(btn);
        return li;
      });
      fillList('mission-macros', mRows, 'Brak powtarzalnych sekwencji akcji na pulpicie.');

      // 6. Time-Travel Timepoints
      const tpRows = (data.timepoints || []).map(tp => {
        const li = el('li', 'studio-item');
        li.append(el('strong', '', `${tp.label} (${tp.session_id}, commit ${String(tp.commit_hash || 'brak').slice(0, 8)})`));
        const btn = el('button', 'studio-button', 'Fork sesji + plików');
        btn.type = 'button';
        btn.addEventListener('click', async () => {
          const res = await apiPost('/mission/action', {
            action: 'fork_timepoint',
            timepoint_id: tp.id,
            restore_files: Boolean(tp.commit_hash),
          });
          setStatus(`Utworzono rozwidlenie: ${res.fork_session_id}`);
          loadMissionControl();
        });
        li.append(btn);
        return li;
      });
      fillList('mission-timepoints', tpRows, 'Brak zapisanych punktów Time-Travel.');

      // 7. Encrypted Backups
      const bRows = (data.backups || []).map(bkp => {
        const li = el('li', 'studio-item');
        li.append(el('strong', '', `${bkp.name} (${Math.round((bkp.bytes || 0) / 1024)} KB)`));
        return li;
      });
      fillList('mission-backups', bRows, 'Brak zaszyfrowanych kopii stanu.');

      setStatus('Mission Control gotowe.');
    } catch (err) {
      setStatus(err.message || 'Nie udało się pobrać stanu Mission Control.');
    }
  }

  function wireControls() {
    const tabBtn = document.querySelector('[data-studio-tab="mission"]');
    if (tabBtn) tabBtn.addEventListener('click', () => loadMissionControl());

    $('mission-refresh')?.addEventListener('click', () => loadMissionControl());

    $('mission-rollback')?.addEventListener('click', async () => {
      try {
        const res = await apiPost('/agents/rollback', {});
        setStatus(`Cofnięto do checkpointu: ${String(res.restored_to || '').slice(0, 10)}`);
        loadMissionControl();
      } catch (err) {
        setStatus(err.message);
      }
    });

    $('mission-run-nightshift')?.addEventListener('click', async () => {
      try {
        setStatus('Trwa wykonywanie cyklu Nocnej Zmiany…');
        await apiPost('/mission/action', { action: 'night_shift', force: true });
        loadMissionControl();
      } catch (err) {
        setStatus(err.message);
      }
    });

    $('mission-team-form')?.addEventListener('submit', async ev => {
      ev.preventDefault();
      const inp = $('mission-team-goal');
      const goal = inp?.value.trim() || '';
      if (!goal) return;
      try {
        const res = await apiPost('/agents/team/start', { goal, plan_first: true });
        inp.value = '';
        setStatus(`Uruchomiono zespół: ${res.project_id}`);
        loadMissionControl();
      } catch (err) {
        setStatus(err.message);
      }
    });

    $('mission-budget-form')?.addEventListener('submit', async ev => {
      ev.preventDefault();
      const val = parseFloat($('mission-budget-daily')?.value || '0');
      if (!val || val <= 0) return;
      try {
        await apiPost('/mission/action', { action: 'budget_config', daily_limit_usd: val });
        setStatus(`Zapisano dzienny limit chmurowy: $${val.toFixed(2)}`);
        loadMissionControl();
      } catch (err) {
        setStatus(err.message);
      }
    });

    $('mission-backup-form')?.addEventListener('submit', async ev => {
      ev.preventDefault();
      const passInput = $('mission-backup-pass');
      const pass = passInput?.value || '';
      if (pass.length < 6) {
        setStatus('Hasło kopii musi mieć minimum 6 znaków.');
        return;
      }
      try {
        const res = await apiPost('/mission/action', { action: 'create_backup', passphrase: pass });
        passInput.value = '';
        setStatus(`Zaszyfrowano i zweryfikowano kopię (${res.file_count} plików).`);
        loadMissionControl();
      } catch (err) {
        setStatus(err.message);
      }
    });

    setupLiveSse();
  }

  let sseSource = null;
  let sseRefreshTimer = null;

  function isMissionActive() {
    const view = $('mission-view');
    return Boolean(view && !view.hidden && document.visibilityState !== 'hidden');
  }

  function scheduleLiveRefresh(note) {
    if (note) setStatus(note);
    if (sseRefreshTimer) clearTimeout(sseRefreshTimer);
    sseRefreshTimer = setTimeout(() => {
      sseRefreshTimer = null;
      if (isMissionActive()) loadMissionControl();
    }, 220);
  }

  function stopSseStream() {
    if (sseSource) {
      sseSource.close();
      sseSource = null;
    }
  }

  function startSseStream() {
    if (sseSource || typeof EventSource === 'undefined' || !isMissionActive()) return;
    try {
      sseSource = new EventSource('/mission/events');
      const liveTopics = [
        'team.message',
        'owner.question',
        'owner.answered',
        'budget.updated',
        'router.circuit_tripped',
        'router.circuit_cleared',
        'night_shift.completed',
      ];
      liveTopics.forEach(topic => {
        sseSource.addEventListener(topic, ev => {
          scheduleLiveRefresh(`Zdarzenie na żywo: ${topic}`);
          void ev;
        });
      });
      sseSource.onerror = () => {
        if (!isMissionActive()) stopSseStream();
      };
    } catch (_) {
      sseSource = null;
    }
  }

  function setupLiveSse() {
    document.addEventListener('visibilitychange', () => {
      if (isMissionActive()) startSseStream();
      else stopSseStream();
    });
    $('mission-tab-btn')?.addEventListener('click', () => {
      setTimeout(() => {
        if (isMissionActive()) startSseStream();
      }, 60);
    });
    const view = $('mission-view');
    if (view && typeof MutationObserver !== 'undefined') {
      const obs = new MutationObserver(() => {
        if (isMissionActive()) startSseStream();
        else stopSseStream();
      });
      obs.observe(view, { attributes: true, attributeFilter: ['hidden'] });
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', wireControls);
  } else {
    wireControls();
  }
})();
