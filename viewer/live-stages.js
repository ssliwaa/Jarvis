/* Jarvis Live Agent Stages & Background Tasks HUD (Etap 2) */
(function () {
  "use strict";
  if (window.__jarvisLiveStagesLoaded) return;
  window.__jarvisLiveStagesLoaded = true;

  const POLL_IDLE_MS = 6000;
  const POLL_ACTIVE_MS = 2200;
  let timer = null;
  let collapsed = false;
  let dismissedIdle = false;

  function esc(str) {
    return String(str == null ? "" : str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function ensureStyles() {
    if (document.getElementById("jarvis-live-stages-css")) return;
    const style = document.createElement("style");
    style.id = "jarvis-live-stages-css";
    style.textContent = `
      #jarvis-live-stages-hud {
        position: fixed;
        right: 18px;
        bottom: 84px;
        width: 365px;
        max-width: calc(100vw - 32px);
        max-height: 68vh;
        overflow-y: auto;
        z-index: 9850;
        background: rgba(13, 17, 26, 0.94);
        backdrop-filter: blur(12px);
        border: 1px solid rgba(99, 179, 237, 0.35);
        border-radius: 12px;
        box-shadow: 0 12px 34px rgba(0, 0, 0, 0.55);
        color: #e2e8f0;
        font-family: system-ui, -apple-system, sans-serif;
        font-size: 12.5px;
        line-height: 1.45;
        padding: 12px 14px;
        transition: opacity 0.2s ease, transform 0.2s ease;
      }
      #jarvis-live-stages-hud.hidden { display: none; }
      .jlsh-head {
        display: flex; align-items: center; justify-content: space-between;
        gap: 8px; margin-bottom: 8px; border-bottom: 1px solid rgba(255,255,255,0.08);
        padding-bottom: 6px;
      }
      .jlsh-title {
        font-weight: 600; font-size: 12.5px; letter-spacing: 0.02em;
        color: #90cdf4; display: flex; align-items: center; gap: 7px;
      }
      .jlsh-dot {
        width: 8px; height: 8px; border-radius: 50%; background: #48bb78;
        box-shadow: 0 0 8px #48bb78; animation: jlshPulse 1.4s infinite ease-in-out;
      }
      .jlsh-dot.idle { background: #718096; box-shadow: none; animation: none; }
      @keyframes jlshPulse {
        0%, 100% { opacity: 1; transform: scale(1); }
        50% { opacity: 0.45; transform: scale(0.82); }
      }
      .jlsh-btns { display: flex; gap: 5px; }
      .jlsh-btn {
        background: rgba(255,255,255,0.07); border: 1px solid rgba(255,255,255,0.12);
        color: #cbd5e0; border-radius: 6px; padding: 2px 7px; font-size: 11px;
        cursor: pointer;
      }
      .jlsh-btn:hover { background: rgba(255,255,255,0.15); color: #fff; }
      .jlsh-btn.danger { border-color: rgba(245, 101, 101, 0.45); color: #feb2b2; }
      .jlsh-btn.accent { border-color: rgba(99, 179, 237, 0.5); color: #90cdf4; }
      .jlsh-card {
        background: rgba(255,255,255,0.035);
        border: 1px solid rgba(255,255,255,0.08);
        border-radius: 9px; padding: 9px 10px; margin-top: 8px;
      }
      .jlsh-card-top {
        display: flex; justify-content: space-between; align-items: center; gap: 6px;
        font-weight: 600; color: #f7fafc; margin-bottom: 4px;
      }
      .jlsh-badge {
        font-size: 10.5px; padding: 1px 6px; border-radius: 99px;
        background: rgba(66, 153, 225, 0.22); color: #90cdf4; font-weight: 600;
      }
      .jlsh-badge.done { background: rgba(72, 187, 120, 0.22); color: #9ae6b4; }
      .jlsh-badge.warn { background: rgba(237, 137, 54, 0.25); color: #fbd38d; }
      .jlsh-task {
        font-size: 11.5px; color: #a0aec0; margin-bottom: 6px;
        white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
      }
      .jlsh-bar-wrap {
        height: 6px; background: rgba(255,255,255,0.09); border-radius: 99px;
        overflow: hidden; margin-bottom: 6px;
      }
      .jlsh-bar {
        height: 100%; background: linear-gradient(90deg, #4299e1, #48bb78);
        transition: width 0.35s ease;
      }
      .jlsh-stage-now {
        font-size: 11.5px; color: #bee3f8; font-weight: 500; margin-bottom: 6px;
      }
      .jlsh-phases { list-style: none; margin: 0; padding: 0; display: grid; gap: 3px; }
      .jlsh-phases li {
        font-size: 11px; color: #718096; display: flex; align-items: center; gap: 6px;
      }
      .jlsh-phases li.done { color: #9ae6b4; }
      .jlsh-phases li.active { color: #f7fafc; font-weight: 600; }
      .jlsh-files {
        margin-top: 6px; padding-top: 5px; border-top: 1px dashed rgba(255,255,255,0.09);
        font-size: 11px; color: #cbd5e0;
      }
      .jlsh-stall {
        margin-top: 6px; padding: 4px 7px; border-radius: 6px;
        background: rgba(237, 137, 54, 0.18); border: 1px solid rgba(237, 137, 54, 0.4);
        color: #fbd38d; font-size: 11px;
      }
      .jlsh-log {
        margin-top: 5px; font-family: monospace; font-size: 10.5px;
        color: #a0aec0; background: rgba(0,0,0,0.35); padding: 4px 6px;
        border-radius: 5px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
      }
      .jlsh-quick-bg {
        margin-top: 9px; padding-top: 8px; border-top: 1px solid rgba(255,255,255,0.08);
        display: flex; gap: 5px;
      }
      .jlsh-quick-bg input {
        flex: 1; background: rgba(0,0,0,0.35); border: 1px solid rgba(255,255,255,0.16);
        border-radius: 6px; color: #f7fafc; padding: 4px 7px; font-size: 11.5px;
      }
    `;
    document.head.appendChild(style);
  }

  function ensureHud() {
    ensureStyles();
    let el = document.getElementById("jarvis-live-stages-hud");
    if (!el) {
      el = document.createElement("div");
      el.id = "jarvis-live-stages-hud";
      el.className = "hidden";
      document.body.appendChild(el);
    }
    return el;
  }

  async function apiPost(url, payload) {
    try {
      const r = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload || {}),
      });
      return await r.json();
    } catch (e) {
      return { ok: false, error: String(e) };
    }
  }

  function renderAgentCard(prog) {
    const phases = Array.isArray(prog.phases) ? prog.phases : [];
    const pct = Math.max(0, Math.min(100, Number(prog.percent || 0)));
    const elapsed = prog.elapsed_seconds != null ? `${prog.elapsed_seconds}s` : "";
    const badgeCls = prog.stalled ? "warn" : (prog.status === "done" ? "done" : "");
    const badgeTxt = prog.running ? `W TLE · ${pct}% ${elapsed}` : `${prog.status || "idle"} ${elapsed}`;
    const files = Array.isArray(prog.outbox_files) ? prog.outbox_files : [];

    const phaseHtml = phases.map((p) => {
      const cls = p.active ? "active" : (p.done ? "done" : "");
      const icon = p.done ? "✓" : (p.active ? "▶" : "○");
      return `<li class="${cls}"><span>${icon}</span><span>${esc(p.label)}</span></li>`;
    }).join("");

    return `
      <div class="jlsh-card">
        <div class="jlsh-card-top">
          <span>🤖 Agent: ${esc(prog.agent)}</span>
          <span class="jlsh-badge ${badgeCls}">${esc(badgeTxt)}</span>
        </div>
        ${prog.task ? `<div class="jlsh-task" title="${esc(prog.task)}">${esc(prog.task)}</div>` : ""}
        <div class="jlsh-bar-wrap"><div class="jlsh-bar" style="width:${pct}%"></div></div>
        <div class="jlsh-stage-now">Etap: ${esc(prog.stage || "—")}</div>
        ${!collapsed ? `<ul class="jlsh-phases">${phaseHtml}</ul>` : ""}
        ${prog.stalled ? `<div class="jlsh-stall">⚠️ ${esc(prog.stall_reason)}</div>` : ""}
        ${!collapsed && files.length ? `<div class="jlsh-files">📦 Outbox (${prog.outbox_count}): ${esc(files.slice(0, 5).join(", "))}</div>` : ""}
        ${!collapsed && prog.last_line ? `<div class="jlsh-log" title="${esc(prog.last_line)}">${esc(prog.last_line)}</div>` : ""}
        ${prog.running ? `<div style="margin-top:6px;text-align:right"><button class="jlsh-btn danger" data-stop-agent="${esc(prog.agent)}">Zatrzymaj agenta</button></div>` : ""}
      </div>
    `;
  }

  function renderBgJobCard(job) {
    if (job.agent) return ""; // covered by rich agent card above
    const pct = Math.max(5, Math.min(100, Number(job.percent || 10)));
    return `
      <div class="jlsh-card">
        <div class="jlsh-card-top">
          <span>⚡ Zadanie w tle (${esc(job.id)})</span>
          <span class="jlsh-badge">${esc(job.seconds || 0)}s</span>
        </div>
        <div class="jlsh-task" title="${esc(job.task)}">${esc(job.task)}</div>
        <div class="jlsh-bar-wrap"><div class="jlsh-bar" style="width:${pct}%"></div></div>
        <div class="jlsh-stage-now">${esc(job.stage || "Wykonywanie…")}</div>
        <div style="margin-top:5px;text-align:right">
          <button class="jlsh-btn danger" data-stop-bg="${esc(job.id)}">Anuluj</button>
        </div>
      </div>
    `;
  }

  async function poll() {
    let data = null;
    try {
      const resp = await fetch("/agents/progress", { cache: "no-store" });
      if (resp.ok) data = await resp.json();
    } catch (_) {
      data = null;
    }
    const hud = ensureHud();
    if (!data || !data.ok) {
      schedule(POLL_IDLE_MS);
      return;
    }

    const agents = Array.isArray(data.agents) ? data.agents : [];
    const runningAgents = agents.filter((a) => a.running);
    const activeBg = Array.isArray(data.active) ? data.active : [];
    const isBusy = runningAgents.length > 0 || activeBg.length > 0;

    if (isBusy) dismissedIdle = false;

    // Show HUD automatically whenever any agent or background job is active,
    // or show the most recent finished agent run until dismissed.
    const recentAgent = !isBusy ? agents.find((a) => a.run_id && (a.outbox_count > 0 || a.status === "failed")) : null;
    if (!isBusy && (!recentAgent || dismissedIdle)) {
      hud.className = "hidden";
      schedule(POLL_IDLE_MS);
      return;
    }

    // Preserve quick-input value if user is typing
    const prevInput = document.getElementById("jlsh-bg-input");
    const draftVal = prevInput ? prevInput.value : "";
    const hadFocus = prevInput && document.activeElement === prevInput;

    const cards = [];
    if (isBusy) {
      runningAgents.forEach((a) => cards.push(renderAgentCard(a)));
      activeBg.forEach((j) => {
        const html = renderBgJobCard(j);
        if (html) cards.push(html);
      });
    } else if (recentAgent) {
      cards.push(renderAgentCard(recentAgent));
    }

    hud.className = "";
    hud.innerHTML = `
      <div class="jlsh-head">
        <div class="jlsh-title">
          <span class="jlsh-dot ${isBusy ? "" : "idle"}"></span>
          <span>${isBusy ? "Praca w tle i etapy agentów" : "Ostatni wynik agenta"}</span>
        </div>
        <div class="jlsh-btns">
          <button class="jlsh-btn" id="jlsh-toggle">${collapsed ? "Rozwiń" : "Zwiń"}</button>
          ${!isBusy ? `<button class="jlsh-btn" id="jlsh-close">✕</button>` : ""}
        </div>
      </div>
      ${cards.join("")}
      ${!collapsed ? `
        <form class="jlsh-quick-bg" id="jlsh-bg-form">
          <input id="jlsh-bg-input" type="text" placeholder="Zleć zadanie w tle (np. antigravity: zbuduj stronę)…" value="${esc(draftVal)}" />
          <button type="submit" class="jlsh-btn accent">W tle</button>
        </form>
      ` : ""}
    `;

    const toggleBtn = document.getElementById("jlsh-toggle");
    if (toggleBtn) toggleBtn.onclick = () => { collapsed = !collapsed; poll(); };
    const closeBtn = document.getElementById("jlsh-close");
    if (closeBtn) closeBtn.onclick = () => { dismissedIdle = true; hud.className = "hidden"; };

    hud.querySelectorAll("[data-stop-agent]").forEach((btn) => {
      btn.onclick = async () => {
        await apiPost("/agents/stop", { agent: btn.getAttribute("data-stop-agent") });
        poll();
      };
    });
    hud.querySelectorAll("[data-stop-bg]").forEach((btn) => {
      btn.onclick = async () => {
        await apiPost("/agent/background/stop", { id: btn.getAttribute("data-stop-bg") });
        poll();
      };
    });

    const form = document.getElementById("jlsh-bg-form");
    if (form) {
      form.onsubmit = async (ev) => {
        ev.preventDefault();
        const inp = document.getElementById("jlsh-bg-input");
        const task = (inp && inp.value || "").trim();
        if (!task) return;
        inp.value = "";
        await apiPost("/agent/background", { task });
        poll();
      };
    }
    if (hadFocus) {
      const newInp = document.getElementById("jlsh-bg-input");
      if (newInp) newInp.focus();
    }

    schedule(isBusy ? POLL_ACTIVE_MS : POLL_IDLE_MS);
  }

  function schedule(ms) {
    if (timer) clearTimeout(timer);
    timer = setTimeout(poll, ms);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", () => schedule(800));
  } else {
    schedule(800);
  }
})();
