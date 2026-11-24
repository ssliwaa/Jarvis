"""Proactive Morning Briefing, Hardware Telemetry & Prioritized Action Advisor for Jarvis.

Synthesizes into a single lightweight snapshot (and concise spoken Polish summary):
  1. Process & host telemetry (`VmRSS` MB from `/proc/self/status`, CPU load, free disk GB)
  2. Pending agent->owner questions (`voice_bridge`)
  3. Cloud API budget utilization & active tier (`budget_guard`)
  4. Latest Night Shift report, QA gate, and open API circuit-breakers
  5. Episodic memory highlights (`episodic_memory`)
  6. Ranked `next_actions` recommendations + `<400ms` TTS `spoken_chunks`
"""

from __future__ import annotations

import os
import shutil
import time
from pathlib import Path

import agent_router
import agent_team
import budget_guard
import episodic_memory
import hardware_guard
import health_watchdog
import night_shift
import voice_bridge
import wayland_voice


def host_telemetry(target_dir: str | Path | None = None) -> dict:
    """Read process RSS memory (MB), 1-min CPU load ratio, and free disk space (GB)."""
    rss_mb = None
    status_file = Path("/proc/self/status")
    if status_file.is_file():
        try:
            for line in status_file.read_text(encoding="utf-8", errors="ignore").splitlines():
                if line.startswith("VmRSS:"):
                    parts = line.split()
                    if len(parts) >= 2 and parts[1].isdigit():
                        rss_mb = round(int(parts[1]) / 1024.0, 1)
                    break
        except OSError:
            rss_mb = None

    try:
        load1 = round(os.getloadavg()[0], 2)
        cores = max(1, os.cpu_count() or 1)
        load_ratio = round(load1 / cores, 3)
    except (AttributeError, OSError):
        load1 = 0.0
        cores = 1
        load_ratio = 0.0

    probe = Path(target_dir or Path.home()).expanduser()
    try:
        usage = shutil.disk_usage(probe if probe.exists() else "/")
        free_gb = round(usage.free / (1024 ** 3), 1)
        total_gb = round(usage.total / (1024 ** 3), 1)
    except OSError:
        free_gb = None
        total_gb = None

    hw = hardware_guard.snapshot()
    return {
        "process_rss_mb": rss_mb,
        "cpu_load_1m": load1,
        "cpu_cores": cores,
        "cpu_load_ratio": load_ratio,
        "disk_free_gb": free_gb,
        "disk_total_gb": total_gb,
        "peak_temp_c": hw["peak_temp_c"],
        "mem_available_mb": hw["mem_available_mb"],
        "thermal_state": hw["state"],
        "recommended_max_parallel_agents": hw["recommended_max_parallel_agents"],
        "dnd": wayland_voice.dnd_status(),
    }


def _greeting_for_hour(hour: int) -> str:
    if 5 <= hour < 12:
        return "Dzień dobry"
    if 12 <= hour < 18:
        return "Cześć"
    return "Dobry wieczór"


def generate_briefing(project_root: str | Path | None = None) -> dict:
    """Build an executive briefing with prioritized actions and speakable Polish chunks."""
    now_struct = time.localtime()
    greeting = _greeting_for_hour(now_struct.tm_hour)

    telemetry = host_telemetry(project_root)
    pending_q = voice_bridge.pending_owner_questions()
    budget = budget_guard.status()
    nshift = night_shift.latest_report()
    watchdog = health_watchdog.watchdog_status()
    circuits = agent_router.active_circuits()
    projects = agent_team.list_projects(6)
    mem_stats = episodic_memory.memory_stats()

    active_projects = [p for p in projects if p.get("status") in ("running", "active")]
    next_actions: list[dict] = []

    if pending_q:
        first_q = pending_q[0]
        next_actions.append({
            "priority": "high",
            "code": "ANSWER_AGENT",
            "title": f"Odpowiedz agentowi {first_q.get('from', 'agent')} ({len(pending_q)} oczekujące)",
            "detail": str(first_q.get("question") or "")[:180],
        })

    if circuits:
        names = ", ".join(sorted(circuits.keys()))
        next_actions.append({
            "priority": "high",
            "code": "CIRCUIT_OPEN",
            "title": f"Sprawdź kwarantannę API dla: {names}",
            "detail": "Router automatycznie omija te silniki do wygaśnięcia cooldownu.",
        })

    if budget["state"] in ("warning", "capped"):
        next_actions.append({
            "priority": "high" if budget["state"] == "capped" else "medium",
            "code": "BUDGET_ALERT",
            "title": f"Budżet chmurowy: ${budget['spent_today_usd']:.2f} / ${budget['daily_limit_usd']:.2f} ({budget['state']})",
            "detail": f"Aktywny tryb routingu: {budget['recommended_cloud_tier']}.",
        })

    if telemetry["disk_free_gb"] is not None and telemetry["disk_free_gb"] < 10.0:
        next_actions.append({
            "priority": "high",
            "code": "LOW_DISK",
            "title": f"Mało wolnego miejsca na dysku ({telemetry['disk_free_gb']} GB)",
            "detail": "Rozważ oczyszczenie starych worktree lub kopii zapasowych.",
        })

    if not nshift.get("has_report"):
        next_actions.append({
            "priority": "low",
            "code": "RUN_NIGHT_SHIFT",
            "title": "Uruchom pierwszy audyt Nocnej Zmiany lub włącz timer 03:30",
            "detail": "Zbuduje świeży raport mutacji AST, indeksu FTS5 i bramki QA.",
        })
    elif nshift.get("viewer_qa") and not nshift["viewer_qa"].get("ok", True):
        next_actions.append({
            "priority": "high",
            "code": "VIEWER_QA_ISSUE",
            "title": "Bramka QA wykryła uwagi w warstwie viewer/",
            "detail": "; ".join(nshift["viewer_qa"].get("issues") or [])[:180],
        })

    # Concise <=3-sentence spoken summary
    spoken_parts = [
        f"{greeting}. Proces Jarvisa zużywa {telemetry['process_rss_mb'] or 'niewiele'} megabajtów pamięci, "
        f"a dzisiejsze wydatki chmurowe to {budget['spent_today_usd']:.2f} dolara z limitu {budget['daily_limit_usd']:.2f}."
    ]
    if pending_q:
        spoken_parts.append(
            f"Czeka {len(pending_q)} pytanie od agenta {pending_q[0].get('from', 'w tle')}."
        )
    elif active_projects:
        spoken_parts.append(f"W tle pracuje obecnie {len(active_projects)} zespół projektowy.")
    else:
        spoken_parts.append(
            f"Wszystkie bezpieczniki są {'czyste' if not circuits else 'częściowo aktywne'}, "
            f"a w pamięci epizodycznej zapisano {mem_stats['total']} zdarzeń."
        )

    spoken_text = " ".join(spoken_parts)
    chunker = wayland_voice.SentenceStreamChunker(min_chars=18)
    spoken_chunks = chunker.push(spoken_text) + chunker.flush()

    return {
        "ok": True,
        "generated_at": round(time.time(), 3),
        "telemetry": telemetry,
        "budget": {
            "state": budget["state"],
            "spent_today_usd": budget["spent_today_usd"],
            "daily_limit_usd": budget["daily_limit_usd"],
            "recommended_cloud_tier": budget["recommended_cloud_tier"],
        },
        "pending_questions_count": len(pending_q),
        "active_projects_count": len(active_projects),
        "open_circuits": list(circuits.keys()),
        "watchdog_incidents": len(watchdog.get("incidents") or []),
        "episodic_memory": mem_stats,
        "next_actions": next_actions,
        "spoken_summary": spoken_text,
        "spoken_chunks": spoken_chunks,
    }
