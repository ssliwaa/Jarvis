"""Deterministic AST- & Hardware-Aware Multi-Agent Task Planner (`task_planner.py`).

Decomposes a natural-language engineering goal into conflict-free, file-disjoint
workstreams (`backend`, `frontend`, `qa`) before launching coding agents:
  1. Locates impacted files & 1-hop AST neighbors via `code_index`.
  2. Recalls past architectural decisions/pitfalls via `episodic_memory`.
  3. Assigns optimal agents per role via `agent_router.rank_agents(role=...)`
     (automatically respecting `budget_guard` and open `429` circuit breakers).
  4. Caps parallel execution waves via `hardware_guard.snapshot()`.
  5. Flags architectural risks (`server.py` bloat, `viewer/` SRI hashes, thermal/budget caps).
"""

from __future__ import annotations

import time
from pathlib import Path

import agent_router
import budget_guard
import code_index
import episodic_memory
import hardware_guard

ROLE_BASE_COST_USD = {
    "architect": 0.045,
    "backend": 0.035,
    "frontend": 0.030,
    "qa": 0.020,
}


def _pick_agent_for_role(role: str, used_in_wave: set[str]) -> dict:
    ranked = agent_router.rank_agents(role=role)
    if not ranked:
        return {"agent": "hermes", "score": 0.5}
    # Prefer an available/unblocked agent not yet assigned in the same parallel wave
    for item in ranked:
        if not item.get("budget_blocked") and not item.get("circuit_open") and item["agent"] not in used_in_wave:
            return item
    for item in ranked:
        if not item.get("budget_blocked") and not item.get("circuit_open"):
            return item
    return ranked[0]


def _classify_path(rel_path: str) -> str:
    p = rel_path.replace("\\", "/").lstrip("./")
    if p.startswith("tests/") or Path(p).name.startswith("test_") or p.endswith("_test.py"):
        return "qa"
    if p.startswith("viewer/") or Path(p).suffix.lower() in (".js", ".css", ".html"):
        return "frontend"
    return "backend"


def plan_goal(goal: str, project_dir: str | Path | None = None, *, max_files: int = 10) -> dict:
    """Build a conflict-free multi-agent execution plan for `goal`."""
    clean_goal = str(goal or "").strip()
    if not clean_goal:
        raise ValueError("Cel zadania (goal) nie może być pusty.")

    safe_root = code_index.validate_safe_project_dir(project_dir) if project_dir else None
    hits = code_index.search_context(clean_goal, root_dir=safe_root, limit=max(4, min(int(max_files), 16)))

    ordered_paths: list[str] = []
    seen: set[str] = set()
    for h in hits:
        rel = str(h.get("path") or "").strip()
        if rel and rel not in seen:
            seen.add(rel)
            ordered_paths.append(rel)
        if safe_root and rel and len(ordered_paths) < max_files:
            try:
                nb = code_index.related_files(rel, safe_root)
                for linked in (nb.get("imported_by") or [])[:2]:
                    if linked not in seen and len(ordered_paths) < max_files:
                        seen.add(linked)
                        ordered_paths.append(linked)
            except Exception:
                pass

    buckets: dict[str, list[str]] = {"backend": [], "frontend": [], "qa": []}
    for rel in ordered_paths:
        buckets[_classify_path(rel)].append(rel)

    # Guarantee at least one workstream even on brand-new/empty repositories
    goal_lower = clean_goal.lower()
    if not any(buckets.values()):
        if any(w in goal_lower for w in ("ui", "viewer", "css", "widok", "przycisk", "panel")):
            buckets["frontend"].append("viewer/mission.js")
        else:
            buckets["backend"].append("new_module.py")
    if not buckets["qa"]:
        buckets["qa"].append("tests/test_planned_feature.py")

    hw = hardware_guard.snapshot()
    budget = budget_guard.status()
    episodes = episodic_memory.recall_episodes(clean_goal[:160], limit=3)

    max_parallel = max(1, int(hw.get("recommended_max_parallel_agents") or 1))
    workstreams: list[dict] = []
    used_agents: set[str] = set()

    stream_specs = (
        ("backend", "Implementacja modułów backendu i logiki domenowej"),
        ("frontend", "Aktualizacja interfejsu użytkownika (czystym DOM API bez .innerHTML)"),
        ("qa", "Testy jednostkowe/integracyjne, linter oraz bramki QA i bezpieczeństwa"),
    )
    for role, desc in stream_specs:
        paths = buckets[role]
        if not paths:
            continue
        chosen = _pick_agent_for_role(role, used_agents)
        aid = str(chosen["agent"])
        used_agents.add(aid)
        est_cost = round(ROLE_BASE_COST_USD.get(role, 0.025) * (0.5 if budget["prefer_economy_tier"] else 1.0), 4)
        workstreams.append({
            "role": role,
            "agent": aid,
            "paths": paths,
            "task": f"[{role.upper()}] {desc} dla celu: {clean_goal}. Przypisane pliki (wyłączność zapisu): {', '.join(paths)}",
            "est_usd": est_cost,
            "router_score": chosen.get("score", 0.0),
        })

    # Group workstreams into waves respecting `max_parallel` (with `qa` always in the final verification wave)
    impl_streams = [w for w in workstreams if w["role"] != "qa"]
    qa_streams = [w for w in workstreams if w["role"] == "qa"]
    waves: list[list[dict]] = []
    for idx in range(0, len(impl_streams), max_parallel):
        waves.append(impl_streams[idx: idx + max_parallel])
    if qa_streams:
        waves.append(qa_streams)

    total_files = sum(len(v) for v in buckets.values())
    if total_files <= 2 and len(workstreams) <= 2:
        complexity = "trivial"
    elif total_files <= 6:
        complexity = "moderate"
    else:
        complexity = "complex"

    risks: list[str] = []
    if "server.py" in buckets["backend"]:
        risks.append("Dotyka server.py — wydziel nowe endpointy do osobnego modułu *_routes.py.")
    if buckets["frontend"]:
        risks.append("Zmiana zasobów viewer/ wymaga zgodności z qa_gate (brak .innerHTML, poprawne SRI sha384).")
    if budget["state"] in ("warning", "capped"):
        risks.append(f"Budżet w stanie {budget['state']} ({budget['recommended_cloud_tier']}) — użyto oszczędnego routingu.")
    if hw["state"] in ("warm", "critical"):
        risks.append(f"Stan sprzętowy {hw['state']} — ograniczono równoległość fali do {max_parallel} agenta.")

    est_total_usd = round(sum(w["est_usd"] for w in workstreams), 4)
    return {
        "ok": True,
        "planned_at": round(time.time(), 3),
        "goal": clean_goal,
        "complexity": complexity,
        "est_total_usd": est_total_usd,
        "max_parallel_agents": max_parallel,
        "budget_tier": budget["recommended_cloud_tier"],
        "thermal_state": hw["state"],
        "impacted_files": ordered_paths,
        "assignments": workstreams,
        "waves": waves,
        "recalled_episodes": [
            {"kind": ep.get("kind"), "title": ep.get("title")}
            for ep in episodes
        ],
        "risks": risks,
    }
