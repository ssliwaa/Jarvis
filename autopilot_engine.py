"""Jarvis Autopilot DAG: 7-Stage Stateful Spec-to-Verification Pipeline (`autopilot_engine.py`).

Orchestrates Jarvis's subsystems into a single closed-loop autonomous workflow:
  1. `SPEC_AND_GRAPH`      — `knowledge_graph` topology + `task_planner` disjoint streams -> `SPEC.md`
  2. `PREFLIGHT_GUARD`     — `hardware_guard` + `budget_guard` + `storage_health` safety gates
  3. `CONTEXT_BLUEPRINT`   — `code_index.build_context_pack` (RRF + AST skeletons + episodes)
  4. `DISPATCH_EXECUTION`  — Safe `dry_run` blueprint OR live `agent_team.start_team_project`
  5. `BLAST_RADIUS_VERIFY` — `change_impact.analyze_blast_radius` + `py_compile` syntax check
  6. `SECURITY_AND_SRI`    — `security_scanner` + `sync_viewer_sri(fix=True)` + `qa_gate`
  7. `MEMORY_COMMIT`       — Writes outcome to `episodic_memory`, `knowledge_graph`, and SSE `event_bus`
"""

from __future__ import annotations

import json
import os
import py_compile
import time
import uuid
from pathlib import Path

import agent_cli
import budget_guard
import change_impact
import code_index
import episodic_memory
import event_bus
import hardware_guard
import knowledge_graph
import qa_gate
import security_scanner
import storage_health
import task_planner

MAX_STORED_RUNS = 40


def _runs_path() -> Path:
    base = agent_cli.ROOT.parent
    base.mkdir(mode=0o700, parents=True, exist_ok=True)
    return base / "autopilot_runs.json"


def list_runs(limit: int = 12) -> list[dict]:
    p = _runs_path()
    if not p.is_file():
        return []
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        if isinstance(data, list):
            return data[: max(1, int(limit))]
    except (OSError, ValueError):
        pass
    return []


def _save_run(record: dict) -> None:
    p = _runs_path()
    existing = [r for r in list_runs(limit=MAX_STORED_RUNS) if r.get("run_id") != record.get("run_id")]
    updated = [record, *existing][:MAX_STORED_RUNS]
    tmp = p.with_name(f".autopilot_runs.json.tmp-{os.getpid()}")
    tmp.write_text(json.dumps(updated, ensure_ascii=False, indent=2), encoding="utf-8")
    os.chmod(tmp, 0o600)
    tmp.replace(p)


def _emit_stage(run_id: str, stage_name: str, status: str, detail: str = "") -> dict:
    entry = {
        "stage": stage_name,
        "status": status,
        "detail": detail,
        "ts": round(time.time(), 3),
    }
    event_bus.publish("autopilot.stage", {"run_id": run_id, **entry})
    return entry


def _render_spec_markdown(goal: str, plan: dict, subgraph: dict) -> str:
    lines = [
        f"# Specyfikacja Autopilota: {goal}",
        "",
        f"- **Złożoność:** `{plan['complexity']}` · **Szacowany koszt:** `${plan['est_total_usd']}` · **Równoległość:** `{plan['max_parallel_agents']}`",
        f"- **Poziom budżetu:** `{plan['budget_tier']}` · **Stan termiczny:** `{plan['thermal_state']}`",
        "",
        "## 1. Rozłączne strumienie prac (brak konfliktów zapisu)",
    ]
    for asg in plan.get("assignments") or []:
        paths_str = ", ".join(f"`{p}`" for p in asg.get("paths") or [])
        lines.append(f"- **`[{asg['role'].upper()}]`** silnikiem `{asg['agent']}` -> {paths_str}")

    if subgraph.get("ascii_map"):
        lines.extend(["", "## 2. Kontekst z grafu architektury Cortex", "```text", subgraph["ascii_map"], "```"])

    if plan.get("risks"):
        lines.extend(["", "## 3. Niezmienniki i ryzyka architektoniczne"])
        for r in plan["risks"]:
            lines.append(f"- {r}")

    lines.extend([
        "",
        "## 4. Kryteria akceptacji (Bramka Deterministyczna)",
        "- `py_compile` bez błędów składni dla wszystkich dotkniętych modułów `.py`.",
        "- `security_scanner`: `0` wycieków sekretów API oraz wywołań `shell=True` / `eval`.",
        "- `sync_viewer_sri` + `qa_gate`: aktualne sumy `sha384` i brak `.innerHTML` w `viewer/`.",
    ])
    return "\n".join(lines)


def run_autopilot(goal: str, project_dir: str | Path, *,
                  execute_team: bool = False,
                  rebuild_graph: bool = True,
                  force: bool = False) -> dict:
    """Execute the 7-stage Jarvis Autopilot state machine on `project_dir`."""
    clean_goal = str(goal or "").strip()
    if not clean_goal:
        raise ValueError("Cel Autopilota (goal) nie może być pusty.")

    safe_root = code_index.validate_safe_project_dir(project_dir)
    run_id = f"ap-{int(time.time())}-{uuid.uuid4().hex[:6]}"
    started_at = round(time.time(), 3)
    stages: list[dict] = []

    # --- STAGE 1: SPEC_AND_GRAPH ---
    if rebuild_graph:
        kg_stats = knowledge_graph.rebuild_code_graph(safe_root)
    else:
        kg_stats = knowledge_graph.graph_summary()
    plan = task_planner.plan_goal(clean_goal, project_dir=safe_root)
    seed_kw = (plan["impacted_files"][0] if plan["impacted_files"] else clean_goal.split()[0])[:48]
    subgraph = knowledge_graph.query_subgraph(Path(seed_kw).stem, hops=2, limit_edges=18)
    spec_md = _render_spec_markdown(clean_goal, plan, subgraph)
    stages.append(_emit_stage(
        run_id,
        "SPEC_AND_GRAPH",
        "ok",
        f"Węzły Cortex: {kg_stats.get('total_nodes', 0)} · strumienie: {len(plan['assignments'])}",
    ))

    # --- STAGE 2: PREFLIGHT_GUARD ---
    hw = hardware_guard.snapshot()
    budget = budget_guard.status()
    storage = storage_health.inspect_storage(project_dir=safe_root)
    preflight_blockers: list[str] = []
    if not storage["ok"]:
        preflight_blockers.append("Wykryto system plików w trybie tylko do odczytu (ro).")
    if hw["state"] == "critical" and not force:
        preflight_blockers.append(f"Krytyczny stan sprzętowy: {', '.join(hw['reasons'])}.")
    if execute_team and budget["hard_capped"] and not force:
        preflight_blockers.append("Wyczerpano dzienny/miesięczny budżet chmurowy.")

    if preflight_blockers:
        stages.append(_emit_stage(run_id, "PREFLIGHT_GUARD", "blocked", "; ".join(preflight_blockers)))
        aborted = {
            "ok": False,
            "run_id": run_id,
            "status": "blocked_preflight",
            "goal": clean_goal,
            "started_at": started_at,
            "finished_at": round(time.time(), 3),
            "stages": stages,
            "spec_markdown": spec_md,
            "plan": plan,
        }
        _save_run(aborted)
        return aborted

    stages.append(_emit_stage(
        run_id,
        "PREFLIGHT_GUARD",
        "ok",
        f"Sprzęt: {hw['state']} · Budżet: {budget['state']} · Dyski: {len(storage['drives'])}",
    ))

    # --- STAGE 3: CONTEXT_BLUEPRINT ---
    context_pack = code_index.build_context_pack(clean_goal, root_dir=safe_root)
    if subgraph.get("ascii_map"):
        context_pack = f"{context_pack}\n### Topologia Cortex\n```text\n{subgraph['ascii_map']}\n```"
    stages.append(_emit_stage(
        run_id,
        "CONTEXT_BLUEPRINT",
        "ok",
        f"Zbudowano pakiet kontekstowy ({len(context_pack)} znaków).",
    ))

    # --- STAGE 4: DISPATCH_EXECUTION ---
    team_info = None
    if execute_team:
        import agent_team
        team_info = agent_team.start_team_project(
            goal=clean_goal,
            assignments=plan["assignments"],
            seed_dir=str(safe_root),
            approved=True,
            consent="autopilot",
        )
        t_root = agent_team.project_root(team_info["id"])
        (t_root / "AUTOPILOT_SPEC.md").write_text(spec_md, encoding="utf-8")
        stages.append(_emit_stage(run_id, "DISPATCH_EXECUTION", "ok", f"Uruchomiono zespół {team_info['id']}."))
    else:
        stages.append(_emit_stage(run_id, "DISPATCH_EXECUTION", "dry_run", "Tryb symulacji i pełnej weryfikacji lokalnej ($0.00)."))

    # --- STAGE 5: BLAST_RADIUS_VERIFY ---
    blast = change_impact.analyze_blast_radius(safe_root, changed_files=plan["impacted_files"])
    compile_errors: list[str] = []
    checked_py = 0
    for rel in blast["affected_modules"][:15]:
        py_path = safe_root / rel
        if py_path.is_file() and py_path.suffix == ".py":
            checked_py += 1
            try:
                py_compile.compile(str(py_path), doraise=True)
            except py_compile.PyCompileError as exc:
                compile_errors.append(f"{rel}: {exc.msg}")
    stages.append(_emit_stage(
        run_id,
        "BLAST_RADIUS_VERIFY",
        "ok" if not compile_errors else "failed",
        f"py_compile: {checked_py} modułów · testy celowane: {len(blast['selected_tests'])}",
    ))

    # --- STAGE 6: SECURITY_AND_SRI ---
    sec = security_scanner.scan_directory(safe_root, include_tests=False)
    sri = change_impact.sync_viewer_sri(safe_root, fix=True)
    viewer_ok = True
    if (safe_root / "viewer" / "index.html").is_file():
        v_qa = qa_gate.audit_viewer(safe_root)
        viewer_ok = bool(v_qa.get("ok"))
    gate_ok = bool(sec["ok"] and sri["ok"] and viewer_ok and not compile_errors)
    stages.append(_emit_stage(
        run_id,
        "SECURITY_AND_SRI",
        "ok" if gate_ok else "failed",
        f"Sekrety/AST: {'OK' if sec['ok'] else 'BŁĄD'} · SRI: {'OK' if sri['ok'] else 'BŁĄD'} · QA UI: {'OK' if viewer_ok else 'BŁĄD'}",
    ))

    # --- STAGE 7: MEMORY_COMMIT ---
    episodic_memory.remember_episode(
        title=f"Autopilot [{run_id}]: {clean_goal[:90]}",
        summary=(
            f"Złożoność {plan['complexity']}, strumienie: {len(plan['assignments'])}, "
            f"testy celowane: {', '.join(blast['selected_tests'][:4]) or 'brak'}, bramka={'OK' if gate_ok else 'UWAGI'}."
        ),
        kind="architecture",
        tags=["autopilot", plan["complexity"]],
        project_id=team_info["id"] if isinstance(team_info, dict) and team_info.get("id") else "",
    )
    knowledge_graph.upsert_triple(
        f"autopilot:{run_id}",
        "verified_goal",
        clean_goal[:120],
        subj_kind="autopilot_run",
        obj_kind="goal",
        source="autopilot",
    )
    stages.append(_emit_stage(run_id, "MEMORY_COMMIT", "ok", "Zapisano przebieg w pamięci epizodycznej i grafie Cortex."))

    result = {
        "ok": gate_ok,
        "run_id": run_id,
        "status": "completed" if gate_ok else "completed_with_warnings",
        "mode": "team_execution" if execute_team else "blueprint_and_verify",
        "goal": clean_goal,
        "started_at": started_at,
        "finished_at": round(time.time(), 3),
        "stages": stages,
        "spec_markdown": spec_md,
        "plan": plan,
        "blast_radius": {
            "affected_modules": blast["affected_modules"][:10],
            "selected_tests": blast["selected_tests"],
            "blast_risk": blast["blast_risk"],
        },
        "gates": {
            "compile_errors": compile_errors,
            "security_ok": sec["ok"],
            "sri_ok": sri["ok"],
            "sri_updated": sri["updated"],
            "viewer_qa_ok": viewer_ok,
        },
        "team": team_info,
    }
    _save_run(result)
    event_bus.publish("autopilot.completed", {"run_id": run_id, "ok": gate_ok, "goal": clean_goal})
    return result
