"""Autonomous 'Night Shift' maintenance & evolution cycle for Jarvis.

Designed to be invoked on-demand (Mission Control / Telegram) or scheduled via
`systemd --user` (`jarvis-night-shift.timer` at `03:30`) with zero persistent RAM.
Respects CPU load, active background coding agents, and `budget_guard` caps before:
  1. Log watchdog scan (`health_watchdog`)
  2. Incremental Hybrid Code RAG index refresh + RAM cache eviction (`code_index`)
  3. Frontend & DOM contract verification (`qa_gate`)
  4. AST mutation & adversarial draft generation (`evolve_engine`)
  5. Skill distillation & SelfHarness guardrail refresh + Morning Report + SSE push
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

import agent_cli
import budget_guard
import code_index
import evolve_engine
import health_watchdog

DEFAULT_MAX_LOAD_RATIO = 0.70


def _report_path() -> Path:
    return agent_cli.ROOT.parent / "night_shift" / "latest_report.json"


def check_system_quiet(max_load_ratio: float = DEFAULT_MAX_LOAD_RATIO) -> tuple[bool, float]:
    """Return (is_quiet, load_per_core) using 1-minute POSIX load average."""
    try:
        load1 = os.getloadavg()[0]
        cores = max(1, os.cpu_count() or 1)
        ratio = round(load1 / cores, 3)
        return ratio <= float(max_load_ratio), ratio
    except (AttributeError, OSError):
        return True, 0.0


def any_agent_busy() -> list[str]:
    """Return IDs of currently running local coding agents."""
    busy = []
    try:
        for aid in agent_cli.agent_ids():
            running, _ = agent_cli._check_running(aid)
            if running:
                busy.append(aid)
    except Exception:
        pass
    return busy


def latest_report() -> dict:
    path = _report_path()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {"ok": True, "has_report": False}
    except (OSError, ValueError):
        return {"ok": True, "has_report": False}


def run_night_shift(*, modules: list[str] | None = None,
                    project_root: str | Path | None = None,
                    auto_repair: bool = False,
                    force: bool = False,
                    max_load_ratio: float = DEFAULT_MAX_LOAD_RATIO,
                    telegram=None) -> dict:
    """Execute one bounded Night Shift maintenance pass and write Morning Report."""
    if not force:
        busy_agents = any_agent_busy()
        if busy_agents:
            return {
                "ok": False,
                "skipped": True,
                "reason": f"Wstrzymano Night Shift — pracują agenci: {', '.join(busy_agents)}.",
                "busy_agents": busy_agents,
            }
        budget_ok, budget_reason = budget_guard.allow_background_run()
        if not budget_ok:
            return {"ok": False, "skipped": True, "reason": budget_reason}
        quiet, load_ratio = check_system_quiet(max_load_ratio=max_load_ratio)
        if not quiet:
            return {
                "ok": False,
                "skipped": True,
                "reason": f"Wstrzymano Night Shift — obciążenie CPU wynosi {int(load_ratio * 100)}%.",
                "load_ratio": load_ratio,
            }
    else:
        _, load_ratio = check_system_quiet(max_load_ratio=max_load_ratio)

    started = time.time()
    proj = Path(project_root or Path(__file__).resolve().parent).expanduser().resolve()
    targets = [str(m).strip().removesuffix(".py") for m in (modules or ["router"]) if str(m).strip()]

    # 1. Service log watchdog scan
    watchdog_res = health_watchdog.scan_logs(auto_repair=auto_repair, project_root=proj)

    # 2. Incremental SQLite FTS5 + AST code index refresh & immediate RAM vector release
    index_res = code_index.index_directory(proj)
    code_index.evict_idle_cache(force=True)

    # 3. Deterministic Viewer QA gate
    try:
        import qa_gate
        viewer_qa = qa_gate.audit_viewer(proj)
    except Exception as exc:
        viewer_qa = {"ok": False, "issues": [str(exc)[:160]]}

    # 4. Mutation testing & adversarial draft generation
    mutation_summaries = []
    for mod in targets[:3]:
        mod_file = proj / f"{mod}.py"
        if not mod_file.is_file():
            continue
        try:
            draft = evolve_engine.AdversarialBreaker.generate_draft_cases(mod, source_path=mod_file)
            mut = draft.get("mutation_report") or {}
            mutation_summaries.append({
                "module": mod,
                "mutants": mut.get("mutants", 0),
                "kill_rate": mut.get("kill_rate", 0.0),
                "survivors": len(mut.get("survivors") or []),
                "draft_cases": len(draft.get("cases") or []),
            })
        except Exception as exc:
            mutation_summaries.append({"module": mod, "error": str(exc)[:160]})

    # 5. Distill improved archive patches + refresh SelfHarness guardrails
    distilled = evolve_engine.SkillDistiller.distill_from_archive()
    harness = evolve_engine.SelfHarness.evolve_prompt_from_failures("patcher")

    elapsed_s = round(time.time() - started, 2)
    incidents_count = len(watchdog_res.get("incidents") or [])
    qa_label = "OK" if viewer_qa.get("ok") else f"{len(viewer_qa.get('issues') or [])} uwag(i)"
    summary_lines = [
        f"Raport Nocnej Zmiany ({elapsed_s}s, CPU load {int(load_ratio * 100)}%):",
        f"- Watchdog logów: {incidents_count} incydent(ów).",
        f"- Indeks kodu (FTS5+AST): +{index_res.get('indexed', 0)} zaktualizowanych, {index_res.get('skipped', 0)} bez zmian.",
        f"- Bramka QA interfejsu: {qa_label}.",
        f"- Destylacja skilli: +{distilled.get('created', 0)} nowych (łącznie {distilled.get('total', 0)}).",
    ]
    for ms in mutation_summaries:
        if "error" not in ms:
            summary_lines.append(
                f"- Mutacje `{ms['module']}`: zabito {int(ms['kill_rate'] * 100)}% z {ms['mutants']} "
                f"(szkice testów: {ms['draft_cases']})."
            )

    report = {
        "ok": True,
        "has_report": True,
        "finished_at": round(time.time(), 3),
        "duration_s": elapsed_s,
        "load_ratio": load_ratio,
        "watchdog": {
            "incidents": incidents_count,
            "dispatched": len(watchdog_res.get("dispatched") or []),
        },
        "code_index": {
            "indexed": index_res.get("indexed", 0),
            "skipped": index_res.get("skipped", 0),
        },
        "viewer_qa": {
            "ok": bool(viewer_qa.get("ok", True)),
            "issues": list(viewer_qa.get("issues") or [])[:10],
        },
        "mutations": mutation_summaries,
        "distilled_skills": distilled,
        "self_harness_updated": bool(harness.get("updated")),
        "budget": budget_guard.status(),
        "summary_text": "\n".join(summary_lines),
    }

    rpath = _report_path()
    rpath.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    tmp = rpath.with_name(f".{rpath.name}.tmp-{os.getpid()}-{threading.get_ident()}-{time.time_ns()}")
    try:
        tmp.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
        os.chmod(tmp, 0o600)
        tmp.replace(rpath)
    finally:
        if tmp.exists():
            try:
                tmp.unlink()
            except OSError:
                pass

    try:
        import event_bus
        event_bus.publish("night_shift.completed", {
            "finished_at": report["finished_at"],
            "duration_s": elapsed_s,
            "incidents": incidents_count,
            "viewer_qa_ok": report["viewer_qa"]["ok"],
        })
    except Exception:
        pass

    if telegram is not None and hasattr(telegram, "_send_safe"):
        try:
            telegram._send_safe(report["summary_text"])
        except Exception:
            pass

    return report


def systemd_unit_files(project_root: str | Path | None = None,
                       on_calendar: str = "*-*-* 03:30:00") -> dict[str, str]:
    """Generate `systemd --user` service and timer unit definitions for Night Shift."""
    proj = Path(project_root or Path(__file__).resolve().parent).expanduser().resolve()
    py_bin = sys.executable
    service = (
        "[Unit]\n"
        "Description=Jarvis Autonomous Night Shift Maintenance\n"
        "After=network.target\n\n"
        "[Service]\n"
        "Type=oneshot\n"
        f"WorkingDirectory={proj}\n"
        f"ExecStart={py_bin} {proj / 'night_shift.py'} --auto\n"
        "Nice=15\n"
        "IOSchedulingClass=idle\n"
    )
    timer = (
        "[Unit]\n"
        "Description=Run Jarvis Night Shift daily at 03:30 when system is idle\n\n"
        "[Timer]\n"
        f"OnCalendar={on_calendar}\n"
        "RandomizedDelaySec=15m\n"
        "Persistent=true\n\n"
        "[Install]\n"
        "WantedBy=timers.target\n"
    )
    return {
        "jarvis-night-shift.service": service,
        "jarvis-night-shift.timer": timer,
    }


def install_user_timer(enable: bool = False,
                       target_dir: str | Path | None = None) -> dict:
    """Write `jarvis-night-shift.{service,timer}` to `~/.config/systemd/user/` and optionally enable."""
    dest = Path(target_dir or (Path.home() / ".config" / "systemd" / "user")).expanduser().resolve()
    dest.mkdir(mode=0o700, parents=True, exist_ok=True)
    units = systemd_unit_files()
    written = []
    for fname, content in units.items():
        upath = dest / fname
        upath.write_text(content, encoding="utf-8")
        written.append(str(upath))

    enabled = False
    if enable:
        subprocess.run(["systemctl", "--user", "daemon-reload"], capture_output=True, timeout=10, check=False)
        proc = subprocess.run(
            ["systemctl", "--user", "enable", "--now", "jarvis-night-shift.timer"],
            capture_output=True, text=True, timeout=10, check=False,
        )
        enabled = proc.returncode == 0
    return {"ok": True, "files": written, "enabled": enabled}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Jarvis Night Shift runner")
    parser.add_argument("--auto", action="store_true", help="Respect CPU/agent/budget guards")
    parser.add_argument("--force", action="store_true", help="Force execution immediately")
    parser.add_argument("--auto-repair", action="store_true", help="Allow watchdog auto-repair")
    args = parser.parse_args(argv)
    res = run_night_shift(force=bool(args.force and not args.auto), auto_repair=bool(args.auto_repair))
    sys.stdout.write(json.dumps(res, ensure_ascii=False, indent=2) + "\n")
    return 0 if res.get("ok") or res.get("skipped") else 1


if __name__ == "__main__":
    raise SystemExit(main())
