"""Parallel Background Task Lane & Live Agent Telemetry Aggregator for Jarvis.

Runs non-UI/non-browser background tasks and external coding agent delegations
concurrently without blocking AgentService's single foreground FIFO browser slot.
"""
from __future__ import annotations

import json
import re
import threading
import time
import uuid
from pathlib import Path
from typing import Any

from atomic_io import atomic_write_json

STATE_ROOT = Path.home() / ".jarvis-tools"
BG_HISTORY_PATH = STATE_ROOT / "background-jobs.json"
MAX_CONCURRENT_BG = 3
MAX_BG_HISTORY = 40

_AGENT_ALIAS = {
    "antigravity": "antigravity",
    "antygravity": "antigravity",
    "agy": "antigravity",
    "claude": "claude",
    "claude code": "claude",
    "opencode": "opencode",
    "hermes": "hermes",
}
_AGENT_DELEGATE_RE = re.compile(
    r"\b(?:antigravity|antygravity|agy|claude(?:\s+code)?|opencode|hermes)\b",
    re.I,
)


def detect_delegated_agent(task: str) -> str | None:
    """Return canonical agent_id when a task explicitly delegates to an external coding agent."""
    match = _AGENT_DELEGATE_RE.search(str(task or ""))
    if not match:
        return None
    raw = re.sub(r"\s+", " ", match.group(0).strip().lower())
    return _AGENT_ALIAS.get(raw)




def pick_default_coding_agent(task: str) -> str | None:
    """Pick the first installed external coding agent for heavy website/app builds."""
    try:
        import auto_bg
        if not auto_bg.HEAVY_BUILD_RE.search(str(task or '')):
            return None
        import agent_cli
        for candidate in ('antigravity', 'claude', 'opencode', 'hermes'):
            if agent_cli.binary_present(candidate):
                return candidate
    except Exception:
        pass
    return None


class BackgroundLane:
    """Thread-safe concurrent background task pool (independent from foreground FIFO queue)."""

    def __init__(self, state_root: Path | None = None, max_workers: int = MAX_CONCURRENT_BG):
        self.state_root = Path(state_root or STATE_ROOT)
        self.history_path = self.state_root / "background-jobs.json"
        self.max_workers = max(1, min(int(max_workers or MAX_CONCURRENT_BG), 6))
        self._lock = threading.RLock()
        self._active: dict[str, dict[str, Any]] = {}
        self._cancel_events: dict[str, threading.Event] = {}
        self._history: list[dict[str, Any]] = self._load_history()

    def _load_history(self) -> list[dict[str, Any]]:
        try:
            rows = json.loads(self.history_path.read_text(encoding="utf-8"))
            return [r for r in rows if isinstance(r, dict) and r.get("id")][-MAX_BG_HISTORY:]
        except (OSError, ValueError):
            return []

    def _save_history(self) -> None:
        try:
            atomic_write_json(self.history_path, self._history[-MAX_BG_HISTORY:], mode=0o600, dir_mode=0o700)
        except OSError:
            pass

    def start(self, task: str, *, runner=None, agent_id: str | None = None) -> dict[str, Any]:
        clean_task = str(task or "").strip()
        if not clean_task:
            return {"ok": False, "error": "Background task text is required."}
        detected_agent = agent_id or detect_delegated_agent(clean_task) or pick_default_coding_agent(clean_task)

        with self._lock:
            if len(self._active) >= self.max_workers:
                return {
                    "ok": False,
                    "error": f"Background lane full ({self.max_workers} concurrent tasks running).",
                }
            job_id = "bg-" + time.strftime("%H%M%S") + "-" + uuid.uuid4().hex[:6]
            cancel_ev = threading.Event()
            row: dict[str, Any] = {
                "id": job_id,
                "task": clean_task[:500],
                "kind": f"agent:{detected_agent}" if detected_agent else "operator-bg",
                "agent": detected_agent,
                "status": "running",
                "background": True,
                "started_at": time.time(),
                "finished_at": None,
                "seconds": None,
                "stage": "Inicjalizacja zadania w tle…",
                "percent": 5,
                "result": None,
                "error": "",
            }
            self._active[job_id] = row
            self._cancel_events[job_id] = cancel_ev

        thread = threading.Thread(
            target=self._execute,
            args=(job_id, clean_task, detected_agent, runner, cancel_ev),
            name=f"jarvis-{job_id}",
            daemon=True,
        )
        thread.start()
        return {"ok": True, "background": True, "job": dict(row)}

    def _execute(self, job_id: str, task: str, agent_id: str | None, runner, cancel_ev: threading.Event) -> None:
        started = time.time()
        status = "done"
        result_summary = ""
        error_msg = ""
        run_id = None

        try:
            if callable(runner):
                out = runner(task, cancel_ev)
                if isinstance(out, dict):
                    status = "done" if out.get("ok", True) else "error"
                    result_summary = str(out.get("summary") or out.get("output") or out.get("note") or "")[:600]
                    error_msg = str(out.get("error") or "")[:300]
                else:
                    result_summary = str(out or "")[:600]
            elif agent_id:
                import agent_cli
                with self._lock:
                    if job_id in self._active:
                        self._active[job_id]["stage"] = f"Uruchamianie agenta {agent_id} w piaskownicy bwrap…"
                        self._active[job_id]["percent"] = 15
                res = agent_cli.run(agent_id, task, approved=True, consent="background-lane")
                run_id = res.get("id")
                status = "done" if res.get("ok") else str(res.get("status") or "error")
                out_cnt = len(res.get("outbox") or [])
                result_summary = f"Agent {agent_id} zakończył pracę ({out_cnt} plików w outbox)."
                if not res.get("ok"):
                    error_msg = f"Kod wyjścia: {res.get('exit_code')}"
            else:
                import plan_files
                pf = plan_files.PlanFiles(job_id, root=self.state_root / "plans")
                st = pf.start(task)
                phases = [p["text"] for p in st.get("phases", [])]
                for idx, ph in enumerate(phases):
                    if cancel_ev.is_set():
                        status = "stopped"
                        error_msg = "Zatrzymano przez użytkownika."
                        break
                    with self._lock:
                        if job_id in self._active:
                            self._active[job_id]["stage"] = ph
                            self._active[job_id]["percent"] = min(90, int(((idx + 1) / max(1, len(phases))) * 85))
                    pf.check(idx)
                if status != "stopped":
                    result_summary = f"Przygotowano plan i kontekst w tle ({len(phases)} etapów)."
        except Exception as exc:
            status = "error"
            error_msg = f"{type(exc).__name__}: {exc}"[:300]

        finished = time.time()
        elapsed = round(finished - started, 1)
        with self._lock:
            row = self._active.pop(job_id, None) or {"id": job_id, "task": task[:500]}
            self._cancel_events.pop(job_id, None)
            row.update(
                status="stopped" if cancel_ev.is_set() else status,
                finished_at=finished,
                seconds=elapsed,
                run_id=run_id,
                percent=100 if status == "done" else row.get("percent", 0),
                stage="Zakończono" if status == "done" else f"Status: {status}",
                result=result_summary,
                error=error_msg,
            )
            # Deliver after-job reminders BEFORE the finished status lands
            # in history: observers reacting to the history row (tests,
            # UI teardown) can then safely remove the state root without
            # racing an async writer that still creates reminders/.
            try:
                from operator_modules import reminders
                reminders.notify_job_finished(
                    self.state_root,
                    job_id=job_id,
                    job_name=task[:80],
                    status=row["status"],
                )
            except Exception:
                pass
            self._history.append(dict(row))
            self._history = self._history[-MAX_BG_HISTORY:]
            self._save_history()

    def stop(self, job_id: str) -> dict[str, Any]:
        with self._lock:
            ev = self._cancel_events.get(job_id)
            row = self._active.get(job_id)
        if ev is None or row is None:
            return {"ok": False, "stopped": False, "error": "Background job is not active."}
        ev.set()
        if row.get("agent"):
            try:
                import agent_cli
                agent_cli.stop(row["agent"])
            except Exception:
                pass
        return {"ok": True, "stopped": True, "id": job_id}

    def snapshot(self) -> dict[str, Any]:
        """Return active background jobs enriched with live external-agent stage telemetry."""
        agent_telemetry: list[dict[str, Any]] = []
        by_agent: dict[str, dict[str, Any]] = {}
        try:
            import agent_cli
            if hasattr(agent_cli, "live_progress"):
                for aid in agent_cli.agent_ids():
                    prog = agent_cli.live_progress(aid)
                    by_agent[aid] = prog
                    if prog.get("running") or prog.get("run_id"):
                        agent_telemetry.append(prog)
        except Exception:
            pass

        with self._lock:
            active_rows = []
            for row in self._active.values():
                item = dict(row)
                item["seconds"] = round(max(0.0, time.time() - float(item.get("started_at") or time.time())), 1)
                aid = item.get("agent")
                if aid and aid in by_agent:
                    prog = by_agent[aid]
                    item["stage"] = prog.get("stage") or item["stage"]
                    item["percent"] = prog.get("percent", item["percent"])
                    item["phases"] = prog.get("phases", [])
                    item["outbox_files"] = prog.get("outbox_files", [])
                    item["stalled"] = prog.get("stalled", False)
                    item["stall_reason"] = prog.get("stall_reason", "")
                active_rows.append(item)
            recent_rows = list(reversed(self._history[-10:]))

        return {
            "ok": True,
            "active_count": len(active_rows),
            "active": active_rows,
            "recent": recent_rows,
            "agents": agent_telemetry,
            "running_agents": [a for a in agent_telemetry if a.get("running")],
        }


_GLOBAL_LANE: BackgroundLane | None = None
_GLOBAL_LOCK = threading.Lock()


def get_lane(state_root: Path | None = None) -> BackgroundLane:
    global _GLOBAL_LANE
    with _GLOBAL_LOCK:
        if _GLOBAL_LANE is None:
            _GLOBAL_LANE = BackgroundLane(state_root=state_root)
        return _GLOBAL_LANE
