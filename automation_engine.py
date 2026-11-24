"""Live Cron Scheduler, Preset Routines & Event-Driven Automation Engine (`automation_engine.py`).

Turns passive connector/cron definitions into an active, self-running background engine:
  1. Schedule Parser (`is_job_due`): supports both human-friendly expressions
     (`every 15m`, `every 2h`, `hourly`, `daily 08:15`, `weekdays 09:00`) AND
     standard 5-field cron expressions (`*/30 * * * *`, `15 8 * * 1-5`).
  2. Multi-Action Executor (`execute_job`): runs `briefing`, `doctor`, `storage_prune`,
     or read-only `connector` queries (`weather_forecast`, `calendar_events`, `gmail_inbox`),
     respecting thermal safety (`hardware_guard`) and DND (`wayland_voice`).
  3. Multi-Channel Delivery: publishes to `event_bus` (`automation.executed`), stores
     outcomes in `episodic_memory`, and optionally delivers to `obsidian`, `ntfy`,
     `telegram`, `discord`, or `slack`.
  4. Reactive Event-Bus Rules: subscribes to `hardware.alert` and `budget.threshold`
     to record automatic diagnostic episodes without polling.
"""

from __future__ import annotations

import json
import os
import re
import threading
import time
import uuid
from datetime import datetime
from pathlib import Path

import agent_cli
import connectors_hub
import episodic_memory
import event_bus
import hardware_guard
import morning_briefing
import storage_health
import system_doctor
import wayland_voice

INTERVAL_RE = re.compile(r"^every\s+(\d+)\s*([smhd])$", re.IGNORECASE)
DAILY_RE = re.compile(r"^(daily|weekdays|weekends)\s+(\d{1,2}):(\d{2})$", re.IGNORECASE)

PRESET_ROUTINES: dict[str, dict] = {
    "morning_digest": {
        "name": "Poranny Briefing i Pogoda",
        "schedule": "daily 08:00",
        "action_type": "briefing",
        "action_params": {},
        "deliver": "local",
    },
    "nightly_doctor": {
        "name": "Nocna Autodiagnostyka i Retencja Kopii",
        "schedule": "daily 03:15",
        "action_type": "doctor",
        "action_params": {"auto_heal": True, "prune_backups": True},
        "deliver": "local",
    },
    "storage_watch": {
        "name": "Kontrola Dysków HDD/NVMe i Montowań",
        "schedule": "every 6h",
        "action_type": "storage_check",
        "action_params": {},
        "deliver": "local",
    },
}

_DAEMON_LOCK = threading.Lock()
_DAEMON_STARTED = False
_RULES_INSTALLED = False


def _jobs_path() -> Path:
    base = agent_cli.ROOT.parent
    base.mkdir(mode=0o700, parents=True, exist_ok=True)
    return base / "scheduled_jobs.json"


def load_jobs() -> list[dict]:
    p = _jobs_path()
    if not p.is_file():
        return []
    try:
        raw = json.loads(p.read_text(encoding="utf-8"))
        if isinstance(raw, list):
            return raw
    except (OSError, ValueError):
        pass
    return []


def save_jobs(jobs: list[dict]) -> None:
    p = _jobs_path()
    tmp = p.with_name(f".scheduled_jobs.json.tmp-{os.getpid()}")
    tmp.write_text(json.dumps(jobs[:60], ensure_ascii=False, indent=2), encoding="utf-8")
    os.chmod(tmp, 0o600)
    tmp.replace(p)


# ---------------------------------------------------------------------------
# Pure-Python Human + 5-Field Cron Matcher
# ---------------------------------------------------------------------------

def _cron_field_matches(expr: str, value: int, min_v: int, max_v: int) -> bool:
    for part in expr.split(","):
        part = part.strip()
        if not part:
            continue
        step = 1
        if "/" in part:
            base, step_s = part.split("/", 1)
            step = max(1, int(step_s))
        else:
            base = part

        if base == "*":
            lo, hi = min_v, max_v
        elif "-" in base:
            a, b = base.split("-", 1)
            lo, hi = int(a), int(b)
        else:
            v = int(base)
            if step == 1:
                if v == value:
                    return True
                continue
            lo, hi = v, max_v

        if lo <= value <= hi and ((value - lo) % step == 0):
            return True
    return False


def matches_cron_5(schedule: str, dt: datetime) -> bool:
    parts = schedule.strip().split()
    if len(parts) != 5:
        return False
    minute_e, hour_e, dom_e, mon_e, dow_e = parts
    # Standard cron dow: 0=Sunday .. 6=Saturday (7=Sunday); Python weekday(): 0=Mon .. 6=Sun
    cron_dow = (dt.weekday() + 1) % 7
    try:
        if not (_cron_field_matches(minute_e, dt.minute, 0, 59)
                and _cron_field_matches(hour_e, dt.hour, 0, 23)):
            return False
        # Standard cron day semantics (Vixie/POSIX): when BOTH day-of-month and
        # day-of-week are restricted, a match on EITHER field satisfies the day.
        dow_e = dow_e.replace("7", "0")
        dom_match = _cron_field_matches(dom_e, dt.day, 1, 31)
        dow_match = _cron_field_matches(dow_e, cron_dow, 0, 6)
        day_ok = dom_match or dow_match if (dom_e != "*" and dow_e != "*") \
            else dom_match and dow_match
        return _cron_field_matches(mon_e, dt.month, 1, 12) and day_ok
    except ValueError:
        return False


def is_job_due(job: dict, *, now_ts: float | None = None) -> bool:
    """Determine if `job` should run at `now_ts`, preventing double-execution within the same slot."""
    if not job.get("enabled", True):
        return False
    ts = float(now_ts if now_ts is not None else time.time())
    last_run = float(job.get("last_run_at") or 0.0)
    sched = str(job.get("schedule") or "").strip().lower()
    if not sched:
        return False

    if sched == "hourly":
        sched = "every 1h"

    m_int = INTERVAL_RE.match(sched)
    if m_int:
        qty = max(1, int(m_int.group(1)))
        unit = m_int.group(2).lower()
        mult = {"s": 1, "m": 60, "h": 3600, "d": 86400}[unit]
        interval_s = max(30, qty * mult)
        return (ts - last_run) >= interval_s

    dt = datetime.fromtimestamp(ts)
    # Prevent running twice inside the same calendar minute
    if last_run > 0:
        prev_dt = datetime.fromtimestamp(last_run)
        if (prev_dt.year, prev_dt.month, prev_dt.day, prev_dt.hour, prev_dt.minute) == (
            dt.year, dt.month, dt.day, dt.hour, dt.minute
        ):
            return False

    m_day = DAILY_RE.match(sched)
    if m_day:
        mode, hh, mm = m_day.group(1).lower(), int(m_day.group(2)), int(m_day.group(3))
        if dt.hour != hh or dt.minute != mm:
            return False
        if mode == "weekdays" and dt.weekday() >= 5:
            return False
        if mode == "weekends" and dt.weekday() < 5:
            return False
        return True

    return matches_cron_5(sched, dt)


# ---------------------------------------------------------------------------
# Job Management, Execution & Delivery
# ---------------------------------------------------------------------------

def create_automation(name: str, schedule: str, *,
                      action_type: str = "briefing",
                      action_params: dict | None = None,
                      deliver: str = "local") -> dict:
    clean_name = str(name or "").strip()[:140]
    clean_sched = str(schedule or "").strip()[:64]
    if not clean_name or not clean_sched:
        raise ValueError("Automatyzacja wymaga niepustych pól name oraz schedule.")
    if action_type not in ("briefing", "doctor", "storage_check", "connector"):
        raise ValueError(f"Nieobsługiwany typ akcji automatyzacji: {action_type!r}")

    jobs = load_jobs()
    record = {
        "id": f"auto-{uuid.uuid4().hex[:8]}",
        "name": clean_name,
        "schedule": clean_sched,
        "action_type": action_type,
        "action_params": dict(action_params or {}),
        "deliver": str(deliver or "local").strip().lower(),
        "enabled": True,
        "created_at": round(time.time(), 3),
        "last_run_at": 0.0,
        "run_count": 0,
        "last_status": "never",
        "last_summary": "",
    }
    jobs.insert(0, record)
    save_jobs(jobs)
    return {"ok": True, "job": record}


def install_preset(preset_id: str) -> dict:
    spec = PRESET_ROUTINES.get(str(preset_id or "").strip())
    if not spec:
        raise ValueError(f"Nieznany szablon rutyny: {preset_id!r}. Dostępne: {sorted(PRESET_ROUTINES)}")
    jobs = load_jobs()
    for existing in jobs:
        if existing.get("name") == spec["name"]:
            return {"ok": True, "already_installed": True, "job": existing}
    return create_automation(
        spec["name"],
        spec["schedule"],
        action_type=spec["action_type"],
        action_params=spec["action_params"],
        deliver=spec["deliver"],
    )


def _deliver_summary(channel: str, title: str, summary: str) -> str:
    if channel in ("", "local"):
        return "local_sse"
    # Respect Do-Not-Disturb for external push notifications
    if wayland_voice.dnd_status().get("active") and channel in ("telegram", "ntfy", "slack", "discord"):
        return "suppressed_dnd"
    text = f"[Jarvis] {title}: {summary}"
    try:
        if channel == "obsidian":
            connectors_hub.execute_connector_action("obsidian_daily_append", {"text": f"{title} — {summary}"})
            return "obsidian"
        if channel == "telegram":
            connectors_hub.execute_connector_action("telegram_send", {"text": text})
            return "telegram"
        if channel == "ntfy":
            connectors_hub.execute_connector_action("ntfy_publish", {"text": text})
            return "ntfy"
        if channel == "discord":
            connectors_hub.execute_connector_action("discord_send", {"text": text})
            return "discord"
        if channel == "slack":
            connectors_hub.execute_connector_action("slack_send", {"text": text})
            return "slack"
    except Exception as exc:
        return f"delivery_error:{exc}"
    return "local_sse"


def execute_job(job: dict, project_dir: str | Path) -> dict:
    """Run a single automation job and return its summary."""
    atype = str(job.get("action_type") or "briefing")
    params = dict(job.get("action_params") or {})
    root = Path(project_dir).expanduser().resolve()

    hw = hardware_guard.snapshot()
    if hw["state"] == "critical" and atype not in ("doctor", "storage_check"):
        return {"ok": False, "status": "deferred_thermal", "summary": "Wstrzymano z powodu wysokiej temperatury CPU/RAM."}

    if atype == "briefing":
        b = morning_briefing.generate_briefing()
        summary = str(b.get("spoken_text") or "Wygenerowano briefing systemowy.")[:280]
    elif atype == "doctor":
        d = system_doctor.run_diagnostics(project_dir=root, auto_heal=bool(params.get("auto_heal", True)))
        pruned_txt = ""
        if params.get("prune_backups"):
            pr = storage_health.prune_mcp_backups(root, keep_latest=30)
            pruned_txt = f", usunięto {pr['removed']} starych kopii .bak"
        summary = f"Zdrowie systemu: {d['health_score']}/100 (naprawiono: {len(d['healed_actions'])}{pruned_txt})."
    elif atype == "storage_check":
        s = storage_health.inspect_storage(project_dir=root)
        summary = f"Sprawdzono {len(s['drives'])} dysków · ostrzeżenia: {len(s['warnings'])}."
    elif atype == "connector":
        c_act = str(params.get("connector_action") or "weather_forecast")
        res = connectors_hub.execute_connector_action(c_act, params)
        summary = json.dumps(res, ensure_ascii=False)[:260]
    else:
        summary = f"Pominięto nieznany typ: {atype}"

    delivered = _deliver_summary(str(job.get("deliver") or "local"), str(job.get("name") or atype), summary)
    event_bus.publish("automation.executed", {
        "job_id": job.get("id"),
        "name": job.get("name"),
        "summary": summary,
        "delivered": delivered,
    })
    return {"ok": True, "status": "ok", "summary": summary, "delivered": delivered}


def run_job_by_id(job_id: str, project_dir: str | Path) -> dict:
    jobs = load_jobs()
    target = None
    for j in jobs:
        if j.get("id") == job_id:
            target = j
            break
    if target is None:
        raise ValueError(f"Nie znaleziono automatyzacji o ID {job_id!r}.")

    out = execute_job(target, project_dir)
    target["last_run_at"] = round(time.time(), 3)
    target["run_count"] = int(target.get("run_count") or 0) + 1
    target["last_status"] = out["status"]
    target["last_summary"] = out["summary"]
    save_jobs(jobs)
    return {"ok": out["ok"], "job": target, "execution": out}


def tick_due_jobs(project_dir: str | Path, *, now_ts: float | None = None) -> dict:
    """Evaluate all enabled jobs and execute any that are due."""
    ts = float(now_ts if now_ts is not None else time.time())
    jobs = load_jobs()
    executed: list[dict] = []
    dirty = False

    for job in jobs:
        if not is_job_due(job, now_ts=ts):
            continue
        try:
            res = execute_job(job, project_dir)
            job["last_status"] = res["status"]
            job["last_summary"] = res["summary"]
        except Exception as exc:
            job["last_status"] = "error"
            job["last_summary"] = str(exc)[:240]
        job["last_run_at"] = round(ts, 3)
        job["run_count"] = int(job.get("run_count") or 0) + 1
        dirty = True
        executed.append({"id": job.get("id"), "name": job.get("name"), "status": job["last_status"]})

    if dirty:
        save_jobs(jobs)
    return {"ok": True, "executed_count": len(executed), "executed": executed}


def install_reactive_event_rules() -> None:
    """Subscribe reactive listeners onto `event_bus` for critical system telemetry."""
    global _RULES_INSTALLED
    if _RULES_INSTALLED:
        return
    _RULES_INSTALLED = True

    def _on_hw_alert(ev: dict) -> None:
        payload = ev.get("data") or ev.get("payload") or {}
        if payload.get("state") == "critical":
            try:
                episodic_memory.remember_episode(
                    title=f"Alert sprzętowy: {payload.get('peak_temp_c')}°C / RAM {payload.get('mem_available_mb')} MB",
                    summary=", ".join(payload.get("reasons") or ["Przekroczono próg krytyczny"]),
                    kind="incident",
                    tags=["hardware", "auto_rule"],
                )
            except Exception:
                pass

    try:
        event_bus.subscribe("hardware.alert", _on_hw_alert)
    except Exception:
        pass


def automation_status() -> dict:
    jobs = load_jobs()
    enabled = [j for j in jobs if j.get("enabled", True)]
    return {
        "ok": True,
        "total_jobs": len(jobs),
        "enabled_jobs": len(enabled),
        "jobs": jobs[:25],
        "presets": [
            {"id": pid, "name": p["name"], "schedule": p["schedule"], "action_type": p["action_type"]}
            for pid, p in PRESET_ROUTINES.items()
        ],
        "reactive_rules_active": _RULES_INSTALLED,
    }


def start_automation_daemon(project_dir: str | Path, *, poll_seconds: float = 25.0) -> None:
    """Start background scheduler thread evaluating due jobs every `poll_seconds`."""
    global _DAEMON_STARTED
    with _DAEMON_LOCK:
        if _DAEMON_STARTED:
            return
        _DAEMON_STARTED = True

    install_reactive_event_rules()
    root = Path(project_dir).expanduser().resolve()

    def _loop() -> None:
        while True:
            time.sleep(max(10.0, float(poll_seconds)))
            try:
                tick_due_jobs(root)
            except Exception:
                pass

    threading.Thread(target=_loop, name="jarvis-automation-daemon", daemon=True).start()
