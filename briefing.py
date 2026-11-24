"""Daily briefing from local state and optional free current weather."""
from __future__ import annotations

import time
from datetime import datetime

import system_monitor


def build(app=None, scheduler=None, include_account=False):
    """Assemble the briefing.

    ``include_account`` is opt-in on purpose: it makes network calls to the
    configured mail and calendar account, so unit tests and the offline lanes
    must not trigger it by accident.
    """
    now = time.time()
    sections = {}
    try:
        sections["system"] = system_monitor.snapshot()
    except Exception:
        sections["system"] = {}
    try:
        graph = app.load_graph() if app is not None else {"nodes": [], "links": []}
        sections["notes"] = {"notes": len(graph.get("nodes", [])), "links": len(graph.get("links", []))}
    except Exception:
        sections["notes"] = {"notes": 0, "links": 0}
    try:
        sections["sessions"] = app.session_store.recent(5) if app is not None and app.session_store else []
    except Exception:
        sections["sessions"] = []
    try:
        source = scheduler if scheduler is not None else getattr(app, "scheduler", None)
        sections["schedules"] = source.list() if source is not None else []
    except Exception:
        sections["schedules"] = []
    try:
        sections["memory"] = app.memory.list() if app is not None and app.memory else []
    except Exception:
        sections["memory"] = []
    try:
        import documents
        sections["documents"] = documents.list_documents(5)
    except Exception:
        sections["documents"] = []
    try:
        from operator_modules import commute_weather
        daily = commute_weather.commute_weather({"include_weather": True})
        plan = dict(daily.get("schedule") or {})
        # The week variant is not known: never quietly present default A as fact.
        plan.pop("active_variant", None)
        plan.pop("today_gym", None)
        sections["daily_plan"] = {"schedule": plan, "weather": daily.get("weather") or {}}
    except Exception:
        sections["daily_plan"] = {"schedule": {}, "weather": {"available": False}}
    sections["calendar"] = {"ok": False, "events": []}
    sections["mail"] = {"ok": False}
    if include_account:
        # Both calls reach the network, so they are opt-in and each one fails
        # closed into an explicit "unavailable" section instead of an exception.
        try:
            from operator_modules import calendar_agent
            sections["calendar"] = calendar_agent.calendar_agent({"action": "agenda", "days": 1}, {})
        except Exception as error:
            sections["calendar"] = {"ok": False, "events": [], "error": type(error).__name__}
        try:
            from operator_modules import email_agent
            sections["mail"] = email_agent.email_agent({"action": "status"}, {})
        except Exception as error:
            sections["mail"] = {"ok": False, "error": type(error).__name__}
    system = sections.get("system") or {}
    memory = system.get("memory") or {}
    disk = system.get("disk") or {}
    notes = sections.get("notes") or {}
    waiting = [row for row in sections.get("schedules", []) if row.get("last_status") == "error"]
    lines = [
        f"Briefing for {datetime.now().astimezone().strftime('%A, %d %B %Y')}.",
        f"System: load {', '.join(str(x) for x in system.get('load', [])) or 'unknown'}; "
        f"memory {memory.get('percent', 0)}%; disk {disk.get('percent', 0)}% used.",
        f"Galaxy: {notes.get('notes', 0)} notes and {notes.get('links', 0)} connections.",
        f"Memory: {len(sections.get('memory', []))} personal facts; "
        f"sessions: {len(sections.get('sessions', []))} recent; documents: {len(sections.get('documents', []))} recent.",
    ]
    daily = sections['daily_plan']
    plan, weather = daily['schedule'], daily['weather']
    if plan:
        leave = plan.get('leave_home') or 'brak danych'
        train = plan.get('km_train') or 'brak danych'
        lines.append(f"Zapisany plan dojazdu: wyjście {leave}; pociąg KM {train} (bez informacji o opóźnieniach).")
        lines.append(f"Trening: {plan.get('running_plan') or 'brak danych'}; "
                     f"siłownia A: {plan.get('gym_a') or 'brak danych'}, "
                     f"B: {plan.get('gym_b') or 'brak danych'} (wybierz aktualny wariant).")
    if weather.get('available') and weather.get('temperature_c') is not None:
        lines.append(f"Pogoda teraz (Open-Meteo): {weather['temperature_c']}°C; "
                     f"opady {weather.get('precipitation_mm') if weather.get('precipitation_mm') is not None else '?'} mm; "
                     f"wiatr {weather.get('wind_kmh') if weather.get('wind_kmh') is not None else '?'} km/h.")
    else:
        lines.append('Pogoda: niedostępna.')
    calendar = sections.get('calendar') or {}
    events = calendar.get('events') or []
    if calendar.get('ok') and events:
        today = []
        for event in events[:3]:
            try:
                when = datetime.fromisoformat(event['start']).astimezone().strftime('%H:%M')
            except (TypeError, ValueError):
                continue
            today.append(f"{when} {event.get('summary') or '(bez tytułu)'}")
        lines.append('Kalendarz na dziś: ' + '; '.join(today) + '.')
    elif calendar.get('ok'):
        lines.append('Kalendarz: brak wydarzeń na dziś.')
    else:
        lines.append('Kalendarz: brak danych (konto niepodłączone).')
    mail = sections.get('mail') or {}
    if mail.get('ok'):
        lines.append(f"Poczta: {mail.get('unseen', 0)} nieprzeczytanych z {mail.get('messages', 0)}.")
    upcoming = [row for row in sections.get('schedules', []) if row.get('enabled', True)
                and isinstance(row.get('next_at'), (int, float)) and row['next_at'] >= now]
    for row in sorted(upcoming, key=lambda item: item['next_at'])[:3]:
        try:
            when = datetime.fromtimestamp(row['next_at']).astimezone().strftime('%d.%m %H:%M')
        except (OSError, OverflowError, ValueError):
            continue
        label = ' '.join(str(row.get('name') or 'zadanie').split())[:80]
        lines.append(f"Zaplanowane zadanie: {label} — {when}.")
    if waiting:
        lines.append(f"Attention: {len(waiting)} scheduled job(s) last failed.")
    elif sections.get("schedules"):
        lines.append(f"Schedules: {len(sections['schedules'])} configured.")
    spoken = ' '.join([lines[0], *lines[4:7]])
    return {"generated": now, "heading": "Daily briefing", "text": "\n".join(lines),
            "spoken": spoken, "sections": sections}
