"""Operator access to external coding agents with background runs, live progress & outbox review."""
from __future__ import annotations

import json
from typing import Any

import agent_cli
import agent_consent
import agent_notes
import agent_review

_SYNTAX_EXTS = {".py", ".json", ".html", ".css", ".js"}


def _review_outbox_quality(agent_id: str, target: str | None = None) -> dict[str, Any]:
    """Validate generated files in the agent outbox (syntax, empty files, summary presence)."""
    out_dir = agent_cli.outbox_path(agent_id)
    files = agent_cli.outbox(agent_id)
    issues: list[dict[str, str]] = []
    checked = 0
    has_summary = False

    for entry in files:
        rel = entry.get("path", "")
        if rel == "outbox.md" or rel.endswith("/outbox.md"):
            has_summary = True
        full = out_dir / rel
        ext = full.suffix.lower()
        if entry.get("bytes", 0) == 0:
            issues.append({"file": rel, "issue": "Plik jest pusty (0 bajtów)."})
            continue
        if ext not in _SYNTAX_EXTS or entry.get("bytes", 0) > 250_000:
            continue
        checked += 1
        try:
            text = full.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if ext == ".py":
            try:
                compile(text, rel, "exec")
            except SyntaxError as exc:
                issues.append({"file": rel, "issue": f"SyntaxError w linii {exc.lineno}: {exc.msg}"})
        elif ext == ".json":
            try:
                json.loads(text)
            except ValueError as exc:
                issues.append({"file": rel, "issue": f"Niepoprawny JSON: {exc}"})
        elif ext == ".html":
            low = text.lower()
            if "<html" not in low and "<!doctype" not in low and "<body" not in low and "<div" not in low:
                issues.append({"file": rel, "issue": "Brak podstawowych znaczników struktury HTML."})

    diff_info = None
    if target and str(target).strip():
        try:
            diff_info = agent_review.diff_outbox(agent_id, str(target).strip())
        except agent_review.ReviewError as exc:
            diff_info = {"ok": False, "error": str(exc)}

    return {
        "ok": True,
        "agent": agent_id,
        "outbox_count": len(files),
        "checked_files": checked,
        "has_outbox_md": has_summary,
        "healthy": len(issues) == 0 and len(files) > 0,
        "issues": issues,
        "files": files,
        "diff": diff_info,
    }


def agents(arguments: dict[str, Any] | None, context=None) -> dict[str, Any]:
    del context
    args = arguments if isinstance(arguments, dict) else {}
    action = str(args.get("action") or "list").strip().lower()
    agent_id = args.get("agent")
    if isinstance(agent_id, str):
        agent_id = agent_id.strip().lower()

    try:
        if action == "list":
            return {"ok": True, **agent_cli.summary(refresh=bool(args.get("refresh", False)))}
        if action in ("status", "logs", "outbox", "stop", "review", "diff", "apply", "iterate") and not agent_id:
            return {"ok": False, "error": "An agent id is required."}
        if action == "status":
            st = agent_cli.status(agent_id, refresh=bool(args.get("refresh", False)))
            if hasattr(agent_cli, "live_progress"):
                st["progress"] = agent_cli.live_progress(agent_id)
            return {"ok": True, "agent": st}
        if action == "progress":
            if not agent_id:
                return {"ok": True, "agents": [agent_cli.live_progress(aid) for aid in agent_cli.agent_ids()]}
            return {"ok": True, **agent_cli.live_progress(agent_id, args.get("run_id"))}
        if action == "logs":
            return {"ok": True, "agent": agent_id, "log": agent_cli.tail(agent_id, args.get("run_id"))}
        if action == "outbox":
            return {"ok": True, "agent": agent_id, "files": agent_cli.outbox(agent_id)}
        if action == "review":
            return _review_outbox_quality(agent_id, target=args.get("target"))
        if action == "diff":
            return agent_review.diff_outbox(agent_id, args.get("target"))
        if action == "apply":
            return agent_review.apply_outbox(agent_id, str(args.get("target") or ""), files=args.get("files"))
        if action == "stop":
            return {"ok": True, **agent_cli.stop(agent_id)}
        if action == "config":
            if args.get("settings") is None:
                return {"ok": True, "agent": agent_id, "settings": agent_cli.load_config(agent_id)}
            saved = agent_cli.save_config(agent_id, args["settings"])
            return {"ok": True, "agent": agent_id, "settings": saved}
        if action == "knowledge":
            if agent_id:
                return {"ok": True, "agent": agent_id, "notes": agent_notes.notes(agent_id, args.get("limit", 20))}
            return {"ok": True, "summary": agent_notes.summary()}
        if action == "note":
            return {"ok": True, **agent_notes.read_note(args.get("name"))}
        if action in ("run", "iterate"):
            task_text = args.get("task")
            if action == "iterate":
                prev_files = [f["path"] for f in agent_cli.outbox(agent_id)[:20]]
                feedback = str(args.get("feedback") or task_text or "").strip()
                if not feedback:
                    return {"ok": False, "error": "A task or feedback is required."}
                task_text = (
                    f"ITERACJA POPRAWKOWA na istniejącym projekcie w Twoim workspace/outbox.\n"
                    f"Obecne pliki w outbox: {', '.join(prev_files) if prev_files else 'brak'}.\n"
                    f"Uwagi i poprawki od Jarvisa/użytkownika:\n{feedback}\n"
                    f"Zaktualizuj odpowiednie pliki w outbox/ oraz dopisz podsumowanie zmian w outbox/outbox.md."
                )
            if not isinstance(task_text, str) or not task_text.strip():
                return {"ok": False, "error": "A task is required."}
            raw_task_for_consent = args.get("task") if isinstance(args.get("task"), str) and args.get("task").strip() else task_text
            token = args.get("consent")
            consent_type = "direct"
            if token:
                try:
                    grant = agent_consent.consume(token, agent_id, raw_task_for_consent)
                    consent_type = "spoken" if grant.get("spoken") else "click"
                except agent_consent.ConsentError as error:
                    return {
                        "ok": False,
                        "outcome": "needs_consent",
                        "error": str(error),
                        "consent_required": True,
                        "how": (
                            "Ask the owner to confirm, then retry with the one-time consent "
                            'token. A spoken "zgadzam się" through /agents/consent counts.'
                        ),
                    }
            bg = bool(args.get("background", False))
            if bg and hasattr(agent_cli, "start_async"):
                res = agent_cli.start_async(
                    agent_id,
                    task_text,
                    approved=True,
                    timeout=args.get("timeout"),
                    consent=consent_type,
                    target_hint=str(args.get("target") or ""),
                )
                res["consent"] = consent_type
                return res
            result = agent_cli.run(
                agent_id,
                task_text,
                approved=True,
                timeout=args.get("timeout"),
                consent=consent_type,
            )
            result["consent"] = consent_type
            return result
    except (agent_cli.AgentError, agent_notes.NoteError, agent_review.ReviewError) as error:
        return {"ok": False, "error": str(error)}
    except agent_consent.ConsentError as error:
        return {"ok": False, "outcome": "needs_consent", "error": str(error), "consent_required": True}
    return {"ok": False, "error": "Unsupported action."}


agents_tool = agents


def _requires_approval(arguments: dict[str, Any] | None = None) -> bool:
    args = arguments if isinstance(arguments, dict) else {}
    return str(args.get("action") or "list").strip().lower() in ("run", "iterate", "apply", "config", "stop")


TOOL = {
    "name": "agents",
    "description": (
        "Manage the external coding agents (claude, opencode, hermes, antigravity). "
        "REQUIRES explicit approval before starting a run or applying files outside Full mode. "
        "They run inside a read-only sandbox: they may read the whole computer and copy files, "
        "but they may only write inside their own folder. Finished code goes to their outbox and "
        "Jarvis reviews and applies it. Actions: list, status, progress, logs, outbox, review, "
        "diff, apply, stop, config, run, iterate, knowledge, note. Pass background=true on 'run' "
        "to execute asynchronously without blocking Jarvis."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "action": {
                "type": "string",
                "enum": [
                    "list", "status", "progress", "logs", "outbox", "review",
                    "diff", "apply", "stop", "config", "run", "iterate", "knowledge", "note",
                ],
            },
            "agent": {"type": "string", "enum": ["claude", "opencode", "hermes", "antigravity"]},
            "task": {"type": "string", "description": "What the agent should do."},
            "feedback": {"type": "string", "description": "Refinement instructions when action='iterate'."},
            "consent": {"type": "string", "description": "Optional one-time consent token for run."},
            "background": {
                "type": "boolean",
                "description": "Start the agent asynchronously in the background and return immediately (default: false).",
            },
            "timeout": {"type": "integer", "minimum": 30, "maximum": 7200},
            "run_id": {"type": "string"},
            "name": {"type": "string", "description": "Note file name for the note action."},
            "limit": {"type": "integer", "minimum": 1, "maximum": 100},
            "target": {"type": "string", "description": "Directory to compare or apply the outbox against."},
            "files": {"type": "array", "items": {"type": "string"}},
            "settings": {"type": "object", "description": "Per-agent settings to store."},
            "refresh": {"type": "boolean"},
        },
        "required": ["action"],
        "additionalProperties": False,
    },
    "handler": agents,
    "approval": True,
    "approval_predicate": _requires_approval,
}
