"""Truthful outcomes for Operator actions.

``done`` means the effect was observed after the call. Each lane carries its own
natural proof: file tools prove the written path or trash copy, the browser
proves a loaded URL or a page change, and shell/PTY commands prove the process's
own exit status — the running process is the observed effect, so ``done`` on
exit code 0 is a legitimate reading, not a fabrication. ``unverified`` means the
request returned but the result could not be proven; ``failed`` means it did not
happen. Only facts carried by the tool result can mark ``done``: a free-text
claim or a bare "it worked" never qualifies.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

import operator_tools as ops

DONE = "done"
UNVERIFIED = "unverified"
FAILED = "failed"
STARTED = "started"

READ_ONLY = {
    "read_page", "read_file", "read_pdf", "ocr_image", "list_dir", "search_files",
    "chat_history", "network", "tabs", "secret", "request_human", "finish",
    "self_heal", "learned_rule",
}
# Only these built-in tools may hand back their own outcome. A generated skill
# or MCP result can print {"outcome": "done"} too; that must never certify it.
TRUSTED_OUTCOME = {"app_control", "document_create"}


def _path(value: Any) -> Path | None:
    try:
        return ops.resolve_path(str(value), must_exist=False)
    except Exception:
        return None


def _ok(result: Any) -> bool:
    return not (isinstance(result, dict) and result.get("ok") is False)


def _line(outcome: str, detail: str, **facts) -> dict:
    return {"outcome": outcome, "detail": detail[:500], **facts}


def verify(action: str, arguments: dict, result: Any) -> dict:
    """Return a machine-readable verification record for one tool call."""
    arguments = arguments if isinstance(arguments, dict) else {}
    if (action in TRUSTED_OUTCOME and isinstance(result, dict)
            and result.get("outcome") in (DONE, UNVERIFIED, FAILED, STARTED)):
        return result
    if action == "write_file":
        target = _path(result.get("path") if isinstance(result, dict) else arguments.get("path"))
        if target is None:
            return _line(UNVERIFIED, "The write returned no resolvable path.")
        if not target.is_file():
            return _line(FAILED, "The write returned but the file does not exist.")
        expected = arguments.get("content")
        if isinstance(expected, str) and not arguments.get("append"):
            try:
                actual = target.read_text(encoding="utf-8", errors="replace")
            except OSError:
                return _line(UNVERIFIED, "The file exists but could not be read back.")
            if actual != expected:
                return _line(FAILED, "The file exists but its content differs from the request.")
            return _line(DONE, "The file exists and its content matches.", path=str(target))
        return _line(DONE, "The file exists after the write.", path=str(target))
    if action == "delete_path":
        target = _path(arguments.get("path"))
        if target is None:
            return _line(UNVERIFIED, "The delete returned no resolvable path.")
        if target.exists():
            return _line(FAILED, "The path still exists after delete.")
        return _line(DONE, "The path is gone; the trash copy is the recovery path.")
    if action == "restore_file":
        target = _path(arguments.get("path"))
        if target is None or not target.is_file():
            return _line(FAILED, "The restored target does not exist.")
        return _line(DONE, "The restored file exists.", path=str(target))
    if action == "terminal":
        if not isinstance(result, dict):
            return _line(UNVERIFIED, "The terminal returned no structured result.")
        code = result.get("returncode", result.get("exit_code"))
        if code is None:
            if result.get("pid"):
                return _line(STARTED, "The command started in the background; its effect is not observed.")
            return _line(UNVERIFIED, "The command returned without a status code.")
        if int(code) == 0:
            return _line(DONE, "The command exited with status 0.")
        return _line(FAILED, f"The command exited with status {code}.")
    if action == "open_url":
        if isinstance(result, dict) and str(result.get("url") or "").startswith(("http://", "https://")):
            return _line(DONE, "The browser reports a loaded http(s) URL.", url=result["url"][:300])
        return _line(UNVERIFIED, "The browser returned no loaded URL.")
    if action in ("click", "click_selector", "click_text", "fill", "fill_selector",
                  "press", "scroll", "eval", "upload", "download"):
        if not _ok(result):
            return _line(FAILED, "The browser action returned ok=false.")
        changed = result.get("changed") if isinstance(result, dict) else None
        where = str(result.get("change") or "")[:20] if isinstance(result, dict) else ""
        if changed is True:
            return _line(DONE, f"The action was delivered and the page changed ({where or 'dom'}).",
                         change=where or "dom")
        if changed is False:
            return _line(UNVERIFIED, "The action was delivered but the page did not change.")
        return _line(UNVERIFIED, "The browser accepted the action; the resulting page state was not proven.")
    if action == "skill_forge":
        if isinstance(result, dict) and result.get("ok") is True and (result.get("tests") or {}).get("ok") is True:
            return _line(DONE, "The generated skill passed Crucible tests and was written.")
        return _line(UNVERIFIED, "Skill generation did not prove a tested skill.")
    if action == "dynamic_skill":
        if isinstance(result, dict) and result.get("ok") is True:
            return _line(UNVERIFIED, "The generated skill returned a result; its side effects were not independently checked.")
        return _line(FAILED, "The generated skill failed.")
    if action == "self_heal":
        mode = str(arguments.get("action") or "status")
        if mode in ("status", "history"):
            return _line(DONE if _ok(result) else FAILED,
                         "The self-heal status was read." if _ok(result) else "The self-heal read failed.")
        if isinstance(result, dict) and result.get("ok") is True:
            if result.get("dry_run"):
                return _line(DONE, "The proposed patch passed syntax validation (dry run).")
            return _line(UNVERIFIED, "The patch was backed up and compiled; the live module may still need a restart.")
        return _line(FAILED, "The self-heal request did not succeed.")
    if action == "learned_rule":
        return _line(DONE if _ok(result) else FAILED,
                     "The learned-rule store accepted the request." if _ok(result) else "The rule request failed.")
    if action == "desktop":
        mode = str(arguments.get("action") or "")
        if mode in {"list_windows", "list_apps", "screenshot", "capture"} and _ok(result):
            return _line(DONE, "The desktop read completed.", action=mode)
        return _line(UNVERIFIED, "The desktop action was delivered; the visible result was not proven.", action=mode)
    if action in READ_ONLY:
        return _line(DONE if _ok(result) else FAILED,
                     "The read completed." if _ok(result) else "The read returned ok=false.")
    if _ok(result):
        return _line(UNVERIFIED, "The tool returned without an independent verification rule.")
    return _line(FAILED, "The tool returned ok=false.")


def attach(action: str, arguments: dict, result: Any) -> Any:
    """Attach outcome/verification to a dict result without changing its shape."""
    verification = verify(action, arguments, result)
    if isinstance(result, dict):
        merged = dict(result)
        merged["outcome"] = verification["outcome"]
        merged["verification"] = verification
        return merged
    return {"ok": verification["outcome"] != FAILED, "result": result,
            "outcome": verification["outcome"], "verification": verification}
