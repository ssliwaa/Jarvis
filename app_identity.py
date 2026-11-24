"""Resolve and control Linux desktop applications without raw clicks.

This is the identity layer between a human name ("Firefox", "Kino") and the
actual desktop entry/window/process. It never closes Jarvis itself and only
uses graceful window messages (`wmctrl -ic`), not SIGKILL.
"""
from __future__ import annotations

import os
import re
import shlex
import shutil
import subprocess
import time
from pathlib import Path

APP_ROOTS = (
    Path.home() / ".local/share/applications",
    Path("/usr/local/share/applications"),
    Path("/usr/share/applications"),
)
PROTECTED = re.compile(r"(jarvis|orbit|knowledge observatory)", re.I)
_DESKTOP_CACHE: tuple[tuple, list[dict]] | None = None


def _roots_signature() -> tuple:
    sig = []
    for root in APP_ROOTS:
        try:
            st = root.stat()
            sig.append((str(root), st.st_mtime_ns, st.st_size))
        except OSError:
            sig.append((str(root), 0, 0))
    return tuple(sig)


def _desktop_entries():
    global _DESKTOP_CACHE
    sig = _roots_signature()
    if _DESKTOP_CACHE is not None and _DESKTOP_CACHE[0] == sig:
        return list(_DESKTOP_CACHE[1])
    entries = {}
    for root in APP_ROOTS:
        if not root.is_dir():
            continue
        for path in sorted(root.glob("*.desktop")):
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if "[Desktop Entry]" not in text:
                continue
            values = {}
            for line in text.split("[Desktop Entry]", 1)[1].splitlines():
                if line.startswith("[") and line.strip() != "[Desktop Entry]":
                    break
                if "=" in line and not line.lstrip().startswith("#"):
                    key, value = line.split("=", 1)
                    values[key.strip()] = value.strip()
            if values.get("Type", "Application") != "Application" or values.get("NoDisplay", "").lower() == "true":
                continue
            name = values.get("Name") or path.stem
            entry = {"id": path.name, "name": name, "exec": values.get("Exec", ""),
                     "icon": values.get("Icon", ""), "path": str(path),
                     "keywords": " ".join(filter(None, (values.get("Keywords", ""),
                                                        values.get("GenericName", ""))))}
            # XDG precedence: the first root (the user's own applications
            # directory) wins, exactly as the desktop environment does; a
            # later system entry must not overwrite a user override.
            entries.setdefault(path.name, entry)
    ordered = sorted(entries.values(), key=lambda row: row["name"].casefold())
    _DESKTOP_CACHE = (sig, ordered)
    return list(ordered)


def _windows():
    if not os.environ.get("DISPLAY") or not shutil.which("wmctrl"):
        return []
    try:
        output = subprocess.run(["wmctrl", "-lpx"], capture_output=True, text=True, timeout=5).stdout
    except (OSError, subprocess.TimeoutExpired):
        return []
    rows = []
    for line in output.splitlines():
        parts = line.split(None, 5)
        if len(parts) < 6:
            continue
        try:
            pid = int(parts[2])
        except ValueError:
            continue
        rows.append({"id": parts[0], "desktop": parts[1], "pid": pid, "class": parts[3],
                     "host": parts[4], "title": parts[5]})
    return rows


def _processes():
    rows = []
    for entry in Path("/proc").iterdir() if Path("/proc").is_dir() else []:
        if not entry.name.isdigit():
            continue
        try:
            name = (entry / "comm").read_text(encoding="utf-8", errors="replace").strip()
            cmdline = (entry / "cmdline").read_bytes().replace(b"\0", b" ").decode("utf-8", "replace").strip()
            rows.append({"pid": int(entry.name), "name": name, "cmdline": cmdline[:300]})
        except (OSError, ValueError):
            continue
    return rows


def find(query: str):
    needle = str(query or "").strip().casefold()
    if not needle:
        return {"query": "", "apps": _desktop_entries()[:80], "windows": _windows()[:40]}
    apps = [row for row in _desktop_entries()
            if needle in (row["name"] + " " + row["exec"] + " " + row["keywords"] + " " + row["id"]).casefold()]
    windows = [row for row in _windows()
               if needle in (row["class"] + " " + row["title"]).casefold()]
    processes = [row for row in _processes() if needle in (row["name"] + " " + row["cmdline"]).casefold()][:20]
    return {"query": query, "apps": apps[:20], "windows": windows[:20], "processes": processes}


def _require_query(query):
    """Return a non-empty app name or the refusal the caller must send back.

    An empty string used to mean "every app/window": ``close('')`` could close
    the first five windows and ``launch('')`` could start the first desktop
    entry. ``find('')`` still intentionally lists everything.
    """
    text = str(query or "").strip()
    if not text:
        return None
    return text


def _command(entry):
    """Expand a .desktop Exec line without a shell and drop field codes."""
    raw = entry.get("exec", "")
    try:
        parts = shlex.split(raw)
    except ValueError:
        return []
    if parts and parts[0] == "env":
        parts = [part for part in parts[1:] if "=" not in part]
    # "%%" is a literal percent sign; every other field code expands to an
    # argument the .desktop file itself supplies.
    command = [re.sub(r"%%|%[fFuUdDnNickvm]",
                      lambda match: "%" if match.group(0) == "%%" else "", part)
               for part in parts]
    command = [part for part in command if part]
    if not command:
        return []
    return command


def launch(query: str):
    if _require_query(query) is None:
        return {"ok": False, "action": "launch", "query": query, "outcome": "refused",
                "error": "An application name is required."}
    found = find(query)
    apps = found.get("apps") or []
    if not apps:
        return {"ok": False, "action": "launch", "query": query, "outcome": "failed",
                "error": "No matching desktop application was found."}
    existing = found.get("windows") or []
    if existing:
        focused = focus(query)
        focused["action"] = "launch"
        focused["already_running"] = True
        return focused
    entry = apps[0]
    command = _command(entry)
    if not command or not shutil.which(command[0]):
        return {"ok": False, "action": "launch", "query": query, "outcome": "failed",
                "error": "The desktop entry has no runnable command.", "target": entry}
    try:
        subprocess.Popen(command, cwd=str(Path.home()), start_new_session=True,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except (OSError, ValueError) as error:
        return {"ok": False, "action": "launch", "query": query, "outcome": "failed",
                "error": str(error)[:200], "target": entry}
    time.sleep(1.0)
    after = find(query)
    observed = bool(after.get("windows") or after.get("processes"))
    return {"ok": True, "action": "launch", "query": query, "target": entry,
            "outcome": "done" if observed else "started-unverified",
            "window_observed": bool(after.get("windows")), "processes": (after.get("processes") or [])[:5]}


def focus(query: str):
    if _require_query(query) is None:
        return {"ok": False, "action": "focus", "query": query, "outcome": "refused",
                "error": "An application name is required."}
    found = find(query)
    windows = found.get("windows") or []
    if not windows:
        return {"ok": False, "action": "focus", "query": query, "outcome": "unverified",
                "error": "No matching window is visible; launch the app first."}
    target = windows[0]
    if PROTECTED.search(target["title"] + " " + target["class"]):
        return {"ok": False, "action": "focus", "query": query, "outcome": "failed",
                "error": "Refusing to focus the Jarvis viewer through the app-control lane."}
    try:
        subprocess.run(["wmctrl", "-ia", target["id"]], capture_output=True, timeout=5, check=False)
    except (OSError, subprocess.TimeoutExpired) as error:
        return {"ok": False, "action": "focus", "query": query, "outcome": "failed", "error": str(error)}
    return {"ok": True, "action": "focus", "target": target, "outcome": "done"}


def close(query: str, confirm=False):
    if confirm is not True:
        return {"ok": False, "action": "close", "outcome": "refused", "error": "close requires confirm:true"}
    if _require_query(query) is None:
        return {"ok": False, "action": "close", "outcome": "refused",
                "error": "An application name is required."}
    found = find(query)
    windows = found.get("windows") or []
    closed = []
    for window in windows[:5]:
        if PROTECTED.search(window["title"] + " " + window["class"]):
            continue
        try:
            subprocess.run(["wmctrl", "-ic", window["id"]], capture_output=True, timeout=5, check=False)
            closed.append(window)
        except (OSError, subprocess.TimeoutExpired):
            continue
    if not closed:
        return {"ok": False, "action": "close", "query": query, "outcome": "failed",
                "error": "No non-protected matching window was closed."}
    return {"ok": True, "action": "close", "closed": closed, "outcome": "done"}
