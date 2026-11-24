"""Linux desktop window and AT-SPI2 accessibility tree inspector for X11/Xfce."""

from __future__ import annotations

import json
import shutil
import subprocess
from typing import Any

_ATSPI_SCRIPT = r"""
import json, sys
try:
    import gi
    gi.require_version("Atspi", "2.0")
    from gi.repository import Atspi
except Exception as exc:
    print(json.dumps({"available": False, "reason": str(exc)}))
    raise SystemExit(0)

limit = int(sys.argv[1]) if len(sys.argv) > 1 else 60
elements = []
desktop = Atspi.get_desktop(0)
if desktop is None:
    print(json.dumps({"available": True, "elements": []}))
    raise SystemExit(0)

INTERACTIVE = {
    "push button", "toggle button", "check box", "radio button", "menu item",
    "text", "password text", "entry", "combo box", "page tab", "link", "slider",
}

def walk(node, app_name, depth=0):
    if node is None or len(elements) >= limit or depth > 10:
        return
    try:
        state = node.get_state_set()
        if state and not state.contains(Atspi.StateType.SHOWING):
            return
        role = (node.get_role_name() or "").lower()
        name = (node.get_name() or "").strip()
        if role in INTERACTIVE or (name and depth <= 3):
            comp = node.get_component_iface()
            if comp is not None:
                rect = comp.get_extents(Atspi.CoordType.SCREEN)
                if rect.width > 0 and rect.height > 0:
                    elements.append({
                        "app": app_name,
                        "role": role,
                        "name": name[:120],
                        "x": int(rect.x),
                        "y": int(rect.y),
                        "width": int(rect.width),
                        "height": int(rect.height),
                        "center_x": int(rect.x + rect.width // 2),
                        "center_y": int(rect.y + rect.height // 2),
                    })
        count = min(node.get_child_count(), 80)
        for idx in range(count):
            if len(elements) >= limit:
                break
            walk(node.get_child_at_index(idx), app_name, depth + 1)
    except Exception:
        return

app_count = min(desktop.get_child_count(), 30)
for i in range(app_count):
    app = desktop.get_child_at_index(i)
    if app is None:
        continue
    try:
        aname = (app.get_name() or "").strip()
        for j in range(min(app.get_child_count(), 10)):
            win = app.get_child_at_index(j)
            if win is None:
                continue
            wstate = win.get_state_set()
            if wstate and wstate.contains(Atspi.StateType.ACTIVE):
                walk(win, aname, 0)
    except Exception:
        continue

print(json.dumps({"available": True, "elements": elements}))
"""


def _run(argv: list[str], timeout: float = 3.0) -> tuple[int, str]:
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)
        return proc.returncode, (proc.stdout or "").strip()
    except (OSError, subprocess.SubprocessError):
        return 1, ""


def _active_window() -> dict[str, Any]:
    if not shutil.which("xdotool"):
        return {"window_id": None, "title": "", "geometry": {}}
    code, wid = _run(["xdotool", "getactivewindow"])
    if code != 0 or not wid:
        return {"window_id": None, "title": "", "geometry": {}}
    _, title = _run(["xdotool", "getwindowname", wid])
    _, geom_raw = _run(["xdotool", "getwindowgeometry", "--shell", wid])
    geom: dict[str, int] = {}
    for line in geom_raw.splitlines():
        if "=" in line:
            k, _, v = line.partition("=")
            if v.isdigit():
                geom[k.lower()] = int(v)
    return {"window_id": wid, "title": title, "geometry": geom}


def _list_windows(limit: int = 30) -> list[dict[str, Any]]:
    if shutil.which("wmctrl"):
        code, out = _run(["wmctrl", "-lG"])
        if code == 0 and out:
            rows = []
            for line in out.splitlines()[:limit]:
                parts = line.split(None, 7)
                if len(parts) >= 8:
                    rows.append({
                        "id": parts[0],
                        "desktop": parts[1],
                        "x": int(parts[2]),
                        "y": int(parts[3]),
                        "width": int(parts[4]),
                        "height": int(parts[5]),
                        "title": parts[7],
                    })
            return rows
    active = _active_window()
    return [active] if active.get("window_id") else []


def _inspect_atspi(limit: int = 60) -> dict[str, Any]:
    python_bin = "/usr/bin/python3" if shutil.which("/usr/bin/python3") else "python3"
    code, out = _run([python_bin, "-c", _ATSPI_SCRIPT, str(limit)], timeout=4.0)
    if code == 0 and out:
        try:
            data = json.loads(out.splitlines()[-1])
            if isinstance(data, dict):
                return data
        except ValueError:
            pass
    return {"available": False, "elements": []}


def desktop_a11y(arguments: dict[str, Any], context=None) -> dict[str, Any]:
    """Inspect active X11/Xfce window, open windows, and AT-SPI2 interactive controls."""
    del context
    action = str((arguments or {}).get("action") or "inspect").strip().lower()
    limit = max(1, min(int((arguments or {}).get("limit") or 50), 150))
    if action == "windows":
        windows = _list_windows(limit=limit)
        return {"ok": True, "action": "windows", "count": len(windows), "windows": windows}
    if action == "inspect":
        active = _active_window()
        atspi = _inspect_atspi(limit=limit)
        return {
            "ok": True,
            "action": "inspect",
            "active_window": active,
            "atspi_available": bool(atspi.get("available")),
            "elements": atspi.get("elements") or [],
        }
    return {"ok": False, "error": f"Unsupported action: {action!r}"}


TOOL = {
    "name": "desktop_a11y",
    "description": (
        "Inspect the active Linux desktop window and list interactive UI controls "
        "(buttons, inputs, menus with screen coordinates) via AT-SPI2 and X11 tools."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "action": {
                "type": "string",
                "enum": ["inspect", "windows"],
                "description": "Use 'inspect' for the active window's UI tree or 'windows' for open windows.",
            },
            "limit": {
                "type": "integer",
                "description": "Maximum number of elements or windows to return (1-150).",
            },
        },
        "additionalProperties": False,
    },
    "handler": desktop_a11y,
    "approval": False,
}
