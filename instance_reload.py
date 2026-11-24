"""Single-Instance Port Guard & Automatic Hot-Reload Controller (`instance_reload.py`).

Eliminates `OSError: [Errno 98] Address already in use` and automates instance reloads:
  1. Tracks `BOOT_TIME` vs `latest_source_mtime(root)` across `*.py` and `viewer/*`.
  2. Exposes `instance_status(root)` (`pid`, `boot_time`, `latest_mtime`, `stale`, `systemd_managed`).
  3. Handles `EADDRINUSE` when a second `server.py` is launched: probes the active instance,
     automatically restarts/reloads it if its in-memory code is stale (or if requested),
     waits for `/health == 200`, and exits `0` cleanly instead of crashing with `code 1`.
  4. Runs a lightweight background debounced watcher (`start_auto_reload_watcher`) so
     `jarvis.service` / standalone `server.py` automatically reloads itself after code edits
     once a 2.5s quiet window passes and no coding agent subprocess is active.
"""

from __future__ import annotations

import json
import os
import signal
import socket
import subprocess
import sys
import threading
import time
import urllib.request
from pathlib import Path

BOOT_TIME = round(time.time(), 3)
WATCH_SKIP_DIRS = {
    ".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build",
    ".pytest_cache", ".jarvis-mcp-backups", ".hermes", ".jarvis-tools",
    "artifacts", "tests",
}
_RELOAD_LOCK = threading.Lock()
_RELOADING = False


def latest_source_mtime(root: str | Path) -> float:
    """Return newest `mtime` among runtime `.py` modules and `viewer/*` assets."""
    base = Path(root).expanduser().resolve()
    newest = 0.0
    try:
        for entry in base.iterdir():
            name = entry.name
            if name in WATCH_SKIP_DIRS or name.startswith("."):
                continue
            if entry.is_file() and name.endswith(".py"):
                newest = max(newest, entry.stat().st_mtime)
            elif entry.is_dir() and name in ("viewer", "operator_modules"):
                for sub in entry.rglob("*"):
                    if sub.is_file() and sub.suffix in (".py", ".js", ".css", ".html"):
                        newest = max(newest, sub.stat().st_mtime)
    except OSError:
        pass
    return round(newest, 3)


def is_systemd_service_active(unit: str = "jarvis.service") -> bool:
    try:
        proc = subprocess.run(
            ["systemctl", "--user", "is-active", "--quiet", unit],
            capture_output=True,
            timeout=3,
            check=False,
        )
        return proc.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def instance_status(root: str | Path) -> dict:
    newest = latest_source_mtime(root)
    systemd_managed = bool(os.environ.get("INVOCATION_ID")) or is_systemd_service_active()
    return {
        "ok": True,
        "pid": os.getpid(),
        "boot_time": BOOT_TIME,
        "uptime_s": round(max(0.0, time.time() - BOOT_TIME), 1),
        "latest_source_mtime": newest,
        "stale": newest > (BOOT_TIME + 1.0),
        "systemd_managed": systemd_managed,
    }


def is_port_open(host: str, port: int, timeout: float = 0.8) -> bool:
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return True
    except OSError:
        return False


def wait_for_healthy(host: str, port: int, *, timeout_s: float = 12.0) -> bool:
    deadline = time.monotonic() + max(1.0, float(timeout_s))
    url = f"http://{host}:{int(port)}/health"
    while time.monotonic() < deadline:
        try:
            req = urllib.request.Request(url, headers={"Host": f"{host}:{int(port)}"}, method="GET")
            with urllib.request.urlopen(req, timeout=1.5) as resp:
                if resp.status == 200:
                    return True
        except Exception:
            pass
        time.sleep(0.35)
    return False


def probe_running_instance(host: str, port: int) -> dict | None:
    url = f"http://{host}:{int(port)}/mission/instance"
    try:
        req = urllib.request.Request(url, headers={"Host": f"{host}:{int(port)}"}, method="GET")
        with urllib.request.urlopen(req, timeout=1.8) as resp:
            if resp.status == 200:
                data = json.loads(resp.read().decode("utf-8"))
                return data if isinstance(data, dict) else None
    except Exception:
        return None
    return None


def _any_agent_busy() -> bool:
    """True while any background job, single agent run or team wave is in flight.

    Restarting the process kills the `bwrap --die-with-parent` sandboxes, so a
    reload during a run turns finished work into a `failed` run and leaves the
    team wave half-merged.
    """
    try:
        import background_lane
        snap = background_lane.get_lane().snapshot()
        if snap.get("running"):
            return True
    except Exception:
        pass
    try:
        import agent_cli
        for agent_id in agent_cli.agent_ids():
            try:
                if agent_cli.live_progress(agent_id).get("running"):
                    return True
            except Exception:
                continue
    except Exception:
        pass
    try:
        import agent_team
        if agent_team.active_waves():
            return True
    except Exception:
        pass
    return False


def trigger_self_reload(httpd=None, *, delay_s: float = 0.25) -> dict:
    """Gracefully reload the current server process (via systemd restart or os.execv)."""
    global _RELOADING
    with _RELOAD_LOCK:
        if _RELOADING:
            return {"ok": True, "reloading": True, "already_scheduled": True}
        _RELOADING = True

    under_systemd = bool(os.environ.get("INVOCATION_ID"))

    def _worker() -> None:
        time.sleep(max(0.05, float(delay_s)))
        if under_systemd:
            # Under systemd `Restart=always` / `on-failure`, try `systemctl --user restart` first,
            # falling back to SIGTERM so systemd respawns a fresh process cleanly.
            try:
                subprocess.Popen(
                    ["systemctl", "--user", "restart", "jarvis.service"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    start_new_session=True,
                )
                return
            except OSError:
                os.kill(os.getpid(), signal.SIGTERM)
                return

        if httpd is not None:
            try:
                httpd.shutdown()
                httpd.server_close()
            except Exception:
                pass
        try:
            os.execv(sys.executable, [sys.executable, *sys.argv])
        except OSError:
            os.kill(os.getpid(), signal.SIGTERM)

    threading.Thread(target=_worker, name="jarvis-self-reload", daemon=True).start()
    return {
        "ok": True,
        "reloading": True,
        "pid": os.getpid(),
        "mode": "systemd" if under_systemd else "execv",
    }


def reload_external_instance(host: str, port: int) -> bool:
    """Restart or reload an already-running Jarvis instance on `host:port`."""
    if is_systemd_service_active("jarvis.service"):
        try:
            subprocess.run(
                ["systemctl", "--user", "restart", "jarvis.service"],
                capture_output=True,
                timeout=10,
                check=False,
            )
            if wait_for_healthy(host, port, timeout_s=12.0):
                return True
        except (OSError, subprocess.SubprocessError):
            pass

    # Fallback for standalone non-systemd `server.py`: call `POST /mission/reload`
    origin = f"http://{host}:{int(port)}"
    try:
        raw = b"{}"
        req = urllib.request.Request(
            f"{origin}/mission/reload",
            data=raw,
            method="POST",
            headers={
                "Host": f"{host}:{int(port)}",
                "Origin": origin,
                "Content-Type": "application/json",
                "Content-Length": "2",
            },
        )
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            if resp.status == 200:
                time.sleep(0.5)
                return wait_for_healthy(host, port, timeout_s=12.0)
    except Exception:
        pass
    return wait_for_healthy(host, port, timeout_s=4.0)


def handle_address_in_use(host: str, port: int, root: str | Path, *, force_reload: bool = False) -> bool:
    """Recover from `Errno 98` when another Jarvis instance already owns `host:port`.

    Returns `True` if a healthy Jarvis instance is serving `host:port` (reloading it
    automatically if its code is older than disk or lacks `/mission/instance`).
    """
    if not is_port_open(host, port):
        return False

    info = probe_running_instance(host, port)
    # If `info` is None, the running server predates `/mission/instance` -> reload it!
    needs_reload = force_reload or (info is None) or bool(info.get("stale"))

    if needs_reload and os.environ.get("JARVIS_RELOAD_ON_CONFLICT", "1") != "0":
        if reload_external_instance(host, port):
            print(f"http://{host}:{port} (reloaded running Jarvis instance)", flush=True)
            return True

    if wait_for_healthy(host, port, timeout_s=5.0):
        print(f"http://{host}:{port} (attached to running Jarvis instance)", flush=True)
        return True
    return False


def start_auto_reload_watcher(httpd, root: str | Path, *, poll_interval: float = 4.0, debounce_s: float = 2.5) -> None:
    """Watch runtime `.py` files and automatically hot-reload when edits settle."""
    if os.environ.get("JARVIS_AUTO_RELOAD", "1") == "0":
        return
    base = Path(root).expanduser().resolve()

    def _watch() -> None:
        baseline = max(BOOT_TIME, latest_source_mtime(base))
        pending_mtime = 0.0
        changed_since = 0.0
        deferred = False

        while not _RELOADING:
            time.sleep(max(1.5, float(poll_interval)))
            # Only watch `.py` backend modules for process restart (frontend JS/CSS is served fresh per request)
            py_newest = 0.0
            try:
                for entry in base.iterdir():
                    if entry.is_file() and entry.name.endswith(".py"):
                        py_newest = max(py_newest, entry.stat().st_mtime)
                    elif entry.is_dir() and entry.name == "operator_modules":
                        for sub in entry.rglob("*.py"):
                            py_newest = max(py_newest, sub.stat().st_mtime)
            except OSError:
                continue

            if py_newest > baseline + 0.5:
                if py_newest != pending_mtime:
                    pending_mtime = py_newest
                    changed_since = time.monotonic()
                    deferred = False
                    continue
                if (time.monotonic() - changed_since) < debounce_s:
                    continue
                if _any_agent_busy():
                    # Reloading now would kill the sandboxes of a running wave: wait for
                    # the room to go quiet and reload then.
                    if not deferred:
                        deferred = True
                        print("[auto-reload] zmiany gotowe, ale trwa praca agenta/zespołu — "
                              "przeładuję po jej zakończeniu", flush=True)
                    continue
                print("[auto-reload] Wykryto zmiany w modułach Python — przeładowywanie instancji Jarvisa…", flush=True)
                trigger_self_reload(httpd, delay_s=0.2)
                return

    threading.Thread(target=_watch, name="jarvis-auto-reload-watcher", daemon=True).start()
