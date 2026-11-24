"""Small systemd --user supervisor for the local Jarvis server.

The desktop shell used to start a bare background process.  That process dies
with its parent and nothing tells the viewer why.  This module owns a user unit
with Restart=always and a real watchdog ping, plus a read-only status view for
the Studio.
"""
from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent
UNIT_NAME = "jarvis.service"
UNIT_DIR = Path.home() / ".config/systemd/user"
UNIT_PATH = UNIT_DIR / UNIT_NAME
PYTHON = ROOT / ".venv/bin/python"
LOG_LIMIT = 40


class ServiceError(Exception):
    pass


def available() -> bool:
    return bool(shutil.which("systemctl")) and bool(os.environ.get("XDG_RUNTIME_DIR"))


def unit_text(root: Path = ROOT) -> str:
    """Return the unit without embedding any API key or other secret."""
    python = root / ".venv/bin/python"
    session_type = os.environ.get("XDG_SESSION_TYPE", "").strip() or "x11"
    if session_type not in ("x11", "wayland"):
        session_type = "x11"
    return f"""[Unit]
Description=Jarvis local knowledge server
After=graphical-session.target
Wants=graphical-session.target

[Service]
Type=notify
WorkingDirectory={root}
ExecStart={python} -u scripts/boot_server.py
Restart=always
RestartSec=2
TimeoutStartSec=20
WatchdogSec=30
Environment=PYTHONUNBUFFERED=1
Environment=DISPLAY=:0
Environment=XDG_SESSION_TYPE={session_type}

[Install]
WantedBy=default.target
"""


def _run(*args, timeout=15, check=True):
    try:
        result = subprocess.run(["systemctl", "--user", *args], capture_output=True, text=True,
                                timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ServiceError(str(error)) from error
    if check and result.returncode != 0:
        detail = (result.stderr or result.stdout or "systemctl failed").strip()
        raise ServiceError(detail[:300])
    return result


def write_unit(root: Path = ROOT) -> Path:
    UNIT_DIR.mkdir(parents=True, exist_ok=True)
    UNIT_PATH.write_text(unit_text(root), encoding="utf-8")
    UNIT_PATH.chmod(0o644)
    return UNIT_PATH


def install(root: Path = ROOT):
    if not available():
        raise ServiceError("systemd --user is not available in this session.")
    target = write_unit(root)
    _run("daemon-reload")
    _run("enable", UNIT_NAME)
    return {"ok": True, "unit": str(target), "enabled": True}


def status() -> dict:
    if not available():
        return {"available": False, "active": "unknown", "enabled": "unknown", "unit": str(UNIT_PATH)}
    result = _run("show", UNIT_NAME, "-p", "ActiveState,SubState,MainPID,UnitFileState,ExecMainStatus",
                  check=False)
    values = {}
    for line in (result.stdout or "").splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            values[key] = value.strip()
    payload = {"available": True, "active": values.get("ActiveState", "inactive"),
               "substate": values.get("SubState", ""), "pid": values.get("MainPID", "0"),
               "enabled": values.get("UnitFileState", "disabled"),
               "exit_status": values.get("ExecMainStatus", ""), "unit": str(UNIT_PATH)}
    if result.returncode != 0:
        payload["error"] = (result.stderr or result.stdout or "systemctl show failed").strip()[:300]
    return payload


def restart():
    if not available():
        raise ServiceError("systemd --user is not available in this session.")
    _run("restart", UNIT_NAME, timeout=30)
    return status()


def start():
    if not available():
        raise ServiceError("systemd --user is not available in this session.")
    _run("start", UNIT_NAME, timeout=30)
    return status()


def stop():
    if not available():
        raise ServiceError("systemd --user is not available in this session.")
    _run("stop", UNIT_NAME, timeout=20)
    return status()


def _detached(action: str):
    """Restart/stop after the HTTP response, from outside this service cgroup."""
    if not available():
        raise ServiceError("systemd --user is not available in this session.")
    runner = shutil.which("systemd-run")
    command = f"sleep 0.6; exec systemctl --user {action} {UNIT_NAME}"
    try:
        if runner:
            subprocess.Popen(
                [runner, "--user", "--collect", "--unit",
                 f"jarvis-{action}-{os.getpid()}-{os.urandom(2).hex()}",
                 "--", "/bin/sh", "-c", command],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                start_new_session=True)
        else:
            subprocess.Popen(["/bin/sh", "-c", command], stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL, start_new_session=True)
    except OSError as error:
        raise ServiceError(f"Could not schedule systemctl {action}: {error}") from None
    return {"ok": True, "outcome": "started", "action": action,
            "answer": f"systemctl {action} was scheduled; this process will stop in a moment."}


def restart_detached():
    return _detached("restart")


def stop_detached():
    return _detached("stop")


def logs(limit: int = LOG_LIMIT) -> list[str]:
    if not available() or not shutil.which("journalctl"):
        return []
    try:
        result = subprocess.run(["journalctl", "--user", "-u", UNIT_NAME, "-n", str(max(1, min(limit, 100))),
                                 "--no-pager", "-o", "short-iso"], capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        return []
    return [line for line in (result.stdout or "").splitlines() if line.strip()][-limit:]
