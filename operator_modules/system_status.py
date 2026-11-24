"""System status, Linux process diagnostics, and controlled self-healing (System Doctor)."""

from __future__ import annotations

import os
import re
import shutil
import socket
import stat
import subprocess
import time
from pathlib import Path
from typing import Any

HOME = Path.home()
STATE_ROOT = HOME / ".jarvis-tools"
CUA_SOCKET = HOME / ".cache" / "cua-driver" / "cua-driver.sock"
MCP_URL_FILE = STATE_ROOT / "mcp-public-url.txt"
PENDING_SELFMOD = STATE_ROOT / "selfmod" / "pending-restart.json"

ALLOWED_USER_UNITS = {
    "jarvis": "jarvis.service",
    "jarvis.service": "jarvis.service",
    "jarvis-mcp-public": "jarvis-mcp-public.service",
    "jarvis-mcp-public.service": "jarvis-mcp-public.service",
}
SAFE_HEAL_TARGETS = frozenset({"cua-driver", *ALLOWED_USER_UNITS.keys()})
_REDACT_TOKEN_RE = re.compile(
    r"(?:\bsk-(?:or-|ant-)?[A-Za-z0-9_-]{8,}|\bBearer\s+\S+|"
    r"(?:api[_-]?key|token|password|secret)\s*[:=]\s*[^\s,;]{4,})",
    re.I,
)


def _redact_log(text: str, limit: int = 2000) -> str:
    cleaned = _REDACT_TOKEN_RE.sub("[REDACTED]", str(text or ""))
    cleaned = cleaned.replace(str(HOME) + "/", "~/")
    return cleaned[:limit]


def _run_cmd(argv: list[str], timeout: float = 4.0) -> tuple[int, str]:
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)
        return proc.returncode, (proc.stdout or proc.stderr or "").strip()
    except (OSError, subprocess.SubprocessError):
        return 1, ""


def _memory() -> dict[str, int]:
    data: dict[str, int] = {}
    try:
        for line in Path("/proc/meminfo").read_text(encoding="utf-8").splitlines():
            key, _, value = line.partition(":")
            if key in ("MemTotal", "MemAvailable", "MemFree", "SwapTotal", "SwapFree"):
                data[key] = int(value.strip().split()[0]) * 1024
    except (OSError, ValueError):
        pass
    total = data.get("MemTotal", 0)
    available = data.get("MemAvailable", 0)
    swap_total = data.get("SwapTotal", 0)
    swap_free = data.get("SwapFree", 0)
    return {
        "total_bytes": total,
        "available_bytes": available,
        "used_bytes": max(0, total - available) if total else 0,
        "swap_total_bytes": swap_total,
        "swap_used_bytes": max(0, swap_total - swap_free) if swap_total else 0,
    }


def _uptime() -> float | None:
    try:
        return float(Path("/proc/uptime").read_text(encoding="utf-8").split()[0])
    except (OSError, ValueError, IndexError):
        return None


def _top_processes(limit: int = 8) -> dict[str, Any]:
    """Scan /proc directly without external dependencies for RSS memory hogs and zombies."""
    uid = os.getuid()
    page_size = 4096
    try:
        page_size = int(os.sysconf("SC_PAGE_SIZE"))
    except (ValueError, OSError, AttributeError):
        pass
    rows: list[dict[str, Any]] = []
    zombies: list[dict[str, Any]] = []
    proc_root = Path("/proc")
    if not proc_root.is_dir():
        return {"top_rss": [], "zombie_count": 0, "zombies": []}

    for entry in proc_root.iterdir():
        name = entry.name
        if not name.isdigit():
            continue
        pid = int(name)
        try:
            st = entry.stat()
            if st.st_uid != uid:
                continue
            stat_text = (entry / "stat").read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        rparen = stat_text.rfind(")")
        if rparen == -1:
            continue
        comm = stat_text[stat_text.find("(") + 1:rparen][:60]
        fields = stat_text[rparen + 2:].split()
        if len(fields) < 22:
            continue
        state = fields[0]
        rss_bytes = max(0, int(fields[21])) * page_size if fields[21].lstrip("-").isdigit() else 0
        if state == "Z":
            zombies.append({"pid": pid, "name": comm})
            continue
        rows.append({"pid": pid, "name": comm, "state": state, "rss_bytes": rss_bytes})

    rows.sort(key=lambda item: item["rss_bytes"], reverse=True)
    return {
        "top_rss": rows[:max(1, min(limit, 25))],
        "zombie_count": len(zombies),
        "zombies": zombies[:10],
    }


def _probe_unix_socket(sock_path: Path) -> dict[str, Any]:
    if not sock_path.exists():
        return {"present": False, "alive": False, "stale": False, "path": str(sock_path)}
    try:
        mode = sock_path.lstat().st_mode
    except OSError:
        return {"present": False, "alive": False, "stale": False, "path": str(sock_path)}
    if not stat.S_ISSOCK(mode):
        return {"present": True, "alive": False, "stale": True, "path": str(sock_path)}
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(0.5)
            client.connect(str(sock_path))
        return {"present": True, "alive": True, "stale": False, "path": str(sock_path)}
    except OSError:
        return {"present": True, "alive": False, "stale": True, "path": str(sock_path)}


def _probe_tcp(port: int) -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.25)
            return sock.connect_ex(("127.0.0.1", int(port))) == 0
    except OSError:
        return False


def _systemd_user_units() -> dict[str, dict[str, Any]]:
    results: dict[str, dict[str, Any]] = {}
    if not shutil.which("systemctl"):
        return results
    seen = sorted(set(ALLOWED_USER_UNITS.values()))
    for unit in seen:
        code, out = _run_cmd([
            "systemctl", "--user", "show", unit,
            "--property=LoadState,ActiveState,SubState,NRestarts",
        ])
        if code != 0 or not out:
            continue
        props = dict(line.split("=", 1) for line in out.splitlines() if "=" in line)
        if props.get("LoadState") == "not-found":
            continue
        try:
            restarts = int(props.get("NRestarts") or 0)
        except ValueError:
            restarts = 0
        results[unit] = {
            "active_state": props.get("ActiveState", "unknown"),
            "sub_state": props.get("SubState", "unknown"),
            "restarts": restarts,
        }
    return results


def _recent_journal_errors(unit: str | None = None, lines: int = 15) -> list[str]:
    if not shutil.which("journalctl"):
        return []
    capped = max(1, min(int(lines or 15), 50))
    argv = ["journalctl", "--user", "-p", "err..alert", "-n", str(capped), "--no-pager", "-o", "short-iso"]
    if unit:
        canonical = ALLOWED_USER_UNITS.get(unit.strip().lower())
        if not canonical:
            return []
        argv.extend(["-u", canonical])
    code, out = _run_cmd(argv, timeout=4.0)
    if code != 0 or not out or "No entries" in out:
        return []
    return [_redact_log(line, 240) for line in out.splitlines()[-capped:]]


def doctor_report(state_root: Path | None = None, cocket_path: Path | None = None) -> dict[str, Any]:
    """Run an active health & anomaly check across resources, sockets, and user services."""
    sroot = Path(state_root or STATE_ROOT)
    csock = Path(cocket_path or CUA_SOCKET)
    mem = _memory()
    disk = shutil.disk_usage(str(HOME))
    procs = _top_processes(limit=6)
    cua = _probe_unix_socket(csock)
    mcp_port = int(os.environ.get("JARVIS_MCP_HTTP_PORT", "4711") or 4711)
    mcp_alive = _probe_tcp(mcp_port)
    mcp_url_file = sroot / "mcp-public-url.txt"
    mcp_url = ""
    if mcp_url_file.is_file():
        try:
            mcp_url = mcp_url_file.read_text(encoding="utf-8", errors="replace").strip()
        except OSError:
            mcp_url = ""
    kino_ports = [p for p in (7358, 7357) if _probe_tcp(p)]
    units = _systemd_user_units()

    issues: list[dict[str, Any]] = []
    recommendations: list[dict[str, Any]] = []

    if mem["total_bytes"] > 0:
        avail_ratio = mem["available_bytes"] / mem["total_bytes"]
        if avail_ratio < 0.08:
            issues.append({
                "severity": "high",
                "component": "memory",
                "detail": f"Low available RAM ({round(avail_ratio * 100, 1)}% free).",
            })
    if disk.total > 0:
        free_gb = disk.free / (1024 ** 3)
        if free_gb < 2.0:
            issues.append({
                "severity": "high",
                "component": "disk_home",
                "detail": f"Low free disk space in HOME ({round(free_gb, 2)} GB remaining).",
            })
    if procs["zombie_count"] > 0:
        issues.append({
            "severity": "low",
            "component": "processes",
            "detail": f"{procs['zombie_count']} zombie process(es) owned by current user.",
        })
    if cua["stale"]:
        issues.append({
            "severity": "medium",
            "component": "cua-driver",
            "detail": f"Stale unresponsive desktop socket at {csock}.",
        })
        recommendations.append({
            "target": "cua-driver",
            "action": "heal",
            "reason": "Remove stale cua-driver socket and restart daemon cleanly.",
        })
    if mcp_url and not mcp_alive:
        issues.append({
            "severity": "medium",
            "component": "jarvis-mcp-public.service",
            "detail": f"Public tunnel URL file is populated, but local MCP bridge port {mcp_port} is closed.",
        })
        recommendations.append({
            "target": "jarvis-mcp-public.service",
            "action": "heal",
            "reason": "Restart jarvis-mcp-public.service to restore local MCP HTTP bridge.",
        })
    for unit_name, uinfo in units.items():
        if uinfo["active_state"] in ("failed", "activating") or uinfo["restarts"] >= 5:
            issues.append({
                "severity": "high" if uinfo["active_state"] == "failed" else "medium",
                "component": unit_name,
                "detail": f"Unit state={uinfo['active_state']}/{uinfo['sub_state']} (restarts={uinfo['restarts']}).",
            })
            recommendations.append({
                "target": unit_name,
                "action": "heal",
                "reason": f"Restart degraded systemd user service {unit_name}.",
            })

    pending_selfmod = (sroot / "selfmod" / "pending-restart.json").is_file()
    bg_logs = 0
    bg_dir = sroot / "background"
    if bg_dir.is_dir():
        try:
            bg_logs = sum(1 for _ in bg_dir.glob("*.log"))
        except OSError:
            bg_logs = 0

    return {
        "ok": True,
        "healthy": len(issues) == 0,
        "issues": issues,
        "recommendations": recommendations,
        "components": {
            "cua_driver_socket": cua,
            "mcp_bridge": {"port": mcp_port, "listening": mcp_alive, "public_url_present": bool(mcp_url)},
            "local_player": {"running": bool(kino_ports), "ports": kino_ports},
            "systemd_user": units,
            "pending_selfmod_restart": pending_selfmod,
            "background_logs_count": bg_logs,
        },
        "processes": procs,
        "recent_errors": _recent_journal_errors(lines=10),
    }


def heal_component(target: str, cua_socket: Path | None = None) -> dict[str, Any]:
    """Perform a strictly whitelisted self-healing action (requires Operator approval)."""
    key = str(target or "").strip().lower()
    if key not in SAFE_HEAL_TARGETS:
        return {
            "ok": False,
            "error": f"Target {target!r} is not in the safe self-heal allowlist ({', '.join(sorted(SAFE_HEAL_TARGETS))}).",
        }
    if key == "cua-driver":
        csock = Path(cua_socket or CUA_SOCKET)
        state = _probe_unix_socket(csock)
        try:
            from operator_tools import CuaDriver
            driver = CuaDriver()
            if not driver.available():
                if state["stale"]:
                    csock.unlink(missing_ok=True)
                    return {"ok": True, "target": "cua-driver", "healed": "removed_stale_socket_no_binary"}
                return {"ok": False, "target": "cua-driver", "error": "cua-driver binary is not installed."}
            driver._start_daemon(force=True)
            after = _probe_unix_socket(csock)
            return {"ok": True, "target": "cua-driver", "healed": "restarted_daemon", "socket": after}
        except Exception as exc:
            if state["stale"]:
                try:
                    csock.unlink(missing_ok=True)
                except OSError:
                    pass
            return {"ok": False, "target": "cua-driver", "error": f"{type(exc).__name__}: {exc}"[:240]}

    unit = ALLOWED_USER_UNITS[key]
    if not shutil.which("systemctl"):
        return {"ok": False, "target": unit, "error": "systemctl is not available on this host."}
    _run_cmd(["systemctl", "--user", "reset-failed", unit], timeout=5.0)
    code, out = _run_cmd(["systemctl", "--user", "restart", unit], timeout=15.0)
    if code != 0:
        return {"ok": False, "target": unit, "error": _redact_log(out or "systemctl restart failed", 300)}
    _, active = _run_cmd(["systemctl", "--user", "is-active", unit], timeout=5.0)
    return {"ok": active == "active", "target": unit, "healed": "restarted_unit", "active_state": active}


def _requires_approval(arguments: dict[str, Any] | None = None) -> bool:
    args = arguments if isinstance(arguments, dict) else {}
    return str(args.get("action") or "status").strip().lower() == "heal"


def system_status(arguments, context=None):
    """Read Linux resources, run System Doctor diagnostics, inspect logs, or heal a safe target."""
    args = arguments if isinstance(arguments, dict) else {}
    action = str(args.get("action") or "status").strip().lower()
    state_root = Path((context or {}).get("state_root") or STATE_ROOT)

    if action == "status":
        try:
            load = list(os.getloadavg())
        except (OSError, AttributeError):
            load = []
        disk = shutil.disk_usage(str(HOME))
        return {
            "ok": True,
            "load_1_5_15": load,
            "memory": _memory(),
            "disk_home": {"total_bytes": disk.total, "used_bytes": disk.used, "free_bytes": disk.free},
            "uptime_seconds": _uptime(),
            "time": time.time(),
        }
    if action == "processes":
        raw_limit = args.get("limit")
        try:
            limit = max(1, min(int(raw_limit if raw_limit is not None else 8), 25))
        except (TypeError, ValueError):
            return {"ok": False, "error": "Parameter 'limit' must be an integer."}
        return {"ok": True, **_top_processes(limit=limit)}
    if action == "logs":
        raw_lines = args.get("lines")
        try:
            lines = max(1, min(int(raw_lines if raw_lines is not None else 15), 50))
        except (TypeError, ValueError):
            return {"ok": False, "error": "Parameter 'lines' must be an integer."}
        unit = args.get("target")
        if unit is not None and str(unit).strip().lower() not in ALLOWED_USER_UNITS:
            return {"ok": False, "error": f"Unsupported log target {unit!r}; use a whitelisted Jarvis unit or omit target."}
        return {"ok": True, "target": unit, "errors": _recent_journal_errors(unit=unit, lines=lines)}
    if action == "doctor":
        return doctor_report(state_root=state_root)
    if action == "heal":
        if args.get("confirm") is not True:
            return {"ok": False, "error": "Pass confirm=true to execute self-healing."}
        return heal_component(str(args.get("target") or ""))
    return {"ok": False, "error": f"Unsupported action: {action!r}"}


TOOL = {
    "name": "system_status",
    "description": (
        "Read Linux CPU/RAM/disk/uptime ('status'), top user processes & zombies ('processes'), "
        "recent user journal errors ('logs'), full System Doctor diagnostics ('doctor'), "
        "or safely restart a degraded Jarvis component ('heal', requires approval)."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "action": {
                "type": "string",
                "enum": ["status", "doctor", "processes", "logs", "heal"],
                "description": "Operation to perform (default: 'status').",
            },
            "target": {
                "type": "string",
                "description": "Whitelisted component for 'heal' or 'logs' (cua-driver, jarvis.service, jarvis-mcp-public.service).",
            },
            "limit": {
                "type": "integer",
                "minimum": 1,
                "maximum": 25,
                "description": "Max processes to return when action='processes'.",
            },
            "confirm": {"type": "boolean", "description": "Explicit confirmation required when action='heal'."},
            "lines": {
                "type": "integer",
                "minimum": 1,
                "maximum": 50,
                "description": "Max error log lines when action='logs'.",
            },
        },
        "additionalProperties": False,
    },
    "handler": system_status,
    "approval": False,
}
