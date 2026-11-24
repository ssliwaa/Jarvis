"""Linux process telemetry, deep resource inspection, socket correlation, and controlled signaling.

Pure Python standard library implementation reading the Linux /proc filesystem.
Zero external dependencies.
"""

from __future__ import annotations

import os
import pwd
import re
import signal
import socket
import struct
from pathlib import Path
from typing import Any

# Memory page size for RSS calculations
PAGE_SIZE = os.sysconf("SC_PAGE_SIZE") if hasattr(os, "sysconf") else 4096

# Allowed signals whitelist
ALLOWED_SIGNALS: dict[str, int] = {
    "SIGTERM": signal.SIGTERM,
    "SIGINT": signal.SIGINT,
    "SIGHUP": signal.SIGHUP,
    "SIGUSR1": signal.SIGUSR1,
    "SIGUSR2": signal.SIGUSR2,
    "SIGKILL": signal.SIGKILL,
}

# Mapping integer values to canonical signal names
INT_TO_SIGNAL: dict[int, str] = {v: k for k, v in ALLOWED_SIGNALS.items()}

# TCP state constants from Linux kernel
TCP_STATE_MAP: dict[str, str] = {
    "01": "ESTABLISHED",
    "02": "SYN_SENT",
    "03": "SYN_RECV",
    "04": "FIN_WAIT1",
    "05": "FIN_WAIT2",
    "06": "TIME_WAIT",
    "07": "CLOSE",
    "08": "CLOSE_WAIT",
    "09": "LAST_ACK",
    "0A": "LISTEN",
    "0B": "CLOSING",
}

# Token redaction regex for sensitive strings, API keys, and environment variables
RE_REDACT_TOKEN = re.compile(
    r"(?:\bsk-(?:or-|ant-|proj-)?[A-Za-z0-9_-]{8,}|\bBearer\s+\S+|"
    r"(?:api[_-]?key|token|password|passwd|secret|auth)\s*[:=]\s*[^\s,;]{4,})",
    re.I,
)

SENSITIVE_ENV_WORDS = frozenset({"KEY", "TOKEN", "SECRET", "PASS", "AUTH", "CREDENTIAL", "PRIVATE", "CERT"})

KNOWN_ARGUMENTS = frozenset({
    "action",
    "pid",
    "limit",
    "filter_name",
    "pattern",
    "filter_user",
    "user",
    "order_by",
    "sort_by",
    "port",
    "protocol",
    "socket_state",
    "signal",
    "confirm",
    "include_fds",
    "include_environ",
})

VALID_ACTIONS = frozenset({"list_processes", "inspect_pid", "socket_owners", "send_signal"})

# User ID cache to avoid repeated pwd lookups
_UID_CACHE: dict[int, str] = {}


def _resolve_uid(uid: int) -> str:
    """Resolve a numeric UID to username with caching and fallback."""
    if uid in _UID_CACHE:
        return _UID_CACHE[uid]
    try:
        name = pwd.getpwuid(uid).pw_name
    except (KeyError, OSError, ValueError):
        name = str(uid)
    _UID_CACHE[uid] = name
    return name


def _envelope_success(payload: Any) -> dict[str, Any]:
    """Standardized 5-key Jarvis success envelope."""
    return {
        "ok": True,
        "success": True,
        "data": payload,
        "result": payload,
        "error": None,
    }


def _envelope_error(err_type: str, message: str) -> dict[str, Any]:
    """Standardized 5-key Jarvis error envelope."""
    return {
        "ok": False,
        "success": False,
        "data": None,
        "result": None,
        "error": f"{err_type}: {message}",
    }


def _redact_cmdline_text(cmdline: str) -> str:
    """Mask sensitive tokens or passwords in command line strings."""
    if not cmdline:
        return cmdline
    return RE_REDACT_TOKEN.sub("[REDACTED]", cmdline)


def _parse_net_address(hex_addr: str) -> tuple[str, int]:
    """Decode HEX_IP:HEX_PORT into human-readable IP string and port integer."""
    try:
        hex_ip, hex_port = hex_addr.split(":")
        port = int(hex_port, 16)
        if len(hex_ip) == 8:
            # IPv4: 32-bit little-endian
            ip = socket.inet_ntoa(struct.pack("<I", int(hex_ip, 16)))
        elif len(hex_ip) == 32:
            # IPv6: four 32-bit host-endian words
            words = [int(hex_ip[i : i + 8], 16) for i in range(0, 32, 8)]
            packed = struct.pack("<IIII", *words)
            ip = socket.inet_ntop(socket.AF_INET6, packed)
        else:
            ip = hex_ip
        return ip, port
    except Exception:
        return hex_addr, 0


def _parse_proc_stat(stat_text: str) -> dict[str, Any]:
    """Parse /proc/<pid>/stat respecting parentheses in the process command name."""
    lparen = stat_text.find("(")
    rparen = stat_text.rfind(")")
    if lparen == -1 or rparen == -1 or rparen <= lparen:
        return {}
    comm = stat_text[lparen + 1 : rparen]
    fields = stat_text[rparen + 2 :].split()
    if len(fields) < 22:
        return {"comm": comm}
    try:
        return {
            "comm": comm,
            "state": fields[0],
            "ppid": int(fields[1]),
            "pgrp": int(fields[2]),
            "session": int(fields[3]),
            "utime": int(fields[11]),
            "stime": int(fields[12]),
            "priority": int(fields[15]),
            "nice": int(fields[16]),
            "num_threads": int(fields[17]),
            "vsize": int(fields[20]),
            "rss": max(0, int(fields[21])) * PAGE_SIZE,
        }
    except (ValueError, IndexError):
        return {"comm": comm}


def _parse_proc_status(status_text: str) -> dict[str, Any]:
    """Parse /proc/<pid>/status into dictionary with memory converted to bytes."""
    data: dict[str, Any] = {}
    for line in status_text.splitlines():
        k, sep, v = line.partition(":")
        if not sep:
            continue
        key = k.strip()
        val = v.strip()
        if key in ("VmSize", "VmRSS", "VmHWM", "VmSwap", "VmPeak"):
            try:
                data[key] = int(val.split()[0]) * 1024
            except (ValueError, IndexError):
                data[key] = 0
        elif key in ("Threads", "FDSize", "PPid", "Pid"):
            try:
                data[key] = int(val)
            except ValueError:
                data[key] = val
        elif key == "Uid":
            uids = val.split()
            data["Uid"] = [int(u) for u in uids if u.isdigit()]
        elif key == "Gid":
            gids = val.split()
            data["Gid"] = [int(g) for g in gids if g.isdigit()]
        else:
            data[key] = val
    return data


def _get_process_cmdline(pid: int, comm: str = "") -> tuple[str, list[str]]:
    """Read /proc/<pid>/cmdline returning redacted full string and argument list."""
    try:
        cmd_bytes = Path(f"/proc/{pid}/cmdline").read_bytes()
        args = [arg.decode("utf-8", errors="replace") for arg in cmd_bytes.split(b"\x00") if arg]
        cmdline = " ".join(args)
        if not cmdline:
            cmdline = f"[{comm}]" if comm else ""
        redacted_cmdline = _redact_cmdline_text(cmdline)
        redacted_args = [_redact_cmdline_text(a) for a in args]
        return redacted_cmdline, redacted_args
    except OSError:
        fallback = f"[{comm}]" if comm else ""
        return fallback, [fallback] if fallback else []


def _redact_environ(env_bytes: bytes) -> dict[str, str]:
    """Parse /proc/<pid>/environ into sanitized key-value dictionary."""
    redacted: dict[str, str] = {}
    entries = [e.decode("utf-8", errors="replace") for e in env_bytes.split(b"\x00") if e]
    for entry in entries:
        k, sep, v = entry.partition("=")
        if not sep:
            continue
        key_upper = k.upper()
        if any(w in key_upper for w in SENSITIVE_ENV_WORDS) or RE_REDACT_TOKEN.search(v):
            redacted[k] = "[REDACTED]"
        else:
            redacted[k] = v[:500]
    return redacted


# --- Action Implementations ---

def _action_list_processes(args: dict[str, Any]) -> dict[str, Any]:
    raw_limit = args.get("limit", 50)
    try:
        limit = max(1, min(int(raw_limit if raw_limit is not None else 50), 200))
    except (TypeError, ValueError):
        return _envelope_error("ValueError", "Parameter 'limit' must be an integer between 1 and 200.")

    filter_name = (args.get("pattern") or args.get("filter_name") or "").strip().lower()
    filter_user = (args.get("user") or args.get("filter_user") or "").strip().lower()
    order_by = (args.get("sort_by") or args.get("order_by") or "rss").strip().lower()
    if order_by == "memory":
        order_by = "rss"

    proc_dir = Path("/proc")
    if not proc_dir.is_dir():
        return _envelope_error("RuntimeError", "Linux /proc filesystem is not available.")

    rows: list[dict[str, Any]] = []
    total_scanned = 0

    try:
        entries = list(proc_dir.iterdir())
    except OSError as err:
        return _envelope_error("OSError", f"Failed to list /proc entries: {err}")

    for entry in entries:
        name = entry.name
        if not name.isdigit():
            continue
        total_scanned += 1
        pid = int(name)

        try:
            st = entry.stat()
            uid = st.st_uid
            stat_text = (entry / "stat").read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        stat_info = _parse_proc_stat(stat_text)
        comm = stat_info.get("comm", "")
        cmdline, _ = _get_process_cmdline(pid, comm)
        user = _resolve_uid(uid)
        cmdline_display = cmdline[:512]

        # Filters
        if filter_name and (filter_name not in comm.lower() and filter_name not in cmdline_display.lower()):
            continue
        if filter_user and (filter_user != user.lower() and filter_user != str(uid)):
            continue

        rows.append({
            "pid": pid,
            "ppid": stat_info.get("ppid", 0),
            "name": comm,
            "state": stat_info.get("state", "unknown"),
            "user": user,
            "uid": uid,
            "rss_bytes": stat_info.get("rss", 0),
            "vms_bytes": stat_info.get("vsize", 0),
            "threads": stat_info.get("num_threads", 1),
            "cmdline": cmdline_display,
        })

    # Sort
    if order_by == "vms":
        rows.sort(key=lambda item: item["vms_bytes"], reverse=True)
    elif order_by == "pid":
        rows.sort(key=lambda item: item["pid"])
    elif order_by == "name":
        rows.sort(key=lambda item: item["name"].lower())
    else:  # default rss
        rows.sort(key=lambda item: item["rss_bytes"], reverse=True)

    data = {
        "count": len(rows[:limit]),
        "total_matched": len(rows),
        "total_scanned": total_scanned,
        "truncated": len(rows) > limit,
        "processes": rows[:limit],
    }
    return _envelope_success(data)


def _action_inspect_pid(args: dict[str, Any]) -> dict[str, Any]:
    raw_pid = args.get("pid")
    if raw_pid is None or isinstance(raw_pid, bool):
        return _envelope_error("ValueError", "Parameter 'pid' must be a positive integer.")
    try:
        pid = int(raw_pid)
        if pid <= 0:
            return _envelope_error("ValueError", "Parameter 'pid' must be a positive integer.")
    except (TypeError, ValueError):
        return _envelope_error("ValueError", "Parameter 'pid' must be a positive integer.")

    proc_path = Path(f"/proc/{pid}")
    if not proc_path.is_dir():
        return _envelope_error("ProcessLookupError", f"Process with PID {pid} not found.")

    try:
        # Use open() directly so mock_open in tests functions predictably
        with open(f"/proc/{pid}/stat", "r", encoding="utf-8", errors="replace") as f:
            stat_text = f.read()
    except ProcessLookupError:
        return _envelope_error("ProcessLookupError", f"Process with PID {pid} not found.")
    except PermissionError:
        return _envelope_error("PermissionError", f"Permission denied accessing /proc/{pid}/stat.")
    except OSError as err:
        return _envelope_error("ProcessLookupError", f"Process with PID {pid} not found: {err}")

    try:
        with open(f"/proc/{pid}/status", "r", encoding="utf-8", errors="replace") as f:
            status_text = f.read()
    except OSError:
        status_text = ""

    stat_info = _parse_proc_stat(stat_text)
    status_info = _parse_proc_status(status_text)
    comm = stat_info.get("comm") or status_info.get("Name", "")
    cmdline_str, cmdline_args = _get_process_cmdline(pid, comm)

    uid_list = status_info.get("Uid")
    if uid_list and isinstance(uid_list, list) and len(uid_list) > 0:
        uid = uid_list[0]
    else:
        try:
            uid = proc_path.stat().st_uid
        except OSError:
            uid = 0

    gid_list = status_info.get("Gid")
    if gid_list and isinstance(gid_list, list) and len(gid_list) > 0:
        gid = gid_list[0]
    else:
        try:
            gid = proc_path.stat().st_gid
        except OSError:
            gid = 0

    user = _resolve_uid(uid)

    # Executable and CWD
    exe_path = None
    try:
        exe_path = os.readlink(proc_path / "exe")
    except OSError:
        pass

    cwd_path = None
    try:
        cwd_path = os.readlink(proc_path / "cwd")
    except OSError:
        pass

    # Open FDs
    include_fds = args.get("include_fds", True)
    open_files: list[dict[str, str]] = []
    process_sockets: list[dict[str, str]] = []
    total_fds = 0
    fds_permission_denied = False

    if include_fds:
        fd_dir = proc_path / "fd"
        try:
            for fd_entry in fd_dir.iterdir():
                total_fds += 1
                try:
                    target = os.readlink(fd_entry)
                    if target.startswith("socket:["):
                        inode = target[8:-1]
                        process_sockets.append({"fd": fd_entry.name, "inode": inode, "target": target})
                    else:
                        if len(open_files) < 50:
                            open_files.append({"fd": fd_entry.name, "path": target})
                except OSError:
                    continue
        except PermissionError:
            fds_permission_denied = True
        except OSError:
            pass

    # Environment
    include_environ = args.get("include_environ", False)
    environ_data = None
    if include_environ:
        try:
            raw_env = (proc_path / "environ").read_bytes()
            environ_data = _redact_environ(raw_env)
        except OSError:
            environ_data = {}

    rss_bytes = status_info.get("VmRSS", stat_info.get("rss", 0))
    vms_bytes = status_info.get("VmSize", stat_info.get("vsize", 0))
    threads_count = status_info.get("Threads", stat_info.get("num_threads", 1))
    fd_count = total_fds if not fds_permission_denied else 0

    data: dict[str, Any] = {
        "pid": pid,
        "ppid": stat_info.get("ppid", status_info.get("PPid", 0)),
        "name": comm,
        "state": status_info.get("State", stat_info.get("state", "unknown")),
        "user": user,
        "uid": uid,
        "gid": gid,
        "threads": threads_count,
        "num_threads": threads_count,
        "executable": exe_path,
        "cwd": cwd_path,
        "cmdline": cmdline_str[:4096],
        "cmdline_args": cmdline_args[:100],
        "rss_bytes": rss_bytes,
        "vms_bytes": vms_bytes,
        "open_fd_count": fd_count,
        "open_fds_count": total_fds if not fds_permission_denied else None,
        "memory": {
            "rss_bytes": rss_bytes,
            "vms_bytes": vms_bytes,
            "peak_rss_bytes": status_info.get("VmHWM", 0),
            "swap_bytes": status_info.get("VmSwap", 0),
        },
        "cpu": {
            "utime_ticks": stat_info.get("utime", 0),
            "stime_ticks": stat_info.get("stime", 0),
        },
        "open_files": open_files,
        "open_sockets": process_sockets,
        "sockets": process_sockets,
        "status": status_info,
    }
    if fds_permission_denied:
        data["fds_permission_denied"] = True
    if environ_data is not None:
        data["environ"] = environ_data

    return _envelope_success(data)


def _action_socket_owners(args: dict[str, Any]) -> dict[str, Any]:
    raw_port = args.get("port")
    port_filter = None
    if raw_port is not None:
        if isinstance(raw_port, bool) or not isinstance(raw_port, int):
            return _envelope_error("ValueError", "Port must be an integer between 1 and 65535.")
        port_filter = int(raw_port)
        if not (1 <= port_filter <= 65535):
            return _envelope_error("ValueError", "Port must be an integer between 1 and 65535.")

    proto_filter = (args.get("protocol") or "all").strip().lower()
    state_filter = (args.get("socket_state") or "LISTEN").strip().upper()
    raw_limit = args.get("limit", 50)
    try:
        limit = max(1, min(int(raw_limit if raw_limit is not None else 50), 200))
    except (TypeError, ValueError):
        return _envelope_error("ValueError", "Parameter 'limit' must be an integer between 1 and 200.")

    sources: list[tuple[str, Path]] = []
    if proto_filter in ("all", "tcp"):
        sources.append(("tcp", Path("/proc/net/tcp")))
    if proto_filter in ("all", "tcp6"):
        sources.append(("tcp6", Path("/proc/net/tcp6")))
    if proto_filter in ("all", "udp"):
        sources.append(("udp", Path("/proc/net/udp")))
    if proto_filter in ("all", "udp6"):
        sources.append(("udp6", Path("/proc/net/udp6")))

    sockets_by_inode: dict[str, dict[str, Any]] = {}

    for proto, path in sources:
        if not path.is_file():
            continue
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()[1:]
        except OSError:
            continue

        for line in lines:
            parts = line.strip().split()
            if len(parts) < 10:
                continue
            local_raw = parts[1]
            rem_raw = parts[2]
            st_raw = parts[3]
            uid_raw = parts[7]
            inode = parts[9]

            if inode == "0":
                continue

            local_ip, local_port = _parse_net_address(local_raw)
            rem_ip, rem_port = _parse_net_address(rem_raw)

            if port_filter is not None and local_port != port_filter:
                continue

            state_name = TCP_STATE_MAP.get(st_raw, st_raw) if "tcp" in proto else "UNCONN"
            if state_filter != "ALL" and state_name != state_filter:
                continue

            uid = int(uid_raw) if uid_raw.isdigit() else 0
            sockets_by_inode[inode] = {
                "protocol": proto,
                "local_address": f"{local_ip}:{local_port}",
                "local_ip": local_ip,
                "local_port": local_port,
                "remote_address": f"{rem_ip}:{rem_port}",
                "remote_ip": rem_ip,
                "remote_port": rem_port,
                "state": state_name,
                "inode": inode,
                "uid": uid,
                "user": _resolve_uid(uid),
                "pid": None,
                "process_name": None,
                "cmdline": None,
            }

    # Invert /proc/[pid]/fd to map inodes to PIDs
    if sockets_by_inode:
        target_inodes = set(sockets_by_inode.keys())
        proc_dir = Path("/proc")
        try:
            entries = list(proc_dir.iterdir())
        except OSError:
            entries = []

        for entry in entries:
            if not entry.name.isdigit():
                continue
            pid = int(entry.name)
            fd_dir = entry / "fd"
            try:
                for fd in fd_dir.iterdir():
                    try:
                        target = os.readlink(fd)
                        if target.startswith("socket:["):
                            in_str = target[8:-1]
                            if in_str in target_inodes:
                                sock_item = sockets_by_inode[in_str]
                                if sock_item["pid"] is None:
                                    sock_item["pid"] = pid
                                    comm = ""
                                    try:
                                        comm = (entry / "comm").read_text(encoding="utf-8").strip()
                                    except OSError:
                                        pass
                                    sock_item["process_name"] = comm
                                    cmdline, _ = _get_process_cmdline(pid, comm)
                                    sock_item["cmdline"] = cmdline
                    except OSError:
                        continue
            except (PermissionError, FileNotFoundError, OSError):
                continue

    results = list(sockets_by_inode.values())
    results.sort(key=lambda s: (s["local_port"], s["protocol"]))

    owner_info = None
    listening = False
    if port_filter is not None:
        matching = [s for s in results if s["local_port"] == port_filter]
        listening = any(s["state"] == "LISTEN" for s in matching) if matching else False
        for s in matching:
            if s["pid"] is not None:
                owner_info = {
                    "pid": s["pid"],
                    "name": s["process_name"] or "",
                    "cmdline": s.get("cmdline") or "",
                }
                break

    data: dict[str, Any] = {
        "count": len(results[:limit]),
        "total_matched": len(results),
        "sockets": results[:limit],
    }
    if port_filter is not None:
        data["port"] = port_filter
        data["protocol"] = proto_filter
        data["listening"] = listening
        data["owner"] = owner_info

    return _envelope_success(data)


def _action_send_signal(args: dict[str, Any]) -> dict[str, Any]:
    raw_pid = args.get("pid")
    if raw_pid is None or isinstance(raw_pid, bool):
        return _envelope_error("ValueError", "Parameter 'pid' must be a positive integer.")
    try:
        pid = int(raw_pid)
        if pid <= 0:
            return _envelope_error("ValueError", "Parameter 'pid' must be a positive integer.")
    except (TypeError, ValueError):
        return _envelope_error("ValueError", "Parameter 'pid' must be a positive integer.")

    # Guardrails: Forbidden PIDs
    if pid == 1:
        return _envelope_error("SecurityError", "Refusing to send signal to PID 1 (system init).")
    if pid == os.getpid():
        return _envelope_error("SecurityError", f"Refusing to send signal to self (PID {pid}).")
    if pid == os.getppid():
        return _envelope_error("SecurityError", f"Refusing to send signal to parent process (PID {pid}).")

    # Kernel thread check (PID 2 is kthreadd, or children of PPID 2, or status Name: kthreadd)
    if pid == 2:
        return _envelope_error("SecurityError", "Refusing to send signal to kernel thread (PID 2).")

    try:
        with open(f"/proc/{pid}/status", "r", encoding="utf-8", errors="replace") as f:
            status_content = f.read()
        for line in status_content.splitlines():
            if line.startswith("PPid:"):
                ppid_val = line.split(":", 1)[1].strip()
                if ppid_val == "2":
                    return _envelope_error("SecurityError", f"Refusing to send signal to kernel thread (PID {pid}, PPID 2).")
            if line.startswith("Name:"):
                name_val = line.split(":", 1)[1].strip()
                if name_val == "kthreadd":
                    return _envelope_error("SecurityError", f"Refusing to send signal to kernel thread '{name_val}' (PID {pid}).")
    except OSError:
        pass

    raw_sig = args.get("signal")
    if raw_sig is None:
        return _envelope_error("ValueError", "Parameter 'signal' is required.")

    sig_number: int | None = None
    sig_name: str | None = None

    if isinstance(raw_sig, int) and not isinstance(raw_sig, bool):
        if raw_sig in INT_TO_SIGNAL:
            sig_number = raw_sig
            sig_name = INT_TO_SIGNAL[raw_sig]
    elif isinstance(raw_sig, str):
        cleaned = raw_sig.strip().upper()
        if not cleaned.startswith("SIG") and f"SIG{cleaned}" in ALLOWED_SIGNALS:
            cleaned = f"SIG{cleaned}"
        if cleaned in ALLOWED_SIGNALS:
            sig_name = cleaned
            sig_number = ALLOWED_SIGNALS[cleaned]

    if sig_number is None or sig_name is None:
        allowed_list = ", ".join(sorted(ALLOWED_SIGNALS.keys()))
        return _envelope_error(
            "ValueError",
            f"Invalid signal {raw_sig!r}. Allowed signals: {allowed_list}.",
        )

    # High-impact confirmation requirement
    if sig_name == "SIGKILL" and args.get("confirm") is not True:
        return _envelope_error(
            "SecurityError",
            "Sending SIGKILL requires explicit confirmation (pass confirm=true).",
        )

    # Deliver signal
    try:
        os.kill(pid, sig_number)
    except ProcessLookupError:
        return _envelope_error("ProcessLookupError", f"Process with PID {pid} not found.")
    except PermissionError:
        return _envelope_error("PermissionError", f"Insufficient permission to send {sig_name} to PID {pid}.")
    except OSError as err:
        return _envelope_error("OSError", f"Failed to send {sig_name} to PID {pid}: {err}")

    payload = {
        "pid": pid,
        "signal": sig_name,
        "signal_number": sig_number,
        "delivered": True,
        "message": f"Successfully sent {sig_name} to PID {pid}.",
    }
    return _envelope_success(payload)


def process_inspector(arguments: dict[str, Any], context: dict[str, Any] | None = None) -> dict[str, Any]:
    """Execute Linux process inspection, telemetry, socket correlation, or signaling."""
    del context
    if not isinstance(arguments, dict):
        return _envelope_error("ValueError", "Arguments must be a dictionary.")

    try:
        # Enforce additionalProperties: False
        extra = set(arguments.keys()) - KNOWN_ARGUMENTS
        if extra:
            return _envelope_error("ValueError", f"Unexpected argument(s): {', '.join(sorted(extra))}")

        action = arguments.get("action")
        if not isinstance(action, str) or not action.strip():
            return _envelope_error("ValueError", "Missing or invalid 'action' parameter.")

        action = action.strip().lower()
        if action not in VALID_ACTIONS:
            return _envelope_error("ValueError", f"Unsupported action: {action!r}")

        if action == "list_processes":
            return _action_list_processes(arguments)
        if action == "inspect_pid":
            return _action_inspect_pid(arguments)
        if action == "socket_owners":
            return _action_socket_owners(arguments)
        if action == "send_signal":
            return _action_send_signal(arguments)

        return _envelope_error("ValueError", f"Unsupported action: {action!r}")
    except Exception as err:
        return _envelope_error(type(err).__name__, str(err))


TOOL = {
    "name": "process_inspector",
    "description": (
        "Inspect Linux system processes, resource telemetry, open file descriptors, "
        "network socket ownership, and send controlled POSIX signals via the /proc filesystem. "
        "Actions: 'list_processes', 'inspect_pid', 'socket_owners', 'send_signal'."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "action": {
                "type": "string",
                "enum": ["list_processes", "inspect_pid", "socket_owners", "send_signal"],
                "description": "Operation to perform.",
            },
            "pid": {
                "type": "integer",
                "minimum": 2,
                "description": "Target process ID for 'inspect_pid' or 'send_signal' (must be > 1).",
            },
            "limit": {
                "type": "integer",
                "minimum": 1,
                "maximum": 200,
                "description": "Maximum number of items to return (default: 50, max: 200).",
            },
            "filter_name": {
                "type": "string",
                "description": "Substring filter on process name or cmdline for 'list_processes'.",
            },
            "pattern": {
                "type": "string",
                "description": "Alias for filter_name for 'list_processes'.",
            },
            "filter_user": {
                "type": "string",
                "description": "Filter by username for 'list_processes'.",
            },
            "user": {
                "type": "string",
                "description": "Alias for filter_user for 'list_processes'.",
            },
            "order_by": {
                "type": "string",
                "enum": ["rss", "vms", "pid", "name", "memory"],
                "description": "Sort order for 'list_processes' (default: 'rss').",
            },
            "sort_by": {
                "type": "string",
                "enum": ["rss", "vms", "pid", "name", "memory"],
                "description": "Alias for order_by for 'list_processes'.",
            },
            "port": {
                "type": "integer",
                "minimum": 1,
                "maximum": 65535,
                "description": "Local port number to filter by for 'socket_owners'.",
            },
            "protocol": {
                "type": "string",
                "enum": ["all", "tcp", "tcp6", "udp", "udp6"],
                "description": "Network protocol to inspect for 'socket_owners' (default: 'all').",
            },
            "socket_state": {
                "type": "string",
                "enum": ["ALL", "LISTEN", "ESTABLISHED", "TIME_WAIT", "CLOSE"],
                "description": "Filter by socket state for 'socket_owners' (default: 'LISTEN').",
            },
            "signal": {
                "description": "POSIX signal to send ('SIGTERM', 'SIGINT', 'SIGHUP', 'SIGUSR1', 'SIGUSR2', 'SIGKILL', or integer).",
            },
            "confirm": {
                "type": "boolean",
                "description": "Explicit confirmation required for dangerous operations (e.g. SIGKILL).",
            },
            "include_fds": {
                "type": "boolean",
                "description": "Whether to include open file descriptors when inspecting PID (default: True).",
            },
            "include_environ": {
                "type": "boolean",
                "description": "Whether to include sanitized environment variables when inspecting PID (default: False).",
            },
        },
        "required": ["action"],
        "additionalProperties": False,
    },
    "handler": process_inspector,
    "approval": True,
}
