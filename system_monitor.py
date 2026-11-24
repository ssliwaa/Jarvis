"""Read-only Linux system diagnostics without a third-party dependency."""
from __future__ import annotations

import os
import shutil
import time
from pathlib import Path

PROC = Path("/proc")


def _read(path: str, default: str = "") -> str:
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return default


def _memory():
    values = {}
    for line in _read("/proc/meminfo").splitlines():
        if ":" in line:
            key, value = line.split(":", 1)
            values[key] = value.strip()
    def kb(name):
        try:
            return int(values.get(name, "0").split()[0]) * 1024
        except (ValueError, IndexError):
            return 0
    total, available = kb("MemTotal"), kb("MemAvailable")
    return {"total": total, "available": available, "used": max(0, total - available),
            "percent": round((max(0, total - available) / total * 100) if total else 0, 1)}


def _processes(limit=10):
    rows = []
    for entry in PROC.iterdir():
        if not entry.name.isdigit():
            continue
        try:
            raw_stat = (entry / "stat").read_text(encoding="utf-8", errors="replace")
            rparen = raw_stat.rfind(")")
            if rparen < 0:
                continue
            comm = raw_stat[raw_stat.find("(") + 1:rparen]
            fields = raw_stat[rparen + 2:].split()
            status = (entry / "status").read_text(encoding="utf-8", errors="replace")
            name = next((line.split(":", 1)[1].strip() for line in status.splitlines()
                         if line.startswith("Name:")), comm)
            rss = next((int(line.split()[1]) for line in status.splitlines()
                        if line.startswith("VmRSS:")), 0) * 1024
            utime, stime = int(fields[11]), int(fields[12])
            rows.append({"pid": int(entry.name), "name": name, "rss": rss,
                         "cpu_ticks": utime + stime, "state": fields[0]})
        except (OSError, ValueError, IndexError):
            continue
    rows.sort(key=lambda row: row["rss"], reverse=True)
    return rows[:max(1, min(int(limit), 30))]


def _battery():
    for path in sorted(Path("/sys/class/power_supply").glob("BAT*")):
        capacity = _read(str(path / "capacity"))
        status = _read(str(path / "status"))
        if capacity:
            try:
                return {"percent": int(capacity), "status": status or "unknown"}
            except ValueError:
                pass
    return None


def snapshot():
    load = _read("/proc/loadavg").split()
    try:
        uptime = float(_read("/proc/uptime", "0").split()[0])
    except (ValueError, IndexError):
        uptime = 0.0
    disk = shutil.disk_usage(str(Path.home()))
    return {
        "time": time.time(),
        "host": os.uname().nodename,
        "kernel": os.uname().release,
        "cpu_count": os.cpu_count() or 1,
        "load": [float(value) for value in load[:3]] if len(load) >= 3 else [0.0, 0.0, 0.0],
        "memory": _memory(),
        "disk": {"total": disk.total, "used": disk.used, "free": disk.free,
                 "percent": round(disk.used / disk.total * 100, 1) if disk.total else 0},
        "uptime": uptime,
        "battery": _battery(),
        "processes": _processes(10),
    }
