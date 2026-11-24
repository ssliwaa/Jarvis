"""Zero-subprocess Linux thermal, RAM pressure & concurrency guardian (`hardware_guard.py`).

Reads `/sys/class/hwmon`, `/sys/class/thermal`, and `/proc/meminfo` directly in <0.5ms
to protect compact desktops from thermal throttling or OOM kills during parallel
multi-agent waves, Whisper transcription, or Night Shift evolution.
"""

from __future__ import annotations

import time
from pathlib import Path

WARM_TEMP_C = 78.0
CRITICAL_TEMP_C = 88.0
LOW_MEM_AVAILABLE_MB = 1400.0
CRITICAL_MEM_AVAILABLE_MB = 600.0


def read_temperatures_c(sys_root: str | Path = "/sys") -> dict:
    """Read CPU/NVMe/SoC sensors from `/sys/class/hwmon` and `/sys/class/thermal`."""
    base = Path(sys_root)
    sensors: list[dict] = []

    hwmon_root = base / "class" / "hwmon"
    if hwmon_root.is_dir():
        for hw in sorted(hwmon_root.iterdir()):
            try:
                chip = (hw / "name").read_text(encoding="utf-8", errors="ignore").strip() or hw.name
            except OSError:
                chip = hw.name
            for tfile in sorted(hw.glob("temp*_input")):
                try:
                    raw = int(tfile.read_text(encoding="utf-8", errors="ignore").strip())
                except (OSError, ValueError):
                    continue
                temp_c = round(raw / 1000.0, 1) if raw > 200 else float(raw)
                if not (-10.0 <= temp_c <= 130.0):
                    continue
                label_file = hw / tfile.name.replace("_input", "_label")
                try:
                    label = label_file.read_text(encoding="utf-8", errors="ignore").strip()
                except OSError:
                    label = tfile.stem
                sensors.append({"chip": chip, "label": label or tfile.stem, "temp_c": temp_c})

    if not sensors:
        tz_root = base / "class" / "thermal"
        if tz_root.is_dir():
            for tz in sorted(tz_root.glob("thermal_zone*")):
                try:
                    raw = int((tz / "temp").read_text(encoding="utf-8", errors="ignore").strip())
                except (OSError, ValueError):
                    continue
                temp_c = round(raw / 1000.0, 1) if raw > 200 else float(raw)
                if not (-10.0 <= temp_c <= 130.0):
                    continue
                try:
                    kind = (tz / "type").read_text(encoding="utf-8", errors="ignore").strip()
                except OSError:
                    kind = tz.name
                sensors.append({"chip": "thermal", "label": kind or tz.name, "temp_c": temp_c})

    peak = max((s["temp_c"] for s in sensors), default=None)
    return {"peak_temp_c": peak, "sensors": sensors[:12]}


def read_memory_pressure(proc_meminfo: str | Path = "/proc/meminfo") -> dict:
    """Parse `MemTotal`, `MemAvailable`, `SwapTotal`, and `SwapFree` (in MB) from `/proc/meminfo`."""
    values_kb: dict[str, int] = {}
    p = Path(proc_meminfo)
    if p.is_file():
        try:
            for line in p.read_text(encoding="utf-8", errors="ignore").splitlines():
                if ":" not in line:
                    continue
                key, rest = line.split(":", 1)
                parts = rest.strip().split()
                if parts and parts[0].isdigit():
                    values_kb[key.strip()] = int(parts[0])
        except OSError:
            pass

    total_mb = round(values_kb.get("MemTotal", 0) / 1024.0, 1) if "MemTotal" in values_kb else None
    avail_mb = round(values_kb.get("MemAvailable", 0) / 1024.0, 1) if "MemAvailable" in values_kb else None
    swap_total = values_kb.get("SwapTotal", 0)
    swap_free = values_kb.get("SwapFree", 0)
    swap_used_mb = round(max(0, swap_total - swap_free) / 1024.0, 1) if swap_total > 0 else 0.0

    return {
        "mem_total_mb": total_mb,
        "mem_available_mb": avail_mb,
        "swap_used_mb": swap_used_mb,
    }


def snapshot(*, sys_root: str | Path = "/sys", proc_meminfo: str | Path = "/proc/meminfo") -> dict:
    """Evaluate thermal & RAM state (`nominal` | `warm` | `critical`) and safe agent parallelism."""
    temps = read_temperatures_c(sys_root)
    mem = read_memory_pressure(proc_meminfo)
    peak_t = temps["peak_temp_c"]
    avail_mb = mem["mem_available_mb"]

    reasons: list[str] = []
    state = "nominal"

    if (peak_t is not None and peak_t >= CRITICAL_TEMP_C) or (
        avail_mb is not None and avail_mb <= CRITICAL_MEM_AVAILABLE_MB
    ):
        state = "critical"
    elif (peak_t is not None and peak_t >= WARM_TEMP_C) or (
        avail_mb is not None and avail_mb <= LOW_MEM_AVAILABLE_MB
    ):
        state = "warm"

    if peak_t is not None and peak_t >= WARM_TEMP_C:
        reasons.append(f"wysoka temperatura czujnika ({peak_t}°C)")
    if avail_mb is not None and avail_mb <= LOW_MEM_AVAILABLE_MB:
        reasons.append(f"niska dostępna pamięć RAM ({avail_mb} MB)")

    if state == "critical":
        max_parallel = 1
        allow_background = False
        try:
            import event_bus
            event_bus.publish("hardware.alert", {
                "state": state,
                "peak_temp_c": peak_t,
                "mem_available_mb": avail_mb,
                "reasons": reasons,
            })
        except Exception:
            pass
    elif state == "warm":
        max_parallel = 1
        allow_background = True
    else:
        max_parallel = 3
        allow_background = True

    return {
        "ok": True,
        "checked_at": round(time.time(), 3),
        "state": state,
        "reasons": reasons,
        "peak_temp_c": peak_t,
        "sensors": temps["sensors"],
        **mem,
        "recommended_max_parallel_agents": max_parallel,
        "allow_heavy_background": allow_background,
    }
