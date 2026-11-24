"""Zero-root Linux block-storage health, mount-safety & backup retention manager (`storage_health.py`).

Tailored for compact Linux hosts with mixed NVMe + rotational 3.5" HDD storage:
  1. Reads `/sys/block/*` without root or subprocesses: classifies `HDD` (`rotational=1`)
     vs `NVMe/SSD` (`rotational=0`), capacity (GB), in-flight I/O requests, and drive `hwmon` °C.
  2. Parses `/proc/mounts` for real filesystems (`ext4`, `btrfs`, `xfs`, `ntfs`, `zfs`)
     remounted `ro` due to I/O errors.
  3. Audits `.jarvis-mcp-backups` footprint and safely prunes old backups beyond `keep_latest`.
"""

from __future__ import annotations

import time
from pathlib import Path

WATCHED_FS_TYPES = {"ext4", "btrfs", "xfs", "zfs", "f2fs", "ntfs", "ntfs3", "exfat"}
VIRTUAL_BLOCK_PREFIXES = ("loop", "ram", "zram", "dm-", "sr", "fd")


def _read_int(path: Path) -> int | None:
    try:
        return int(path.read_text(encoding="utf-8", errors="ignore").strip())
    except (OSError, ValueError):
        return None


def _drive_temp_c(block_dir: Path) -> float | None:
    for hw_root in (block_dir / "device" / "hwmon", block_dir / "device"):
        if not hw_root.is_dir():
            continue
        for tfile in sorted(hw_root.glob("**/temp*_input")):
            raw = _read_int(tfile)
            if raw is None:
                continue
            temp_c = round(raw / 1000.0, 1) if raw > 200 else float(raw)
            if -10.0 <= temp_c <= 115.0:
                return temp_c
    return None


def inspect_block_devices(sys_block: str | Path = "/sys/block") -> list[dict]:
    """Enumerate physical drives from `/sys/block` (`HDD` vs `NVMe/SSD`, GB, temp °C, I/O inflight)."""
    root = Path(sys_block)
    if not root.is_dir():
        return []

    drives: list[dict] = []
    for entry in sorted(root.iterdir()):
        name = entry.name
        if name.startswith(VIRTUAL_BLOCK_PREFIXES):
            continue
        sectors = _read_int(entry / "size")
        if not sectors or sectors <= 0:
            continue
        size_gb = round((sectors * 512) / (1024 ** 3), 1)
        rot = _read_int(entry / "queue" / "rotational")
        if name.startswith("nvme"):
            media = "NVMe"
        elif rot == 1:
            media = "HDD"
        else:
            media = "SSD"

        model = ""
        for mpath in (entry / "device" / "model", entry / "device" / "name"):
            if mpath.is_file():
                try:
                    model = mpath.read_text(encoding="utf-8", errors="ignore").strip()
                    if model:
                        break
                except OSError:
                    pass

        inflight_io = 0
        inflight_file = entry / "inflight"
        if inflight_file.is_file():
            try:
                parts = inflight_file.read_text(encoding="utf-8", errors="ignore").split()
                inflight_io = sum(int(x) for x in parts if x.isdigit())
            except OSError:
                inflight_io = 0

        drives.append({
            "device": name,
            "media": media,
            "rotational": bool(rot == 1),
            "model": model or name,
            "size_gb": size_gb,
            "temp_c": _drive_temp_c(entry),
            "inflight_io": inflight_io,
        })
    return drives[:16]


def inspect_mounts(proc_mounts: str | Path = "/proc/mounts") -> dict:
    """Detect real data filesystems unexpectedly mounted read-only (`ro`)."""
    p = Path(proc_mounts)
    ro_mounts: list[dict] = []
    checked = 0
    if p.is_file():
        try:
            for line in p.read_text(encoding="utf-8", errors="ignore").splitlines():
                parts = line.split()
                if len(parts) < 4:
                    continue
                dev, mnt, fstype, opts = parts[0], parts[1], parts[2], parts[3]
                if fstype not in WATCHED_FS_TYPES:
                    continue
                if mnt.startswith(("/snap/", "/boot/efi")):
                    continue
                checked += 1
                opt_set = set(opts.split(","))
                if "ro" in opt_set:
                    ro_mounts.append({"device": dev, "mountpoint": mnt, "fstype": fstype})
        except OSError:
            pass
    return {"checked_mounts": checked, "readonly_alerts": ro_mounts}


def backup_footprint(project_dir: str | Path | None) -> dict:
    """Measure `.jarvis-mcp-backups` file count and total MB inside `project_dir`."""
    if not project_dir:
        return {"count": 0, "total_mb": 0.0}
    bdir = Path(project_dir).expanduser().resolve() / ".jarvis-mcp-backups"
    if not bdir.is_dir():
        return {"count": 0, "total_mb": 0.0}
    files = [f for f in bdir.iterdir() if f.is_file() and f.name.endswith(".bak")]
    total_bytes = 0
    for f in files:
        try:
            total_bytes += f.stat().st_size
        except OSError:
            continue
    return {"count": len(files), "total_mb": round(total_bytes / (1024 * 1024), 2)}


def prune_mcp_backups(project_dir: str | Path, *, keep_latest: int = 30) -> dict:
    """Keep the newest `keep_latest` `.bak` files in `.jarvis-mcp-backups` and remove older ones."""
    root = Path(project_dir).expanduser().resolve()
    bdir = root / ".jarvis-mcp-backups"
    keep = max(5, int(keep_latest))
    if not bdir.is_dir():
        return {"ok": True, "removed": 0, "kept": 0, "freed_mb": 0.0}

    dated: list[tuple[float, int, Path]] = []
    for f in bdir.iterdir():
        if not f.is_file() or not f.name.endswith(".bak") or f.is_symlink():
            continue
        try:
            st = f.stat()
            dated.append((st.st_mtime, st.st_size, f))
        except OSError:
            continue

    dated.sort(key=lambda item: (item[0], item[2].name), reverse=True)
    to_keep = dated[:keep]
    to_remove = dated[keep:]

    removed = 0
    freed_bytes = 0
    for _mtime, sz, fpath in to_remove:
        try:
            fpath.unlink()
            removed += 1
            freed_bytes += sz
        except OSError:
            continue

    return {
        "ok": True,
        "removed": removed,
        "kept": len(to_keep),
        "freed_mb": round(freed_bytes / (1024 * 1024), 2),
    }


def inspect_storage(*, project_dir: str | Path | None = None,
                    sys_block: str | Path = "/sys/block",
                    proc_mounts: str | Path = "/proc/mounts") -> dict:
    """Unified non-privileged storage health snapshot (drives + mounts + backup bloat)."""
    drives = inspect_block_devices(sys_block)
    mounts = inspect_mounts(proc_mounts)
    backups = backup_footprint(project_dir)

    warnings: list[str] = []
    for r in mounts["readonly_alerts"]:
        warnings.append(f"System plików {r['mountpoint']} ({r['fstype']}) zamontowany w trybie tylko do odczytu (ro)!")
    for d in drives:
        t = d.get("temp_c")
        if t is not None:
            limit = 55.0 if d["media"] == "HDD" else 72.0
            if t >= limit:
                warnings.append(f"Wysoka temperatura dysku {d['device']} ({d['media']}): {t}°C")
    if backups["count"] > 60:
        warnings.append(f"Katalog .jarvis-mcp-backups zawiera {backups['count']} kopii ({backups['total_mb']} MB).")

    return {
        "ok": len(mounts["readonly_alerts"]) == 0,
        "checked_at": round(time.time(), 3),
        "drives": drives,
        "mounts": mounts,
        "mcp_backups": backups,
        "warnings": warnings,
    }
