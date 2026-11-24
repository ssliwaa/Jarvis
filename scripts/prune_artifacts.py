#!/usr/bin/env python3
"""Prune old generated evidence while keeping the newest runs.

Nothing outside the configured artifact roots is touched. The default keeps
the 25 newest evidence jobs and files younger than 7 days; sessions/memory are
owned by their own retention settings and are never modified here.
"""
from __future__ import annotations

import argparse
import shutil
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CANDIDATES = ("artifacts/evidence", "artifacts/agent")


def prune(directory: Path, keep: int, days: float) -> dict:
    if not directory.is_dir():
        return {"path": str(directory), "removed": 0, "kept": 0}
    cutoff = time.time() - max(0.0, days) * 86400
    rows = []
    for path in directory.iterdir():
        try:
            rows.append((path.stat().st_mtime, path))
        except OSError:
            continue
    rows.sort(reverse=True)
    removed = 0
    for index, (mtime, path) in enumerate(rows):
        if index < keep or mtime >= cutoff:
            continue
        shutil.rmtree(path, ignore_errors=True) if path.is_dir() else path.unlink(missing_ok=True)
        removed += 1
    return {"path": str(directory), "removed": removed, "kept": len(rows) - removed}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--keep", type=int, default=25, help="newest entries to keep")
    parser.add_argument("--days", type=float, default=7.0, help="keep entries younger than this")
    parser.add_argument("--apply", action="store_true", help="delete; default is a dry run")
    args = parser.parse_args()
    for relative in CANDIDATES:
        directory = ROOT / relative
        if not directory.is_dir():
            continue
        if args.apply:
            print(prune(directory, args.keep, args.days))
        else:
            rows = sorted(directory.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True)
            print(f"{directory}: {len(rows)} entries; would keep {min(len(rows), args.keep)} newest")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
