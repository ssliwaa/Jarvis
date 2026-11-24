#!/usr/bin/env python3
"""Boot guard for the systemd unit.

A guarded self-mod patch can leave ``server.py`` (or a module it imports) in a
state that fails at import time. systemd would then restart it every two
seconds and the in-process ``reconcile_pending()`` would never run. This small
wrapper checks the pending patch *before* handing control to server.py and
restores the backup when the patched tree cannot import.

It runs only at boot; it never touches a healthy patch and never imports the
server twice in the same process.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(os.environ.get("JARVIS_PROJECT_ROOT", Path(__file__).resolve().parents[1])).resolve()
STATE = Path(os.environ.get("JARVIS_STATE_HOME", Path.home() / ".jarvis-tools")).resolve()
PENDING = STATE / "selfmod" / "pending-restart.json"
BACKUPS = STATE / "selfmod" / "patch-backups"


def _imports(root: Path) -> bool:
    """Import the application in a child so a broken module is detectable."""
    try:
        result = subprocess.run(
            [sys.executable, "-c", "import server"],
            cwd=str(root), stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
            text=True, timeout=30,
            env={**os.environ, "JARVIS_EMBEDDINGS": "off",
                 "PYTHONDONTWRITEBYTECODE": "1"},
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    if result.returncode == 0:
        return True
    print(f"[jarvis-boot] import failed: {(result.stderr or '')[-400:]}", file=sys.stderr, flush=True)
    return False


def restore_if_broken(root: Path = ROOT, pending_path: Path = PENDING) -> dict:
    """Restore the pending backup if the patched tree cannot import."""
    try:
        pending = json.loads(Path(pending_path).read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeError):
        return {"ok": True, "action": "no-pending"}
    target = Path(str(pending.get("target") or ""))
    backup = Path(str(pending.get("backup") or ""))
    if not target.is_file() or not backup.is_file():
        return {"ok": True, "action": "missing-target-or-backup"}
    if _imports(Path(root)):
        return {"ok": True, "action": "healthy"}
    try:
        shutil.copy2(backup, target)
        print(f"[jarvis-boot] restored backup after failed import: {target}",
              file=sys.stderr, flush=True)
        return {"ok": True, "action": "restored", "target": str(target)}
    except OSError as error:
        print(f"[jarvis-boot] could not restore backup: {error}", file=sys.stderr, flush=True)
        return {"ok": False, "action": "restore-failed", "error": str(error)}


def main() -> int:
    restore_if_broken()
    os.execv(sys.executable, [sys.executable, "-u", str(Path(ROOT) / "server.py"),
                              *sys.argv[1:]])
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
