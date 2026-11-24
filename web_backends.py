"""Optional web-reading backends in an isolated venv.

`web_runner.py` runs under ~/.jarvis-tools/venvs/web so crawl4ai and Scrapling
never share the Jarvis interpreter. If the venv or the runner is missing, the
caller falls back to the built-in urllib reader; nothing here is required for
the server to boot.
"""
from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent
VENV = Path.home() / ".jarvis-tools" / "venvs" / "web"
PYTHON = VENV / "bin" / "python"
RUNNER = ROOT / "web_runner.py"
MARKER = "@@JARVIS@@"
MAX_TIMEOUT = 60


def enabled() -> bool:
    return os.environ.get("JARVIS_WEB_BACKEND", "").strip().lower() != "builtin"


def installed() -> bool:
    return bool(enabled() and PYTHON.is_file() and RUNNER.is_file())


def _call(payload: dict, timeout: float) -> dict | None:
    if not installed():
        return None
    try:
        result = subprocess.run(
            [str(PYTHON), str(RUNNER)],
            input=json.dumps(payload), capture_output=True, text=True,
            timeout=max(3, min(float(timeout), MAX_TIMEOUT)), cwd=str(ROOT),
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    for line in reversed((result.stdout or "").splitlines()):
        if line.startswith(MARKER):
            try:
                return json.loads(line[len(MARKER):])
            except ValueError:
                return None
    try:
        return json.loads((result.stdout or "").strip().splitlines()[-1])
    except (ValueError, IndexError):
        return None


def status(probe: bool = False) -> dict:
    """Cheap readiness facts; `probe` spends a subprocess to import the engines."""
    facts = {"enabled": enabled(), "installed": installed(),
             "venv": str(VENV), "runner": str(RUNNER)}
    if probe and installed():
        found = _call({"mode": "probe"}, 30)
        facts["reachable"] = bool(found and found.get("ok"))
        facts["engines"] = (found or {}).get("engines", {})
        facts["chrome"] = (found or {}).get("chrome", "")
    return facts


def fetch(url: str, timeout: float = 20) -> dict | None:
    """Read a public page through crawl4ai. None = unavailable."""
    found = _call({"mode": "fetch", "url": url, "timeout": timeout,
                   "engines": ["crawl4ai"]}, timeout + 2)
    if not found or not found.get("ok"):
        return None
    text = str(found.get("text") or "")
    if not text.strip():
        return None
    return {"url": str(found.get("url") or url), "title": str(found.get("title") or "")[:240],
            "text": text, "engine": str(found.get("engine") or "unknown"),
            "status": int(found.get("status") or 200)}
