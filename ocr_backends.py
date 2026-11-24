"""Optional surya OCR in its own venv.

surya pins `opencv-python-headless` and `pillow<11`; on Python 3.14 neither has
a wheel, so the venv cannot be built on this host. Everything here degrades to
"unavailable" and the caller keeps tesseract as the working engine.
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent
VENV = Path.home() / ".jarvis-tools" / "venvs" / "ocr"
PYTHON = VENV / "bin" / "python"
RUNNER = ROOT / "ocr_runner.py"
MARKER = "@@JARVIS@@"


def installed() -> bool:
    return PYTHON.is_file() and RUNNER.is_file()


def _call(payload: dict, timeout: float = 60) -> dict | None:
    if not installed():
        return None
    try:
        result = subprocess.run([str(PYTHON), str(RUNNER)], input=json.dumps(payload),
                                capture_output=True, text=True, timeout=timeout, cwd=str(ROOT))
    except (OSError, subprocess.TimeoutExpired):
        return None
    for line in reversed((result.stdout or "").splitlines()):
        if line.startswith(MARKER):
            try:
                return json.loads(line[len(MARKER):])
            except ValueError:
                return None
    return None


def status(probe: bool = False) -> dict:
    facts = {"installed": installed(), "venv": str(VENV)}
    if probe and installed():
        found = _call({"mode": "probe"}, 30) or {}
        facts.update({"ready": bool(found.get("ok")), "surya": bool(found.get("surya")),
                      "torch": found.get("torch", ""), "error": found.get("error", "")})
    return facts


def text(path: str, timeout: float = 300) -> dict | None:
    found = _call({"mode": "text", "path": str(path)}, timeout)
    if not found or not found.get("ok"):
        return None
    return {"text": str(found.get("text") or ""), "engine": "surya",
            "chars": int(found.get("chars") or 0)}
