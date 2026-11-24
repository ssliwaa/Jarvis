#!/usr/bin/env python3
"""OCR bridge executed by the isolated OCR venv (surya + torch).

Protocol: one JSON request on stdin, one JSON response on stdout.
The caller never imports torch; a missing venv simply means "surya unavailable".

Note: this runner is written against the `surya_ocr` CLI, which is the stable
surface across surya releases. It is exercised by unit tests with a fixture;
a live run needs a host where surya's opencv pin has a wheel.
"""
from __future__ import annotations

import glob
import json
import os
import shutil
import subprocess
import sys
import tempfile

MARKER = "@@JARVIS@@"


def _surya_cli() -> str:
    candidate = os.path.join(os.path.dirname(sys.executable), "surya_ocr")
    if os.path.isfile(candidate):
        return candidate
    return shutil.which("surya_ocr") or ""


def probe() -> dict:
    try:
        import torch  # noqa: F401
        torch_version = torch.__version__
    except Exception as error:
        return {"ok": False, "error": f"torch: {type(error).__name__}", "surya": False}
    cli = _surya_cli()
    return {"ok": bool(cli), "surya": bool(cli), "cli": cli,
            "torch": torch_version, "error": "" if cli else "surya_ocr CLI not installed"}


def _read_results(folder: str) -> str:
    """Join the text of every page surya wrote to results.json."""
    for path in sorted(glob.glob(os.path.join(folder, "**", "*.json"), recursive=True)):
        try:
            with open(path, encoding="utf-8") as handle:
                data = json.load(handle)
        except Exception:
            continue
        pages = data if isinstance(data, list) else [data]
        chunks = []
        for page in pages:
            for line in (page.get("text_lines") or []):
                text = str(line.get("text") or "").strip()
                if text:
                    chunks.append(text)
        if chunks:
            return "\n".join(chunks)
    return ""


def run_text(request: dict) -> dict:
    path = str(request.get("path") or "")
    if not os.path.isfile(path):
        return {"ok": False, "error": "file not found"}
    cli = _surya_cli()
    if not cli:
        return {"ok": False, "error": "surya_ocr CLI not installed"}
    output = tempfile.mkdtemp(prefix="jarvis-surya-")
    try:
        # Stage the single file into an isolated directory: pointing the CLI
        # at the file's own folder used to OCR *everything* next to it and
        # returned the first JSON it happened to find.
        staged = os.path.join(output, "input-dir", os.path.basename(path) or "image.png")
        os.makedirs(os.path.dirname(staged), exist_ok=True)
        shutil.copy2(path, staged)
        result = subprocess.run([cli, os.path.join(output, "input-dir"), "--output_dir", output],
                                capture_output=True, text=True, timeout=300)
        if result.returncode != 0:
            return {"ok": False, "error": (result.stderr or "surya failed").strip()[:300]}
        text = _read_results(output)
        if not text:
            return {"ok": False, "error": "surya returned no text"}
        return {"ok": True, "text": text[:20000], "chars": len(text),
                "engine": "surya", "pages": 1}
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "surya timed out"}
    finally:
        shutil.rmtree(output, ignore_errors=True)


def main() -> int:
    try:
        request = json.loads(sys.stdin.read() or "{}")
    except Exception:
        print(MARKER + json.dumps({"ok": False, "error": "bad request"}))
        return 0
    mode = request.get("mode") or "probe"
    answer = probe() if mode == "probe" else run_text(request)
    print(MARKER + json.dumps(answer, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
