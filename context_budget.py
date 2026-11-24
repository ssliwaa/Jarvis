"""Bounded tool output before it reaches the model.

The Operator lane feeds raw terminal output, page text and element lists back
into the context window. This module is the in-process equivalent of the
headroom/context-mode idea: strip noise, collapse duplicates, keep the head and
tail of long text, and cap long lists — without changing any control field.
"""
from __future__ import annotations

import math
import os
import re

DEFAULT_LIMIT = 6000
TEXT_KEYS = {"text", "output", "stdout", "stderr", "content", "html", "markdown",
             "body", "page_text", "message", "error", "detail", "snippet"}
KEEP_KEYS = {"ok", "status", "outcome", "id", "url", "href", "path", "token",
             "job_id", "step", "index", "count", "chars", "words", "engine"}
ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07]*\x07")


def limit() -> int:
    try:
        value = int(os.environ.get("JARVIS_TOOL_CHARS", DEFAULT_LIMIT))
    except ValueError:
        return DEFAULT_LIMIT
    return max(1200, min(value, 40000))


def strip_ansi(text: str) -> str:
    return ANSI.sub("", str(text or ""))


def squash(text: str, keep_repeats: int = 2) -> str:
    """Trim trailing spaces, collapse blank runs and repeated identical lines."""
    lines = []
    previous = None
    repeat = 0
    for raw in str(text or "").replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        line = raw.rstrip()
        if line == previous:
            repeat += 1
            if repeat > keep_repeats:
                continue
        else:
            repeat = 0
        previous = line
        lines.append(line)
    out = "\n".join(lines)
    out = re.sub(r"\n{3,}", "\n\n", out)
    return out.strip()


def middle_truncate(text: str, max_chars: int) -> str:
    text = str(text or "")
    if len(text) <= max_chars:
        return text
    head = int(max_chars * 0.6)
    tail = max_chars - head
    omitted = len(text) - head - tail
    return (text[:head] + f"\n… [{omitted} chars omitted] …\n" + text[-tail:])


def compress_text(text: str, max_chars: int | None = None) -> str:
    cap = int(max_chars or limit())
    cleaned = squash(strip_ansi(text))
    return middle_truncate(cleaned, cap)


def compress_payload(payload, max_chars: int | None = None, max_items: int = 200, depth: int = 0):
    """Return a copy with long strings and lists bounded; control fields untouched."""
    cap = int(max_chars or limit())
    if depth > 6:
        return "…"
    if isinstance(payload, str):
        return compress_text(payload, cap)
    if isinstance(payload, list):
        items = [compress_payload(item, cap, max_items, depth + 1) for item in payload[:max_items]]
        if len(payload) > max_items:
            items.append(f"… [{len(payload) - max_items} more items] …")
        return items
    if isinstance(payload, dict):
        out = {}
        for key, value in payload.items():
            if key in KEEP_KEYS:
                out[key] = value
            elif isinstance(value, str):
                out[key] = compress_text(value, cap) if key in TEXT_KEYS or len(value) > cap else value
            else:
                out[key] = compress_payload(value, cap, max_items, depth + 1)
        return out
    return payload


def estimate_tokens(text: str) -> int:
    return int(math.ceil(len(str(text or "")) / 4))


def stats(before, after) -> dict:
    raw = str(before or "")
    kept = str(after or "")
    return {"chars_before": len(raw), "chars_after": len(kept),
            "tokens_saved": max(0, estimate_tokens(raw) - estimate_tokens(kept)),
            "ratio": round(len(kept) / len(raw), 3) if raw else 1.0}
