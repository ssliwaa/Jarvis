"""Voice, Wayland dictation, barge-in, and sentence-streaming TTS HTTP routes.

Follows the `studio_routes.py` / `mission_routes.py` convention: returns `True`
when a route was handled and a JSON response was sent.
"""

from __future__ import annotations

import wayland_voice
from errors import AppError


def dictate_to_desktop(raw_text: str, clipboard_mod=None) -> dict:
    """Copy sanitized text to clipboard (fallback) and type via Wayland/X11 backend."""
    safe = wayland_voice.sanitize_dictation_text(raw_text)
    copied = False
    if safe and clipboard_mod is not None:
        try:
            clipboard_mod.write(safe)
            copied = True
        except Exception:
            copied = False
    typed_res = wayland_voice.type_text(safe)
    return {
        "dictated": bool(copied or typed_res.get("typed")),
        "copied_to_clipboard": copied,
        "typed": bool(typed_res.get("typed")),
        "typing_backend": typed_res.get("backend"),
    }


def get_voice(handler, parsed) -> bool:
    """Handle voice/DND GET endpoints; returns True if handled."""
    if parsed.path == "/voice/dnd":
        handler.validate_origin()
        handler.send_json(200, {
            "ok": True,
            **wayland_voice.dnd_status(),
            "barge_in_generation": wayland_voice.BARGE_IN.generation,
        })
        return True
    return False


def _chunk_bounds(body: dict) -> tuple[int, int]:
    """Coerce the chunk-bounds query; garbage answers 400, never a 500."""
    try:
        min_chars = int(body.get("min_chars") or 18)
        max_chars = int(body.get("max_chars") or 260)
    except (TypeError, ValueError):
        raise AppError("INVALID_TTS_PARAMS",
                       "min_chars i max_chars muszą być liczbami całkowitymi.", 400) from None
    return min_chars, max_chars


def post_voice(handler, path: str, clipboard_mod=None) -> bool:
    """Handle voice barge-in, Wayland dictation, and sentence-chunk TTS POST endpoints."""
    if path == "/voice/barge-in":
        handler.read_empty_body()
        gen = wayland_voice.BARGE_IN.interrupt()
        handler.send_json(200, {"ok": True, "interrupted": True, "generation": gen})
        return True

    if path == "/voice/dictate-wayland":
        body = handler.read_json_body() or {}
        text = str(body.get("text") or "").strip()
        if not text:
            raise AppError("INVALID_DICTATION", "Wymagany niepusty tekst do podyktowania.", 400)
        res = dictate_to_desktop(text, clipboard_mod=clipboard_mod)
        handler.send_json(200, {"ok": True, **res})
        return True

    if path == "/tts/chunks":
        body = handler.read_json_body() or {}
        text = str(body.get("text") or "")
        min_chars, max_chars = _chunk_bounds(body)
        chunker = wayland_voice.SentenceStreamChunker(min_chars=min_chars, max_chars=max_chars)
        chunks = chunker.push(text) + chunker.flush()
        handler.send_json(200, {
            "ok": True,
            "chunks": chunks,
            "count": len(chunks),
            "generation": wayland_voice.BARGE_IN.begin_utterance(),
        })
        return True

    return False
