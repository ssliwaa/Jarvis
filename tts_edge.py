"""Optional Edge TTS bridge.

Edge TTS is Microsoft's free neural speech service. It needs the network and
sends the text being spoken to Microsoft; it never sees the vault or the API
key. Jarvis boots without this module and falls back to the browser voice.
"""
from __future__ import annotations

import asyncio
import re
import threading
from collections import OrderedDict
from importlib.metadata import version as package_version

DEFAULT_VOICE = "en-GB-RyanNeural"
MAX_CHARS = 4000
MAX_AUDIO_BYTES = 4 * 1024 * 1024
TIMEOUT_SECONDS = 45
CACHE_MAX_ENTRIES = 64
CACHE_MAX_TEXT_CHARS = 240
_AUDIO_CACHE: OrderedDict[tuple[str, str], bytes] = OrderedDict()
_CACHE_LOCK = threading.Lock()
_LOOP_LOCK = threading.Lock()
_LOOP: asyncio.AbstractEventLoop | None = None


def _ensure_loop() -> asyncio.AbstractEventLoop:
    global _LOOP
    with _LOOP_LOCK:
        if _LOOP is None or _LOOP.is_closed():
            loop = asyncio.new_event_loop()
            thread = threading.Thread(target=loop.run_forever, name="jarvis-tts-loop", daemon=True)
            thread.start()
            _LOOP = loop
        return _LOOP


def _run_coro(coro, timeout: float):
    loop = _ensure_loop()
    future = asyncio.run_coroutine_threadsafe(coro, loop)
    try:
        return future.result(timeout=timeout)
    except BaseException:
        future.cancel()
        raise

VOICES = (
    {"id": "en-GB-RyanNeural", "label": "Ryan — British male", "lang": "en-GB", "gender": "Male"},
    {"id": "en-GB-ThomasNeural", "label": "Thomas — British male", "lang": "en-GB", "gender": "Male"},
    {"id": "en-GB-SoniaNeural", "label": "Sonia — British female", "lang": "en-GB", "gender": "Female"},
    {"id": "en-GB-LibbyNeural", "label": "Libby — British female", "lang": "en-GB", "gender": "Female"},
    {"id": "pl-PL-MarekNeural", "label": "Marek — Polish male", "lang": "pl-PL", "gender": "Male"},
    {"id": "pl-PL-ZofiaNeural", "label": "Zofia — Polish female", "lang": "pl-PL", "gender": "Female"},
)
VOICE_IDS = frozenset(item["id"] for item in VOICES)
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


class TTSError(Exception):
    """A safe, public failure; no provider response or local path."""

    def __init__(self, message, status=502):
        super().__init__(message)
        self.status = status


def available():
    try:
        import edge_tts  # noqa: F401
        return True
    except Exception:
        return False


def version():
    try:
        return package_version("edge-tts")
    except Exception:
        return None


def voices():
    return [dict(item) for item in VOICES]


def _clean_text(text):
    if not isinstance(text, str):
        raise TTSError("The text to speak must be a string.", 400)
    text = text.strip()
    if not 1 <= len(text) <= MAX_CHARS:
        raise TTSError(f"Text to speak must be between 1 and {MAX_CHARS} characters.", 400)
    if _CONTROL.search(text):
        raise TTSError("The text to speak contains unsupported control characters.", 400)
    return text


def _clean_voice(voice):
    if voice in (None, ""):
        return DEFAULT_VOICE
    if not isinstance(voice, str) or voice not in VOICE_IDS:
        raise TTSError("That Edge voice is not in the approved list.", 400)
    return voice


async def _collect(text, voice):
    import edge_tts

    audio = bytearray()
    async for chunk in edge_tts.Communicate(text, voice).stream():
        if chunk.get("type") == "audio":
            audio.extend(chunk["data"])
            if len(audio) > MAX_AUDIO_BYTES:
                raise TTSError("The synthesized audio exceeded the size limit.")
    if not audio:
        raise TTSError("Edge TTS returned no audio.")
    return bytes(audio)


def clear_cache():
    with _CACHE_LOCK:
        _AUDIO_CACHE.clear()


def synthesize(text, voice=None):
    """Return one MP3. The caller is responsible for the per-request timeout."""
    text = _clean_text(text)
    voice = _clean_voice(voice)
    cache_key = (voice, text) if len(text) <= CACHE_MAX_TEXT_CHARS else None
    if cache_key is not None:
        with _CACHE_LOCK:
            cached = _AUDIO_CACHE.get(cache_key)
            if cached is not None:
                _AUDIO_CACHE.move_to_end(cache_key)
                return cached
    try:
        audio = _run_coro(_collect(text, voice), TIMEOUT_SECONDS)
    except TTSError:
        raise
    except Exception:
        raise TTSError("Edge TTS could not synthesize that sentence; the browser voice can be used instead.") from None
    if cache_key is not None and audio:
        with _CACHE_LOCK:
            _AUDIO_CACHE[cache_key] = audio
            _AUDIO_CACHE.move_to_end(cache_key)
            while len(_AUDIO_CACHE) > CACHE_MAX_ENTRIES:
                _AUDIO_CACHE.popitem(last=False)
    return audio


def status():
    return {
        "engine": "edge-tts",
        "available": available(),
        "version": version(),
        "default_voice": DEFAULT_VOICE,
        "voices": voices(),
        "max_chars": MAX_CHARS,
    }
