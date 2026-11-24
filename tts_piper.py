"""Piper neural text-to-speech bridge (local, fast CPU inference).

Piper runs locally via ONNX Runtime without network access.
Provides the authentic J.A.R.V.I.S. voice (Paul Bettany) with sub-200ms latency on CPU.
"""
from __future__ import annotations

import io
import os
import re
import threading
import wave
from collections import OrderedDict
from pathlib import Path

DEFAULT_VOICE = "en_GB-jarvis-medium"
MAX_CHARS = 4000
MAX_AUDIO_BYTES = 8 * 1024 * 1024
CACHE_MAX_ENTRIES = 64
CACHE_MAX_TEXT_CHARS = 240

# Tuned synthesis parameters to eliminate distortion, raspiness and clipping:
# - volume=0.82: gives ~2 dB headroom to prevent 16-bit digital clipping (peak 26213 vs 32767).
# - noise_scale=0.333: halves latent noise, eliminating metallic buzz and raspiness on phonemes.
# - length_scale=1.0: restores crisp, natural British cadence (replaces sluggish 1.15 default).
SYNTHESIS_VOLUME = 0.82
SYNTHESIS_NOISE_SCALE = 0.333
SYNTHESIS_LENGTH_SCALE = 1.0
SYNTHESIS_NOISE_W = 0.8

DISTILLED_MODEL_PATH = Path(os.environ.get(
    "JARVIS_PIPER_DISTILLED_MODEL",
    Path.home() / ".jarvis-tools/models/piper/en/en_GB/jarvis/distilled/jarvis-distilled.onnx"
))
MEDIUM_MODEL_PATH = Path(os.environ.get(
    "JARVIS_PIPER_MODEL",
    Path.home() / ".jarvis-tools/models/piper/en/en_GB/jarvis/medium/jarvis-medium.onnx"
))

MODEL_PATH = DISTILLED_MODEL_PATH if DISTILLED_MODEL_PATH.is_file() else MEDIUM_MODEL_PATH
DEFAULT_VOICE = "en_GB-jarvis-distilled" if DISTILLED_MODEL_PATH.is_file() else "en_GB-jarvis-medium"

VOICES = (
    {"id": "en_GB-jarvis-distilled", "label": "J.A.R.V.I.S. — F5-TTS Distilled (Clear & Natural)", "lang": "en-GB", "gender": "Male"},
    {"id": "en_GB-jarvis-medium", "label": "J.A.R.V.I.S. — Paul Bettany (Movie rip)", "lang": "en-GB", "gender": "Male"},
)
VOICE_IDS = frozenset(item["id"] for item in VOICES)
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

_AUDIO_CACHE: OrderedDict[tuple[str, str], bytes] = OrderedDict()
_CACHE_LOCK = threading.Lock()
_VOICE_LOCK = threading.Lock()
_VOICE_INSTANCES: dict[str, object] = {}


class TTSError(Exception):
    """A safe, public failure."""

    def __init__(self, message: str, status: int = 502):
        super().__init__(message)
        self.status = status


def available() -> bool:
    """Return True if piper is installed and at least one JARVIS voice model is present."""
    if not DISTILLED_MODEL_PATH.is_file() and not MEDIUM_MODEL_PATH.is_file():
        return False
    try:
        import piper  # noqa: F401
        return True
    except Exception:
        return False


def voices() -> list[dict]:
    return [dict(item) for item in VOICES]


def _clean_text(text: str) -> str:
    if not isinstance(text, str):
        raise TTSError("The text to speak must be a string.", 400)
    text = text.strip()
    if not 1 <= len(text) <= MAX_CHARS:
        raise TTSError(f"Text to speak must be between 1 and {MAX_CHARS} characters.", 400)
    if _CONTROL.search(text):
        raise TTSError("The text to speak contains unsupported control characters.", 400)
    return text


def _get_voice(voice_id: str | None = None):
    target = voice_id or DEFAULT_VOICE
    if target in ("jarvis", "piper:jarvis"):
        target = DEFAULT_VOICE
    if target.startswith("piper:"):
        target = target[6:]

    model_file = DISTILLED_MODEL_PATH if ("distilled" in target and DISTILLED_MODEL_PATH.is_file()) else MEDIUM_MODEL_PATH
    if not model_file.is_file():
        model_file = MODEL_PATH

    with _VOICE_LOCK:
        if target not in _VOICE_INSTANCES:
            if not model_file.is_file():
                raise TTSError("Piper voice model file is missing.", 503)
            try:
                from piper.voice import PiperVoice
                _VOICE_INSTANCES[target] = PiperVoice.load(str(model_file))
            except Exception as error:
                raise TTSError(f"Failed to load Piper voice model: {error}", 502)
        return _VOICE_INSTANCES[target]


def clear_cache():
    with _CACHE_LOCK:
        _AUDIO_CACHE.clear()


def synthesize(text: str, voice: str | None = None) -> bytes:
    """Synthesize text using Piper into a valid WAV byte string."""
    text = _clean_text(text)
    target_voice = voice or DEFAULT_VOICE
    if target_voice.startswith("piper:"):
        target_voice = target_voice[6:]
    if target_voice not in VOICE_IDS and target_voice not in ("jarvis", DEFAULT_VOICE):
        raise TTSError(f"Unknown Piper voice: {voice}", 400)

    cache_key = (target_voice, text) if len(text) <= CACHE_MAX_TEXT_CHARS else None
    if cache_key is not None:
        with _CACHE_LOCK:
            cached = _AUDIO_CACHE.get(cache_key)
            if cached is not None:
                _AUDIO_CACHE.move_to_end(cache_key)
                return cached

    piper_voice = _get_voice(target_voice)
    try:
        from piper.config import SynthesisConfig
        cfg = SynthesisConfig(
            volume=SYNTHESIS_VOLUME,
            noise_scale=SYNTHESIS_NOISE_SCALE,
            length_scale=SYNTHESIS_LENGTH_SCALE,
            noise_w_scale=SYNTHESIS_NOISE_W,
            normalize_audio=True,
        )
        chunks = list(piper_voice.synthesize(text, syn_config=cfg))
    except Exception as error:
        raise TTSError(f"Piper synthesis error: {error}", 502)

    if not chunks:
        raise TTSError("Piper returned no audio chunks.", 502)

    buf = io.BytesIO()
    try:
        with wave.open(buf, "wb") as wav_file:
            wav_file.setnchannels(chunks[0].sample_channels)
            wav_file.setsampwidth(chunks[0].sample_width)
            wav_file.setframerate(chunks[0].sample_rate)
            for c in chunks:
                wav_file.writeframes(c.audio_int16_bytes)
        audio = buf.getvalue()
    except Exception as error:
        raise TTSError(f"Failed to encode WAV audio: {error}", 502)

    if len(audio) > MAX_AUDIO_BYTES:
        raise TTSError("The synthesized audio exceeded the size limit.", 502)

    if cache_key is not None and audio:
        with _CACHE_LOCK:
            _AUDIO_CACHE[cache_key] = audio
            _AUDIO_CACHE.move_to_end(cache_key)
            while len(_AUDIO_CACHE) > CACHE_MAX_ENTRIES:
                _AUDIO_CACHE.popitem(last=False)

    return audio


def status() -> dict:
    return {
        "engine": "piper",
        "available": available(),
        "model": MODEL_PATH.name,
        "default_voice": DEFAULT_VOICE,
        "voices": voices(),
        "max_chars": MAX_CHARS,
    }
