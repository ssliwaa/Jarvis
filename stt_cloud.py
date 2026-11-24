"""Cloud speech-to-text for Jarvis: Groq's whisper-large-v3-turbo.

The local whisper.cpp build (`stt.py`) fits a four-core CPU, but the `small`
model hallucinates on Polish and needs its own CPU time per take. A dedicated,
cheap STT service does one job and does it better: whisper-large-v3-turbo
answers a ten-second Polish question in well under a second and its rate is
roughly $0.04 per hour of audio.

Only takes recorded when this module is configured leave the machine: the
server sends the blob here first and falls back to the silent local engine
when the key is missing, the network is down or the provider rejects the
request. `JARVIS_GROQ_API_KEY` wins over a `GROQ_API_KEY=` line in the shared
`~/.hermes/.env`.
"""

from __future__ import annotations

import os
import re
import threading
import time
from pathlib import Path

import httpx2

import stt

_ORIG_HTTPX_POST = httpx2.post
_HTTP_LOCK = threading.Lock()
_HTTP_CLIENT = None


def _client():
    global _HTTP_CLIENT
    with _HTTP_LOCK:
        if _HTTP_CLIENT is None:
            _HTTP_CLIENT = httpx2.Client(timeout=TIMEOUT)
        return _HTTP_CLIENT

URL = "https://api.groq.com/openai/v1/audio/transcriptions"
# The non-turbo model is the deliberate choice: the same noise take that
# whisper-large-v3-turbo transcribed into a hallucinated "Zobaczcie." comes
# back from large-v3 as " ..." — the LPU latency difference is negligible
# while the rate (~$0.11/h) stays far below any chat model call.
MODEL = "whisper-large-v3"
# Enough for a 60 s take over a slow link; the request itself is tiny.
TIMEOUT = 45.0
MAX_BYTES = 25 * 1024 * 1024  # Groq's request ceiling, above stt's own 12 MB.
# whisper marks takes whose segments report no_speech_prob at/above this as
# noise, not speech; OpenAI's own docs line sits at 0.6+ and the docs group
# 0.7+ with "not speech". 0.65 keeps a small margin for accented speech while
# cutting the confident-looking noise segments (a lifted tone scored 0.71).
_NO_SPEECH_LIMIT = 0.65
# whisper's own confidence for a segment: live speech usually reports
# avg_logprob well above -1.0, while a token the model invented from room
# noise sits far below. Missing fields mean "no verdict", which passes.
_LOGPROB_LIMIT = -1.0
# A compression_ratio above ~2.6 marks the repeated-token yarn hallucinations
# produce on steady noise ("the, the, the, the").
_COMPRESSION_LIMIT = 2.6
# One letter is trivially guessable ("Dziękuję" from a fat-puff); real speech
# segments carry more than one.
_MIN_LETTERS = 2

# Whisper's best-documented failure mode: on non-speech audio it "says" one of
# a handful of politeness formulas with excellent per-segment confidence. A
# lifted sub-dither tone returned 'Dziękuję.' with no_speech 0.71 and
# avg_logprob -0.18 — no probability gate catches that. The vocabulary is
# fixed, so the guard is lexical instead: if every word of the final
# transcript is one of these formulas, the transcript is noise-mold, not
# speech. A take that contained real content words always survives, because
# the gate needs a 100%-formula transcript.
_FORMULA_WORDS = stt._FORMULA_WORDS
_CREDIT_MOLD = stt._CREDIT_MOLD


def _all_formula_words(text: str) -> bool:
    tokens = re.findall(r"\w+", str(text or "").casefold(), re.UNICODE)
    return bool(tokens) and all(token in _FORMULA_WORDS for token in tokens)

_DEFAULT_MIME = "audio/webm"  # fallback body type for the upload


class CloudSTTError(Exception):
    """The cloud transcriber refused or failed; the caller falls back locally."""

    def __init__(self, message: str, status_code: int = 0):
        self.status_code = int(status_code or 0)
        super().__init__(message)


def _env_file_key(path: Path) -> str:
    try:
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.startswith("GROQ_API_KEY="):
                value = line.split("=", 1)[1].strip().strip('"').strip("'")
                if value:
                    return value
    except OSError:
        pass
    return ""


def api_key() -> str:
    key = os.environ.get("JARVIS_GROQ_API_KEY", "").strip()
    if key:
        return key
    key = os.environ.get("GROQ_API_KEY", "").strip()
    if key:
        return key
    hermes_home = os.environ.get("HERMES_HOME", "").strip()
    candidates = [Path.home() / ".hermes/.env"]
    if hermes_home:
        candidates.append(Path(hermes_home).expanduser() / ".env")
    for candidate in candidates:
        value = _env_file_key(candidate)
        if value:
            return value
    return ""


def available() -> bool:
    """True when a key exists; network reachability is checked on use."""
    return bool(api_key())


def status() -> dict:
    return {
        "engine": f"groq/{MODEL}",
        "model": MODEL,
        "available": available(),
    }


def _filename(content_type: str) -> str:
    mime = str(content_type or "").split(";", 1)[0].strip().lower()
    if mime in ("audio/x-wav", "audio/wave"):
        return "take.wav"
    if mime in ("audio/mpeg", "audio/mp3"):
        return "take.mp3"
    if mime == "audio/ogg":
        return "take.ogg"
    if mime in ("audio/mp4", "audio/m4a", "audio/x-m4a"):
        return "take.m4a"
    if mime == "audio/flac":
        return "take.flac"
    return "take.webm"


def _has_word(text: str) -> bool:
    return any(character.isalnum() for character in text)


def _letters(text: str) -> int:
    return sum(1 for character in text if character.isalpha())


def _drop_hallucinations(payload: dict) -> str:
    """Keep only segments whisper itself believes are speech.

    On background noise the turbo model returns one plausible token ("Dziękuję",
    "Zobaczcie.") inside a segment whose no_speech_prob is near 1. Dropping
    those segments turns the hallucination back into "heard nothing", which
    the voice UI already reports with the measured level instead of sending a
    fake answer to the brain. large-v3 answers pure noise with lone
    punctuation (" ..."), which is stripped at the end the same way.
    """
    text = ""
    segments = payload.get("segments") if isinstance(payload, dict) else None
    if isinstance(segments, list) and segments:
        kept = []
        for segment in segments:
            if not isinstance(segment, dict):
                continue

            def _number(field, fallback=0.0):
                try:
                    return float(segment.get(field) or fallback)
                except (TypeError, ValueError):
                    return fallback

            piece = str(segment.get("text") or "").strip()
            # Three independent verdicts: the no-speech gate (did the model
            # hear anything at all), its confidence in the words, and whether
            # the text is a stutter loop of the same token. A segment needs to
            # clear all three before one plausible word from room noise
            # reaches the brain.
            if not piece or not _letters(piece) >= _MIN_LETTERS:
                continue
            if _number("no_speech_prob") >= _NO_SPEECH_LIMIT:
                continue
            if _number("avg_logprob") < _LOGPROB_LIMIT:
                continue
            if _number("compression_ratio") > _COMPRESSION_LIMIT:
                continue
            kept.append(piece)
        text = " ".join(kept)
    else:
        text = str((payload or {}).get("text") or "")
    text = text.strip()
    if _all_formula_words(text) or _CREDIT_MOLD.fullmatch(text):
        # The whole answer is a politeness/subtitle formula: Whisper's noise
        # mold on non-speech audio.
        return ""
    return text if _has_word(text) else ""


def transcribe(data: bytes, language: str = "pl",
               timeout: float = TIMEOUT, content_type: str = "") -> dict:
    """Send a recorded blob to Groq and return stt.transcribe-shaped text.

    Raises CloudSTTError with a readable reason; the server falls back to the
    local engine on any of them.
    """
    if not data:
        raise CloudSTTError("The recording was empty")
    if len(data) > MAX_BYTES:
        raise CloudSTTError("The recording is too large for the cloud service")
    if not available():
        raise CloudSTTError("No cloud transcriber key is configured")
    mime = str(content_type or "").split(";", 1)[0].strip().lower()
    started = time.monotonic()
    try:
        post_fn = (httpx2.post if httpx2.post is not _ORIG_HTTPX_POST
                   else _client().post)
        response = post_fn(
            URL,
            headers={"Authorization": "Bearer " + api_key()},
            # Whisper's language field wants a bare ISO-639-1 code.
            # verbose_json exposes whisper's per-segment no_speech probability,
            # which is the cheapest reliable hallucination guard: noise takes
            # come back as one plausible word ("Dziękuję") wrapped in segments
            # where the model itself says no speech was present.
            data={"model": MODEL, "language": str(language or "").split("-")[0],
                  "response_format": "verbose_json", "temperature": "0"},
            files={"file": (_filename(mime), data, mime or _DEFAULT_MIME)},
            timeout=max(5.0, min(float(timeout or TIMEOUT), 120.0)),
        )
    except Exception as error:
        raise CloudSTTError(
            f"Could not reach the cloud transcriber: {type(error).__name__}.") from None
    seconds = round(time.monotonic() - started, 2)
    if response.status_code >= 400:
        body = str(getattr(response, "text", "") or "")[:2000]
        try:
            detail = response.json().get("error", {})
            body = str(detail.get("message") or body)
        except (ValueError, AttributeError):
            pass
        hint = ""
        if response.status_code == 401:
            hint = " — the JARVIS_GROQ_API_KEY was rejected"
        elif response.status_code == 429:
            hint = " — the cloud service rate limit is reached"
        raise CloudSTTError(f"Cloud transcription failed (HTTP {response.status_code}) "
                            f"— {body}{hint}", response.status_code)
    try:
        payload = response.json()
    except ValueError:
        raise CloudSTTError("The cloud transcriber returned an invalid response.") from None
    if not isinstance(payload, dict):
        payload = {}
    text = _drop_hallucinations(payload)
    return {"text": text, "language": str(language or "").split("-")[0],
            "engine": f"groq/{MODEL}", "seconds": seconds}


if __name__ == "__main__":
    import sys
    blob = Path(sys.argv[1]).read_bytes() if len(sys.argv) > 1 else b""
    print(status())
    print(transcribe(blob, content_type="audio/webm"))
