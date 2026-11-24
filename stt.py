"""Local speech-to-text for Jarvis.

Electron ships Chromium without Google's speech backend, so `webkitSpeechRecognition`
exists but every session dies with a `network` error. This module gives the console a
real, offline path: the browser records Opus/WebM with MediaRecorder, the server
converts it to 16 kHz mono WAV with ffmpeg and runs whisper.cpp.

Nothing leaves the machine and there is no API key. The binary and the model are
looked up under ~/.jarvis-tools and can be overridden with JARVIS_WHISPER_BIN and
JARVIS_WHISPER_MODEL.
"""

from __future__ import annotations

import array
import math
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import wave
from pathlib import Path

TOOLS = Path.home() / ".jarvis-tools"          # whisper.cpp binary and model
HERMES_TOOLS = Path.home() / ".hermes" / "tools"  # shared ffmpeg build
BIN = Path(os.environ.get("JARVIS_WHISPER_BIN", TOOLS / "src" / "whisper.cpp-1.9.5" / "build" / "bin" / "whisper-cli"))
def _default_model() -> Path:
    # Accuracy first: `small` understands real, quiet Polish speech noticeably
    # better than `base` (it also stops the base model's repeated-sentence
    # hallucination) at roughly three times the CPU time. Use it whenever the
    # installer has fetched it; base remains the fast default for old installs.
    models = TOOLS / "models"
    for name in ("ggml-small-q5_1.bin", "ggml-small.bin",
                 "ggml-base-q5_1.bin", "ggml-base.bin"):
        candidate = models / name
        if candidate.is_file():
            return candidate
    return models / "ggml-base-q5_1.bin"


MODEL = Path(os.environ.get("JARVIS_WHISPER_MODEL", _default_model()))


def _find_ffmpeg() -> Path:
    override = os.environ.get("JARVIS_FFMPEG")
    if override:
        return Path(override)
    bundled = sorted(HERMES_TOOLS.glob("ffmpeg-*/bin/ffmpeg"))
    if bundled:
        return bundled[-1]
    found = shutil.which("ffmpeg")
    return Path(found) if found else HERMES_TOOLS / "ffmpeg" / "bin" / "ffmpeg"


def _env_number(name: str, default, cast):
    """A malformed tuning variable must never take the whole server down."""
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        value = cast(raw)
    except (TypeError, ValueError):
        return default
    return value if value > 0 else default


FFMPEG = _find_ffmpeg()
MAX_SECONDS = min(_env_number("JARVIS_STT_MAX_SECONDS", 60.0, float), 300.0)
# The console keeps a WebGL graph running on the same four cores; asking for all
# of them made whisper slower (5.4 s vs 4.3 s on the same clip).
THREADS = min(_env_number("JARVIS_STT_THREADS",
                          max(1, min(3, (os.cpu_count() or 2) - 1)), int), 16)
MAX_BYTES = 12 * 1024 * 1024

# A take that never rises above this peak (dBFS) is microphone silence, not
# speech: whisper.cpp answers silence with an empty string, which used to look
# like a recognition failure. A quiet but real take is lifted after the leading
# and trailing silence is trimmed.
# The bar is a *rescue floor*, not a usability bar: the shaper lifts any take
# up to +48 dB, so a -66 dBFS distant laptop-mic voice lands around -18 dBFS
# and is transcribed normally. The floor sits at -68 dBFS because at that level
# the lift still lands above the old -30 dBFS bar; anything quieter than -68
# has no signal shaped like speech (it is sub-dither room tone or a muted/wrong
# mic) and gets the clear diagnostic instead of a hallucination from amplified
# noise.
MIN_AUDIO_SECONDS = 0.1
SILENCE_PEAK_DBFS = -68.0
TRIM_THRESHOLD_DBFS = -45.0
TRIM_PAD_SECONDS = 0.15
QUIET_PEAK_DBFS = -12.0
TARGET_PEAK_DBFS = -3.0
MAX_GAIN_DB = 48.0

# whisper.cpp always runs the encoder over a padded 30-second window, even for a
# three-second question. `-ac` narrows that window to the speech that is actually
# present. Measured on this host (i3-8100T, base-q5_1): a 3.2 s question drops
# from 2.01 s to about 0.7 s. Longer clips gain less because the safe bucket
# keeps a wide margin (a 14.9 s clip stays near 2.2 s); a tighter 768-frame
# window reaches 1.9 s but leaves only half a second of margin. Too small a
# window clips the last words, so a degenerate result is retried with the full
# 30-second context.
AUDIO_CTX_BUCKETS = ((5.0, 256), (9.0, 512), (12.0, 768), (18.0, 1024), (24.0, 1280))
AUDIO_CTX_ENV = os.environ.get("JARVIS_STT_AUDIO_CTX", "auto").strip().lower()
_LANGUAGE_RE = re.compile(r"[a-z]{2,3}")

_lock = threading.Lock()
_last_lock = threading.Lock()
_last = {"text": "", "seconds": 0.0, "at": 0.0, "language": "",
         "audio_seconds": 0.0, "level_dbfs": None, "engine": ""}


def _probe() -> dict:
    return {
        "binary": str(BIN),
        "binary_present": BIN.is_file() and os.access(BIN, os.X_OK),
        "model": str(MODEL),
        "model_present": MODEL.is_file(),
        "ffmpeg": str(FFMPEG),
        "ffmpeg_present": FFMPEG.is_file() and os.access(FFMPEG, os.X_OK),
    }


def available() -> bool:
    probe = _probe()
    return probe["binary_present"] and probe["model_present"] and probe["ffmpeg_present"]


def status() -> dict:
    probe = _probe()
    with _last_lock:
        last_snapshot = dict(_last)
    probe.update({
        "engine": "whisper.cpp",
        "available": available(),
        "model_size": MODEL.stat().st_size if MODEL.is_file() else 0,
        "threads": THREADS,
        "busy": _lock.locked(),
        "last": last_snapshot,
        "file_size_limit": MAX_BYTES,
    })
    return probe


def audio_context_for(seconds: float) -> int:
    """Encoder frames to keep; 0 means Whisper's full 30-second window."""
    if AUDIO_CTX_ENV not in ("", "auto"):
        try:
            return max(0, int(AUDIO_CTX_ENV))
        except ValueError:
            pass  # A malformed override falls back to the measured buckets.
    if seconds <= 0:
        return 0
    for limit, frames in AUDIO_CTX_BUCKETS:
        if seconds <= limit:
            return frames
    return 0


def normalise_language(value: str | None, default: str = "pl") -> str:
    """Accept "pl-PL", "en_GB" or "en"; reject anything that is not a code."""
    raw = str(value or "").strip().lower().replace("_", "-")
    if not raw:
        return default
    base = raw.split("-", 1)[0]
    if not _LANGUAGE_RE.fullmatch(base):
        raise ValueError("language must be a two- or three-letter code")
    return base


def _wav_seconds(wav: Path) -> float:
    try:
        return max(0.0, (wav.stat().st_size - 44) / 32000.0)
    except OSError:
        return 0.0


def _dbfs(amplitude: float) -> float:
    """Peak or RMS level in dBFS; digital silence is negative infinity."""
    return 20.0 * math.log10(amplitude) if amplitude > 0 else float("-inf")


def _wav_samples(wav: Path):
    with wave.open(str(wav), "rb") as reader:
        params = reader.getparams()
        frames = reader.readframes(reader.getnframes())
    if params.sampwidth != 2 or params.nchannels != 1:
        return params, None
    samples = array.array("h")
    samples.frombytes(frames)
    if sys.byteorder == "big":
        samples.byteswap()
    return params, samples


def _shape_audio(wav: Path) -> dict:
    """Trim dead air, lift a quiet take, and describe what Whisper will hear.

    The returned peak and RMS describe the input, before any gain, so the UI can
    say why a take was rejected. A silent file is left untouched; the caller
    turns it into a readable error instead of an empty transcript.
    """
    params, samples = _wav_samples(wav)
    rate = params.framerate or 16000
    duration = len(samples) / rate if samples is not None else _wav_seconds(wav)
    stats = {"audio_seconds": round(duration, 2),
             "peak_dbfs": None, "rms_dbfs": None, "gain_db": 0.0}
    if samples is None or not len(samples):
        return stats

    # The whole-file peak decides both the lift and how eagerly dead air is
    # trimmed. For a quiet take the trim threshold moves down with the signal so
    # the first and last syllables are not cut off before the gain is applied.
    whole_peak = max((abs(value) for value in samples), default=0)
    whole_peak_dbfs = _dbfs(whole_peak / 32768.0)
    if whole_peak == 0:
        stats["peak_dbfs"] = float("-inf")
        stats["rms_dbfs"] = float("-inf")
        return stats
    trim_dbfs = min(TRIM_THRESHOLD_DBFS, whole_peak_dbfs - 30.0)
    threshold = max(1, int(32768 * (10 ** (trim_dbfs / 20))))
    first = next(index for index, value in enumerate(samples)
                 if abs(value) >= threshold)
    last = next(index for index in range(len(samples) - 1, -1, -1)
                if abs(samples[index]) >= threshold)
    padding = int(rate * TRIM_PAD_SECONDS)
    start = max(0, first - padding)
    end = min(len(samples), last + padding + 1)
    trimmed = samples[start:end]

    peak = 0
    total = 0
    for value in trimmed:
        magnitude = -value if value < 0 else value
        if magnitude > peak:
            peak = magnitude
        total += value * value
    peak_dbfs = _dbfs(peak / 32768.0)
    stats.update({"audio_seconds": round(len(trimmed) / rate, 2),
                  "peak_dbfs": peak_dbfs,
                  "rms_dbfs": _dbfs(math.sqrt(total / len(trimmed)) / 32768.0)})

    gain = 1.0
    if math.isfinite(peak_dbfs) and peak_dbfs < QUIET_PEAK_DBFS:
        gain = min(10 ** ((TARGET_PEAK_DBFS - peak_dbfs) / 20.0),
                   10 ** (MAX_GAIN_DB / 20.0))
    if gain <= 1.01 and start == 0 and end == len(samples):
        return stats
    if gain > 1.01:
        for index, value in enumerate(trimmed):
            boosted = int(value * gain)
            trimmed[index] = 32767 if boosted > 32767 else -32768 if boosted < -32768 else boosted
        stats["gain_db"] = round(_dbfs(gain), 1)
    payload = array.array("h", trimmed)
    if sys.byteorder == "big":
        payload.byteswap()  # WAV stores little-endian samples.
    with wave.open(str(wav), "wb") as writer:
        writer.setnchannels(1)
        writer.setsampwidth(2)
        writer.setframerate(rate)
        writer.writeframes(payload.tobytes())
    return stats


_SENTENCE_SPLIT = re.compile(r"(?<=[.!?])\s+")
_NOISE_ONLY = re.compile(r"^(?:\[[^\]]{1,40}\]\s*)+$")

# Whisper's noise mold on non-speech audio is a short politeness formula with
# great confidence ("Dziękuję.", "Zobaczcie.", "Proszę państwa") — stt_cloud
# documents the same list. A transcript composed only of these tokens is
# noise, not speech; real content words always survive the whole-phrase gate.
_FORMULA_WORDS = frozenset({
    "dziękuję", "dziekuje", "dziękuje", "dzięki", "dzieki", "za", "zobaczcie", "widzenia",
    "oglądanie", "ogladanie", "oglądania", "ogladania", "subskrybuj", "subskrypcja",
    "zobaczenia", "razie", "dobranoc", "do", "zapraszam", "kanale", "kanału", "kanalu",
    "film", "filmu",
    "państwo", "państwa", "panstwo", "panstwa", "wszystkiego", "najlepszego",
    "cześć", "czesc", "witaj", "witajcie", "witamy", "proszę", "prosze",
    "dobry", "dzień", "dzien", "dobrym", "hej", "halo", "aha", "hm", "hmm",
    "mhm", "ma", "no", "okej", "hah", "hehe", "działa", "check", "testing", "papapa",
    "thanks", "thank", "you", "watching", "for", "bye", "subtitles", "subscribe",
    "um", "uh", "okay", "amin", "ameen",
})

# The subtitle-credit hallucination ("Napisy by Jacek Makarewicz") escaped the
# token set because credits carry names. stt_cloud documents the reasoning: a
# whole transcript that starts with the subtitle word and adds credit filler
# only, is noise. Real speech mentioning subtitles never OPENS with the word.
_CREDIT_MOLD = re.compile(
    r"(?:napisy|subtitles?)\s*(?::|—|-|–|\[|(?:by|na|poprzez|przez|od)\b)[^?!.]{0,80}"
    r"|\bsubtitles?\b[^?!.]{0,80}\bamara(?:\.org)?\b[^?!.]{0,40}"
    r"|\bamara\.?org\b[^?!.]{0,60}",
    re.I | re.UNICODE)


def _dedupe(text: str) -> str:
    """Collapse the repeated sentence Whisper emits on short, quiet clips."""
    parts = [part.strip() for part in _SENTENCE_SPLIT.split(text) if part.strip()]
    if len(parts) < 2:
        return text

    def key(value: str) -> str:
        return re.sub(r"\W+", " ", value.casefold()).strip()

    kept = [parts[0]]
    for part in parts[1:]:
        current = key(part)
        if len(current.split()) >= 3 and current == key(kept[-1]):
            continue
        kept.append(part)
    return " ".join(kept)


def _clean(text: str) -> str:
    text = re.sub(r"\[\d\d:\d\d:\d\d\.\d\d\d --> \d\d:\d\d:\d\d\.\d\d\d\]\s*", "", text)
    text = re.sub(r"\s+", " ", text).strip()
    # Whisper marks non-speech audio with bracketed tags. A take made only of
    # them ("[Muzyka] [Muzyka]") is noise, not an answer.
    if _NOISE_ONLY.fullmatch(text):
        return ""
    text = _dedupe(re.sub(r"^\[[^\]]{1,40}\]$", "", text).strip())
    tokens = re.findall(r"\w+", text.casefold(), re.UNICODE)
    if tokens and all(token in _FORMULA_WORDS for token in tokens):
        return ""
    if _CREDIT_MOLD.fullmatch(text):
        return ""
    return text


def _looks_degenerate(text: str) -> bool:
    """Catch the repetition/truncation failure a too-small encoder window causes."""
    words = re.findall(r"\w+", text.casefold())
    if len(words) < 9:
        return False
    counts: dict[str, int] = {}
    for index in range(len(words) - 2):
        gram = " ".join(words[index:index + 3])
        counts[gram] = counts.get(gram, 0) + 1
    return max(counts.values(), default=0) >= 3


def _command(wav: Path, language: str, audio_ctx: int) -> list[str]:
    command = [
        str(BIN), "-m", str(MODEL), "-f", str(wav),
        "-l", language, "-t", str(THREADS), "-nt", "-np",
    ]
    if audio_ctx > 0:
        command.extend(["-ac", str(audio_ctx)])
    return command


def _run_whisper(wav: Path, language: str, audio_ctx: int, deadline: float) -> tuple[str, int]:
    try:
        result = subprocess.run(_command(wav, language, audio_ctx), capture_output=True,
                                timeout=max(1.0, deadline - time.monotonic()), check=False)
    except subprocess.TimeoutExpired:
        raise RuntimeError("Transcription timed out") from None
    except OSError as error:
        raise RuntimeError(f"whisper.cpp could not start: {error.strerror or error}") from None
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", "replace").strip().splitlines()
        raise RuntimeError(detail[-1] if detail else "whisper.cpp failed")
    text = _clean(result.stdout.decode("utf-8", "replace"))
    if audio_ctx > 0 and _looks_degenerate(text):
        try:
            again = subprocess.run(_command(wav, language, 0), capture_output=True,
                                   timeout=max(1.0, deadline - time.monotonic()), check=False)
        except (subprocess.TimeoutExpired, OSError):
            return text, audio_ctx
        if again.returncode == 0:
            retry_text = _clean(again.stdout.decode("utf-8", "replace"))
            if retry_text and not _looks_degenerate(retry_text):
                return retry_text, 0
    return text, audio_ctx


def _convert(source: Path, target: Path, timeout: float = 60.0) -> None:
    command = [
        str(FFMPEG), "-nostdin", "-hide_banner", "-loglevel", "error", "-y",
        "-i", str(source),
        "-ac", "1", "-ar", "16000", "-c:a", "pcm_s16le",
        str(target),
    ]
    try:
        result = subprocess.run(command, capture_output=True,
                                timeout=max(1.0, min(float(timeout), 60.0)), check=False)
    except subprocess.TimeoutExpired:
        raise RuntimeError("The recording could not be decoded in time") from None
    except OSError as error:
        raise RuntimeError(f"ffmpeg could not start: {error.strerror or error}") from None
    if result.returncode != 0 or not target.is_file() or target.stat().st_size <= 44:
        message = result.stderr.decode("utf-8", "replace").strip().splitlines()
        raise RuntimeError(message[-1] if message else "ffmpeg could not decode the recording")


def _prepare_in_folder(data: bytes, folder: Path, deadline: float | None = None) -> tuple[Path, dict]:
    if not data:
        raise RuntimeError("The recording was empty")
    if len(data) > MAX_BYTES:
        raise RuntimeError("The recording is too large")
    raw = folder / "input.bin"
    wav = folder / "input.wav"
    raw.write_bytes(data)
    remaining = (deadline - time.monotonic()) if deadline is not None else 60.0
    if remaining <= 0:
        raise RuntimeError("Transcription timed out")
    _convert(raw, wav, remaining)
    stats = _shape_audio(wav)
    if stats["audio_seconds"] < MIN_AUDIO_SECONDS:
        raise RuntimeError("The recording was too short; hold the key while you speak")
    if stats["peak_dbfs"] is None or stats["peak_dbfs"] < SILENCE_PEAK_DBFS:
        peak_val = stats["peak_dbfs"]
        if peak_val is not None and math.isfinite(peak_val):
            level_str = f"{round(peak_val, 1)} dBFS"
            raise RuntimeError(
                f"Microphone signal too weak ({level_str}) — speak closer to the mic, "
                "raise its volume in system settings, or check that it is not muted"
            )
        raise RuntimeError(
            "The recording was silent — check the microphone and its mute button"
        )
    return wav, stats


def prepare_take(data: bytes, deadline: float | None = None) -> tuple[bytes, dict]:
    """Decode, trim dead air and lift a quiet take; guard before recognition.

    Returns the shaped 16 kHz mono WAV bytes with the level statistics. The
    user-facing errors are identical to the local engine's, so the cloud call
    can reuse this gate and never spend upload bandwidth or API quota on a
    recording that would transcribe into hallucinatory noise.
    """
    if not data:
        raise RuntimeError("The recording was empty")
    if len(data) > MAX_BYTES:
        raise RuntimeError("The recording is too large")
    with tempfile.TemporaryDirectory(prefix="jarvis-stt-") as folder:
        wav, stats = _prepare_in_folder(data, Path(folder), deadline)
        return wav.read_bytes(), stats


def note_result(result: dict, stats: dict) -> None:
    """Remember a take the local engine did not run (the cloud lane)."""
    peak = stats.get("peak_dbfs")
    with _last_lock:
        _last.update({"engine": str(result.get("engine") or ""), "text": str(result.get("text") or ""),
                      "language": str(result.get("language") or ""),
                      "seconds": float(result.get("seconds") or 0.0),
                      "at": time.time(),
                      "audio_seconds": stats.get("audio_seconds", 0.0),
                      "level_dbfs": round(peak, 1) if isinstance(peak, float) and math.isfinite(peak) else None})


def transcribe(data: bytes, language: str = "pl", timeout: float | None = None) -> dict:
    """Turn a recorded blob into text. Raises RuntimeError with a readable message."""
    if not data:
        raise RuntimeError("The recording was empty")
    if len(data) > MAX_BYTES:
        raise RuntimeError("The recording is too large")
    if not available():
        raise RuntimeError("Local transcription is not installed")

    try:
        language = normalise_language(language)
    except ValueError:
        language = "pl"

    limit = float(timeout or MAX_SECONDS + 30)
    deadline = time.monotonic() + limit
    started = time.monotonic()
    with _lock:
        with tempfile.TemporaryDirectory(prefix="jarvis-stt-") as folder:
            wav, stats = _prepare_in_folder(data, Path(folder), deadline)
            audio_ctx = audio_context_for(stats["audio_seconds"])
            text, audio_ctx = _run_whisper(wav, language, audio_ctx, deadline)
    elapsed = round(time.monotonic() - started, 2)
    peak = stats["peak_dbfs"]
    level = round(peak, 1) if peak is not None and math.isfinite(peak) else None
    with _last_lock:
        _last.update({"engine": "whisper.cpp", "text": text, "seconds": elapsed, "at": time.time(),
                      "language": language,
                      "audio_seconds": stats["audio_seconds"], "level_dbfs": level})
    return {"text": text, "seconds": elapsed, "language": language,
            "engine": "whisper.cpp", "audio_context": audio_ctx,
            "audio_seconds": stats["audio_seconds"], "level_dbfs": level}


if __name__ == "__main__":  # manual probe: python stt.py file.webm
    payload = Path(sys.argv[1]).read_bytes() if len(sys.argv) > 1 else b""
    print(status())
    print(transcribe(payload))
