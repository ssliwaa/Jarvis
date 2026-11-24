#!/usr/bin/env bash
# Build the offline transcriber used by the microphone in the Electron window.
#
# Electron ships Chromium without Google's speech backend, so `webkitSpeechRecognition`
# fails every session with a `network` error. `viewer/voice.js` records with
# MediaRecorder and posts the blob to `/voice/transcribe`, which runs ffmpeg and
# whisper.cpp locally. This script installs those two pieces under ~/.jarvis-tools.
#
# Re-run it after moving machines or deleting ~/.jarvis-tools. It is idempotent.
# JARVIS_STT_MODEL_SIZE=small fetches the 190 MB model: noticeably better on real
# Polish speech, about three times slower than the 57 MB base model.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="${JARVIS_PROJECT_ROOT:-$(cd "$SCRIPT_DIR/.." && pwd)}"
PROJECT_PYTHON="${JARVIS_PYTHON:-$PROJECT_ROOT/.venv/bin/python}"

VERSION=v1.9.5
TOOLS="$HOME/.jarvis-tools"
SRC="$TOOLS/src"
MODELS="$TOOLS/models"
BUILD_VENV="$TOOLS/venvs/build"
UV="${UV:-$(command -v uv || printf '%s' "$HOME/.hermes/tools/uv-0.12.3-linux-x64/uv")}"
MODEL_SIZE="${JARVIS_STT_MODEL_SIZE:-base}"
case "$MODEL_SIZE" in
  small) MODEL="ggml-small-q5_1.bin"; MODEL_BYTES="190 MB" ;;
  base|"") MODEL="ggml-base-q5_1.bin"; MODEL_BYTES="57 MB" ;;
  *) printf "Unknown JARVIS_STT_MODEL_SIZE='%s'; use base or small.\n" "$MODEL_SIZE" >&2; exit 2 ;;
esac

say() { printf '%s\n' "$*"; }

mkdir -p "$SRC" "$MODELS"

if [ ! -x "$SRC/whisper.cpp-$VERSION/build/bin/whisper-cli" ]; then
  say "Fetching whisper.cpp $VERSION…"
  if [ ! -d "$SRC/whisper.cpp-$VERSION" ]; then
    tmp_archive="$(mktemp "$SRC/.whisper-$VERSION.XXXXXX.tar.gz")"
    trap 'rm -f "$tmp_archive"' EXIT
    curl -fsSL --retry 3 -o "$tmp_archive" \
      "https://github.com/ggml-org/whisper.cpp/archive/refs/tags/$VERSION.tar.gz"
    tar xzf "$tmp_archive" -C "$SRC"
    rm -f "$tmp_archive"
    trap - EXIT
  fi
  if [ ! -x "$BUILD_VENV/bin/cmake" ]; then
    if [ ! -x "$UV" ]; then
      say "uv binary not found at $UV; install uv or set UV=/path/to/uv." >&2
      exit 1
    fi
    say "Installing cmake into $BUILD_VENV…"
    "$UV" venv "$BUILD_VENV" >/dev/null
    "$UV" pip install --python "$BUILD_VENV/bin/python" cmake >/dev/null
  fi
  say "Compiling (a few minutes on four cores)…"
  "$BUILD_VENV/bin/cmake" -S "$SRC/whisper.cpp-$VERSION" -B "$SRC/whisper.cpp-$VERSION/build" \
    -DCMAKE_BUILD_TYPE=Release -DWHISPER_BUILD_TESTS=OFF -DWHISPER_BUILD_EXAMPLES=ON \
    -DWHISPER_BUILD_SERVER=OFF -DGGML_NATIVE=ON >/dev/null
  "$BUILD_VENV/bin/cmake" --build "$SRC/whisper.cpp-$VERSION/build" -j4 >/dev/null
fi

if [ ! -s "$MODELS/$MODEL" ]; then
  say "Downloading $MODEL ($MODEL_BYTES)…"
  part="$MODELS/.$MODEL.part"
  curl -fL --retry 3 -o "$part" \
    "https://huggingface.co/ggerganov/whisper.cpp/resolve/main/$MODEL"
  bytes=$(wc -c < "$part")
  if [ "$bytes" -lt 1000000 ]; then
    say "The model download looks truncated ($bytes bytes); remove $part and retry." >&2
    exit 1
  fi
  mv "$part" "$MODELS/$MODEL"
fi
say "Recognition model: $MODEL (switch with JARVIS_STT_MODEL_SIZE=base|small, then restart Jarvis)."

say "Checking the pipeline…"
if [ ! -x "$PROJECT_PYTHON" ]; then
  PROJECT_PYTHON="$(command -v python3 || true)"
fi
if [ -z "$PROJECT_PYTHON" ]; then
  say "No Python interpreter found to verify stt.py." >&2
  exit 1
fi
PYTHONPATH="$PROJECT_ROOT${PYTHONPATH:+:$PYTHONPATH}" "$PROJECT_PYTHON" - <<'PY'
import stt
status = stt.status()
print({key: status[key] for key in ('available', 'binary', 'model', 'ffmpeg', 'threads')})
raise SystemExit(0 if status['available'] else 1)
PY

say "Done. Restart the Jarvis window and press the microphone."
