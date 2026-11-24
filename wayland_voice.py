"""Wayland-native dictation, <400ms sentence-streaming TTS chunker, barge-in, and DND guard.

Designed for ThinkCentre M720q running GNOME Wayland:
1. `type_text`: tries `wtype` -> `ydotool` (with socket auto-discovery) -> `xdotool` (XWayland),
   always stripping newlines/control chars to prevent accidental command execution.
2. `SentenceStreamChunker`: splits streaming LLM deltas into speakable sentences while
   respecting Polish abbreviations (`np.`, `m.in.`, `dr.`, `ul.`, `ok.`, `tzn.`, `itd.`).
3. `BargeInController`: cancels queued/playing TTS immediately when user starts speaking.
4. `dnd_status`: checks GNOME Do-Not-Disturb (`show-banners == false`) and active mic capture.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import threading
from pathlib import Path

PL_ABBREVS = {
    "np.", "m.in.", "dr.", "prof.", "mgr.", "inż.", "ul.", "al.", "pl.",
    "ok.", "tzn.", "tj.", "itd.", "itp.", "nr.", "pkt.", "art.", "ust.",
    "poz.", "godz.", "min.", "sek.", "tys.", "mln.", "mld.", "proc.", "zwł.",
}
SENTENCE_END_RE = re.compile(r"([.!?]+|\n+)(\s+|$)")


def sanitize_dictation_text(raw: str) -> str:
    """Strip CR/LF and ASCII control characters so simulated typing never hits Enter."""
    return re.sub(r"[\r\n\x00-\x1f\x7f]+", " ", str(raw or "")).strip()


def _ydotool_socket() -> str | None:
    env_sock = os.environ.get("YDOTOOL_SOCKET", "").strip()
    candidates = [env_sock] if env_sock else []
    uid = os.getuid() if hasattr(os, "getuid") else 1000
    candidates.extend([
        f"/run/user/{uid}/.ydotool_socket",
        "/tmp/.ydotool_socket",
    ])
    for cand in candidates:
        if cand and Path(cand).exists():
            return cand
    return None


def type_text(raw_text: str, timeout: float = 10.0) -> dict:
    """Type sanitized text into the focused window on Wayland (`wtype`/`ydotool`) or X11 (`xdotool`)."""
    safe = sanitize_dictation_text(raw_text)
    if not safe:
        return {"typed": False, "backend": None, "safe_text": ""}

    session_type = os.environ.get("XDG_SESSION_TYPE", "").strip().lower()
    has_wayland = session_type == "wayland" or bool(os.environ.get("WAYLAND_DISPLAY"))

    # 1. Native Wayland virtual-keyboard protocol (`wtype`)
    if has_wayland and shutil.which("wtype"):
        try:
            proc = subprocess.run(
                ["wtype", "--", safe],
                capture_output=True, text=True, timeout=timeout, check=False,
            )
            if proc.returncode == 0:
                return {"typed": True, "backend": "wtype", "safe_text": safe}
        except Exception:
            pass

    # 2. Kernel uinput daemon (`ydotool`) — works natively across GNOME Wayland & XWayland
    if shutil.which("ydotool"):
        sock = _ydotool_socket()
        if sock:
            env = {**os.environ, "YDOTOOL_SOCKET": sock}
            try:
                proc = subprocess.run(
                    ["ydotool", "type", "--key-delay", "12", "--", safe],
                    capture_output=True, text=True, timeout=timeout, env=env, check=False,
                )
                if proc.returncode == 0:
                    return {"typed": True, "backend": "ydotool", "safe_text": safe}
            except Exception:
                pass

    # 3. X11 / XWayland fallback (`xdotool`)
    if shutil.which("xdotool") and os.environ.get("DISPLAY"):
        try:
            proc = subprocess.run(
                ["xdotool", "type", "--clearmodifiers", "--delay", "12", "--", safe],
                capture_output=True, text=True, timeout=timeout, check=False,
            )
            if proc.returncode == 0:
                return {"typed": True, "backend": "xdotool", "safe_text": safe}
        except Exception:
            pass

    return {"typed": False, "backend": None, "safe_text": safe}


class SentenceStreamChunker:
    """Incremental streaming text -> speakable sentences splitter (<400ms first-chunk latency)."""

    def __init__(self, min_chars: int = 18, max_chars: int = 260):
        self.min_chars = max(6, int(min_chars))
        self.max_chars = max(60, int(max_chars))
        self._buf = ""

    def push(self, delta: str) -> list[str]:
        if not delta:
            return []
        self._buf += str(delta)
        ready: list[str] = []

        while True:
            extracted = self._pop_one()
            if extracted is None:
                break
            if extracted:
                ready.append(extracted)
        return ready

    def _pop_one(self) -> str | None:
        buf = self._buf
        if not buf:
            return None
        for match in SENTENCE_END_RE.finditer(buf):
            end_idx = match.end()
            candidate = buf[:end_idx].strip()
            if len(candidate) < self.min_chars and "\n" not in match.group(1):
                continue
            last_word = candidate.rsplit(None, 1)[-1].lower() if candidate else ""
            if last_word in PL_ABBREVS:
                continue
            self._buf = buf[end_idx:].lstrip()
            return candidate

        if len(buf) >= self.max_chars:
            cut = buf.rfind(" ", 0, self.max_chars)
            if cut < self.min_chars:
                cut = self.max_chars
            chunk = buf[:cut].strip()
            self._buf = buf[cut:].lstrip()
            return chunk
        return None

    def flush(self) -> list[str]:
        tail = self._buf.strip()
        self._buf = ""
        return [tail] if tail else []


class BargeInController:
    """Thread-safe speech generation counter and subprocess terminator for instant barge-in."""

    def __init__(self):
        self._lock = threading.Lock()
        self._gen = 0
        self._procs: set[subprocess.Popen] = set()

    def begin_utterance(self) -> int:
        with self._lock:
            self._gen += 1
            return self._gen

    def register_proc(self, proc: subprocess.Popen, gen_id: int) -> bool:
        with self._lock:
            if gen_id != self._gen:
                try:
                    proc.terminate()
                except Exception:
                    pass
                return False
            self._procs.add(proc)
            return True

    def unregister_proc(self, proc: subprocess.Popen) -> None:
        with self._lock:
            self._procs.discard(proc)

    def interrupt(self) -> int:
        """Advance generation and terminate any active TTS playback subprocesses."""
        with self._lock:
            self._gen += 1
            gen = self._gen
            active = list(self._procs)
            self._procs.clear()
        for proc in active:
            try:
                proc.terminate()
            except Exception:
                pass
        try:
            import event_bus
            event_bus.publish("voice.barge_in", {"generation": gen, "stopped_procs": len(active)})
        except Exception:
            pass
        return gen

    def is_current(self, gen_id: int) -> bool:
        with self._lock:
            return int(gen_id) == self._gen

    @property
    def generation(self) -> int:
        with self._lock:
            return self._gen


BARGE_IN = BargeInController()


def dnd_status() -> dict:
    """Return whether Do-Not-Disturb or an active microphone call suppresses spoken prompts."""
    if os.environ.get("JARVIS_DND", "").strip() in ("1", "true", "yes"):
        return {"dnd": True, "reason": "env_dnd"}

    if shutil.which("gsettings"):
        try:
            proc = subprocess.run(
                ["gsettings", "get", "org.gnome.desktop.notifications", "show-banners"],
                capture_output=True, text=True, timeout=1.5, check=False,
            )
            if proc.returncode == 0 and proc.stdout.strip().lower() == "false":
                return {"dnd": True, "reason": "gnome_do_not_disturb"}
        except Exception:
            pass

    if shutil.which("pactl"):
        try:
            proc = subprocess.run(
                ["pactl", "list", "source-outputs"],
                capture_output=True, text=True, timeout=1.5, check=False,
            )
            out = proc.stdout.lower()
            if proc.returncode == 0 and "corked: no" in out and any(
                app in out for app in ("webrtc", "zoom", "teams", "discord", "chromium", "firefox")
            ):
                return {"dnd": True, "reason": "active_call_mic"}
        except Exception:
            pass

    return {"dnd": False, "reason": "clear"}
