"""MPRIS2 media player control, PipeWire/PulseAudio volume, and local media app status."""

from __future__ import annotations

import re
import shutil
import socket
import subprocess
from typing import Any

_MPRIS_METHODS = {
    "play": "Play",
    "pause": "Pause",
    "play_pause": "PlayPause",
    "next": "Next",
    "previous": "Previous",
    "stop": "Stop",
}


def _run(argv: list[str], timeout: float = 3.0) -> tuple[int, str]:
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)
        return proc.returncode, (proc.stdout or proc.stderr or "").strip()
    except (OSError, subprocess.SubprocessError):
        return 1, ""


def _mpris_destinations() -> list[str]:
    if not shutil.which("gdbus"):
        return []
    code, out = _run([
        "gdbus", "call", "--session",
        "--dest", "org.freedesktop.DBus",
        "--object-path", "/org/freedesktop/DBus",
        "--method", "org.freedesktop.DBus.ListNames",
    ])
    if code != 0 or not out:
        return []
    return sorted(set(re.findall(r"org\.mpris\.MediaPlayer2\.[A-Za-z0-9_.-]+", out)))


def _mpris_status() -> list[dict[str, Any]]:
    if shutil.which("playerctl"):
        code, out = _run([
            "playerctl", "-a", "metadata",
            "--format", "{{playerName}}\t{{status}}\t{{artist}}\t{{title}}",
        ])
        if code == 0 and out:
            rows = []
            for line in out.splitlines():
                parts = line.split("\t")
                if len(parts) >= 4:
                    rows.append({
                        "player": parts[0],
                        "status": parts[1],
                        "artist": parts[2],
                        "title": parts[3],
                    })
            return rows
    players = []
    for dest in _mpris_destinations():
        _, state = _run([
            "gdbus", "call", "--session", "--dest", dest,
            "--object-path", "/org/mpris/MediaPlayer2",
            "--method", "org.freedesktop.DBus.Properties.Get",
            "org.mpris.MediaPlayer2.Player", "PlaybackStatus",
        ])
        status_match = re.search(r"'([A-Za-z]+)'", state)
        players.append({
            "player": dest.removeprefix("org.mpris.MediaPlayer2."),
            "bus_name": dest,
            "status": status_match.group(1) if status_match else "Unknown",
        })
    return players


def _volume_status() -> dict[str, Any]:
    if shutil.which("wpctl"):
        code, out = _run(["wpctl", "get-volume", "@DEFAULT_AUDIO_SINK@"])
        if code == 0 and out:
            match = re.search(r"([0-9]+(?:\.[0-9]+)?)", out)
            vol = round(float(match.group(1)) * 100) if match else None
            return {"backend": "wpctl", "volume_percent": vol, "muted": "MUTED" in out.upper()}
    if shutil.which("pactl"):
        code, out = _run(["pactl", "get-sink-volume", "@DEFAULT_SINK@"])
        _, mute_out = _run(["pactl", "get-sink-mute", "@DEFAULT_SINK@"])
        if code == 0 and out:
            match = re.search(r"(\d+)%", out)
            return {
                "backend": "pactl",
                "volume_percent": int(match.group(1)) if match else None,
                "muted": "yes" in mute_out.lower(),
            }
    return {"backend": "unavailable", "volume_percent": None, "muted": None}


def _kino_status() -> dict[str, Any]:
    ports = []
    for port in (7358, 7357):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(0.25)
                if sock.connect_ex(("127.0.0.1", port)) == 0:
                    ports.append(port)
        except OSError:
            continue
    return {
        "running": bool(ports),
        "active_ports": ports,
        "url": f"http://127.0.0.1:{ports[0]}" if ports else None,
    }


def _audio_backend() -> str | None:
    if shutil.which("wpctl"):
        return "wpctl"
    if shutil.which("pactl"):
        return "pactl"
    return None


def media_control(arguments: dict[str, Any], context=None) -> dict[str, Any]:
    """Inspect or control desktop media playback, system volume, and the local media app."""
    del context
    args = arguments if isinstance(arguments, dict) else {}
    action = str(args.get("action") or "status").strip().lower()
    if action == "status":
        return {
            "ok": True,
            "action": "status",
            "players": _mpris_status(),
            "audio": _volume_status(),
            "local_player": _kino_status(),
        }

    if action in _MPRIS_METHODS:
        if shutil.which("playerctl"):
            cmd = "play-pause" if action == "play_pause" else action
            code, out = _run(["playerctl", cmd])
            if code != 0:
                return {"ok": False, "action": action, "via": "playerctl",
                        "error": out or "playerctl command failed."}
            return {"ok": True, "action": action, "via": "playerctl", "detail": out}
        destinations = _mpris_destinations()
        if not destinations:
            return {"ok": False, "action": action, "error": "No active MPRIS2 media player found."}
        method = f"org.mpris.MediaPlayer2.Player.{_MPRIS_METHODS[action]}"
        code, out = _run([
            "gdbus", "call", "--session", "--dest", destinations[0],
            "--object-path", "/org/mpris/MediaPlayer2", "--method", method,
        ])
        if code != 0:
            return {"ok": False, "action": action, "player": destinations[0],
                    "error": out or "MPRIS2 call failed."}
        return {"ok": True, "action": action, "player": destinations[0], "detail": out}

    if action == "volume":
        level = args.get("volume_percent")
        mute = args.get("mute")
        if level is None and mute is None:
            return {"ok": True, "action": "volume", "audio": _volume_status()}
        if mute is not None and not isinstance(mute, bool):
            return {"ok": False, "action": "volume", "error": "Parameter 'mute' must be a boolean."}
        clamped = None
        if level is not None:
            if isinstance(level, bool):
                return {"ok": False, "action": "volume", "error": "Parameter 'volume_percent' must be an integer."}
            try:
                clamped = max(0, min(int(level), 150))
            except (TypeError, ValueError):
                return {"ok": False, "action": "volume", "error": "Parameter 'volume_percent' must be an integer."}

        backend = _audio_backend()
        if backend is None:
            return {"ok": False, "action": "volume", "error": "No supported audio backend (wpctl or pactl) is installed."}

        errors: list[str] = []
        if mute is not None:
            flag = "1" if mute else "0"
            cmd = (["wpctl", "set-mute", "@DEFAULT_AUDIO_SINK@", flag]
                   if backend == "wpctl"
                   else ["pactl", "set-sink-mute", "@DEFAULT_SINK@", flag])
            code, out = _run(cmd)
            if code != 0:
                errors.append(out or "failed to update mute state")
        if clamped is not None:
            cmd = (["wpctl", "set-volume", "@DEFAULT_AUDIO_SINK@", f"{clamped}%"]
                   if backend == "wpctl"
                   else ["pactl", "set-sink-volume", "@DEFAULT_SINK@", f"{clamped}%"])
            code, out = _run(cmd)
            if code != 0:
                errors.append(out or "failed to set volume")
        status = _volume_status()
        if errors:
            return {"ok": False, "action": "volume", "error": "; ".join(errors), "audio": status}
        return {"ok": True, "action": "volume", "audio": status}

    return {"ok": False, "error": f"Unsupported action: {action!r}"}


TOOL = {
    "name": "media_control",
    "description": (
        "Inspect or control Linux MPRIS2 media players (Spotify, browser, SMPlayer), "
        "PipeWire/PulseAudio volume, and local media player status (ports 7358/7357)."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "action": {
                "type": "string",
                "enum": ["status", "play", "pause", "play_pause", "next", "previous", "stop", "volume"],
                "description": "Action to perform (default: status).",
            },
            "volume_percent": {
                "type": "integer",
                "description": "Target audio volume percentage (0-150) when action='volume'.",
            },
            "mute": {
                "type": "boolean",
                "description": "Mute or unmute audio when action='volume'.",
            },
        },
        "additionalProperties": False,
    },
    "handler": media_control,
    "approval": False,
}
