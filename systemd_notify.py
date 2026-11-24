"""Minimal sd_notify support without a systemd Python dependency."""
from __future__ import annotations

import os
import socket
import threading


def notify(state: str = "READY=1") -> bool:
    address = os.environ.get("NOTIFY_SOCKET", "")
    if not address:
        return False
    if address.startswith("@"):
        address = "\0" + address[1:]
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as sock:
            sock.connect(address)
            sock.sendall(state.encode("ascii", "replace"))
        return True
    except OSError:
        return False


def start_watchdog(stop_event: threading.Event | None = None) -> threading.Thread | None:
    """Ping systemd at half of WatchdogSec.  No-op outside a systemd unit."""
    usec = os.environ.get("WATCHDOG_USEC", "")
    if not usec.isdigit() or int(usec) <= 0:
        return None
    interval = max(1.0, int(usec) / 1_000_000 / 2)
    stop = stop_event or threading.Event()

    def loop():
        while not stop.wait(interval):
            notify("WATCHDOG=1")

    thread = threading.Thread(target=loop, name="jarvis-watchdog", daemon=True)
    thread.start()
    return thread
