"""sd_notify: env gating, datagram delivery and the watchdog thread."""
import os
import socket
import tempfile
import threading
import time
import unittest
from unittest import mock

import systemd_notify


class NotifyTests(unittest.TestCase):
    def test_no_socket_env_is_a_silent_noop(self):
        env = {key: value for key, value in os.environ.items() if key != "NOTIFY_SOCKET"}
        with mock.patch.dict(os.environ, env, clear=True):
            self.assertFalse(systemd_notify.notify("READY=1"))

    def test_notify_delivers_to_a_unix_datagram_socket(self):
        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, "notify.sock")
            with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as listener:
                listener.bind(path)
                listener.settimeout(2)
                with mock.patch.dict(os.environ, {"NOTIFY_SOCKET": path}):
                    self.assertTrue(systemd_notify.notify("READY=1"))
                payload, _ = listener.recvfrom(64)
        self.assertEqual(payload, b"READY=1")

    def test_abstract_socket_at_prefix_is_translated(self):
        name = f"jarvis-test-{os.getpid()}"
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as listener:
            listener.bind("\0" + name)
            listener.settimeout(2)
            with mock.patch.dict(os.environ, {"NOTIFY_SOCKET": "@" + name}):
                self.assertTrue(systemd_notify.notify("WATCHDOG=1"))
            payload, _ = listener.recvfrom(64)
        self.assertEqual(payload, b"WATCHDOG=1")

    def test_watchdog_is_a_noop_outside_systemd(self):
        env = {key: value for key, value in os.environ.items() if key != "WATCHDOG_USEC"}
        with mock.patch.dict(os.environ, env, clear=True):
            self.assertIsNone(systemd_notify.start_watchdog())

    def test_watchdog_pings_and_stops(self):
        stop = threading.Event()
        with mock.patch.dict(os.environ, {"WATCHDOG_USEC": "200000"}), \
                mock.patch.object(systemd_notify, "notify") as notify:
            thread = systemd_notify.start_watchdog(stop)
            self.assertIsNotNone(thread)
            self.assertTrue(thread.daemon)
            deadline = time.monotonic() + 2.5
            while time.monotonic() < deadline and not notify.called:
                time.sleep(0.05)
            stop.set()
            thread.join(timeout=2)
        self.assertTrue(notify.called)
        self.assertFalse(thread.is_alive())


if __name__ == "__main__":
    unittest.main()
