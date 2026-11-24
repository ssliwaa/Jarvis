"""Offline Telegram boundary and remote-mode regression tests."""
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import browser_agent


class FakeApp:
    def __init__(self, root):
        self.root = Path(root)

    def read_settings(self):
        return "test-key", "test-model"

    def read_models(self):
        return ["test-model"]


class FakeTransport:
    def __init__(self):
        self.sent = []

    def send(self, chat_id, text):
        self.sent.append((chat_id, text))


class FakeAgent:
    def __init__(self):
        self.started = []

    def start(self, task, **kwargs):
        self.started.append((task, kwargs))
        return {"id": "job1", "status": "queued", "mode": "safe"}


class TelegramServerTests(unittest.TestCase):
    def test_server_starts_and_stops_configured_channel(self):
        from types import SimpleNamespace
        from unittest.mock import MagicMock

        import server
        with tempfile.TemporaryDirectory() as tmp:
            app = SimpleNamespace(root=Path(tmp), close=MagicMock())
            agent = MagicMock()
            channel = MagicMock()
            factory = MagicMock(return_value=channel)
            with patch.object(server, "Application", return_value=app), \
                 patch.object(server, "atomic_write"), \
                 patch.object(server.agent_bay, "AgentService", return_value=agent), \
                 patch.object(server, "telegram_channel", SimpleNamespace(from_environment=factory), create=True):
                httpd = server.create_server(root=tmp, port=0, state_root=tmp,
                                             enable_scheduler=False)
                channel.start.assert_called_once()
                httpd.server_close()
                channel.stop.assert_called_once()
                factory.assert_called_once_with(agent, Path(tmp))


class TelegramTransportTests(unittest.TestCase):
    def test_transport_polls_with_offset_and_sends_plain_text(self):
        import json

        import telegram_channel
        class Response:
            def __enter__(self):
                return self
            def __exit__(self, *args):
                return False
            def read(self, limit):
                return b'{"ok":true,"result":[]}'
        class Opener:
            def __init__(self):
                self.requests = []
            def open(self, request, timeout):
                self.requests.append((request.full_url, json.loads(request.data), timeout))
                return Response()
        opener = Opener()
        transport = telegram_channel.TelegramTransport("123456:test_secret", opener=opener)
        self.assertEqual(transport.poll(17), [])
        transport.send(42, "safe text")
        self.assertTrue(opener.requests[0][0].endswith("/getUpdates"))
        self.assertEqual(opener.requests[0][1]["offset"], 17)
        self.assertEqual(opener.requests[1][1], {"chat_id": 42, "text": "safe text"})


class TelegramBoundaryTests(unittest.TestCase):
    def test_channel_configuration_is_disabled_without_explicit_opt_in(self):
        import telegram_channel
        with tempfile.TemporaryDirectory() as tmp:
            with patch.dict("os.environ", {}, clear=True):
                self.assertIsNone(telegram_channel.from_environment(FakeAgent(), tmp))
            self.assertFalse((Path(tmp) / "telegram").exists())

    def test_token_falls_back_to_the_credential_store_not_the_unit_file(self):
        import telegram_channel
        token = "123456789:AAHstored-token_value-123"
        with tempfile.TemporaryDirectory() as tmp:
            env = {"JARVIS_TELEGRAM_ENABLED": "1", "JARVIS_TELEGRAM_OWNER_ID": "42"}
            with patch.dict("os.environ", env, clear=True), \
                 patch.object(telegram_channel, "_bot_token", return_value=token):
                channel = telegram_channel.from_environment(FakeAgent(), tmp)
        self.assertIsNotNone(channel)
        self.assertTrue(channel.transport._url.endswith(token + "/"))
        self.assertEqual(channel.owner_id, 42)

    def test_missing_token_fails_closed(self):
        import telegram_channel
        with tempfile.TemporaryDirectory() as tmp:
            env = {"JARVIS_TELEGRAM_ENABLED": "1", "JARVIS_TELEGRAM_OWNER_ID": "42"}
            with patch.dict("os.environ", env, clear=True), \
                 patch.object(telegram_channel, "_bot_token", return_value=""):
                with self.assertRaises(ValueError) as caught:
                    telegram_channel.from_environment(FakeAgent(), tmp)
        self.assertIn("token", str(caught.exception).lower())

    def test_a_non_numeric_owner_id_is_refused(self):
        import telegram_channel
        with tempfile.TemporaryDirectory() as tmp:
            env = {"JARVIS_TELEGRAM_ENABLED": "1", "JARVIS_TELEGRAM_OWNER_ID": "not-an-id"}
            with patch.dict("os.environ", env, clear=True), \
                 patch.object(telegram_channel, "_bot_token", return_value="stored-token"):
                with self.assertRaises(ValueError):
                    telegram_channel.from_environment(FakeAgent(), tmp)

    def test_stop_drops_a_poll_response_that_arrived_during_shutdown(self):
        import threading

        import telegram_channel
        with tempfile.TemporaryDirectory() as tmp:
            agent = FakeAgent()
            class BlockingTransport(FakeTransport):
                def __init__(self):
                    super().__init__()
                    self.entered = threading.Event()
                    self.release = threading.Event()
                def poll(self, offset):
                    self.entered.set()
                    self.release.wait(1)
                    return [{"update_id": 7, "message": {"from": {"id": 42},
                            "chat": {"id": 42, "type": "private"}, "text": "/run task"}}]
            transport = BlockingTransport()
            channel = telegram_channel.TelegramChannel(agent, transport, 42, tmp)
            channel.start()
            self.assertTrue(transport.entered.wait(1))
            channel._stop.set()
            transport.release.set()
            channel.stop()
            self.assertEqual(agent.started, [])
            self.assertFalse(channel._thread.is_alive())

    def test_failed_notification_is_retried_without_restarting_job(self):
        import telegram_channel
        with tempfile.TemporaryDirectory() as tmp:
            agent = FakeAgent()
            class FlakyTransport(FakeTransport):
                def __init__(self):
                    super().__init__()
                    self.fail = False
                def send(self, chat_id, text):
                    if self.fail:
                        self.fail = False
                        raise RuntimeError("transport error")
                    super().send(chat_id, text)
            transport = FlakyTransport()
            channel = telegram_channel.TelegramChannel(agent, transport, 42, tmp)
            channel.handle_update({"update_id": 6, "message": {"from": {"id": 42},
                "chat": {"id": 42, "type": "private"}, "text": "/run test"}})
            agent.status = lambda job_id: {"job": {"id": job_id, "status": "done"}}
            transport.fail = True
            channel.notify_jobs()
            channel.notify_jobs()
            self.assertEqual(len(agent.started), 1)
            self.assertIn("done", transport.sent[-1][1])

    def test_first_poll_discards_old_messages_and_persists_cursor(self):
        import telegram_channel
        with tempfile.TemporaryDirectory() as tmp:
            agent = FakeAgent()
            class PollTransport(FakeTransport):
                def __init__(self):
                    super().__init__()
                    self.offsets = []
                def poll(self, offset):
                    self.offsets.append(offset)
                    uid = 9 if offset == -1 else 10
                    return [{"update_id": uid, "message": {"from": {"id": 42},
                            "chat": {"id": 42, "type": "private"}, "text": "/run task"}}]
            transport = PollTransport()
            channel = telegram_channel.TelegramChannel(agent, transport, 42, tmp)
            channel.poll_once()
            self.assertEqual(agent.started, [])
            channel = telegram_channel.TelegramChannel(agent, transport, 42, tmp)
            channel.poll_once()
            self.assertEqual(transport.offsets, [-1, 10])
            self.assertEqual(len(agent.started), 1)

    def test_job_progress_is_delivered_without_approval_tokens_or_private_output(self):
        import telegram_channel
        with tempfile.TemporaryDirectory() as tmp:
            agent, transport = FakeAgent(), FakeTransport()
            channel = telegram_channel.TelegramChannel(agent, transport, 42, tmp)
            update = {"update_id": 5, "message": {"from": {"id": 42},
                      "chat": {"id": 42, "type": "private"}, "text": "/run test"}}
            channel.handle_update(update)
            agent.status = lambda job_id: {"job": {"id": job_id, "status": "awaiting_approval",
                                           "pending": {"token": "must-never-send"}}}
            channel.notify_jobs()
            channel.notify_jobs()
            agent.status = lambda job_id: {"job": {"id": job_id, "status": "done",
                                           "summary": "private summary"}}
            channel.notify_jobs()
            self.assertEqual(len(transport.sent), 3)
            sent = str(transport.sent)
            self.assertNotIn("must-never-send", sent)
            self.assertNotIn("private summary", sent)
            self.assertIn("awaiting_approval", sent)
            self.assertIn("done", sent)

    def test_only_owner_private_chat_starts_once_across_restart(self):
        import telegram_channel
        with tempfile.TemporaryDirectory() as tmp:
            agent, transport = FakeAgent(), FakeTransport()
            channel = telegram_channel.TelegramChannel(agent, transport, 42, tmp)
            def update(uid, sender, chat_id, kind="private"):
                return {"update_id": uid, "message": {"from": {"id": sender},
                        "chat": {"id": chat_id, "type": kind}, "text": "/run check disk"}}
            channel.handle_update(update(1, 13, 13))
            channel.handle_update(update(2, 13, 42))
            channel.handle_update(update(3, 42, 42, "group"))
            self.assertEqual(agent.started, [])
            channel.handle_update(update(4, 42, 42))
            channel = telegram_channel.TelegramChannel(agent, transport, 42, tmp)
            channel.handle_update(update(4, 42, 42))
            self.assertEqual(agent.started, [("check disk", {"queue": True, "remote": True})])
            self.assertEqual(len(transport.sent), 1)


class RemoteJobTests(unittest.TestCase):
    def test_remote_job_never_uses_full_mode_and_gates_browser_actions(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(browser_agent.AgentJob, "start"):
            service = browser_agent.AgentService(FakeApp(tmp), state_root=tmp, seed_secrets=False)
            service.mode = "full"
            snapshot = service.start("remote task", remote=True)
            self.assertEqual(snapshot["mode"], "safe")
            with patch.object(service.job, "_ensure_browser", side_effect=AssertionError("browser launch")):
                self.assertTrue(service.job._guard("click_selector", {"selector": "button"}))
            self.assertTrue(service.job._guard("fill", {"text": "value"}))

    def test_queued_remote_job_keeps_safe_mode_after_restart(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(browser_agent.AgentJob, "start"):
            first = browser_agent.AgentService(FakeApp(tmp), state_root=tmp, seed_secrets=False)
            first.mode = "full"
            first.start("local task")
            queued = first.start("remote task", queue=True, remote=True)
            self.assertEqual(queued["mode"], "safe")
            second = browser_agent.AgentService(FakeApp(tmp), state_root=tmp, seed_secrets=False)
            second.mode = "full"
            job = second.resume_queue()["started"]
            self.assertEqual(job["id"], queued["id"])
            self.assertEqual(job["mode"], "safe")
            self.assertTrue(second.job._guard("terminal", {"command": "printf hello"}))


if __name__ == "____main____":
    unittest.main()
