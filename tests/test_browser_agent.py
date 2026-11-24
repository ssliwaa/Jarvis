"""Unit contracts for the browser agent: no real browser, network or model."""
import json
import os
SANDBOXED = os.environ.get("JARVIS_VERIFY_SANDBOX") == "1"
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import browser_agent
import plan_files



class FakeBrowser:
    instances = []

    def __init__(self, headless=False):
        self.headless = headless
        self.clicked = []
        self.filled = []
        self.closed = False
        FakeBrowser.instances.append(self)

    def open(self, url):
        return self.state()

    def state(self):
        return {"title": "Test page", "url": "https://example.test/",
                "text": "Hello", "elements": [{"index": 0, "label": "Publish campaign"}]}

    def element_info(self, index):
        return {"index": index, "label": "Publish campaign", "type": "button"}

    def click(self, index):
        self.clicked.append(index)
        return self.state()

    def fill(self, index, text, submit=False):
        self.filled.append((index, text, submit))
        return self.state()

    def fill_secret(self, index, value, submit=False):
        self.filled.append((index, value, submit))
        return {**self.state(), "secret_typed": True}

    def press(self, key):
        return self.state()

    def scroll(self, direction, amount):
        return self.state()

    def screenshot(self, path):
        Path(path).write_bytes(b"\x89PNG\r\n\x1a\nfake")

    def close(self):
        self.closed = True


class FakeClient:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = 0
        self.closed = False
        self.messages = SimpleNamespace(create=self._create)

    def _create(self, **kwargs):
        self.calls += 1
        if not self.responses:
            raise AssertionError("unexpected model call")
        return self.responses.pop(0)

    def close(self):
        self.closed = True


def response(*blocks):
    return SimpleNamespace(content=list(blocks))


def tool(name, tool_id, **arguments):
    return SimpleNamespace(type="tool_use", id=tool_id, name=name, input=arguments)


def text(value):
    return SimpleNamespace(type="text", text=value)


@unittest.skipIf(SANDBOXED, "needs the developer's local env (vault/Hermes/Piper/desktop); skipped in CI")
class BrowserAgentTests(unittest.TestCase):
    def setUp(self):
        FakeBrowser.instances.clear()

    def test_timeout_falls_back_to_the_next_model(self):
        calls = []

        class Flaky:
            def __init__(self):
                self.messages = SimpleNamespace(create=self.create)

            def create(self, **kwargs):
                calls.append(kwargs["model"])
                if len(calls) == 1:
                    raise TimeoutError("temporary")
                return response(tool("finish", "t1", summary="Fallback worked."))

            def close(self):
                pass

        client = Flaky()
        with tempfile.TemporaryDirectory() as tmp:
            service = SimpleNamespace(root=Path(tmp), headless=True, mode="full")
            job = browser_agent.AgentJob(service, "do it", "key", "bad/model", "job",
                                         client_factory=lambda **_: client,
                                         models=["bad/model", "good/model"])
            job.start()
            job._thread.join(5)
        self.assertEqual(job.status, "done")
        self.assertEqual(calls, ["bad/model", "good/model"])
        self.assertIn("Fallback worked", job.summary)

    def test_english_voice_pins_operator_narration_to_english(self):
        captured = {}

        class Probe:
            def __init__(self):
                self.messages = SimpleNamespace(create=self.create)

            def create(self, **kwargs):
                captured.update(kwargs)
                return response(tool("finish", "t1", summary="Opera GX is open."))

            def close(self):
                pass

        with tempfile.TemporaryDirectory() as tmp:
            service = SimpleNamespace(root=Path(tmp), headless=True, mode="full")
            job = browser_agent.AgentJob(service, "Otwórz Opera GX", "key", "model", "job-language",
                                         client_factory=lambda **_: Probe(), language="en")
            job.start()
            job._thread.join(5)
        self.assertEqual(job.status, "done")
        self.assertIn("English voice", captured["system"])
        self.assertIn("English only", captured["system"])
        self.assertIn("final finish summary", captured["system"])

    def test_polish_narration_is_translated_for_an_english_voice(self):
        class Translator:
            def __init__(self):
                self.calls = []

            def _translate_to_english(self, text):
                self.calls.append(text)
                return "Checking the disk now." if "dysk" in text else "Done."

        app = Translator()
        client = FakeClient([
            response(text("Sprawdzam dysk."), tool("finish", "t1", summary="Gotowe.")),
        ])
        with tempfile.TemporaryDirectory() as tmp:
            service = SimpleNamespace(root=Path(tmp), headless=True, mode="full", app=app)
            job = browser_agent.AgentJob(service, "Sprawdź dysk", "key", "model", "job-voice",
                                         client_factory=lambda **_: client, language="en")
            job.start()
            job._thread.join(5)
        self.assertEqual(job.status, "done")
        say = next(step for step in job.steps if step["kind"] == "say")
        self.assertEqual(say["text"], "Checking the disk now.")
        self.assertEqual(say["lang"], "en")
        self.assertEqual(job.summary, "Done.")
        self.assertEqual(app.calls, ["Sprawdzam dysk.", "Gotowe."])

    def test_untranslated_polish_narration_is_marked_not_to_be_spoken(self):
        class Broken:
            def _translate_to_english(self, text):
                raise RuntimeError("no model")

        client = FakeClient([
            response(text("Sprawdzam dysk."), tool("finish", "t1", summary="Gotowe.")),
        ])
        with tempfile.TemporaryDirectory() as tmp:
            service = SimpleNamespace(root=Path(tmp), headless=True, mode="full", app=Broken())
            job = browser_agent.AgentJob(service, "Sprawdź dysk", "key", "model", "job-voice-fail",
                                         client_factory=lambda **_: client, language="en")
            job.start()
            job._thread.join(5)
        say = next(step for step in job.steps if step["kind"] == "say")
        self.assertEqual(say["text"], "Sprawdzam dysk.")
        self.assertEqual(say["lang"], "pl")

    def test_job_publishes_its_outcome_to_the_chat_session(self):
        recorded = {}

        class App:
            def remember_operator(self, token, snapshot):
                recorded["token"] = token
                recorded["snapshot"] = dict(snapshot)

            def _translate_to_english(self, text):
                return text

        client = FakeClient([response(tool("finish", "t1", summary="Done."))])
        token = "s" * 43
        with tempfile.TemporaryDirectory() as tmp:
            service = SimpleNamespace(root=Path(tmp), headless=True, mode="full", app=App())
            job = browser_agent.AgentJob(service, "open YouTube", "key", "model", "job-session",
                                         client_factory=lambda **_: client, language="en",
                                         session_token=token)
            job.start()
            job._thread.join(5)
        self.assertEqual(recorded["token"], token)
        self.assertEqual(recorded["snapshot"]["task"], "open YouTube")
        self.assertEqual(recorded["snapshot"]["status"], "done")
        self.assertEqual(recorded["snapshot"]["summary"], "Done.")

    def test_private_http_targets_are_blocked_for_the_operator(self):
        self.assertTrue(browser_agent._is_private_http("http://127.0.0.1:4700/self/forge"))
        self.assertTrue(browser_agent._is_private_http("http://localhost:4700/"))
        self.assertTrue(browser_agent._is_private_http("http://10.0.0.5/"))
        self.assertFalse(browser_agent._is_private_http("https://8.8.8.8/"))
        # URL-parser differentials: Python sees 8.8.8.8 after the userinfo,
        # while Chromium treats the backslash as a separator and hits loopback.
        self.assertTrue(browser_agent._is_private_http("http://127.0.0.1\\@8.8.8.8/"))
        self.assertTrue(browser_agent._is_private_http("http://user:pass@8.8.8.8/"))

    def test_a_response_from_a_private_peer_blocks_content_reads(self):
        browser = object.__new__(browser_agent.AgentBrowser)
        browser._allow_private = False
        browser._peer_violation = None
        browser._network = __import__("collections").deque()

        class Response:
            url = "http://rebind.example/"

            def __init__(self, address):
                self.address = address

            def server_addr(self):
                return self.address

        browser._note_peer(Response({"ipAddress": "93.184.216.34", "port": 80}))
        self.assertIsNone(browser._peer_violation)
        browser._note_peer(Response({"ipAddress": "127.0.0.1", "port": 4700}))
        self.assertEqual(browser._peer_violation, "127.0.0.1")
        with self.assertRaises(browser_agent.AgentError):
            browser._refuse_private_peer()
        # A private tab is refused by URL as well, not only by a response.
        browser._refuse_private_page(SimpleNamespace(url="https://8.8.8.8/"))
        with self.assertRaises(browser_agent.AgentError):
            browser._refuse_private_page(SimpleNamespace(url="http://127.0.0.1:4700/"))

    def test_urls_are_http_only(self):
        self.assertEqual(browser_agent._url("8.8.8.8"), "https://8.8.8.8")
        for value in ("file:///etc/passwd", "chrome://settings", "javascript:alert(1)"):
            with self.subTest(value=value):
                with self.assertRaises(browser_agent.AgentError):
                    browser_agent._url(value)

    def test_high_risk_click_requires_approval_and_runs_after_it(self):
        client = FakeClient([
            response(tool("click", "t1", index=0)),
            response(tool("finish", "t2", summary="Finished after approval.")),
        ])
        with tempfile.TemporaryDirectory() as tmp:
            service = SimpleNamespace(root=Path(tmp), headless=True)
            job = browser_agent.AgentJob(service, "publish it", "key", "model", "job",
                                         client_factory=lambda **_: client)
            with patch.object(browser_agent, "AgentBrowser", FakeBrowser):
                job.start()
                deadline = time.time() + 5
                while time.time() < deadline and job.status != "awaiting_approval":
                    time.sleep(0.02)
                self.assertEqual(job.status, "awaiting_approval")
                self.assertTrue(job.decide(True, job.pending["token"]))
                job._thread.join(5)
        self.assertEqual(job.status, "done")
        self.assertEqual(FakeBrowser.instances[0].clicked, [0])
        self.assertIn("Finished after approval", job.summary)

    def test_the_snapshot_carries_the_task_so_a_cancel_can_name_and_target_it(self):
        # The cancel lane narrows by subject ("cancel this youtube") and names the
        # task it stopped; both need the task text in the status snapshot.
        with tempfile.TemporaryDirectory() as tmp:
            service = SimpleNamespace(root=Path(tmp), headless=True)
            job = browser_agent.AgentJob(service, "Play some music on YouTube.",
                                         "key", "model", "task-snapshot")
            self.assertEqual(job.snapshot()["task"], "Play some music on YouTube.")

    def test_one_time_approval_token_is_required(self):
        with tempfile.TemporaryDirectory() as tmp:
            service = SimpleNamespace(root=Path(tmp), headless=True)
            job = browser_agent.AgentJob(service, "x", "key", "model", "token")
            job.pending = {"token": "abc", "expires_at": time.time() + 60,
                           "name": "terminal", "reason": "test", "args": "{}",
                           "risk": "standard", "irreversible": False}
            # The approval panel reads the token from the status snapshot.
            pending = job.snapshot()["pending"]
            self.assertEqual(pending["token"], "abc")
            self.assertFalse(job.decide(True))
            self.assertFalse(job.decide(True, "wrong"))
            self.assertTrue(job.decide(True, pending["token"]))
            # Consumed in the same locked decision: a second click cannot
            # approve or deny the action again.
            self.assertFalse(job.decide(False, "abc"))

    def test_deepseek_model_ladder_is_not_filtered_by_slashes(self):
        with tempfile.TemporaryDirectory() as tmp:
            service = SimpleNamespace(root=Path(tmp), headless=True)
            job = browser_agent.AgentJob(
                service, "x", "key", "deepseek-flash", "ladder",
                models=["deepseek-flash", "deepseek-v4-pro"])
            self.assertEqual(job.models, ["deepseek-flash", "deepseek-v4-pro"])

    def test_enter_and_submit_forms_are_approval_gated(self):
        with tempfile.TemporaryDirectory() as tmp:
            service = SimpleNamespace(root=Path(tmp), headless=True)
            job = browser_agent.AgentJob(service, "fill it", "key", "model", "job")
            self.assertIn("submit", job._guard("fill", {"index": 0, "text": "hello", "submit": True}).lower())
            self.assertIn("Enter", job._guard("press", {"key": "Enter"}))
            self.assertEqual(job._guard("press", {"key": "Tab"}), "")

    def test_denied_high_risk_click_is_not_delivered(self):
        client = FakeClient([
            response(tool("click", "t1", index=0)),
            response(tool("finish", "t2", summary="Stopped at the approval gate.")),
        ])
        with tempfile.TemporaryDirectory() as tmp:
            service = SimpleNamespace(root=Path(tmp), headless=True)
            job = browser_agent.AgentJob(service, "publish it", "key", "model", "job",
                                         client_factory=lambda **_: client)
            with patch.object(browser_agent, "AgentBrowser", FakeBrowser):
                job.start()
                deadline = time.time() + 5
                while time.time() < deadline and job.status != "awaiting_approval":
                    time.sleep(0.02)
                self.assertTrue(job.decide(False, job.pending["token"]))
                job._thread.join(5)
        self.assertEqual(job.status, "done")
        self.assertEqual(FakeBrowser.instances[0].clicked, [])

    def test_non_browser_tool_loop_does_not_launch_a_browser(self):
        client = FakeClient([
            response(tool("terminal", "t1", command="printf operator-ok")),
            response(tool("finish", "t2", summary="Command completed.")),
        ])
        with tempfile.TemporaryDirectory() as tmp:
            service = SimpleNamespace(root=Path(tmp), headless=True, mode="standard")
            job = browser_agent.AgentJob(service, "run a command", "key", "model", "job",
                                         client_factory=lambda **_: client)
            with patch.object(browser_agent, "AgentBrowser", FakeBrowser):
                job.start()
                job._thread.join(5)
        self.assertEqual(job.status, "done")
        self.assertEqual(FakeBrowser.instances, [])
        self.assertTrue(any("operator-ok" in str(step) for step in job.steps))

    def test_desktop_and_secret_tools_use_backends_without_exposing_a_secret(self):
        with tempfile.TemporaryDirectory() as tmp:
            service = SimpleNamespace(root=Path(tmp), headless=True, mode="full")
            job = browser_agent.AgentJob(service, "use the desktop", "key", "model", "job")
            job.cua = SimpleNamespace(
                windows=lambda: [{"pid": 10, "window_id": 20, "title": "Terminal"}],
                apps=lambda: [{"name": "Terminal", "running": True}],
                capture=lambda pid, window, path: {"ok": True, "pid": pid, "window_id": window},
                click=lambda pid, window, **kw: {"ok": True, "clicked": kw},
                type=lambda pid, window, text, **kw: {"ok": True, "typed": True},
                key=lambda pid, window, keys: {"ok": True, "keys": keys},
                scroll=lambda pid, window, direction, amount: {"ok": True},
                focus=lambda pid, window: {"ok": True},
                launch=lambda name: {"ok": True, "name": name},
                desktop_screenshot=lambda path: {"ok": True},
            )
            job.browser = FakeBrowser()
            job.secrets = SimpleNamespace(
                names=lambda: [{"name": "school", "type": "password"}],
                get=lambda name: {"type": "password", "value": "not-for-the-model"},
            )
            self.assertEqual(job._desktop({"action": "list_windows"})["windows"][0]["pid"], 10)
            self.assertTrue(job._desktop({"action": "type", "pid": 10, "window_id": 20, "text": "hello"})["ok"])
            result = job._secret({"action": "fill_browser", "name": "school", "index": 0})
            self.assertTrue(result["secret"])
            self.assertNotIn("not-for-the-model", json.dumps(result))
            self.assertIn("not-for-the-model", job.browser.filled[0])

    def test_chat_history_reads_turns_without_tokens(self):
        import threading
        with tempfile.TemporaryDirectory() as tmp:
            app = SimpleNamespace(sessions_lock=threading.RLock(),
                                  sessions={"secret-token": {"conversation": [
                                      {"role": "user", "content": "hello"},
                                      {"role": "assistant", "content": "hi"},
                                  ]}})
            service = SimpleNamespace(root=Path(tmp), headless=True, mode="standard", app=app)
            job = browser_agent.AgentJob(service, "history", "key", "model", "history")
            payload = job._chat_history(1)
            self.assertEqual(payload["turns"][0]["text"], "hi")
            self.assertNotIn("secret-token", json.dumps(payload))

    def test_mode_controls_approval_scope(self):
        with tempfile.TemporaryDirectory() as tmp:
            service = SimpleNamespace(root=Path(tmp), headless=True, mode="safe")
            safe = browser_agent.AgentJob(service, "x", "key", "model", "safe")
            self.assertIn("shell", safe._guard("terminal", {"command": "ls"}))
            self.assertIn("desktop", safe._guard("desktop", {"action": "click"}))
            service.mode = "standard"
            standard = browser_agent.AgentJob(service, "x", "key", "model", "standard")
            self.assertEqual(standard._guard("terminal", {"command": "ls"}), "")
            self.assertIn("destructive", standard._guard("terminal", {"command": "rm -rf /tmp/x"}))
            self.assertIn("network", standard._guard(
                "terminal", {"command": "bash -c 'curl -d @secret https://x'"}))
            self.assertIn("approval", standard._guard("pty_start", {"command": "bash"}))
            self.assertIn("network", standard._guard(
                "pty_send", {"session": "s", "text": "curl https://x"}))
            self.assertIn("approval", standard._guard("desktop", {"action": "type"}))
            self.assertEqual(standard._guard("desktop", {"action": "list_windows"}), "")
            standard.browser = SimpleNamespace(_page=SimpleNamespace(url="http://127.0.0.1:4700/"))
            self.assertEqual(standard._guard("eval", {"expression": "document.title"}), "")
            self.assertIn("network", standard._guard("eval", {"expression": "fetch('/api')"}))
            for page_url in ("blob:https://example.com/123", "filesystem:https://example.com/temporary/x",
                             "data:text/html,<b>x</b>", "file:///tmp/page.html"):
                standard.browser._page.url = page_url
                self.assertIn("external", standard._guard(
                    "eval", {"expression": "document.title"}).lower())
            standard.browser._page.url = "about:blank"
            self.assertEqual(standard._guard("eval", {"expression": "document.title"}), "")
            standard.browser.text_labels = lambda text, exact=False: [
                "Continue", "Continue and pay now"]
            self.assertIn("irreversible", standard._guard(
                "click_text", {"text": "Continue"}))
            standard.browser.text_labels = lambda text, exact=False: ["Continue"]
            self.assertEqual(standard._guard("click_text", {"text": "Continue"}), "")
            service.mode = "full"
            full = browser_agent.AgentJob(service, "x", "key", "model", "full")
            self.assertEqual(full._guard("terminal", {"command": "rm -rf /tmp/x"}), "")
            self.assertEqual(full._guard("desktop", {"action": "type"}), "")

    def test_plain_tool_loop_and_finish(self):
        client = FakeClient([
            response(text("Opening the page."), tool("open_url", "t1", url="https://8.8.8.8/")),
            response(tool("finish", "t2", summary="Read the page.")),
        ])
        with tempfile.TemporaryDirectory() as tmp:
            service = SimpleNamespace(root=Path(tmp), headless=True)
            job = browser_agent.AgentJob(service, "open it", "key", "model", "job",
                                         client_factory=lambda **_: client)
            with patch.object(browser_agent, "AgentBrowser", FakeBrowser):
                job.start()
                job._thread.join(5)
        self.assertEqual(job.status, "done")
        self.assertEqual(job.summary, "Read the page.")
        self.assertEqual(client.calls, 2)
        self.assertTrue(any(step["kind"] == "action" and "open_url" in step["text"] for step in job.steps))

    def test_finish_is_blocked_once_by_an_unchecked_plan(self):
        client = FakeClient([
            response(tool("finish", "t1", summary="Done early.")),
            response(tool("plan", "t2", action="check", index=0)),
            response(tool("finish", "t3", summary="Phase checked, done.")),
        ])
        with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, {"JARVIS_PLAN_ROOT": tmp}):
            seed = plan_files.PlanFiles("job-plan", root=Path(tmp))
            seed.start("open it", ["open the page"])
            service = SimpleNamespace(root=Path(tmp), headless=True, mode="full")
            job = browser_agent.AgentJob(service, "open it", "key", "model", "job-plan",
                                         client_factory=lambda **_: client)
            with patch.object(browser_agent, "AgentBrowser", FakeBrowser):
                job.start()
                job._thread.join(5)
            status = seed.status()
        self.assertEqual(job.status, "done")
        self.assertEqual(client.calls, 3)
        self.assertTrue(status["complete"])
        self.assertNotIn("unchecked", job.summary)
        self.assertTrue(any(step["kind"] == "plan" for step in job.steps))

    def test_a_second_finish_passes_with_a_warning(self):
        client = FakeClient([
            response(tool("finish", "t1", summary="First attempt.")),
            response(tool("finish", "t2", summary="Second attempt.")),
        ])
        with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, {"JARVIS_PLAN_ROOT": tmp}):
            seed = plan_files.PlanFiles("job-gate", root=Path(tmp))
            seed.start("open it", ["open the page"])
            service = SimpleNamespace(root=Path(tmp), headless=True, mode="full")
            job = browser_agent.AgentJob(service, "open it", "key", "model", "job-gate",
                                         client_factory=lambda **_: client)
            with patch.object(browser_agent, "AgentBrowser", FakeBrowser):
                job.start()
                job._thread.join(5)
        self.assertEqual(job.status, "done")
        self.assertEqual(client.calls, 2)
        self.assertIn("unchecked", job.summary)


    def test_operator_snapshots_the_project_before_a_file_mutation(self):
        import checkpoint_manager
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project = root / "project"
            project.mkdir()
            (project / "pyproject.toml").write_text("[project]\nname='p'\n", encoding="utf-8")
            (project / "note.txt").write_text("before\n", encoding="utf-8")
            service = SimpleNamespace(root=root, headless=True, mode="full")
            job = browser_agent.AgentJob(service, "edit", "key", "model", "job-checkpoint",
                                         client_factory=lambda **_: FakeClient([]))
            job.checkpoints = checkpoint_manager.CheckpointManager(
                base=root / "checkpoints", enabled=True, max_file_size_mb=10)
            job.checkpoints.new_turn()
            job._maybe_checkpoint("write_file", {"path": str(project / "note.txt")})
            snapshots = job.checkpoints.list_checkpoints(project)
        self.assertGreaterEqual(len(snapshots), 1)
        self.assertIn("before write_file", snapshots[0]["reason"])
    def test_subagent_spawn_returns_only_a_bounded_summary(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            service = SimpleNamespace(root=root, headless=True, mode="full", app=None)
            parent = browser_agent.AgentJob(
                service, "parent", "key", "model", "parent-subagents",
                client_factory=lambda **_: FakeClient([
                    response(tool("finish", "g1", summary="Child one found the answer."))
                ]),
            )
            spawned = parent.subagents.spawn([
                {"goal": "find one", "context": "only this child sees the context"},
                {"goal": "find two"},
            ])
            self.assertTrue(spawned["ok"])
            ids = [row["subagent_id"] for row in spawned["subagents"]]
            self.assertEqual(len(ids), 2)
            waited = parent.subagents.wait(ids, 10)
            self.assertTrue(waited["ok"])
            self.assertEqual(len(waited["results"]), 2)
            for result in waited["results"]:
                self.assertTrue(result["ready"], result)
                self.assertEqual(result["status"], "done", result)
                self.assertIn("Child one found", result["summary"])
                self.assertNotIn("steps", result)
                self.assertNotIn("context", result)
            child = parent.subagents.records[ids[0]].job
            self.assertIn("finish", child.allowed_tools)
            self.assertIn("read_file", child.allowed_tools)
            self.assertNotIn("write_file", child.allowed_tools)
            self.assertNotIn("terminal", child.allowed_tools)
            self.assertNotIn("delegate", child.allowed_tools)
            self.assertIn("READ-ONLY", child.system_override)
            parent.subagents.close()

    def test_parent_operator_can_spawn_wait_and_finish_with_a_summary(self):
        parent_client = FakeClient([
            response(tool("delegate", "d1", action="spawn",
                          tasks=[{"goal": "research one thing", "context": "self-contained"}])),
            response(tool("delegate", "d2", action="wait", timeout=10)),
            response(tool("finish", "f1", summary="Parent used the child summary.")),
        ])
        child_client = FakeClient([
            response(tool("finish", "c1", summary="The child found a fact.")),
        ])
        clients = [parent_client, child_client]

        def factory(**_kwargs):
            return clients.pop(0) if clients else FakeClient([
                response(tool("finish", "c2", summary="extra child"))
            ])

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            service = SimpleNamespace(root=root, headless=True, mode="full", app=None)
            job = browser_agent.AgentJob(service, "parent task", "key", "model", "parent-e2e",
                                         client_factory=factory)
            job.start()
            job._thread.join(10)
        self.assertEqual(job.status, "done", job.error)
        self.assertIn("Parent used the child summary", job.summary)
        actions = [step["text"] for step in job.steps if step["kind"] == "action"]
        self.assertTrue(any(text.startswith("delegate") for text in actions), actions)

    def test_subagent_cancel_stops_a_running_child(self):
        import threading
        gate = threading.Event()

        class Blocking:
            def __init__(self):
                self.messages = SimpleNamespace(create=self.create)

            def create(self, **_kwargs):
                gate.wait(5)
                return response(tool("finish", "t1", summary="late result"))

            def close(self):
                pass

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            service = SimpleNamespace(root=root, headless=True, mode="full", app=None)
            parent = browser_agent.AgentJob(
                service, "parent", "key", "model", "parent-cancel",
                client_factory=lambda **_: Blocking(),
            )
            spawned = parent.subagents.spawn([{"goal": "wait forever"}])
            subagent_id = spawned["subagents"][0]["subagent_id"]
            cancelled = parent.subagents.cancel(subagent_id)
            self.assertTrue(cancelled["ok"])
            gate.set()
            waited = parent.subagents.wait([subagent_id], 10)
            self.assertEqual(waited["results"][0]["status"], "cancelled", waited)
            parent.subagents.close()

    def test_subagent_batch_and_total_budgets_are_enforced(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            service = SimpleNamespace(root=root, headless=True, mode="full", app=None)
            parent = browser_agent.AgentJob(service, "parent", "key", "model", "parent-budget")
            parent.subagents.max_concurrent = 1
            with self.assertRaises(Exception):
                parent.subagents.spawn([{"goal": "one"}, {"goal": "two"}])
            parent.subagents.max_concurrent = 3
            parent.subagents.max_total = 1
            with self.assertRaises(Exception):
                parent.subagents.spawn([{"goal": "one"}, {"goal": "two"}])
            parent.subagents.close()

    def test_subagent_rejects_unknown_ids_and_forbidden_tool_requests(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            service = SimpleNamespace(root=root, headless=True, mode="full", app=None)
            parent = browser_agent.AgentJob(service, "parent", "key", "model", "parent-subagents-2")
            with self.assertRaises(browser_agent.AgentError):
                parent._act("delegate", {"action": "wait", "ids": ["missing"]})
            child = browser_agent.AgentJob(
                service, "child", "key", "model", "child-forbidden",
                allowed_tools={"finish"}, max_steps=2, subagent_depth=1,
            )
            self.assertFalse(child._tool_allowed("write_file"))
            with self.assertRaises(browser_agent.AgentError):
                child._act("write_file", {"path": str(root / "x"), "content": "no"})
            self.assertFalse((root / "x").exists())

    def test_subagent_steering_is_delivered_at_the_next_boundary(self):
        captured = []

        class Probe(FakeClient):
            def _create(self, **kwargs):
                captured.append(kwargs.get("messages") or [])
                return super()._create(**kwargs)

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            service = SimpleNamespace(root=root, headless=True, mode="full", app=None)
            client = Probe([response(tool("finish", "t1", summary="done"))])
            job = browser_agent.AgentJob(
                service, "child", "key", "model", "child-steer",
                client_factory=lambda **_: client, allowed_tools={"finish"},
                max_steps=2, subagent_depth=1,
            )
            self.assertTrue(job.steer("focus on the first result"))
            job.start()
            job._thread.join(5)
            self.assertTrue(captured)
            self.assertIn("STEERING FROM PARENT", json.dumps(captured[0]))
            self.assertEqual(job.summary, "done")

    def test_operator_prunes_or_compacts_context_before_a_model_call(self):
        import context_compressor
        import context_state

        client = FakeClient([response(text("## Goal\nOperator summary"))])
        with tempfile.TemporaryDirectory() as tmp:
            service = SimpleNamespace(root=Path(tmp), headless=True, mode="full")
            job = browser_agent.AgentJob(service, "do it", "key", "model", "job-context",
                                         client_factory=lambda **_: client)
            job.model_client = client
            job.context = context_compressor.ContextCompressor(
                "model", context_length=20_000, threshold_percent=0.5,
                protect_first_n=1, protect_last_n=2, max_tokens=1000,
                summary_caller=job._context_summary_call,
                state_store=context_state.NullStateStore(),
                state_key="operator:test-context", quiet_mode=True,
            )
            messages = [{"role": "user", "content": "inspect the disk"}]
            for index in range(12):
                messages.append({"role": "assistant", "content": [{
                    "type": "tool_use", "id": f"c{index}", "name": "terminal",
                    "input": {"command": "echo " + ("a" * 4000)}}]})
                messages.append({"role": "user", "content": [{
                    "type": "tool_result", "tool_use_id": f"c{index}",
                    "content": "result " + ("x" * 3000)}]})
            bounded = job._maybe_compress_context(messages, "system " + ("s" * 20000), [])
        self.assertIsNot(bounded, messages)
        self.assertLess(len(bounded), len(messages))
        self.assertTrue(any(step["kind"] == "context" for step in job.steps))
        self.assertTrue(any(message.get(context_compressor.COMPRESSED_SUMMARY_KEY)
                            for message in bounded))


def bare_browser():
    """An AgentBrowser instance without Playwright: attribute-fixture only."""
    return browser_agent.AgentBrowser.__new__(browser_agent.AgentBrowser)




class FakePage:
    def __init__(self, actions=None):
        self.handlers = {}
        self.closed = False
        self.actions = actions or {}

    def on(self, event, callback):
        self.handlers.setdefault(event, []).append(callback)

    def emit(self, event, payload):
        for callback in self.handlers.get(event, []):
            callback(payload)

    def is_closed(self):
        return self.closed

    def close(self):
        self.closed = True

    def set_default_timeout(self, value):
        self.default_timeout = value

    def evaluate(self, script):
        action = self.actions.get("evaluate")
        if action is not None:
            if isinstance(action, Exception):
                raise action
            return action
        return {"title": "t", "url": "https://example.test/", "text": "", "elements": []}


class FakeContext:
    def __init__(self, *pages):
        self._pages = list(pages)

    def new_page(self):
        page = FakePage()
        self._pages.append(page)
        return page

    @property
    def pages(self):
        return self._pages


class NetworkLogTests(unittest.TestCase):
    def test_the_log_keeps_the_latest_events_rather_than_the_first_300(self):
        browser = bare_browser()
        browser._network = browser_agent.deque(maxlen=browser_agent.NETWORK_LOG_LIMIT)
        page = FakePage()
        browser._attach_page(page)
        request = page.handlers["request"][0]
        for number in range(310):
            request(SimpleNamespace(method="GET", url=f"https://example.test/{number}",
                                    resource_type="document"))
        self.assertEqual(len(browser._network), 300)
        self.assertEqual(browser.network(1)["events"][-1]["url"], "https://example.test/309")
        self.assertNotIn("/0", browser.network(50)["events"][0]["url"])


class NewTabRollbackTests(unittest.TestCase):
    def test_a_failed_navigation_closes_the_orphan_and_restores_the_page(self):
        browser = bare_browser()
        before = FakePage()
        context = FakeContext(before)
        browser._context = context
        browser._page = before
        browser._network = browser_agent.deque(maxlen=50)

        broken = FakePage(actions={"evaluate": RuntimeError("net::ERR_NAME_NOT_RESOLVED")})

        def goto(url, **_kwargs):
            raise RuntimeError("net::ERR_NAME_NOT_RESOLVED")

        broken.goto = goto
        context.new_page = lambda: broken
        with self.assertRaises(browser_agent.AgentError):
            browser.new_tab("https://blocked.example/")
        self.assertIs(browser._page, before)
        for page in context._pages:
            if page is not before:
                self.assertTrue(page.is_closed())  # the orphan was closed


class CrashRecoveryTests(unittest.TestCase):
    def test_a_crashed_target_is_rebuilt_once_and_the_caller_is_told(self):
        class TargetClosedError(RuntimeError):  # playwright raises a class of this name
            pass

        browser = bare_browser()
        crashed = FakePage(actions={"evaluate": TargetClosedError("Target page closed")})
        context = FakeContext(crashed)
        browser._context = context
        browser._page = crashed
        browser._network = browser_agent.deque(maxlen=50)
        with self.assertRaises(browser_agent.AgentError) as caught:
            browser.state()
        self.assertIn("fresh blank tab", str(caught.exception))
        self.assertIsNot(browser._page, crashed)  # a rebuild happened
        self.assertTrue(crashed.is_closed())


class MarkDigestTests(unittest.TestCase):
    def test_the_cheap_mark_hashes_what_a_full_state_sweep_hashes(self):
        browser = bare_browser()
        raw = "line one\n\n\n\nline two and " + "x" * 1400
        # a snapshot normalizes the text before returning it
        normalized = raw.replace("\n\n\n\n", "\n\n").strip()
        fingerprint = "https://example.test/p|3|" + normalized[:1200]
        page = FakePage(actions={"evaluate": fingerprint})
        browser._page = page
        browser._context = FakeContext(page)
        browser._network = browser_agent.deque(maxlen=10)
        before = browser._mark()
        state = {"url": "https://example.test/p", "text": normalized, "elements": [1, 2, 3]}
        after = browser._mark(state)
        self.assertEqual(before, after)  # same digest: an unchanged page reads 'unchanged'
        self.assertEqual(browser._annotate(before, state)["changed"], False)
        drifted = dict(state, text="something else entirely")
        self.assertEqual(browser._annotate(before, drifted)["change"], "dom")


class SingletonLockTests(unittest.TestCase):
    def test_a_stale_link_with_no_live_owner_is_removed(self):
        with tempfile.TemporaryDirectory() as tmp:
            profile = Path(tmp)
            dead_pid = 2_147_483_647  # a valid pid range value nothing has live-claimed in tests
            (profile / "SingletonLock").symlink_to(f"somehost-{dead_pid}")
            (profile / "SingletonCookie").symlink_to(f"somehost-{dead_pid}")
            browser_agent._clear_stale_singleton(profile)
            # is_symlink: a broken link still reads `exists()` as False
            self.assertFalse((profile / "SingletonLock").is_symlink())
            self.assertFalse((profile / "SingletonCookie").is_symlink())

    def test_an_alive_owner_and_a_corrupt_link_are_left_alone(self):
        with tempfile.TemporaryDirectory() as tmp:
            profile = Path(tmp)
            (profile / "SingletonLock").symlink_to(f"somehost-{os.getpid()}")
            (profile / "SingletonSocket").symlink_to("somehost-not-a-pid")  # corrupt target
            bore = profile / "not-a-symlink"
            bore.write_text("data")
            browser_agent._clear_stale_singleton(profile)
            self.assertTrue((profile / "SingletonLock").is_symlink())  # alive owner: intact
            self.assertTrue((profile / "SingletonSocket").is_symlink())
            self.assertTrue(bore.exists())  # regular files are never touched


@unittest.skipIf(SANDBOXED, "needs the developer's local env (vault/Hermes/Piper/desktop); skipped in CI")
class ScreenshotGateTests(unittest.TestCase):
    def test_only_browser_steps_repaint_latest_png(self):
        shots = []

        class CountingBrowser(FakeBrowser):
            def screenshot(self, path):
                shots.append(Path(path))
                Path(path).write_bytes(b"png")

        client = FakeClient([
            response(tool("click", "t1", index=0)),
            response(tool("terminal", "t2", command="printf operator-ok")),
            response(tool("finish", "t3", summary="One shot, then none.")),
        ])
        with tempfile.TemporaryDirectory() as tmp:
            service = SimpleNamespace(root=Path(tmp), headless=True, mode="full")
            job = browser_agent.AgentJob(service, "mix tools", "key", "model", "job",
                                         client_factory=lambda **_: client)
            with patch.object(browser_agent, "AgentBrowser", CountingBrowser):
                job.start()
                job._thread.join(10)
        self.assertEqual(job.status, "done")
        self.assertEqual(len(shots), 1)  # after the click; not after the terminal step


@unittest.skipIf(SANDBOXED, "needs the developer's local env (vault/Hermes/Piper/desktop); skipped in CI")
class CloseResilienceTests(unittest.TestCase):
    def test_a_failing_browser_close_cannot_skip_history_and_job_finish(self):
        class DyingBrowser(FakeBrowser):
            def close(self):
                super().close()
                raise RuntimeError("browser half-dead")

        recorded, finished = [], []
        client = FakeClient([
            response(tool("click", "t1", index=0)),
            response(tool("finish", "t2", summary="All finished.")),
        ])
        with tempfile.TemporaryDirectory() as tmp:
            service = SimpleNamespace(root=Path(tmp), headless=True, mode="full",
                                      _record_history=lambda snapshot: recorded.append(snapshot),
                                      _job_finished=lambda job: finished.append(job))
            job = browser_agent.AgentJob(service, "just finish", "key", "model", "job",
                                         client_factory=lambda **_: client)
            with patch.object(browser_agent, "AgentBrowser", DyingBrowser):
                job.start()
                job._thread.join(10)
        self.assertEqual(job.status, "done")
        self.assertEqual(len(finished), 1)  # the lock was released despite the close raise
        self.assertEqual(len(recorded), 1)
        self.assertTrue(any("close failed" in str(step.get("text", "")).lower()
                            for step in job.steps))


class QueueAdvanceTests(unittest.TestCase):
    def _service(self, queue, fail_first=False):
        import threading
        service = browser_agent.AgentService.__new__(browser_agent.AgentService)
        service.lock = threading.RLock()
        service.job = object()
        service.queue = list(queue)
        service.shutting_down = False
        service._save_queue = lambda: None
        service._record_history = lambda row: None
        launched = []

        def launch(task, job_id=None, language=None, session_token=None):
            if fail_first and not launched:
                launched.append(task)
                raise RuntimeError("config missing")
            launched.append(task)

        service._launch_job = launch
        return service, launched

    def test_a_failed_queued_launch_is_not_lost_and_the_next_row_runs(self):
        service, launched = self._service(
            [{"id": "a", "task": "first"}, {"id": "b", "task": "second"}],
            fail_first=True)
        active = service.job
        service._job_finished(active)
        self.assertEqual(launched, ["first", "second"])
        self.assertEqual([row["id"] for row in service.queue], ["a"])

    def test_shutdown_stops_queue_advance(self):
        service, launched = self._service([{"id": "a", "task": "first"}])
        service.shutting_down = True
        active = service.job
        service._job_finished(active)
        self.assertEqual(launched, [])
        self.assertEqual([row["id"] for row in service.queue], ["a"])


    def test_completed_job_remains_queryable_by_id_and_screenshot_after_finish(self):
        service, _ = self._service([])
        with tempfile.TemporaryDirectory() as tmp:
            artifacts = Path(tmp) / "done-1"
            artifacts.mkdir()
            (artifacts / "latest.png").write_bytes(b"png-bytes")
            done_job = SimpleNamespace(
                id="done-1",
                artifacts=artifacts,
                snapshot=lambda: {"id": "done-1", "status": "done", "summary": "Completed."},
            )
            service.job = done_job
            service.mode = "standard"
            service.available = lambda: True
            service.browser_available = lambda: True
            service.features = lambda: {}
            service._job_finished(done_job)
            self.assertIsNone(service.status()["job"])
            self.assertEqual(service.status("done-1")["job"]["status"], "done")
            self.assertEqual(service.screenshot("done-1"), b"png-bytes")


class ArtifactSweepTests(unittest.TestCase):
    def test_old_job_directories_are_pruned(self):
        service = browser_agent.AgentService.__new__(browser_agent.AgentService)
        with tempfile.TemporaryDirectory() as tmp:
            service.root = Path(tmp)
            service.ARTIFACT_KEEP = 3
            for number in range(6):
                path = service.root / f"job-{number}"
                path.mkdir()
                (path / "latest.png").write_bytes(b"png")
                time.sleep(0.01)
            service._sweep_artifacts()
            remaining = sorted(path.name for path in service.root.iterdir())
        self.assertEqual(remaining, ["job-3", "job-4", "job-5"])






class CancelAllTests(unittest.TestCase):
    """'Cancel everything' must not hand the freed slot to the next queued task."""

    def _service(self, queue):
        import threading
        service = browser_agent.AgentService.__new__(browser_agent.AgentService)
        service.lock = threading.RLock()
        service.queue = list(queue)
        service.shutting_down = False
        service.cancelling = False
        service._save_queue = lambda: None
        service._record_history = lambda row: None
        launched = []
        service._launch_job = lambda task, *a, **k: launched.append(task)
        stopped = []

        class Job:
            id = "j1"
            task = "Play some music"
            def stop(self):
                stopped.append(self.id)
                service.job = None
                return {"id": self.id, "status": "stopped"}

        service.job = Job()
        return service, launched, stopped

    def test_cancel_all_stops_the_job_and_empties_the_queue(self):
        service, launched, stopped = self._service([{"id": "a", "task": "first"},
                                                    {"id": "b", "task": "second"}])
        result = service.cancel_all()
        self.assertEqual(stopped, ["j1"])
        self.assertEqual(service.queue, [])
        self.assertEqual(result["cleared"], 2)
        self.assertEqual([row["id"] for row in result["stopped"]], ["j1", "a", "b"])
        self.assertTrue(all(row.get("removed_from_queue") for row in result["stopped"][1:]))
        self.assertEqual(launched, [])

    def test_a_finishing_job_cannot_promote_the_next_row_during_a_cancel(self):
        service, launched, _stopped = self._service([{"id": "a", "task": "first"}])
        service.cancelling = True
        service._job_finished(service.job)
        self.assertEqual(launched, [])


class RedactionAndRetentionTests(unittest.TestCase):
    def test_the_public_view_never_invents_a_home_path(self):
        # The panel and the approval prompt used to show /home/testuser/x as
        # ~/kowalski/x — a path that does not exist, on the very screen where the
        # user approves a write. Only the real home prefix is shortened.
        home = str(Path.home())
        self.assertEqual(browser_agent._redact(home + "/.hermes/test.txt"),
                         "~/.hermes/test.txt")
        self.assertEqual(browser_agent._redact("/home/other/file.txt"), "/home/other/file.txt")
        self.assertEqual(browser_agent._redact("path " + home), "path " + home)

    def test_a_completed_job_stays_readable_after_the_next_one_starts(self):
        import threading
        service = browser_agent.AgentService.__new__(browser_agent.AgentService)
        service.lock = threading.RLock()
        service.job = None
        service.last_job = None
        service.recent_jobs = {}
        service.recent_order = []
        service.queue = []
        service.mode = "standard"
        service.available = lambda: True
        service.browser_available = lambda: True
        service.features = lambda: {}
        service.queue_rows = lambda: []
        service._remember_snapshot({"id": "old-1", "status": "done", "summary": "first"})
        service._remember_snapshot({"id": "old-2", "status": "done", "summary": "second"})
        self.assertEqual(service.status("old-1")["job"]["summary"], "first")
        self.assertEqual(service.status("old-2")["job"]["summary"], "second")
        service._remember_snapshot({"id": "old-1", "status": "done", "summary": "first again"})
        self.assertEqual(service.status("old-1")["job"]["summary"], "first again")
        self.assertEqual(service.recent_order[-1], "old-1")

    def test_only_the_last_twenty_snapshots_are_kept(self):
        import threading
        service = browser_agent.AgentService.__new__(browser_agent.AgentService)
        service.lock = threading.RLock()
        service.recent_jobs = {}
        service.recent_order = []
        for index in range(25):
            service._remember_snapshot({"id": f"j{index}", "status": "done"})
        self.assertEqual(len(service.recent_jobs), 20)
        self.assertNotIn("j0", service.recent_jobs)
        self.assertIn("j24", service.recent_jobs)


if __name__ == "__main__":
    unittest.main()
