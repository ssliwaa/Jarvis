"""Chat-level routing guards: destructive tasks, system reads, capabilities.

Reported live: "Usuń wszystkie pliki z katalogu ~/notes." was queued as
an Operator job with no warning in Full mode, "sprawdź ile wolnego miejsca na
dysku" was answered with "this lane cannot read your disk", and "co potrafisz?"
was answered from the notes instead of the live registry.
"""
import unittest
from types import SimpleNamespace

import router
import server


class StartRecorder:
    """Minimal Operator stand-in that records what chat tried to start."""

    def __init__(self):
        self.started = []

    def available(self):
        return True

    def start(self, task, queue=False, **_kwargs):
        self.started.append(task)
        return {"id": "job-1", "status": "running", "queued": False}


def app_for(agent):
    # route_operator_or_clarify lives on the request handler, not on Application.
    handler = object.__new__(server.Handler)
    handler.server = SimpleNamespace(agent=agent)
    return handler


class DestructiveChatGateTests(unittest.TestCase):
    def test_a_deletion_from_chat_asks_before_starting_anything(self):
        agent = StartRecorder()
        result = app_for(agent).route_operator_or_clarify(
            "Usuń wszystkie pliki z katalogu ~/notes.")
        self.assertEqual(result["outcome"], "ask")
        self.assertTrue(result["needs_confirmation"])
        self.assertEqual(agent.started, [])
        self.assertIn("potwierdzam", result["answer"])

    def test_the_confirmation_message_starts_the_task(self):
        agent = StartRecorder()
        result = app_for(agent).route_operator_or_clarify(
            "potwierdzam: usuń wszystkie pliki z katalogu ~/notes")
        self.assertEqual(result["outcome"], "started")
        self.assertEqual(len(agent.started), 1)

    def test_a_read_only_system_task_starts_directly(self):
        agent = StartRecorder()
        result = app_for(agent).route_operator_or_clarify(
            "Sprawdź ile wolnego miejsca jest na dysku.")
        self.assertEqual(result["outcome"], "started")
        self.assertEqual(len(agent.started), 1)

    def test_a_capability_question_is_answered_from_the_registry(self):
        agent = StartRecorder()
        result = app_for(agent).route_operator_or_clarify("Co dokładnie potrafisz?")
        self.assertEqual(agent.started, [])
        self.assertEqual(result["outcome"], "done")
        self.assertTrue([row["label"] for row in result["capabilities"]])
        self.assertTrue(result["limits"])
        self.assertIn("CAPABILITIES", result["answer"])

    def test_an_english_destructive_request_answers_in_english(self):
        agent = StartRecorder()
        result = app_for(agent).route_operator_or_clarify("Delete everything in /tmp")
        self.assertEqual(result["outcome"], "ask")
        self.assertIn("confirm", result["answer"])
        self.assertEqual(agent.started, [])

    def test_scan_and_upgrade_code_starts_operator_directly(self):
        cases = [
            "przeskanuj swój kod i powiedz co możesz ulepszyć",
            "przeanalizuj swój kod i powiedz co możesz ulepszyć",
            "przeskanuj kod jarvisa i powiedz co ulepszyć",
            "sprawdź kod jarvisa i powiedz co można ulepszyć",
            "Can you analyze the code of Jarvis and tell me what can you upgrade?",
            "Scan your code and tell me what can you improve",
            "zrób audyt kodu i wskaż co ulepszyć",
            "przeanalizuj kod i powiedz co można poprawić",
        ]
        for msg in cases:
            with self.subTest(msg=msg):
                agent = StartRecorder()
                result = app_for(agent).route_operator_or_clarify(msg)
                self.assertEqual(result["outcome"], "started", f"Failed to start operator for: {msg}")
                self.assertEqual(len(agent.started), 1)
                self.assertEqual(agent.started[0], msg)

    def test_operator_dispatch_phrasings_start_operator(self):
        cases = [
            ("OK, dispatch the operator to scan Jarvis for real candidates.", "scan Jarvis for real candidates."),
            ("odpal operatora żeby przeskanował kod", "przeskanował kod"),
            ("uruchom operatora aby sprawdził pliki", "sprawdził pliki"),
            ("niech operator sprawdzi kod i powie co ulepszyć", "sprawdzi kod i powie co ulepszyć"),
        ]
        for msg, expected_task in cases:
            with self.subTest(msg=msg):
                agent = StartRecorder()
                result = app_for(agent).route_operator_or_clarify(msg)
                self.assertEqual(result["outcome"], "started", f"Failed for: {msg}")
                self.assertEqual(len(agent.started), 1)
                self.assertEqual(agent.started[0], expected_task)

    def test_generic_operator_trigger_resolves_task_from_history(self):
        agent = StartRecorder()
        handler = app_for(agent)
        mock_app = SimpleNamespace()
        mock_app.session_store = True
        mock_app.get_history = lambda tok: [
            {"role": "user", "content": "Can you analyze the code of Jarvis and tell me what can you upgrade?"},
            {"role": "assistant", "content": "I'll dispatch the Operator to scan /home/testuser/jarvis for real candidates."}
        ]
        handler.server.app = mock_app
        handler.session_token = "test-token"
        result = handler.route_operator_or_clarify("Run the operator, bro.")
        self.assertEqual(result["outcome"], "started")
        self.assertEqual(len(agent.started), 1)
        self.assertIn("scan /home/testuser/jarvis for real candidates", agent.started[0])


class ComparisonSplitTests(unittest.TestCase):
    def test_a_comparison_question_yields_its_sides(self):
        parts = server.comparison_parts("Porównaj notatkę o uTorrencie z notatką o Kino.")
        self.assertEqual(len(parts), 2)
        self.assertIn("uTorrencie", parts[0])
        self.assertIn("Kino", parts[1])
        # "notatkę" is on every architecture note and must not carry the query.
        for part in parts:
            self.assertNotIn("notat", part.casefold())

    def test_a_plain_question_is_not_split(self):
        self.assertEqual(server.comparison_parts("Co notatka mówi o Kino?"), [])
        self.assertEqual(server.comparison_parts("porównaj"), [])


class OperatorAccessReflexTests(unittest.TestCase):
    def test_operator_access_question_returns_affirmative_in_polish(self):
        reply = server.conversational_reply("masz dostęp do operatora")
        self.assertIsNotNone(reply)
        self.assertIn("zintegrowany z Operatorem", reply)
        self.assertIn("terminalu", reply)

    def test_operator_access_question_with_english_language_hint_answers_in_english(self):
        reply = server.conversational_reply("masz dostęp do operatora", reply_language="en")
        self.assertIsNotNone(reply)
        self.assertIn("integrated with the Operator", reply)
        self.assertIn("acting hand", reply)

    def test_integrated_with_operator_question(self):
        reply = server.conversational_reply("jesteś zintegrowany z operatorem")
        self.assertIsNotNone(reply)
        self.assertIn("zintegrowany z Operatorem", reply)

    def test_operator_access_question_in_english(self):
        reply = server.conversational_reply("do you have access to the operator?", reply_language="en")
        self.assertIsNotNone(reply)
        self.assertIn("integrated with the Operator", reply)

    def test_operator_integration_prompt_is_present_in_operator_context(self):
        app = object.__new__(server.Application)
        app.sessions_lock = server.threading.Lock()
        app.sessions = {}
        app.session_store = None
        ctx = app._operator_context("dummy-session")
        self.assertIn("OPERATOR INTEGRATION:", ctx)
        self.assertIn("You are fully integrated with the Operator engine", ctx)

    def test_operator_context_with_job_preserves_both_integration_and_recent_record(self):
        app = object.__new__(server.Application)
        app.sessions_lock = server.threading.Lock()
        app.sessions = {"tok": {"operator": {"id": "job-42", "task": "ls", "status": "done",
                                             "summary": "Listed files", "error": ""}}}
        app.session_store = None
        ctx = app._operator_context("tok")
        self.assertIn("OPERATOR INTEGRATION:", ctx)
        self.assertIn("RECENT OPERATOR JOB", ctx)
        self.assertIn("Listed files", ctx)

    def test_polite_agent_testing_routes_to_operator(self):
        cases = [
            ("Hello Jarvis, could you test all the agents if they are responsive?", "OPERATOR · agent action"),
            ("Could you test all the agents if they are responsive?", "OPERATOR · agent action"),
            ("test all the agents if they are responsive", "OPERATOR · agent action"),
            ("check if all agents are responsive", "OPERATOR · agent action"),
            ("sprawdź czy agenci działają", "OPERATOR · agent action"),
            ("przetestuj wszystkich agentów", "OPERATOR · agent action"),
            ("Hello Jarvis, check all agents", "OPERATOR · agent action"),
            ("Can you test if hermes and claude are working?", "OPERATOR · agent action"),
            ("Mógłbyś przetestować agenta hermes?", "OPERATOR · agent action"),
            ("Hi Jarvis, please check if opencode is alive", "OPERATOR · agent action"),
            ("Cześć Jarvis, zrestartuj serwis", "OPERATOR · service action"),
            ("Czy mógłbyś otworzyć Opera GX?", "OPERATOR · plan ready"),
            ("Hello Jarvis, could you please open Opera GX?", "OPERATOR · plan ready"),
        ]
        for query, expected_label in cases:
            res = router.classify(query)
            self.assertEqual(res.get("action"), "operator", f"Failed for query: {query}")
            self.assertEqual(res.get("label"), expected_label, f"Wrong label for query: {query}")

    def test_agent_notes_query_stays_in_notes(self):
        res = router.classify("co notatki mówią o agentach?")
        self.assertEqual(res.get("action"), "notes")


class HermesAutonomousChatTests(unittest.TestCase):
    def test_dev_queries_route_to_operator(self):
        cases = [
            "zbuduj stronę internetową",
            "build a website for my portfolio",
            "Can you build a website for me?",
            "Check the Kino application and every function in it",
            "Could you fix the bug in the player?",
            "napisz bota do discorda",
        ]
        for query in cases:
            res = router.classify(query)
            self.assertEqual(res.get("action"), "operator", f"Failed for query: {query}")
            self.assertEqual(res.get("intent"), "operator", f"Failed for query: {query}")
            self.assertTrue(res.get("label", "").startswith("OPERATOR"), f"Wrong label for: {query}")

    def test_operator_tag_in_chat_starts_operator_autonomously(self):
        app = object.__new__(server.Application)
        app.sessions_lock = server.threading.Lock()
        app.sessions = {"tok-123": {}}
        app.agent = StartRecorder()
        app.read_settings = lambda: ("fake-key", "fake-model")

        answer = "[OPERATOR: test all agents for responsiveness] Very good, sir; I have dispatched the Operator."
        result = app._handle_operator_tag(answer, "test agents", session_token="tok-123", reply_language="en")
        self.assertIsNotNone(result)
        self.assertEqual(result["outcome"], "started")
        self.assertEqual(app.agent.started, ["test all agents for responsiveness"])
        self.assertEqual(result["answer"], "Very good, sir; I have dispatched the Operator.")
        self.assertEqual(app.sessions["tok-123"]["operator"]["id"], "job-1")

    def test_operator_tag_without_extra_text_generates_polite_butler_ack(self):
        app = object.__new__(server.Application)
        app.sessions_lock = server.threading.Lock()
        app.sessions = {"tok-456": {}}
        app.agent = StartRecorder()
        app.read_settings = lambda: ("fake-key", "fake-model")

        answer = "[OPERATOR: zbadaj aplikację kino]"
        result = app._handle_operator_tag(answer, "zbadaj aplikację kino", session_token="tok-456", reply_language="pl")
        self.assertIsNotNone(result)
        self.assertEqual(result["outcome"], "started")
        self.assertEqual(app.agent.started, ["zbadaj aplikację kino"])
        self.assertIn("przekazałem to zadanie do Operatora", result["answer"])


if __name__ == "__main__":
    unittest.main()
