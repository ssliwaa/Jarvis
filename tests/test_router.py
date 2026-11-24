import unittest
from unittest import mock

import jev_decision
import router
import web_research


class RouterTests(unittest.TestCase):
    def setUp(self):
        # The rules are what is under test here. A stored Jev key would upgrade
        # some general/notes answers to web and make the result depend on the
        # operator's own config (it did: three order-dependent failures).
        patcher = mock.patch.object(jev_decision, "available", return_value=False)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_web_intent_shares_one_source_of_truth(self):
        # The router used to keep its own compiled copy of RESEARCH_HINTS,
        # and the copies drifted apart on "search (the )?web".
        self.assertIs(router.WEB_RE, web_research.RESEARCH_HINTS)
        self.assertTrue(web_research.should_research("search web"))

    def test_price_question_goes_to_web(self):
        route = router.classify("ile kosztuje zestaw kart do gry")
        self.assertEqual(route["intent"], "web")
        self.assertEqual(route["action"], "web")

    def test_url_imperative_is_a_ready_operator_plan(self):
        route = router.classify("otwórz https://example.com i sprawdź tytuł")
        self.assertEqual(route["intent"], "operator")
        self.assertEqual(route["action"], "operator")
        self.assertFalse(route["needs_confirmation"])
        self.assertIn("approval", route["plan"])

    def test_vague_imperative_asks_for_a_target(self):
        for message in ("zrób", "zrób coś", "sprawdź to", "uruchom mi to"):
            with self.subTest(message=message):
                route = router.classify(message)
                self.assertEqual(route["action"], "clarify")
                self.assertTrue(route["needs_confirmation"])
                self.assertIn("Podaj obiekt", route["plan"])

    def test_short_imperative_with_a_real_object_is_a_plan(self):
        # Two words are enough when the second one names something concrete;
        # the old length check sent "sprawdź stronę" to clarify forever.
        for message in ("sprawdź stronę", "uruchom testy", "otwórz google",
                        "otwórz mi przeglądarkę"):
            with self.subTest(message=message):
                route = router.classify(message)
                self.assertEqual(route["action"], "operator")
                self.assertFalse(route["needs_confirmation"])

    def test_lookup_and_creative_tasks_stay_out_of_the_operator(self):
        for message, action in (
                ("napisz wiersz o morzu", "general"),
                ("przetłumacz to na angielski", "general"),
                ("streść tę notatkę", "notes"),
                ("znajdź notatkę o Operze GX", "notes"),
                ("sprawdź czy to prawda", "general"),
                ("przeanalizuj mój plan treningowy", "general"),
                ("przeanalizuj tę notatkę o bieganiu", "notes"),
                ("znajdź najlepszą restaurację w mieście", "web"),
                ("znajdź mi hotel", "web"),
                ("sprawdź mi ceny", "web")):
            with self.subTest(message=message):
                route = router.classify(message)
                self.assertEqual(route["action"], action)
                self.assertNotEqual(route["intent"], "operator")
        self.assertEqual(router.classify("znajdź plik raport.txt")["action"], "operator")
        self.assertEqual(router.classify("przeanalizuj plik server.py")["action"], "operator")
        self.assertEqual(router.classify("sprawdź stronę")["action"], "operator")

    def test_plain_open_command_with_a_named_app_is_an_operator_plan(self):
        # Reported: "Otwórz Opera GX" was answered with generic instructions
        # instead of opening the app. The router always classified it as an
        # Operator task; the streaming lane now honours that decision.
        route = router.classify("Otwórz Opera GX")
        self.assertEqual(route["intent"], "operator")
        self.assertEqual(route["action"], "operator")
        self.assertEqual(route["task"], "Otwórz Opera GX")
        self.assertFalse(route["needs_confirmation"])

    def test_notes_question_stays_in_chat(self):
        route = router.classify("Co w notatkach o Jarvisie?")
        self.assertEqual(route["action"], "notes")

    def test_explicit_operator_still_wins(self):
        route = router.classify("/operator ls -la")
        self.assertEqual(route["intent"], "operator")
        self.assertEqual(route["task"], "ls -la")

    def test_use_the_operator_prefix_routes_the_action_behind_it(self):
        # Reported: "Użyj operatora i otwórz Opera GX." fell into the general
        # chat lane, which has no computer access and answered that it could
        # not open anything. The action verb is no longer required first.
        for message, task in (
                ("Użyj operatora i otwórz Opera GX.", "otwórz Opera GX."),
                ("Czy możesz użyć operatora i otworzyć Opera GX?", "otworzyć Opera GX?"),
                ("użyj operatora, otwórz Operę GX", "otwórz Operę GX"),
                ("Use the operator and open Opera GX", "open Opera GX"),
                ("przekaż do operatora: otwórz Opera GX", "otwórz Opera GX"),
                ("zleć operatorowi otwarcie Opera GX", "otwarcie Opera GX")):
            with self.subTest(message=message):
                route = router.classify(message)
                self.assertEqual(route["intent"], "operator")
                self.assertEqual(route["action"], "operator")
                self.assertEqual(route["task"], task)
                self.assertFalse(route["needs_confirmation"])
                self.assertIn("approval", route["plan"])

    def test_multiline_and_please_operator_calls_keep_the_task(self):
        for message, task in (
                ("użyj operatora\nopen X", "open X"),
                ("Can you please use the operator and open Opera GX",
                 "open Opera GX")):
            with self.subTest(message=message):
                route = router.classify(message)
                self.assertEqual(route["action"], "operator")
                self.assertEqual(route["task"], task)

    def test_job_control_questions_are_answered_locally(self):
        cases = {
            "co robisz?": "status", "co robi operator": "status", "jaki status": "status",
            "co jest w kolejce": "queue", "które zadanie czeka": "queue", "kolejka": "queue",
            "zatrzymaj to zadanie": "stop", "zatrzymaj": "stop", "przerwij zadanie": "stop",
            "what are you doing": "status", "queue": "queue", "stop the job": "stop",
        }
        for message, control in cases.items():
            with self.subTest(message=message):
                route = router.classify(message)
                self.assertEqual(route["action"], "job_control")
                self.assertEqual(route["control"], control)
                self.assertNotEqual(route["action"], "operator")

    def test_polish_job_requests_answer_in_polish_without_diacritics(self):
        # "co robisz" has no diacritics; a language guess based on them answered
        # a Polish question in English.
        for message in ("co robisz", "co robisz?", "co jest w kolejce", "zatrzymaj to zadanie"):
            with self.subTest(message=message):
                self.assertEqual(router.classify(message)["lang"], "pl")
        for message in ("what are you doing", "queue", "stop the job"):
            with self.subTest(message=message):
                self.assertEqual(router.classify(message)["lang"], "en")

    def test_job_control_accepts_the_common_trailing_words(self):
        # A real microphone question was "What are you doing now?" — the anchored
        # pattern must accept the words people actually add.
        for message in ("what are you doing now", "what are you doing right now?",
                        "what are you doing at the moment", "co robisz teraz",
                        "co teraz robisz?", "co się teraz dzieje"):
            with self.subTest(message=message):
                self.assertEqual(router.classify(message)["action"], "job_control")

    def test_job_control_does_not_swallow_questions_or_tasks(self):
        # A local status shortcut must not capture real work or ordinary questions.
        for message in ("co robisz z plikiem config.json", "zatrzymaj proces Opera GX",
                        "co jest w kolejce zakupów", "status projektu w notatkach"):
            with self.subTest(message=message):
                self.assertNotEqual(router.classify(message)["action"], "job_control")

    def test_a_spoken_cancel_reaches_the_local_lane(self):
        # Live request: "cancel this youtube I don't want it" was answered by the
        # general lane with "this lane can't cancel or stop anything, sir". A
        # cancel that names its subject and adds a reason is still a cancel.
        for message, subject in (
                ("cancel this youtube I don't want it", "youtube"),
                ("Cancel this YouTube", "youtube"),
                ("stop the music", "music"),
                ("anuluj spotify", "spotify"),
                ("przerwij to zadanie", "zadanie")):
            with self.subTest(message=message):
                route = router.classify(message)
                self.assertEqual(route["action"], "job_control", route)
                self.assertEqual(route["control"], "stop")
                self.assertEqual(route.get("subject"), subject)

    def test_a_bare_cancel_still_stops_the_active_task(self):
        for message in ("cancel this", "cancel that", "cancel it please", "stop it",
                        "abort that", "anuluj to", "przestań", "wyłącz to",
                        "nie chcę tego", "nie chcę już tego", "zapomnij o tym"):
            with self.subTest(message=message):
                route = router.classify(message)
                self.assertEqual(route["action"], "job_control", route)
                self.assertEqual(route["control"], "stop")
                self.assertNotIn("subject", route)

    def test_cancel_everything_clears_the_queue_too(self):
        for message in ("cancel everything", "cancel all tasks", "anuluj wszystko"):
            with self.subTest(message=message):
                self.assertEqual(router.classify(message)["control"], "cancel_all")

    def test_a_cancel_never_swallows_a_real_task_or_a_subscription(self):
        for message in ("zatrzymaj proces Opera GX", "zamknij youtube", "cancel my subscription",
                        "stop the music and play jazz", "nie chcę iść do szkoły",
                        "forget it", "never mind"):
            with self.subTest(message=message):
                self.assertNotEqual(router.classify(message)["action"], "job_control")

    def test_playback_requests_reach_the_operator_not_the_chat(self):
        # Jarvis really can do this (media_control over MPRIS, app_control launch),
        # so "play music" must be routed to the Operator instead of answered as prose
        # and then refused with a protocol error.
        for message in ("Could you play music on Spotify for me, please?", "play some jazz",
                        "zagraj muzykę", "włącz Spotify", "pauzuj", "next track"):
            with self.subTest(message=message):
                route = router.classify(message)
                self.assertEqual(route["action"], "operator", route)

    def test_playback_words_in_a_question_do_not_start_the_operator(self):
        for message in ("co sądzisz o muzyce", "jak zagrać w tę grę?",
                        "jaka jest najlepsza playlista do biegania"):
            with self.subTest(message=message):
                self.assertNotEqual(router.classify(message)["action"], "operator")

    def test_operator_named_without_a_task_asks_for_one(self):
        for message in ("użyj operatora", "use the operator"):
            with self.subTest(message=message):
                route = router.classify(message)
                self.assertEqual(route["action"], "clarify")
                self.assertTrue(route["needs_confirmation"])
                self.assertIn("Operatora", route["plan"])

    def test_a_generic_subject_keeps_the_route_intact(self):
        # The router keeps the word ("przerwij to zadanie" → subject "zadanie");
        # the job-control lane is what must ignore a generic subject instead of
        # filtering the active task by it (see tests/test_job_control.py).
        route = router.classify("przerwij to zadanie")
        self.assertEqual(route["action"], "job_control")
        self.assertEqual(route.get("subject"), "zadanie")
        # A named subject still narrows the target.
        self.assertEqual(router.classify("zatrzymaj muzykę").get("subject"), "muzykę")

    def test_machine_state_goes_to_the_operator_not_the_chat(self):
        # Reported live: "sprawdź ile wolnego miejsca na dysku" was answered
        # with "this lane cannot read your disk" because the router treated it
        # as a web/notes question. The Operator owns system_monitor and the
        # file tools, so these belong to it.
        for message in ("Sprawdź ile wolnego miejsca jest na dysku i podaj wynik.",
                        "Sprawdź ile wolnej pamięci RAM zostało.",
                        "Sprawdź temperaturę CPU.",
                        "Pokaż listę procesów.",
                        "Policz pliki .md w Sejf.",
                        "Ile wolnej pamięci RAM mam teraz?",
                        "Ile wolnego miejsca na dysku?"):
            with self.subTest(message=message):
                route = router.classify(message)
                self.assertEqual(route["action"], "operator", route)
                self.assertFalse(route.get("destructive"))

    def test_a_general_knowledge_question_about_memory_stays_general(self):
        for message in ("Jak działa pamięć RAM?", "Co to jest dysk SSD?",
                        "Ile kosztuje procesor do laptopa?"):
            with self.subTest(message=message):
                self.assertNotEqual(router.classify(message)["action"], "operator")

    def test_destructive_tasks_are_flagged_and_need_a_second_message(self):
        for message in ("Usuń wszystkie pliki z katalogu ~/notes.",
                        "Usuń plik /tmp/x.txt.",
                        "delete everything in /tmp",
                        "wyczyść folder Pobrane"):
            with self.subTest(message=message):
                route = router.classify(message)
                self.assertEqual(route["action"], "operator", route)
                self.assertTrue(route.get("destructive"), route)
                self.assertFalse(route.get("confirmed"))

    def test_confirm_prefix_releases_a_destructive_task(self):
        route = router.classify("potwierdzam: usuń wszystkie pliki z katalogu ~/notes")
        self.assertEqual(route["action"], "operator")
        self.assertTrue(route["destructive"])
        self.assertTrue(route["confirmed"])
        self.assertEqual(route["task"], "usuń wszystkie pliki z katalogu ~/notes")

    def test_benign_bug_fix_idiom_scopes_only_itself(self):
        # The bug-fix idiom is benign only when it stands alone: scrubbing it
        # also removes its verb, so a conjunctive second target ("i plik
        # old.py") must keep the whole sentence destructive-flagged.
        for benign in ("usuń te błędy", "usuń te błędy z listy",
                       "usuń błędy w viewer/app.js", "usuń te błędy i przetestuj ponownie",
                       "delete these bugs", "usuń wszystkie bug, dodaj testy"):
            with self.subTest(message=benign):
                self.assertFalse(router._is_destructive(benign), benign)
        for destructive in ("usuń te błędy i plik old.py",
                            "usuń te błędy oraz folder Stare",
                             "usuń te błędy i wszystkie pliki .log",
                             "usuń błędy, potem skasuj plik x.txt",
                             "delete these bugs and /tmp/old",
                             "usuń te błędy i dane produkcyjne"):
            with self.subTest(message=destructive):
                self.assertTrue(router._is_destructive(destructive), destructive)

    def test_a_destructive_sentence_about_files_is_not_a_queue_cancel(self):
        # "usuń wszystko z kolejki" cancels work; "usuń wszystko z Sejfu" is a
        # filesystem task and must never be answered as a queue operation.
        self.assertEqual(router.classify("Usuń wszystko z kolejki")["action"], "job_control")
        self.assertEqual(router.classify("usuń wszystko z kolejki")["control"], "cancel_all")
        route = router.classify("usuń wszystko z katalogu ~/notes")
        self.assertEqual(route["action"], "operator")
        self.assertTrue(route["destructive"])

    def test_capability_questions_use_the_live_registry(self):
        for message in ("Co dokładnie potrafisz?", "Jakie masz narzędzia?",
                        "what can you do"):
            with self.subTest(message=message):
                route = router.classify(message)
                self.assertEqual(route["action"], "capabilities", route)
                self.assertEqual(route["nodes"] if "nodes" in route else [], [])

    def test_code_scan_and_audit_intent_routes_to_operator(self):
        cases = [
            "przeskanuj swój kod i powiedz co możesz ulepszyć",
            "przeanalizuj swój kod i powiedz co możesz ulepszyć",
            "przeskanuj kod jarvisa i powiedz co ulepszyć",
            "sprawdź kod jarvisa i powiedz co można ulepszyć",
            "zrób skan kodu",
            "przeanalizuj kod i powiedz co można poprawić",
            "zrób audyt kodu",
            "Can you analyze the code of Jarvis and tell me what can you upgrade?",
            "Scan your code and tell me what can you improve",
            "audit the Jarvis codebase and suggest upgrades",
            "zbadaj kod i wskaż optymalizacje",
            "przebadaj kod",
            "przebadaj kod Jarvisa i ulepsz co możesz",
        ]
        for msg in cases:
            with self.subTest(msg=msg):
                route = router.classify(msg)
                self.assertEqual(route["action"], "operator", f"Failed for {msg}")
                self.assertEqual(route["intent"], "operator", f"Failed for {msg}")
                self.assertFalse(route.get("needs_confirmation"))

    def test_operator_call_with_modern_prefixes_and_dispatch(self):
        cases = [
            ("OK, dispatch the operator to scan Jarvis for real candidates.", "scan Jarvis for real candidates."),
            ("odpal operatora żeby przeskanował kod", "przeskanował kod"),
            ("uruchom operatora aby sprawdził pliki", "sprawdził pliki"),
            ("niech operator sprawdzi kod i powie co ulepszyć", "sprawdzi kod i powie co ulepszyć"),
            ("dobra, odpal operatora i sprawdź błędy", "sprawdź błędy"),
        ]
        for msg, expected_task in cases:
            with self.subTest(msg=msg):
                route = router.classify(msg)
                self.assertEqual(route["action"], "operator", f"Failed for {msg}")
                self.assertEqual(route["intent"], "operator", f"Failed for {msg}")
                self.assertEqual(route["task"], expected_task)

    def test_bare_operator_call_with_filler_requests_clarification(self):
        for msg in ("Run the operator, bro.", "odpal operatora", "use the operator, please"):
            with self.subTest(msg=msg):
                route = router.classify(msg)
                self.assertEqual(route["action"], "clarify", f"Failed for {msg}")
                self.assertTrue(route.get("needs_confirmation"))


if __name__ == "__main__":
    unittest.main()
