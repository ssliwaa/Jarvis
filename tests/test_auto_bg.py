"""auto_bg: the natural-language background-lane detector contract.

`should_run_in_background` decides which spoken/typed tasks may run on the
non-blocking BackgroundLane; `strip_bg_prefix` scrubs the "/bg" style prefix
before the lane sees the task. The destructive gate keeps deletes, disk
formats and table drops on the foreground unless the user force-routes them
with an explicit "/bg" prefix — benign words ("w formacie") must not trip it.
"""
import unittest

from auto_bg import should_run_in_background, strip_bg_prefix


class StripPrefixTests(unittest.TestCase):
    def test_strips_bg_prefixes_with_and_without_colon(self):
        cases = {
            "/bg zrób raport": "zrób raport",
            "/bg: zrób raport": "zrób raport",
            "/bg, zrób raport": "zrób raport",
            "  /bg:  zadanie  ": "zadanie",
            "/BG ZRÓB RAPORT": "ZRÓB RAPORT",
            "/background deploy": "deploy",
            "/background: deploy": "deploy",
            "w tle: zrób raport": "zrób raport",
            "na tle: analiza": "analiza",
            "uruchom w tle skan": "skan",
            "zrób w tle raport": "raport",
            "zrob w tle raport": "raport",
            "odpal w tle analizę": "analizę",
            "run in background deploy": "deploy",
            "run in the background: deploy": "deploy",
        }
        for raw, wanted in cases.items():
            self.assertEqual(strip_bg_prefix(raw), wanted, repr(raw))

    def test_leaves_non_prefix_text_alone(self):
        # Only a leading prefix is removed: mid-sentence mentions stay.
        self.assertEqual(strip_bg_prefix("zrób raport w tle"), "zrób raport w tle")
        self.assertEqual(strip_bg_prefix("przeanalizuj /bg w dokumentacji"), "przeanalizuj /bg w dokumentacji")
        self.assertEqual(strip_bg_prefix("zrób to, ale dopiero wieczorem"), "zrób to, ale dopiero wieczorem")

    def test_empty_and_degenerate_inputs(self):
        self.assertEqual(strip_bg_prefix(""), "")
        self.assertEqual(strip_bg_prefix(None), "")
        self.assertEqual(strip_bg_prefix(42), "42")
        # A prefix with no task falls back to the original text, never ''.
        self.assertEqual(strip_bg_prefix("/bg"), "/bg")
        self.assertEqual(strip_bg_prefix("   "), "")


class ExplicitBackgroundTests(unittest.TestCase):
    def test_natural_language_phrases_trigger_bg_with_reason(self):
        cases = [
            "poszukaj czegoś w tle",
            "na tle przetwórz dane",
            "odpal to w bekgrandzie",
            "przetwórz równolegle",
            "przetworz rownolegle",
            "zrób to asynchronicznie",
            "run it asynchronously",
            "run in the background please",
            "po cichu pobierz archiwum",
            "nie blokuj mnie tym",
            "bez blokowania pobierz dane",
            "fetch it without blocking",
            "w międzyczasie sprawdź pocztę",
            "w miedzyczasie sprawdz poczte",
            "meanwhile cook the dataset",
            "in the meantime index notes",
        ]
        for text in cases:
            run, reason = should_run_in_background(text)
            self.assertTrue(run, text)
            self.assertEqual(reason, "explicit natural-language background phrase")

    def test_completion_notification_phrases_trigger_bg(self):
        cases = [
            "daj mi znać jak skończysz",
            "daj znać gdy skończysz",
            "daj mi znac kiedy skonczysz",
            "zawołaj jak skończysz",
            "powiadom mnie gdy skończysz",
            "powiadom kiedy skończysz",
            "let me know when you're done",
            "let me know when it's done",
            "notify me when done",
        ]
        for text in cases:
            run, reason = should_run_in_background(text)
            self.assertTrue(run, text)
            self.assertEqual(reason, "explicit natural-language background phrase")

    def test_explicit_prefix_with_colon_routes_too(self):
        # EXPLICIT_BG_RE does not see the colon form; the /bg prefix does.
        self.assertEqual(should_run_in_background("/bg zrób raport"),
                         (True, "explicit natural-language background phrase"))
        self.assertEqual(should_run_in_background("/bg: zrób raport"),
                         (True, "explicit natural-language background phrase"))

    def test_empty_task_never_routes_to_bg(self):
        self.assertEqual(should_run_in_background(""), (False, ""))
        self.assertEqual(should_run_in_background(None), (False, ""))
        self.assertEqual(should_run_in_background("   "), (False, ""))


class DestructiveGateTests(unittest.TestCase):
    def test_destructive_verbs_stay_in_foreground_even_when_bg_is_implied(self):
        cases = [
            "usuń plik tmp.dat",
            "skasuj katalog docs",
            "wymaż wszystkie dane",
            "rm -rf build",
            "drop table users",
            "wipe the cache directory",
            "sformatuj dysk",
            "sformatować dysk",
            "sformatowanie dysku",
            "format c:",
            "format d: please",
            # Even an explicit "w tle" cannot move destructive work off-stage.
            "usuń plik w tle",
            "skasuj plik w tle",
            "sformatuj dysk w tle",
            "sformatowanie dysku w tle",
            "format c: w tle",
            "rm -rf build w tle",
        ]
        for text in cases:
            self.assertEqual(should_run_in_background(text), (False, ""), text)

    def test_explicit_bg_prefix_still_routes_destructive_work(self):
        self.assertEqual(should_run_in_background("/bg usuń plik tmp.dat"),
                         (True, "explicit /bg prefix"))
        self.assertEqual(should_run_in_background("/background skasuj build"),
                         (True, "explicit /bg prefix"))

    def test_benign_format_wording_no_longer_trips_the_gate(self):
        # "format" alone used to swallow tasks; only real disk formatting does.
        self.assertEqual(should_run_in_background("pobierz dane w formacie json w tle"),
                         (True, "explicit natural-language background phrase"))
        self.assertEqual(should_run_in_background("zbuduj stronę w formacie mobilnym")[0], True)
        self.assertEqual(should_run_in_background("sformatowanie tekstu w tle"),
                         (True, "explicit natural-language background phrase"))
        # Conservative by design: the bare formatowanie-verb stays foreground.
        self.assertEqual(should_run_in_background("formatować kod w tle"), (False, ""))


class ForegroundForceTests(unittest.TestCase):
    def test_page_and_desktop_actions_need_the_foreground(self):
        cases = [
            "kliknij przycisk zapisz",
            "wypełnij formularz w przeglądarce",
            "przewiń stronę w dół",
            "zrób zrzut ekranu",
            "otwórz kartę chrome",
            "otwórz spotify",
            "puść muzykę",
            "pogłoś trochę",
            "wycisz pod koniec",
            "click the green button",
            "scroll to the footer",
            "take a screenshot of the page",
            "bring to front the settings window",
            "play music quietly",
        ]
        for text in cases:
            self.assertEqual(should_run_in_background(text), (False, ""), text)

    def test_explicit_background_phrase_wins_over_foreground_force(self):
        # The user said "w tle" / "nie blokując": their words outrank the
        # page-action heuristic and the lane decides whether to reject it.
        run, _ = should_run_in_background("zrób zrzut ekranu, nie blokując mnie")
        self.assertTrue(run)


class AgentDelegationTests(unittest.TestCase):
    def test_delegating_work_to_an_external_agent_runs_in_bg(self):
        cases = [
            "powiedz antigravity żeby zbudował stronę",
            "antigravity zbuduj aplikację webową",
            "agy napraw bug w teście",
            "claude code zoptymalizuj ten moduł",
            "opencode zaimplementuj narzędzie",
            "niech hermes napisze testy",
            "have opencode build the tools",
            "ask claude to fix the bug",
            "tell antygravity to refactor the page",
        ]
        for text in cases:
            self.assertEqual(should_run_in_background(text),
                             (True, "external coding agent delegation"), text)

    def test_status_and_version_checks_stay_in_foreground(self):
        cases = [
            "sprawdź status antigravity",
            "pokaż wersję hersa",
            "czy działa opencode",
            "jaki jest status claude code",
            "check if opencode is available",
            "przetestuj agenta claude",
        ]
        for text in cases:
            self.assertEqual(should_run_in_background(text), (False, ""), text)

    def test_work_verb_requires_an_agent_name(self):
        # "zbuduj stronę" alone is handled by the heavy-build rule or nothing.
        self.assertEqual(should_run_in_background("napisz do kogoś maila"), (False, ""))


class HeavyBuildTests(unittest.TestCase):
    def test_website_and_app_builds_route_to_bg(self):
        cases = [
            "zbuduj responsywną stronę portfolio",
            "stwórz portfolio",
            "zaprojektuj landing page",
            "zbuduj aplikację webową",
            "create a landing page",
            "generate the webapp",
            "develop a website for the lab",
            "wygeneruj stronę główną",
        ]
        for text in cases:
            run, reason = should_run_in_background(text)
            self.assertTrue(run, text)
            self.assertEqual(reason, "long-running website/app build")

    def test_foreground_busy_flips_the_heavy_build_reason(self):
        run, reason = should_run_in_background("zbuduj stronę portfolio", foreground_busy=True)
        self.assertTrue(run)
        self.assertEqual(reason, "foreground busy; heavy build")
        # A busy foreground slot alone must not push ordinary work off-stage.
        self.assertEqual(should_run_in_background("napisz notatkę z zebrania",
                                                  foreground_busy=True), (False, ""))

    def test_ordinary_tasks_stay_in_foreground(self):
        cases = [
            "napisz raport z wczoraj",
            "poszukaj notatek o jarvisie",
            "opowiedz kawał",
            "która jest godzina",
        ]
        for text in cases:
            self.assertEqual(should_run_in_background(text), (False, ""), text)


if __name__ == "__main__":
    unittest.main()
