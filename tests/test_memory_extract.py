"""Fact extraction: parsing, validation and the trust routing."""
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

import memory_extract
from memory_store import MemoryStore


class FakeClient:
    def __init__(self, reply):
        self.reply = reply
        self.calls = []

    @property
    def messages(self):
        return self

    def create(self, **kwargs):
        self.calls.append(kwargs)
        block = SimpleNamespace(type="text", text=self.reply)
        return SimpleNamespace(content=[block])


class ParseTests(unittest.TestCase):
    def test_plain_json_is_accepted(self):
        facts = memory_extract.parse('{"facts":[{"category":"identity","key":"miasto","value":"Testville"}]}')
        self.assertEqual(len(facts), 1)

    def test_fenced_json_is_accepted(self):
        raw = 'Oto wynik:\n```json\n{"facts":[{"category":"identity","key":"miasto","value":"Testville"}]}\n```'
        self.assertEqual(memory_extract.parse(raw)[0]["key"], "miasto")

    def test_garbage_returns_nothing(self):
        for raw in ("", "brak", "{nie json}", '{"facts": "nie lista"}'):
            self.assertEqual(memory_extract.parse(raw), [])

    def test_validation_drops_bad_rows_and_clamps_confidence(self):
        facts = memory_extract.validate([
            {"category": "identity", "key": "miasto", "value": "Testville", "confidence": 5},
            {"category": "wymyslone", "key": "x", "value": "y"},
            {"category": "identity", "key": "", "value": "y"},
            {"category": "identity", "key": "puste", "value": ""},
        ])
        self.assertEqual(len(facts), 1)
        self.assertEqual(facts[0]["confidence"], 1.0)
        self.assertEqual(facts[0]["key"], "miasto")

    def test_duplicates_within_one_reply_are_collapsed(self):
        facts = memory_extract.validate([
            {"category": "identity", "key": "miasto", "value": "Testville", "confidence": 0.9},
            {"category": "identity", "key": "miasto", "value": "testville", "confidence": 0.9},
        ])
        self.assertEqual(len(facts), 1)


class ExtractTests(unittest.TestCase):
    def test_extract_uses_the_model_reply(self):
        client = FakeClient('{"facts":[{"category":"identity","key":"miasto","value":"Testville",'
                            '"confidence":0.9,"quote":"Mieszkam w Testville"}]}')
        facts = memory_extract.extract(client, "Mieszkam w Testville od zawsze, dojeżdżam do szkoły.")
        self.assertEqual(facts[0]["value"], "Testville")
        self.assertEqual(facts[0]["quote"], "Mieszkam w Testville")
        self.assertEqual(client.calls[0]["max_tokens"], 400)

    def test_extract_without_a_client_is_empty(self):
        self.assertEqual(memory_extract.extract(None, "cokolwiek"), [])


class GateTests(unittest.TestCase):
    def test_a_question_about_the_vault_is_not_captured(self):
        self.assertFalse(memory_extract.should_capture(
            'In the note titled "plan-treningowy-bieg", what is one concrete practical fact?'))

    def test_a_first_person_statement_is_captured(self):
        self.assertTrue(memory_extract.should_capture(
            "Mieszkam w Testville i dojeżdżam pociągiem do szkoły w Przykładowie."))
        self.assertTrue(memory_extract.should_capture("Mieszkam w Testville."))

    def test_a_short_reply_is_skipped(self):
        self.assertFalse(memory_extract.should_capture("say something"))
        self.assertFalse(memory_extract.should_capture("dzięki"))

    def test_a_command_is_skipped(self):
        self.assertFalse(memory_extract.should_capture("/run " + "x" * 60))

    def test_a_self_directed_question_still_counts(self):
        self.assertTrue(memory_extract.should_capture(
            "Czy pamiętasz, że mieszkam w Testville i chodzę do szkoły w Przykładowie?"))


class RoutingTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = MemoryStore(Path(self.tmp.name) / "memory.db")
        self.addCleanup(self.store.close)

    def facts(self):
        return [
            {"category": "identity", "key": "miasto", "value": "Testville",
             "confidence": 0.9, "quote": "Mieszkam w Testville"},
            {"category": "preferences", "key": "kawa", "value": "bez cukru",
             "confidence": 0.9, "quote": "Wolę kawę bez cukru"},
            {"category": "rules", "key": "krotko", "value": "odpowiadaj krótko",
             "confidence": 0.95, "quote": "Odpowiadaj krótko"},
        ]

    def test_objective_facts_are_written_and_the_rest_wait_for_approval(self):
        result = memory_extract.capture(self.store, self.facts())
        self.assertEqual([row["key"] for row in result["written"]], ["miasto"])
        self.assertEqual(sorted(row["key"] for row in result["proposed"]), ["kawa", "krotko"])
        self.assertEqual(len(self.store.list()), 1)
        self.assertEqual(len(self.store.suggestions()), 2)

    def test_a_rule_is_never_written_automatically(self):
        result = memory_extract.capture(self.store, [self.facts()[2]])
        self.assertEqual(result["written"], [])
        self.assertEqual(len(result["proposed"]), 1)
        self.assertEqual(self.store.list(), [])

    def test_low_confidence_identity_is_only_proposed(self):
        fact = dict(self.facts()[0], confidence=0.4)
        result = memory_extract.capture(self.store, [fact])
        self.assertEqual(result["written"], [])
        self.assertEqual(len(self.store.suggestions()), 1)

    def test_the_same_fact_twice_does_not_duplicate_a_suggestion(self):
        memory_extract.capture(self.store, [self.facts()[1]])
        memory_extract.capture(self.store, [self.facts()[1]])
        self.assertEqual(len(self.store.suggestions()), 1)

    def test_accepting_a_suggestion_keeps_the_evidence(self):
        memory_extract.capture(self.store, [self.facts()[1]])
        suggestion = self.store.suggestions()[0]
        saved = self.store.accept_suggestion(suggestion["id"])
        self.assertEqual(saved["confidence"], 0.9)
        self.assertEqual(saved["quote"], "Wolę kawę bez cukru")
        self.assertEqual(saved["source"], "chat")


if __name__ == "__main__":
    unittest.main()
