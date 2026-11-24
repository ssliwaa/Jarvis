"""wayland_voice: dictation hygiene, sentence streaming and barge-in.

The system backends (wtype, ydotool, xdotool, gsettings, pactl) are patched
at the module boundary (shutil.which / subprocess.run / _ydotool_socket), so
every fallback branch is exercised without a Wayland session. Pinned: typing
only ever receives sanitized text (no CR/LF/controls can reach a shell key),
the chunker honours Polish abbreviations and forces cuts on newlines and the
max-chars budget, the barge-in controller is a generation counter that
terminates exactly the registered-and-current subprocesses, and DND answers
from env, GNOME settings or an active call.
"""
import os
import subprocess
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import wayland_voice as wv


def proc_result(returncode=0, stdout=""):
    return SimpleNamespace(returncode=returncode, stdout=stdout, stderr="")


class FakePopen:
    def __init__(self):
        self.terminated = 0

    def terminate(self):
        self.terminated += 1


class SanitizeTests(unittest.TestCase):
    def test_control_characters_never_reach_a_keyboard(self):
        cleaned = wv.sanitize_dictation_text("Cześć\nrm -rf /\r\x07świecie\x1b[0m")
        self.assertEqual(cleaned, "Cześć rm -rf / świecie [0m")
        self.assertNotIn("\n", cleaned)
        self.assertNotIn("\x07", cleaned)
        self.assertNotIn("\x1b", cleaned)
        self.assertEqual(wv.sanitize_dictation_text(""), "")
        self.assertEqual(wv.sanitize_dictation_text(None), "")
        self.assertEqual(wv.sanitize_dictation_text("   \t  x  ").replace("\t", " ").strip(), "x")


class TypeTextTests(unittest.TestCase):
    def run_type(self, text, which, caller, session="wayland",
                 env=None, socket="/run/user/1000/.ydotool_socket"):
        """caller(cmd, *args, **kwargs) stands in for subprocess.run itself."""
        with patch.object(wv.shutil, "which", side_effect=lambda name: which.get(name)), \
                patch.object(wv.subprocess, "run", side_effect=caller), \
                patch.object(wv, "_ydotool_socket", return_value=socket), \
                patch.dict(os.environ, env or {"XDG_SESSION_TYPE": session,
                                               "DISPLAY": ":0"}):
            return wv.type_text(text)

    def test_empty_text_short_circuits(self):
        sent = []

        def fail(*_a, **_k):
            sent.append("called!")
            raise AssertionError("nothing should run")

        for blank in ("", "   ", None):
            result = self.run_type(blank, {}, fail)
            self.assertEqual(result, {"typed": False, "backend": None, "safe_text": ""})
        self.assertEqual(sent, [])

    def test_wtype_is_the_native_first_choice(self):
        calls = []

        def fake_run(cmd, *args, **kwargs):
            calls.append(cmd)
            return proc_result(0)

        result = self.run_type("hello\nworld", {"wtype": "/usr/bin/wtype"}, fake_run)
        self.assertEqual(result, {"typed": True, "backend": "wtype",
                                  "safe_text": "hello world"})
        self.assertEqual(calls[0][:2], ["wtype", "--"])
        # Sanitized, newline-free text is the only thing ever dispatched.
        self.assertEqual(calls[0][2], "hello world")

    def test_wtype_failure_falls_back_to_ydotool(self):
        calls = []

        def fake_run(cmd, *args, **kwargs):
            calls.append((cmd, kwargs.get("env", {})))
            return proc_result(len(calls) == 1 and 1 or 0)

        result = self.run_type("tekst", {"wtype": "/w", "ydotool": "/y"}, fake_run)
        self.assertEqual(result["backend"], "ydotool")
        self.assertTrue(result["typed"])
        ydotool_call, env = calls[-1]
        self.assertEqual(ydotool_call[0], "ydotool")
        self.assertIn("type", ydotool_call)
        self.assertEqual(env["YDOTOOL_SOCKET"], "/run/user/1000/.ydotool_socket")

    def test_missing_socket_skips_ydotool(self):
        calls = []

        def fake_run(cmd, *args, **kwargs):
            calls.append(cmd)
            return proc_result(0)

        with patch.object(wv, "_ydotool_socket", return_value=None):
            with patch.object(wv.shutil, "which",
                              side_effect=lambda n: {"ydotool": "/y", "xdotool": "/x"}.get(n)), \
                    patch.object(wv.subprocess, "run", side_effect=fake_run), \
                    patch.dict(os.environ, {"DISPLAY": ":0"}):
                result = wv.type_text("abc")
        self.assertEqual(result["backend"], "xdotool")
        self.assertEqual([cmd[0] for cmd in calls], ["xdotool"])  # ydotool never ran

    def test_all_backends_failing_reports_honestly(self):
        def broken_run(cmd, *args, **kwargs):
            if cmd[0] == "xdotool":
                raise subprocess.TimeoutExpired(cmd, 10.0)
            return proc_result(1)

        result = self.run_type("x", {"wtype": "/w", "ydotool": "/y", "xdotool": "/x"},
                               broken_run)
        self.assertEqual(result, {"typed": False, "backend": None, "safe_text": "x"})


class ChunkerTests(unittest.TestCase):
    def test_clamps_and_empty_push(self):
        chunker = wv.SentenceStreamChunker(min_chars=-3, max_chars=7)
        self.assertEqual(chunker.min_chars, 6)
        self.assertEqual(chunker.max_chars, 60)
        self.assertEqual(chunker.push(""), [])
        self.assertEqual(chunker.flush(), [])

    def test_short_sentences_accumulate_until_min_reached(self):
        chunker = wv.SentenceStreamChunker(min_chars=18)   # default max 260
        ready = chunker.push("Ala ma kota. Pies biega dalej po parku.")
        # "Ala ma kota." alone is too short; the first emitted chunk carries both.
        self.assertEqual(ready, ["Ala ma kota. Pies biega dalej po parku."])

    def test_streaming_deltas_emit_complete_sentences_only(self):
        chunker = wv.SentenceStreamChunker(min_chars=6, max_chars=80)
        self.assertEqual(chunker.push("Ala ma "), [])
        # Both complete sentences (the end-of-buffer counts as a boundary) pop out.
        self.assertEqual(chunker.push("kota. I teraz pies."),
                         ["Ala ma kota.", "I teraz pies."])
        self.assertEqual(chunker.flush(), [])

    def test_polish_abbreviations_do_not_break_sentences(self):
        chunker = wv.SentenceStreamChunker(min_chars=6, max_chars=200)
        ready = chunker.push("Zgodnie z np. m.in. zasadą. Dalej idziemy.")
        # "np." and "m.in." never end a chunk; the next sentence still pops in push.
        self.assertEqual(ready, ["Zgodnie z np. m.in. zasadą.", "Dalej idziemy."])
        self.assertEqual(chunker.flush(), [])

    def test_a_bare_newline_ends_a_short_line_but_punctuation_does_not(self):
        chunker = wv.SentenceStreamChunker(min_chars=60, max_chars=200)
        # A period consumes the following \n as its separator: no forced cut.
        uncut = chunker.push("Hi.\n\nReszta zostaje w buforze jeszcze")
        self.assertEqual(uncut, [])
        chunker = wv.SentenceStreamChunker(min_chars=60, max_chars=200)
        # A newline itself is a hard boundary: 16 chars beat min 60.
        cut = chunker.push("Witam wszystkich\n\nReszta zostaje w buforze")
        self.assertEqual(cut, ["Witam wszystkich"])
        self.assertEqual(chunker.flush(), ["Reszta zostaje w buforze"])

    def test_max_chars_splits_on_the_last_space_without_losing_words(self):
        chunker = wv.SentenceStreamChunker(min_chars=6, max_chars=60)
        text = " ".join(["slowo"] * 20)              # 119 chars, no sentence end
        first = chunker.push(text)
        tail = chunker.flush()
        for piece in first + tail:
            self.assertLessEqual(len(piece), 60)
        # Only the boundary whitespace is dropped: every word survives, in order.
        self.assertEqual(" ".join(first + tail).split(), text.split())

    def test_long_unbroken_blob_cuts_hard_at_the_limit(self):
        chunker = wv.SentenceStreamChunker(min_chars=6, max_chars=60)
        pieces = chunker.push("x" * 150) + chunker.flush()
        self.assertEqual(sum(len(p) for p in pieces), 150)
        self.assertEqual([len(p) for p in pieces], [60, 60, 30])


class BargeInTests(unittest.TestCase):
    def setUp(self):
        self.ctrl = wv.BargeInController()

    def test_generation_counter_and_currentity(self):
        first = self.ctrl.begin_utterance()
        self.assertEqual(first, 1)
        self.assertTrue(self.ctrl.is_current(first))
        second = self.ctrl.begin_utterance()
        self.assertFalse(self.ctrl.is_current(first))
        self.assertTrue(self.ctrl.is_current(second))
        self.assertEqual(self.ctrl.generation, 2)

    def test_register_tracks_current_and_kills_stale(self):
        current = self.ctrl.begin_utterance()
        live, stale = FakePopen(), FakePopen()
        self.assertTrue(self.ctrl.register_proc(live, current))
        self.assertFalse(self.ctrl.register_proc(stale, current - 1))
        self.assertEqual(stale.terminated, 1)      # stale process is killed at the door
        self.assertEqual(live.terminated, 0)
        self.ctrl.unregister_proc(live)
        self.assertEqual(live.terminated, 0)        # unregister is a clean leave

    def test_interrupt_kills_registered_and_advances(self):
        gen = self.ctrl.begin_utterance()
        live = FakePopen()
        self.ctrl.register_proc(live, gen)
        published = []
        fake_bus = SimpleNamespace(publish=lambda topic, payload: published.append((topic, payload)))
        import sys
        with patch.dict(sys.modules, {"event_bus": fake_bus}):
            new_gen = self.ctrl.interrupt()
        self.assertEqual(new_gen, gen + 1)
        self.assertEqual(live.terminated, 1)
        self.assertFalse(self.ctrl.is_current(gen))
        self.assertEqual(published[0][0], "voice.barge_in")
        self.assertEqual(published[0][1]["stopped_procs"], 1)
        # A late registration against the old generation is refused and killed.
        late = FakePopen()
        self.assertFalse(self.ctrl.register_proc(late, gen))
        self.assertEqual(late.terminated, 1)

    def test_module_level_controller_exists_and_counts(self):
        self.assertIsInstance(wv.BARGE_IN, wv.BargeInController)
        before = wv.BARGE_IN.generation
        wv.BARGE_IN.begin_utterance()
        self.assertEqual(wv.BARGE_IN.generation, before + 1)


class DndStatusTests(unittest.TestCase):
    def test_env_dnd_wins_without_any_subprocess(self):
        for truthy in ("1", "true", "yes"):
            with patch.dict(os.environ, {"JARVIS_DND": truthy}), \
                    patch.object(wv.shutil, "which", side_effect=lambda name: None):
                self.assertEqual(wv.dnd_status(), {"dnd": True, "reason": "env_dnd"})
        # The check is case-sensitive: "YES" is not a truthy DND value.
        with patch.dict(os.environ, {"JARVIS_DND": "YES"}), \
                patch.object(wv.shutil, "which", side_effect=lambda name: None):
            self.assertEqual(wv.dnd_status(), {"dnd": False, "reason": "clear"})

    def test_gnome_dnd_and_clear_and_call_detection(self):
        def scenario(which, results, expected):
            env = {"JARVIS_DND": ""}
            with patch.dict(os.environ, env), \
                    patch.object(wv.shutil, "which",
                                 side_effect=lambda n: which.get(n)), \
                    patch.object(wv.subprocess, "run", side_effect=results):
                self.assertEqual(wv.dnd_status(), expected)

        # GNOME show-banners == false means DND.
        scenario({"gsettings": "/g", "pactl": "/p"},
                 [proc_result(0, "false\n")],
                 {"dnd": True, "reason": "gnome_do_not_disturb"})
        # Banners on, no pactl app: clear.
        scenario({"gsettings": "/g"},
                 [proc_result(0, "true\n")],
                 {"dnd": False, "reason": "clear"})
        # An un-corked firefox mic means an active call.
        scenario({"gsettings": "/g", "pactl": "/p"},
                 [proc_result(0, "true\n"), proc_result(0, "Corked: no, firefox")],
                 {"dnd": True, "reason": "active_call_mic"})
        # Uncorked but no known calling app: clear.
        scenario({"gsettings": "/g", "pactl": "/p"},
                 [proc_result(0, "true\n"), proc_result(0, "corked: no, mystery")],
                 {"dnd": False, "reason": "clear"})
        # No tools at all: clear.
        scenario({}, [], {"dnd": False, "reason": "clear"})


if __name__ == "__main__":
    unittest.main()
