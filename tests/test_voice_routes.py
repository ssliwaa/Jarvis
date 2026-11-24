"""voice_routes: dictation, barge-in and sentence-chunk TTS route contracts.

`wayland_voice` is a live system module; every test patches the pieces the
routes touch (sanitize, type_text, BARGE_IN, SentenceStreamChunker, dnd_status)
so the HTTP contracts are pinned without a Wayland session: sanitised text is
what reaches clipboard and typing, empty dictation is refused, chunk bounds
answer 400 instead of a ValueError on a 500, and barge-in bumps generations.
"""
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import voice_routes
import wayland_voice
from errors import AppError


class FakeHandler:
    def __init__(self, body=None, fail_origin=False):
        self.body = body if body is not None else {}
        self.fail_origin = fail_origin
        self.origin_checked = 0
        self.sent = []
        self.empty_body_reads = 0

    def validate_origin(self):
        self.origin_checked += 1
        if self.fail_origin:
            raise PermissionError("cross-origin")

    def send_json(self, status, payload):
        self.sent.append((status, payload))

    def read_json_body(self):
        return self.body

    def read_empty_body(self):
        self.empty_body_reads += 1
        return b""


class FakeBargeIn:
    def __init__(self):
        self.generation = 7

    def interrupt(self):
        self.generation += 1
        return self.generation

    def begin_utterance(self):
        self.generation += 1
        return self.generation


class FakeChunker:
    """Records the bounds the route chose; deterministic chunk output."""
    last_params = None

    def __init__(self, min_chars=18, max_chars=260):
        FakeChunker.last_params = (min_chars, max_chars)
        self.buf = ""

    def push(self, delta):
        self.buf = str(delta)
        return ["chunk-a", "chunk-b"] if self.buf else []

    def flush(self):
        return ["chunk-c"] if self.buf else []


class RouteTestCase(unittest.TestCase):
    def setUp(self):
        self.barge = FakeBargeIn()
        self.typed = {"typed": True, "backend": "wtype"}
        patches = [
            patch.object(wayland_voice, "BARGE_IN", self.barge),
            patch.object(wayland_voice, "SentenceStreamChunker", FakeChunker),
            patch.object(wayland_voice, "sanitize_dictation_text",
                         side_effect=self.sanitize),
            patch.object(wayland_voice, "type_text", side_effect=self.type_text),
            patch.object(wayland_voice, "dnd_status",
                         side_effect=lambda: {"dnd": True, "until": 123.5}),
        ]
        for item in patches:
            item.start()
            self.addCleanup(item.stop)
        self.sanitized_seen = []
        self.typed_seen = []
        FakeChunker.last_params = None

    def sanitize(self, raw):
        self.sanitized_seen.append(raw)
        return str(raw or "").replace("\n", " ").strip()

    def type_text(self, text):
        self.typed_seen.append(text)
        return dict(self.typed)


class ClipboardStub:
    def __init__(self, fail=False):
        self.fail = fail
        self.written = []

    def write(self, text):
        if self.fail:
            raise RuntimeError("clipboard unavailable")
        self.written.append(text)


class GetVoiceTests(RouteTestCase):
    def test_dnd_status_served_with_origin_check(self):
        handler = FakeHandler()
        handled = voice_routes.get_voice(handler, SimpleNamespace(path="/voice/dnd"))
        self.assertTrue(handled)
        self.assertEqual(handler.origin_checked, 1)
        self.assertEqual(handler.sent, [(200, {"ok": True, "dnd": True,
                                               "until": 123.5,
                                               "barge_in_generation": 7})])

    def test_other_paths_are_ignored(self):
        handler = FakeHandler()
        self.assertFalse(voice_routes.get_voice(handler, SimpleNamespace(path="/voice/dictate-wayland")))
        self.assertEqual(handler.sent, [])
        self.assertEqual(handler.origin_checked, 0)


class BargeInTests(RouteTestCase):
    def test_barge_in_reads_empty_body_and_bumps_generation(self):
        handler = FakeHandler()
        handled = voice_routes.post_voice(handler, "/voice/barge-in")
        self.assertTrue(handled)
        self.assertEqual(handler.empty_body_reads, 1)
        status, payload = handler.sent[0]
        self.assertEqual(status, 200)
        self.assertEqual(payload, {"ok": True, "interrupted": True, "generation": 8})


class DictationTests(RouteTestCase):
    def test_dictation_routes_sanitized_text_to_clipboard_and_typing(self):
        handler = FakeHandler(body={"text": "Cześć\nświecie"})
        clipboard = ClipboardStub()
        handled = voice_routes.post_voice(handler, "/voice/dictate-wayland",
                                          clipboard_mod=clipboard)
        self.assertTrue(handled)
        self.assertEqual(handler.sent[0][1], {"ok": True, "dictated": True,
                                              "copied_to_clipboard": True,
                                              "typed": True,
                                              "typing_backend": "wtype"})
        # Both backends received the sanitized text, never the raw one.
        self.assertEqual(clipboard.written, ["Cześć świecie"])
        self.assertEqual(self.typed_seen, ["Cześć świecie"])

    def test_clipboard_failure_falls_back_to_typing_still_trying(self):
        handler = FakeHandler(body={"text": "tekst"})
        clipboard = ClipboardStub(fail=True)
        handled = voice_routes.post_voice(handler, "/voice/dictate-wayland",
                                          clipboard_mod=clipboard)
        self.assertTrue(handled)
        status, payload = handler.sent[0]
        self.assertEqual(status, 200)
        self.assertTrue(payload["dictated"])           # typed saved the day
        self.assertFalse(payload["copied_to_clipboard"])
        self.assertEqual(len(self.typed_seen), 1)      # typing still attempted

    def test_empty_dictation_is_refused_with_400(self):
        handler = FakeHandler(body={"text": "   "})
        with self.assertRaises(AppError) as caught:
            voice_routes.post_voice(handler, "/voice/dictate-wayland")
        self.assertEqual(caught.exception.status, 400)
        self.assertEqual(caught.exception.code, "INVALID_DICTATION")

    def test_dictate_to_desktop_without_clipboard(self):
        result = voice_routes.dictate_to_desktop("plain", clipboard_mod=None)
        self.assertEqual(result, {"dictated": True, "copied_to_clipboard": False,
                                  "typed": True, "typing_backend": "wtype"})
        # And when typing fails too, dictated is honestly False.
        with patch.object(wayland_voice, "type_text",
                          side_effect=lambda text: {"typed": False, "backend": "none"}):
            failed = voice_routes.dictate_to_desktop("plain", clipboard_mod=None)
        self.assertEqual(failed, {"dictated": False, "copied_to_clipboard": False,
                                 "typed": False, "typing_backend": "none"})


class TtsChunksTests(RouteTestCase):
    def test_chunking_serves_chunks_with_generation(self):
        handler = FakeHandler(body={"text": "Długa wypowiedź do syntezatora."})
        handled = voice_routes.post_voice(handler, "/tts/chunks")
        self.assertTrue(handled)
        status, payload = handler.sent[0]
        self.assertEqual(status, 200)
        self.assertEqual(payload, {"ok": True,
                                  "chunks": ["chunk-a", "chunk-b", "chunk-c"],
                                  "count": 3, "generation": 8})
        self.assertEqual(FakeChunker.last_params, (18, 260))  # defaults

    def test_bounds_zero_or_absent_fall_back_to_defaults(self):
        for body in ({"min_chars": 0, "max_chars": 0}, {}, {"min_chars": None}):
            FakeChunker.last_params = None
            handler = FakeHandler(body=body)
            self.assertTrue(voice_routes.post_voice(handler, "/tts/chunks"))
            self.assertEqual(FakeChunker.last_params, (18, 260))

    def test_numeric_bounds_are_passed_through(self):
        handler = FakeHandler(body={"text": "x", "min_chars": "40", "max_chars": 500})
        self.assertTrue(voice_routes.post_voice(handler, "/tts/chunks"))
        self.assertEqual(FakeChunker.last_params, (40, 500))

    def test_garbage_bounds_answer_400_not_500(self):
        handler = FakeHandler(body={"text": "x", "min_chars": "duzo"})
        with self.assertRaises(AppError) as caught:
            voice_routes.post_voice(handler, "/tts/chunks")
        self.assertEqual(caught.exception.status, 400)
        self.assertEqual(caught.exception.code, "INVALID_TTS_PARAMS")
        self.assertEqual(handler.sent, [])  # nothing half-served


class UnsupportedPathTests(RouteTestCase):
    def test_unknown_post_path_is_ignored(self):
        handler = FakeHandler()
        self.assertFalse(voice_routes.post_voice(handler, "/voice/mystery"))
        self.assertEqual(handler.sent, [])
        self.assertEqual(self.barge.generation, 7)  # nothing triggered


if __name__ == "__main__":
    unittest.main()
