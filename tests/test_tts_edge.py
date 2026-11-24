"""Offline contracts for the optional Edge TTS bridge."""
import unittest
from unittest.mock import patch

import tts_edge


class FakeCommunicate:
    calls = []

    def __init__(self, text, voice):
        self.text = text
        self.voice = voice
        FakeCommunicate.calls.append((text, voice))

    async def stream(self):
        yield {"type": "audio", "data": b"\xff\xf3fake-mp3"}


class EdgeTTSTests(unittest.TestCase):
    def setUp(self):
        FakeCommunicate.calls.clear()
        tts_edge.clear_cache()

    def test_synthesize_collects_audio_and_uses_the_approved_voice(self):
        with patch("edge_tts.Communicate", FakeCommunicate):
            audio = tts_edge.synthesize("Good evening, sir.", "en-GB-RyanNeural")
            second = tts_edge.synthesize("Good evening, sir.", "en-GB-RyanNeural")
        self.assertTrue(audio.startswith(b"\xff\xf3"))
        self.assertEqual(audio, second)
        self.assertEqual(FakeCommunicate.calls, [("Good evening, sir.", "en-GB-RyanNeural")])

    def test_invalid_text_and_voice_fail_before_network(self):
        for text, voice in [
            ("", None),
            ("x" * (tts_edge.MAX_CHARS + 1), None),
            ("bad\x00text", None),
            ("hello", "not-a-voice"),
        ]:
            with self.subTest(text=text[:20], voice=voice):
                with self.assertRaises(tts_edge.TTSError) as caught:
                    tts_edge.synthesize(text, voice)
                self.assertEqual(caught.exception.status, 400)

    def test_empty_provider_stream_is_a_failure(self):
        class Silent:
            def __init__(self, text, voice):
                pass

            async def stream(self):
                yield {"type": "metadata", "data": b"nothing"}

        with patch("edge_tts.Communicate", Silent):
            with self.assertRaises(tts_edge.TTSError):
                tts_edge.synthesize("hello", tts_edge.DEFAULT_VOICE)

    def test_status_exposes_only_public_voice_metadata(self):
        status = tts_edge.status()
        self.assertEqual(status["engine"], "edge-tts")
        self.assertTrue(status["available"])
        self.assertEqual(status["default_voice"], "en-GB-RyanNeural")
        self.assertTrue(any(voice["id"] == "pl-PL-MarekNeural" for voice in status["voices"]))
        self.assertNotIn("/home/", str(status))


if __name__ == "__main__":
    unittest.main()
