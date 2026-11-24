"""Unit tests for the Piper neural TTS module."""
import io
import os
import unittest
SANDBOXED = os.environ.get("JARVIS_VERIFY_SANDBOX") == "1"
import wave

import tts_piper


@unittest.skipIf(SANDBOXED, "needs the developer's local env (vault/Hermes/Piper/desktop); skipped in CI")
class TestTTSPiper(unittest.TestCase):

    def test_available_and_status(self):
        self.assertTrue(tts_piper.available())
        status = tts_piper.status()
        self.assertEqual(status["engine"], "piper")
        self.assertTrue(status["available"])
        self.assertIn("en_GB-jarvis", status["default_voice"])
        self.assertTrue(len(status["voices"]) >= 1)

    def test_synthesize_valid_wav(self):
        audio = tts_piper.synthesize("Jarvis online.")
        self.assertIsInstance(audio, bytes)
        self.assertTrue(audio.startswith(b"RIFF"))
        self.assertIn(b"WAVE", audio[:16])

        # Verify WAV can be opened and parsed
        buf = io.BytesIO(audio)
        with wave.open(buf, "rb") as wf:
            self.assertEqual(wf.getnchannels(), 1)
            self.assertGreater(wf.getframerate(), 16000)
            self.assertGreater(wf.getnframes(), 0)

    def test_clean_text_validation(self):
        with self.assertRaises(tts_piper.TTSError):
            tts_piper.synthesize("")

        with self.assertRaises(tts_piper.TTSError):
            tts_piper.synthesize(12345)

        with self.assertRaises(tts_piper.TTSError):
            tts_piper.synthesize("Bad \x00 character")

    def test_unknown_voice_rejected(self):
        with self.assertRaises(tts_piper.TTSError):
            tts_piper.synthesize("Hello sir", voice="non-existent-voice")


if __name__ == "__main__":
    unittest.main()
