"""Local whisper.cpp transcription: paths, guards and a real Polish round trip."""
import array
import io
import math
import os
import tempfile
import unittest
import wave
from pathlib import Path
from unittest import mock

import stt


def wav_bytes(seconds, amplitude=0, rate=16000):
    """A 16 kHz mono PCM clip; zero amplitude is digital silence."""
    buffer = io.BytesIO()
    with wave.open(buffer, "wb") as writer:
        writer.setnchannels(1)
        writer.setsampwidth(2)
        writer.setframerate(rate)
        if amplitude:
            samples = array.array("h", [amplitude if index % 2 else -amplitude
                                        for index in range(int(rate * seconds))])
            writer.writeframes(samples.tobytes())
        else:
            writer.writeframes(b"\x00\x00" * int(rate * seconds))
    return buffer.getvalue()

SAMPLE = Path.home() / ".hermes" / "cache" / "scratch" / "stt-pl.webm"


class SttStatusTests(unittest.TestCase):
    def test_status_names_the_engine_and_every_dependency(self):
        status = stt.status()
        self.assertEqual(status["engine"], "whisper.cpp")
        for key in ("binary_present", "model_present", "ffmpeg_present", "available",
                    "model_size", "threads", "busy", "last"):
            self.assertIn(key, status)
        self.assertIsInstance(status["available"], bool)
        self.assertIn("audio_seconds", status["last"])
        self.assertIn("level_dbfs", status["last"])

    def test_missing_binary_is_reported_as_unavailable(self):
        with mock.patch.object(stt, "BIN", Path("/nonexistent/whisper-cli")):
            self.assertFalse(stt.available())
            with self.assertRaises(RuntimeError) as caught:
                stt.transcribe(b"x" * 2048)
        self.assertIn("not installed", str(caught.exception))


class SttGuardTests(unittest.TestCase):
    def test_empty_recording_is_rejected(self):
        with self.assertRaises(RuntimeError):
            stt.transcribe(b"")

    def test_oversized_recording_is_rejected(self):
        with mock.patch.object(stt, "MAX_BYTES", 1024):
            with self.assertRaises(RuntimeError) as caught:
                stt.transcribe(b"x" * 4096)
        self.assertIn("too large", str(caught.exception))

    def test_undecodable_bytes_fail_with_a_readable_message(self):
        if not stt.available():
            self.skipTest("whisper.cpp is not installed")
        with self.assertRaises(RuntimeError):
            stt.transcribe(b"not an audio file, just text" * 40)

    def test_prepare_take_gates_noise_before_any_recogniser(self):
        if not stt.available():
            self.skipTest("whisper.cpp is not installed")
        with self.assertRaises(RuntimeError) as caught:
            stt.prepare_take(wav_bytes(1.0))
        self.assertIn("silent", str(caught.exception).lower())
        with self.assertRaises(RuntimeError) as caught:
            stt.prepare_take(b"")
        self.assertIn("empty", str(caught.exception))

    def test_prepare_take_shapes_a_real_take_for_the_cloud(self):
        if not stt.available():
            self.skipTest("whisper.cpp is not installed")
        blob = wav_bytes(1.0, amplitude=20000)
        wav, stats = stt.prepare_take(blob)
        self.assertGreater(stats["audio_seconds"], 0.3)
        self.assertGreater(stats["peak_dbfs"], -30)
        self.assertTrue(wav.startswith(b"RIFF"))


class SttTuningTests(unittest.TestCase):
    def test_malformed_tuning_environment_falls_back_instead_of_crashing(self):
        with mock.patch.dict(os.environ, {"JARVIS_STT_TEST_FLOAT": "fast"}):
            self.assertEqual(stt._env_number("JARVIS_STT_TEST_FLOAT", 60.0, float), 60.0)
        with mock.patch.dict(os.environ, {"JARVIS_STT_TEST_INT": ""}):
            self.assertEqual(stt._env_number("JARVIS_STT_TEST_INT", 3, int), 3)
        with mock.patch.dict(os.environ, {"JARVIS_STT_TEST_INT": "-2"}):
            self.assertEqual(stt._env_number("JARVIS_STT_TEST_INT", 3, int), 3)
        self.assertLessEqual(stt.MAX_SECONDS, 300.0)
        self.assertGreaterEqual(stt.THREADS, 1)
        self.assertLessEqual(stt.THREADS, 16)

    def test_audio_context_keeps_a_wide_margin(self):
        with mock.patch.object(stt, "AUDIO_CTX_ENV", "auto"):
            self.assertEqual(stt.audio_context_for(3.2), 256)
            self.assertEqual(stt.audio_context_for(7.0), 512)
            self.assertEqual(stt.audio_context_for(11.0), 768)
            self.assertEqual(stt.audio_context_for(15.0), 1024)
            self.assertEqual(stt.audio_context_for(22.0), 1280)
            self.assertEqual(stt.audio_context_for(30.0), 0)
            self.assertEqual(stt.audio_context_for(0), 0)

    def test_audio_context_can_be_overridden_or_disabled(self):
        with mock.patch.object(stt, "AUDIO_CTX_ENV", "0"):
            self.assertEqual(stt.audio_context_for(3.2), 0)
        with mock.patch.object(stt, "AUDIO_CTX_ENV", "512"):
            self.assertEqual(stt.audio_context_for(15.0), 512)
        with mock.patch.object(stt, "AUDIO_CTX_ENV", "nonsense"):
            self.assertEqual(stt.audio_context_for(3.2), 256)

    def test_conversion_honours_the_caller_deadline(self):
        with mock.patch.object(stt.subprocess, "run") as run:
            run.return_value = mock.Mock(returncode=1, stderr=b"decode failed")
            with self.assertRaises(RuntimeError):
                stt._convert(Path("/tmp/in.bin"), Path("/tmp/out.wav"), 2.5)
            self.assertLessEqual(run.call_args.kwargs["timeout"], 2.5)

    def test_language_accepts_tags_and_rejects_flags(self):
        self.assertEqual(stt.normalise_language("pl-PL"), "pl")
        self.assertEqual(stt.normalise_language("en_GB"), "en")
        self.assertEqual(stt.normalise_language(None), "pl")
        with self.assertRaises(ValueError):
            stt.normalise_language("--prompt")

    def test_degenerate_repetition_is_detected(self):
        self.assertFalse(stt._looks_degenerate("krótkie pytanie"))
        self.assertTrue(stt._looks_degenerate("to samo zdanie " * 4))

    def test_politeness_formula_only_transcripts_are_noise(self):
        # Whisper's noise mold on a lifted quiet take: a fixed formula said
        # with great confidence. Real words always survive the whole-phrase gate.
        self.assertEqual(stt._clean("Dziękuję."), "")
        self.assertEqual(stt._clean("Dziękuję, dziękuję."), "")
        self.assertEqual(stt._clean("Zobaczcie. Zobaczcie."), "")
        self.assertEqual(stt._clean("Dziękuję. Jaki jest plan na dziś?"),
                         "Dziękuję. Jaki jest plan na dziś?")

    def test_polish_thanks_for_watching_is_a_noise_mold(self):
        # The sentence that actually reached the user from a quiet take was
        # "Dzięki za oglądanie!" — the Polish translation of whisper's
        # best-documented English noise mould. Every token must be in the set,
        # and a real question that merely opens with "dzięki" must survive.
        self.assertEqual(stt._clean("Dzięki za oglądanie!"), "")
        self.assertEqual(stt._clean("Dziękuję za oglądanie."), "")
        self.assertEqual(stt._clean("Dzięki za oglądanie, do zobaczenia!"), "")
        self.assertEqual(stt._clean("Dzięki, sprawdź plan na czwartek."),
                         "Dzięki, sprawdź plan na czwartek.")

    def test_subtitle_credit_hallucinations_are_noise(self):
        # A real 4.8 s question arrived as "Napisy by Jacek Makarewicz" —
        # Whisper's film-credit mold on near-silence, carried by names, so the
        # token list alone cannot hold it. Credits die whole; content that
        # merely mentions subtitles ("włącz napisy") or follows a credit with
        # a real sentence must survive.
        self.assertEqual(stt._clean("Napisy by Jacek Makarewicz"), "")
        self.assertEqual(stt._clean("Napisy: SETN"), "")
        self.assertEqual(stt._clean("Subtitles by the Amara.org community"), "")
        self.assertEqual(stt._clean("Włącz napisy by zrozumieć film"),
                         "Włącz napisy by zrozumieć film")
        self.assertEqual(stt._clean("Napisy by Jacek. Co się dzieje we Francji?"),
                         "Napisy by Jacek. Co się dzieje we Francji?")


class SttAudioShapeTests(unittest.TestCase):
    def test_silent_recording_is_named_as_silence(self):
        if not stt.available():
            self.skipTest("whisper.cpp is not installed")
        with self.assertRaises(RuntimeError) as caught:
            stt.transcribe(wav_bytes(1.0), "pl")
        self.assertIn("silent", str(caught.exception).lower())

    def test_quiet_audio_is_lifted_towards_the_speech_range(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "quiet.wav"
            path.write_bytes(wav_bytes(1.0, amplitude=300))
            stats = stt._shape_audio(path)
            self.assertGreater(stats["gain_db"], 6)
            self.assertLess(stats["peak_dbfs"], -30)
            with wave.open(str(path), "rb") as reader:
                samples = array.array("h")
                samples.frombytes(reader.readframes(reader.getnframes()))
            self.assertGreater(max(abs(value) for value in samples), 3000)

    def test_a_hopelessly_weak_take_still_carries_no_speech(self):
        # A digital near-silence (peak ~ -90 dBFS) must not be rescued into
        # amplified hiss: the gate stays above any lift the shaper can apply.
        if not stt.available():
            self.skipTest("whisper.cpp is not installed")
        with self.assertRaises(RuntimeError) as caught:
            stt.prepare_take(wav_bytes(1.0, amplitude=1))
        self.assertIn("too weak", str(caught.exception))
        self.assertIn("-90", str(caught.exception))

    def test_a_previously_undershooting_weak_take_is_rescued_by_the_gain(self):
        # A distant/laptop-mic voice peaks around -60 dBFS; the old +30 dB cap
        # left it at -30 dBFS (whisper strangled on it). The +48 dB cap must
        # lift such a take to a level whisper actually hears.
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "distant.wav"
            path.write_bytes(wav_bytes(1.0, amplitude=30))
            stats = stt._shape_audio(path)
            self.assertLess(stats["peak_dbfs"], -55)
            self.assertGreaterEqual(stats["gain_db"], 45)
            with wave.open(str(path), "rb") as reader:
                samples = array.array("h")
                samples.frombytes(reader.readframes(reader.getnframes()))
            rescued_peak = 20 * math.log10(max(abs(s) for s in samples) / 32768.0)
            self.assertGreater(rescued_peak, -20)

    def test_silence_around_speech_is_trimmed(self):
        rate = 16000
        silence = array.array("h", [0] * int(rate * 0.8))
        tone = array.array("h", [2000 if index % 2 else -2000
                                 for index in range(int(rate * 0.4))])
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "padded.wav"
            with wave.open(str(path), "wb") as writer:
                writer.setnchannels(1)
                writer.setsampwidth(2)
                writer.setframerate(rate)
                writer.writeframes(silence.tobytes() + tone.tobytes() + silence.tobytes())
            stats = stt._shape_audio(path)
        self.assertAlmostEqual(stats["audio_seconds"], 0.7, delta=0.1)


class SttCleanupTests(unittest.TestCase):
    def test_repeated_sentence_is_collapsed(self):
        sentence = "To samo zdanie jest tutaj."
        self.assertEqual(stt._clean(sentence + " " + sentence), sentence)

    def test_noise_tags_alone_are_not_an_answer(self):
        self.assertEqual(stt._clean("[Muzyka] [Muzyka] [Muzyka]"), "")

    def test_a_short_repeated_answer_is_preserved(self):
        self.assertEqual(stt._clean("Yes. Yes."), "Yes. Yes.")

    def test_installed_small_model_is_preferred(self):
        with tempfile.TemporaryDirectory() as folder:
            models = Path(folder) / "models"
            models.mkdir()
            (models / "ggml-base-q5_1.bin").write_bytes(b"base")
            (models / "ggml-small-q5_1.bin").write_bytes(b"small")
            with mock.patch.object(stt, "TOOLS", Path(folder)):
                self.assertEqual(stt._default_model().name, "ggml-small-q5_1.bin")


@unittest.skipUnless(os.environ.get("JARVIS_STT_LIVE") == "1", "set JARVIS_STT_LIVE=1 to run the model")
class SttLiveTests(unittest.TestCase):
    """Feeds a Polish sentence recorded through the same Opus/WebM path MediaRecorder uses."""

    def test_polish_sentence_survives_the_round_trip(self):
        if not SAMPLE.is_file():
            self.skipTest(f"sample missing: {SAMPLE}")
        result = stt.transcribe(SAMPLE.read_bytes(), "pl")
        text = result["text"].lower()
        self.assertTrue(text)
        for word in ("plan", "treningowy"):
            self.assertIn(word, text)
        self.assertLess(result["seconds"], 60)


if __name__ == "__main__":
    unittest.main()
