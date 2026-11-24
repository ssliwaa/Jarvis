"""Groq cloud transcription: key discovery, request shape and error mapping."""
import os
import unittest
from unittest import mock

import stt_cloud


class Reader:
    """A minimal stand-in for an httpx2 Response."""
    def __init__(self, payload=None, status=200, raw=""):
        self.status_code = status
        self._payload = payload
        self.text = raw if not isinstance(payload, dict) else ""

    def json(self):
        if self._payload is None:
            raise ValueError("no json")
        return self._payload


class KeyDiscoveryTests(unittest.TestCase):
    def setUp(self):
        for name in ("JARVIS_GROQ_API_KEY", "GROQ_API_KEY"):
            os.environ.pop(name, None)

    def tearDown(self):
        os.environ.pop("JARVIS_GROQ_API_KEY", None)
        os.environ.pop("GROQ_API_KEY", None)

    def test_without_a_key_the_engine_is_unavailable(self):
        with mock.patch.object(stt_cloud, "api_key", return_value=""):
            self.assertFalse(stt_cloud.available())
            with self.assertRaises(stt_cloud.CloudSTTError):
                stt_cloud.transcribe(b"x" * 4096)

    def test_status_reports_the_model(self):
        self.assertEqual(stt_cloud.status()["model"], "whisper-large-v3")
        self.assertIn("groq", stt_cloud.status()["engine"])


class TranscribeTests(unittest.TestCase):
    def setUp(self):
        self.key_patch = mock.patch.dict(os.environ, {"JARVIS_GROQ_API_KEY": "gsk_test"})
        self.key_patch.start()
        self.addCleanup(self.key_patch.stop)

    def test_the_recorder_blob_travels_as_webm_with_the_language_forced(self):
        posted = {}

        def post(url, **kwargs):
            posted["url"] = url
            posted.update(kwargs)
            return Reader({"text": "Jaki jest plan?"})

        with mock.patch.object(stt_cloud.httpx2, "post", side_effect=post):
            result = stt_cloud.transcribe(b"\x1aE\xdf\xa3" + b"\x00" * 4096,
                                          "pl-PL", content_type="audio/webm;codecs=opus")
        self.assertEqual(posted["url"], stt_cloud.URL)
        self.assertEqual(posted["data"]["model"], "whisper-large-v3")
        self.assertEqual(posted["data"]["language"], "pl")
        self.assertEqual(posted["data"]["response_format"], "verbose_json")
        name, blob, mime = posted["files"]["file"]
        self.assertEqual((name, mime), ("take.webm", "audio/webm"))
        self.assertTrue(blob.startswith(b"\x1aE\xdf\xa3"))
        self.assertEqual(result["text"], "Jaki jest plan?")
        self.assertTrue(result["engine"].startswith("groq/"))

    def test_a_wav_take_is_uploaded_with_a_wav_name(self):
        names = []

        def post(url, **kwargs):
            names.append(kwargs["files"]["file"][0])
            return Reader({"text": "hello"})

        with mock.patch.object(stt_cloud.httpx2, "post", side_effect=post):
            stt_cloud.transcribe(b"RIFF" + b"\x00" * 4096, "en", content_type="audio/x-wav")
        self.assertEqual(names, ["take.wav"])

    def test_empty_text_is_still_a_success(self):
        with mock.patch.object(stt_cloud.httpx2, "post",
                               return_value=Reader({"text": ""})):
            self.assertEqual(stt_cloud.transcribe(b"\x00" * 4096)["text"], "")

    def test_lone_punctuation_is_not_a_transcript(self):
        with mock.patch.object(stt_cloud.httpx2, "post",
                               return_value=Reader({"text": "  ... "})):
            self.assertEqual(stt_cloud.transcribe(b"\x00" * 4096)["text"], "")

    def test_noise_segments_whisper_marks_as_silence_are_dropped(self):
        hallucination = {
            "text": "Dziękuję.",
            "segments": [{"text": "Dziękuję.", "no_speech_prob": 0.9987,
                          "avg_logprob": -0.7}],
        }
        with mock.patch.object(stt_cloud.httpx2, "post",
                               return_value=Reader(hallucination)):
            self.assertEqual(stt_cloud.transcribe(b"\x00" * 4096)["text"], "")

    def test_low_confidence_segments_from_noise_are_dropped(self):
        # A segment the model invented from room noise carries a poor average
        # logprob even when no_speech_prob stays low enough to pass.
        payload = {
            "text": "Nie wiem.",
            "segments": [{"text": "Nie wiem.", "no_speech_prob": 0.21,
                          "avg_logprob": -3.42}],
        }
        with mock.patch.object(stt_cloud.httpx2, "post",
                               return_value=Reader(payload)):
            self.assertEqual(stt_cloud.transcribe(b"\x00" * 4096)["text"], "")

    def test_stutter_loops_from_steady_noise_are_dropped(self):
        # The repeated-token yarn (" the, the, the") reports a high
        # compression_ratio and must not reach the brain.
        payload = {
            "text": "the, the, the, the, the. What time is it?",
            "segments": [
                {"text": "the, the, the, the, the.", "no_speech_prob": 0.1,
                 "avg_logprob": -0.6, "compression_ratio": 4.9},
                {"text": "What time is it?", "no_speech_prob": 0.05,
                 "avg_logprob": -0.4, "compression_ratio": 1.2},
            ],
        }
        with mock.patch.object(stt_cloud.httpx2, "post",
                               return_value=Reader(payload)):
            self.assertEqual(stt_cloud.transcribe(b"\x00" * 4096)["text"],
                             "What time is it?")

    def test_one_guessable_letter_is_not_speech(self):
        # A single alpha token ("H.") is trivially guessable from a noise puff.
        payload = {
            "text": "H.",
            "segments": [{"text": "H.", "no_speech_prob": 0.3,
                          "avg_logprob": -0.5}],
        }
        with mock.patch.object(stt_cloud.httpx2, "post",
                               return_value=Reader(payload)):
            self.assertEqual(stt_cloud.transcribe(b"\x00" * 4096)["text"], "")

    def test_confident_politeness_formula_is_noise_mold(self):
        # A lifted sub-dither tone really produced this from Groq: excellent
        # per-segment confidence, only the fixed vocabulary gives it away.
        payload = {
            "text": " Dziękuję.",
            "segments": [{"text": " Dziękuję.", "no_speech_prob": 0.71,
                          "avg_logprob": -0.18, "compression_ratio": 0.6}],
        }
        with mock.patch.object(stt_cloud.httpx2, "post",
                               return_value=Reader(payload)):
            self.assertEqual(stt_cloud.transcribe(b"\x00" * 4096)["text"], "")

    def test_polish_thanks_for_watching_is_a_noise_mold(self):
        # The exact string that reached the user from a quiet take: the Polish
        # half of whisper's best-documented English mould.
        payload = {
            "text": " Dzięki za oglądanie!",
            "segments": [{"text": " Dzięki za oglądanie!", "no_speech_prob": 0.4,
                          "avg_logprob": -0.3, "compression_ratio": 0.8}],
        }
        with mock.patch.object(stt_cloud.httpx2, "post",
                               return_value=Reader(payload)):
            self.assertEqual(stt_cloud.transcribe(b"\x00" * 4096)["text"], "")

    def test_a_content_word_rescues_a_formula_fragment(self):
        # A transcript that carries anything beyond the fixed formula list is
        # real speech even if it opens with a formula.
        payload = {
            "text": "Dziękuję. Jaki jest plan na dziś?",
            "segments": [
                {"text": "Dziękuję.", "no_speech_prob": 0.5},
                {"text": "Jaki jest plan na dziś?", "no_speech_prob": 0.1},
            ],
        }
        with mock.patch.object(stt_cloud.httpx2, "post",
                               return_value=Reader(payload)):
            self.assertEqual(stt_cloud.transcribe(b"\x00" * 4096)["text"],
                             "Dziękuję. Jaki jest plan na dziś?")

    def test_subtitle_credit_hallucinations_are_noise(self):
        # The very take this machine produced: a real question spoken into a
        # weak mic, Groq returned only a subtitle credit.
        payload = {
            "text": " Napisy by Jacek Makarewicz",
            "segments": [{"text": " Napisy by Jacek Makarewicz",
                          "no_speech_prob": 0.12, "avg_logprob": -0.31,
                          "compression_ratio": 1.1}],
        }
        with mock.patch.object(stt_cloud.httpx2, "post",
                               return_value=Reader(payload)):
            self.assertEqual(stt_cloud.transcribe(b"\x00" * 4096)["text"], "")

    def test_segments_whisper_trusts_are_joined_in_order(self):
        payload = {
            "text": "Dziękuję. Jaki jest plan na dziś?",
            "segments": [
                {"text": "Dziękuję.", "no_speech_prob": 0.999},
                {"text": "Jaki jest plan", "no_speech_prob": 0.038},
                {"text": " na dziś?", "no_speech_prob": 0.12},
            ],
        }
        with mock.patch.object(stt_cloud.httpx2, "post",
                               return_value=Reader(payload)):
            self.assertEqual(stt_cloud.transcribe(b"\x00" * 4096)["text"],
                             "Jaki jest plan na dziś?")

    def test_a_response_without_segments_keeps_the_plain_text(self):
        with mock.patch.object(stt_cloud.httpx2, "post",
                               return_value=Reader({"text": "hello"})):
            self.assertEqual(stt_cloud.transcribe(b"\x00" * 4096)["text"], "hello")

    def test_provider_errors_list_the_status_and_hint(self):
        for status, hint in ((401, "rejected"), (429, "rate limit"), (500, None)):
            with mock.patch.object(stt_cloud.httpx2, "post",
                                   return_value=Reader({"error": {"message": "boom"}}, status=status)):
                with self.assertRaises(stt_cloud.CloudSTTError) as caught:
                    stt_cloud.transcribe(b"\x00" * 4096)
            self.assertIn(f"HTTP {status}", str(caught.exception))
            self.assertIn("boom", str(caught.exception))
        with mock.patch.object(stt_cloud.httpx2, "post",
                               return_value=Reader(None, status=503, raw="down")):
            with self.assertRaises(stt_cloud.CloudSTTError) as caught:
                stt_cloud.transcribe(b"\x00" * 4096)
        self.assertIn("down", str(caught.exception))

    def test_transport_failures_and_bad_json_become_cloud_errors(self):
        with mock.patch.object(stt_cloud.httpx2, "post", side_effect=OSError("no route")):
            with self.assertRaises(stt_cloud.CloudSTTError) as caught:
                stt_cloud.transcribe(b"\x00" * 4096)
        self.assertIn("OSError", str(caught.exception))
        with mock.patch.object(stt_cloud.httpx2, "post",
                               return_value=Reader(None, status=200, raw="not-json")):
            with self.assertRaises(stt_cloud.CloudSTTError):
                stt_cloud.transcribe(b"\x00" * 4096)


class GuardTests(unittest.TestCase):
    def test_empty_recording_is_rejected_before_the_network(self):
        self.key_patch = mock.patch.dict(os.environ, {"JARVIS_GROQ_API_KEY": "gsk_test"})
        self.key_patch.start()
        self.addCleanup(self.key_patch.stop)
        with self.assertRaises(stt_cloud.CloudSTTError):
            stt_cloud.transcribe(b"")

    def test_oversized_recording_is_rejected_before_the_network(self):
        posted = []

        def post(url, **kwargs):
            posted.append(kwargs)
            return Reader({"text": "x"})

        with mock.patch.dict(os.environ, {"JARVIS_GROQ_API_KEY": "gsk_test"}), \
                mock.patch.object(stt_cloud.httpx2, "post", side_effect=post):
            with self.assertRaises(stt_cloud.CloudSTTError) as caught:
                stt_cloud.transcribe(b"x" * (stt_cloud.MAX_BYTES + 1))
        self.assertIn("too large", str(caught.exception))
        self.assertEqual(posted, [])


if __name__ == "__main__":
    unittest.main()
