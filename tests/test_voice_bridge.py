"""Unit tests for `voice_bridge.py` — owner-question queue, answering flows, voice path.

Dotąd moduł używany przypadkowo w testach innych modułów (wave2 episodic, p1 concurrency).
ZERO pokrycia: `transcribe_and_answer` oraz cała logika krawędzi (idempotencja req_id, cap 80,
publish cichy, speak-handsfree z DND, integracja agent_team requests/resp, rozpoznawanie
głosowe z fallbackiem chmury). Izolacja: ROOT na świeży tmp per test; `event_bus`,
`wayland_voice`, `tts_piper`, `agent_team`, `stt`, `stt_cloud` wstrzykiwane fałszywami przez
`patch.dict(sys.modules)` (wszystkie importowane wewnątrz funkcji) — prawdziwe TTS/STT
i magistrala nigdy nie są dotykane.
"""
from __future__ import annotations

import json
import os
import shutil
import sys
import threading
import time
import unittest
from contextlib import contextmanager
from pathlib import Path
from tempfile import mkdtemp
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, ".")

import voice_bridge as vb  # noqa: E402


class _FakeBus:
    def __init__(self) -> None:
        self.published: list[tuple[str, dict]] = []

    def publish(self, topic: str, payload: dict) -> None:
        self.published.append((topic, payload))


class _FakeTTS:
    def __init__(self) -> None:
        self.spoken: list[str] = []
        self.called = threading.Event()

    def speak(self, text: str) -> None:
        self.spoken.append(text)
        self.called.set()


class _FakeBargeIn:
    def __init__(self) -> None:
        self.utterances = 0

    def begin_utterance(self) -> str:
        self.utterances += 1
        return "gen-fake"

    def is_current(self, gen_id: str) -> bool:
        return gen_id == "gen-fake"


class VoiceBridgeBase(unittest.TestCase):
    def setUp(self) -> None:
        self.base = Path(mkdtemp())
        self.addCleanup(shutil.rmtree, self.base, True)
        self.root = self.base / "state" / ".jarvis-tools" / "agents" / "root"
        self.root_patch = mock.patch.object(vb.agent_cli, "ROOT", self.root)
        self.root_patch.start()
        self.addCleanup(self.root_patch.stop)

    @property
    def store_path(self) -> Path:
        return self.base / "state" / ".jarvis-tools" / "agents" / "owner_questions.json"

    def _silent_team(self):
        """Fake agent_team przyjmujacy wszystko (answer bez side effectow z ew. pid)."""
        proj_dir = self.base / "silent-proj"
        (proj_dir / "requests").mkdir(parents=True, exist_ok=True)

        @contextmanager
        def _lock(path):
            yield

        team = SimpleNamespace(
            project_root=lambda pid: proj_dir,
            _file_lock=_lock,
            post_message=lambda pid, **kw: None,
        )
        ctx = mock.patch.dict(sys.modules, {"agent_team": team})
        ctx.start()
        self.addCleanup(ctx.stop)
        return team

    def _bus(self) -> _FakeBus:
        bus = _FakeBus()
        ctx = mock.patch.dict(sys.modules, {"event_bus": bus})
        ctx.start()
        self.addCleanup(ctx.stop)
        return bus


class EnqueueTests(VoiceBridgeBase):
    def test_entry_shape_and_publish(self):
        bus = self._bus()
        entry = vb.enqueue_owner_question("Proj A", "req-1", "hermes", "Migrujemy?")
        self.assertEqual(set(entry.keys()), {
            "id", "project_id", "from", "question", "created_at", "status",
            "answer", "answered_at", "source",
        })
        self.assertEqual(entry["project_id"], "Proj A")
        self.assertEqual(entry["from"], "hermes")
        self.assertEqual(entry["status"], "pending")
        self.assertIsNone(entry["answered_at"])
        self.assertEqual(bus.published[0][0], "owner.question")
        self.assertIs(bus.published[0][1], entry)

    def test_defaults_and_truncation(self):
        self._bus()
        entry = vb.enqueue_owner_question(" ", "req-2", "", "q" * 3000)
        self.assertEqual(entry["project_id"], "")
        self.assertEqual(entry["from"], "agent")
        self.assertEqual(entry["question"], "q" * 2000)

    def test_idempotent_req_id_returns_original(self):
        self._bus()
        first = vb.enqueue_owner_question("p", "req-3", "opus", "Pytanie 1")
        time.sleep(0.01)  # odmienny created_at gdyby nadpisywal
        second = vb.enqueue_owner_question("p", "req-3", "opus", "Pytanie 2")
        self.assertEqual(first["created_at"], second["created_at"])
        self.assertEqual(second["question"], "Pytanie 1")
        self.assertEqual(len(vb.pending_owner_questions()), 1)

    def test_missing_fields_raise(self):
        with self.assertRaises(ValueError) as ctx:
            vb.enqueue_owner_question("p", "", "a", "q")
        self.assertIn("req_id and question are required", str(ctx.exception))
        with self.assertRaises(ValueError):
            vb.enqueue_owner_question("p", "req-x", "a", "   ")

    def test_queue_capped_at_80_prunes_oldest(self):
        self._bus()
        for i in range(80):
            vb.enqueue_owner_question("", f"req-{i:03d}", "a", f"q{i}")
        vb.enqueue_owner_question("", "req-new", "a", "nowe")
        items = json.loads(self.store_path.read_text(encoding="utf-8"))
        self.assertEqual(len(items), 80)
        self.assertNotIn("req-000", items)          # najstarsze usuniete
        self.assertIn("req-new", items)

    def test_publish_failure_is_silent(self):
        class _BoomBus:
            def publish(self, topic, payload):  # noqa: ANN001
                raise RuntimeError("bus down")
        ctx = mock.patch.dict(sys.modules, {"event_bus": _BoomBus()})
        ctx.start()
        self.addCleanup(ctx.stop)
        entry = vb.enqueue_owner_question("p", "req-ok", "a", "q")
        self.assertEqual(entry["id"], "req-ok")
        self.assertEqual(len(vb.pending_owner_questions()), 1)


class SpeakFlowTests(VoiceBridgeBase):
    def test_explicit_speak_uses_async_tts_thread(self):
        self._bus()
        tts = _FakeTTS()
        fake_wayland = SimpleNamespace(BARGE_IN=_FakeBargeIn(), dnd_status=lambda: {"dnd": False})
        ctx = mock.patch.dict(sys.modules, {"wayland_voice": fake_wayland, "tts_piper": tts})
        ctx.start()
        self.addCleanup(ctx.stop)
        vb.enqueue_owner_question("p", "req-s", "hermes", "Czy gramy?", speak=True)
        self.assertTrue(tts.called.wait(2.0), "TTS nie zostal wywolany w 2 s")
        self.assertEqual(len(tts.spoken), 1)
        self.assertIn("hermes pyta", tts.spoken[0])

    def test_speak_none_respects_handsfree_env_and_dnd(self):
        self._bus()
        tts = _FakeTTS()
        fake_module = mock.MagicMock()
        fake_module.BARGE_IN = _FakeBargeIn()
        fake_module.dnd_status = mock.MagicMock(return_value={"dnd": True})
        mods = {"tts_piper": tts}
        # Handsfree ON + DND True -> brak TTS
        fake_module.dnd_status.return_value = {"dnd": True}
        ctx1 = mock.patch.dict(sys.modules, {"wayland_voice": fake_module, **mods})
        ctx1.start()
        with mock.patch.dict(os.environ, {"JARVIS_VOICE_HANDSFREE": "1"}):
            vb.enqueue_owner_question("p", "req-hfon-dnd", "a", "q")
        self.assertFalse(tts.called.wait(0.3))
        ctx1.stop()

        # Handsfree ON + DND False -> TTS startuje
        tts2 = _FakeTTS()
        fake_module2 = mock.MagicMock()
        fake_module2.BARGE_IN = _FakeBargeIn()
        fake_module2.dnd_status.return_value = {"dnd": False}
        ctx2 = mock.patch.dict(sys.modules, {"wayland_voice": fake_module2, "tts_piper": tts2})
        ctx2.start()
        with mock.patch.dict(os.environ, {"JARVIS_VOICE_HANDSFREE": "yes"}):
            vb.enqueue_owner_question("p", "req-hfon-dnd2", "a", "q")
        self.assertTrue(tts2.called.wait(2.0))
        ctx2.stop()

        # Handsfree OFF (domyslnie) -> cisza mimo DND czystego
        with mock.patch.dict(os.environ, {"JARVIS_VOICE_HANDSFREE": "0"}):
            vb.enqueue_owner_question("p", "req-hf0", "a", "q", speak=None)
        time.sleep(0.05)

    def test_speak_false_never_reaches_tts(self):
        self._bus()
        tts = _FakeTTS()
        fake = SimpleNamespace(BARGE_IN=_FakeBargeIn(), dnd_status=lambda: {"dnd": False})
        ctx = mock.patch.dict(sys.modules, {"wayland_voice": fake, "tts_piper": tts})
        ctx.start()
        self.addCleanup(ctx.stop)
        with mock.patch.dict(os.environ, {"JARVIS_VOICE_HANDSFREE": "1"}):
            vb.enqueue_owner_question("p", "req-quiet", "a", "q", speak=False)
        self.assertFalse(tts.called.wait(0.3))


class PendingTests(VoiceBridgeBase):
    def test_pending_filter_sort_and_answers_excluded(self):
        self._bus()
        self._silent_team()
        vb.enqueue_owner_question("ProjA", "r1", "a", "starsze")
        time.sleep(0.01)
        vb.enqueue_owner_question("projb", "r2", "a", "nowsze")
        time.sleep(0.01)
        vb.enqueue_owner_question("PROJA", "r3", "a", "trzecie")
        vb.answer_owner_question("odp", req_id="r3", source="text")

        rows = vb.pending_owner_questions()
        self.assertEqual([r["id"] for r in rows], ["r1", "r2"])   # posortowane po created_at
        only_a = vb.pending_owner_questions("proja")
        self.assertEqual([r["id"] for r in only_a], ["r1"])       # filtr case-insensitive
        self.assertEqual(vb.pending_owner_questions("brak"), [])


class AnswerTests(VoiceBridgeBase):
    def test_answer_by_id_shapes_and_publish(self):
        bus = self._bus()
        vb.enqueue_owner_question("", "r1", "opus", "Pytanie?")
        entry = vb.answer_owner_question("Zdecydowanie tak", req_id="r1", source="web-ui")
        self.assertEqual(entry["status"], "answered")
        self.assertEqual(entry["answer"], "Zdecydowanie tak")
        self.assertEqual(entry["source"], "web-ui")
        self.assertAlmostEqual(entry["answered_at"], time.time(), delta=10.0)
        self.assertEqual(bus.published[0][0], "owner.question")
        self.assertEqual(bus.published[1][0], "owner.answered")
        self.assertIs(bus.published[1][1], entry)
        self.assertEqual(vb.pending_owner_questions(), [])

    def test_answer_validation_errors(self):
        with self.assertRaises(ValueError) as ctx:
            vb.answer_owner_question("   ")
        self.assertIn("Answer cannot be empty", str(ctx.exception))
        with self.assertRaises(ValueError) as ctx2:
            vb.answer_owner_question("ok", req_id="nie-znany")
        self.assertIn("Nieznane ID pytania", str(ctx2.exception))
        with self.assertRaises(ValueError) as ctx3:       # brak req_id, brak pending
            vb.answer_owner_question("ok")
        self.assertIn("Brak oczekujących pytań", str(ctx3.exception))

    def test_answer_without_req_targets_oldest_pending(self):
        self._bus()
        vb.enqueue_owner_question("", "r-old", "a", "starsze")
        time.sleep(0.01)
        vb.enqueue_owner_question("", "r-new", "a", "nowsze")
        entry = vb.answer_owner_question("odp")
        self.assertEqual(entry["id"], "r-old")
        self.assertEqual([r["id"] for r in vb.pending_owner_questions()], ["r-new"])
        self.assertEqual(entry["source"], "text")

    def test_answer_truncates_fields(self):
        self._bus()
        vb.enqueue_owner_question("", "r-tr", "a", "q")
        entry = vb.answer_owner_question("a" * 5000, req_id="r-tr", source="s" * 30)
        self.assertEqual(len(entry["answer"]), 4000)
        self.assertEqual(len(entry["source"]), 24)


class AgentTeamIntegrationTests(VoiceBridgeBase):
    def _fake_team(self, with_req_file: bool) -> SimpleNamespace:
        proj_dir = self.base / "projroot"
        req_dir = proj_dir / "requests"
        req_dir.mkdir(parents=True, exist_ok=True)
        posted: list[dict] = []

        @contextmanager
        def _lock(path):
            yield

        team = SimpleNamespace(
            project_root=lambda pid: proj_dir,
            _file_lock=_lock,
            post_message=lambda pid, **kw: posted.append({"pid": pid, **kw}),
        )
        if with_req_file:
            (req_dir / "req-rq1.json").write_text(
                json.dumps({"id": "rq1", "status": "waiting"}), encoding="utf-8")
        return team, req_dir, posted

    def test_answer_updates_request_and_posts_message(self):
        self._bus()
        team, req_dir, posted = self._fake_team(with_req_file=True)
        ctx = mock.patch.dict(sys.modules, {"agent_team": team})
        ctx.start()
        self.addCleanup(ctx.stop)

        vb.enqueue_owner_question("proj1", "rq1", "opus", "Finalna decyzja?")
        entry = vb.answer_owner_question("Idziemy!", req_id="rq1", source="voice")

        req = json.loads((req_dir / "req-rq1.json").read_text(encoding="utf-8"))
        self.assertEqual(req["status"], "answered")
        resp = json.loads((req_dir / "resp-rq1.json").read_text(encoding="utf-8"))
        self.assertEqual(resp["from"], "owner")
        self.assertEqual(resp["to"], "opus")
        self.assertEqual(resp["answer"], "Idziemy!")
        self.assertEqual(resp["answered_at"], entry["answered_at"])
        self.assertEqual(len(posted), 1)
        self.assertEqual(posted[0]["pid"], "proj1")
        self.assertIn("[reply:rq1] Idziemy!", posted[0]["text"])
        self.assertEqual(posted[0]["kind"], "answer")
        self.assertEqual(posted[0]["sender"], "owner")

    def test_missing_req_file_still_writes_response(self):
        self._bus()
        team, req_dir, posted = self._fake_team(with_req_file=False)
        ctx = mock.patch.dict(sys.modules, {"agent_team": team})
        ctx.start()
        self.addCleanup(ctx.stop)
        vb.enqueue_owner_question("proj1", "rq2", "opus", "Pytanie?")
        vb.answer_owner_question("OK", req_id="rq2")
        self.assertFalse((req_dir / "req-rq2.json").exists())
        resp = json.loads((req_dir / "resp-rq2.json").read_text(encoding="utf-8"))
        self.assertEqual(resp["answer"], "OK")
        self.assertEqual(len(posted), 1)

    def test_no_project_id_skips_agent_team(self):
        self._bus()
        boom = SimpleNamespace(
            project_root=lambda pid: (_ for _ in ()).throw(AssertionError("nie wolno!")),
        )
        ctx = mock.patch.dict(sys.modules, {"agent_team": boom})
        ctx.start()
        self.addCleanup(ctx.stop)
        vb.enqueue_owner_question("", "rq3", "a", "Pytanie?")
        entry = vb.answer_owner_question("odp", req_id="rq3")
        self.assertEqual(entry["status"], "answered")


class TranscribeTests(VoiceBridgeBase):
    def _stt(self, text: str, cloud: bool):
        calls: dict = {"prepare": 0, "local": 0, "cloud": 0}
        stt_mod = SimpleNamespace(
            prepare_take=lambda payload: (calls.update(prepare=1), (payload, {"dur": 1.0}))[1],
            transcribe=lambda wav, lang: (calls.update(local=1), {"text": text})[1],
        )
        cloud_mod = SimpleNamespace(
            available=lambda: cloud,
            transcribe=lambda wav, lang, content_type: (
                calls.update(cloud=1), {"text": text})[1],
        )
        return stt_mod, cloud_mod, calls

    def test_voice_answer_takes_cloud_when_available(self):
        self._bus()
        stt_mod, cloud_mod, calls = self._stt("  Tak, ruszamy  ", cloud=True)
        ctx = mock.patch.dict(sys.modules, {"stt": stt_mod, "stt_cloud": cloud_mod})
        ctx.start()
        self.addCleanup(ctx.stop)
        vb.enqueue_owner_question("", "rq-v1", "opus", "Idziemy?")
        res = vb.transcribe_and_answer(b"FAKEDATA", language="pl")
        self.assertTrue(res["ok"])
        self.assertEqual(res["heard"], "Tak, ruszamy")      # strip
        self.assertEqual(calls["cloud"], 1)
        self.assertEqual(calls["local"], 0)
        self.assertEqual(res["question"]["source"], "voice")
        self.assertEqual(vb.pending_owner_questions(), [])

    def test_voice_answer_falls_back_to_local_stt(self):
        self._bus()
        stt_mod, cloud_mod, calls = self._stt("lokalna odpowiedz", cloud=False)
        ctx = mock.patch.dict(sys.modules, {"stt": stt_mod, "stt_cloud": cloud_mod})
        ctx.start()
        self.addCleanup(ctx.stop)
        vb.enqueue_owner_question("", "rq-v2", "opus", "Idziemy?")
        res = vb.transcribe_and_answer(b"FAKEDATA")
        self.assertEqual(res["heard"], "lokalna odpowiedz")
        self.assertEqual(calls["local"], 1)
        self.assertEqual(calls["cloud"], 0)

    def test_voice_edge_errors(self):
        self._bus()
        with self.assertRaises(ValueError) as ctx:
            vb.transcribe_and_answer(b"")
        self.assertIn("Empty audio payload", str(ctx.exception))

        stt_mod, cloud_mod, _ = self._stt("", cloud=True)
        with mock.patch.dict(sys.modules, {"stt": stt_mod, "stt_cloud": cloud_mod}):
            with self.assertRaises(ValueError) as ctx2:
                vb.transcribe_and_answer(b"xyz")
        self.assertIn("Nie udało się rozpoznać odpowiedzi głosowej", str(ctx2.exception))


if __name__ == "__main__":
    unittest.main()
