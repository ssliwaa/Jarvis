"""Unit tests for `time_travel.py` — timepoint recording, listing, and session forking.

Dotąd wyłącznie happy-path: p1_concurrency (24 równoległych zapisów) i mission_suite
(fork z PRAWDZIWYM CheckpointManager). Tu: normalizacja pól, falsy edge
`turn_index=0` przy odtwarzaniu wiadomości (przywróci CAŁOŚĆ listy, nie 0!),
clamp limitów, cap 300 rekordów, komunikaty błędów i meta pliki forków.
Izolacja: `agent_cli.ROOT` patchowane na świeży tmp per test (prawdziwa
przestrzeń `time_travel` niedotknięta); `checkpoint_manager.default_manager`
fałszowany przez `patch.object` (top-level import).
"""
from __future__ import annotations

import json
import sys
import time
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, ".")

import time_travel as tt  # noqa: E402


class TimeTravelBase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.root = self.base / "state" / ".jarvis-tools" / "agents" / "root"
        self.root_patch = mock.patch.object(tt.agent_cli, "ROOT", self.root)
        self.root_patch.start()
        self.addCleanup(self.root_patch.stop)

    @property
    def tt_dir(self) -> Path:
        return self.base / "state" / ".jarvis-tools" / "agents" / "time_travel"

    @property
    def forks_dir(self) -> Path:
        return self.tt_dir / "forks"

    def _msgs(self, count: int) -> list[dict]:
        return [{"role": "user", "content": f"m{i}"} for i in range(count)]

    def _seed_rows(self, rows: list[dict]) -> None:
        tt._save_rows(rows)


class RecordTimepointTests(TimeTravelBase):
    def test_defaults_and_entry_shape(self):
        before = time.time()
        entry = tt.record_timepoint(session_id="", turn_index=0, messages=None)
        self.assertEqual(entry["session_id"], "default")       # pusty sid -> default
        self.assertEqual(entry["turn_index"], 0)
        self.assertEqual(entry["label"], "Tura #0")
        self.assertEqual(entry["project_dir"], "")
        self.assertEqual(entry["commit_hash"], "")
        self.assertEqual(entry["messages_file"], "")
        self.assertEqual(entry["message_count"], 0)
        self.assertTrue(entry["id"].startswith("tp-"))
        self.assertEqual(set(entry.keys()), {
            "id", "session_id", "turn_index", "project_dir", "commit_hash",
            "messages_file", "message_count", "label", "created_at",
        })
        self.assertAlmostEqual(entry["created_at"], before, delta=10.0)

    def test_field_normalization_and_truncation(self):
        entry = tt.record_timepoint(
            session_id="  ab cd  ", turn_index=-5, label="  opis  ")
        self.assertEqual(entry["session_id"], "ab cd")
        self.assertEqual(entry["turn_index"], 0)                 # max(0, -5)
        self.assertEqual(entry["label"], "opis")

        # turn_index ujemny zostawia slad w domyslnym labelu (pre-clamp format)
        raw = tt.record_timepoint(session_id="x", turn_index=-5)
        self.assertEqual(raw["turn_index"], 0)
        self.assertEqual(raw["label"], "Tura #-5")

        long = tt.record_timepoint(session_id="s" * 100, label="L" * 200)
        self.assertEqual(len(long["session_id"]), 80)
        self.assertEqual(len(long["label"]), 160)

    def test_messages_persisted_to_snapshot_file(self):
        msgs = self._msgs(4)
        entry = tt.record_timepoint(session_id="sesja", turn_index=2, messages=msgs)
        self.assertEqual(entry["message_count"], 4)
        snap = self.forks_dir / entry["messages_file"]
        self.assertTrue(snap.is_file())
        self.assertEqual(json.loads(snap.read_text(encoding="utf-8")), msgs)

    def test_project_checkpoint_binding(self):
        ensure_calls: list[tuple] = []
        mgr = SimpleNamespace(
            ensure_checkpoint=lambda proj, reason: ensure_calls.append((str(proj), reason)),
            list_checkpoints=lambda proj: [{"hash": "abc123def"}],
        )
        with mock.patch.object(tt.checkpoint_manager, "default_manager", return_value=mgr):
            proj = self.base / "proj"
            proj.mkdir()
            entry = tt.record_timepoint(
                session_id="s5", turn_index=1, project_dir=proj, messages=self._msgs(2))
        self.assertEqual(entry["commit_hash"], "abc123def")
        self.assertEqual(entry["project_dir"], str(proj))
        self.assertEqual(len(ensure_calls), 1)
        self.assertIn("timepoint:s5:t1", ensure_calls[0][1])

    def test_missing_project_dir_never_touches_manager(self):
        calls: list[object] = []
        mgr = SimpleNamespace(
            ensure_checkpoint=lambda *a, **k: calls.append("BOOM"),
            list_checkpoints=lambda proj: [],
        )
        with mock.patch.object(tt.checkpoint_manager, "default_manager", return_value=mgr):
            entry = tt.record_timepoint(session_id="s6", project_dir=self.base / "nie-ma")
        self.assertEqual(entry["project_dir"], "")
        self.assertEqual(entry["commit_hash"], "")
        self.assertEqual(calls, [])

    def test_record_persists_to_index(self):
        ids = []
        for i in range(3):
            ids.append(tt.record_timepoint(session_id=f"s{i}")["id"])
        raw_rows = json.loads((self.tt_dir / "timepoints.json").read_text(encoding="utf-8"))
        self.assertEqual([r["id"] for r in raw_rows], ids)


class ListTimepointsTests(TimeTravelBase):
    def _row(self, sid: str, created: float) -> dict:
        return {"id": f"tp-{sid}-{int(created)}", "session_id": sid, "created_at": created,
                "turn_index": 0, "project_dir": "", "commit_hash": "",
                "messages_file": "", "message_count": 0, "label": "l"}

    def test_sort_descending_and_session_filter(self):
        self._seed_rows([self._row("a", 1.0), self._row("b", 2.0), self._row("a", 3.0)])
        listed = tt.list_timepoints()
        self.assertEqual([r["id"] for r in listed], ["tp-a-3", "tp-b-2", "tp-a-1"])
        only_a = tt.list_timepoints(session_id="a")
        self.assertEqual([r["id"] for r in only_a], ["tp-a-3", "tp-a-1"])

    def test_limit_clamps(self):
        self._seed_rows([self._row(f"s{i}", float(i)) for i in range(60)])
        self.assertEqual(len(tt.list_timepoints(limit=0)), 40)    # 0 -> domyslne 40
        self.assertEqual(len(tt.list_timepoints(limit=-5)), 1)    # max(1, -5)
        self.assertEqual(len(tt.list_timepoints(limit=999)), 60)   # clamp 200 > posiadane 60
        self.assertEqual(len(tt.list_timepoints(limit=2)), 2)


class ForkTimepointTests(TimeTravelBase):
    def test_missing_timepoint_raises_with_message(self):
        with self.assertRaises(tt.TimeTravelError) as ctx:
            tt.fork_timepoint("tp-nieistniejacy")
        self.assertEqual(str(ctx.exception), "Nie znaleziono punktu w czasie: tp-nieistniejacy")

    def test_message_prefix_by_turn_index(self):
        entry = tt.record_timepoint(session_id="sesja", turn_index=2, messages=self._msgs(4))
        fork = tt.fork_timepoint(entry["id"])
        self.assertEqual(fork["messages_restored"], 2)
        self.assertTrue(fork["fork_session_id"].startswith("sesja-fork-"))
        self.assertEqual(fork["from_timepoint"], entry["id"])
        self.assertTrue(fork["ok"])
        self.assertFalse(fork["files_restored"])
        self.assertEqual(fork["checkpoint_hash"], "")

    def test_turn_index_zero_restores_all_messages(self):
        # cutoff = int(tp['turn_index'] or len(loaded)) - 0 jest falsy => cala lista
        entry = tt.record_timepoint(session_id="s0", turn_index=0, messages=self._msgs(3))
        fork = tt.fork_timepoint(entry["id"])
        self.assertEqual(fork["messages_restored"], 3)

    def test_missing_and_corrupt_message_files_are_silent(self):
        no_msgs = tt.record_timepoint(session_id="s1")
        self.assertEqual(tt.fork_timepoint(no_msgs["id"])["messages_restored"], 0)

        ghost = tt.record_timepoint(session_id="s2", turn_index=1, messages=self._msgs(2))
        (self.forks_dir / ghost["messages_file"]).unlink()  # plik znikl
        self.assertEqual(tt.fork_timepoint(ghost["id"])["messages_restored"], 0)

        corrupt = tt.record_timepoint(session_id="s3", turn_index=1, messages=self._msgs(2))
        (self.forks_dir / corrupt["messages_file"]).write_text("{nie-json", encoding="utf-8")
        self.assertEqual(tt.fork_timepoint(corrupt["id"])["messages_restored"], 0)

    def test_fork_meta_file_written_with_title(self):
        entry = tt.record_timepoint(session_id="sesja", turn_index=1, label="Przed eksperymentem")
        fork = tt.fork_timepoint(entry["id"], new_title="Moja nitka")
        meta_path = self.forks_dir / f"{fork['fork_session_id']}.json"
        self.assertTrue(meta_path.is_file())
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        self.assertEqual(meta["title"], "Moja nitka")
        self.assertEqual(meta["parent_session_id"], "sesja")
        self.assertEqual(meta["from_timepoint"], entry["id"])
        self.assertEqual(meta["turn_index"], 1)

        default_titled = tt.fork_timepoint(entry["id"])
        default_meta = json.loads(
            (self.forks_dir / f"{default_titled['fork_session_id']}.json").read_text(encoding="utf-8"))
        self.assertEqual(default_meta["title"], "Fork od Przed eksperymentem")
        long_titled = tt.fork_timepoint(entry["id"], new_title="T" * 200)
        long_meta = json.loads(
            (self.forks_dir / f"{long_titled['fork_session_id']}.json").read_text(encoding="utf-8"))
        self.assertEqual(len(long_meta["title"]), 140)

    def _bound_timepoint(self, sid: str, hash_value: str = "shaX") -> dict:
        """Zapis punktu z checkpointem pod zafalszowanym managerem (bez realnego gita)."""
        with mock.patch.object(tt.checkpoint_manager, "default_manager", return_value=SimpleNamespace(
                ensure_checkpoint=lambda proj, reason: None,
                list_checkpoints=lambda proj: [{"hash": hash_value}])):
            return tt.record_timepoint(session_id=sid, turn_index=1, project_dir=self.base)

    def test_restore_files_success_flow(self):
        entry = self._bound_timepoint("sR")
        restore_book: list[tuple] = []
        res = {"success": True, "restored": 5}
        with mock.patch.object(tt.checkpoint_manager, "default_manager", return_value=SimpleNamespace(
                restore=lambda proj, h: (restore_book.append((str(proj), h)) or res))):
            fork = tt.fork_timepoint(entry["id"], restore_files=True)
        self.assertTrue(fork["ok"])
        self.assertTrue(fork["files_restored"])
        self.assertEqual(fork["restore_detail"], res)
        self.assertEqual(restore_book, [(str(self.base), entry["commit_hash"])])

    def test_restore_files_failures_and_missing_checkpoint(self):
        entry = tt.record_timepoint(session_id="sF", turn_index=1)  # bez projektu
        with self.assertRaises(tt.TimeTravelError) as ctx:
            tt.fork_timepoint(entry["id"], restore_files=True)
        self.assertEqual(str(ctx.exception), "Ten punkt czasu nie posiada powiązanego checkpointu plików.")

        bound = self._bound_timepoint("sF2")
        with mock.patch.object(tt.checkpoint_manager, "default_manager", return_value=SimpleNamespace(
                restore=lambda p, h: {"success": False, "error": "boom"})):
            with self.assertRaises(tt.TimeTravelError) as ctx2:
                tt.fork_timepoint(bound["id"], restore_files=True)
        self.assertEqual(str(ctx2.exception), "boom")

        failure_only = self._bound_timepoint("sF3")
        with mock.patch.object(tt.checkpoint_manager, "default_manager", return_value=SimpleNamespace(
                restore=lambda p, h: {"failed_in_another_shape": 1})):
            with self.assertRaises(tt.TimeTravelError) as ctx3:
                tt.fork_timepoint(failure_only["id"], restore_files=True)
        self.assertEqual(str(ctx3.exception), "Przywrócenie plików nie powiodło się.")


class CapRowsTests(TimeTravelBase):
    def test_index_keeps_last_300(self):
        self._seed_rows([
            {"id": f"tp-old{i}", "session_id": "cap", "created_at": float(i),
             "turn_index": 0, "project_dir": "", "commit_hash": "",
             "messages_file": "", "message_count": 0, "label": "l"}
            for i in range(305)
        ])
        fresh = tt.record_timepoint(session_id="cap")
        rows = tt._load_rows()
        self.assertEqual(len(rows), 300)
        self.assertEqual(rows[-1]["id"], fresh["id"])
        self.assertNotIn("tp-old0", {r["id"] for r in rows})


if __name__ == "__main__":
    unittest.main()
