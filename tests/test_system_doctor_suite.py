"""Unit tests for system_doctor: hermetic self-healing diagnostics.

The state root comes from agent_cli.ROOT.parent, so that seam is patched
onto a tmp directory; code_index / hardware_guard / security_scanner /
qa_gate are replaced with SimpleNamespace fakes, and change_impact (an
in-function import) is injected through sys.modules. SQLite checks run
against real files in tmp (valid and corrupted), permissions healing
performs real chmods inside the sandbox - no production paths are
touched.

Polish issue strings are matched through `fold` (NFKD -> ASCII); this
file stays pure ASCII except em-dashes.
"""
import os
import sqlite3
import stat
import sys
import tempfile
import time
import unicodedata
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import system_doctor as sd


def fold(text):
    """ASCII view of a Polish issue string (tests stay pure-ASCII)."""
    return unicodedata.normalize("NFKD", str(text)).encode(
        "ascii", "ignore").decode()


def make_sqlite(path):
    conn = sqlite3.connect(path)
    with conn:
        conn.execute("CREATE TABLE t (x TEXT)")
        conn.execute("INSERT INTO t VALUES ('ok')")
    conn.close()


class _DoctorCase(unittest.TestCase):
    """tmp state root + patched live seams."""

    def setUp(self):
        self.tmp_obj = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp_obj.cleanup)
        self.tmp = Path(self.tmp_obj.name)
        self.state = self.tmp / "state"
        self.state.mkdir(mode=0o700)
        # ROOT lives inside state's child, so ROOT.parent == state.
        fake_agent_cli = SimpleNamespace(ROOT=self.state / "agent-cli")

        patcher = mock.patch.object(sd, "agent_cli", fake_agent_cli)
        patcher.start()
        self.addCleanup(patcher.stop)

        self.ejected = []

        def evict(force=False):
            popped = len(self.ejected)
            self.ejected = []
            return popped

        self.hardware = {"state": "ok", "reasons": []}
        self.hw_calls = []

        def hw_snapshot():
            self.hw_calls.append(True)
            return dict(self.hardware)

        self.security = {"ok": True, "findings_count": 0}
        self.viewer_qa = {"ok": True, "issues": []}
        self.sri = {"ok": True, "updated": 0, "mismatches": []}

        for name, fake in (
                ("code_index", SimpleNamespace(evict_idle_cache=evict)),
                ("hardware_guard", SimpleNamespace(snapshot=hw_snapshot)),
                ("security_scanner", SimpleNamespace(
                    scan_directory=self._security_scan)),
                ("qa_gate", SimpleNamespace(audit_viewer=self._audit_viewer)),
        ):
            p = mock.patch.object(sd, name, fake)
            p.start()
            self.addCleanup(p.stop)

        self.fake_change_impact = SimpleNamespace(
            sync_viewer_sri=lambda proj, fix=True: dict(self.sri))

    def _security_scan(self, proj, include_tests=False):
        return dict(self.security)

    def _audit_viewer(self, proj):
        return dict(self.viewer_qa)

    def install_change_impact(self):
        """Patch the in-function `import change_impact` via sys.modules."""
        holder = {}

        def sri(project, fix=True):
            holder["calls"] = holder.get("calls", 0) + 1
            return dict(self.sri)

        self.fake_change_impact = SimpleNamespace(sync_viewer_sri=sri)
        patcher = mock.patch.dict(sys.modules,
                                  {"change_impact": self.fake_change_impact})
        patcher.start()
        self.addCleanup(patcher.stop)
        return holder

    def diagnostics(self, **kwargs):
        kwargs.setdefault("auto_heal", True)
        return sd.run_diagnostics(**kwargs)

    def backdate(self, path, seconds):
        was = time.time() - seconds
        os.utime(path, (was, was))


class TestCheckSqliteFile(_DoctorCase):
    """_check_sqlite_file: present/ok/healed paths."""

    def test_missing_file_is_ok(self):
        result = sd._check_sqlite_file(
            self.state / "semantic_cache.sqlite3", auto_heal=True)
        self.assertEqual(result, {"path": "semantic_cache.sqlite3",
                                  "present": False, "ok": True,
                                  "healed": False})

    def test_valid_database_passes(self):
        db = self.state / "episodic_memory.sqlite3"
        make_sqlite(db)
        result = sd._check_sqlite_file(db, auto_heal=True)
        self.assertEqual(result["present"], True)
        self.assertEqual(result["ok"], True)
        self.assertEqual(result["healed"], False)
        self.assertTrue(db.is_file())

    def test_corrupt_database_without_heal_only_reports(self):
        db = self.state / "episodic_memory.sqlite3"
        db.write_bytes(b"to nie jest baza sqlite \x00\x01")
        result = sd._check_sqlite_file(db, auto_heal=False)
        self.assertTrue(result["present"])
        self.assertFalse(result["ok"])
        self.assertFalse(result["healed"])
        self.assertIn("corrupt", fold(result["detail"]))
        self.assertTrue(db.is_file())

    def test_corrupt_database_quarantined_with_sidecars(self):
        db = self.state / "episodic_memory.sqlite3"
        db.write_bytes(b"garbage-header\x00\x02")
        wal = self.state / "episodic_memory.sqlite3-wal"
        shm = self.state / "episodic_memory.sqlite3-shm"
        wal.write_bytes(b"w")
        shm.write_bytes(b"s")

        result = sd._check_sqlite_file(db, auto_heal=True)

        self.assertEqual(result["healed"], True)
        self.assertEqual(result["ok"], True)
        self.assertFalse(db.exists())
        self.assertFalse(wal.exists())
        self.assertFalse(shm.exists())
        quarantined = list(self.state.glob(
            "episodic_memory.sqlite3.corrupt-*"))
        self.assertEqual(len(quarantined), 1)


class TestHealPermissions(_DoctorCase):
    """_heal_permissions: dir 0700 + file 0600 enforcement."""

    def modes(self):
        return (stat.S_IMODE(self.state.stat().st_mode),
                stat.S_IMODE((self.state / "budget_ledger.json")
                             .stat().st_mode))

    def test_wide_modes_reported_and_healed(self):
        self.state.chmod(0o777)
        ledger = self.state / "budget_ledger.json"
        ledger.write_text("{}", encoding="utf-8")
        ledger.chmod(0o644)

        issues, healed = sd._heal_permissions(self.state, auto_heal=True)

        self.assertEqual(issues, [])
        self.assertEqual(len(healed), 2)
        self.assertIn("chmod 0700 state", healed)
        self.assertTrue(any("budget_ledger.json" in h for h in healed))
        self.assertEqual(self.modes(), (0o700, 0o600))

    def test_wide_modes_without_heal_stay_wide(self):
        self.state.chmod(0o755)
        ledger = self.state / "budget_ledger.json"
        ledger.write_text("{}", encoding="utf-8")
        ledger.chmod(0o666)

        issues, healed = sd._heal_permissions(self.state, auto_heal=False)

        self.assertEqual(healed, [])
        self.assertEqual(len(issues), 2)
        self.assertEqual(self.modes(), (0o755, 0o666))
        folds = [fold(i) for i in issues]
        self.assertTrue(all("uprawnienia" in i for i in folds))

    def test_tidy_state_and_missing_files_report_nothing(self):
        self.state.chmod(0o700)
        issues, healed = sd._heal_permissions(self.state, auto_heal=True)
        self.assertEqual((issues, healed), ([], []))


class TestSweepStaleTemps(_DoctorCase):
    """_sweep_stale_temps: orphaned atomic .tmp-* files."""

    def test_stale_orphan_removed_fresh_kept(self):
        stale = self.state / ".tmp-pathway"
        stale.write_text("x", encoding="utf-8")
        self.backdate(stale, 7200)
        fresh = self.state / "note.tmp-123"
        fresh.write_text("y", encoding="utf-8")

        found, removed = sd._sweep_stale_temps(
            self.state, stale_seconds=3600.0, auto_heal=True)

        self.assertEqual((found, removed), (1, 1))
        self.assertFalse(stale.exists())
        self.assertTrue(fresh.exists())

    def test_no_auto_heal_reports_without_removal(self):
        stale = self.state / ".tmp-phase"
        stale.write_text("x", encoding="utf-8")
        self.backdate(stale, 7200)
        found, removed = sd._sweep_stale_temps(
            self.state, stale_seconds=1.0, auto_heal=False)
        self.assertEqual((found, removed), (1, 0))
        self.assertTrue(stale.exists())

    def test_non_temp_files_ignored(self):
        keep = self.state / "budget_ledger.json"
        keep.write_text("{}", encoding="utf-8")
        self.backdate(keep, 999999)
        found, removed = sd._sweep_stale_temps(
            self.state, stale_seconds=1.0, auto_heal=True)
        self.assertEqual((found, removed), (0, 0))
        self.assertTrue(keep.is_file())


class TestRunDiagnostics(_DoctorCase):
    """run_diagnostics: scoring gates, healing actions, report shape."""

    def test_healthy_state_scores_100(self):
        result = self.diagnostics()
        self.assertTrue(result["ok"])
        self.assertEqual(result["health_score"], 100)
        self.assertEqual(result["issues"], [])
        self.assertEqual(result["healed_actions"], [])
        self.assertEqual(len(result["sqlite"]), 2)
        self.assertTrue(all(s["present"] is False for s in result["sqlite"]))
        self.assertEqual(result["hardware"]["state"], "ok")
        self.assertIsNone(result["sri_ok"])
        self.assertIsNone(result["viewer_qa_ok"])
        self.assertIsNone(result["security_ok"])

    def test_warm_hardware_costs_ten(self):
        self.hardware = {"state": "warm", "reasons": ["termometr 71C"]}
        result = self.diagnostics()
        self.assertEqual(result["health_score"], 90)
        self.assertIn("termometr 71C", result["issues"])

    def test_critical_hardware_costs_twenty_five_but_still_ok(self):
        self.hardware = {"state": "critical", "reasons": ["RAM 97%"]}
        result = self.diagnostics()
        # 100 - 25 = 75 >= 70 and no corrupt DB -> still green
        self.assertEqual(result["health_score"], 75)
        self.assertTrue(result["ok"])
        self.assertIn("RAM 97%", result["issues"])

    def test_corrupt_db_without_heal_fails_report_even_at_score_75(self):
        db = self.state / "episodic_memory.sqlite3"
        db.write_bytes(b"broken\x00\xff")
        db.chmod(0o600)  # keep permissions out of the accounting
        self.hardware = {"state": "critical", "reasons": ["RAM 97%"]}
        result = self.diagnostics(auto_heal=False)
        self.assertEqual(result["health_score"], 50)  # 25 db + 25 hw
        self.assertFalse(result["ok"])
        corrupt_reports = [i for i in result["issues"]
                           if "Uszkodzona" in fold(i)]
        self.assertEqual(len(corrupt_reports), 1)

    def test_corrupt_db_with_heal_restores_full_score_and_evicts(self):
        db = self.state / "semantic_cache.sqlite3"
        db.write_bytes(b"broken\x00\x01")
        self.ejected = ["idx-a", "idx-b", "idx-c"]

        result = self.diagnostics(auto_heal=True)

        self.assertEqual(result["health_score"], 100)
        self.assertTrue(result["ok"])
        actions = [fold(a) for a in result["healed_actions"]]
        self.assertTrue(any("kwarantanna" in a for a in actions))
        self.assertTrue(any("zwolniono 3" in a for a in actions))
        # no stale temps were seeded, so no removal action is reported
        self.assertFalse([a for a in result["healed_actions"]
                          if ".tmp" in a])
        quarantined = list(self.state.glob(
            "semantic_cache.sqlite3.corrupt-*"))
        self.assertEqual(len(quarantined), 1)

    def test_project_without_viewer_runs_security_scan_only(self):
        proj = self.tmp / "project"
        proj.mkdir()
        self.security = {"ok": False, "findings_count": 3}
        result = self.diagnostics(project_dir=proj)
        self.assertFalse(result["security_ok"])
        self.assertEqual(result["health_score"], 75)
        # 75 is still >= 70, so the overall gate stays green at the limit.
        self.assertTrue(result["ok"])
        self.assertIn("Skaner", fold(
            [i for i in result["issues"] if "zagro" in fold(i)][0]))
        self.assertIsNone(result["sri_ok"])

    def test_viewer_gates_apply_sri_and_qa_scores(self):
        proj = self.tmp / "viewer-proj"
        (proj / "viewer").mkdir(parents=True)
        (proj / "viewer" / "index.html").write_text(
            "<html><script src=\"capabilities.js\"></script></html>",
            encoding="utf-8")
        holder = self.install_change_impact()
        self.sri = {"ok": False, "updated": 4, "mismatches": ["a", "b"]}
        self.viewer_qa = {"ok": False, "issues": ["brak capabilities"]}
        self.security = {"ok": True, "findings_count": 0}

        result = self.diagnostics(project_dir=proj)

        self.assertEqual(holder["calls"], 1)
        self.assertFalse(result["viewer_qa_ok"])
        # sri "updated" counts as healed, not as an issue; qa gate costs 20.
        self.assertEqual(result["health_score"], 80)
        self.assertTrue(any("sha384" in fold(a)
                            for a in result["healed_actions"]))
        self.assertIn("brak capabilities", result["issues"])

    def test_sri_mismatch_without_fix_costs_twenty(self):
        proj = self.tmp / "viewer-proj2"
        (proj / "viewer").mkdir(parents=True)
        (proj / "viewer" / "index.html").write_text("x", encoding="utf-8")
        self.install_change_impact()
        self.sri = {"ok": False, "updated": 0, "mismatches": ["m1", "m2"]}
        self.viewer_qa = {"ok": True, "issues": []}

        result = self.diagnostics(project_dir=proj)

        self.assertFalse(result["sri_ok"])
        self.assertEqual(result["health_score"], 80)
        mismatch = [i for i in result["issues"] if "SRI" in fold(i)]
        self.assertEqual(len(mismatch), 1)
        self.assertIn("2", mismatch[0])  # mismatch count surfaced

    def test_score_clamped_to_zero_and_report_keys_stable(self):
        db = self.state / "episodic_memory.sqlite3"
        db.write_bytes(b"broken\x00")
        self.hardware = {"state": "critical", "reasons": ["RAM 97%"]}
        stale = self.state / ".tmp-rogue"
        stale.write_text("x", encoding="utf-8")
        self.backdate(stale, 7200)
        proj = self.tmp / "proj3"
        proj.mkdir()
        (proj / "viewer").mkdir(parents=True)
        (proj / "viewer" / "index.html").write_text("x", encoding="utf-8")
        self.reset_sri_sec_for_floor(proj)
        result = self.diagnostics(project_dir=proj, auto_heal=False,
                                  stale_temp_seconds=3600.0)
        self.assertEqual(result["health_score"], 0)
        self.assertFalse(result["ok"])
        for key in ("checked_at", "auto_heal", "healed_actions", "issues",
                    "sqlite", "stale_temps_found", "hardware", "sri_ok",
                    "viewer_qa_ok", "security_ok"):
            self.assertIn(key, result)

    def reset_sri_sec_for_floor(self, proj):
        """Force every remaining gate to fail (-20 -25 adds to -55)."""
        holder_needed = self.install_change_impact()
        self.sri = {"ok": False, "updated": 0, "mismatches": ["x", "y"]}
        self.viewer_qa = {"ok": False, "issues": ["zle temp"]}
        self.security = {"ok": False, "findings_count": 9}
        return holder_needed


if __name__ == "__main__":
    unittest.main()
