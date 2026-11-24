"""Unit tests for `morning_briefing.py` — telemetry mapping, action rules, spoken branches.

Dotąd moduł testowany wyłącznie happy-pathem w `test_wave2_intelligence` (prawdziwe
voice_bridge/budget_guard/agent_router). Tu cała „światToFront" logika zaślepiona
przez `mock.patch.object` na atrybutach modułów zaimportowanych top-level w
`morning_briefing` — prawdziwe magazyny pytań, budżet, circuit-breakery i Nocna
Zmiana nigdy nie są dotykane. Chunker `wayland_voice.SentenceStreamChunker` jest
użyty prawdziwy (czysta klasa tekstowa, deterministyczna).
"""
from __future__ import annotations

import os
import sys
import time
import unittest
from contextlib import ExitStack
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

sys.path.insert(0, ".")

import morning_briefing as mb  # noqa: E402

FAKE_TELEMETRY = {
    "process_rss_mb": 123.4,
    "cpu_load_1m": 2.5,
    "cpu_cores": 8,
    "cpu_load_ratio": 0.313,
    "disk_free_gb": 55.2,
    "disk_total_gb": 512.0,
    "peak_temp_c": 60.0,
    "mem_available_mb": 3906.0,
    "thermal_state": "nominal",
    "recommended_max_parallel_agents": 3,
    "dnd": {"dnd": False, "reason": "clear"},
}


class HostTelemetryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)

    def _hw_snapshot(self, **hw) -> None:
        snap = {
            "peak_temp_c": 71.5,
            "mem_available_mb": 2048.0,
            "state": "nominal",
            "recommended_max_parallel_agents": 3,
        }
        snap.update(hw)
        self.stack.enter_context(
            mock.patch.object(mb.hardware_guard, "snapshot", return_value=snap))

    def test_telemetry_passes_hw_keys_and_dnd(self):
        self._hw_snapshot()
        self.stack.enter_context(mock.patch.object(
            mb.wayland_voice, "dnd_status", return_value={"dnd": True, "reason": "spotkanie"}))

        tel = mb.host_telemetry(self.tmp.name)
        self.assertEqual(tel["peak_temp_c"], 71.5)
        self.assertEqual(tel["mem_available_mb"], 2048.0)
        self.assertEqual(tel["thermal_state"], "nominal")
        self.assertEqual(tel["recommended_max_parallel_agents"], 3)
        self.assertEqual(tel["dnd"], {"dnd": True, "reason": "spotkanie"})
        self.assertEqual(tel["cpu_cores"], max(1, os.cpu_count() or 1))
        self.assertEqual(tel["cpu_load_ratio"], round(tel["cpu_load_1m"] / tel["cpu_cores"], 3))
        self.assertIsNotNone(tel["disk_free_gb"])
        self.assertIsNotNone(tel["disk_total_gb"])
        self.assertGreaterEqual(tel["disk_free_gb"], 0.0)
        self.assertEqual(set(tel.keys()), set(FAKE_TELEMETRY.keys()))

    def test_telemetry_reads_rss_from_proc(self):
        """Na Linuksie VmRSS istnieje → rss_mb dodatni i zaokrąglony do 1 miejsca."""
        self._hw_snapshot(state="warm", recommended_max_parallel_agents=1)
        tel = mb.host_telemetry(self.tmp.name)
        self.assertIsInstance(tel["process_rss_mb"], float)
        self.assertGreater(tel["process_rss_mb"], 0.0)
        self.assertEqual(tel["thermal_state"], "warm")
        self.assertEqual(tel["recommended_max_parallel_agents"], 1)

    def test_telemetry_falls_back_to_root_for_missing_target(self):
        """Nieistniejący target_dir nie wybucha — disk_usage('/') przejmuje rolę."""
        self._hw_snapshot()
        tel = mb.host_telemetry(str(Path(self.tmp.name) / "nie-ma-takiego"))
        self.assertIsNotNone(tel["disk_free_gb"])
        self.assertGreater(tel["disk_free_gb"], 0.0)


class GenerateBriefingTests(unittest.TestCase):
    """Czysty świat w setUp; testy nadpisują pojedyncze faux przed wywołaniem."""

    def setUp(self) -> None:
        self.tmp = TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)

        self.telemetry = dict(FAKE_TELEMETRY)
        self.telemetry_mock = self.stack.enter_context(
            mock.patch.object(mb, "host_telemetry", return_value=self.telemetry))
        self.pending_mock = self.stack.enter_context(
            mock.patch.object(mb.voice_bridge, "pending_owner_questions", return_value=[]))
        self.budget_mock = self.stack.enter_context(mock.patch.object(
            mb.budget_guard, "status",
            return_value={"state": "ok", "spent_today_usd": 0.42, "daily_limit_usd": 2.0,
                          "recommended_cloud_tier": "small"}))
        self.nshift_mock = self.stack.enter_context(mock.patch.object(
            mb.night_shift, "latest_report", return_value={"has_report": False}))
        self.watchdog_mock = self.stack.enter_context(mock.patch.object(
            mb.health_watchdog, "watchdog_status", return_value={"incidents": []}))
        self.circuits_mock = self.stack.enter_context(
            mock.patch.object(mb.agent_router, "active_circuits", return_value={}))
        self.projects_mock = self.stack.enter_context(
            mock.patch.object(mb.agent_team, "list_projects", return_value=[]))
        self.memstats_mock = self.stack.enter_context(mock.patch.object(
            mb.episodic_memory, "memory_stats", return_value={"total": 5}))

    def _brief(self):
        return mb.generate_briefing(self.tmp.name)

    def test_clean_world_low_priority_night_shift_and_summary(self):
        brief = self._brief()
        self.assertTrue(brief["ok"])
        self.assertEqual(
            [(a["code"], a["priority"]) for a in brief["next_actions"]],
            [("RUN_NIGHT_SHIFT", "low")],
        )
        self.assertIn(
            "Wszystkie bezpieczniki są czyste, a w pamięci epizodycznej zapisano 5 zdarzeń.",
            brief["spoken_summary"],
        )
        self.assertTrue(brief["spoken_chunks"])
        self.assertEqual(brief["pending_questions_count"], 0)
        self.assertEqual(brief["active_projects_count"], 0)
        self.assertEqual(brief["open_circuits"], [])
        self.assertEqual(brief["watchdog_incidents"], 0)
        self.assertEqual(brief["episodic_memory"], {"total": 5})
        self.assertEqual(
            brief["budget"],
            {"state": "ok", "spent_today_usd": 0.42, "daily_limit_usd": 2.0,
             "recommended_cloud_tier": "small"},
        )
        self.assertAlmostEqual(brief["generated_at"], time.time(), delta=10.0)

    def test_greeting_follows_local_hour(self):
        for hour, expected_start in ((4, "Dobry wieczór."), (5, "Dzień dobry."),
                                     (12, "Cześć."), (18, "Dobry wieczór.")):
            with mock.patch.object(mb.time, "localtime",
                                   return_value=time.struct_time((2026, 1, 1, hour, 0, 0, 0, 0, -1))):
                brief = self._brief()
            self.assertTrue(brief["spoken_summary"].startswith(expected_start), brief["spoken_summary"])

    def test_answer_agent_high_priority_first_with_truncation(self):
        self.pending_mock.return_value = [
            {"from": "hermes", "question": "q" * 300},
        ]
        brief = self._brief()
        first = brief["next_actions"][0]
        self.assertEqual(first["code"], "ANSWER_AGENT")
        self.assertEqual(first["priority"], "high")
        self.assertEqual(first["title"], "Odpowiedz agentowi hermes (1 oczekujące)")
        self.assertEqual(first["detail"], "q" * 180)
        self.assertIn("Czeka 1 pytanie od agenta hermes.", brief["spoken_summary"])

    def test_circuit_open_lists_sorted_names(self):
        self.circuits_mock.return_value = {"opencode": {"until": 1.0}, "claude": {"until": 2.0}}
        brief = self._brief()
        action = next(a for a in brief["next_actions"] if a["code"] == "CIRCUIT_OPEN")
        self.assertEqual(action["priority"], "high")
        self.assertIn("claude, opencode", action["title"])
        self.assertEqual(brief["open_circuits"], ["opencode", "claude"])
        self.assertIn("częściowo aktywne", brief["spoken_summary"])

    def test_budget_warning_is_medium_capped_is_high(self):
        self.budget_mock.return_value = {
            "state": "warning", "spent_today_usd": 1.2, "daily_limit_usd": 2.0,
            "recommended_cloud_tier": "small",
        }
        action = next(a for a in self._brief()["next_actions"] if a["code"] == "BUDGET_ALERT")
        self.assertEqual(action["priority"], "medium")
        self.assertIn("Budżet chmurowy: $1.20 / $2.00 (warning)", action["title"])

        self.budget_mock.return_value = {
            "state": "capped", "spent_today_usd": 2.0, "daily_limit_usd": 2.0,
            "recommended_cloud_tier": "tiny",
        }
        action = next(a for a in self._brief()["next_actions"] if a["code"] == "BUDGET_ALERT")
        self.assertEqual(action["priority"], "high")
        self.assertEqual(action["detail"], "Aktywny tryb routingu: tiny.")

    def test_low_disk_only_under_10_gb(self):
        self.telemetry["disk_free_gb"] = 9.5
        brief = self._brief()
        action = next(a for a in brief["next_actions"] if a["code"] == "LOW_DISK")
        self.assertEqual(action["priority"], "high")
        self.assertIn("9.5 GB", action["title"])

        self.telemetry["disk_free_gb"] = None
        codes = [a["code"] for a in self._brief()["next_actions"]]
        self.assertNotIn("LOW_DISK", codes)

    def test_viewer_qa_replaces_night_shift_when_report_exists(self):
        """has_report=True + qa z uwagami → VIEWER_QA_ISSUE (high), bez RUN_NIGHT_SHIFT."""
        self.nshift_mock.return_value = {
            "has_report": True,
            "viewer_qa": {"ok": False, "issues": ["misja.js", "viewer.css"]},
        }
        brief = self._brief()
        codes = [a["code"] for a in brief["next_actions"]]
        self.assertIn("VIEWER_QA_ISSUE", codes)
        self.assertNotIn("RUN_NIGHT_SHIFT", codes)
        action = next(a for a in brief["next_actions"] if a["code"] == "VIEWER_QA_ISSUE")
        self.assertEqual(action["priority"], "high")
        self.assertIn("misja.js; viewer.css", action["detail"])

    def test_active_projects_count_and_spoken_branch(self):
        self.projects_mock.return_value = [
            {"status": "running"}, {"status": "active"}, {"status": "done"},
        ]
        brief = self._brief()
        self.assertEqual(brief["active_projects_count"], 2)
        self.assertIn("W tle pracuje obecnie 2 zespół projektowy.", brief["spoken_summary"])

    def test_full_crisis_action_ordering(self):
        """Kolejność akcji w pełnym kryzysie: pytanie → kwarantanna → budżet → dysk → noc."""
        self.pending_mock.return_value = [{"from": "opus", "question": "Migrujemy?"}]
        self.circuits_mock.return_value = {"opus": {}}
        self.budget_mock.return_value = {
            "state": "capped", "spent_today_usd": 2.0, "daily_limit_usd": 2.0,
            "recommended_cloud_tier": "tiny",
        }
        self.telemetry["disk_free_gb"] = 8.1
        brief = self._brief()
        self.assertEqual(
            [a["code"] for a in brief["next_actions"]],
            ["ANSWER_AGENT", "CIRCUIT_OPEN", "BUDGET_ALERT", "LOW_DISK", "RUN_NIGHT_SHIFT"],
        )

    def test_spoken_summary_budget_line_uses_fallback_for_none_rss(self):
        self.telemetry["process_rss_mb"] = None
        brief = self._brief()
        self.assertIn("zużywa niewiele megabajtów", brief["spoken_summary"])
        self.assertIn("to 0.42 dolara z limitu 2.00.", brief["spoken_summary"])


if __name__ == "__main__":
    unittest.main()
