"""Cloud budget guard: pricing estimates, two-tier status, ledger persistence,
background-run gating and the economy-model downgrade policy."""
import json
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest import TestCase, mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import budget_guard as guard


class _LedgerCase(TestCase):
    """Isolated agent_cli.ROOT on tmp so the real ledger is never touched."""

    def setUp(self):
        base = Path(tempfile.mkdtemp())
        self.root = base / "agent_cli"
        self.root.mkdir()
        self.ledger_path = base / "budget_ledger.json"
        self.lock_path = base / ".budget.lock"
        patcher = mock.patch.object(guard, "agent_cli", SimpleNamespace(ROOT=self.root))
        patcher.start()
        self.addCleanup(patcher.stop)

    def seed(self, ledger):
        self.ledger_path.write_text(json.dumps(ledger), encoding="utf-8")

    def stored(self):
        return json.loads(self.ledger_path.read_text(encoding="utf-8"))

    @property
    def today(self):
        return guard._today_keys()[0]

    @property
    def month(self):
        return guard._today_keys()[1]

    def publish_recorder(self):
        published = []
        bus = SimpleNamespace(publish=lambda name, payload: published.append((name, payload)))
        patcher = mock.patch.dict(sys.modules, {"event_bus": bus})
        return published, patcher


class EstimateCostTests(_LedgerCase):
    def test_pricing_prefix_rounding_and_clamps(self):
        cases = (
            ("claude-opus-4-5", 1_000_000, 0, 15.0),
            ("GPT-4o", 1_000_000, 0, 2.5),
            ("gemini-2.5-pro", 200_000, 100_000, 1.25),
            ("claude-haiku-4-5", 1_000_000, 0, 0.8),
            ("mystery", 1_000_000, 0, 1.0),
            ("groq", -5, -5, 0.0),
            ("groq", 3333, 777, 0.000229),
            ("claude-opus", 1, 1, 9e-05),
        )
        for model, in_tok, out_tok, expected in cases:
            self.assertEqual(guard.estimate_cost_usd(model, in_tok, out_tok), expected,
                             (model, in_tok, out_tok))
        day, month = guard._today_keys()
        self.assertEqual((len(day), len(month)), (10, 7))


class ComputeStatusTests(_LedgerCase):
    def _status(self, ledger):
        return guard._compute_status(ledger)

    def test_three_states_and_month_peak(self):
        ok = self._status({})
        self.assertEqual((ok["state"], ok["recommended_cloud_tier"], ok["utilization_ratio"]),
                         ("ok", "primary_cloud", 0.0))
        self.assertTrue(ok["allow_background"] and ok["allow_paid_cloud"])
        self.assertFalse(ok["prefer_economy_tier"])
        warning = self._status({"days": {self.today: 4.0},
                                "config": {"daily_limit_usd": 5.0}})
        self.assertEqual((warning["state"], warning["recommended_cloud_tier"],
                         warning["utilization_ratio"]),
                         ("warning", "economy_cloud", 0.8))
        self.assertTrue(warning["prefer_economy_tier"])
        capped = self._status({"months": {self.month: 60.5},
                               "config": {"daily_limit_usd": 5.0,
                                          "monthly_limit_usd": 60.0}})
        self.assertEqual((capped["state"], capped["recommended_cloud_tier"],
                         capped["utilization_ratio"], capped["spent_month_usd"]),
                         ("capped", "local_only", 1.0083, 60.5))
        self.assertFalse(capped["allow_background"] or capped["allow_paid_cloud"])
        self.assertTrue(capped["prefer_economy_tier"])

    def test_config_clamps_and_monthly_zero_quirk(self):
        clamped = self._status({"config": {"daily_limit_usd": 0.01,
                                           "monthly_limit_usd": 0.0,
                                           "soft_ratio": 0.1}})
        self.assertEqual((clamped["daily_limit_usd"], clamped["monthly_limit_usd"],
                          clamped["soft_ratio"]),
                         (0.05, 60.0, 0.3))
        high = self._status({"config": {"soft_ratio": 0.999}})
        self.assertEqual(high["soft_ratio"], 0.99)

    def test_recent_window_capped_at_15(self):
        snap = self._status({"recent": list(range(20))})
        self.assertEqual(snap["recent"], list(range(5, 20)))


class LedgerTests(_LedgerCase):
    def test_status_reads_ledger_and_creates_private_lock(self):
        self.seed({"days": {self.today: 1.0}})
        snap = guard.status()
        self.assertEqual((snap["spent_today_usd"], snap["state"]), (1.0, "ok"))
        self.assertTrue(self.lock_path.is_file())
        self.assertEqual(oct(self.lock_path.stat().st_mode & 0o777), "0o600")
        self.assertEqual(oct(self.root.parent.stat().st_mode & 0o777), "0o700")

    def test_allow_background_run_messages(self):
        self.assertEqual(guard.allow_background_run(), (True, "ok"))
        self.seed({"days": {self.today: 5.0}, "config": {"daily_limit_usd": 5.0}})
        allowed, reason = guard.allow_background_run()
        self.assertFalse(allowed)
        self.assertEqual(reason,
                         "Osiągnięto dzienny/miesięczny limit budżetu chmurowego ($5.00/$5.00).")

    def test_configure_limits_persists_and_publishes(self):
        published, patcher = self.publish_recorder()
        with patcher:
            snap = guard.configure_limits(daily_limit_usd=0.2, monthly_limit_usd=1.0,
                                          soft_ratio=0.5)
        self.assertEqual((snap["daily_limit_usd"], snap["monthly_limit_usd"], snap["soft_ratio"]),
                         (0.2, 1.0, 0.5))
        self.assertEqual(self.stored()["config"],
                         {"daily_limit_usd": 0.2, "monthly_limit_usd": 1.0, "soft_ratio": 0.5})
        self.assertEqual(published, [("budget.updated", snap)])

    def test_record_spend_estimate_override_and_entries(self):
        self.seed({"days": {self.today: 1.0}, "months": {self.month: 2.0}})
        published, patcher = self.publish_recorder()
        with patcher:
            first = guard.record_spend(model="groq", input_tokens=1_000_000,
                                       output_tokens=1_000_000)
            second = guard.record_spend(model="x", usd=0.1234565, prompt_tokens=10,
                                        completion_tokens=20, source="unit-test")
        self.assertEqual((first["spent_today_usd"], second["spent_today_usd"]), (1.13, 1.2535))
        stored = self.stored()
        self.assertEqual((stored["days"][self.today], stored["months"][self.month]),
                         (1.253456, 2.253456))
        entries = stored["recent"]
        self.assertEqual(entries[0]["usd"], 0.13)
        self.assertEqual((entries[1]["in_tok"], entries[1]["out_tok"]), (10, 20))
        self.assertEqual(entries[1]["source"], "unit-test")
        self.assertTrue(all(round(entry["ts"], 3) == entry["ts"] for entry in entries))
        self.assertEqual([name for name, _ in published], ["budget.updated", "budget.updated"])

    def test_record_spend_prunes_days_and_months(self):
        days = {f"2025-01-{day:02d}": 0.1 for day in range(2, 52)}
        days[self.today] = 1.0
        months = {f"2024-{month:02d}": 0.1 for month in range(1, 13)}
        months.update({f"2025-{month:02d}": 0.1 for month in range(1, 9)})
        months[self.month] = 1.0
        self.seed({"days": days, "months": months})
        guard.record_spend(model="groq", usd=0.01)
        stored = self.stored()
        self.assertEqual(len(stored["days"]), 45)
        self.assertEqual(len(stored["months"]), 18)
        self.assertGreaterEqual(min(stored["days"]), "2025-01-07")
        self.assertIn(self.today, stored["days"])
        self.assertIn(self.month, stored["months"])

    def test_record_spend_caps_recent_at_60(self):
        self.seed({"recent": [{"i": i} for i in range(60)]})
        guard.record_spend(model="m", usd=0.0)
        recent = self.stored()["recent"]
        self.assertEqual(len(recent), 60)
        self.assertEqual(recent[-1]["model"], "m")
        self.assertEqual(recent[0].get("i"), 1)

    def test_save_raw_is_atomic_and_private(self):
        guard._save_raw({"x": 1})
        self.assertEqual(self.stored(), {"x": 1})
        self.assertEqual(oct(self.ledger_path.stat().st_mode & 0o777), "0o600")
        self.assertEqual(list(self.root.parent.glob(".budget_ledger.json*")), [])
        self.assertTrue(self.ledger_path.is_file())


class EnforceModelTests(_LedgerCase):
    def seed_cap(self):
        self.seed({"days": {self.today: 5.0},
                   "config": {"daily_limit_usd": 5.0, "monthly_limit_usd": 60.0}})

    def seed_warning(self):
        self.seed({"days": {self.today: 4.0}, "config": {"daily_limit_usd": 5.0}})

    def test_capped_raises_exact_unless_override(self):
        self.seed_cap()
        with self.assertRaises(guard.BudgetExceededError) as ctx:
            guard.enforce_and_select_model("claude-opus")
        self.assertEqual(
            str(ctx.exception),
            "Osiągnięto 100% limitu budżetu chmurowego ($5.00 / $5.00). "
            "Zwiększ limit w Mission Control lub użyj jawnego potwierdzenia.")
        override = guard.enforce_and_select_model("claude-opus", allow_override=True)
        self.assertEqual(override, {"model": "claude-haiku-4-5", "requested_model": "claude-opus",
                                    "downgraded": True, "budget_state": "capped",
                                    "utilization_ratio": 1.0})

    def test_warning_downgrade_matrix(self):
        self.seed_warning()
        cases = (
            ("CLAUDE-OPUS-4-5", "general", "claude-haiku-4-5", True),
            ("gpt-5-mini", "general", "gpt-4o-mini", True),
            ("gemini-2.5-pro-002", "general", "gemini-2.5-flash", True),
            ("claude-haiku-4-5", "general", "claude-haiku-4-5", False),
            ("claude-sonnet-4", "architect_critical", "claude-sonnet-4", False),
            ("", "general", "", False),
        )
        for requested, role, model, downgraded in cases:
            reply = guard.enforce_and_select_model(requested, role=role)
            self.assertEqual((reply["model"], reply["downgraded"], reply["budget_state"]),
                             (model, downgraded, "warning"), requested)
            self.assertEqual(reply["requested_model"], requested)

    def test_ok_state_keeps_request(self):
        self.seed({})
        for requested in ("claude-opus-4-5", "claude-sonnet"):
            reply = guard.enforce_and_select_model(requested, role="architect_critical")
            self.assertEqual((reply["model"], reply["downgraded"], reply["budget_state"]),
                             (requested, False, "ok"))


if __name__ == "__main__":
    import unittest
    unittest.main()
