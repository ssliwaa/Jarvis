"""End-to-end tests for the 6 SOTA self-improvement upgrades in evolve_engine.py."""

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import evolution
import evolve_engine

SANDBOXED = os.environ.get("JARVIS_VERIFY_SANDBOX") == "1"


class EvolveSotaTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.state_dir = Path(self.tmp.name) / "selfmod"
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.p_state = patch.object(evolution, "STATE", self.state_dir)
        self.p_state.start()
        self.addCleanup(self.p_state.stop)

    def test_1_map_elites_preserves_both_compact_fast_and_rich_thorough_champions(self):
        arch = evolution.Archive(self.state_dir / "archive.json")
        grid = evolve_engine.MapElitesGrid(self.state_dir / "map_elites.json")

        compact_src = "def score_fn(x):\n    return x * 2\n"
        rich_lines = ["def score_fn(x):"] + [f"    if x == {i}:\n        return {i * 2}" for i in range(70)] + ["    return x * 2"]
        rich_src = "\n".join(rich_lines) + "\n"

        n_compact = arch.record(
            module="ranker", file="ranker.py", parent="",
            score={"score": 1.0}, before=None, verdict="baseline", source=compact_src,
        )
        n_rich = arch.record(
            module="ranker", file="ranker.py", parent="",
            score={"score": 1.0}, before=None, verdict="improved", source=rich_src,
        )

        r1 = grid.insert(module="ranker", node_id=n_compact["id"], score=1.0, source=compact_src, duration_ms=15.0, island=0)
        r2 = grid.insert(module="ranker", node_id=n_rich["id"], score=1.0, source=rich_src, duration_ms=900.0, island=1)
        self.assertTrue(r1["accepted"])
        self.assertTrue(r2["accepted"])
        self.assertNotEqual(r1["cell"], r2["cell"])

        elites = grid.elites("ranker")
        self.assertEqual(len(elites), 2)

        migrated = grid.migrate_islands("ranker")
        self.assertGreaterEqual(migrated, 1)

        inspirations = grid.sample_inspirations("ranker", archive=arch, k=2)
        self.assertEqual(len(inspirations), 2)

        prompt = evolve_engine.build_crossover_prompt(
            "ranker.py", "Połącz szybkość i prostotę", compact_src,
            inspirations=inspirations, artifacts=["Wolny przebieg dla x=99"],
        )
        self.assertIn("Inspiracja #1", prompt)
        self.assertIn("Wolny przebieg dla x=99", prompt)

    def test_2_ucb_dgm_parent_selection_decays_over_exploited_branches(self):
        arch = evolution.Archive(self.state_dir / "archive.json")
        exhausted = arch.record(
            module="opt", file="opt.py", parent="",
            score={"score": 0.85}, before=None, verdict="baseline",
        )
        fresh = arch.record(
            module="opt", file="opt.py", parent="",
            score={"score": 0.80}, before=None, verdict="baseline",
        )
        # Simulate 30 failed attempts on `exhausted` -> UCB 1/sqrt(1+30) penalty
        for _ in range(30):
            evolution.record_attempt(arch, exhausted["id"])

        picks = [evolution.pick_parent(arch, "opt", temperature=0.05)["id"] for _ in range(10)]
        self.assertTrue(all(pid == fresh["id"] for pid in picks))

    @unittest.skipIf(SANDBOXED, "nested bwrap unavailable inside verification sandbox")
    def test_3_evolve_blocks_and_cascade_evaluator_with_tracemalloc(self):
        bench_dir = Path(self.tmp.name) / "bench"
        bench_dir.mkdir(parents=True)
        (bench_dir / "algo.json").write_text(
            '[{"call": "compute", "kwargs": {"n": 5}, "expect": 25, "level": 1}]',
            encoding="utf-8",
        )

        original = (
            "FROZEN_CONSTANT = 1\n\n"
            "def compute(n):\n"
            "    # EVOLVE-BLOCK-START:core_math\n"
            "    return n * n\n"
            "    # EVOLVE-BLOCK-END\n"
        )
        illegal_outside_edit = (
            "FROZEN_CONSTANT = 999\n\n"
            "def compute(n):\n"
            "    # EVOLVE-BLOCK-START:core_math\n"
            "    return n * n\n"
            "    # EVOLVE-BLOCK-END\n"
        )
        legal_inside_edit = (
            "FROZEN_CONSTANT = 1\n\n"
            "def compute(n):\n"
            "    # EVOLVE-BLOCK-START:core_math\n"
            "    buf = [i for i in range(100)]\n"
            "    return (n ** 2) if buf else 0\n"
            "    # EVOLVE-BLOCK-END\n"
        )

        with patch.object(evolution, "BENCH", bench_dir):
            rejected = evolve_engine.CascadeEvaluator.evaluate_candidate(
                "algo", illegal_outside_edit, original_source=original, strict_blocks=True
            )
            self.assertFalse(rejected["ok"])
            self.assertEqual(rejected["stage"], "evolve_block")

            accepted = evolve_engine.CascadeEvaluator.evaluate_candidate(
                "algo", legal_inside_edit, original_source=original, strict_blocks=True
            )
            self.assertTrue(accepted["ok"])
            self.assertEqual(accepted["score"], 1.0)
            self.assertGreaterEqual(accepted["peak_kb"], 0.0)

    @unittest.skipIf(SANDBOXED, "nested bwrap unavailable inside verification sandbox")
    def test_4_mutation_tester_and_adversarial_breaker_with_seal_guard(self):
        bench_dir = Path(self.tmp.name) / "bench_mut"
        bench_dir.mkdir(parents=True)
        src_path = Path(self.tmp.name) / "clamp_mod.py"
        src_path.write_text(
            "def clamp(val=0):\n"
            "    if val is None or val == '':\n"
            "        return 0\n"
            "    if val < 0:\n"
            "        return 0\n"
            "    return val + 1\n",
            encoding="utf-8",
        )
        # Weak bench: only tests val=5 -> leaves `val < 0` boundary mutant alive!
        (bench_dir / "clamp_mod.json").write_text(
            '[{"call": "clamp", "kwargs": {"val": 5}, "expect": 6, "level": 1}]',
            encoding="utf-8",
        )

        with patch.object(evolution, "BENCH", bench_dir), \
             patch.object(evolution, "BENCH_MANIFEST", bench_dir / "manifest.json"):
            evolution.Bench.seal()
            mut = evolve_engine.MutationTester.evaluate_suite("clamp_mod", source_path=src_path, max_mutants=5)
            self.assertGreater(mut["mutants"], 0)
            self.assertGreater(len(mut["survivors"]), 0)

            # Breaker writes ONLY to bench_drafts/ — sealed bench_dir has zero drift!
            draft = evolve_engine.AdversarialBreaker.generate_draft_cases("clamp_mod", source_path=src_path)
            self.assertTrue(draft["ok"])
            self.assertEqual(evolution.Bench.drift()["changed"], [])

            # Owner promotion merges passing cases and re-seals bench manifest
            promoted = evolve_engine.AdversarialBreaker.promote_draft("clamp_mod", only_passing=True)
            self.assertTrue(promoted["sealed"])
            self.assertGreaterEqual(promoted["added"], 1)
            self.assertEqual(evolution.Bench.drift()["changed"], [])

    def test_5_self_harness_prompt_evolution_rollback_and_skill_distillation(self):
        arch = evolution.Archive(self.state_dir / "archive.json")
        failures = evolution.Failures(self.state_dir / "failures.json")
        lab = evolution.PromptLab(self.state_dir / "prompts.json")

        failures.add("router", "Nie usuwaj obsługi pustego zapytania", kind="regressed")
        evolved = evolve_engine.SelfHarness.evolve_prompt_from_failures("patcher", failures=failures, lab=lab)
        self.assertTrue(evolved["updated"])
        self.assertIn("Nie usuwaj obsługi pustego zapytania", lab.get("patcher"))

        # Record 1 improved node -> distilled into Markdown skill
        node = arch.record(
            module="router", file="router.py", parent="",
            score={"score": 0.95}, before={"score": 0.75},
            verdict="improved", explanation="Dodano szybki skrót dla pustych wejść",
        )
        dist = evolve_engine.SkillDistiller.distill_from_archive(arch)
        self.assertEqual(dist["created"], 1)
        loaded_skill = evolve_engine.SkillDistiller.load_for_module("router")
        self.assertIn(node["id"], loaded_skill)

        # 3 consecutive regressions auto-rollback custom PromptLab override
        for _ in range(3):
            arch.record(
                module="router", file="router.py", parent=node["id"],
                score={"score": 0.4}, before={"score": 0.95}, verdict="regressed",
            )
        guarded = evolve_engine.SelfHarness.audit_and_guard_prompt("patcher", archive=arch, lab=lab)
        self.assertTrue(guarded["rolled_back"])
        self.assertEqual(lab.get("patcher"), evolution.PROMPT_DEFAULTS["patcher"])


if __name__ == "__main__":
    unittest.main()
