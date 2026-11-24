"""Regression tests for the 6 self-improvement audit fixes in evolution.py and self_modify.py."""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import evolution
import self_modify


class SelfModAuditFixesTests(unittest.TestCase):
    def test_fix1_archive_snapshots_and_true_dgm_ancestor_branching(self):
        with tempfile.TemporaryDirectory() as tmp:
            arch_path = Path(tmp) / "archive.json"
            archive = evolution.Archive(arch_path)
            v1_code = "def calc(x):\n    return x + 1\n"
            n1 = archive.record(
                module="demo",
                file="demo.py",
                parent="",
                score={"score": 0.8},
                before=None,
                verdict="baseline",
                source=v1_code,
            )
            self.assertTrue(n1["has_snapshot"])
            self.assertEqual(archive.source_of(n1["id"]), v1_code)

            # Give n1 improved descendants so pick_parent strongly prefers n1
            archive.record(
                module="demo",
                file="demo.py",
                parent=n1["id"],
                score={"score": 0.9},
                before={"score": 0.8},
                verdict="improved",
                source="def calc(x):\n    return x + 2\n",
            )

            # Even if disk currently holds a different experiment, branch_from_archive loads snapshot from Archive
            target = Path(tmp) / "demo.py"
            disk_code = "def calc(x):\n    return x * 999\n"
            target.write_text(disk_code, encoding="utf-8")

            heal = self_modify.AutoHeal(None, "test-model")
            heal.root = Path(tmp)
            with patch.object(evolution, "ARCHIVE", arch_path):
                base_src, parent_id = heal._select_base_source(target, disk_code, branch_from_archive=True)
            self.assertIn(parent_id, {r["id"] for r in archive.rows()})
            self.assertNotEqual(base_src, disk_code)

            # Tampering with snapshot on disk invalidates source_of()
            snap_file = archive.snapshots_dir / f"{n1['id']}.py"
            snap_file.write_text("TAMPERED = True\n", encoding="utf-8")
            self.assertIsNone(archive.source_of(n1["id"]))

    def test_fix2_root_modules_default_to_guarded_not_free(self):
        self.assertEqual(self_modify.policy_for(self_modify.ROOT / "agent_team.py"), "guarded")
        self.assertEqual(self_modify.policy_for(self_modify.ROOT / "telegram_channel.py"), "guarded")
        self.assertEqual(self_modify.policy_for(self_modify.ROOT / "future_new_core_module.py"), "guarded")

        # External temp test roots still allow "free" fixtures
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(self_modify.policy_for(Path(tmp) / "fixture_mod.py", root=Path(tmp)), "free")

    def test_fix3_jarvis_tools_hidden_in_evolution_sandbox(self):
        with tempfile.TemporaryDirectory(dir="/var/tmp" if Path("/var/tmp").is_dir() else None) as tmp:
            fake_home = Path(tmp) / "home"
            proposals_dir = fake_home / ".jarvis-tools" / "selfmod"
            proposals_dir.mkdir(parents=True)
            (proposals_dir / "proposals.json").write_text('[{"token":"SECRET_APPROVAL_TOKEN"}]', encoding="utf-8")

            dirs, _files = evolution.hidden_home_paths(fake_home)
            self.assertIn(fake_home / ".jarvis-tools", dirs)

            if shutil.which("bwrap") and os.environ.get("JARVIS_VERIFY_SANDBOX") != "1":
                with patch.dict(os.environ, {"HOME": str(fake_home)}):
                    probe = (
                        "import json, pathlib; "
                        f"p = pathlib.Path({str(proposals_dir / 'proposals.json')!r}); "
                        "print(json.dumps({'visible': p.exists()}))"
                    )
                    argv = evolution.sandbox_argv([sys.executable, "-c", probe])
                    proc = subprocess.run(argv, capture_output=True, text=True, timeout=10, check=False)
                    if proc.returncode == 0:
                        out = json.loads(proc.stdout.strip().splitlines()[-1])
                        self.assertFalse(out["visible"])

    def test_fix4_scorecard_unittests_parses_exact_ran_and_partial_failures(self):
        fake_stderr = (
            "Server listening on 127.0.0.1:4700 in 2026\n"
            "======================================================================\n"
            "Ran 10 tests in 0.042s\n\n"
            "FAILED (failures=2, errors=1)\n"
        )

        class _FakeProc:
            returncode = 1

            def communicate(self, timeout=None):
                return "", fake_stderr

        with patch.object(evolution.subprocess, "Popen", return_value=_FakeProc()):
            res = evolution.Scorecard.unittests("router")
        self.assertEqual(res["total"], 10)
        self.assertEqual(res["ok"], 7)

    def test_fix5_smart_source_window_and_independent_critic_model(self):
        filler = "\n".join(f"def filler_fn_{i}():\n    return {i}\n" for i in range(5500))
        tail_fn = "\ndef tail_critical_handler(payload):\n    return payload.get('status', 'ok')\n"
        huge_source = "import json\n\n" + filler + tail_fn
        self.assertGreater(len(huge_source), self_modify.MAX_PATCH)

        window = self_modify._smart_source_window(
            huge_source, "Popraw funkcję tail_critical_handler aby zwracała dict"
        )
        self.assertLessEqual(len(window), self_modify.MAX_PATCH)
        self.assertIn("def tail_critical_handler", window)
        self.assertIn("import json", window)

        used_models = []

        class _FakeMessages:
            def create(self, *, model, **kwargs):
                used_models.append(model)
                return SimpleNamespace(content=[SimpleNamespace(type="text", text='{"approve": true, "reasons": ["ok"]}')])

        fake_client = SimpleNamespace(messages=_FakeMessages())
        heal = self_modify.AutoHeal(fake_client, "generator-model-v1")
        with patch.dict(os.environ, {"JARVIS_SELFMOD_CRITIC_MODEL": "independent-critic-v2"}):
            verdict = heal.review(Path("router.py"), "X = 1\n", "X = 2\n", "Zmień stałą X")
        self.assertTrue(verdict["ok"])
        self.assertEqual(used_models, ["independent-critic-v2"])

    def test_fix6_planner_suggest_preserves_dot_py_extension(self):
        class _FakeMessages:
            def create(self, **kwargs):
                payload = {
                    "suggestions": [
                        {"file": "router.py", "instruction": "Dodaj cache", "evidence": "bench #2"},
                        {"file": "agent_team", "instruction": "Usprawnij locki", "evidence": "audit"},
                    ]
                }
                return SimpleNamespace(content=[SimpleNamespace(type="text", text=json.dumps(payload))])

        planner = self_modify.Planner(SimpleNamespace(messages=_FakeMessages()), "test-model")
        with patch.object(evolution, "suggest_prompt", return_value="signals"):
            res = planner.suggest(limit=3)
        files = [s["file"] for s in res["suggestions"]]
        self.assertEqual(files, ["router.py", "agent_team.py"])


if __name__ == "__main__":
    unittest.main()
