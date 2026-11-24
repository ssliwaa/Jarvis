"""End-to-end tests for Mission Control UI, Cloud Budget Guard, Night Shift,
Git PR Bridge, Workflow Miner, Time-Travel Fork, and Encrypted State Backup.
"""

import importlib.util
import shutil
import sqlite3
import subprocess
import tempfile
import os
import unittest
SANDBOXED = os.environ.get("JARVIS_VERIFY_SANDBOX") == "1"
from pathlib import Path
from unittest.mock import patch

import agent_cli
import agent_team
import budget_guard
import checkpoint_manager
import evolution
import git_pr_bridge
import night_shift
import state_backup
import time_travel
import visual_qa
import workflow_miner


@unittest.skipIf(SANDBOXED, "needs the developer's local env (vault/Hermes/Piper/desktop); skipped in CI")
class MissionSuiteTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir='/tmp' if Path('/tmp').is_dir() else None)
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name) / ".jarvis-tools"
        self.agents_root = self.base / "agents"
        self.agents_root.mkdir(parents=True, exist_ok=True)
        self.selfmod_dir = self.base / "selfmod"
        self.selfmod_dir.mkdir(parents=True, exist_ok=True)

        self.p_agents = patch.object(agent_cli, "ROOT", self.agents_root)
        self.p_state = patch.object(evolution, "STATE", self.selfmod_dir)
        self.p_agents.start()
        self.p_state.start()
        self.addCleanup(self.p_agents.stop)
        self.addCleanup(self.p_state.stop)

    def test_1_cloud_budget_guard_soft_warning_and_background_cap(self):
        budget_guard.configure_limits(daily_limit_usd=1.00, monthly_limit_usd=10.00, soft_ratio=0.80)
        ok_before, _ = budget_guard.allow_background_run()
        self.assertTrue(ok_before)

        st_warn = budget_guard.record_spend(model="claude-sonnet", usd=0.85, prompt_tokens=1000, completion_tokens=500)
        self.assertEqual(st_warn["state"], "warning")
        self.assertEqual(st_warn["recommended_cloud_tier"], "economy_cloud")
        self.assertTrue(st_warn["allow_background"])

        st_cap = budget_guard.record_spend(model="claude-sonnet", usd=0.25)
        self.assertEqual(st_cap["state"], "capped")
        ok_after, reason = budget_guard.allow_background_run()
        self.assertFalse(ok_after)
        self.assertIn("limit budżetu chmurowego", reason)

    def test_2_night_shift_respects_budget_and_generates_morning_report(self):
        mini_proj = Path(self.tmp.name) / "mini_proj"
        mini_proj.mkdir(parents=True)
        (mini_proj / "sample_mod.py").write_text(
            "def greet(name='world'):\n    return f'hi {name}'\n",
            encoding="utf-8",
        )

        # When budget is capped and force=False, Night Shift skips cleanly
        budget_guard.configure_limits(daily_limit_usd=0.10)
        budget_guard.record_spend(usd=0.20)
        skipped = night_shift.run_night_shift(modules=["sample_mod"], project_root=mini_proj, force=False)
        self.assertFalse(skipped["ok"])
        self.assertTrue(skipped["skipped"])

        # Raising cap allows full Night Shift pass and persists Morning Report
        budget_guard.configure_limits(daily_limit_usd=10.00)
        with patch.object(night_shift, "check_system_quiet", return_value=(True, 0.15)), \
             patch("health_watchdog.scan_logs", return_value={"ok": True, "incidents": [], "dispatched": []}):
            rep = night_shift.run_night_shift(modules=["sample_mod"], project_root=mini_proj, force=False)
        self.assertTrue(rep["ok"])
        self.assertIn("Raport Nocnej Zmiany", rep["summary_text"])
        self.assertTrue(night_shift.latest_report()["has_report"])

    def test_3_git_pr_bridge_branch_from_outbox_and_sandbox_review(self):
        if not shutil.which("git"):
            self.skipTest("git not installed")

        repo = Path(self.tmp.name) / "git_repo"
        repo.mkdir(parents=True)
        subprocess.run(["git", "init", "-b", "main"], cwd=str(repo), check=True, capture_output=True)
        (repo / "service.py").write_text("VALUE = 1\n", encoding="utf-8")
        subprocess.run(["git", "add", "."], cwd=str(repo), check=True, capture_output=True)
        subprocess.run(
            ["git", "-c", "user.name=Test", "-c", "user.email=t@local", "commit", "-m", "init"],
            cwd=str(repo), check=True, capture_output=True,
        )

        # Stage a team outbox modification
        agent_team.create_project(
            goal="PR branch test", participants=["claude"], project_id="pr-team",
            use_worktrees=False, auto_wake_mentions=False,
        )
        pdir = agent_team.project_root("pr-team")
        (pdir / "repo" / "service.py").write_text("VALUE = 2\n", encoding="utf-8")
        agent_team.sync_repo_to_outbox("pr-team")

        cp_base = self.base / "checkpoints"
        with patch.object(checkpoint_manager, "default_manager",
                          side_effect=lambda **kw: checkpoint_manager.CheckpointManager(base=cp_base, enabled=True)):
            br = git_pr_bridge.create_branch_from_outbox(
                repo, "feat/auto-upgrade", "team:pr-team", commit_message="Upgrade VALUE to 2"
            )
        self.assertTrue(br["ok"])
        self.assertEqual(br["branch"], "feat/auto-upgrade")
        # Main working tree remains untouched (`VALUE = 1`)!
        self.assertEqual((repo / "service.py").read_text(encoding="utf-8"), "VALUE = 1\n")

        # Review the new branch in isolated sandbox worktree
        rev = git_pr_bridge.review_ref_in_sandbox(repo, "feat/auto-upgrade")
        self.assertTrue(rev["ok"])
        self.assertIn("service.py", rev["changed_files"])

    def test_4_workflow_miner_discovers_pattern_and_compiles_callable_macro(self):
        for _ in range(3):
            workflow_miner.record_event("clipboard.read", target="selection")
            workflow_miner.record_event("ocr.extract", target="screenshot")
            workflow_miner.record_event("notes.save", target="inbox.md", params={"tag": "clip"})

        patterns = workflow_miner.mine_patterns(min_len=2, max_len=4, min_support=3)
        self.assertGreaterEqual(len(patterns), 1)
        top = patterns[0]
        self.assertEqual(top["length"], 3)
        self.assertEqual(top["support"], 3)

        compiled = workflow_miner.compile_macro(top["id"], name="clip_ocr_inbox")
        self.assertTrue(compiled["ok"])
        macro_file = Path(compiled["macro"]["file"])
        self.assertTrue(macro_file.is_file())

        spec = importlib.util.spec_from_file_location("macro_mod", str(macro_file))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        calls = []
        res = mod.run_macro(executor=lambda k, t, p: calls.append((k, t)))
        self.assertTrue(res["ok"])
        self.assertEqual(len(calls), 3)

    def test_5_time_travel_fork_rewinds_both_session_turns_and_workspace_files(self):
        if not shutil.which("git"):
            self.skipTest("git not installed")

        cp_base = self.base / "checkpoints"
        proj = Path(self.tmp.name) / "tt_workspace"
        proj.mkdir(parents=True)
        (proj / "module.py").write_text("STEP = 1\n", encoding="utf-8")

        msgs = [
            {"role": "user", "content": "Krok 1"},
            {"role": "assistant", "content": "Gotowe 1"},
            {"role": "user", "content": "Krok 2 (błędny kierunek)"},
            {"role": "assistant", "content": "Gotowe 2"},
        ]

        with patch.object(checkpoint_manager, "default_manager",
                          side_effect=lambda **kw: checkpoint_manager.CheckpointManager(base=cp_base, enabled=True)):
            tp = time_travel.record_timepoint(
                session_id="sesja-glowna",
                turn_index=2,
                project_dir=proj,
                messages=msgs,
                label="Przed eksperymentem",
            )
            self.assertTrue(tp["commit_hash"])

            # Mutate workspace file after timepoint
            (proj / "module.py").write_text("STEP = 999\n", encoding="utf-8")

            forked = time_travel.fork_timepoint(tp["id"], restore_files=True)
            self.assertTrue(forked["ok"])
            self.assertEqual(forked["messages_restored"], 2)
            self.assertTrue(forked["files_restored"])
            self.assertEqual((proj / "module.py").read_text(encoding="utf-8"), "STEP = 1\n")

    def test_6_encrypted_state_backup_sqlite_safety_hmac_and_restore(self):
        # Create a live SQLite DB + JSON state under self.base
        db_path = self.base / "memory.sqlite3"
        conn = sqlite3.connect(str(db_path))
        conn.execute("CREATE TABLE facts(k TEXT, v TEXT)")
        conn.execute("INSERT INTO facts VALUES ('owner', 'kowalski')")
        conn.commit()
        conn.close()
        (self.selfmod_dir / "learned-rules.json").write_text('["Zawsze testuj"]', encoding="utf-8")

        out_dir = Path(self.tmp.name) / "bkp_out"
        created = state_backup.create_backup(
            passphrase="BardzoSilneHaslo123!",
            source_root=self.base,
            output_dir=out_dir,
        )
        self.assertTrue(created["ok"])
        self.assertTrue(created["verified"])
        bkp_file = Path(created["path"])
        self.assertTrue(bkp_file.is_file())

        # Wrong password fails HMAC check
        with self.assertRaises(state_backup.BackupError):
            state_backup.verify_backup(bkp_file, passphrase="ZleHaslo999")

        # Tampered byte fails Encrypt-then-MAC verification
        tampered = out_dir / "tampered.jenc"
        raw = bytearray(bkp_file.read_bytes())
        raw[-10] ^= 0xFF
        tampered.write_bytes(bytes(raw))
        with self.assertRaises(state_backup.BackupError):
            state_backup.verify_backup(tampered, passphrase="BardzoSilneHaslo123!")

        # Clean restore recovers SQLite DB and JSON files intact
        restore_dir = Path(self.tmp.name) / "restored_state"
        restored = state_backup.restore_backup(bkp_file, restore_dir, passphrase="BardzoSilneHaslo123!")
        self.assertTrue(restored["ok"])
        self.assertGreaterEqual(restored["restored_files"], 2)

        r_conn = sqlite3.connect(str(restore_dir / "memory.sqlite3"))
        row = r_conn.execute("SELECT v FROM facts WHERE k='owner'").fetchone()
        r_conn.close()
        self.assertEqual(row[0], "kowalski")

    def test_7_mission_control_viewer_passes_visual_qa_and_js_syntax(self):
        viewer_dir = Path(__file__).resolve().parent.parent / "viewer"
        index_html = (viewer_dir / "index.html").read_text(encoding="utf-8")
        self.assertIn('data-studio-tab="mission"', index_html)
        self.assertIn('id="studio-mission"', index_html)
        self.assertIn('src="mission.js"', index_html)

        with patch.object(visual_qa, "_find_browser", return_value=""):
            qa = visual_qa.run_visual_qa(viewer_dir)
        self.assertEqual(qa["missing_assets"], [])
        self.assertEqual(qa.get("syntax_errors", []), [])
        self.assertTrue(qa["ok"])


if __name__ == "__main__":
    unittest.main()
