import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import agent_cli
import agent_review
import agent_team


class _DummyLog:
    def close(self):
        pass


class AgentTeamTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name) / '.jarvis-tools'
        self.agents_root = self.base / 'agents'
        self.agents_root.mkdir(parents=True, exist_ok=True)
        self.p_root = patch.object(agent_cli, 'ROOT', self.agents_root)
        self.p_root.start()
        self.addCleanup(self.p_root.stop)

    def test_chat_bus_and_atomic_file_claims(self):
        proj = agent_team.create_project(
            goal='Zbuduj wspólny kalkulator API + UI',
            participants=['claude', 'hermes'],
            project_id='calc-room',
            auto_wake_mentions=False,
        )
        self.assertEqual(proj['id'], 'calc-room')
        self.assertEqual(proj['participants'], ['claude', 'hermes'])

        agent_team.post_message('calc-room', sender='claude', role='backend', text='Endpoint POST /sum gotowy')
        agent_team.post_message('calc-room', sender='hermes', to='claude', kind='question', text='Jaki kod błędu dla NaN?')

        all_msgs = agent_team.read_messages('calc-room')
        self.assertGreaterEqual(len(all_msgs), 3)
        claude_msgs = agent_team.read_messages('calc-room', for_agent='claude')
        self.assertTrue(any('Jaki kod błędu' in m['text'] for m in claude_msgs))

        agent_team.claim_files('calc-room', 'claude', ['api/routes.py', 'shared'])
        with self.assertRaises(agent_team.TeamError):
            agent_team.claim_files('calc-room', 'hermes', ['api/routes.py'])
        with self.assertRaises(agent_team.TeamError):
            agent_team.claim_files('calc-room', 'hermes', ['shared/schema.json'])

        agent_team.claim_files('calc-room', 'hermes', ['ui/app.js'])
        locks = agent_team.active_claims('calc-room')
        self.assertEqual(locks['api/routes.py']['agent'], 'claude')
        self.assertEqual(locks['ui/app.js']['agent'], 'hermes')

        released = agent_team.release_files('calc-room', 'claude')
        self.assertIn('shared', released)
        agent_team.claim_files('calc-room', 'hermes', ['shared/schema.json'])

    def test_git_worktrees_auto_merge_and_conflict_detection(self):
        if not shutil.which('git'):
            self.skipTest('git not installed')

        agent_team.create_project(
            goal='Test izolowanych worktree git',
            participants=['claude', 'hermes'],
            project_id='wt-demo',
            use_worktrees=True,
            auto_wake_mentions=False,
        )
        pdir = agent_team.project_root('wt-demo')
        wt_c = agent_team.prepare_agent_worktree('wt-demo', 'claude', 1)
        wt_h = agent_team.prepare_agent_worktree('wt-demo', 'hermes', 1)
        self.assertNotEqual(wt_c, pdir / 'repo')
        self.assertNotEqual(wt_c, wt_h)

        # Non-overlapping edits merge cleanly into canonical repo/
        (wt_c / 'service.py').write_text('VALUE = 42\n', encoding='utf-8')
        (wt_h / 'client.py').write_text('NAME = "ok"\n', encoding='utf-8')
        m1 = agent_team.merge_agent_worktree('wt-demo', 'claude', 1)
        m2 = agent_team.merge_agent_worktree('wt-demo', 'hermes', 1)
        self.assertTrue(m1['merged'])
        self.assertTrue(m2['merged'])
        self.assertTrue((pdir / 'repo' / 'service.py').is_file())
        self.assertTrue((pdir / 'repo' / 'client.py').is_file())

        # Conflicting edits on the exact same line are detected and aborted cleanly
        wt_c2 = agent_team.prepare_agent_worktree('wt-demo', 'claude', 2)
        wt_h2 = agent_team.prepare_agent_worktree('wt-demo', 'hermes', 2)
        (wt_c2 / 'service.py').write_text('VALUE = 100\n', encoding='utf-8')
        (wt_h2 / 'service.py').write_text('VALUE = 999\n', encoding='utf-8')
        mc1 = agent_team.merge_agent_worktree('wt-demo', 'claude', 2)
        mc2 = agent_team.merge_agent_worktree('wt-demo', 'hermes', 2)
        self.assertTrue(mc1['merged'])
        self.assertFalse(mc2['merged'])
        self.assertIn('service.py', mc2['conflicts'])
        self.assertEqual((pdir / 'repo' / 'service.py').read_text(encoding='utf-8'), 'VALUE = 100\n')

    def test_worktree_merge_keeps_commits_the_agent_made_itself(self):
        # A coding CLI working in a real worktree commits on its own branch, so the
        # worktree is clean when the run ends. That must still be merged: relying on
        # `git status` alone silently threw such work away.
        if not shutil.which('git'):
            self.skipTest('git not installed')

        agent_team.create_project(
            goal='Agent commit sam',
            participants=['hermes'],
            project_id='wt-commit',
            use_worktrees=True,
            auto_wake_mentions=False,
        )
        pdir = agent_team.project_root('wt-commit')
        wt = agent_team.prepare_agent_worktree('wt-commit', 'hermes', 1)
        (wt / 'README.md').write_text('TEAM OK\n', encoding='utf-8')
        agent_team._git(wt, 'add', '-A')
        commit = agent_team._git(wt, 'commit', '-m', 'agent work')
        self.assertEqual(commit.returncode, 0, commit.stderr)
        self.assertEqual(agent_team._git(wt, 'status', '--porcelain').stdout.strip(), '')

        info = agent_team.merge_agent_worktree('wt-commit', 'hermes', 1)
        self.assertTrue(info['merged'])
        self.assertIn('README.md', info['changed_files'])
        self.assertEqual((pdir / 'repo' / 'README.md').read_text(encoding='utf-8'), 'TEAM OK\n')

    def test_architect_phase_and_deterministic_gate_before_review(self):
        pid_seq = iter(range(33000, 33100))
        events = {'arch': 0, 'review': 0, 'claude_builds': 0}

        def fake_spawn(argv, cwd, env, log_path):
            agent_id = env.get('JARVIS_TEAM_AGENT', '')
            role = env.get('JARVIS_TEAM_ROLE', '')
            work_dir = Path(cwd)
            pid = next(pid_seq)

            def _worker():
                if role == 'architect':
                    events['arch'] += 1
                    (work_dir / 'base.py').write_text('BASE = 1\n', encoding='utf-8')
                    plan = {
                        'board': '# Plan Architekta\n- claude: core.py\n- hermes: util.py',
                        'assignments': [
                            {'agent': 'claude', 'role': 'backend', 'subtask': 'Zbuduj core.py', 'paths': ['core.py']},
                            {'agent': 'hermes', 'role': 'frontend', 'subtask': 'Zbuduj util.py', 'paths': ['util.py']},
                        ],
                    }
                    (work_dir / 'PLAN.json').write_text(json.dumps(plan), encoding='utf-8')
                    Path(log_path).write_text('[STAGE] Plan ready\n', encoding='utf-8')
                elif role == 'backend':
                    events['claude_builds'] += 1
                    if events['claude_builds'] == 1:
                        # Intentional Python syntax error on round 1 -> caught by deterministic gate BEFORE review!
                        (work_dir / 'core.py').write_text('def broken(:\n    pass\n', encoding='utf-8')
                    else:
                        (work_dir / 'core.py').write_text('def working():\n    return 42\n', encoding='utf-8')
                    Path(log_path).write_text('[STAGE] Backend written\n', encoding='utf-8')
                elif role == 'frontend':
                    (work_dir / 'util.py').write_text('HELPER = True\n', encoding='utf-8')
                    Path(log_path).write_text('[STAGE] Util written\n', encoding='utf-8')
                elif role == 'reviewer':
                    events['review'] += 1
                    agent_team.post_message(
                        env['JARVIS_TEAM_ID'],
                        sender=agent_id,
                        role='reviewer',
                        kind='review',
                        text='[APPROVED] Kod kompiluje się i działa.',
                        _trigger_wake=False,
                    )
                    Path(log_path).write_text('[STAGE] Approved\n', encoding='utf-8')

            t = threading.Thread(target=_worker, daemon=True)
            t.start()

            class _Proc:
                def __init__(self, p, th):
                    self.pid = p
                    self._th = th
                    self.returncode = 0

                def wait(self, timeout=None):
                    self._th.join(timeout=timeout)
                    return 0

            return _Proc(pid, t), _DummyLog()

        with patch.object(agent_cli, 'binary_present', return_value=True), \
             patch.object(agent_cli, 'sandbox_argv', side_effect=lambda a, inner, **kw: inner), \
             patch.object(agent_cli, '_spawn', side_effect=fake_spawn):
            started = agent_team.start_team_project(
                goal='System z Architektem i bramką py_compile',
                project_id='arch-gate',
                participants=['claude', 'hermes'],
                architect_agent='claude',
                plan_first=True,
                review_agent='opencode',
                max_rounds=3,
                max_total_runs=15,
            )
            self.assertTrue(started['ok'])

            deadline = time.time() + 10.0
            st = {}
            while time.time() < deadline:
                st = agent_team.project_status('arch-gate')
                if st['status'] == 'done' and st['phase'] == 'completed':
                    break
                time.sleep(0.05)

        self.assertEqual(st['status'], 'done')
        self.assertEqual(events['arch'], 1)
        self.assertEqual(events['claude_builds'], 2, 'Round 1 syntax error should bounce to Round 2')
        self.assertEqual(events['review'], 1, 'Reviewer must only run ONCE after deterministic gate passes')
        self.assertTrue(st['last_gate']['ok'])
        out_names = {f['path'] for f in st['outbox_files']}
        self.assertIn('base.py', out_names)
        self.assertIn('core.py', out_names)
        self.assertIn('util.py', out_names)

    def test_gate_finds_tests_in_a_plain_directory_without_init(self):
        # tests/ without __init__.py is not a package: `unittest discover` from the
        # repo root collected nothing and the gate reported "NO TESTS RAN" while all
        # tests passed when run directly. The real project failed on exactly this.
        pid = 'gate-discovery'
        agent_team.create_project(goal='Gate discovery', participants=['hermes'], project_id=pid,
                                  use_worktrees=False, auto_wake_mentions=False)
        repo = agent_team.project_root(pid) / 'repo'
        (repo / 'tests').mkdir(parents=True, exist_ok=True)
        (repo / 'tests' / 'test_sample.py').write_text(
            'import unittest\n\n\nclass SampleTests(unittest.TestCase):\n'
            '    def test_one(self):\n        self.assertEqual(1, 1)\n', encoding='utf-8')
        (repo / 'mod.py').write_text('VALUE = 1\n', encoding='utf-8')

        gate = agent_team.run_deterministic_gate(pid)
        checks = {c['name']: c['ok'] for c in gate['checks']}
        self.assertTrue(checks.get('unittest'), gate)
        self.assertTrue(gate['ok'], gate)
        self.assertEqual(agent_team._count_unittest_tests('Ran 25 tests in 2.0s'), 25)
        self.assertEqual(agent_team._count_unittest_tests('Ran 0 tests in 0.000s'), 0)

    def test_member_timeout_is_bounded_by_project_time(self):
        pid = 'timeout-cap'
        agent_team.create_project(goal='Timeout cap', participants=['hermes'], project_id=pid,
                                  max_project_minutes=30, use_worktrees=False,
                                  auto_wake_mentions=False)
        captured = {}

        def fake_start_async(agent_id, task, **kwargs):
            captured.update(kwargs)
            return {'id': 'run-1', 'pid': 4242}

        with patch.object(agent_cli, 'start_async', side_effect=fake_start_async):
            agent_team._launch_member_async(
                pid, {'agent': 'hermes', 'role': 'developer', 'subtask': 'zadanie'}, 1)

        self.assertIsNotNone(captured.get('timeout'), captured)
        # At most half of the 30-minute budget; the CLI's own 1800 s must not win.
        self.assertLessEqual(captured['timeout'], 30 * 60 * 0.5 + 1)
        self.assertGreaterEqual(captured['timeout'], 120)

        # An explicit timeout (the architect pass) is capped by the budget too.
        agent_team.create_project(goal='Krótki projekt', participants=['hermes'], project_id='timeout-cap-2',
                                  max_project_minutes=5, use_worktrees=False,
                                  auto_wake_mentions=False)
        captured.clear()
        with patch.object(agent_cli, 'start_async', side_effect=fake_start_async):
            agent_team._launch_member_async(
                'timeout-cap-2', {'agent': 'hermes', 'role': 'architect', 'subtask': 'plan'}, 0,
                timeout=420)
        self.assertLessEqual(captured['timeout'], 5 * 60 - 120 + 1)
        self.assertGreaterEqual(captured['timeout'], 120)

    def test_timed_out_architect_is_not_relaunched_in_the_wave(self):
        roles = []
        pid_seq = iter(range(34000, 34100))

        def fake_spawn(argv, cwd, env, log_path):
            role = env.get('JARVIS_TEAM_ROLE', '')
            work_dir = Path(cwd)
            pid = next(pid_seq)

            def _worker():
                roles.append(role)
                if role == 'architect':
                    plan = {'board': '# plan', 'assignments': [
                        {'agent': 'claude', 'role': 'architect', 'subtask': 'spinaj', 'paths': []},
                        {'agent': 'hermes', 'role': 'backend', 'subtask': 'util', 'paths': ['util.py']},
                    ]}
                    (work_dir / 'PLAN.json').write_text(json.dumps(plan), encoding='utf-8')
                elif role == 'backend':
                    (work_dir / 'util.py').write_text('HELPER = True\n', encoding='utf-8')

            t = threading.Thread(target=_worker, daemon=True)
            t.start()

            class _Proc:
                def __init__(self, p, th, rc):
                    self.pid = p
                    self._th = th
                    self.returncode = rc

                def wait(self, timeout=None):
                    self._th.join(timeout=timeout)
                    return self.returncode

            return _Proc(pid, t, 1 if role == 'architect' else 0), _DummyLog()

        with patch.object(agent_cli, 'binary_present', return_value=True), \
             patch.object(agent_cli, 'sandbox_argv', side_effect=lambda a, inner, **kw: inner), \
             patch.object(agent_cli, '_spawn', side_effect=fake_spawn):
            started = agent_team.start_team_project(
                goal='Architekt pada, reszta pracuje',
                project_id='arch-timeout',
                participants=['claude', 'hermes'],
                architect_agent='claude',
                plan_first=True,
                max_total_runs=8,
            )
            self.assertTrue(started['ok'])
            deadline = time.time() + 10.0
            while time.time() < deadline:
                st = agent_team.project_status('arch-timeout')
                if st['phase'] == 'completed':
                    break
                time.sleep(0.05)

        self.assertEqual(roles.count('architect'), 1, 'a failed architect must not run twice')
        self.assertIn('backend', roles, 'the rest of the team must still work')

    def test_synchronous_ask_wakes_idle_colleague_and_returns_reply(self):
        agent_team.create_project(
            goal='Konsultacje synchroniczne ask/reply',
            participants=['claude', 'hermes'],
            project_id='ask-demo',
        )
        pdir = agent_team.project_root('ask-demo')

        def fake_spawn(argv, cwd, env, log_path):
            role = env.get('JARVIS_TEAM_ROLE', '')
            if role == 'responder':
                # Extract req_id from prompt and call jarvis-team reply
                prompt_str = ' '.join(argv)
                m = subprocess.run(
                    [sys.executable, '-c',
                     "import re, sys; m = re.search(r'ID pytania: `([^`]+)`', sys.argv[1]); print(m.group(1) if m else '')",
                     prompt_str],
                    capture_output=True, text=True, check=False,
                )
                req_id = m.stdout.strip()
                subprocess.run(
                    [sys.executable, str(pdir / 'bin' / 'jarvis-team'),
                     'reply', req_id, 'Token to JWT HS256'],
                    env={**os.environ, **env}, check=False,
                )
                Path(log_path).write_text('Answered\n', encoding='utf-8')
            proc = type('P', (), {'pid': 34567, 'returncode': 0, 'wait': lambda self, timeout=None: 0})()
            return proc, _DummyLog()

        with patch.object(agent_cli, 'binary_present', return_value=True), \
             patch.object(agent_cli, 'sandbox_argv', side_effect=lambda a, inner, **kw: inner), \
             patch.object(agent_cli, '_spawn', side_effect=fake_spawn):
            agent_team._ensure_request_watcher('ask-demo')
            ask_env = {
                **os.environ,
                'JARVIS_TEAM_DIR': str(pdir),
                'JARVIS_TEAM_ID': 'ask-demo',
                'JARVIS_TEAM_AGENT': 'claude',
                'JARVIS_TEAM_ROLE': 'backend',
            }
            ask_proc = subprocess.run(
                [sys.executable, str(pdir / 'bin' / 'jarvis-team'),
                 'ask', 'hermes', 'Jaki format ma token?', '--wait', '8'],
                env=ask_env, capture_output=True, text=True, timeout=12, check=False,
            )

        self.assertEqual(ask_proc.returncode, 0, ask_proc.stderr)
        self.assertIn('JWT HS256', ask_proc.stdout)

    def test_project_budget_and_agent_review_team_outbox_integration(self):
        agent_team.create_project(
            goal='Test budżetu i integracji z agent_review',
            participants=['claude'],
            project_id='budget-rev',
            max_total_runs=2,
            use_worktrees=False,
            auto_wake_mentions=False,
        )
        pdir = agent_team.project_root('budget-rev')
        (pdir / 'repo' / 'hello.py').write_text('MSG = "hello team"\n', encoding='utf-8')
        agent_team.sync_repo_to_outbox('budget-rev')

        target_dir = Path(self.tmp.name) / 'deploy_target'
        target_dir.mkdir(parents=True, exist_ok=True)
        (target_dir / 'hello.py').write_text('MSG = "old"\n', encoding='utf-8')

        diff = agent_review.diff_outbox('team:budget-rev', str(target_dir))
        self.assertTrue(diff['ok'])
        self.assertGreaterEqual(diff['changed'], 1)

        applied = agent_review.apply_outbox('team:budget-rev', str(target_dir), files=['hello.py'])
        self.assertEqual(applied['applied'], 1)
        self.assertEqual((target_dir / 'hello.py').read_text(encoding='utf-8'), 'MSG = "hello team"\n')

        # Exhaust budget (max_total_runs=2) and verify 3rd launch raises TeamError
        with agent_team._file_lock(pdir / '.meta.lock'):
            meta = agent_team._load_meta(pdir)
            meta['total_runs'] = 2
            agent_team._save_meta(pdir, meta)
        with patch.object(agent_cli, 'binary_present', return_value=True):
            with self.assertRaises(agent_team.TeamError) as ctx:
                agent_team.start_parallel_wave('budget-rev')
            self.assertIn('limit uruchomień', str(ctx.exception))

    def test_auto_fallback_when_member_hits_quota_429(self):
        pid_seq = iter(range(32000, 32050))

        def fake_spawn(argv, cwd, env, log_path):
            agent_id = env.get('JARVIS_TEAM_AGENT', '')
            pid = next(pid_seq)
            if agent_id == 'claude':
                Path(log_path).write_text('HTTP 429 Too Many Requests: quota exceeded\n', encoding='utf-8')
                rc = 1
            else:
                (Path(cwd) / 'recovered.py').write_text('OK = True\n', encoding='utf-8')
                Path(log_path).write_text('[STAGE] Recovered by fallback\n', encoding='utf-8')
                rc = 0
            proc = type('P', (), {'pid': pid, 'returncode': rc, 'wait': lambda self, timeout=None: rc})()
            return proc, _DummyLog()

        with patch.object(agent_cli, 'binary_present', side_effect=lambda a: a in ('claude', 'hermes')), \
             patch.object(agent_cli, 'sandbox_argv', side_effect=lambda a, inner, **kw: inner), \
             patch.object(agent_cli, '_spawn', side_effect=fake_spawn):
            agent_team.start_team_project(
                goal='Moduł z fallbackiem 429',
                project_id='fallback-proj',
                participants=['claude', 'hermes'],
                assignments=[
                    {'agent': 'claude', 'role': 'backend', 'subtask': 'Napisz recovered.py', 'paths': ['recovered.py']},
                ],
                auto_fallback=True,
            )
            deadline = time.time() + 6.0
            status = {}
            while time.time() < deadline:
                status = agent_team.project_status('fallback-proj')
                if status['status'] == 'done' and status['phase'] == 'completed':
                    break
                time.sleep(0.05)

        self.assertEqual(status['status'], 'done')
        out_names = {f['path'] for f in status['outbox_files']}
        self.assertIn('recovered.py', out_names)
        agents_in_hist = [h['agent'] for h in status['history']]
        self.assertEqual(agents_in_hist, ['claude', 'hermes'])

    def test_bwrap_live_worktree_chat_and_secret_isolation(self):
        if not shutil.which('bwrap') or not shutil.which('git'):
            self.skipTest('bwrap or git not installed')

        var_tmp = tempfile.TemporaryDirectory(dir='/var/tmp' if Path('/var/tmp').is_dir() else None)
        self.addCleanup(var_tmp.cleanup)
        fake_home = Path(var_tmp.name) / 'home'
        (fake_home / '.ssh').mkdir(parents=True)
        (fake_home / '.ssh' / 'id_ed25519').write_text('TOP_SECRET_SSH', encoding='utf-8')
        jarvis_tools = fake_home / '.jarvis-tools'
        live_agents_root = jarvis_tools / 'agents'
        jarvis_tools.mkdir(parents=True)
        (jarvis_tools / 'secrets.json').write_text('{"key":"TOP_SECRET"}', encoding='utf-8')

        with patch.object(agent_cli, 'ROOT', live_agents_root), \
             patch.dict(os.environ, {'HOME': str(fake_home)}):
            agent_cli._ensure_dirs('claude')
            agent_cli._ensure_dirs('hermes')
            agent_team.create_project('Sekretny inny projekt', participants=['claude'], project_id='other-secret', auto_wake_mentions=False)
            agent_team.create_project('Wspólny projekt worktree', participants=['claude', 'hermes'], project_id='collab-wt', use_worktrees=True, auto_wake_mentions=False)
            pdir = agent_team.project_root('collab-wt')
            wt_c = agent_team.prepare_agent_worktree('collab-wt', 'claude', 1)
            wt_h = agent_team.prepare_agent_worktree('collab-wt', 'hermes', 1)

            claude_code = (
                "import json, os, pathlib, subprocess\n"
                "r1 = subprocess.run(['jarvis-team', 'say', 'Czesc hermes z worktree!', '--to', 'hermes'], capture_output=True, text=True)\n"
                "pathlib.Path('backend.py').write_text('API_VERSION = 2\\n', encoding='utf-8')\n"
                "repo_ro = False\n"
                "try:\n"
                f"    (pathlib.Path({str(pdir / 'repo')!r}) / 'tamper.py').write_text('x')\n"
                "except OSError:\n"
                "    repo_ro = True\n"
                "sibling_wt_exists = pathlib.Path(" + repr(str(wt_h)) + ").exists()\n"
                "print(json.dumps({\n"
                "    'say_rc': r1.returncode,\n"
                "    'repo_ro': repo_ro,\n"
                "    'sibling_wt_exists': sibling_wt_exists,\n"
                "    'ssh': os.listdir(pathlib.Path.home() / '.ssh'),\n"
                "    'secrets': (pathlib.Path.home() / '.jarvis-tools' / 'secrets.json').exists(),\n"
                "}))\n"
            )
            hermes_code = (
                "import json, pathlib, subprocess, time\n"
                "pathlib.Path('frontend.js').write_text('export const v = 2;\\n', encoding='utf-8')\n"
                "saw = False\n"
                "for _ in range(20):\n"
                "    c = subprocess.run(['jarvis-team', 'chat', '--mine'], capture_output=True, text=True)\n"
                "    if 'Czesc hermes z worktree' in c.stdout:\n"
                "        saw = True\n"
                "        break\n"
                "    time.sleep(0.05)\n"
                "print(json.dumps({'saw_chat': saw}))\n"
            )

            env_c = agent_cli._env('claude', extra_env={
                'JARVIS_TEAM_DIR': str(pdir),
                'JARVIS_TEAM_ID': 'collab-wt',
                'JARVIS_TEAM_AGENT': 'claude',
                'JARVIS_TEAM_ROLE': 'backend',
                'JARVIS_TEAM_BIN': str(pdir / 'bin'),
            })
            env_h = agent_cli._env('hermes', extra_env={
                'JARVIS_TEAM_DIR': str(pdir),
                'JARVIS_TEAM_ID': 'collab-wt',
                'JARVIS_TEAM_AGENT': 'hermes',
                'JARVIS_TEAM_ROLE': 'frontend',
                'JARVIS_TEAM_BIN': str(pdir / 'bin'),
            })
            argv_c = agent_cli.sandbox_argv(
                'claude', [sys.executable, '-c', claude_code],
                cwd=wt_c,
                extra_rw_paths=[wt_c, pdir / 'chat', pdir / 'locks', pdir / 'requests'],
                extra_ro_paths=[pdir / 'repo', pdir / 'bin', pdir / 'BOARD.md'],
            )
            argv_h = agent_cli.sandbox_argv(
                'hermes', [sys.executable, '-c', hermes_code],
                cwd=wt_h,
                extra_rw_paths=[wt_h, pdir / 'chat', pdir / 'locks', pdir / 'requests'],
                extra_ro_paths=[pdir / 'repo', pdir / 'bin', pdir / 'BOARD.md'],
            )

            p_c = subprocess.Popen(argv_c, env=env_c, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            p_h = subprocess.Popen(argv_h, env=env_h, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            out_c, err_c = p_c.communicate(timeout=15)
            out_h, err_h = p_h.communicate(timeout=15)

            if p_c.returncode != 0 and ('Operation not permitted' in err_c or 'setting up uid map' in err_c):
                self.skipTest(f'bwrap userns unavailable: {err_c.strip()}')

            self.assertEqual(p_c.returncode, 0, err_c)
            self.assertEqual(p_h.returncode, 0, err_h)

            res_c = json.loads(out_c.strip().splitlines()[-1])
            res_h = json.loads(out_h.strip().splitlines()[-1])

            self.assertEqual(res_c['say_rc'], 0)
            self.assertTrue(res_c['repo_ro'], 'Canonical repo/ must be read-only inside worktree sandbox')
            self.assertFalse(res_c['sibling_wt_exists'], 'Sibling agent worktree must be hidden inside bwrap')
            self.assertEqual(res_c['ssh'], [])
            self.assertFalse(res_c['secrets'])
            self.assertTrue(res_h['saw_chat'])

            m_c = agent_team.merge_agent_worktree('collab-wt', 'claude', 1)
            m_h = agent_team.merge_agent_worktree('collab-wt', 'hermes', 1)
            self.assertTrue(m_c['merged'])
            self.assertTrue(m_h['merged'])
            self.assertTrue((pdir / 'repo' / 'backend.py').is_file())
            self.assertTrue((pdir / 'repo' / 'frontend.js').is_file())


class ReconciledWaveTests(unittest.TestCase):
    """A Jarvis restart leaves a wave looking alive forever: finish it instead."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        base = Path(self.tmp.name) / '.jarvis-tools'
        self.agents_root = base / 'agents'
        self.agents_root.mkdir(parents=True, exist_ok=True)
        self.p_root = patch.object(agent_cli, 'ROOT', self.agents_root)
        self.p_root.start()
        self.addCleanup(self.p_root.stop)
        agent_team.create_project(goal='Odzyskaj falę', participants=['hermes', 'opencode'],
                                  project_id='recover-room', auto_wake_mentions=False)
        self.pdir = agent_team.project_root('recover-room')

    def _fake_active(self, agents=('hermes', 'opencode')):
        with agent_team._file_lock(self.pdir / '.meta.lock'):
            meta = agent_team._load_meta(self.pdir)
            meta['status'] = 'running'
            meta['phase'] = 'build'
            meta['current_round'] = 1
            meta['active_runs'] = {a: {'run_id': 'r', 'round': 1} for a in agents}
            agent_team._save_meta(self.pdir, meta)

    def test_active_waves_reports_rooms_with_members_in_flight(self):
        self._fake_active(['hermes'])
        waves = agent_team.active_waves()
        self.assertEqual([w['id'] for w in waves], ['recover-room'])
        self.assertEqual(waves[0]['agents'], ['hermes'])

    def test_a_live_member_is_left_alone(self):
        self._fake_active(['hermes'])
        with patch.object(agent_cli, 'live_progress', lambda aid: {'running': True}):
            result = agent_team.reconcile_stale_runs('recover-room')
        self.assertEqual(result['reconciled'], [])
        self.assertEqual(list(agent_team._load_meta(self.pdir)['active_runs']), ['hermes'])

    def test_a_room_that_was_just_written_to_is_not_reconciled_yet(self):
        self._fake_active(['hermes'])
        with patch.object(agent_cli, 'live_progress', lambda aid: {'running': False}):
            result = agent_team.reconcile_stale_runs('recover-room', require_quiet=True)
        self.assertTrue(result.get('deferred'))
        self.assertEqual(list(agent_team._load_meta(self.pdir)['active_runs']), ['hermes'])

    def test_dead_members_are_cleared_and_their_work_is_merged(self):
        self._fake_active(['hermes', 'opencode'])
        merged = []

        def _merge(pid, aid, rnd):
            merged.append(aid)
            return {'merged': True, 'changed_files': [f'{aid}.py'], 'conflicts': []}

        with patch.object(agent_cli, 'live_progress', lambda aid: {'running': False}), \
             patch.object(agent_team, 'merge_agent_worktree', _merge), \
             patch.object(agent_team, '_evaluate_gate_and_advance', lambda pid, rnd: None):
            result = agent_team.reconcile_stale_runs('recover-room', require_quiet=False)

        meta = agent_team._load_meta(self.pdir)
        self.assertEqual(sorted(result['reconciled']), ['hermes', 'opencode'])
        self.assertEqual(sorted(merged), ['hermes', 'opencode'])
        self.assertEqual(meta['active_runs'], {})
        self.assertTrue(meta.get('recovered_wave'))
        self.assertNotEqual(meta['status'], 'running')
        self.assertTrue(result.get('gate_started'))


if __name__ == '__main__':
    unittest.main()
