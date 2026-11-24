"""Agent runner boundaries: read-only sandbox, explicit approval, no secret leak.

Nothing here launches a real agent: ``_spawn`` is patched so the tests exercise
argv construction, the lock, the log and the stop path without spending money.
"""
import json
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import agent_cli


class FakeProcess:
    def __init__(self, returncode=0, pid=4242):
        self.pid = pid
        self.returncode = returncode
        self.waited = []
        self.killed = False

    def wait(self, timeout=None):
        self.waited.append(timeout)
        return self.returncode

    def terminate(self):
        self.killed = True


class AgentSandboxTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / 'agents'
        env = patch.object(agent_cli, 'ROOT', self.root)
        env.start()
        self.addCleanup(env.stop)

    def test_every_installed_agent_is_described_with_real_flags(self):
        self.assertEqual(agent_cli.agent_ids(), ['antigravity', 'claude', 'hermes', 'opencode'])
        claude = agent_cli.AGENTS['claude']
        self.assertEqual(claude['prompt_args'], ['-p'])
        self.assertIn('--effort', claude['settings']['effort']['flag'])
        self.assertIsNone(agent_cli.AGENTS['opencode']['settings']['effort'],
                          'opencode has no thinking-level flag and must not pretend to')

    def test_argv_only_carries_flags_the_cli_accepts(self):
        agent_cli.save_config('claude', {'model': 'claude-sonnet-4-6', 'effort': 'high'})
        argv = agent_cli.build_argv('claude', 'zadanie')
        # The binary is resolved to an absolute path: the service PATH omits
        # ~/.local/bin, so a bare name would not be found inside the sandbox.
        self.assertTrue(argv[0].endswith('claude'), argv[0])
        self.assertEqual(argv[1:3], ['-p', 'zadanie'])
        self.assertIn('--model', argv)
        self.assertIn('claude-sonnet-4-6', argv)
        self.assertIn('--effort', argv)
        self.assertIn('high', argv)
        self.assertNotIn('--reasoning', argv)

        agent_cli.save_config('hermes', {'model': 'deepseek-chat', 'reasoning': 'high'})
        hermes = agent_cli.build_argv('hermes', 'zadanie')
        self.assertTrue(hermes[0].endswith('hermes'), hermes[0])
        self.assertEqual(hermes[1:3], ['-z', 'zadanie'])
        self.assertIn('--reasoning', hermes)
        self.assertNotIn('--effort', hermes)

    def test_a_setting_the_agent_cannot_apply_is_refused(self):
        with self.assertRaises(agent_cli.AgentError) as caught:
            agent_cli.save_config('opencode', {'effort': 'high'})
        self.assertIn('does not support', str(caught.exception))
        with self.assertRaises(agent_cli.AgentError):
            agent_cli.save_config('claude', {'effort': 'impossible'})

    def test_a_suspicious_model_gets_a_warning_not_a_rejection(self):
        # A truncated id ("dee") used to persist silently and turn every run into a
        # model_rejected failure minutes later.
        config = agent_cli.save_config('claude', {'model': 'dee'})
        warnings = agent_cli.setting_warnings('claude', config)
        self.assertTrue(any('dee' in note for note in warnings), warnings)
        self.assertEqual(config['model'], 'dee', 'a warning must not silently rewrite the value')

        config = agent_cli.save_config('claude', {'model': 'deepseek-flash'})
        self.assertEqual(agent_cli.setting_warnings('claude', config), [])

    def test_the_settings_file_is_private_and_holds_no_credentials(self):
        agent_cli.save_config('claude', {'model': 'x'})
        path = agent_cli.agent_root('claude') / 'config.json'
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertNotIn('api_key', path.read_text())

    def test_the_sandbox_makes_the_whole_filesystem_read_only_except_the_agent(self):
        argv = agent_cli.sandbox_argv('claude', ['claude', '-p', 'x'])
        rendered = ' '.join(argv)
        self.assertEqual(argv[0], 'bwrap')
        self.assertIn('--ro-bind / /', rendered)
        self.assertIn(str(agent_cli.agent_root('claude')), rendered)
        self.assertIn('--', argv)
        self.assertNotIn('--unshare-net', argv, 'agents need the network for their own API')

    def test_run_without_approval_starts_nothing(self):
        with patch.object(agent_cli, '_spawn') as spawn:
            with self.assertRaises(agent_cli.AgentError) as caught:
                agent_cli.run('claude', 'zadanie')
        self.assertIn('approval', str(caught.exception))
        spawn.assert_not_called()

    def test_an_unknown_agent_is_refused(self):
        with self.assertRaises(agent_cli.AgentError):
            agent_cli.run('nonexistent', 'zadanie', approved=True)

    def test_a_run_writes_a_log_and_reports_a_status(self):
        process = FakeProcess(returncode=0)
        with patch.object(agent_cli, '_spawn', return_value=(process, _Closer())) as spawn, \
             patch.object(agent_cli, 'binary_present', return_value=True):
            result = agent_cli.run('claude', 'napisz OK', approved=True, timeout=60)
        self.assertTrue(result['ok'])
        self.assertEqual(result['status'], 'done')
        self.assertEqual(result['exit_code'], 0)
        argv = spawn.call_args.args[0]
        self.assertEqual(argv[0], 'bwrap')

    def test_a_failing_agent_is_reported_as_failed_not_done(self):
        process = FakeProcess(returncode=2)
        with patch.object(agent_cli, '_spawn', return_value=(process, _Closer())), \
             patch.object(agent_cli, 'binary_present', return_value=True):
            result = agent_cli.run('opencode', 'zadanie', approved=True, timeout=60)
        self.assertFalse(result['ok'])
        self.assertEqual(result['status'], 'failed')

    def test_the_task_carries_the_read_only_rules(self):
        captured = {}

        def fake_spawn(argv, cwd, env, log_path):
            captured['argv'] = argv
            return FakeProcess(), _Closer()

        with patch.object(agent_cli, '_spawn', side_effect=fake_spawn), \
             patch.object(agent_cli, 'binary_present', return_value=True):
            agent_cli.run('claude', 'zadanie', approved=True, timeout=60)
        prompt = next(arg for arg in captured['argv'] if 'ZASADY PRACY' in arg)
        self.assertIn('tylko do odczytu', prompt)
        self.assertIn(str(agent_cli.outbox_path('claude')), prompt)

    def test_second_run_for_the_same_agent_is_refused_while_one_is_active(self):
        holder = {}

        def fake_wait(timeout=None):
            holder['lock_held'] = True
            return 0

        process = FakeProcess()
        process.wait = fake_wait
        with patch.object(agent_cli, '_spawn', return_value=(process, _Closer())), \
             patch.object(agent_cli, 'binary_present', return_value=True):
            agent_cli.run('claude', 'pierwsze', approved=True, timeout=60)
        # The lock is released after the run, so a second run is allowed again.
        with patch.object(agent_cli, '_spawn', return_value=(FakeProcess(), _Closer())), \
             patch.object(agent_cli, 'binary_present', return_value=True):
            agent_cli.run('claude', 'drugie', approved=True, timeout=60)
        self.assertEqual(len(agent_cli.runs('claude')), 2)

    def test_stop_with_no_active_run_is_an_empty_state(self):
        self.assertTrue(agent_cli.stop('claude')['ok'])
        self.assertFalse(agent_cli.stop('claude')['stopped'])

    def test_outbox_lists_files_without_touching_anything(self):
        directory = agent_cli.outbox_path('claude')
        directory.mkdir(parents=True, exist_ok=True)
        (directory / 'patch.py').write_text('print(1)')
        (directory / 'outbox.md').write_text('co zrobiłem')
        rows = agent_cli.outbox('claude')
        self.assertEqual({row['path'] for row in rows}, {'patch.py', 'outbox.md'})
        self.assertTrue(all(row['bytes'] >= 0 for row in rows))

    def test_summary_is_honest_about_the_sandbox(self):
        data = agent_cli.summary()
        self.assertEqual(len(data['agents']), 4)
        self.assertIn('read-only', data['sandbox'])

    def test_a_dynamic_model_list_accepts_a_model_outside_the_static_one(self):
        # antigravity and opencode enumerate their own models, so their setting has
        # no static choices; saving a real id from that list must not raise KeyError.
        config = agent_cli.save_config('antigravity', {'model': 'gemini-3.8-flash-high'})
        self.assertEqual(config['model'], 'gemini-3.8-flash-high')
        self.assertEqual(agent_cli.load_config('antigravity')['model'], 'gemini-3.8-flash-high')

    def test_a_static_choice_still_refuses_an_unknown_value(self):
        with self.assertRaises(agent_cli.AgentError):
            agent_cli.save_config('antigravity', {'effort': 'high'})

    def test_the_registry_covers_antigravity_with_its_real_flags(self):
        antigravity = agent_cli.AGENTS['antigravity']
        self.assertEqual(antigravity['binary'], 'agy')
        self.assertEqual(antigravity['prompt_args'], ['-p'])
        # agy conflicts --model with --effort, so effort is not offered at all.
        self.assertIsNone(antigravity['settings']['effort'])
        self.assertIn('--model', antigravity['settings']['model']['flag'])

    def test_hermes_provider_dropdown_and_custom_values(self):
        providers = agent_cli.list_providers('hermes', refresh=True)
        self.assertIsInstance(providers, list)
        self.assertIn('custom', providers)
        self.assertIn('openrouter', providers)

        stat = agent_cli.status('hermes')
        self.assertEqual(stat['choices']['provider'], providers)
        self.assertTrue(stat['allow_custom']['provider'])
        self.assertIn('provider', stat['hints'])

        # Saving a standard provider choice
        config = agent_cli.save_config('hermes', {'provider': 'openrouter'})
        self.assertEqual(config['provider'], 'openrouter')
        argv = agent_cli.build_argv('hermes', 'zadanie')
        self.assertIn('--provider', argv)
        self.assertIn('openrouter', argv)

        # Saving a custom provider choice (allowed via allow_custom: True)
        config = agent_cli.save_config('hermes', {'provider': 'my-custom-llm'})
        self.assertEqual(config['provider'], 'my-custom-llm')
        argv = agent_cli.build_argv('hermes', 'zadanie')
        self.assertIn('--provider', argv)
        self.assertIn('my-custom-llm', argv)

        # Clearing provider
        config = agent_cli.save_config('hermes', {'provider': ''})
        self.assertEqual(config['provider'], '')
        argv = agent_cli.build_argv('hermes', 'zadanie')
        self.assertNotIn('--provider', argv)

    def test_hermes_models_depend_on_provider(self):
        by_prov = agent_cli.list_models_by_provider('hermes', refresh=True)
        self.assertIsInstance(by_prov, dict)
        self.assertIn('deepseek', by_prov)
        self.assertIn('openrouter', by_prov)
        self.assertIn('deepseek-v4.1-flash-uncensored', by_prov['deepseek'])

        deepseek_models = agent_cli.list_models('hermes', provider='deepseek')
        self.assertIn('deepseek-v4.1-flash-uncensored', deepseek_models)

        openrouter_models = agent_cli.list_models('hermes', provider='openrouter')
        self.assertIsInstance(openrouter_models, list)
        self.assertTrue(len(openrouter_models) > 0)

        # Hermes status reports models_by_provider mapping
        stat = agent_cli.status('hermes')
        self.assertIn('models_by_provider', stat)
        self.assertEqual(stat['models_by_provider'], by_prov)

        # Status choices.model reflects configured provider
        agent_cli.save_config('hermes', {'provider': 'deepseek', 'model': 'deepseek-v4.1-flash-1017'})
        stat_deepseek = agent_cli.status('hermes')
        self.assertEqual(stat_deepseek['choices']['model'], deepseek_models)

    def test_start_async_holds_lock_against_concurrent_run_and_async(self):
        import threading
        import time
        gate = threading.Event()

        class BlockingProcess(FakeProcess):
            def wait(self, timeout=None):
                gate.wait(timeout=5)
                return 0

        try:
            with patch.object(agent_cli, '_spawn', return_value=(BlockingProcess(), _Closer())), \
                 patch.object(agent_cli, 'binary_present', return_value=True):
                started = agent_cli.start_async('claude', 'zadanie w tle', approved=True, timeout=60)
                self.assertTrue(started['ok'])
                self.assertTrue(started['progress']['running'])
                with self.assertRaises(agent_cli.AgentError):
                    agent_cli.run('claude', 'kolidujące synchroniczne', approved=True, timeout=60)
                with self.assertRaises(agent_cli.AgentError):
                    agent_cli.start_async('claude', 'kolidujące w tle', approved=True, timeout=60)
        finally:
            gate.set()

        for _ in range(50):
            if not agent_cli.status('claude')['running']:
                break
            time.sleep(0.02)
        self.assertFalse(agent_cli.status('claude')['running'])

    def test_new_run_archives_previous_outbox_and_resets_live_progress(self):
        import threading
        import time
        out_dir = agent_cli.outbox_path('hermes')
        out_dir.mkdir(parents=True, exist_ok=True)

        def first_spawn(argv, cwd, env, log_path):
            (out_dir / 'index.html').write_text('<h1>v1</h1>', encoding='utf-8')
            (out_dir / 'outbox.md').write_text('raport v1', encoding='utf-8')
            return FakeProcess(returncode=0), _Closer()

        with patch.object(agent_cli, '_spawn', side_effect=first_spawn), \
             patch.object(agent_cli, 'binary_present', return_value=True):
            first = agent_cli.run('hermes', 'pierwsza strona', approved=True, timeout=60)
        self.assertEqual({f['path'] for f in first['outbox']}, {'index.html', 'outbox.md'})

        gate = threading.Event()

        class BlockingProcess(FakeProcess):
            def wait(self, timeout=None):
                gate.wait(timeout=5)
                return 0

        try:
            with patch.object(agent_cli, '_spawn', return_value=(BlockingProcess(), _Closer())), \
                 patch.object(agent_cli, 'binary_present', return_value=True):
                second = agent_cli.start_async('hermes', 'druga strona', approved=True, timeout=60)
                prog = second['progress']
                self.assertEqual(prog['outbox_count'], 0)
                phases_by_idx = {p['index']: p['done'] for p in prog['phases']}
                self.assertTrue(phases_by_idx[1])
                self.assertFalse(phases_by_idx[3], 'stale outbox files must not mark code phase done')
                self.assertFalse(phases_by_idx[4], 'stale outbox.md must not mark report phase done')
                archived = agent_cli.agent_root('hermes') / 'runs' / 'outbox-archive' / first['id']
                self.assertTrue((archived / 'index.html').is_file())
                self.assertTrue((archived / 'outbox.md').is_file())
        finally:
            gate.set()

        for _ in range(50):
            if not agent_cli.status('hermes')['running']:
                break
            time.sleep(0.02)

    def test_stale_current_json_from_dead_pid_is_reaped_by_status(self):
        root = agent_cli.agent_root('opencode')
        root.mkdir(parents=True, exist_ok=True)
        stale_id = '20261113-120000-dead01'
        (root / 'runs.json').write_text(json.dumps([{
            'id': stale_id, 'agent': 'opencode', 'task': 'przerwane zadanie',
            'status': 'running', 'started_at': 1000.0, 'pid': 99999999,
            'consent': 'operator', 'log': str(root / 'runs' / f'{stale_id}.log'),
            'exit_code': None, 'seconds': None,
        }]), encoding='utf-8')
        (root / 'current.json').write_text(json.dumps({
            'pid': 99999999, 'run_id': stale_id, 'started_at': 1000.0, 'task': 'przerwane zadanie',
        }), encoding='utf-8')

        stat = agent_cli.status('opencode')
        self.assertFalse(stat['running'])
        self.assertFalse(stat['progress']['running'])
        self.assertFalse((root / 'current.json').exists())
        self.assertEqual(stat['last_run']['status'], 'failed')

    def test_sandbox_masks_sensitive_home_and_sibling_agent_state(self):
        fake_home = Path(self.tmp.name) / 'home'
        (fake_home / '.ssh').mkdir(parents=True)
        (fake_home / '.ssh' / 'id_ed25519').write_text('PRIVATE', encoding='utf-8')
        (fake_home / '.netrc').write_text('machine github.com password tok', encoding='utf-8')
        (fake_home / '.hermes' / 'tools').mkdir(parents=True)
        (fake_home / '.hermes' / 'sessions').mkdir(parents=True)
        (fake_home / '.hermes' / '.env').write_text('DEEPSEEK_API_KEY=sec', encoding='utf-8')
        (fake_home / '.claude').mkdir(parents=True)
        (fake_home / '.claude' / 'settings.json').write_text('{"hooks":{}}', encoding='utf-8')

        agent_cli._ensure_dirs('claude')
        empty_mask = agent_cli.ROOT / '.empty'
        with patch.dict('os.environ', {'HOME': str(fake_home)}):
            argv = agent_cli.sandbox_argv('claude', ['claude', '-p', 'x'])
            offline_argv = agent_cli.sandbox_argv('claude', ['claude', '-p', 'x'], network=False)
            hermes_argv = agent_cli.sandbox_argv('hermes', ['hermes', '-z', 'x'])

        rendered = ' '.join(argv)
        self.assertIn('--unshare-ipc', argv)
        self.assertNotIn('--unshare-net', argv)
        self.assertIn('--unshare-net', offline_argv)
        self.assertIn(f'--tmpfs {fake_home / ".ssh"} --remount-ro {fake_home / ".ssh"}', rendered)
        self.assertIn(f'--ro-bind {empty_mask} {fake_home / ".netrc"}', rendered)
        self.assertIn(f'--ro-bind {empty_mask} {fake_home / ".hermes" / ".env"}', rendered)
        self.assertIn(f'--tmpfs {fake_home / ".hermes" / "sessions"} --remount-ro {fake_home / ".hermes" / "sessions"}', rendered)
        self.assertNotIn(f'--tmpfs {fake_home / ".hermes" / "tools"}', rendered)
        self.assertIn(f'--bind {fake_home / ".claude"} {fake_home / ".claude"}', rendered)
        self.assertIn(f'--ro-bind {fake_home / ".claude" / "settings.json"} {fake_home / ".claude" / "settings.json"}', rendered)

        hermes_rendered = ' '.join(hermes_argv)
        self.assertIn(f'--bind {fake_home / ".hermes"} {fake_home / ".hermes"}', hermes_rendered)
        self.assertIn(f'--ro-bind {fake_home / ".hermes" / ".env"} {fake_home / ".hermes" / ".env"}', hermes_rendered)
        self.assertIn(f'--ro-bind {fake_home / ".hermes" / "tools"} {fake_home / ".hermes" / "tools"}', hermes_rendered)
        self.assertIn(f'--tmpfs {fake_home / ".claude"} --remount-ro {fake_home / ".claude"}', hermes_rendered)

    def test_sandbox_kernel_enforces_secret_masking_and_protected_configs(self):
        import shutil
        import subprocess
        import sys
        if not shutil.which('bwrap'):
            self.skipTest('bwrap not installed')

        var_tmp = tempfile.TemporaryDirectory(dir='/var/tmp' if Path('/var/tmp').is_dir() else None)
        self.addCleanup(var_tmp.cleanup)
        fake_home = Path(var_tmp.name) / 'live_home'
        (fake_home / '.ssh').mkdir(parents=True)
        (fake_home / '.ssh' / 'id_ed25519').write_text('SECRET_SSH_KEY', encoding='utf-8')
        (fake_home / '.netrc').write_text('SECRET_NETRC', encoding='utf-8')
        (fake_home / '.hermes' / 'tools').mkdir(parents=True)
        (fake_home / '.hermes' / 'tools' / 'runtime.txt').write_text('SHARED_RUNTIME', encoding='utf-8')
        (fake_home / '.hermes' / 'sessions').mkdir(parents=True)
        (fake_home / '.hermes' / 'sessions' / 's1.json').write_text('SECRET_SESSION', encoding='utf-8')
        (fake_home / '.hermes' / '.env').write_text('SECRET_HERMES_ENV', encoding='utf-8')
        (fake_home / '.claude').mkdir(parents=True)
        (fake_home / '.claude' / 'settings.json').write_text('{"safe":true}', encoding='utf-8')

        jarvis_tools = fake_home / '.jarvis-tools'
        live_root = jarvis_tools / 'agents'
        jarvis_tools.mkdir(parents=True)
        (jarvis_tools / 'secrets.json').write_text('{"items":["top-secret"]}', encoding='utf-8')

        with patch.object(agent_cli, 'ROOT', live_root), \
             patch.dict('os.environ', {'HOME': str(fake_home)}):
            agent_cli._ensure_dirs('claude')
            agent_cli._ensure_dirs('hermes')
            probe_code = (
                "import errno, json, os, pathlib\n"
                f"home = pathlib.Path({str(fake_home)!r})\n"
                f"out = pathlib.Path({str(agent_cli.outbox_path('claude'))!r})\n"
                f"aroot = pathlib.Path({str(agent_cli.agent_root('claude'))!r})\n"
                "res = {}\n"
                "res['ssh_list'] = os.listdir(home / '.ssh')\n"
                "res['hermes_sessions'] = os.listdir(home / '.hermes' / 'sessions')\n"
                "res['hermes_env'] = (home / '.hermes' / '.env').read_text()\n"
                "res['hermes_tools'] = (home / '.hermes' / 'tools' / 'runtime.txt').read_text()\n"
                "res['netrc'] = (home / '.netrc').read_text()\n"
                "res['secrets_exists'] = (home / '.jarvis-tools' / 'secrets.json').exists()\n"
                "res['sibling_exists'] = (home / '.jarvis-tools' / 'agents' / 'hermes').exists()\n"
                "res['settings_read'] = (home / '.claude' / 'settings.json').read_text()\n"
                "def try_write(p):\n"
                "    try:\n"
                "        pathlib.Path(p).write_text('x')\n"
                "        return 'ok'\n"
                "    except OSError as e:\n"
                "        return errno.errorcode.get(e.errno, str(e.errno))\n"
                "res['write_ssh'] = try_write(home / '.ssh' / 'pwn')\n"
                "res['write_netrc'] = try_write(home / '.netrc')\n"
                "res['write_settings'] = try_write(home / '.claude' / 'settings.json')\n"
                "res['write_session'] = try_write(home / '.claude' / 'session.jsonl')\n"
                "res['write_aroot'] = try_write(aroot / 'escape.txt')\n"
                "res['write_outbox'] = try_write(out / 'ok.txt')\n"
                "print(json.dumps(res))\n"
            )
            argv = agent_cli.sandbox_argv('claude', [sys.executable, '-c', probe_code])
            proc = subprocess.run(argv, capture_output=True, text=True, timeout=15, check=False)

        if proc.returncode != 0 and ('Operation not permitted' in proc.stderr or 'setting up uid map' in proc.stderr):
            self.skipTest(f'bwrap userns unavailable in test environment: {proc.stderr.strip()}')
        self.assertEqual(proc.returncode, 0, proc.stderr)
        data = json.loads(proc.stdout.strip())
        self.assertEqual(data['ssh_list'], [])
        self.assertEqual(data['hermes_sessions'], [])
        self.assertEqual(data['hermes_env'], '')
        self.assertEqual(data['hermes_tools'], 'SHARED_RUNTIME')
        self.assertEqual(data['netrc'], '')
        self.assertFalse(data['secrets_exists'])
        self.assertFalse(data['sibling_exists'])
        self.assertEqual(data['settings_read'], '{"safe":true}')
        self.assertEqual(data['write_ssh'], 'EROFS')
        self.assertEqual(data['write_netrc'], 'EROFS')
        self.assertEqual(data['write_settings'], 'EROFS')
        self.assertEqual(data['write_aroot'], 'EROFS')
        self.assertEqual(data['write_session'], 'ok')
        self.assertEqual(data['write_outbox'], 'ok')

    def test_hermes_river_provider_rejects_or_clears_reasoning_and_omits_flag(self):
        cfg = agent_cli.save_config('hermes', {'provider': 'deepseek', 'reasoning': 'high'})
        self.assertEqual(cfg['reasoning'], 'high')
        argv_ds = agent_cli.build_argv('hermes', 'hello', config=cfg)
        self.assertIn('--reasoning', argv_ds)

        switched = agent_cli.save_config('hermes', {'provider': 'river'})
        self.assertEqual(switched['provider'], 'river')
        self.assertEqual(switched['reasoning'], '')
        self.assertNotIn('--reasoning', agent_cli.build_argv('hermes', 'hello', config=switched))

        with self.assertRaises(agent_cli.AgentError):
            agent_cli.save_config('hermes', {'provider': 'river', 'reasoning': 'medium'})
        with self.assertRaises(agent_cli.AgentError):
            agent_cli.save_config('hermes', {'reasoning': 'low'})

        stale_cfg = dict(switched, provider='river-glm', reasoning='high')
        self.assertNotIn('--reasoning', agent_cli.build_argv('hermes', 'hello', config=stale_cfg))

    def test_classify_log_error_and_unified_run_finalization(self):
        self.assertEqual(agent_cli.classify_log_error('Error: HTTP 429 rate limit exceeded')[0], 'quota_exceeded')
        self.assertEqual(agent_cli.classify_log_error('401 Unauthorized: invalid_api_key')[0], 'auth_failed')
        self.assertEqual(agent_cli.classify_log_error('reasoning_effort is not supported by model')[0], 'model_rejected')
        self.assertEqual(agent_cli.classify_log_error('OSError: [Errno 30] Read-only file system')[0], 'sandbox_readonly')

        notified = []
        fake_reminders = type(
            'R', (), {'notify_job_finished': staticmethod(lambda **kw: notified.append(kw))}
        )()

        def fake_spawn_quota(argv, cwd, env, log_path):
            Path(log_path).write_text('API Error: 429 Resource_Exhausted quota exceeded\n', encoding='utf-8')
            proc = type('P', (), {'pid': 42424, 'returncode': 1, 'wait': lambda self, timeout=None: 1})()
            return proc, _Closer()

        with patch.object(agent_cli, 'binary_present', return_value=True), \
             patch.object(agent_cli, 'sandbox_argv', side_effect=lambda a, inner, **kw: inner), \
             patch.object(agent_cli, '_spawn', side_effect=fake_spawn_quota), \
             patch.dict('sys.modules', {'operator_modules': type('OM', (), {'reminders': fake_reminders})(),
                                        'operator_modules.reminders': fake_reminders}):
            res = agent_cli.run('claude', 'build widget', approved=True, consent='once')

        self.assertFalse(res['ok'])
        self.assertEqual(res['status'], 'failed')
        self.assertEqual(res['error_kind'], 'quota_exceeded')
        self.assertIn('429', res['error_hint'])
        self.assertEqual(agent_cli.runs('claude')[-1]['error_kind'], 'quota_exceeded')
        prog = agent_cli.live_progress('claude')
        self.assertEqual(prog['error_kind'], 'quota_exceeded')
        self.assertEqual(len(notified), 1)
        self.assertEqual(notified[0]['status'], 'failed')

        def fake_spawn_ok_with_warning(argv, cwd, env, log_path):
            Path(log_path).write_text('Warning: unrecognized_model deepseek-flash[1m]\nPONG\n', encoding='utf-8')
            proc = type('P', (), {'pid': 42425, 'returncode': 0, 'wait': lambda self, timeout=None: 0})()
            return proc, _Closer()

        with patch.object(agent_cli, 'binary_present', return_value=True), \
             patch.object(agent_cli, 'sandbox_argv', side_effect=lambda a, inner, **kw: inner), \
             patch.object(agent_cli, '_spawn', side_effect=fake_spawn_ok_with_warning):
            ok_res = agent_cli.run('claude', 'ping test', approved=True, consent='once')

        self.assertTrue(ok_res['ok'])
        self.assertEqual(ok_res['status'], 'done')
        self.assertEqual(ok_res['error_kind'], '')
        self.assertEqual(agent_cli.live_progress('claude')['error_kind'], '')

    def test_a_signal_killed_sandbox_is_reported_and_reaped(self):
        """exit -9 used to end as a silent 'failed' with an empty hint and a leaked CLI."""
        reaped = []

        def fake_spawn_sigkill(argv, cwd, env, log_path):
            proc = type('P', (), {'pid': 42426, 'returncode': -9,
                                  'wait': lambda self, timeout=None: -9})()
            return proc, _Closer()

        with patch.object(agent_cli, 'binary_present', return_value=True), \
             patch.object(agent_cli, 'sandbox_argv', side_effect=lambda a, inner, **kw: inner), \
             patch.object(agent_cli, '_spawn', side_effect=fake_spawn_sigkill), \
             patch.object(agent_cli, '_reap_orphaned_session',
                          side_effect=lambda sid, started=None: reaped.append(sid) or [sid]):
            res = agent_cli.run('claude', 'build widget', approved=True, consent='once')

        self.assertEqual(res['status'], 'failed')
        self.assertEqual(res['error_kind'], 'killed')
        self.assertIn('9', res['error_hint'])
        self.assertEqual(res['exit_code'], -9)
        self.assertEqual(reaped, [42426], 'the leftover session must be reaped, not leaked')

    def test_spawn_runs_on_the_long_lived_spawner_thread(self):
        """bwrap --die-with-parent kills the wrapper when the *forking* thread exits."""
        seen = []

        class Proc:
            pid = 42427
            returncode = 0

        def fake_popen(*args, **kwargs):
            seen.append(threading.current_thread().name)
            return Proc()

        log_path = self.root / 'claude' / 'runs' / 'spawn-probe.log'
        log_path.parent.mkdir(parents=True, exist_ok=True)
        with patch.object(agent_cli.subprocess, 'Popen', side_effect=fake_popen):
            _proc, log = agent_cli._spawn(['/bin/true'], Path('/tmp'), {}, log_path)
        log.close()
        self.assertEqual(seen, ['jarvis-agent-spawner'])
        self.assertIn('jarvis-agent-spawner', {t.name for t in threading.enumerate()})


class _Closer:
    def close(self):
        pass


class AgentSecretsTests(unittest.TestCase):
    def test_credentials_are_injected_by_name_and_never_returned(self):
        fake_store = type('S', (), {'get': staticmethod(
            lambda name: {'value': 'sk-secret-value'} if name == 'anthropic-api-key' else {})})()
        with patch.dict('sys.modules', {'operator_tools': type('M', (), {'SecretStore': lambda: fake_store,
                                                                        'ToolError': Exception})}):
            env = agent_cli._env('claude')
        self.assertEqual(env.get('ANTHROPIC_API_KEY'), 'sk-secret-value')
        self.assertNotIn('sk-secret-value', json.dumps(agent_cli.load_config('claude')))


class SpawnAbandonmentTest(unittest.TestCase):
    """A caller that gives up on the spawner must not leave a live sandbox."""

    def test_a_timing_out_spawn_runs_the_abandoned_cleanup(self):
        gate = threading.Event()
        seen = {}

        def slow_launch():
            gate.wait(10)          # the caller times out while this blocks
            return ('PROCESS', 'LOG')

        def on_abandoned(value):
            seen['cleanup'] = value

        with patch.object(agent_cli, '_spawn_thread', lambda: None):
            with self.assertRaises(agent_cli.AgentError):
                agent_cli._call_in_spawn_thread(slow_launch, timeout=0.15,
                                                on_abandoned=on_abandoned)
            gate.set()
            deadline = time.time() + 10
            while 'cleanup' not in seen and time.time() < deadline:
                time.sleep(0.01)
        self.assertEqual(seen['cleanup'], ('PROCESS', 'LOG'))

    def test_a_fast_spawn_returns_its_value_without_cleanup(self):
        seen = {}
        with patch.object(agent_cli, '_spawn_thread', lambda: None):
            out = agent_cli._call_in_spawn_thread(lambda: ('P', 'L'), timeout=5,
                                                 on_abandoned=lambda value: seen.__setitem__('bad', value))
        self.assertEqual(out, ('P', 'L'))
        self.assertNotIn('bad', seen)


if __name__ == '__main__':
    unittest.main()
