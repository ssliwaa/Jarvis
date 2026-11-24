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
import agent_router
import agent_team
import checkpoint_manager
import code_index
import health_watchdog
import telegram_channel
import visual_qa
import voice_bridge


class _DummyLog:
    def close(self):
        pass


class _FakeTelegramTransport:
    def __init__(self):
        self.sent = []
        self.callbacks = []

    def poll(self, offset):
        return []

    def send(self, chat_id, text, reply_markup=None):
        self.sent.append({'chat_id': chat_id, 'text': text, 'reply_markup': reply_markup})

    def answer_callback(self, callback_id, text=''):
        self.callbacks.append((callback_id, text))


class AdvancedFeaturesTests(unittest.TestCase):
    def setUp(self):
        # /tmp on purpose: a TMPDIR inside ~/.hermes is a directory code_index
        # refuses to touch, and these tests index their own temp tree.
        self.tmp = tempfile.TemporaryDirectory(dir='/tmp' if Path('/tmp').is_dir() else None)
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name) / '.jarvis-tools'
        self.agents_root = self.base / 'agents'
        self.agents_root.mkdir(parents=True, exist_ok=True)
        self.p_root = patch.object(agent_cli, 'ROOT', self.agents_root)
        self.p_root.start()
        self.addCleanup(self.p_root.stop)

    def test_adaptive_router_and_429_circuit_breaker(self):
        self.assertEqual(agent_router.infer_role('Popraw widok CSS i przyciski UI'), 'frontend')
        self.assertEqual(agent_router.infer_role('Napraw wyjątek KeyError w daemonie'), 'repair')

        with patch.object(agent_cli, 'binary_present', return_value=True), \
             patch.object(agent_cli, '_check_running', return_value=(False, None)):
            first = agent_router.pick_best_agent(role='architect')
            self.assertEqual(first, 'claude')

            # Simulate HTTP 429 quota failure on claude -> trips 15-min circuit breaker
            agent_router.record_run_outcome('claude', {
                'status': 'failed',
                'error_kind': 'quota_exceeded',
                'error_hint': 'Przekroczony limit zapytań',
            })
            circuits = agent_router.active_circuits()
            self.assertIn('claude', circuits)

            second = agent_router.pick_best_agent(role='architect')
            self.assertNotEqual(second, 'claude')

            roster = agent_router.select_team('Zbuduj API i testy', max_members=2)
            self.assertEqual(len(roster), 2)
            self.assertNotIn('claude', [r['agent'] for r in roster])

            # Clean completion clears quarantine
            agent_router.record_run_outcome('claude', {'status': 'done'})
            self.assertNotIn('claude', agent_router.active_circuits())

    def test_code_index_fts5_incremental_and_secret_exclusion(self):
        proj = Path(self.tmp.name) / 'sample_repo'
        proj.mkdir(parents=True)
        (proj / 'billing_engine.py').write_text(
            'class InvoiceCalculator:\n'
            '    def compute_vat_total(self, net_amount):\n'
            '        return round(net_amount * 1.23, 2)\n',
            encoding='utf-8',
        )
        (proj / '.env').write_text('SUPER_SECRET_TOKEN=xyz987\n', encoding='utf-8')
        (proj / 'secrets.json').write_text('{"api":"hidden_secret_token"}', encoding='utf-8')

        r1 = code_index.index_directory(proj)
        self.assertTrue(r1['ok'])
        self.assertEqual(r1['indexed'], 1)

        # Second pass skips unchanged file via mtime check
        r2 = code_index.index_directory(proj)
        self.assertEqual(r2['indexed'], 0)
        self.assertEqual(r2['skipped'], 1)

        hits = code_index.search_context('compute_vat_total InvoiceCalculator', root_dir=proj)
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]['path'], 'billing_engine.py')
        self.assertIn('InvoiceCalculator', hits[0]['symbols'])

        # Secret files are never indexed
        secret_hits = code_index.search_context('SUPER_SECRET_TOKEN hidden_secret_token', root_dir=proj, auto_index=False)
        self.assertEqual(secret_hits, [])

        pack = code_index.build_context_pack('Popraw funkcję compute_vat_total', root_dir=proj)
        self.assertIn('billing_engine.py', pack)

    def test_visual_qa_catches_missing_404_assets_and_passes_clean_ui(self):
        web = Path(self.tmp.name) / 'web_app'
        web.mkdir(parents=True)
        (web / 'index.html').write_text(
            '<!doctype html><html><head><link rel="stylesheet" href="style.css"></head>'
            '<body><h1>Panel OK</h1><script src="missing_bundle.js"></script></body></html>',
            encoding='utf-8',
        )
        (web / 'style.css').write_text('body { margin: 0; }\n', encoding='utf-8')

        with patch.object(visual_qa, '_find_browser', return_value=''):
            bad = visual_qa.run_visual_qa(web)
            self.assertFalse(bad['ok'])
            self.assertTrue(any('missing_bundle.js' in x for x in bad['missing_assets']))

            (web / 'missing_bundle.js').write_text('console.log("loaded");\n', encoding='utf-8')
            good = visual_qa.run_visual_qa(web)
            self.assertTrue(good['ok'])
            self.assertEqual(good['missing_assets'], [])

    def test_health_watchdog_groups_tracebacks_and_dispatches_sandbox_repair(self):
        proj = Path(self.tmp.name) / 'jarvis_src'
        proj.mkdir(parents=True)
        (proj / 'worker.py').write_text('def sync_items(data):\n    return data["missing"]\n', encoding='utf-8')

        sample_tb = (
            'Nov 13 20:10:01 host python[999]: Traceback (most recent call last):\n'
            'Nov 13 20:10:01 host python[999]:   File "/app/worker.py", line 2, in sync_items\n'
            'Nov 13 20:10:01 host python[999]:     return data["missing"]\n'
            'Nov 13 20:10:01 host python[999]: KeyError: \'missing\'\n'
        )
        repeated_log = '\n'.join([sample_tb, sample_tb, sample_tb])
        captured = {}

        def fake_start_async(agent_id, task, **kwargs):
            captured['agent'] = agent_id
            captured['task'] = task
            return {'id': 'run-wd-1', 'pid': 41000}

        with patch.object(agent_cli, 'binary_present', return_value=True), \
             patch.object(agent_cli, '_check_running', return_value=(False, None)), \
             patch.object(agent_cli, 'start_async', side_effect=fake_start_async):
            res = health_watchdog.scan_logs(
                log_text=repeated_log,
                threshold=3,
                auto_repair=True,
                project_root=proj,
            )

        self.assertEqual(len(res['incidents']), 1)
        self.assertEqual(res['incidents'][0]['count'], 3)
        self.assertEqual(res['incidents'][0]['error_type'], 'KeyError')
        self.assertEqual(len(res['dispatched']), 1)
        self.assertIn('worker.py', captured['task'])

    def test_voice_bridge_unblocks_jarvis_team_ask_owner(self):
        agent_team.create_project(
            goal='Konsultacja głosowa z właścicielem',
            participants=['claude'],
            project_id='voice-proj',
            auto_wake_mentions=False,
        )
        pdir = agent_team.project_root('voice-proj')
        agent_team._ensure_request_watcher('voice-proj')

        def _owner_responder():
            deadline = time.time() + 6.0
            while time.time() < deadline:
                pending = voice_bridge.pending_owner_questions('voice-proj')
                if pending:
                    voice_bridge.answer_owner_question(
                        'Użyj bazy SQLite z trybem WAL',
                        req_id=pending[0]['id'],
                        project_id='voice-proj',
                        source='voice',
                    )
                    return
                time.sleep(0.1)

        threading.Thread(target=_owner_responder, daemon=True).start()
        ask_env = {
            **os.environ,
            'JARVIS_TEAM_DIR': str(pdir),
            'JARVIS_TEAM_ID': 'voice-proj',
            'JARVIS_TEAM_AGENT': 'claude',
            'JARVIS_TEAM_ROLE': 'architect',
        }
        proc = subprocess.run(
            [sys.executable, str(pdir / 'bin' / 'jarvis-team'),
             'ask', 'owner', 'Jaką bazę danych wybieramy?', '--wait', '8'],
            env=ask_env,
            capture_output=True,
            text=True,
            timeout=12,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn('SQLite z trybem WAL', proc.stdout)

    def test_telegram_mobile_diff_apply_and_checkpoint_rollback(self):
        if not shutil.which('git'):
            self.skipTest('git not installed')

        cp_base = self.base / 'checkpoints'
        target_dir = Path(self.tmp.name) / 'live_app'
        target_dir.mkdir(parents=True)
        (target_dir / 'app.py').write_text('VERSION = 1\n', encoding='utf-8')

        agent_team.create_project(
            goal='Wdrożenie mobilne przez Telegram',
            participants=['claude'],
            project_id='tg-deploy',
            use_worktrees=False,
            auto_wake_mentions=False,
        )
        pdir = agent_team.project_root('tg-deploy')
        (pdir / 'repo' / 'app.py').write_text('VERSION = 2\n', encoding='utf-8')
        agent_team.sync_repo_to_outbox('tg-deploy')

        transport = _FakeTelegramTransport()
        owner_id = 777001
        channel = telegram_channel.TelegramChannel(
            agent=type('DummyOp', (), {'start': lambda *a, **k: {'id': 'job1'}, 'status': lambda *a: {}})(),
            transport=transport,
            owner_id=owner_id,
            state_root=self.base,
            default_target=target_dir,
        )

        with patch.object(checkpoint_manager, 'default_manager',
                          side_effect=lambda **kw: checkpoint_manager.CheckpointManager(base=cp_base, enabled=True)):
            # 1. Stranger message is ignored
            channel.handle_update({
                'update_id': 1,
                'message': {
                    'from': {'id': 999999, 'is_bot': False},
                    'chat': {'id': 999999, 'type': 'private'},
                    'text': '/apply tg-deploy',
                },
            })
            self.assertEqual((target_dir / 'app.py').read_text(encoding='utf-8'), 'VERSION = 1\n')

            # 2. Owner runs /apply tg-deploy -> updates file AND creates shadow-git checkpoint
            channel.handle_update({
                'update_id': 2,
                'message': {
                    'from': {'id': owner_id, 'is_bot': False},
                    'chat': {'id': owner_id, 'type': 'private'},
                    'text': '/apply tg-deploy',
                },
            })
            self.assertEqual((target_dir / 'app.py').read_text(encoding='utf-8'), 'VERSION = 2\n')
            self.assertTrue(any('Wdrożono' in m['text'] for m in transport.sent))

            # 3. Owner taps inline "Cofnij Checkpoint" callback button -> restores VERSION = 1!
            channel.handle_update({
                'update_id': 3,
                'callback_query': {
                    'id': 'cb-1',
                    'from': {'id': owner_id, 'is_bot': False},
                    'message': {'chat': {'id': owner_id, 'type': 'private'}},
                    'data': 'rollback:',
                },
            })
            self.assertEqual((target_dir / 'app.py').read_text(encoding='utf-8'), 'VERSION = 1\n')


if __name__ == '__main__':
    unittest.main()
