"""health_watchdog: traceback fingerprinting, incident scan and repair dispatch.

The parser and scanner run pure over synthetic logs; every backend (journalctl
through `subprocess`, the incident state store through `agent_cli.ROOT`,
agent routing and context packs) is replaced with fakes. Pinned: journal
prefix stripping, the signature normalisation rules (line numbers and hex
addresses are irrelevant; only the innermost-4 frame functions plus the
exception type matter), the 45-line block cap, threshold semantics (0 →
default 3, negative → 1), the 3600 s repair cooldown, the sandbox-repair task
contract (agent_cli.start_async envelope with approved=True + consent
'watchdog') and the top-1-only dispatch policy.
"""
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import health_watchdog
from health_watchdog import (
    DEFAULT_COOLDOWN_SEC,
    _strip_journal_prefix,
    dispatch_sandbox_repair,
    fetch_service_logs,
    parse_tracebacks,
    scan_logs,
    watchdog_status,
)

TB = '''Traceback (most recent call last):
  File "/proj/core.py", line 42, in do_work
    raise ValueError("asset 0x7fdead beef missing")
ValueError: asset 0x7fdead beef missing'''

TB_OTHER = '''Traceback (most recent call last):
  File "/proj/views.py", line 7, in render
    raise RuntimeError("render puknal")
RuntimeError: render puknal'''


class ParseHelpers(unittest.TestCase):
    def test_journal_prefix_stripping_edges(self):
        self.assertEqual(_strip_journal_prefix('Nov 24 02:10:11 host python[1]: X'), 'X')
        self.assertEqual(_strip_journal_prefix(']: X'), ']: X')           # marker at 0: kept
        self.assertEqual(_strip_journal_prefix('plain: no marker here'), 'plain: no marker here')
        self.assertEqual(_strip_journal_prefix('x' * 70 + ']: Y'),
                         'x' * 70 + ']: Y')                                # beyond 64: kept


class ParseTracebacks(unittest.TestCase):
    def test_single_traceback_full_extraction(self):
        found = parse_tracebacks(TB)
        self.assertEqual(len(found), 1)
        item = found[0]
        self.assertEqual(item['error_type'], 'ValueError')
        self.assertEqual(item['message'], 'asset 0x7fdead beef missing')  # not normalised
        self.assertEqual(item['file'], '/proj/core.py')                   # innermost frame
        self.assertEqual(item['line'], 42)
        self.assertEqual(item['function'], 'do_work')
        self.assertIn('Traceback (most recent call last):', item['traceback'])
        self.assertIn('raise ValueError', item['traceback'])
        self.assertEqual(len(item['signature']), 12)

    def test_journal_prefixes_do_not_change_the_signature(self):
        prefix = 'Nov 24 02:10:11 host python[1234]: '
        prefixed = prefix + TB.replace('\n', '\n' + prefix)
        self.assertEqual(parse_tracebacks(TB)[0]['signature'],
                         parse_tracebacks(prefixed)[0]['signature'])

    def test_signature_normalisation_rules(self):
        base = parse_tracebacks(TB)[0]['signature']
        # lines + hex addresses are ignored -> same signature
        variant = TB.replace('line 42', 'line 90').replace('0x7fdead', '0x112233')
        self.assertEqual(base, parse_tracebacks(variant)[0]['signature'])
        # a different exception type -> different signature
        self.assertNotEqual(base, parse_tracebacks(TB.replace('ValueError', 'TypeError'))[0]['signature'])

        def stack(prefix_files, tail_files):
            head = '\n'.join(f'  File "/{prefix_files}{i}.py", line {i}, in outer{i}'
                            for i in range(4))
            tail = '\n'.join(f'  File "/{tail_files}{i}.py", line {i}, in keep{i}'
                             for i in range(4))
            return (f'Traceback (most recent call last):\n{head}\n{tail}\n'
                    f'RuntimeError: x')
        # frames outside the innermost-4 window are ignored
        self.assertEqual(parse_tracebacks(stack('old', 'keep'))[0]['signature'],
                         parse_tracebacks(stack('zzz', 'keep'))[0]['signature'])
        # a change inside the window matters
        self.assertNotEqual(parse_tracebacks(stack('old', 'keep'))[0]['signature'],
                            parse_tracebacks(stack('old', 'nope'))[0]['signature'])

    def test_adjacent_tracebacks_are_split(self):
        found = parse_tracebacks(TB + '\n' + TB_OTHER)
        self.assertEqual([(f['error_type'], f['function']) for f in found],
                         [('ValueError', 'do_work'), ('RuntimeError', 'render')])

    def test_frameless_and_unknown_exception_names(self):
        self.assertEqual(parse_tracebacks('Traceback (most recent call last):\nBoom: x'), [])
        # exception names outside Error/Exception/Warning/Fault keep the default
        found = parse_tracebacks(TB.replace('ValueError', 'MyCustomFailure'))
        self.assertEqual(found[0]['error_type'], 'Exception')

    def test_block_cap_and_traceback_clip(self):
        huge = 'Traceback (most recent call last):'
        for i in range(60):
            huge += f'\n  File "/f{i}.py", line {i}, in func{i}'
        huge += '\nRuntimeError: boom'
        found = parse_tracebacks(huge)
        self.assertEqual(len(found), 1)
        self.assertEqual(len(found[0]['traceback'].splitlines()), 45)   # block cap
        self.assertEqual(found[0]['function'], 'func43')

        wide = 'Traceback (most recent call last):\n  File "/p.py", line 1, in a\n' \
               + '    padding-' * 300 + f'\nRuntimeError: {"msg" * 900}'
        found = parse_tracebacks(wide)
        self.assertLessEqual(len(found[0]['traceback']), 2500)   # tail clip
        self.assertTrue(found[0]['traceback'].endswith(found[0]['traceback'][-40:]))


class FetchLogs(unittest.TestCase):
    def test_journalctl_command_and_window_clamp(self):
        run = MagicMock(return_value=SimpleNamespace(stdout='LOGS', returncode=0))
        with patch.object(health_watchdog.subprocess, 'run', run):
            out = fetch_service_logs(window_minutes=999)
        self.assertEqual(out, 'LOGS')
        self.assertEqual(run.call_args.args, (
            ['journalctl', '--user', '-u', 'jarvis.service',
             '--since', '180 minutes ago', '--no-pager', '-n', '600'],))
        self.assertEqual(run.call_args.kwargs['capture_output'], True)
        self.assertEqual(run.call_args.kwargs['timeout'], 10)

    def test_missing_journalctl_returns_empty(self):
        run = MagicMock(side_effect=OSError('no journalctl'))
        with patch.object(health_watchdog.subprocess, 'run', run):
            self.assertEqual(fetch_service_logs(), '')

    def test_slow_journalctl_timeout_returns_empty(self):
        # regression: journalctl overrunning the 10 s window must not raise
        # (TimeoutExpired is a SubprocessError, not an OSError)
        import subprocess
        run = MagicMock(side_effect=subprocess.TimeoutExpired(
            cmd=['journalctl'], timeout=10))
        with patch.object(health_watchdog.subprocess, 'run', run):
            self.assertEqual(fetch_service_logs(), '')
        self.assertEqual(run.call_count, 1)


class WatchdogBase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.state_file = self.tmp / 'agents' / 'watchdog_state.json'
        self.started = MagicMock(return_value={'id': 'run-77'})
        self.started_args = None
        modules = dict(
            agent_cli=SimpleNamespace(ROOT=self.tmp / 'agents' / 'agent_cli.py',
                                      start_async=self.started),
            agent_router=SimpleNamespace(
                pick_best_agent=MagicMock(return_value='klorek')),
            code_index=SimpleNamespace(
                build_context_pack=MagicMock(return_value='PACK')),
            time=SimpleNamespace(time=lambda: 5000.0),
        )
        for name, fake in modules.items():
            patcher = patch.object(health_watchdog, name, fake)
            setattr(self, name, fake)
            patcher.start()
            self.addCleanup(patcher.stop)

    def write_state(self, state):
        self.state_file.parent.mkdir(parents=True, exist_ok=True)
        self.state_file.write_text(json.dumps(state), encoding='utf-8')

    def read_state(self):
        return json.loads(self.state_file.read_text(encoding='utf-8'))


class ScanLogs(WatchdogBase):
    def test_explicit_log_text_skips_fetch(self):
        fetch = MagicMock(return_value='')
        with patch.object(health_watchdog, 'fetch_service_logs', fetch):
            out = scan_logs(TB + '\n' + TB, threshold=2)
        fetch.assert_not_called()
        self.assertEqual(out['scanned_tracebacks'], 2)
        self.assertEqual([i['count'] for i in out['incidents']], [2])

        with patch.object(health_watchdog, 'fetch_service_logs', fetch):
            scan_logs(threshold=2)
        fetch.assert_called_once_with(window_minutes=10)

    def test_grouping_thresholds_and_sorting(self):
        log = '\n'.join([TB, TB, TB, TB_OTHER, TB_OTHER])
        out = scan_logs(log, threshold=2)
        self.assertEqual(out['scanned_tracebacks'], 5)
        self.assertEqual([(i['count'], i['error_type']) for i in out['incidents']],
                         [(3, 'ValueError'), (2, 'RuntimeError')])
        # one occurrence is below the default threshold
        out = scan_logs(TB, threshold=2)
        self.assertEqual(out['incidents'], [])

    def test_threshold_zero_falls_back_to_default_three(self):
        self.assertEqual(scan_logs(TB + '\n' + TB, threshold=0)['incidents'], [])
        out = scan_logs(TB + '\n' + TB + '\n' + TB, threshold=0)
        self.assertEqual([i['count'] for i in out['incidents']], [3])

    def test_negative_threshold_clamps_to_one(self):
        out = scan_logs(TB, threshold=-1)
        self.assertEqual([i['count'] for i in out['incidents']], [1])

    def test_state_persistence_and_repair_field_preservation(self):
        scan_logs(TB + '\n' + TB, threshold=2)
        self.assertEqual(self.state_file.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.state_file.parent.stat().st_mode & 0o777, 0o700)
        state = self.read_state()
        self.assertEqual(state['last_scan_at'], 5000.0)
        incident = next(iter(state['incidents'].values()))
        self.assertEqual(incident['last_seen'], 5000.0)
        self.assertEqual(incident['repair_run_id'], '')
        self.assertEqual(incident['repair_agent'], '')
        self.assertEqual(incident['repaired_at'], 0)

        # a later scan of unrelated noise keeps the incident recorded
        scan_logs('noise', threshold=2)
        state = self.read_state()
        self.assertEqual(len(state['incidents']), 1)
        self.assertEqual(state['last_scan_at'], 5000.0)

    def test_corrupted_and_non_dict_state_tolerated(self):
        self.state_file.parent.mkdir(parents=True, exist_ok=True)
        self.state_file.write_text('{oops', encoding='utf-8')
        out = scan_logs(TB, threshold=1)
        self.assertEqual([i['count'] for i in out['incidents']], [1])
        self.state_file.write_text('["a list"]', encoding='utf-8')
        out = scan_logs(TB, threshold=1)
        self.assertEqual(len(out['incidents']), 1)

    def test_auto_repair_respects_cooldown_and_dispatches_only_top_incident(self):
        log = '\n'.join([TB, TB, TB, TB_OTHER, TB_OTHER])
        dispatched = MagicMock(return_value={'ok': True, 'agent': 'klorek'})
        with patch.object(health_watchdog, 'dispatch_sandbox_repair', dispatched):
            out = scan_logs(log, threshold=2, auto_repair=True)
        # nothing repaired yet -> one dispatch for the top (3x) incident only
        dispatched.assert_called_once()
        self.assertEqual(len(out['dispatched']), 1)

        # mark as repaired "now" -> the cooldown suppresses re-dispatch
        signature = out['incidents'][0]['signature']
        state = self.read_state()
        state['incidents'][signature]['repaired_at'] = 5000.0
        self.write_state(state)
        dispatched.reset_mock()
        with patch.object(health_watchdog, 'dispatch_sandbox_repair', dispatched):
            out = scan_logs(log, threshold=2, auto_repair=True)
        dispatched.assert_not_called()
        self.assertEqual(out['dispatched'], [])

        # cooldown window elapsed (-3601 s) -> dispatched again
        state['incidents'][signature]['repaired_at'] = 5000.0 - DEFAULT_COOLDOWN_SEC - 1
        self.write_state(state)
        with patch.object(health_watchdog, 'dispatch_sandbox_repair', dispatched):
            out = scan_logs(log, threshold=2, auto_repair=True)
        dispatched.assert_called_once()


class DispatchRepair(WatchdogBase):
    def seed_incident(self):
        out = scan_logs(TB + '\n' + TB, threshold=2)
        return out['incidents'][0]['signature']

    def test_unknown_signature_refused(self):
        with self.assertRaises(ValueError) as ctx:
            dispatch_sandbox_repair('nope123')
        self.assertIn('Unknown incident signature', str(ctx.exception))

    def test_dispatch_task_contract_and_state_update(self):
        signature = self.seed_incident()
        out = dispatch_sandbox_repair(signature, project_root='/proj')
        self.assertEqual(out, {
            'ok': True, 'signature': signature, 'agent': 'klorek',
            'run_id': 'run-77',
            'outbox_hint': "Po zakończeniu przejrzyj diff i wdróż przez "
                           "apply_outbox('klorek', '/proj')."})
        self.agent_router.pick_best_agent.assert_called_once()
        kwargs = self.agent_router.pick_best_agent.call_args.kwargs
        self.assertEqual(kwargs['role'], 'repair')
        self.assertTrue(kwargs['require_idle'])
        self.assertIn('ValueError', kwargs['task'])

        pack = self.code_index.build_context_pack
        pack.assert_called_once_with('ValueError core.py do_work',
                                     root_dir=Path('/proj'), limit=5)
        self.started.assert_called_once()
        agent, task_text = self.started.call_args.args
        self.assertEqual(agent, 'klorek')
        self.assertTrue(task_text.startswith(
            f'[WATCHDOG SAMONAPRAWA — sygnatura `{signature}`]'))
        sent = self.started.call_args.kwargs
        self.assertTrue(sent['approved'])
        self.assertEqual(sent['consent'], 'watchdog')
        self.assertEqual(sent['target_hint'], '/proj')
        self.assertEqual(sent['task_label'],
                         f'[watchdog:{signature}] Naprawa ValueError w core.py')

        incident = self.read_state()['incidents'][signature]
        self.assertEqual(incident['repair_agent'], 'klorek')
        self.assertEqual(incident['repair_run_id'], 'run-77')
        self.assertEqual(incident['repaired_at'], 5000.0)

    def test_default_project_root_is_the_module_directory(self):
        signature = self.seed_incident()
        dispatch_sandbox_repair(signature)
        self.assertEqual(self.code_index.build_context_pack.call_args.kwargs['root_dir'],
                         Path(health_watchdog.__file__).resolve().parent)

    def test_no_available_agent_answers_not_ok(self):
        signature = self.seed_incident()
        router = SimpleNamespace(pick_best_agent=MagicMock(return_value=''))
        with patch.object(health_watchdog, 'agent_router', router):
            out = dispatch_sandbox_repair(signature)
        self.assertFalse(out['ok'])
        self.assertIn('Brak wolnego zainstalowanego agenta', out['error'])
        self.started.assert_not_called()

    def test_explicit_lowercase_agent_id_wins(self):
        signature = self.seed_incident()
        router = SimpleNamespace(pick_best_agent=MagicMock(return_value='klorek'))
        with patch.object(health_watchdog, 'agent_router', router):
            out = dispatch_sandbox_repair(signature, agent_id='KLOREK-X')
        self.assertEqual(out['agent'], 'klorek-x')
        router.pick_best_agent.assert_not_called()
        self.assertEqual(self.started.call_args.args[0], 'klorek-x')


class Status(WatchdogBase):
    def test_missing_state_returns_clean_envelope(self):
        self.assertEqual(watchdog_status(),
                         {'ok': True, 'last_scan_at': None, 'incidents': []})

    def test_sorted_by_last_seen_and_capped(self):
        self.write_state({
            'last_scan_at': 9.0,
            'incidents': {f's{i}': {'sig': f's{i}', 'last_seen': float(i)}
                          for i in range(30)},
        })
        out = watchdog_status()
        self.assertEqual(len(out['incidents']), 25)
        seen = [inc['last_seen'] for inc in out['incidents']]
        self.assertEqual(seen, sorted(seen, reverse=True))
        self.assertEqual(seen[0], 29.0)
        self.assertEqual(out['last_scan_at'], 9.0)


if __name__ == '__main__':
    unittest.main()
