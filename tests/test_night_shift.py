"""night_shift: guard gates, five-step maintenance pass and Morning Report.

The maintenance loop fans out into real backends (watchdog, code index, QA
gate, evolve engine), so every dependency is faked: module-level imports via
`patch.object`, function-level `event_bus`/`qa_gate` imports via
`patch.dict(sys.modules)`, the load average via `os.getloadavg/cpu_count` and
the clock via a consuming fake (three time.time() calls per run: started,
elapsed, finished_at). Pinned: the three skip gates and their order, force
recording the load instead of skipping, target-module slicing with `.py`
suffix stripping, the atomic 0600 report with no temp residue, the exact
summary format, the night_shift.completed payload and the systemd unit/
CLI contracts. The report lives in `ROOT.parent/night_shift/latest_report.json`.
"""
import io
import json
import shutil
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import night_shift
from night_shift import (
    DEFAULT_MAX_LOAD_RATIO,
    any_agent_busy,
    check_system_quiet,
    install_user_timer,
    latest_report,
    main,
    run_night_shift,
    systemd_unit_files,
)

QUIET_LOAD = {'getloadavg': ((2.1, 1, 1), 4), 'result_ratio': 0.525}
BUSY_LOAD = ((8.0, 1, 1), 4)


class NightShiftBase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.sdir = self.tmp / 'agents'
        self.report_file = self.sdir / 'night_shift' / 'latest_report.json'
        self.proj = self.tmp / 'proj'
        self.proj.mkdir()
        (self.proj / 'router.py').write_text('x = 1')
        (self.proj / 'server.py').write_text('y = 2')
        self.published = []

    def make_fakes(self, **override):
        vals = iter((1000.0, 1002.5, 1002.5))
        clock = SimpleNamespace(time=lambda: next(vals), time_ns=lambda: 444)
        defaults = dict(
            agent_cli=SimpleNamespace(
                ROOT=self.sdir / 'agent_cli.py',
                agent_ids=lambda: [],
                _check_running=lambda aid: (False, None)),
            budget_guard=SimpleNamespace(
                allow_background_run=lambda: (True, ''),
                status=lambda: {'daily': 'ok'}),
            code_index=SimpleNamespace(
                index_directory=MagicMock(return_value={'indexed': 7, 'skipped': 3}),
                evict_idle_cache=MagicMock()),
            health_watchdog=SimpleNamespace(
                scan_logs=MagicMock(return_value={'incidents': [{'i': 1}], 'dispatched': []})),
            evolve_engine=SimpleNamespace(
                AdversarialBreaker=SimpleNamespace(generate_draft_cases=MagicMock(
                    return_value={'mutation_report': {'mutants': 10, 'kill_rate': 0.8,
                                                      'survivors': ['s1', 's2']},
                                  'cases': [1, 2, 3]})),
                SkillDistiller=SimpleNamespace(
                    distill_from_archive=MagicMock(return_value={'created': 2, 'total': 9})),
                SelfHarness=SimpleNamespace(
                    evolve_prompt_from_failures=MagicMock(return_value={'updated': True}))),
            time=clock,
        )
        defaults.update(override)
        return defaults

    def run_shift(self, fakes=None, load_avg=(2.1, 1, 1), cores=4,
                  qa_crash=None, **kwargs):
        fakes = fakes or self.make_fakes()
        audit = MagicMock(return_value={'ok': True, 'issues': []})
        if qa_crash is not None:
            audit = MagicMock(side_effect=RuntimeError(qa_crash))
        self.published = []
        event_bus = SimpleNamespace(
            publish=lambda topic, payload: self.published.append((topic, payload)))
        qa_gate = SimpleNamespace(audit_viewer=audit)
        with patch.dict(sys.modules, {'event_bus': event_bus, 'qa_gate': qa_gate}), \
                patch('os.getloadavg', return_value=load_avg), \
                patch('os.cpu_count', return_value=cores):
            patchers = [patch.object(night_shift, k, v) for k, v in fakes.items()]
            for p in patchers:
                p.start()
                self.addCleanup(p.stop)
            self.qa_gate = qa_gate
            self.event_bus = event_bus
            return run_night_shift(project_root=self.proj, **kwargs)


class QuietCheck(unittest.TestCase):
    def test_ratio_normalised_per_core(self):
        with patch('os.getloadavg', return_value=(2.1, 1, 1)), \
                patch('os.cpu_count', return_value=4):
            self.assertEqual(check_system_quiet(), (True, 0.525))
        with patch('os.getloadavg', return_value=(2.87, 1, 1)), \
                patch('os.cpu_count', return_value=4):
            self.assertEqual(check_system_quiet(),
                            (False, 0.718))
        # boundary: exactly at the max ratio counts as quiet (<=)
        with patch('os.getloadavg', return_value=(2.8, 1, 1)), \
                patch('os.cpu_count', return_value=4):
            self.assertEqual(check_system_quiet(), (True, 0.7))

    def test_custom_ratio_and_missing_cpus(self):
        with patch('os.getloadavg', return_value=(3.6, 1, 1)), \
                patch('os.cpu_count', return_value=4):
            self.assertTrue(check_system_quiet(max_load_ratio=0.9)[0])
        # cpu_count() -> None falls back to a single core
        with patch('os.getloadavg', return_value=(3.6, 1, 1)), \
                patch('os.cpu_count', return_value=None):
            self.assertEqual(check_system_quiet(max_load_ratio=5.0), (True, 3.6))

    def test_missing_getloadavg_is_treated_as_quiet(self):
        with patch('os.getloadavg', side_effect=OSError('no procfs')):
            self.assertEqual(check_system_quiet(), (True, 0.0))
        self.assertEqual(DEFAULT_MAX_LOAD_RATIO, 0.70)


class AgentBusy(NightShiftBase):
    def test_only_running_agents_reported(self):
        fake = self.make_fakes()
        fake['agent_cli'] = SimpleNamespace(
            ROOT=self.sdir / 'agent_cli.py',
            agent_ids=lambda: ['klorek', 'czlek', 'idlek'],
            _check_running=lambda aid: (aid in ('klorek', 'czlek'), None))
        with patch.object(night_shift, 'agent_cli', fake['agent_cli']):
            self.assertEqual(any_agent_busy(), ['klorek', 'czlek'])

    def test_agent_lookup_failure_is_swallowed(self):
        fake = self.make_fakes()
        fake['agent_cli'] = SimpleNamespace(
            ROOT=self.sdir / 'agent_cli.py',
            agent_ids=lambda: (_ for _ in ()).throw(RuntimeError('boom')))
        with patch.object(night_shift, 'agent_cli', fake['agent_cli']):
            self.assertEqual(any_agent_busy(), [])


class LatestReport(NightShiftBase):
    def test_missing_corrupt_and_non_dict_fall_back(self):
        fake = self.make_fakes()
        self.report_file.parent.mkdir(parents=True, exist_ok=True)
        with patch.object(night_shift, 'agent_cli', fake['agent_cli']):
            self.assertEqual(latest_report(), {'ok': True, 'has_report': False})
            self.report_file.write_text('{oops', encoding='utf-8')
            self.assertEqual(latest_report(), {'ok': True, 'has_report': False})
            self.report_file.write_text('["a list"]', encoding='utf-8')
            self.assertEqual(latest_report(), {'ok': True, 'has_report': False})

    def test_full_run_persists_a_readable_report(self):
        result = self.run_shift()
        self.assertTrue(result['ok'])
        with patch.object(night_shift, 'agent_cli', self.make_fakes()['agent_cli']):
            stored = latest_report()
        self.assertEqual(stored, json.loads(json.dumps(result)))


class RunShift(NightShiftBase):
    def test_skip_when_agents_running(self):
        fake = self.make_fakes()
        fake['agent_cli'] = SimpleNamespace(
            ROOT=self.sdir / 'agent_cli.py',
            agent_ids=lambda: ['klorek', 'czlek'],
            _check_running=lambda aid: (aid == 'klorek', None))
        result = self.run_shift(fakes=fake)
        self.assertFalse(result['ok'])
        self.assertTrue(result['skipped'])
        self.assertEqual(result['reason'],
                         'Wstrzymano Night Shift — pracują agenci: klorek.')
        self.assertEqual(result['busy_agents'], ['klorek'])
        fake['health_watchdog'].scan_logs.assert_not_called()
        self.assertFalse(self.report_file.exists())

    def test_skip_when_budget_blocks(self):
        fake = self.make_fakes()
        fake['budget_guard'] = SimpleNamespace(
            allow_background_run=lambda: (False, 'Budżet dzienny wyczerpany'),
            status=lambda: {})
        result = self.run_shift(fakes=fake)
        self.assertFalse(result['ok'])
        self.assertTrue(result['skipped'])
        self.assertEqual(result['reason'], 'Budżet dzienny wyczerpany')

    def test_skip_when_cpu_is_loaded(self):
        fake = self.make_fakes()
        result = self.run_shift(fakes=fake, load_avg=BUSY_LOAD[0], cores=BUSY_LOAD[1])
        self.assertFalse(result['ok'])
        self.assertTrue(result['skipped'])
        self.assertEqual(result['reason'],
                         'Wstrzymano Night Shift — obciążenie CPU wynosi 200%.')
        self.assertEqual(result['load_ratio'], 2.0)
        fake['health_watchdog'].scan_logs.assert_not_called()

    def test_force_bypasses_gates_but_records_load(self):
        result = self.run_shift(load_avg=BUSY_LOAD[0], cores=4, force=True)
        self.assertTrue(result['ok'])
        self.assertEqual(result['load_ratio'], 2.0)
        self.assertIn('CPU load 200%):', result['summary_text'][:60])
        self.assertEqual(result['duration_s'], 2.5)
        self.assertEqual(result['finished_at'], 1002.5)

    def test_happy_pass_report_and_side_effects(self):
        fake = self.make_fakes()
        result = self.run_shift(fakes=fake,
                                modules=['router', 'missing', 'server.py'],
                                auto_repair=True)
        self.assertTrue(result['ok'])
        self.assertTrue(result['has_report'])
        # step wiring
        fake['health_watchdog'].scan_logs.assert_called_once_with(
            auto_repair=True, project_root=self.proj)
        fake['code_index'].index_directory.assert_called_once_with(self.proj)
        fake['code_index'].evict_idle_cache.assert_called_once_with(force=True)
        self.qa_gate.audit_viewer.assert_called_once_with(self.proj)
        draft = fake['evolve_engine'].AdversarialBreaker.generate_draft_cases
        self.assertEqual([(c.args[0], c.kwargs) for c in draft.call_args_list],
                         [('router', {'source_path': self.proj / 'router.py'}),
                          ('server', {'source_path': self.proj / 'server.py'})])
        fake['evolve_engine'].SkillDistiller.distill_from_archive.assert_called_once_with()
        fake['evolve_engine'].SelfHarness.evolve_prompt_from_failures.assert_called_once_with(
            'patcher')
        # report payload
        self.assertEqual(result['watchdog'], {'incidents': 1, 'dispatched': 0})
        self.assertEqual(result['code_index'], {'indexed': 7, 'skipped': 3})
        self.assertEqual(result['viewer_qa'], {'ok': True, 'issues': []})
        self.assertEqual(result['distilled_skills'], {'created': 2, 'total': 9})
        self.assertTrue(result['self_harness_updated'])
        self.assertEqual(result['budget'], {'daily': 'ok'})
        self.assertEqual(result['mutations'],
                         [{'module': 'router', 'mutants': 10, 'kill_rate': 0.8,
                           'survivors': 2, 'draft_cases': 3},
                          {'module': 'server', 'mutants': 10, 'kill_rate': 0.8,
                           'survivors': 2, 'draft_cases': 3}])
        self.assertEqual(
            result['summary_text'],
            'Raport Nocnej Zmiany (2.5s, CPU load 52%):\n'
            '- Watchdog logów: 1 incydent(ów).\n'
            '- Indeks kodu (FTS5+AST): +7 zaktualizowanych, 3 bez zmian.\n'
            '- Bramka QA interfejsu: OK.\n'
            '- Destylacja skilli: +2 nowych (łącznie 9).\n'
            '- Mutacje `router`: zabito 80% z 10 (szkice testów: 3).\n'
            '- Mutacje `server`: zabito 80% z 10 (szkice testów: 3).')
        # persistence: 0600 file in a 0700 dir, unique tmp gone
        self.assertEqual(self.report_file.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.report_file.parent.stat().st_mode & 0o777, 0o700)
        self.assertEqual(list(self.report_file.parent.glob('.latest_report.json.tmp*')), [])
        # SSE push payload
        self.assertEqual(self.published, [('night_shift.completed', {
            'finished_at': 1002.5, 'duration_s': 2.5,
            'incidents': 1, 'viewer_qa_ok': True})])

    def test_default_targets_and_module_cap(self):
        # modules=None -> ['router'] default; more than 3 targets -> capped
        fake = self.make_fakes()
        for name in ('alpha', 'beta', 'gamma', 'delta'):
            (self.proj / f'{name}.py').write_text('x = 1')
        self.run_shift(fakes=fake, modules=['alpha', 'beta', 'gamma', 'delta'])
        called = [c.args[0] for c in
                  fake['evolve_engine'].AdversarialBreaker.generate_draft_cases.call_args_list]
        self.assertEqual(called, ['alpha', 'beta', 'gamma'])   # cap [:3]

        fake = self.make_fakes()
        self.run_shift(fakes=fake)                     # default: router only
        called = [c.args[0] for c in
                  fake['evolve_engine'].AdversarialBreaker.generate_draft_cases.call_args_list]
        self.assertEqual(called, ['router'])

    def test_mutate_error_and_missing_modules(self):
        fake = self.make_fakes()
        fake['evolve_engine'] = SimpleNamespace(
            AdversarialBreaker=SimpleNamespace(generate_draft_cases=MagicMock(
                side_effect=RuntimeError('mutation kaputt'))),
            SkillDistiller=SimpleNamespace(
                distill_from_archive=MagicMock(return_value={})),
            SelfHarness=SimpleNamespace(
                evolve_prompt_from_failures=MagicMock(return_value={})))
        result = self.run_shift(fakes=fake, modules=['router'])
        self.assertEqual(result['mutations'],
                         [{'module': 'router', 'error': 'mutation kaputt'}])
        # missing module file produces no summary entry at all
        fake = self.make_fakes()
        result = self.run_shift(fakes=fake, modules=['nope'])
        self.assertEqual(result['mutations'], [])

    def test_qa_gate_failure_reflected_and_exception_enveloped(self):
        # healthy viewer -> labelled OK in the summary
        result = self.run_shift()
        self.assertEqual(result['viewer_qa'], {'ok': True, 'issues': []})
        self.assertIn('Bramka QA interfejsu: OK.', result['summary_text'])

        # a QA crash is enveloped, message clipped to 160
        result = self.run_shift(qa_crash='x' * 500)
        self.assertEqual(result['viewer_qa'],
                         {'ok': False, 'issues': ['x' * 160]})
        self.assertEqual([ln for ln in result['summary_text'].splitlines()
                          if 'QA' in ln], ['- Bramka QA interfejsu: 1 uwag(i).'])

    def test_telegram_delivery_matrix(self):
        telegram = SimpleNamespace(_send_safe=MagicMock())
        result = self.run_shift(telegram=telegram)
        telegram._send_safe.assert_called_once_with(result['summary_text'])

        broken = SimpleNamespace(_send_safe=MagicMock(
            side_effect=RuntimeError('no net')))
        self.assertTrue(self.run_shift(telegram=broken)['ok'])

        no_attr = object()
        self.assertTrue(self.run_shift(telegram=no_attr)['ok'])
        self.assertTrue(self.run_shift()['ok'])

    def test_event_bus_failure_does_not_break_the_run(self):
        # run_shift injects a healthy event_bus; swap for a failing one
        fakes = self.make_fakes()
        failing = SimpleNamespace(publish=MagicMock(side_effect=RuntimeError('down')))
        with patch.dict(sys.modules, {'event_bus': failing}), \
                patch('os.getloadavg', return_value=(0.0, 0, 0)), \
                patch('os.cpu_count', return_value=4):
            patchers = [patch.object(night_shift, k, v) for k, v in fakes.items()]
            for p in patchers:
                p.start()
            try:
                result = run_night_shift(project_root=self.proj, force=True)
            finally:
                for p in patchers:
                    p.stop()
        self.assertTrue(result['ok'])
        failing.publish.assert_called_once()


class SystemdUnits(unittest.TestCase):
    def test_unit_contents(self):
        units = systemd_unit_files(project_root='/proj')
        self.assertEqual(sorted(units), ['jarvis-night-shift.service',
                                         'jarvis-night-shift.timer'])
        service = units['jarvis-night-shift.service']
        self.assertIn('WorkingDirectory=/proj', service)
        self.assertIn(f'ExecStart={sys.executable} /proj/night_shift.py --auto', service)
        self.assertIn('Nice=15', service)
        self.assertIn('IOSchedulingClass=idle', service)
        timer = units['jarvis-night-shift.timer']
        self.assertIn('OnCalendar=*-*-* 03:30:00', timer)
        self.assertIn('RandomizedDelaySec=15m', timer)
        self.assertIn('Persistent=true', timer)
        self.assertIn('WantedBy=timers.target', timer)
        custom = systemd_unit_files(on_calendar='*-*-* 04:00:00')['jarvis-night-shift.timer']
        self.assertIn('OnCalendar=*-*-* 04:00:00', custom)

    def test_install_writes_files_and_enables_optionally(self):
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp) / 'units'
            with patch('subprocess.run', MagicMock(return_value=SimpleNamespace(returncode=0))) as run:
                out = install_user_timer(enable=True, target_dir=dest)
            self.assertTrue(out['ok'])
            self.assertTrue(out['enabled'])
            self.assertEqual(len(out['files']), 2)
            for name in ('jarvis-night-shift.service', 'jarvis-night-shift.timer'):
                self.assertTrue((dest / name).is_file())
            self.assertEqual(run.call_args_list[0].args,
                             (['systemctl', '--user', 'daemon-reload'],))
            self.assertEqual(run.call_args_list[1].args,
                             (['systemctl', '--user', 'enable', '--now',
                               'jarvis-night-shift.timer'],))
            self.assertEqual(dest.stat().st_mode & 0o777, 0o700)

            with patch('subprocess.run', MagicMock(return_value=SimpleNamespace(returncode=1))):
                self.assertFalse(install_user_timer(enable=True, target_dir=dest)['enabled'])
            with patch('subprocess.run', MagicMock()) as untouched:
                self.assertFalse(install_user_timer(target_dir=dest)['enabled'])
            untouched.assert_not_called()


class CliEntry(unittest.TestCase):
    def _main(self, argv, result):
        with patch.object(night_shift, 'run_night_shift',
                          MagicMock(return_value=result)) as shifted:
            buffer = io.StringIO()
            with redirect_stdout(buffer):
                code = main(argv)
        return code, shifted, buffer.getvalue()

    def test_flags_and_exit_codes(self):
        code, shifted, out = self._main(['--force', '--auto-repair'], {'ok': True})
        self.assertEqual(code, 0)
        self.assertTrue(shifted.call_args.kwargs['force'])
        self.assertTrue(shifted.call_args.kwargs['auto_repair'])
        self.assertIn('"ok": true', out)

        # --auto alone means guard mode: force must be False
        code, shifted, _ = self._main(['--auto'], {'ok': False, 'skipped': True})
        self.assertEqual(code, 0)     # skip still exits cleanly
        self.assertFalse(shifted.call_args.kwargs['force'])

        # --force together with --auto also respects the guards
        code, shifted, _ = self._main(['--force', '--auto'], {'ok': True})
        self.assertFalse(shifted.call_args.kwargs['force'])

        # a genuine failure exits non-zero
        code, _, _ = self._main(['--force'], {'ok': False})
        self.assertEqual(code, 1)


if __name__ == '__main__':
    unittest.main()
