"""automation_engine: cron matcher, job store, execution and delivery contracts.

The engine binds its backends at module import, so every stateful dependency
(agent_cli root, connectors, event bus, episodic memory, hardware/briefing/
doctor/storage, wayland DND, time) is replaced with `patch.object` fakes —
probing this module against real backends writes to the live episodic-memory
store, which nothing here exercises. Pinned: the pure cron matcher (steps,
ranges, lists, the POSIX day rule), the human-friendly parser with its 30 s
interval floor and same-minute double-execution guard, the 0600/0700 atomic
job store with its 60-job and 25-status caps, DND suppression for push
channels (obsidian deliberately exempt), thermal deferral, tick error
isolation and the reactive hardware-alert listener.
"""
import re
import shutil
import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import automation_engine
from automation_engine import (
    _cron_field_matches,
    automation_status,
    create_automation,
    execute_job,
    install_preset,
    install_reactive_event_rules,
    is_job_due,
    load_jobs,
    matches_cron_5,
    run_job_by_id,
    save_jobs,
    start_automation_daemon,
    tick_due_jobs,
)

TS_TUE_0800 = datetime(2026, 11, 24, 8, 0).timestamp()   # Tuesday 08:00
TS_SAT_0900 = datetime(2026, 11, 28, 9, 0).timestamp()    # Saturday 09:00
TS_SUN_0900 = datetime(2026, 11, 29, 9, 0).timestamp()    # Sunday 09:00
DT_MON_1200 = datetime(2026, 11, 23, 12, 0)              # Monday 12:00


class CronFields(unittest.TestCase):
    def test_wildcard_steps_and_clamp(self):
        # '*' matches any value; '*/0' clamps the step to 1 -> matches all.
        for value in (0, 7, 59):
            self.assertTrue(_cron_field_matches('*', value, 0, 59))
            self.assertTrue(_cron_field_matches('*/0', value, 0, 59))
        self.assertTrue(_cron_field_matches('*/15', 30, 0, 59))
        self.assertFalse(_cron_field_matches('*/15', 20, 0, 59))

    def test_ranges_lists_and_inverted(self):
        self.assertTrue(_cron_field_matches('1-5', 3, 0, 59))
        self.assertFalse(_cron_field_matches('1-5', 6, 0, 59))
        self.assertFalse(_cron_field_matches('5-3', 4, 0, 59))   # inverted: empty span
        self.assertTrue(_cron_field_matches('1,3,5', 5, 0, 59))
        self.assertFalse(_cron_field_matches('1,3,5', 4, 0, 59))
        # empty parts between commas are skipped, not errors
        self.assertTrue(_cron_field_matches('1,,3', 3, 0, 59))

    def test_base_with_and_without_step(self):
        self.assertTrue(_cron_field_matches('10', 10, 0, 59))
        self.assertFalse(_cron_field_matches('10', 11, 0, 59))
        # '10/2': base value with step over the rest of the range
        self.assertTrue(_cron_field_matches('10/2', 12, 0, 59))
        self.assertFalse(_cron_field_matches('10/2', 9, 0, 59))


class Cron5(unittest.TestCase):
    def test_osobady_mapping_and_seven_alias(self):
        sunday = datetime(2026, 11, 29, 8, 0)   # cron dow 0
        self.assertTrue(matches_cron_5('0 8 * * 0', sunday))
        self.assertTrue(matches_cron_5('0 8 * * 7', sunday))    # 7 == Sunday
        self.assertFalse(matches_cron_5('0 8 * * 1', sunday))
        saturday = datetime(2026, 11, 28, 8, 0)
        self.assertTrue(matches_cron_5('0 8 * * 6', saturday))
        self.assertTrue(matches_cron_5('0 12 * * 1', DT_MON_1200))  # cron 1 == Monday

    def test_field_count_and_value_errors_swallowed(self):
        self.assertFalse(matches_cron_5('* * * *', DT_MON_1200))
        self.assertFalse(matches_cron_5('* * * * * *', DT_MON_1200))
        self.assertFalse(matches_cron_5('*/x * * * *', DT_MON_1200))
        self.assertFalse(matches_cron_5('-1 * * * *', DT_MON_1200))

    def test_posix_day_rule_or_when_both_days_restricted(self):
        # Standard cron: both day fields restricted -> EITHER match satisfies
        # the day (fixed from the earlier AND interpretation).
        monday23 = DT_MON_1200
        self.assertTrue(matches_cron_5('0 12 1 * 1', monday23))   # dow matches
        sunday1 = datetime(2026, 11, 1, 12, 0)
        self.assertTrue(matches_cron_5('0 12 1 * 1', sunday1))    # dom matches
        wednesday25 = datetime(2026, 11, 25, 12, 0)
        self.assertFalse(matches_cron_5('0 12 1 * 1', wednesday25))  # neither
        self.assertTrue(matches_cron_5('0 12 15 11 3', wednesday25))   # dow hits
        self.assertFalse(matches_cron_5('0 12 15 12 3', wednesday25))   # month misses

    def test_single_day_restriction_stays_and(self):
        self.assertTrue(matches_cron_5('0 12 * * 1', DT_MON_1200))
        self.assertFalse(matches_cron_5('0 12 1 * *', DT_MON_1200))     # not the 1st
        self.assertTrue(matches_cron_5('0 12 * * *', DT_MON_1200))


class IsJobDue(unittest.TestCase):
    def test_gates(self):
        self.assertFalse(is_job_due({'schedule': 'daily 08:00', 'enabled': False},
                                    now_ts=TS_TUE_0800))
        self.assertFalse(is_job_due({'schedule': ''}, now_ts=TS_TUE_0800))
        self.assertFalse(is_job_due({'schedule': 'co 5 minut'}, now_ts=TS_TUE_0800))
        self.assertFalse(is_job_due({'schedule': 'daily 25:00'}, now_ts=TS_TUE_0800))
        self.assertFalse(is_job_due({'schedule': '*/x * * * *'}, now_ts=TS_TUE_0800))

    def test_daily_and_weekday_modes(self):
        self.assertTrue(is_job_due({'schedule': 'daily 08:00', 'last_run_at': 0},
                                   now_ts=TS_TUE_0800))
        self.assertTrue(is_job_due({'schedule': 'DAILY 08:00', 'last_run_at': 0},
                                   now_ts=TS_TUE_0800))       # case-insensitive
        self.assertFalse(is_job_due({'schedule': 'daily 08:01'}, now_ts=TS_TUE_0800))
        self.assertFalse(is_job_due({'schedule': 'weekdays 09:00'}, now_ts=TS_SAT_0900))
        self.assertTrue(is_job_due({'schedule': 'weekends 09:00'}, now_ts=TS_SUN_0900))
        self.assertFalse(is_job_due({'schedule': 'weekends 09:00'}, now_ts=TS_TUE_0800))

    def test_same_minute_double_execution_guard(self):
        # A run recorded inside the same calendar minute blocks re-execution.
        self.assertFalse(is_job_due({'schedule': 'daily 08:00',
                                     'last_run_at': TS_TUE_0800},
                                    now_ts=TS_TUE_0800 + 30))
        self.assertFalse(is_job_due({'schedule': 'daily 08:00',
                                     'last_run_at': TS_TUE_0800 + 1},
                                    now_ts=TS_TUE_0800 + 30))
        self.assertTrue(is_job_due({'schedule': 'daily 08:00',
                                    'last_run_at': TS_TUE_0800 - 60},
                                   now_ts=TS_TUE_0800))

    def test_interval_alias_and_floor(self):
        self.assertTrue(is_job_due({'schedule': 'hourly',
                                    'last_run_at': TS_TUE_0800 - 3600},
                                   now_ts=TS_TUE_0800))
        self.assertFalse(is_job_due({'schedule': 'hourly',
                                     'last_run_at': TS_TUE_0800 - 300},
                                    now_ts=TS_TUE_0800))
        # sub-30-second schedules are clamped up to a 30 s floor
        self.assertFalse(is_job_due({'schedule': 'every 1s',
                                     'last_run_at': TS_TUE_0800 - 20},
                                    now_ts=TS_TUE_0800))
        self.assertTrue(is_job_due({'schedule': 'every 1s',
                                   'last_run_at': TS_TUE_0800 - 30},
                                  now_ts=TS_TUE_0800))
        self.assertTrue(is_job_due({'schedule': 'EVERY 5m',
                                   'last_run_at': TS_TUE_0800 - 300},
                                  now_ts=TS_TUE_0800))
        self.assertTrue(is_job_due({'schedule': 'every 2d',
                                   'last_run_at': TS_TUE_0800 - 172800},
                                  now_ts=TS_TUE_0800))
        self.assertFalse(is_job_due({'schedule': 'every 2d',
                                    'last_run_at': TS_TUE_0800 - 86400},
                                   now_ts=TS_TUE_0800))


class AEBase(unittest.TestCase):
    """Sandboxed root + every backend faked; probes never touch live state."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.jobs_file = self.tmp / 'agents' / 'scheduled_jobs.json'
        self.exec_calls = []
        self.published = []
        self.doctor_calls = []
        self.subscribe = MagicMock()
        self.remember = MagicMock(return_value={'id': 'e1'})
        fakes = dict(
            agent_cli=SimpleNamespace(ROOT=self.tmp / 'agents' / 'agent_cli.py'),
            connectors_hub=SimpleNamespace(
                execute_connector_action=lambda act, params:
                (self.exec_calls.append((act, params)), {'ok': True})[1]),
            event_bus=SimpleNamespace(publish=self._publish,
                                     subscribe=self.subscribe),
            wayland_voice=SimpleNamespace(dnd_status=lambda: {'active': False}),
            hardware_guard=SimpleNamespace(snapshot=lambda: {'state': 'ok'}),
            morning_briefing=SimpleNamespace(
                generate_briefing=lambda: {'spoken_text': 'brief gotowy'}),
            system_doctor=SimpleNamespace(
                run_diagnostics=lambda **k: (self.doctor_calls.append(k),
                                             {'health_score': 93,
                                              'healed_actions': ['a', 'b']})[1]),
            storage_health=SimpleNamespace(
                inspect_storage=lambda **k: {'drives': [1, 2], 'warnings': []},
                prune_mcp_backups=lambda *a, **k: {'removed': 3}),
            episodic_memory=SimpleNamespace(remember_episode=self.remember),
            time=SimpleNamespace(time=lambda: 1234.5),
        )
        for name, fake in fakes.items():
            patcher = patch.object(automation_engine, name, fake)
            patcher.start()
            self.addCleanup(patcher.stop)

    def _publish(self, topic, payload):
        self.published.append((topic, payload))

    def save_jobs_direct(self, jobs):
        save_jobs(jobs)


class JobsStore(AEBase):
    def test_missing_garbage_and_non_list_return_empty(self):
        self.assertEqual(load_jobs(), [])
        self.jobs_file.parent.mkdir(parents=True, exist_ok=True)
        self.jobs_file.write_text('{"broken', encoding='utf-8')
        self.assertEqual(load_jobs(), [])
        self.jobs_file.write_text('{"not": "a list"}', encoding='utf-8')
        self.assertEqual(load_jobs(), [])

    def test_atomic_save_permissions_and_no_temp_residue(self):
        jobs = [{'id': 'x1', 'name': 'Jeden', 'schedule': 'daily 08:00',
                 'enabled': True, 'action_type': 'briefing',
                 'action_params': {}, 'deliver': 'local',
                 'last_run_at': 0.0, 'run_count': 0}]
        save_jobs(jobs)
        self.assertTrue(self.jobs_file.is_file())
        self.assertEqual(self.jobs_file.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.jobs_file.parent.stat().st_mode & 0o777, 0o700)
        # the atomic temp file is gone after replace
        self.assertEqual(list(self.jobs_file.parent.glob('.scheduled_jobs*tmp*')), [])
        self.assertEqual(load_jobs(), jobs)

    def test_sixty_job_cap_persisted(self):
        jobs = [{'id': f'x{i}', 'name': f'j{i}', 'schedule': 'daily 08:00'}
                for i in range(65)]
        save_jobs(jobs)
        self.assertEqual(len(load_jobs()), 60)


class CreateAndPresets(AEBase):
    def test_create_validation_matrix_and_no_write_on_error(self):
        with self.assertRaises(ValueError):
            create_automation('', 'daily 08:00')
        with self.assertRaises(ValueError):
            create_automation('Nazwa', '  ')
        with self.assertRaises(ValueError) as ctx:
            create_automation('Nazwa', 'daily 08:00', action_type='kaboom')
        self.assertIn('Nieobsługiwany typ akcji', str(ctx.exception))
        # invalid calls never touch the store
        self.assertFalse(self.jobs_file.exists())
        for action in ('briefing', 'doctor', 'storage_check', 'connector'):
            create_automation(f'ok-{action}', 'daily 08:00', action_type=action)
        self.assertTrue(self.jobs_file.is_file())

    def test_create_record_shape_and_normalisation(self):
        out = create_automation('  Mój digest  ', 'EVERY 15m', deliver='LOCAL')
        job = out['job']
        self.assertTrue(out['ok'])
        self.assertRegex(job['id'], re.compile(r'^auto-[0-9a-f]{8}$'))
        self.assertEqual(job['name'], 'Mój digest')
        self.assertEqual(job['schedule'], 'EVERY 15m')   # not lowercased; match-time is
        self.assertEqual(job['deliver'], 'local')       # normalised
        self.assertEqual(job['action_params'], {})
        self.assertTrue(job['enabled'])
        self.assertEqual(job['created_at'], 1234.5)      # patched clock
        self.assertEqual(job['last_run_at'], 0.0)
        self.assertEqual(job['run_count'], 0)
        self.assertEqual(job['last_status'], 'never')
        self.assertEqual(job['last_summary'], '')
        # newest first
        create_automation('Drugi', 'daily 08:00')
        self.assertEqual([j['name'] for j in load_jobs()], ['Drugi', 'Mój digest'])

    def test_create_clips_long_fields(self):
        out = create_automation('N' * 300, 's' * 200)
        self.assertEqual(len(out['job']['name']), 140)
        self.assertEqual(len(out['job']['schedule']), 64)

    def test_install_preset_unknown_duplicate_and_fresh(self):
        with self.assertRaises(ValueError):
            install_preset('nope')
        first = install_preset('morning_digest')
        self.assertNotIn('already_installed', first)
        self.assertEqual(first['job']['schedule'], 'daily 08:00')
        self.assertEqual(first['job']['action_type'], 'briefing')
        again = install_preset('morning_digest')
        self.assertTrue(again['already_installed'])
        self.assertEqual(again['job']['id'], first['job']['id'])
        self.assertEqual([j['name'] for j in load_jobs()], [first['job']['name']])


class DeliverSummary(AEBase):
    def test_local_and_unknown_channels_skip_connectors(self):
        self.assertEqual(automation_engine._deliver_summary('', 'T', 'S'), 'local_sse')
        self.assertEqual(automation_engine._deliver_summary('local', 'T', 'S'), 'local_sse')
        self.assertEqual(automation_engine._deliver_summary('wpm', 'T', 'S'), 'local_sse')
        self.assertEqual(self.exec_calls, [])

    def test_obsidian_and_push_text_shapes(self):
        self.assertEqual(automation_engine._deliver_summary('obsidian', 'Tytuł', 'Sumka'),
                         'obsidian')
        self.assertEqual(self.exec_calls[-1],
                         ('obsidian_daily_append', {'text': 'Tytuł — Sumka'}))
        self.assertEqual(automation_engine._deliver_summary('ntfy', 'T', 'S'), 'ntfy')
        self.assertEqual(self.exec_calls[-1],
                         ('ntfy_publish', {'text': '[Jarvis] T: S'}))
        self.assertEqual(automation_engine._deliver_summary('telegram', 'T', 'S'),
                         'telegram')
        self.assertEqual(automation_engine._deliver_summary('discord', 'T', 'S'),
                         'discord')
        self.assertEqual(automation_engine._deliver_summary('slack', 'T', 'S'), 'slack')

    def test_dnd_suppresses_push_but_not_obsidian(self):
        dnd = SimpleNamespace(dnd_status=lambda: {'active': True})
        with patch.object(automation_engine, 'wayland_voice', dnd):
            for channel in ('telegram', 'ntfy', 'slack', 'discord'):
                self.assertEqual(automation_engine._deliver_summary(channel, 'T', 'S'),
                                 'suppressed_dnd')
            # obsidian is a local vault append — deliberately exempt from DND
            self.assertEqual(automation_engine._deliver_summary('obsidian', 'T', 'S'),
                             'obsidian')
        self.assertEqual(len(self.exec_calls), 1)

    def test_connector_failure_returns_error_marker(self):
        with patch.object(automation_engine, 'connectors_hub',
                          SimpleNamespace(execute_connector_action=MagicMock(
                              side_effect=RuntimeError('boom')))):
            delivered = automation_engine._deliver_summary('telegram', 'T', 'S')
        self.assertEqual(delivered, 'delivery_error:boom')


class ExecuteJob(AEBase):
    def _job(self, **over):
        job = {'id': 'j1', 'name': 'Nazwa', 'action_type': 'briefing',
               'action_params': {}, 'deliver': 'local'}
        job.update(over)
        return job

    def test_briefing_summary_publish_and_envelope(self):
        out = execute_job(self._job(), self.tmp)
        self.assertEqual(out, {'ok': True, 'status': 'ok',
                               'summary': 'brief gotowy', 'delivered': 'local_sse'})
        self.assertEqual(self.published, [('automation.executed',
                                           {'job_id': 'j1', 'name': 'Nazwa',
                                            'summary': 'brief gotowy',
                                            'delivered': 'local_sse'})])

        with patch.object(automation_engine, 'morning_briefing',
                          SimpleNamespace(generate_briefing=lambda: {})):
            out = execute_job(self._job(), self.tmp)
        self.assertEqual(out['summary'], 'Wygenerowano briefing systemowy.')

    def test_doctor_autoheal_and_prune(self):
        out = execute_job(self._job(action_type='doctor',
                                    action_params={'auto_heal': False,
                                                   'prune_backups': True}),
                          self.tmp)
        self.assertEqual(out['summary'],
                         'Zdrowie systemu: 93/100 (naprawiono: 2, '
                         'usunięto 3 starych kopii .bak).')
        self.assertEqual(self.doctor_calls[-1], {'project_dir': self.tmp,
                                                 'auto_heal': False})
        execute_job(self._job(action_type='doctor'), self.tmp)
        self.assertEqual(self.doctor_calls[-1]['auto_heal'], True)  # default

    def test_storage_and_connector_and_unknown(self):
        out = execute_job(self._job(action_type='storage_check'), self.tmp)
        self.assertEqual(out['summary'], 'Sprawdzono 2 dysków · ostrzeżenia: 0.')

        big = {'blob': 'x' * 500}
        with patch.object(automation_engine, 'connectors_hub',
                          SimpleNamespace(execute_connector_action=lambda a, p: big)):
            out = execute_job(self._job(action_type='connector',
                                        action_params={'connector_action':
                                                       'gmail_inbox'}), self.tmp)
        # summary is the JSON dump clipped to 260 chars
        import json
        self.assertEqual(out['summary'], json.dumps(big, ensure_ascii=False)[:260])

        calls = []
        with patch.object(automation_engine, 'connectors_hub',
                          SimpleNamespace(execute_connector_action=lambda a, p:
                                          (calls.append((a, p)), big)[1])):
            execute_job(self._job(action_type='connector'), self.tmp)
        # default connector action when action_params lack one
        self.assertEqual(calls, [('weather_forecast', {})])

        out = execute_job(self._job(action_type='xyzzy'), self.tmp)
        self.assertEqual(out['summary'], 'Pominięto nieznany typ: xyzzy')
        self.assertTrue(out['ok'])   # still an "ok" outcome envelope

    def test_thermal_defers_but_bypasses_for_doctor(self):
        hot = SimpleNamespace(snapshot=lambda: {'state': 'critical'})
        with patch.object(automation_engine, 'hardware_guard', hot):
            out = execute_job(self._job(), self.tmp)
            self.assertEqual(out, {'ok': False, 'status': 'deferred_thermal',
                                   'summary': 'Wstrzymano z powodu wysokiej '
                                              'temperatury CPU/RAM.'})
            self.assertEqual(self.published, [])   # deferred: nothing published
            out = execute_job(self._job(action_type='doctor'), self.tmp)
            self.assertEqual(out['status'], 'ok')
            out = execute_job(self._job(action_type='storage_check'), self.tmp)
            self.assertEqual(out['status'], 'ok')


class RunAndTick(AEBase):
    def _seed(self, jobs):
        save_jobs(jobs)
        return jobs

    def test_run_job_by_id_updates_persist_and_missing(self):
        self._seed([{'id': 'j1', 'name': 'N', 'schedule': 'daily 08:00',
                     'enabled': True, 'action_type': 'briefing',
                     'action_params': {}, 'deliver': 'local',
                     'last_run_at': 0.0, 'run_count': 0}])
        out = run_job_by_id('j1', self.tmp)
        self.assertTrue(out['ok'])
        self.assertEqual(out['job']['last_run_at'], 1234.5)   # patched clock
        self.assertEqual(out['job']['run_count'], 1)
        self.assertEqual(out['job']['last_status'], 'ok')
        self.assertEqual(out['execution']['summary'], 'brief gotowy')
        persisted = load_jobs()[0]
        self.assertEqual(persisted['run_count'], 1)
        self.assertEqual(persisted['last_summary'], 'brief gotowy')
        with self.assertRaises(ValueError):
            run_job_by_id('nope', self.tmp)

    def test_tick_runs_only_due_jobs_and_uses_given_clock(self):
        self._seed([
            {'id': 'due', 'name': 'Due', 'schedule': 'every 30s', 'enabled': True,
             'action_type': 'briefing', 'action_params': {}, 'deliver': 'local',
             'last_run_at': 0.0, 'run_count': 3},
            {'id': 'idle', 'name': 'Idle', 'schedule': 'daily 23:59', 'enabled': True,
             'action_type': 'briefing', 'action_params': {}, 'deliver': 'local',
             'last_run_at': 0.0, 'run_count': 0},
        ])
        out = tick_due_jobs(self.tmp, now_ts=99999.0)
        self.assertEqual(out['executed_count'], 1)
        self.assertEqual(out['executed'],
                         [{'id': 'due', 'name': 'Due', 'status': 'ok'}])
        by_id = {j['id']: j for j in load_jobs()}
        self.assertEqual(by_id['due']['last_run_at'], 99999.0)  # exact tick clock
        self.assertEqual(by_id['due']['run_count'], 4)
        self.assertNotIn('idle', [e['id'] for e in out['executed']])

    def test_tick_swallows_execution_errors_and_records_them(self):
        self._seed([{'id': 'boom', 'name': 'Boom', 'schedule': 'every 30s',
                     'enabled': True, 'action_type': 'briefing',
                     'action_params': {}, 'deliver': 'local',
                     'last_run_at': 0.0, 'run_count': 0}])
        with patch.object(automation_engine, 'morning_briefing',
                          SimpleNamespace(generate_briefing=MagicMock(
                              side_effect=RuntimeError('kaputt')))):
            out = tick_due_jobs(self.tmp, now_ts=5000.0)
        self.assertEqual(out['executed'],
                         [{'id': 'boom', 'name': 'Boom', 'status': 'error'}])
        job = load_jobs()[0]
        self.assertEqual(job['last_status'], 'error')
        self.assertEqual(job['last_summary'], 'kaputt')
        self.assertEqual(job['run_count'], 1)   # error still counts as an attempt

    def test_tick_without_due_jobs_writes_nothing(self):
        self._seed([{'id': 'idle', 'name': 'Idle', 'schedule': 'daily 23:59',
                     'enabled': True, 'action_type': 'briefing',
                     'action_params': {}, 'deliver': 'local',
                     'last_run_at': 0.0, 'run_count': 0}])
        with patch.object(automation_engine, 'save_jobs',
                          wraps=save_jobs) as save_mock:
            out = tick_due_jobs(self.tmp, now_ts=1000.0)
        self.assertEqual(out, {'ok': True, 'executed_count': 0, 'executed': []})
        save_mock.assert_not_called()


class RulesStatusDaemon(AEBase):
    def test_reactive_rules_subscribe_once_and_listener_contract(self):
        with patch.object(automation_engine, '_RULES_INSTALLED', False):
            install_reactive_event_rules()
            install_reactive_event_rules()
        self.subscribe.assert_called_once()
        topic, listener = self.subscribe.call_args[0]
        self.assertEqual(topic, 'hardware.alert')

        listener({'data': {'state': 'critical', 'peak_temp_c': 95,
                           'mem_available_mb': 120,
                           'reasons': ['CPU gorąca', 'RAM']}})
        # the episode is recorded through keyword arguments only
        kwargs = self.remember.call_args.kwargs
        self.assertEqual(kwargs['title'], 'Alert sprzętowy: 95°C / RAM 120 MB')
        self.assertEqual(kwargs['summary'], 'CPU gorąca, RAM')
        self.assertEqual(kwargs['kind'], 'incident')
        self.assertEqual(kwargs['tags'], ['hardware', 'auto_rule'])

        self.remember.reset_mock()
        listener({'data': {'state': 'warn'}})
        self.remember.assert_not_called()   # only critical is recorded

        listener({'payload': {'state': 'critical', 'reasons': []}})   # payload key
        self.assertIn('Przekroczono próg krytyczny',
                      self.remember.call_args.kwargs['summary'])

        self.remember.side_effect = RuntimeError('store down')
        listener({'data': {'state': 'critical'}})   # swallowed, no raise

    def test_automation_status_counts_caps_and_presets(self):
        save_jobs([{'id': f'x{i}', 'name': f'j{i}', 'schedule': 'daily 08:00',
                     'enabled': i != 3, 'action_type': 'briefing',
                     'action_params': {}, 'deliver': 'local',
                     'last_run_at': 0.0, 'run_count': 0} for i in range(65)])
        with patch.object(automation_engine, '_RULES_INSTALLED', False):
            status = automation_status()
        self.assertEqual(status['total_jobs'], 60)      # store already capped
        self.assertEqual(status['enabled_jobs'], 59)    # one disabled survived
        self.assertEqual(len(status['jobs']), 25)       # status caps at 25
        self.assertEqual([p['id'] for p in status['presets']],
                         ['morning_digest', 'nightly_doctor', 'storage_watch'])
        self.assertEqual(status['presets'][0]['schedule'], 'daily 08:00')
        self.assertFalse(status['reactive_rules_active'])

    def test_daemon_starts_one_thread_and_is_idempotent(self):
        thread = MagicMock()
        with patch.object(automation_engine, '_DAEMON_STARTED', False), \
                patch.object(automation_engine, 'threading',
                             SimpleNamespace(Thread=thread)):
            start_automation_daemon(self.tmp, poll_seconds=5)
            start_automation_daemon(self.tmp)
        thread.assert_called_once()
        kwargs = thread.call_args.kwargs
        self.assertEqual(kwargs['name'], 'jarvis-automation-daemon')
        self.assertTrue(kwargs['daemon'])
        self.assertTrue(callable(kwargs['target']))
        thread.return_value.start.assert_called_once()


if __name__ == '__main__':
    unittest.main()
