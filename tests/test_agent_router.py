"""agent_router: circuit breakers, budget-aware ranking and team selection.

The router reads its whole world through `agent_cli` (agent registry, run
history, busy state, state ROOT), `budget_guard` and `event_bus` (imported inside
functions), so everything is faked per test and each test gets a fresh sandbox
ROOT — probes showed state, budget and clock contamination produce silently
wrong scores otherwise. Pinned: role inference keyword order, circuit-breaker
cooldowns and clamps, the prior/empirical blend `(prior*4 + emp*n) / (4+n)`
with speed bonus, all budget shifts and penalties (soft cap ±, hard cap block,
architect exemption, override), eligibility gates and the final sort, pick_best
fallbacks, select_team roster dedup and the summary telemetry shape.
"""
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import agent_router
from agent_router import (
    DEFAULT_COOLDOWN_SECONDS,
    ECONOMY_AGENTS,
    METERED_PREMIUM_AGENTS,
    active_circuits,
    clear_circuit,
    infer_role,
    pick_best_agent,
    rank_agents,
    record_run_outcome,
    router_summary,
    select_team,
    trip_circuit,
)

FAKE_IDS = {'antigravity', 'claude', 'hermes', 'klorek', 'opencode'}


class RouterBase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.root = self.tmp / 'agents'
        self.state_file = self.root / 'router_state.json'
        self.published = []
        self.budget = {'state': 'healthy', 'utilization_ratio': 0.0}
        self.clock = [1000.0]
        self.AgentError = type('AgentError', (Exception,), {})
        self.runs_map = {}
        self.binaries = {}
        self.busy = {}

        self.event_bus = SimpleNamespace(
            publish=lambda topic, payload: self.published.append((topic, payload)))
        self.budget_guard = SimpleNamespace(status=lambda: dict(self.budget))
        modules = {'event_bus': self.event_bus, 'budget_guard': self.budget_guard}
        self._sys_patch = patch.dict(sys.modules, modules)
        self._sys_patch.start()
        self.addCleanup(self._sys_patch.stop)
        self._open()

    def _agent_cli(self):
        def agent(aid):
            if aid not in FAKE_IDS:
                raise self.AgentError(f'Unknown agent {aid!r}.')
            return {'binary': aid}
        return SimpleNamespace(
            ROOT=self.root,
            AgentError=self.AgentError,
            agent_ids=lambda: sorted(FAKE_IDS),
            _agent=agent,
            binary_present=lambda aid: self.binaries.get(aid, True),
            _check_running=lambda aid: (self.busy.get(aid, False), {}),
            runs=lambda aid: self.runs_map.get(aid, []),
        )

    def _open(self):
        self._patches = [
            patch.object(agent_router, 'agent_cli', self._agent_cli()),
            patch.object(agent_router.time, 'time', lambda: self.clock[0]),
        ]
        for p in self._patches:
            p.start()
            self.addCleanup(p.stop)

    def row_for(self, rows, agent):
        return next(r for r in rows if r['agent'] == agent)

    def score_of(self, agent, **kwargs):
        return self.row_for(rank_agents(**kwargs), agent)['score']


class StateStore(RouterBase):
    def test_corrupt_and_non_dict_state_tolerated(self):
        self.state_file.parent.mkdir(parents=True, exist_ok=True)
        self.state_file.write_text('{oops', encoding='utf-8')
        self.assertEqual(active_circuits(), {})
        self.state_file.write_text('["list"]', encoding='utf-8')
        self.assertEqual(active_circuits(), {})
        # a trip right after a corrupted state heals the file
        entry = trip_circuit('claude', 'quota_exceeded')
        self.assertEqual(json.loads(self.state_file.read_text())['circuits']['claude'],
                         entry)
        self.assertEqual(self.state_file.stat().st_mode & 0o777, 0o600)
        self.assertEqual((self.root / '.router.lock').stat().st_mode & 0o777, 0o600)


class InferRole(RouterBase):
    def test_keyword_matrix_and_priority(self):
        for task, role in (('dodaj styl css w przycisku', 'frontend'),
                           ('napraw traceback w viewer', 'frontend'),   # frontend beats repair
                           ('napisz test regresj unittest', 'qa'),
                           ('zaprojektuj strukturę kontraktu', 'architect'),
                           ('napraw crash wyjątku', 'repair'),
                           ('openapi endpoint i sqlite', 'backend'),
                           ('zwykłe zadanie bez słów kluczowych', 'general')):
            with self.subTest(task=task):
                self.assertEqual(infer_role(task), role)

    def test_non_string_and_defaults(self):
        self.assertEqual(infer_role(''), 'general')
        self.assertEqual(infer_role(None), 'general')
        self.assertEqual(infer_role(12345), 'general')


class CircuitBreakers(RouterBase):
    def test_trip_clamps_and_entry_shape(self):
        entry = trip_circuit('claude', 'quota_exceeded', error_hint='HTTP 429')
        self.assertEqual(entry, {'agent': 'claude', 'error_kind': 'quota_exceeded',
                                 'error_hint': 'HTTP 429',
                                 'tripped_at': 1000.0, 'until': 1900.0})   # 900 s cooldown
        # explicit cooldown wins, but is clamped into [10, 7200]
        self.assertEqual(trip_circuit('claude', 'quota_exceeded',
                                       cooldown_seconds=5)['until'], 1010.0)
        self.assertEqual(trip_circuit('claude', 'quota_exceeded',
                                       cooldown_seconds=99999)['until'], 8200.0)
        self.assertEqual(trip_circuit('claude', 'quota_exceeded',
                                     cooldown_seconds=0)['until'], 1010.0)   # falsy -> clamp
        # unknown error kinds fall back to 300 s
        self.assertEqual(trip_circuit('hermes', 'cosik')['until'], 1300.0)
        # hints are clipped to 240 chars
        self.assertEqual(len(trip_circuit('hermes', 'auth_failed',
                                          error_hint='h' * 300)['error_hint']), 240)
        self.assertEqual(list(DEFAULT_COOLDOWN_SECONDS),
                         ['quota_exceeded', 'auth_failed', 'model_rejected'])

    def test_trip_publishes_and_validates_agent(self):
        entry = trip_circuit('claude', 'auth_failed', error_hint='key expired')
        self.assertEqual(self.published,
                         [('router.circuit_tripped', entry)])
        with self.assertRaises(self.AgentError):
            trip_circuit('ghost', 'quota_exceeded')
        # the rejected trip did not touch the state: claude is still the only circuit
        self.assertEqual(list(active_circuits()), ['claude'])

    def test_clear_circuit_publishes_only_when_present(self):
        trip_circuit('claude', 'model_rejected')
        self.assertTrue(clear_circuit('claude'))
        self.assertEqual(self.published[-1], ('router.circuit_cleared', {'agent': 'claude'}))
        self.assertFalse(clear_circuit('claude'))
        self.assertEqual([t for t, _ in self.published].count('router.circuit_cleared'), 1)
        with self.assertRaises(self.AgentError):
            clear_circuit('ghost')

    def test_active_circuits_filter_expired_and_shape(self):
        trip_circuit('claude', 'model_rejected')           # until 1600
        trip_circuit('hermes', 'auth_failed')              # until 2800
        self.clock[0] = 1500.0
        active = active_circuits()
        self.assertEqual(sorted(active), ['claude', 'hermes'])
        self.assertEqual(active['claude']['remaining_seconds'], 100.0)
        self.clock[0] = 1700.0
        self.assertEqual(sorted(active_circuits()), ['hermes'])
        # malformed entries are skipped, not fatal (hermes kept alive in the rewrite)
        self.state_file.parent.mkdir(parents=True, exist_ok=True)
        self.state_file.write_text(json.dumps(
            {'circuits': {'claude': {'until': 99999.0, 'junk': True},
                          'hermes': {'agent': 'hermes', 'until': 99999.0},
                          'bad': 'not-a-dict', 'opaque': {}}}), encoding='utf-8')
        self.assertEqual(sorted(active_circuits()), ['claude', 'hermes'])

    def test_record_run_outcome_matrix(self):
        trip_circuit('claude', 'model_rejected')
        trip_circuit('hermes', 'auth_failed')
        record_run_outcome('claude', {'status': 'done'})     # done clears the circuit
        self.assertNotIn('claude', active_circuits())
        trip_circuit('claude', 'quota_exceeded')
        before = self.state_file.read_text()
        record_run_outcome('claude', {'status': 'failed', 'error_kind': 'zzz_unk'})
        record_run_outcome('claude', 'not-a-dict')
        record_run_outcome('claude', {'status': 'timeout'})   # no error kind -> no trip
        self.assertEqual(self.state_file.read_text(), before)
        record_run_outcome('hermes', {'status': 'failed', 'error_kind': 'model_rejected',
                                      'error_hint': 'o1 nieobsługiwany'})
        self.assertEqual(active_circuits()['hermes']['error_kind'], 'model_rejected')

    def test_trip_overwrites_previous_circuit(self):
        trip_circuit('claude', 'model_rejected')
        trip_circuit('claude', 'quota_exceeded')
        circuits = json.loads(self.state_file.read_text())['circuits']
        self.assertEqual(list(circuits), ['claude'])
        self.assertEqual(circuits['claude']['error_kind'], 'quota_exceeded')


class EmpiricalMetrics(RouterBase):
    def test_metrics_from_finished_runs(self):
        self.runs_map['hermes'] = [
            {'status': 'done', 'seconds': 100},
            {'status': 'failed'},
            {'status': 'planning', 'seconds': 999},   # not a finished status
            {'status': 'timeout', 'seconds': 200},
        ]
        metrics = agent_router._empirical_metrics('hermes')
        self.assertEqual(metrics, {'runs': 3, 'success_rate': round(1 / 3, 3),
                                   'avg_seconds': 150.0})

    def test_metrics_empty_and_history_cap(self):
        self.assertEqual(agent_router._empirical_metrics('claude'),
                         {'runs': 0, 'success_rate': None, 'avg_seconds': None})
        self.runs_map['claude'] = [{'status': 'done', 'seconds': 1}] * 30
        self.assertEqual(agent_router._empirical_metrics('claude')['runs'], 25)


class RankAgents(RouterBase):
    def test_base_scores_prior_default_and_empirical(self):
        self.assertEqual(self.score_of('claude', role='architect'), 0.93)   # 0.92 + speed 0.01
        # unlisted agent falls back to the 0.80 prior
        self.assertEqual(self.score_of('klorek', role='general'), 0.81)
        # empirical blend: (0.88*4 + 0.5*2) / 6 = 0.7533 + speed 0.0267
        self.runs_map['hermes'] = [{'status': 'done', 'seconds': 100},
                                  {'status': 'failed'}]
        row = self.score_of('hermes', role='backend')
        self.assertEqual(row, 0.78)
        ranked = rank_agents(role='backend')
        hermes_row = self.row_for(ranked, 'hermes')
        self.assertEqual(hermes_row['metrics']['runs'], 2)
        self.assertEqual(hermes_row['budget_state'], 'healthy')

    def test_sort_order_eligible_first(self):
        self.binaries = {'antigravity': False}
        self.busy = {'claude': True}
        ranked = rank_agents(role='general', require_idle=True)
        # eligible & installed first, then by score; missing binary sinks to the bottom
        self.assertTrue(all(r['eligible'] for r in ranked[:2]))
        self.assertEqual(ranked[-1]['agent'], 'antigravity')
        self.assertEqual(ranked[-1]['score'], -1.0)
        scores = [r['score'] for r in ranked[:2]]
        self.assertEqual(scores, sorted(scores, reverse=True))

    def test_budget_soft_cap_shifts_economy_up(self):
        self.budget['state'] = 'warning'
        self.assertEqual(self.score_of('claude', role='general'), 0.83)    # 0.91 - 0.08
        self.assertEqual(self.score_of('claude', role='architect'), 0.93)  # architect exempt
        self.assertEqual(self.score_of('opencode', role='general'), 0.89)  # 0.83 + 0.06
        rows = rank_agents(role='general')
        self.assertTrue(self.row_for(rows, 'claude')['eligible'])   # soft cap only nudges

    def test_budget_hard_cap_blocks_premium(self):
        self.budget['state'] = 'capped'
        row = self.row_for(rank_agents(role='general'), 'claude')
        self.assertTrue(row['budget_blocked'])
        self.assertFalse(row['eligible'])
        self.assertEqual(row['score'], 0.31)                       # 0.91 - 0.60
        self.assertEqual(self.score_of('opencode', role='general'), 0.91)   # 0.83 + 0.08
        # override restores the raw ranking
        self.assertEqual(self.score_of('claude', role='general',
                                        allow_budget_override=True), 0.91)

    def test_busy_and_idle_requirements(self):
        self.busy = {'claude': True}
        idle_row = self.row_for(rank_agents(role='general', require_idle=True), 'claude')
        self.assertFalse(idle_row['eligible'])
        self.assertEqual(idle_row['score'], 0.56)                  # 0.91 - 0.35
        relaxed_row = self.row_for(rank_agents(role='general'), 'claude')
        self.assertTrue(relaxed_row['eligible'])
        self.assertEqual(relaxed_row['score'], 0.91)               # no penalty when relaxed

    def test_quarantine_penalty_and_allowance(self):
        trip_circuit('hermes', 'quota_exceeded')
        row = self.row_for(rank_agents(role='general'), 'hermes')
        self.assertTrue(row['quarantined'])
        self.assertFalse(row['eligible'])
        self.assertEqual(row['score'], 0.37)                  # 0.87 - 0.50
        allowed = self.row_for(rank_agents(role='general', allow_quarantined=True),
                                'hermes')
        self.assertTrue(allowed['eligible'])
        self.assertEqual(allowed['score'], 0.37)              # penalty stays
        self.assertEqual(row['circuit']['error_kind'], 'quota_exceeded')

    def test_excluded_ids_never_ranked(self):
        # ' hermes ' with stray spaces is still excluded; rest ranked by score
        self.assertEqual([r['agent'] for r in rank_agents(exclude=('claude', ' hermes '))],
                         ['antigravity', 'opencode', 'klorek'])

    def test_agent_groups_constants(self):
        self.assertEqual(ECONOMY_AGENTS, {'opencode', 'hermes', 'antigravity'})
        self.assertEqual(METERED_PREMIUM_AGENTS, {'claude'})


class PickBest(RouterBase):
    def test_picks_the_top_eligible(self):
        # architect prior: claude 0.92 > antigravity 0.86 > hermes 0.82
        self.assertEqual(pick_best_agent(role='architect'), 'claude')
        self.assertEqual(pick_best_agent(role='architect', exclude={'claude'}),
                         'antigravity')

    def test_hard_cap_never_returns_premium(self):
        self.budget['state'] = 'capped'
        chosen = pick_best_agent(role='general')
        self.assertIn(chosen, ECONOMY_AGENTS)          # claude must never win under the cap
        self.assertEqual(chosen, 'hermes')            # 0.87 + 0.08 economy bonus

    def test_idle_required_and_quarantine_fallback(self):
        self.runs_map.clear()
        self.busy = {'claude': True, 'antigravity': True, 'opencode': True}
        self.assertEqual(pick_best_agent(role='general'), 'hermes')

        # all agents quarantined -> fallback returns the best quarantined one
        for aid in FAKE_IDS:
            trip_circuit(aid, 'quota_exceeded')
        chosen = pick_best_agent(role='general')
        self.assertIn(chosen, FAKE_IDS)

    def test_empty_when_nothing_usable(self):
        self.binaries = {aid: False for aid in FAKE_IDS}
        self.runs_map.clear()
        self.assertEqual(pick_best_agent(role='general'), '')
        # a quarantined but installed agent is still better than nothing
        self.binaries = {aid: False for aid in FAKE_IDS if aid != 'opencode'}
        trip_circuit('opencode', 'quota_exceeded')
        self.assertEqual(pick_best_agent(role='general'), 'opencode')


class TeamsAndSummary(RouterBase):
    def test_select_team_dedupes_and_respects_caps(self):
        team = select_team('zbuduj apkę web z testami', max_members=2)
        self.assertEqual([{'agent': 'claude', 'role': 'architect'},
                          {'agent': 'hermes', 'role': 'backend'}], team)
        # defaults and clamping: 0 -> 3 (falsy!), 9 -> 4
        team = select_team('goal', max_members=0)
        self.assertEqual(len(team), 3)
        team = select_team('goal', max_members=9)
        self.assertEqual(len(team), 4)
        # every agent picked at most once
        team = select_team('goal', max_members=4)
        agents = [entry['agent'] for entry in team]
        self.assertEqual(len(agents), len(set(agents)))

    def test_select_team_breaks_when_roster_exhausted(self):
        self.binaries = {aid: False for aid in FAKE_IDS if aid != 'claude'}
        self.runs_map.clear()
        team = select_team('goal', max_members=3)
        self.assertEqual(team, [{'agent': 'claude', 'role': 'architect'}])

    def test_router_summary_shape(self):
        trip_circuit('hermes', 'quota_exceeded', error_hint='429')
        summary = router_summary()
        self.assertEqual(sorted(summary), ['active_circuits', 'budget_state',
                                           'circuits', 'rankings'])
        self.assertEqual(summary['circuits'], summary['active_circuits'])
        self.assertEqual(sorted(summary['circuits']), ['hermes'])
        self.assertEqual(summary['budget_state'], 'healthy')
        self.assertEqual(sorted(summary['rankings']),
                         ['architect', 'backend', 'frontend', 'general', 'qa', 'repair'])
        for role, rows in summary['rankings'].items():
            self.assertTrue(rows)
            self.assertTrue(all(r['role'] == role for r in rows))


if __name__ == '__main__':
    unittest.main()
