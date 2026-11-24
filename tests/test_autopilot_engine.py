"""autopilot_engine: 7-stage spec-to-verification pipeline contracts.

The engine is a pure orchestrator — every subsystem it pulls is module-level
imported, so all of them are swapped with SimpleNamespace fakes per test (only
`py_compile` and the runs-file IO run real, on tmp trees). Pinned: the runs
store (limit clamps, 0600 atomic save, dedupe-to-front, cap 40), the Polish
SPEC.md rendering with its section gating, `_emit_stage` events, the full
dry-run happy path with exact stage names/statuses/details and publish topics,
all three preflight blockers (join order, force bypassing hardware/budget but
NEVER the read-only filesystem), the goal validation, subgraph seeding rules,
real py_compile failure semantics and the team dispatch contract.
"""
import json
import shutil
import sys
import tempfile
import unittest
import uuid
from pathlib import Path
from types import SimpleNamespace as NS
from unittest.mock import patch

import autopilot_engine as ap
from autopilot_engine import MAX_STORED_RUNS, list_runs, run_autopilot


class ApBase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.root = self.tmp / 'agents' / 'agent_cli.py'
        self.runs_file = self.tmp / 'agents' / 'autopilot_runs.json'
        self.proj = self.tmp / 'proj'
        self.proj.mkdir()

    def env(self, *, impacted=(), ascii_map='', hw='ok', storage_ok=True,
            hard_capped=False, viewer_exists=False, complexity='low', assignments=(),
            risks=(), blast_modules=('good.py',), selected_tests=(), sec_ok=True, sri_ok=True,
            viewer_qa_ok=True, caps=None):
        """Build the full fake-subsystem environment + patch it on the module."""
        caps = caps if caps is not None else {}
        good = self.proj / 'good.py'
        if impacted or True:
            good.write_text('x = 1\n', encoding='utf-8')

        def plan_goal(goal, project_dir=None):
            return {'complexity': complexity, 'est_total_usd': 0.42,
                    'max_parallel_agents': 2, 'budget_tier': 't2',
                    'thermal_state': 'nominal', 'assignments': list(assignments),
                    'impacted_files': list(impacted), 'risks': list(risks)}

        fakes = {
            'agent_cli': NS(ROOT=self.root),
            'knowledge_graph': NS(
                rebuild_code_graph=lambda root: caps.setdefault('rebuild', []) or {'total_nodes': 42},
                graph_summary=lambda: {'total_nodes': 7},
                query_subgraph=lambda stem, hops=2, limit_edges=18: (
                    caps.update(stem=stem, hops=hops, limit=limit_edges)
                    or {'ascii_map': ascii_map}),
                upsert_triple=lambda *a, **k: caps.setdefault('triple', (a, k))),
            'task_planner': NS(plan_goal=plan_goal),
            'hardware_guard': NS(snapshot=lambda: {'state': hw, 'reasons': ['r1', 'r2']}),
            'budget_guard': NS(status=lambda: {'state': 'ok', 'hard_capped': hard_capped}),
            'storage_health': NS(inspect_storage=lambda project_dir=None: {
                'ok': storage_ok, 'drives': ['/dev/sda1', '/dev/sdb1']}),
            'code_index': NS(validate_safe_project_dir=lambda d: Path(d).resolve(),
                             build_context_pack=lambda goal, root_dir=None: 'PACK-CONTENT'),
            'change_impact': NS(
                analyze_blast_radius=lambda root, changed_files=None: {
                    'affected_modules': list(blast_modules), 'selected_tests': list(selected_tests),
                    'blast_risk': 'medium'},
                sync_viewer_sri=lambda root, fix=True: {'ok': sri_ok, 'updated': 2}),
            'security_scanner': NS(scan_directory=lambda root, include_tests=False: {
                'ok': sec_ok, 'include_tests_seen': False}),
            'qa_gate': NS(audit_viewer=lambda root: {'ok': viewer_qa_ok}),
            'episodic_memory': NS(remember_episode=lambda **k: caps.setdefault('episode', k)),
            'event_bus': NS(publish=lambda topic, payload: caps.setdefault(
                'pubs', []).append((topic, payload)) or True),
        }
        stack = [patch.object(ap, name, fake) for name, fake in fakes.items()]
        stack += [patch.object(ap.time, 'time', lambda: 1000.0),
                  patch.object(uuid, 'uuid4', lambda: NS(hex='aabbccdd1234'))]
        for p in stack:
            p.start()
            self.addCleanup(p.stop)
        if viewer_exists:
            (self.proj / 'viewer').mkdir(exist_ok=True)
            (self.proj / 'viewer' / 'index.html').write_text('<html></html>', encoding='utf-8')
        return caps

    def stage(self, result, name):
        return next(s for s in result['stages'] if s['stage'] == name)


class RunsStore(ApBase):
    def test_list_runs_clamps_and_tolerates_corruption(self):
        self.runs_file.parent.mkdir(parents=True, exist_ok=True)
        self.runs_file.write_text(json.dumps(
            [{'run_id': f'ap-{i}'} for i in range(50)]), encoding='utf-8')
        with patch.object(ap, 'agent_cli', NS(ROOT=self.root)):
            self.assertEqual(len(list_runs()), 12)          # default limit
            self.assertEqual([r['run_id'] for r in list_runs(limit=5)],
                             ['ap-0', 'ap-1', 'ap-2', 'ap-3', 'ap-4'])
            self.assertEqual(len(list_runs(limit=0)), 1)    # clamp max(1, 0)
            self.assertEqual(len(list_runs(limit=-9)), 1)
            self.runs_file.write_text('corrupt{', encoding='utf-8')
            self.assertEqual(list_runs(), [])
            self.runs_file.write_text('"just a string"', encoding='utf-8')
            self.assertEqual(list_runs(), [])
            self.runs_file.write_text('["a", 2]', encoding='utf-8')
            self.assertEqual(list_runs(), ['a', 2])        # list passthrough, no dict filter

    def test_save_run_dedupe_cap_and_permissions(self):
        self.assertEqual(MAX_STORED_RUNS, 40)
        with patch.object(ap, 'agent_cli', NS(ROOT=self.root)):
            for i in range(45):
                ap._save_run({'run_id': f'ap-{i}', 'k': i})
            data = json.loads(self.runs_file.read_text())
            self.assertEqual(len(data), 40)                     # capped
            self.assertEqual(data[0]['run_id'], 'ap-44')        # newest first
            ap._save_run({'run_id': 'ap-0', 'k': 'REPLACED'})
            data = json.loads(self.runs_file.read_text())
            ids = [d['run_id'] for d in data]
            self.assertEqual(ids.count('ap-0'), 1)              # deduped
            self.assertEqual(data[0]['k'], 'REPLACED')          # and moved to the front
            self.assertEqual(self.runs_file.stat().st_mode & 0o777, 0o600)
            leftovers = [p.name for p in self.runs_file.parent.iterdir()
                         if p.name.startswith('.autopilot')]
            self.assertEqual(leftovers, [])                     # atomic replace, no temp files


class SpecMarkdown(ApBase):
    PLAN = {'complexity': 'high', 'est_total_usd': 0.42, 'max_parallel_agents': 2,
            'budget_tier': 't2', 'thermal_state': 'nominal',
            'assignments': [{'role': 'backend', 'agent': 'hermes',
                             'paths': ['a.py', 'b.py']}],
            'impacted_files': [], 'risks': ['ryzyko alfa']}

    def test_full_render_with_cortex_and_risks(self):
        spec = ap._render_spec_markdown('zrób coś fajnego', self.PLAN,
                                        {'ascii_map': '[a]-->[b] ascii-line'})
        self.assertEqual(spec.splitlines(), [
            '# Specyfikacja Autopilota: zrób coś fajnego',
            '',
            '- **Złożoność:** `high` · **Szacowany koszt:** `$0.42` · **Równoległość:** `2`',
            '- **Poziom budżetu:** `t2` · **Stan termiczny:** `nominal`',
            '',
            '## 1. Rozłączne strumienie prac (brak konfliktów zapisu)',
            '- **`[BACKEND]`** silnikiem `hermes` -> `a.py`, `b.py`',
            '',
            '## 2. Kontekst z grafu architektury Cortex',
            '```text',
            '[a]-->[b] ascii-line',
            '```',
            '',
            '## 3. Niezmienniki i ryzyka architektoniczne',
            '- ryzyko alfa',
            '',
            '## 4. Kryteria akceptacji (Bramka Deterministyczna)',
            '- `py_compile` bez błędów składni dla wszystkich dotkniętych modułów `.py`.',
            '- `security_scanner`: `0` wycieków sekretów API oraz wywołań `shell=True` / `eval`.',
            '- `sync_viewer_sri` + `qa_gate`: aktualne sumy `sha384` i brak `.innerHTML` w `viewer/`.',
        ])

    def test_sections_gate_on_missing_data(self):
        spec = ap._render_spec_markdown('cel', {**self.PLAN, 'risks': []},
                                        {'ascii_map': ''})
        self.assertNotIn('Kontekst z grafu', spec)
        self.assertNotIn('Niezmienniki', spec)
        self.assertIn('Kryteria akceptacji', spec)      # section 4 always present
        self.assertIn('`$0.42`', spec)


class StageEvents(ApBase):
    def test_emit_stage_shape_and_publish(self):
        pubs = []
        with patch.object(ap, 'event_bus', NS(publish=lambda t, p: pubs.append((t, p)))), \
                patch.object(ap.time, 'time', lambda: 987.654321):
            entry = ap._emit_stage('ap-1', 'SPEC_AND_GRAPH', 'ok', 'detail tekstu')
        self.assertEqual(entry, {'stage': 'SPEC_AND_GRAPH', 'status': 'ok',
                                 'detail': 'detail tekstu', 'ts': 987.654})
        self.assertEqual(pubs, [('autopilot.stage', {'run_id': 'ap-1', **entry})])
        with patch.object(ap, 'event_bus', NS(publish=lambda t, p: pubs.append((t, p)))):
            self.assertEqual(ap._emit_stage('ap-1', 'X', 'ok').get('detail'), '')


class HappyDryRun(ApBase):
    def test_full_contract_stages_publishes_and_persistence(self):
        caps = self.env(assignments=[{'role': 'backend', 'agent': 'hermes',
                                      'paths': ['a.py', 'b.py']}],
                        impacted=['good.py'], ascii_map='[a]-->[b] ascii-line',
                        selected_tests=['test_x.py', 'test_y.py'])
        result = run_autopilot('zrób coś fajnego', self.proj)
        self.assertEqual(sorted(result), ['blast_radius', 'finished_at', 'gates', 'goal',
                                          'mode', 'ok', 'plan', 'run_id', 'spec_markdown',
                                          'stages', 'started_at', 'status', 'team'])
        self.assertTrue(result['ok'])
        self.assertEqual(result['run_id'], 'ap-1000-aabbcc')
        self.assertEqual((result['status'], result['mode'], result['team']),
                         ('completed', 'blueprint_and_verify', None))
        self.assertEqual([(s['stage'], s['status']) for s in result['stages']], [
            ('SPEC_AND_GRAPH', 'ok'), ('PREFLIGHT_GUARD', 'ok'),
            ('CONTEXT_BLUEPRINT', 'ok'), ('DISPATCH_EXECUTION', 'dry_run'),
            ('BLAST_RADIUS_VERIFY', 'ok'), ('SECURITY_AND_SRI', 'ok'),
            ('MEMORY_COMMIT', 'ok')])
        self.assertEqual(self.stage(result, 'SPEC_AND_GRAPH')['detail'],
                         'Węzły Cortex: 42 · strumienie: 1')
        self.assertEqual(self.stage(result, 'PREFLIGHT_GUARD')['detail'],
                         'Sprzęt: ok · Budżet: ok · Dyski: 2')
        self.assertEqual(self.stage(result, 'CONTEXT_BLUEPRINT')['detail'],
                         'Zbudowano pakiet kontekstowy (66 znaków).')
        pack = 'PACK-CONTENT\n### Topologia Cortex\n```text\n[a]-->[b] ascii-line\n```'
        self.assertEqual(len(pack), 66)
        self.assertEqual(self.stage(result, 'BLAST_RADIUS_VERIFY')['detail'],
                         'py_compile: 1 modułów · testy celowane: 2')   # real py_compile
        self.assertEqual(self.stage(result, 'SECURITY_AND_SRI')['detail'],
                         'Sekrety/AST: OK · SRI: OK · QA UI: OK')       # no viewer -> not audited
        self.assertEqual(self.stage(result, 'MEMORY_COMMIT')['detail'],
                         'Zapisano przebieg w pamięci epizodycznej i grafie Cortex.')
        self.assertEqual(result['gates'], {'compile_errors': [], 'security_ok': True,
                                          'sri_ok': True, 'sri_updated': 2,
                                          'viewer_qa_ok': True})
        self.assertEqual(result['blast_radius'], {'affected_modules': ['good.py'],
                                                  'selected_tests': ['test_x.py', 'test_y.py'],
                                                  'blast_risk': 'medium'})
        pubs = [t for t, _ in caps['pubs']]
        self.assertEqual(pubs, ['autopilot.stage'] * 7 + ['autopilot.completed'])
        self.assertEqual(caps['pubs'][-1][1], {'run_id': 'ap-1000-aabbcc', 'ok': True,
                                               'goal': 'zrób coś fajnego'})
        saved = json.loads(self.runs_file.read_text())
        self.assertEqual(saved[0]['run_id'], 'ap-1000-aabbcc')
        self.assertEqual(saved[0]['status'], 'completed')

    def test_memory_commit_details(self):
        caps = self.env(impacted=['good.py'], complexity='high',
                        selected_tests=['t1', 't2', 't3', 't4', 't5'])
        run_autopilot('cel', self.proj)
        episode = caps['episode']
        self.assertEqual(episode['title'], 'Autopilot [ap-1000-aabbcc]: cel')
        self.assertEqual(episode['kind'], 'architecture')
        self.assertEqual(episode['tags'], ['autopilot', 'high'])
        self.assertEqual(episode['project_id'], '')
        # only first 4 targeted tests land in the summary
        self.assertEqual(episode['summary'],
                         'Złożoność high, strumienie: 0, testy celowane: '
                         't1, t2, t3, t4, bramka=OK.')
        triple, kwargs = caps['triple']
        self.assertEqual(triple, ('autopilot:ap-1000-aabbcc', 'verified_goal', 'cel'))
        self.assertEqual(kwargs, {'subj_kind': 'autopilot_run', 'obj_kind': 'goal',
                                 'source': 'autopilot'})


class PreflightBlockers(ApBase):
    def test_goal_must_be_non_empty(self):
        self.env()
        for bad in ('', '   ', None):
            with self.subTest(goal=bad):
                with self.assertRaises(ValueError) as ctx:
                    run_autopilot(bad, self.proj)
                self.assertEqual(str(ctx.exception),
                                 'Cel Autopilota (goal) nie może być pusty.')

    def test_three_blockers_join_in_fixed_order(self):
        self.env(hw='critical', hard_capped=True, storage_ok=False)
        result = run_autopilot('cel', self.proj, execute_team=True)
        self.assertEqual(result['status'], 'blocked_preflight')
        self.assertEqual(sorted(result), ['finished_at', 'goal', 'ok', 'plan',
                                         'run_id', 'spec_markdown', 'stages',
                                         'started_at', 'status'])
        pf = self.stage(result, 'PREFLIGHT_GUARD')
        self.assertEqual((pf['status'], pf['detail']), (
            'blocked',
            'Wykryto system plików w trybie tylko do odczytu (ro).; '
            'Krytyczny stan sprzętowy: r1, r2.; '
            'Wyczerpano dzienny/miesięczny budżet chmurowy.'))
        self.assertEqual(len(result['stages']), 2)      # nothing after PREFLIGHT runs
        saved = json.loads(self.runs_file.read_text())
        self.assertEqual(saved[0]['status'], 'blocked_preflight')

    def test_force_bypasses_hardware_and_budget_but_never_ro_storage(self):
        self.runs_file.unlink(missing_ok=True)
        self.env(hw='critical', hard_capped=True, ascii_map='ASCIIMAP')
        # force reopens hw/budget gates, so the run reaches team dispatch:
        # the fake team must be in place or the real agent_team would launch
        team_proj = self.tmp / 'teamroot'
        team_calls = []

        def fake_team():
            def start(**kwargs):
                team_calls.append(kwargs)
                return {'id': 'wave-77', 'ok': True}

            def project_root(team_id):
                path = team_proj / team_id
                path.mkdir(parents=True, exist_ok=True)
                return path

            return NS(start_team_project=start, project_root=project_root)

        with patch.dict(sys.modules, {'agent_team': fake_team()}):
            result = run_autopilot('cel', self.proj, execute_team=True, force=True)
        self.assertEqual(result['status'], 'completed')     # force reopens the gates
        self.assertEqual(len(result['stages']), 7)
        self.assertEqual(len(team_calls), 1)               # dispatch reached the fake team
        self.assertIsNotNone(result['team'])

        self.runs_file.unlink(missing_ok=True)
        self.env(storage_ok=False)
        blocked = run_autopilot('cel', self.proj, force=True)
        self.assertEqual(blocked['status'], 'blocked_preflight')
        self.assertIn('tylko do odczytu', self.stage(blocked, 'PREFLIGHT_GUARD')['detail'])

    def test_rebuild_graph_false_uses_summary(self):
        caps = self.env()
        result = run_autopilot('cel', self.proj, rebuild_graph=False)
        self.assertNotIn('rebuild', caps)               # rebuild_code_graph never called
        self.assertEqual(self.stage(result, 'SPEC_AND_GRAPH')['detail'],
                         'Węzły Cortex: 7 · strumienie: 0')   # graph_summary() number


class SeedingAndBlast(ApBase):
    def test_subgraph_seed_stem_rules(self):
        caps = self.env(impacted=['src/deep/thing.py'])
        run_autopilot('cel', self.proj)
        self.assertEqual((caps['stem'], caps['hops'], caps['limit']), ('thing', 2, 18))
        caps2 = self.env(impacted=[])
        run_autopilot('moduł/stack/plik.py w celu', self.proj)
        self.assertEqual(caps2['stem'], 'plik')          # first goal word, Path().stem

    def test_real_syntax_error_flunks_gates_without_abort(self):
        (self.proj / 'bad.py').write_text('def broken(:\n', encoding='utf-8')
        caps = self.env(impacted=['bad.py'], blast_modules=['bad.py', 'note.txt'],
                        viewer_exists=True, viewer_qa_ok=False)
        result = run_autopilot('cel', self.proj)
        self.assertFalse(result['ok'])
        self.assertEqual(result['status'], 'completed_with_warnings')
        errors = result['gates']['compile_errors']
        self.assertEqual(len(errors), 1)                # note.txt skipped: not .py
        self.assertTrue(errors[0].startswith('bad.py:'))
        self.assertIn('SyntaxError', errors[0])
        stage5 = self.stage(result, 'BLAST_RADIUS_VERIFY')
        self.assertEqual((stage5['status'], stage5['detail']),
                        ('failed', 'py_compile: 1 modułów · testy celowane: 0'))
        stage6 = self.stage(result, 'SECURITY_AND_SRI')
        self.assertEqual((stage6['status'], stage6['detail']),
                        ('failed', 'Sekrety/AST: OK · SRI: OK · QA UI: BŁĄD'))
        self.assertEqual(result['gates']['viewer_qa_ok'], False)
        self.assertIn('bramka=UWAGI', caps['episode']['summary'])


class TeamDispatch(ApBase):
    def test_execute_team_contract(self):
        caps = self.env(ascii_map='ASCIIMAP', complexity='high',
                        assignments=[{'role': 'qa', 'agent': 'klorek', 'paths': []}])
        team_proj = self.tmp / 'teamroot'
        team_calls = []

        def fake_team():
            def start(**kwargs):
                team_calls.append(kwargs)
                return {'id': 'wave-77', 'ok': True}

            def project_root(team_id):
                path = team_proj / team_id
                path.mkdir(parents=True, exist_ok=True)
                return path

            return NS(start_team_project=start, project_root=project_root)

        with patch.dict(sys.modules, {'agent_team': fake_team()}):
            result = run_autopilot('cel zespołowy', self.proj, execute_team=True)
        self.assertEqual(result['mode'], 'team_execution')
        self.assertEqual(result['team'], {'id': 'wave-77', 'ok': True})
        self.assertEqual(team_calls, [{'goal': 'cel zespołowy',
                                       'assignments': [{'role': 'qa', 'agent': 'klorek',
                                                        'paths': []}],
                                       'seed_dir': str(self.proj.resolve()),
                                       'approved': True, 'consent': 'autopilot'}])
        spec_file = team_proj / 'wave-77' / 'AUTOPILOT_SPEC.md'
        self.assertEqual(spec_file.read_text(), result['spec_markdown'])
        self.assertEqual(caps['episode']['project_id'], 'wave-77')
        dispatch = self.stage(result, 'DISPATCH_EXECUTION')
        self.assertEqual((dispatch['status'], dispatch['detail']),
                         ('ok', 'Uruchomiono zespół wave-77.'))
        context = self.stage(result, 'CONTEXT_BLUEPRINT')
        pack = 'PACK-CONTENT\n### Topologia Cortex\n```text\nASCIIMAP\n```'
        self.assertEqual(len(pack), 54)
        self.assertEqual(context['detail'], 'Zbudowano pakiet kontekstowy (54 znaków).')

    def test_team_flow_blocked_by_budget_never_starts_a_team(self):
        self.env(hard_capped=True)
        team_calls = []
        with patch.dict(sys.modules, {'agent_team': NS(
                start_team_project=lambda **k: team_calls.append(k))}):
            result = run_autopilot('cel', self.proj, execute_team=True)
        self.assertEqual(result['status'], 'blocked_preflight')
        self.assertEqual(team_calls, [])
        self.assertIn('budżet chmurowy', self.stage(result, 'PREFLIGHT_GUARD')['detail'])


if __name__ == '__main__':
    unittest.main()
