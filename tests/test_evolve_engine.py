"""evolve_engine: MAP-Elites grid, evolve blocks, cascade, mutants, adversarial
drafts, skill distillation and prompt harness contracts.

The engine grew from `evolution` — every subsystem it touches lives behind the
module-level `evolution` attribute, so each test swaps it with a SimpleNamespace
harness (tmp STATE, json helpers, fake Scorecard/Archive/PromptLab/Failures);
`subprocess.run` and the clock are patched too. Real parts: pure AST units and
the tmp-tree JSON stores. Includes regressions for two hardening fixes made in
this iteration: compute_code_metrics(None) used to raise TypeError (the coerced
string now feeds ast.parse), and non-dict module entries in map_elites.json
used to crash elites()/summary(). Pinned: metric bins and exact node counts,
speed-bin boundaries, evolve-block extraction/skeleton verification, the
crossover prompt shape, insert/migrate/elites/inspirations semantics, mutant
generation and kill-rate flow, the cascade stage machine with blended scores,
adversarial fallback probes and promotion, distilled skill files and the
self-harness prompt rewrite with rollback.
"""
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace as NS
from unittest.mock import patch

import evolve_engine as ev
from evolve_engine import (
    MapElitesGrid,
    MutationTester,
    classify_speed_bin,
    compute_code_metrics,
)

SOLVE_SRC = '''def solve(x):
    # komentarz
    if x > 0:
        total = 0
        for i in range(10):
            total += i
        while total > 3:
            total -= 1
    return total + x
'''

TINY_SRC = 'def f():\n    return 1\n'
BIGGISH_SRC = 'def f():\n' + '\n'.join(f'    v{i} = {i}' for i in range(30)) + '\n    return 1\n'


class EvolveBase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.state = self.tmp / 'state'
        self.EvolutionError = type('EvE', (Exception,), {})

    @staticmethod
    def read_json(path, default):
        try:
            return json.loads(Path(path).read_text(encoding='utf-8'))
        except Exception:
            return default

    @staticmethod
    def write_json(path, data):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding='utf-8')

    def fake_evolution(self, **overrides):
        score = NS(bench_cases=lambda module: [], run_cases=lambda p, c: {
            'ok': len(c), 'total': len(c), 'results': []}, unittests=lambda m: {})
        fake = NS(
            STATE=self.state, ROOT=self.tmp, BENCH=self.tmp / 'bench',
            _read_json=self.read_json, _write_json=self.write_json,
            Scorecard=score, EvolutionError=self.EvolutionError,
            sandbox_refusal=lambda: '', sandbox_argv=lambda argv, **k: argv,
            _bench_environment=lambda: {},
            PROMPT_DEFAULTS={'patcher': 'BASE-PROMPT\n', 'codeditor': 'CE'},
            Failures=lambda: NS(rows=lambda: [], for_module=lambda m, limit=5: []),
            Archive=lambda: NS(rows=lambda: [], source_of=lambda nid: None),
            PromptLab=lambda: NS(get=lambda k: 'CUSTOM', set=lambda k, v: None,
                                 reset=lambda k: None),
            Bench=NS(seal=lambda: None), Curriculum=NS(invalidate=lambda: None),
        )
        for key, value in overrides.items():
            setattr(fake, key, value)
        stack = [patch.object(ev, 'evolution', fake),
                 patch.object(ev.time, 'time', lambda: 100.0)]
        for p in stack:
            p.start()
            self.addCleanup(p.stop)
        return fake


class CodeMetrics(EvolveBase):
    def test_exact_metrics_and_bins(self):
        self.assertEqual(compute_code_metrics(SOLVE_SRC), {
            'valid_ast': True, 'sloc': 8, 'ast_nodes': 45, 'branches': 3,
            'simplicity_bin': 'compact'})
        self.assertEqual(compute_code_metrics(''),
                         {'valid_ast': True, 'sloc': 0, 'ast_nodes': 1,
                          'branches': 0, 'simplicity_bin': 'compact'})

    def test_syntax_error_and_none_regression(self):
        bad = compute_code_metrics('def broken(:')
        self.assertEqual(bad, {'valid_ast': False, 'sloc': 1, 'ast_nodes': 99999,
                               'branches': 999, 'simplicity_bin': 'rich'})
        # regression: None used to raise TypeError (raw None reached ast.parse)
        self.assertEqual(compute_code_metrics(None), compute_code_metrics(''))

    def test_bin_thresholds(self):
        wide = '\n'.join(f'v{i} = {i}' for i in range(200))
        self.assertEqual(compute_code_metrics(wide)['ast_nodes'], 801)
        self.assertEqual(compute_code_metrics(wide)['simplicity_bin'], 'rich')
        ifs = 'def g(a):\n' + '\n'.join(f'    if a > {i}: a += 1'
                                        for i in range(100)) + '\n    return a'
        metrics = compute_code_metrics(ifs)
        self.assertEqual((metrics['ast_nodes'], metrics['branches'],
                          metrics['simplicity_bin']), (1107, 100, 'rich'))

    def test_speed_bins(self):
        for (ms, kb), expected in (((None, None), 'medium'),   # default 250 ms
                                   ((100.0, 2000.0), 'fast'),
                                   ((100.0, 3000.0), 'medium'),
                                   ((120.0, 2048.0), 'fast'),
                                   ((121.0, None), 'medium'),
                                   ((600.0, 12288.0), 'medium'),
                                   ((601.0, None), 'thorough'),
                                   ((600.0, 13000.0), 'thorough'),
                                   ((10, 100), 'fast'),
                                   ((0, 0), 'fast')):
            with self.subTest(ms=ms, kb=kb):
                self.assertEqual(classify_speed_bin(ms, kb), expected)


class EvolveBlocks(EvolveBase):
    MARKED = ('# EVOLVE-BLOCK-START:core\n'
              'def f():\n'
              '    return 1\n'
              '# EVOLVE-BLOCK-END\n'
              '# stray\n'
              'x = 2\n'
              '# EVOLVE-BLOCK-START\n'
              'y = 3\n'
              '# EVOLVE-BLOCK-END\n'
              '# EVOLVE-BLOCK-START:nested\n'
              'never closed\n')

    def test_extract_shapes(self):
        blocks = ev.EvolveBlocks.extract(self.MARKED)
        self.assertEqual([b['name'] for b in blocks], ['core', 'block_2'])
        self.assertEqual(blocks[0], {'name': 'core', 'start_line': 1, 'end_line': 4,
                                     'body': 'def f():\n    return 1'})
        self.assertEqual(blocks[1]['body'], 'y = 3')       # unnamed -> block_2, unclosed dropped
        self.assertEqual(ev.EvolveBlocks.extract('plain code'), [])
        self.assertEqual(ev.EvolveBlocks.extract('a=1\n# EVOLVE-BLOCK-END\nb=2'), [])
        # a second START inside an open block becomes part of its body
        nested = ev.EvolveBlocks.extract(
            '# EVOLVE-BLOCK-START:a\nx\n# EVOLVE-BLOCK-START:b\ny\n# EVOLVE-BLOCK-END\n')
        self.assertEqual(len(nested), 1)
        self.assertEqual(nested[0]['body'], 'x\n# EVOLVE-BLOCK-START:b\ny')

    def test_frozen_skeleton_verification(self):
        orig = 'A = 1\n# EVOLVE-BLOCK-START:z\nold()\n# EVOLVE-BLOCK-END\nB = 2\n'
        ok, msg = ev.EvolveBlocks.verify_frozen_outside_blocks(
            orig, orig.replace('old', 'new'))
        self.assertEqual((ok, msg), (True, ''))
        ok, msg = ev.EvolveBlocks.verify_frozen_outside_blocks(
            orig, orig.replace('A = 1', 'A = 9'))
        self.assertEqual((ok, msg), (False, 'Patch zmodyfikował zamrożony kod '
                                           'poza strefą # EVOLVE-BLOCK.'))
        ok, msg = ev.EvolveBlocks.verify_frozen_outside_blocks(
            orig, orig + '# EVOLVE-BLOCK-START:z2\nx()\n# EVOLVE-BLOCK-END\n')
        self.assertEqual((ok, msg), (False, 'Patch usunął lub zmienił liczbę '
                                          'znaczników # EVOLVE-BLOCK.'))
        self.assertEqual(ev.EvolveBlocks.verify_frozen_outside_blocks('x=1', 'y=2'),
                         (True, ''))

    def test_crossover_prompt_shape(self):
        parent = 'A = 1\n' + self.MARKED.split('# stray')[0]
        prompt = ev.build_crossover_prompt('mod.py', 'popraw szybkość', parent, [], None)
        self.assertEqual(prompt.splitlines()[:4], [
            'File: mod.py',
            'Instruction: popraw szybkość',
            '',
            'UWAGA: Ten plik posiada strefy ewolucji `# EVOLVE-BLOCK-START` (core). '
            'Modyfikuj WYŁĄCZNIE kod wewnątrz znaczników `# EVOLVE-BLOCK-START` .. '
            '`# EVOLVE-BLOCK-END`!'])
        self.assertIn('## Kod rodzica do zmodyfikowania', prompt)
        arts = [f'art{i}' for i in range(7)]
        inspirations = [
            {'cell': 'compact:fast', 'score': 0.9, 'ast_nodes': 40,
             'duration_ms': 12.5, 'source': 'SRC-A'},
            {'cell': 'rich:thorough', 'score': 0.5, 'ast_nodes': 900,
             'duration_ms': 900.0, 'source': 'SRC-B'},
            {'cell': 'x:y', 'score': 0.1, 'ast_nodes': 0, 'duration_ms': 0.0,
             'source': 'SRC-DROPPED'},
        ]
        prompt2 = ev.build_crossover_prompt('m', 'i', 'x=1', inspirations, arts)
        self.assertEqual(prompt2.splitlines()[3],
                         'Artefakty z ostatniego wykonania / profilera '
                         '(wyeliminuj te błędy):')
        self.assertEqual(prompt2.splitlines()[4:10],
                         [f'- art{i}' for i in range(6)])   # 6-line artifact list
        self.assertIn('- art5', prompt2)
        self.assertNotIn('art6', prompt2)
        self.assertIn('### Inspiracja #1 (nisza `compact:fast`, score=0.9, AST=40, 12.5 ms)',
                      prompt2)
        self.assertIn('### Inspiracja #2 (nisza `rich:thorough`, score=0.5, AST=900, 900.0 ms)',
                      prompt2)
        self.assertNotIn('SRC-DROPPED', prompt2)      # inspirations capped at 2

    def test_crossover_prompt_without_extras(self):
        prompt = ev.build_crossover_prompt('m.py', 'i', 'plain = 1')
        self.assertNotIn('UWAGA', prompt)             # no evolve blocks -> no note
        self.assertNotIn('Artefakty', prompt)
        self.assertTrue(prompt.startswith('File: m.py\nInstruction: i\n\n'))


class GridBase(EvolveBase):
    def grid(self, **overrides):
        self.fake_evolution(**overrides)
        return MapElitesGrid()


class MapElites(GridBase):
    def test_insert_acceptance_clip_and_islands(self):
        grid = self.grid()
        result = grid.insert(module='router', node_id='n1', score=0.9, source=TINY_SRC,
                             duration_ms=50.0, peak_kb=100.0, island=0,
                             explanation='e' * 300)
        self.assertTrue(result['accepted'])
        self.assertEqual((result['cell'], result['island']), ('compact:fast', 0))
        entry = result['entry']
        self.assertEqual(entry['score'], 0.9)
        self.assertEqual(entry['duration_ms'], 50.0)
        self.assertEqual(len(entry['explanation']), 220)      # clipped
        self.assertEqual(entry['ts'], 100.0)
        data = json.loads((self.state / 'map_elites.json').read_text())
        self.assertEqual(data['router']['updated_at'], 100.0)
        # island 1 stays absent until used: only islands with cells get keys
        self.assertEqual(sorted(data['router']['islands']), ['0'])

    def test_insert_rejection_paths(self):
        grid = self.grid()
        # big incumbent first: same score + same cell, but a tinier candidate wins
        first = grid.insert(module='m', node_id='n1', score=0.9, source=BIGGISH_SRC,
                           duration_ms=50.0, island=0)
        self.assertTrue(first['accepted'])
        worse = grid.insert(module='m', node_id='n2', score=0.5, source=TINY_SRC,
                            duration_ms=50.0, island=0)
        self.assertFalse(worse['accepted'])
        tie_smaller = grid.insert(module='m', node_id='n3', score=0.9, source=TINY_SRC,
                                  duration_ms=50.0, island=0)
        self.assertTrue(tie_smaller['accepted'])      # -ast_nodes beats the tie
        rejected_bigger = grid.insert(module='m', node_id='n4', score=0.9,
                                       source=BIGGISH_SRC, duration_ms=50.0, island=0)
        self.assertFalse(rejected_bigger['accepted'])  # bigger ast loses the tie
        faster = grid.insert(module='m', node_id='n6', score=0.9, source=TINY_SRC,
                             duration_ms=30.0, island=0)
        self.assertTrue(faster['accepted'])           # same score+ast, faster wins
        better = grid.insert(module='m', node_id='n5', score=0.95, source=BIGGISH_SRC,
                             duration_ms=50.0, island=0)
        self.assertTrue(better['accepted'])           # strictly higher score replaces
        self.assertEqual(better['entry']['node_id'], 'n5')

    def test_migrate_ring_copies_superior_best(self):
        grid = self.grid()
        grid.insert(module='m', node_id='a', score=0.9, source=TINY_SRC,
                    duration_ms=50.0, island=0)
        grid.insert(module='m', node_id='b', score=0.7, source=TINY_SRC,
                    duration_ms=50.0, island=0)
        grid.insert(module='m', node_id='c', score=0.95, source=TINY_SRC,
                    duration_ms=50.0, island=2)
        migrated = grid.migrate_islands('m')
        self.assertEqual(migrated, 2)              # best of 0 -> 1, best of 2 -> 0/1?
        data = json.loads((self.state / 'map_elites.json').read_text())
        islands = data['m']['islands']
        # island 0's best (a, 0.9) lands on island 1 with a migration stamp
        self.assertEqual(islands['1']['compact:fast']['node_id'], 'a')
        self.assertEqual(islands['1']['compact:fast']['migrated_from'], 0)
        # island 2's best (c, 0.95) replaces island 0's weaker incumbent a
        self.assertEqual(islands['0']['compact:fast']['node_id'], 'c')
        self.assertEqual(islands['0']['compact:fast']['migrated_from'], 2)
        self.assertEqual(self.grid().migrate_islands('ghost'), 0)

    def test_elites_dedupe_sort_and_corrupt_guard(self):
        grid = self.grid()
        payload = {'m': {'islands': {
            '0': {'compact:fast': {'node_id': 'dup', 'score': 0.4, 'ast_nodes': 10,
                                   'duration_ms': 5.0, 'cell': 'compact:fast'}},
            '1': {'compact:fast': {'node_id': 'dup', 'score': 0.9, 'ast_nodes': 10,
                                   'duration_ms': 5.0, 'cell': 'compact:fast'}},
            'j': 'not-a-dict',
        }}}
        self.write_json(self.state / 'map_elites.json', payload)
        rows = grid.elites('m')
        self.assertEqual([(r['node_id'], r['score']) for r in rows], [('dup', 0.9)])
        # regression: non-dict module entry used to crash elites()/summary()
        self.write_json(self.state / 'map_elites.json',
                        {'m': {'islands': {'0': {}}}, 'corrupt': 'a-string'})
        self.assertEqual(grid.elites('corrupt'), [])
        summary = grid.summary()
        self.assertEqual(summary['corrupt'], {'cells': 0, 'top': []})
        self.assertIn('m', summary)

    def test_sample_inspirations_and_summary(self):
        grid = self.grid()
        self.write_json(self.state / 'map_elites.json', {'m': {'islands': {'0': {
            'compact:fast': {'node_id': 'd', 'score': 0.9, 'ast_nodes': 10,
                             'duration_ms': 10.0, 'cell': 'compact:fast'},
            'rich:thorough': {'node_id': 'e', 'score': 0.7, 'ast_nodes': 900,
                              'duration_ms': 900.0, 'cell': 'rich:thorough'},
        }}}})

        class Archive:
            def __init__(self, srcs):
                self.srcs = srcs

            def source_of(self, node_id):
                return self.srcs.get(node_id)

        arch = Archive({'d': 'SRC-D', 'e': 'SRC-E'})
        chosen = grid.sample_inspirations('m', archive=arch, k=2)
        self.assertEqual([(c['node_id'], c['source']) for c in chosen],
                         [('d', 'SRC-D'), ('e', 'SRC-E')])   # diverse cells
        self.assertEqual([c['node_id'] for c in
                          grid.sample_inspirations('m', archive=arch,
                                                   exclude_id='d', k=2)], ['e'])
        self.assertEqual(grid.sample_inspirations('m', archive=Archive({}), k=2), [])
        module_summary = grid.summary('m')
        self.assertEqual(module_summary['module'], 'm')
        self.assertEqual(len(module_summary['elites']), 2)
        all_summary = grid.summary()
        self.assertEqual(all_summary['m']['cells'], 2)
        self.assertEqual([e['node_id'] for e in all_summary['m']['top']], ['d', 'e'])


class Mutations(GridBase):
    SRC = 'def f(a, b):\n    if a < b:\n        return a == b\n    return a + b\n'

    def test_generate_mutants(self):
        mutants = MutationTester.generate_mutants(self.SRC, limit=20)
        # ast.walk is breadth-first: Lt, then the Add of the trailing return,
        # then the Eq nested inside the if
        self.assertEqual([(m['kind'], m['line'], m['original']) for m in mutants],
                         [('compare', 2, 'Lt'), ('binop', 4, 'Add'),
                          ('compare', 3, 'Eq')])
        self.assertTrue(all(m['source'] != self.SRC for m in mutants))
        self.assertIn('a <= b', mutants[0]['source'])
        self.assertIn('a - b', mutants[1]['source'])
        self.assertIn('a != b', mutants[2]['source'])
        # cap: 0 is falsy -> 8; genuine limit respected
        self.assertEqual(len(MutationTester.generate_mutants(self.SRC, limit=0)), 3)
        self.assertEqual(MutationTester.generate_mutants('def x(:', 5), [])
        self.assertEqual([(m['kind'], m['original']) for m in
                          MutationTester.generate_mutants('x = 1 + 2\n', 5)],
                         [('binop', 'Add')])

    def test_evaluate_suite_kill_flow(self):
        (self.tmp / 'mod.py').write_text(self.SRC, encoding='utf-8')
        score = NS(
            bench_cases=lambda m: [{'call': 'f'}],
            run_cases=lambda path, cases: (
                {'ok': 0, 'total': len(cases), 'results': []}
                if any(x in Path(path).read_text() for x in ('<=', '!=', ' - b'))
                else {'ok': len(cases), 'total': len(cases), 'results': []}),
            unittests=lambda m: {})
        self.fake_evolution(Scorecard=score)
        report = MutationTester.evaluate_suite('mod', source_path=self.tmp / 'mod.py',
                                               max_mutants=6)
        self.assertTrue(report['ok'])
        self.assertEqual(report['mutants'], 3)
        self.assertEqual(report['killed'], 3)     # all three mutants flip a marker
        self.assertEqual(report['kill_rate'], 1.0)
        self.assertEqual(report['survivors'], [])

        # a marker that only one mutant trips: 1 killed, 2 survivors
        score.run_cases = lambda path, cases: (
            {'ok': 0, 'total': len(cases), 'results': []}
            if '<=' in Path(path).read_text()
            else {'ok': len(cases), 'total': len(cases), 'results': []})
        report = MutationTester.evaluate_suite('mod', source_path=self.tmp / 'mod.py',
                                               max_mutants=6)
        self.assertEqual((report['killed'], report['kill_rate']), (1, 0.333))
        self.assertEqual([(s['kind'], s['line'], s['original']) for s in
                          report['survivors']],
                         [('binop', 4, 'Add'), ('compare', 3, 'Eq')])

    def test_evaluate_suite_preconditions(self):
        (self.tmp / 'mod.py').write_text(self.SRC, encoding='utf-8')
        score = NS(run_cases=lambda p, c: {'ok': 0, 'total': len(c), 'results': []},
                   bench_cases=lambda m: [{'call': 'f'}], unittests=lambda m: {})
        self.fake_evolution(Scorecard=score)
        report = MutationTester.evaluate_suite('mod', source_path=self.tmp / 'mod.py',
                                               cases=[{'call': 'f'}], max_mutants=6)
        self.assertEqual((report['mutants'], report['kill_rate']), (0, 0.0))
        self.assertEqual(report['note'], 'Bazowe przypadki bench jeszcze nie '
                                        'przechodzą w 100%.')
        missing = MutationTester.evaluate_suite('mod', source_path=self.tmp / 'ghost.py',
                                                cases=[{'call': 'f'}])
        self.assertEqual((missing['ok'], missing['mutants']), (True, 0))
        no_cases = MutationTester.evaluate_suite('mod', source_path=self.tmp / 'mod.py',
                                                 cases=[])
        self.assertEqual((no_cases['ok'], no_cases['mutants']), (True, 0))


class Cascade(EvolveBase):
    SMOKE_OK = NS(returncode=0,
                  stdout='{"ok": true, "peak_kb": 12.5, "smoke_ms": 3.3}', stderr='')

    def test_smoke_matrix(self):
        self.fake_evolution()
        probe = self.tmp / 'mod.py'
        probe.write_text('x = 1', encoding='utf-8')
        self.assertEqual(ev.CascadeEvaluator.measure_memory_and_smoke(probe, []),
                         {'ok': True, 'peak_kb': 0.0, 'smoke_ms': 0.0})
        refusal = ev.CascadeEvaluator.measure_memory_and_smoke(
            probe, [{'call': 'x'}]) if False else None
        with patch.object(ev.evolution, 'sandbox_refusal', lambda: 'brak bwrap'):
            refusal = ev.CascadeEvaluator.measure_memory_and_smoke(
                probe, [{'call': 'x'}])
        self.assertEqual((refusal['ok'], refusal['error']), (False, 'brak bwrap'))
        with patch.object(ev.subprocess, 'run',
                          lambda *a, **k: NS(returncode=1, stdout='', stderr='E' * 300)):
            crashed = ev.CascadeEvaluator.measure_memory_and_smoke(
                probe, [{'call': 'x'}])
        self.assertEqual((crashed['ok'], len(crashed['error'])), (False, 240))
        with patch.object(ev.subprocess, 'run',
                          lambda *a, **k: NS(returncode=0,
                                             stdout='junk-line\n{"ok": true, '
                                                    '"peak_kb": 1.0, "smoke_ms": 2.0}',
                                             stderr='')):
            healthy = ev.CascadeEvaluator.measure_memory_and_smoke(
                probe, [{'call': 'x'}])
        self.assertEqual(healthy, {'ok': True, 'peak_kb': 1.0, 'smoke_ms': 2.0})
        with patch.object(ev.subprocess, 'run',
                          lambda *a, **k: (_ for _ in ()).throw(OSError('boom'))):
            exploded = ev.CascadeEvaluator.measure_memory_and_smoke(
                probe, [{'call': 'x'}])
        self.assertEqual((exploded['ok'], exploded['error']), (False, 'boom'))

    def test_candidate_stage_machine(self):
        score = NS(bench_cases=lambda m: [{'call': 'f'}],
                   run_cases=lambda p, c: {
                       'ok': len(c), 'total': len(c),
                       'results': [{'ok': True, 'detail': ''} for _ in c]},
                   unittests=lambda m: {'ok': 2, 'total': 3})
        self.fake_evolution(Scorecard=score)
        with patch.object(ev.subprocess, 'run', lambda *a, **k: self.SMOKE_OK):
            ast_fail = ev.CascadeEvaluator.evaluate_candidate('m', 'def broken(:')
            self.assertEqual((ast_fail['ok'], ast_fail['stage'], ast_fail['error']),
                             (False, 'ast', 'Błąd składni AST'))
            orig = 'A = 1\n# EVOLVE-BLOCK-START:z\nold()\n# EVOLVE-BLOCK-END\nB = 2\n'
            staged = orig.replace('A = 1', 'A = 9')
            block_fail = ev.CascadeEvaluator.evaluate_candidate('m', staged, orig)
            self.assertEqual((block_fail['ok'], block_fail['stage']),
                             (False, 'evolve_block'))
            # not strict: frozen-zone violation is forgiven
            relaxed = ev.CascadeEvaluator.evaluate_candidate(
                'm', staged, orig, strict_blocks=False)
            self.assertEqual((relaxed['ok'], relaxed['stage'], relaxed['score']),
                             (True, 'complete', 1.0))
            complete = ev.CascadeEvaluator.evaluate_candidate('m', 'x = 1\n')
            self.assertEqual(complete['bench'], {'ok': 1, 'total': 1})
            self.assertEqual(complete['artifacts'], [])
            self.assertEqual(complete['peak_kb'], 12.5)
            blended = ev.CascadeEvaluator.evaluate_candidate(
                'm', 'x = 1\n', run_unittests=True)
            self.assertEqual(blended['score'], 0.9)   # 0.7*1.0 + 0.3*(2/3)

    def test_candidate_smoke_and_bench_failures(self):
        score = NS(bench_cases=lambda m: [{'call': 'f'}],
                   run_cases=lambda p, c: {'ok': 0, 'total': len(c), 'results': []},
                   unittests=lambda m: {})
        self.fake_evolution(Scorecard=score)
        smoke_bad = NS(returncode=0,
                       stdout='{"ok": false, "peak_kb": 1.0, "smoke_ms": 9.0}',
                       stderr='')
        with patch.object(ev.subprocess, 'run', lambda *a, **k: smoke_bad):
            failed = ev.CascadeEvaluator.evaluate_candidate('m', 'x = 1\n')
            self.assertEqual((failed['ok'], failed['stage'], failed['error'],
                              failed['peak_kb']),
                             (False, 'smoke', 'Smoke test failed', 1.0))
        with patch.object(ev.subprocess, 'run', lambda *a, **k: self.SMOKE_OK):
            benched = ev.CascadeEvaluator.evaluate_candidate('m', 'x = 1\n')
            self.assertEqual((benched['ok'], benched['stage']), (False, 'bench'))
            self.assertEqual(benched['error'],
                             'Wszystkie przypadki held-out bench zakończyły się błędem.')
            # partial pass: failure details flow into artifacts (cap 6)
            score.run_cases = lambda p, c: {
                'ok': 1, 'total': 2,
                'results': [{'ok': True}, {'ok': False, 'detail': 'boom-detail'}]}
            partial = ev.CascadeEvaluator.evaluate_candidate('m', 'x = 1\n')
            self.assertEqual((partial['ok'], partial['score'], partial['artifacts']),
                             (True, 0.5, ['boom-detail']))
            # artifact cap: 6 failing rows among 9 keep the first 6 details
            score.run_cases = lambda p, c: {
                'ok': 3, 'total': 9,
                'results': [{'ok': i < 3} for i in range(3)] +
                           [{'ok': False, 'detail': f'd{i}'} for i in range(6)]}
            capped = ev.CascadeEvaluator.evaluate_candidate('m', 'x = 1\n')
            self.assertEqual(capped['stage'], 'complete')
            self.assertEqual(capped['artifacts'], [f'd{i}' for i in range(6)])
            # no bench cases at all: perfect ratio without running anything
            score.bench_cases = lambda m: []
            empty = ev.CascadeEvaluator.evaluate_candidate('m', 'x = 1\n')
            self.assertEqual((empty['ok'], empty['score']), (True, 1.0))


class Adversarial(EvolveBase):
    def setUp(self):
        super().setUp()
        (self.tmp / 'adv.py').write_text(
            'def zero():\n    return 0\n\ndef one(x):\n    return x\n', encoding='utf-8')

    def test_fallback_probes_without_client(self):
        def run_cases(path, cases):
            def passes(case):
                if case.get('call') == 'zero' and not case.get('kwargs'):
                    return True
                return case.get('kwargs') == {'x': None}

            return {'ok': 0, 'total': len(cases),
                    'results': [{'ok': passes(c), 'detail': f'row-{i}'}
                                for i, c in enumerate(cases)]}

        score = NS(unittests=lambda m: {}, bench_cases=lambda m: [{'call': 'zero'}],
                   run_cases=run_cases)
        self.fake_evolution(Scorecard=score)
        result = ev.AdversarialBreaker.generate_draft_cases('adv',
                                                             source_path=self.tmp / 'adv.py')
        self.assertTrue(result['ok'])
        self.assertEqual(result['draft_file'],
                         str(self.state / 'bench_drafts' / 'adv.draft.json'))
        self.assertEqual([(c['call'], c.get('kwargs'), c.get('level'),
                           c.get('current_passes'), c.get('detail'))
                          for c in result['cases']], [
            ('zero', {}, 2, True, 'row-0'),
            ('one', {'x': ''}, 3, False, 'row-1'),
            ('one', {'x': None}, 3, True, 'row-2'),
        ])
        self.assertEqual(result['mutation_report']['module'], 'adv')
        self.assertEqual((self.state / 'bench_drafts').stat().st_mode & 0o777, 0o700)
        with self.assertRaises(self.EvolutionError):
            ev.AdversarialBreaker.generate_draft_cases('ghostmod')

    def test_client_cases_verification_and_failure(self):
        create_calls = []

        class TextBlock:
            type, text = 'text', json.dumps(
                {'cases': [{'call': 'zero', 'kwargs': {}, 'level': 5},
                           {'call': 'one', 'kwargs': {'x': 3}},
                           {'not': 'a case'}]})

        client = NS(messages=NS(create=lambda **k: (
            create_calls.append(k), NS(content=[TextBlock()]))[1]))
        score = NS(unittests=lambda m: {}, bench_cases=lambda m: [],
                   run_cases=lambda p, c: {'ok': 0, 'total': len(c),
                                           'results': [{'ok': True, 'detail': 'd(i)'}
                                                       for _ in c]})
        self.fake_evolution(Scorecard=score)
        result = ev.AdversarialBreaker.generate_draft_cases(
            'adv', client=client, model='bigm', source_path=self.tmp / 'adv.py')
        self.assertEqual(create_calls[0]['model'], 'bigm')
        self.assertEqual(create_calls[0]['max_tokens'], 1400)
        self.assertEqual(create_calls[0]['stream'], False)
        self.assertEqual(create_calls[0]['system'], 'CUSTOM')   # PromptLab override wins
        self.assertIn('Surviving AST mutants', create_calls[0]['messages'][0]['content'])
        # client's level kept, missing level defaults to 3, junk shape dropped
        self.assertEqual([(c['call'], c.get('level')) for c in result['cases']],
                         [('zero', 5), ('one', 3)])
        self.assertEqual([c['current_passes'] for c in result['cases']], [True, True])
        # an exploding client falls back to AST probes
        broken = NS(messages=NS(create=lambda **k: (_ for _ in ()).throw(RuntimeError())))
        fallback = ev.AdversarialBreaker.generate_draft_cases(
            'adv', client=broken, source_path=self.tmp / 'adv.py')
        self.assertTrue({c['call'] for c in fallback['cases']} >= {'zero', 'one'})

    def test_promote_draft_semantics(self):
        calls = []
        self.fake_evolution(
            Bench=NS(seal=lambda: calls.append('seal')),
            Curriculum=NS(invalidate=lambda: calls.append('inval')))
        drafts = self.state / 'bench_drafts'
        drafts.mkdir(parents=True, exist_ok=True)
        self.write_json(drafts / 'adv.draft.json', {'module': 'adv', 'cases': [
            {'call': 'zero', 'kwargs': {}, 'current_passes': True, 'detail': 'x'},
            {'call': 'one', 'current_passes': False, 'detail': 'y'},
            {'call': 'keep', 'current_passes': True, 'detail': 'z'},
            'junk-entry']})
        promoted = ev.AdversarialBreaker.promote_draft('adv')
        self.assertEqual(promoted, {'ok': True, 'module': 'adv', 'added': 2,
                                   'total': 2, 'sealed': True})
        bench = json.loads((self.tmp / 'bench' / 'adv.json').read_text())
        self.assertEqual(bench, [{'call': 'zero', 'kwargs': {}}, {'call': 'keep'}])
        self.assertEqual(calls, ['seal', 'inval'])
        # dict-shaped bench keeps its sibling keys through the merge
        self.write_json(drafts / 'adv2.draft.json',
                         {'module': 'adv2', 'cases': [{'call': 'z',
                                                       'current_passes': True}]})
        self.write_json(self.tmp / 'bench' / 'adv2.json',
                        {'version': 7, 'cases': ['existing']})
        promoted2 = ev.AdversarialBreaker.promote_draft('adv2')
        self.assertEqual((promoted2['added'], promoted2['total']), (1, 2))
        merged = json.loads((self.tmp / 'bench' / 'adv2.json').read_text())
        self.assertEqual(merged, {'version': 7, 'cases': ['existing', {'call': 'z'}]})
        # nothing promotable / missing drafts
        self.write_json(drafts / 'adv3.draft.json', {'module': 'x', 'cases': []})
        with self.assertRaises(self.EvolutionError):
            ev.AdversarialBreaker.promote_draft('adv3')
        with self.assertRaises(self.EvolutionError):
            ev.AdversarialBreaker.promote_draft('ghostdraft')
        self.write_json(drafts / 'adv4.draft.json',
                         {'module': 'x', 'cases': [{'call': 'z',
                                                    'current_passes': False}]})
        self.assertEqual(ev.AdversarialBreaker.promote_draft('adv4'),
                         {'ok': True, 'module': 'adv4', 'added': 0, 'sealed': False})


class SkillsAndHarness(EvolveBase):
    def test_distill_from_archive(self):
        rows = [
            {'id': 'n1', 'module': 'router', 'status': 'applied', 'verdict': 'improved',
             'score': 0.9, 'before': 0.5, 'explanation': 'lepsze cache'},
            {'id': 'n2', 'module': 'router', 'status': 'applied', 'verdict': 'improved',
             'score': 0.8, 'before': 0.5, 'explanation': ''},
            {'id': 'n3', 'module': 'router', 'status': 'applied', 'verdict': 'regressed',
             'score': 0.1, 'before': 0.5, 'explanation': 'x'},
            {'id': 'n4', 'module': 'kb', 'status': 'staged', 'verdict': 'improved',
             'score': 0.9, 'before': 0.5, 'explanation': 'x'},
        ]
        self.fake_evolution(
            Archive=lambda: NS(rows=lambda: rows, source_of=lambda nid: None),
            Failures=lambda: NS(
                rows=lambda: [],
                for_module=lambda m, limit=5: [{'lesson': f'pit-{m}'}]))
        result = ev.SkillDistiller.distill_from_archive()
        self.assertEqual((result['ok'], result['created'], result['files']),
                         (True, 2, ['router-n1.md', 'router-n2.md']))
        content = (self.state / 'distilled_skills' / 'router-n1.md').read_text()
        self.assertEqual(content.splitlines()[0],
                         '# Destylowana umiejętność: `router` (węzeł `n1`)')
        self.assertIn('- **Wzrost wyniku Scorecard**: `+0.4` (`0.5` -> `0.9`)', content)
        self.assertIn('- **Zastosowany wzorzec**: lepsze cache', content)
        second = (self.state / 'distilled_skills' / 'router-n2.md').read_text()
        self.assertIn('- **Zastosowany wzorzec**: Ulepszenie zweryfikowane '
                      'na held-out bench.', second)
        self.assertIn('- Unikaj: pit-router', content)
        self.assertEqual((self.state / 'distilled_skills').stat().st_mode & 0o777, 0o700)
        # re-distillation skips files that already exist
        self.assertEqual(ev.SkillDistiller.distill_from_archive()['created'], 0)

    def test_load_for_module(self):
        self.fake_evolution()
        skills = self.state / 'distilled_skills'
        skills.mkdir(parents=True, exist_ok=True)
        (skills / 'mod-a.md').write_text('A' * 1200, encoding='utf-8')
        (skills / 'mod-b.md').write_text('B', encoding='utf-8')
        (skills / 'other-c.md').write_text('C', encoding='utf-8')
        loaded = ev.SkillDistiller.load_for_module('mod', limit=2)
        self.assertTrue(loaded.startswith('\n\n## Destylowane umiejętności '
                                          'z udanych ewolucji tego modułu'))
        body = loaded.split('\n\n## Destylowane umiejętności z udanych ewolucji '
                            'tego modułu\n', 1)[1]
        self.assertTrue(body.startswith('A'[:900]) or body.startswith('B'))
        self.assertIn('\n---\n', body)
        self.assertLessEqual(len(body.split('\n---\n')[0]), 900)
        self.assertEqual(ev.SkillDistiller.load_for_module('ghost'), '')

    def test_self_harness_prompt_evolution(self):
        lab = {}
        lab_fake = NS(get=lambda k: lab.get(k, 'CUSTOM'),
                      set=lambda k, v: lab.update({k: v}),
                      reset=lambda k: lab.update({f'reset:{k}': True}))
        failures = NS(rows=lambda: [
            {'count': 9, 'ts': 5, 'module': 'kb', 'lesson': 'L9'},
            {'count': 3, 'ts': 10, 'module': 'router', 'lesson': 'L' * 200},
            {'count': 1, 'ts': 99, 'module': 'ui', 'lesson': 'L1'}])
        self.fake_evolution(PromptLab=lambda: lab_fake)
        with self.assertRaises(self.EvolutionError):
            ev.SelfHarness.evolve_prompt_from_failures('unknown', failures=failures,
                                                      lab=lab_fake)
        quiet = NS(rows=lambda: [])
        no_update = ev.SelfHarness.evolve_prompt_from_failures(
            'patcher', failures=quiet, lab=lab_fake)
        self.assertEqual((no_update['ok'], no_update['updated'], no_update['prompt']),
                         (True, False, 'CUSTOM'))
        result = ev.SelfHarness.evolve_prompt_from_failures(
            'patcher', failures=failures, lab=lab_fake)
        self.assertEqual((result['ok'], result['updated'], result['rules_added']),
                         (True, True, 3))
        self.assertTrue(lab['patcher'].startswith('BASE-PROMPT\n\nLearned Self-Harness '
                                                  'Guardrails:\n'))
        self.assertIn('- NEVER repeat known failure (kb): L9', lab['patcher'])
        self.assertIn('- NEVER repeat known failure (router): ' + 'L' * 160, lab['patcher'])
        self.assertNotIn('L' * 161, lab['patcher'])             # lesson clipped to 160
        self.assertEqual(lab['patcher'].splitlines()[-1],
                         '- NEVER repeat known failure (ui): L1')

    def test_self_harness_audit_rollback(self):
        lab = {}

        class Lab:
            def get(self, k):
                return lab.get(k, 'CUSTOM')

            def set(self, k, v):
                lab[k] = v

            def reset(self, k):
                lab[f'reset-{k}'] = True

        self.fake_evolution(PromptLab=Lab)
        arch3 = NS(rows=lambda: [{'verdict': 'regressed'}] * 3)
        rolled = ev.SelfHarness.audit_and_guard_prompt('patcher', archive=arch3, lab=Lab())
        self.assertEqual(rolled, {'ok': True, 'key': 'patcher', 'rolled_back': True})
        self.assertTrue(lab.get('reset-patcher'))
        mixed = NS(rows=lambda: [{'verdict': 'regressed'}, {'verdict': 'improved'},
                                 {'verdict': 'regressed'}])
        self.assertEqual(ev.SelfHarness.audit_and_guard_prompt(
            'codeditor', archive=mixed, lab=Lab())['rolled_back'], False)
        two = NS(rows=lambda: [{'verdict': 'regressed'}] * 2)
        self.assertEqual(ev.SelfHarness.audit_and_guard_prompt(
            'codeditor', archive=two, lab=Lab())['rolled_back'], False)


if __name__ == '__main__':
    unittest.main()
