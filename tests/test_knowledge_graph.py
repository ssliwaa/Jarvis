"""knowledge_graph: Cortex topology and semantic triple contracts.

This suite pins the persistent SQLite knowledge graph: triple validation and
normalisation (strip/clips, relation lowering with underscore folding,
conflict updates of kind and weight without duplicate edges), the AST
topology harvester (imports limited to known modules and sorted, class cap
of 15, the HTTP route regex perimeter, sqlite-store detection rules, the
event_bus publish/subscribe extraction quirk where a naked publish counts
when the file merely mentions event_bus, syntax-error isolation), the
rebuild pipeline (source='ast' replacement that preserves source='manual'
triples, test_ files and skip-dir exclusion, edge weights per relation,
anomaly and summary in the result envelope), the anomaly detector (closed
3-node cycle representation, self-loops below the path-length threshold of 2
are not flagged, fan-in hub ranking) and the BFS subgraph query (hop clamps
1..3 with hops=0 falling back to 1, case-insensitive label seeding, the
40-edge collection cap and the 20-line ascii map cap, empty-query fallback
to recent seeds).

All assertions were pinned empirically before writing. The database is
redirected into a per-test sandbox by patching knowledge_graph.agent_cli.ROOT.
"""
import sqlite3
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import knowledge_graph


class KnowledgeGraphBase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix='kgt_')
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(self._tmp.name)
        self.agents_dir = self.tmp / 'agents'  # left for knowledge_graph to create (0700)
        self._cli_patcher = patch.object(
            knowledge_graph, 'agent_cli', SimpleNamespace(ROOT=self.agents_dir / 'agent_cli.py'))
        self._cli_patcher.start()
        self.addCleanup(self._cli_patcher.stop)

    def db(self):
        conn = sqlite3.connect(self.agents_dir / 'knowledge_graph.sqlite3')
        conn.row_factory = sqlite3.Row
        self.addCleanup(conn.close)
        return conn


class TestUpsertTriple(KnowledgeGraphBase):
    def test_triple_normalisation_and_persistence(self):
        result = knowledge_graph.upsert_triple('  Poland  ', 'IS PART OF', 'EU')
        self.assertEqual(result, {'ok': True, 'subject': 'Poland',
                                  'relation': 'is_part_of', 'object': 'EU'})
        conn = self.db()
        kinds = {row['node_id']: row['kind'] for row in conn.execute('SELECT node_id, kind FROM kg_nodes')}
        edge = conn.execute('SELECT rel, weight, source FROM kg_edges').fetchone()
        self.assertEqual(kinds, {'Poland': 'entity', 'EU': 'entity'})
        self.assertEqual((edge['rel'], edge['weight'], edge['source']), ('is_part_of', 1.0, 'manual'))

    def test_empty_fields_rejected(self):
        for subject, relation, obj in (('', 'rel', 'obj'), ('s', '', 'obj'), ('s', 'rel', '')):
            with self.assertRaises(ValueError) as ctx:
                knowledge_graph.upsert_triple(subject, relation, obj)
            self.assertIn('Trójka grafu wiedzy wymaga niepustych pól', str(ctx.exception))

    def test_clip_lengths(self):
        result = knowledge_graph.upsert_triple('S' * 170, 'R' * 70, 'O' * 170)
        self.assertEqual(len(result['subject']), 160)
        self.assertEqual(len(result['relation']), 64)
        self.assertEqual(len(result['object']), 160)
        self.assertTrue(result['relation'].startswith('rrr'))  # relation is lowercased
        self.assertTrue(result['subject'].startswith('SSS'))

    def test_reupsert_updates_kind_and_weight_without_duplicates(self):
        knowledge_graph.upsert_triple('hub', 'linked', 'x1', weight=5.0, subj_kind='thing')
        knowledge_graph.upsert_triple('hub', 'linked', 'x1', weight=2.0, subj_kind='other')
        conn = self.db()
        node = conn.execute("SELECT kind FROM kg_nodes WHERE node_id = 'hub'").fetchone()
        edges = conn.execute("SELECT weight FROM kg_edges WHERE src = 'hub'").fetchall()
        self.assertEqual(node['kind'], 'other')  # conflict updates the kind
        self.assertEqual([e['weight'] for e in edges], [2.0])  # weight replaced, one edge

    def test_source_and_kind_parameters_persisted(self):
        knowledge_graph.upsert_triple('Idea', 'describes', 'Widget',
                                      subj_kind='concept', obj_kind='artifact', source='agent')
        conn = self.db()
        rows = {row['node_id']: (row['kind'], row['source'])
                for row in conn.execute('SELECT node_id, kind, source FROM kg_nodes')}
        self.assertEqual(rows['Idea'], ('concept', 'agent'))
        self.assertEqual(rows['Widget'], ('artifact', 'agent'))
        edge_source = conn.execute('SELECT source FROM kg_edges').fetchone()['source']
        self.assertEqual(edge_source, 'agent')


class TestExtractTopology(unittest.TestCase):
    def test_imports_limited_to_known_modules(self):
        known = {'b': 'b.py', 'c': 'c.py', 'a': 'a.py'}
        src = ('import b\n'
               'import os\n'          # unknown module: ignored
               'from c import x\n'
               'from a import y\n')   # self: ignored
        topo = knowledge_graph._extract_module_topology('a.py', src, known)
        self.assertEqual(topo['imports'], ['b.py', 'c.py'])

    def test_classes_sorted_and_capped(self):
        src = '\n'.join(f'class Q{i:03d}:\n    pass' for i in range(17))
        classes = knowledge_graph._extract_module_topology('a.py', src, {})['classes']
        self.assertEqual(len(classes), 15)
        self.assertEqual(classes[:2], ['Q000', 'Q001'])

    def test_http_route_regex_contract(self):
        accepted = ('/mission/status', '/voice/tts/stream', '/api/v2/x-y_z', '/chat')
        rejected = ('/missions', '/mission/', '/mission/x.y', 'mission/status', '/other/status')
        for route in accepted:
            self.assertIsNotNone(knowledge_graph.HTTP_ROUTE_RE.match(route), route)
        for route in rejected:
            self.assertIsNone(knowledge_graph.HTTP_ROUTE_RE.match(route), route)

    def test_routes_and_dbs_extracted_from_constants(self):
        src = ('R = "/mission/status"\n'
               'BAD = "/missions"\n'
               'S = "/api/v2/x-y_z"\n'
               'DB1 = "memory.sqlite3"\n'
               'DB2 = "path/to.sqlite3"\n'          # contains '/' -> rejected
               'DB3 = "' + 'z' * 62 + '.sqlite3"\n'  # 71 chars -> rejected
               'DB4 = "notes.txt"\n')
        topo = knowledge_graph._extract_module_topology('a.py', src, {})
        self.assertEqual(topo['routes'], ['/api/v2/x-y_z', '/mission/status'])
        self.assertEqual(topo['sqlite_dbs'], ['memory.sqlite3'])

    def test_event_bus_pub_sub_extraction(self):
        src = ('import event_bus\n'
               'event_bus.publish("ui.state")\n'
               'event_bus.subscribe("ui.ctl")\n'
               'self.bus.publish("naked.pub")\n'  # event_bus mentioned -> captured
               'plain_publish("nope.x")\n')      # no .publish attr call
        topo = knowledge_graph._extract_module_topology('a.py', src, {})
        self.assertEqual(topo['pub_topics'], ['naked.pub', 'ui.state'])
        self.assertEqual(topo['sub_topics'], ['ui.ctl'])

    def test_publish_without_event_bus_mention_ignored(self):
        src = 'b = __build__\nb.publish("naked2.y")\n'
        topo = knowledge_graph._extract_module_topology('a.py', src, {})
        self.assertEqual(topo['pub_topics'], [])  # substring 'event_bus' absent

    def test_syntax_error_returns_empty_topology(self):
        topo = knowledge_graph._extract_module_topology('a.py', 'def broken(:', {})
        self.assertEqual(topo, {'imports': [], 'classes': [], 'routes': [],
                                'pub_topics': [], 'sub_topics': [], 'sqlite_dbs': []})


class TestRebuildCodeGraph(KnowledgeGraphBase):
    def _sample_project(self):
        proj = self.tmp / 'repo'
        proj.mkdir()
        (proj / 'a.py').write_text(
            'import b\nimport event_bus\nclass Alpha:\n    pass\n'
            'RO = "/mission/status"\nevent_bus.publish("ui.events")\nDBN = "state.sqlite3"\n',
            encoding='utf-8')
        (proj / 'b.py').write_text('class Beta:\n    pass\n', encoding='utf-8')
        return proj

    def test_full_harvest_counts_kinds_and_weights(self):
        proj = self._sample_project()
        result = knowledge_graph.rebuild_code_graph(proj)
        self.assertTrue(result['ok'])
        self.assertEqual(result['total_nodes'], 7)
        self.assertEqual(result['total_edges'], 6)
        self.assertEqual(result['by_kind'], {'class': 2, 'http_route': 1, 'module': 2,
                                             'sqlite_db': 1, 'sse_topic': 1})
        conn = self.db()
        weights = {(row['rel'], row['weight'])
                   for row in conn.execute('SELECT rel, weight FROM kg_edges')}
        self.assertEqual(weights, {('imports', 1.0), ('defines_class', 1.0),
                                   ('serves_route', 1.2), ('publishes_event', 1.2),
                                   ('persists_in', 1.1)})
        self.assertEqual(knowledge_graph.graph_summary(),
                         {'total_nodes': 7, 'total_edges': 6,
                          'by_kind': {'class': 2, 'http_route': 1, 'module': 2,
                                      'sqlite_db': 1, 'sse_topic': 1}})
        self.assertIn('circular_imports', result['anomalies'])
        self.assertIn('core_hubs', result['anomalies'])

    def test_test_files_and_skip_dirs_excluded(self):
        proj = self._sample_project()
        (proj / 'test_skipme.py').write_text('class Never:\n    pass\n', encoding='utf-8')
        (proj / 'node_modules').mkdir()
        (proj / 'node_modules' / 'nm.py').write_text('x = 1\n', encoding='utf-8')
        (proj / '.jarvis-cache').mkdir()
        (proj / '.jarvis-cache' / 'j.py').write_text('x = 1\n', encoding='utf-8')
        knowledge_graph.rebuild_code_graph(proj)
        node_ids = ' '.join(row['node_id'] for row in self.db().execute('SELECT node_id FROM kg_nodes'))
        self.assertEqual(node_ids.count('skipme'), 0)
        self.assertEqual(node_ids.count('node_modules'), 0)
        self.assertEqual(node_ids.count('.jarvis-cache'), 0)

    def test_rebuild_replaces_ast_but_preserves_manual_triples(self):
        proj = self._sample_project()
        knowledge_graph.upsert_triple('ManualNode', 'knows', 'ManualTarget', source='manual')
        result = knowledge_graph.rebuild_code_graph(proj)
        self.assertEqual(result['total_nodes'], 9)   # 7 AST + 2 manual
        self.assertEqual(result['total_edges'], 7)   # 6 AST + 1 manual
        conn = self.db()
        manual_nodes = conn.execute(
            "SELECT COUNT(*) AS c FROM kg_nodes WHERE source = 'manual'").fetchone()['c']
        manual_edges = conn.execute(
            "SELECT COUNT(*) AS c FROM kg_edges WHERE source = 'manual'").fetchone()['c']
        self.assertEqual((manual_nodes, manual_edges), (2, 1))
        edge = conn.execute("SELECT rel FROM kg_edges WHERE source = 'manual'").fetchone()
        self.assertEqual(edge['rel'], 'knows')

    def test_missing_dir_raises_value_error(self):
        with self.assertRaises(ValueError) as ctx:
            knowledge_graph.rebuild_code_graph(self.tmp / 'missing-dir')
        self.assertIn('Brak katalogu projektu', str(ctx.exception))


class TestDetectAnomalies(KnowledgeGraphBase):
    def seed_import_edges(self, edges):
        for src, dst in edges:
            knowledge_graph.upsert_triple(src, 'imports', dst)

    def test_three_node_cycle_reported_once_and_self_loop_ignored(self):
        self.seed_import_edges([
            ('a.py', 'b.py'), ('b.py', 'c.py'), ('c.py', 'a.py'),
            ('self.py', 'self.py'),  # below the length-2 cycle path threshold
        ])
        result = knowledge_graph.detect_anomalies()
        self.assertEqual(result['circular_imports'], [['a.py', 'b.py', 'c.py', 'a.py']])

    def test_hubs_ranked_by_fan_in(self):
        self.seed_import_edges([
            ('x.py', 'hub.py'), ('y.py', 'hub.py'),
            ('a.py', 'b.py'), ('b.py', 'c.py'),
        ])
        hubs = knowledge_graph.detect_anomalies()['core_hubs']
        self.assertEqual(hubs[0], {'module': 'hub.py', 'imported_by_count': 2})
        self.assertIn({'module': 'b.py', 'imported_by_count': 1}, hubs[:3])
        for hub in hubs:
            self.assertIsInstance(hub['imported_by_count'], int)


class TestQuerySubgraph(KnowledgeGraphBase):
    def seed_chain(self, count=5):
        for i in range(count - 1):
            knowledge_graph.upsert_triple(f'n{i:02d}', 'linked', f'n{i + 1:02d}')

    def test_hop_expansion_clamped_between_one_and_three(self):
        self.seed_chain(5)
        ids_1 = {n['id'] for n in knowledge_graph.query_subgraph('n00', hops=1)['nodes']}
        self.assertEqual(ids_1, {'n00', 'n01'})
        ids_3 = {n['id'] for n in knowledge_graph.query_subgraph('n00', hops=3)['nodes']}
        self.assertEqual(ids_3, {'n00', 'n01', 'n02', 'n03'})  # n04 needs a 4th hop
        ids_0 = {n['id'] for n in knowledge_graph.query_subgraph('n00', hops=0)['nodes']}
        self.assertEqual(ids_0, {'n00', 'n01'})  # hops=0 clamps to 1

    def test_case_insensitive_label_seeding(self):
        knowledge_graph.upsert_triple('Polska', 'stolicą', 'Warszawa')
        result = knowledge_graph.query_subgraph('polska', hops=2)
        self.assertTrue(result['ok'])
        self.assertGreaterEqual({n['id'] for n in result['nodes']}, {'Polska', 'Warszawa'})
        self.assertTrue(any(e['rel'] == 'stolicą' for e in result['edges']))

    def test_limit_edges_and_ascii_map_caps(self):
        knowledge_graph.upsert_triple('fan', 'linked', 'f01')
        for i in range(2, 46):
            knowledge_graph.upsert_triple('fan', 'linked', f'f{i:02d}')
        result = knowledge_graph.query_subgraph('fan', hops=1, limit_edges=40)
        self.assertEqual(len(result['edges']), 40)
        self.assertEqual(result['ascii_map'].count('\n') + 1, 20)  # map shows 20 lines
        self.assertIn('fan --[linked]--> f01', result['ascii_map'])

    def test_empty_query_falls_back_to_recent_seeds(self):
        knowledge_graph.upsert_triple('Alpha', 'linked', 'Beta')
        result = knowledge_graph.query_subgraph('')
        self.assertTrue(result['ok'])
        self.assertEqual(result['query'], '')
        self.assertGreater(len(result['nodes']), 0)


class TestDatabaseIsolation(KnowledgeGraphBase):
    def test_db_file_0600_and_dir_0700(self):
        knowledge_graph.upsert_triple('A', 'linked', 'B')
        db_file = self.agents_dir / 'knowledge_graph.sqlite3'
        self.assertEqual(db_file.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.agents_dir.stat().st_mode & 0o777, 0o700)


if __name__ == '__main__':
    unittest.main()
