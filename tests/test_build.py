"""Indexer regression tests. All fixture markdown is synthetic, never real secrets."""
import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[1]
SCRATCH = Path(os.environ.get('TMPDIR', str(Path.home() / '.hermes/cache/scratch')))


class IndexTests(unittest.TestCase):
    def setUp(self):
        self.assertTrue((PROJECT / 'build.py').is_file(), 'build.py must implement the indexer')
        spec = importlib.util.spec_from_file_location('galaxy_build', PROJECT / 'build.py')
        self.build = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.build)
        self.temp = tempfile.TemporaryDirectory(dir=SCRATCH)
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def note(self, name, text):
        p = self.root / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding='utf-8')

    def test_index_has_contiguous_numeric_ids_and_real_metadata(self):
        self.note('z/Night run.md', '# Running\n' + 'x' * 1000)
        self.note('a/Zażółć.md', 'Polish text')
        self.note('a/ignore.txt', 'not markdown')
        self.note('a/CAPS.MD', 'uppercase markdown extension')
        graph = self.build.make_graph(self.root)
        self.assertEqual([n['id'] for n in graph['nodes']], list(range(3)))
        self.assertEqual({n['label'] for n in graph['nodes']}, {'Night run', 'Zażółć', 'CAPS'})
        night = next(n for n in graph['nodes'] if n['label'] == 'Night run')
        self.assertEqual(night['group'], 'z')
        self.assertEqual(night['path'], 'z/Night run.md')
        self.assertGreaterEqual(len(night['excerpt']), 650)
        self.assertLessEqual(len(night['excerpt']), 720)
        self.assertEqual(graph, self.build.make_graph(self.root))

    def test_links_title_mentions_direct_wikilinks_and_shared_targets(self):
        self.note('a/Tempo.md', 'A tempo workout improves speed. [[Plans/Running#Week|the plan]]')
        self.note('b/Strength.md', 'Discusses TEMPO and [[Plans/Running|running]].')
        self.note('b/Rest.md', '[[Plans/Running]]')
        self.note('c/Unrelated.md', 'No common topics here.')
        self.note('c/Run.md', 'Tiny title should not match the word runner.')
        self.note('c/Boundary.md', 'runner and template are not title mentions')
        graph = self.build.make_graph(self.root)
        ids = {n['label']: n['id'] for n in graph['nodes']}
        edges = {tuple(sorted((e['source'], e['target']))) for e in graph['links']}
        expected = {tuple(sorted((ids[a], ids[b]))) for a, b in
                    [('Tempo', 'Strength'), ('Tempo', 'Rest'), ('Strength', 'Rest')]}
        self.assertEqual(edges, expected)
        self.assertTrue(all(a < b for a, b in edges))
        self.assertEqual(len(edges), len(graph['links']))
        self.note('d/Direct.md', '[[b/Strength#Training|lifting]]')
        newer = self.build.make_graph(self.root)
        ids = {n['label']: n['id'] for n in newer['nodes']}
        self.assertIn({'source': min(ids['Direct'], ids['Strength']),
                       'target': max(ids['Direct'], ids['Strength'])}, newer['links'])

    def test_secrets_redacted_and_script_payload_remains_json_data(self):
        credential = 'sk-or-v1-' + 'a' * 64
        self.note('p/Secret.md', 'API_KEY="local-private-value"\n' + credential + '\n</script><script>alert(1)</script>')
        graph = self.build.make_graph(self.root)
        self.assertNotIn(credential, graph['nodes'][0]['excerpt'])
        self.assertNotIn('local-private-value', graph['nodes'][0]['excerpt'])
        self.assertIn('[REDACTED]', graph['nodes'][0]['excerpt'])
        self.assertNotIn(credential, self.build.load_notes(self.root)[0]['content'])
        target = self.root / 'generated/graph-data.js'
        self.build.write_graph(graph, target)
        source = target.read_text(encoding='utf-8')
        self.assertTrue(source.startswith('const GRAPH = '))
        self.assertNotIn('</script>', source)
        self.assertEqual(json.loads(source[len('const GRAPH = '):].strip().removesuffix(';')), graph)


if __name__ == '__main__':
    unittest.main()
