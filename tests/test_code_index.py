"""code_index: hybrid Code RAG contracts.

This suite pins the behaviour of the hybrid search index end to end: the
path validation perimeter (allowed roots, ".." rejection, secret part
blocking with the ~/.jarvis-tools/projects sandbox exemption), the secret
file filter, Python/JS symbol and import extraction (BFS walk ordering of
ast.walk, level-1 relative imports captured as 'sib' while 'from . import x'
is dropped), the L2-normalised hashed subword vectors (camelCase identifier
equals its spaced words), the FTS5 query builder (stopwords, dedup, 14-token
cap, wildcard suffix), the incremental SQLite indexing (mtime+size skip,
touch re-index, stale removal, per-root cap, size gate, symlink and skip-dir
exclusion, 0600 DB / 0700 directory permissions, semantic-cache
invalidation), the AST import graph (both directions, path normalisation,
ghost/self exclusion), the RRF search envelope (limit=0 -> 8, hard cap 25,
auto-index vs explicit, global cross-root search) and the semantic cache
idle-eviction lifecycle (300 s threshold, backwards clock keeps entries).

All assertions were pinned empirically before writing, so the suite encodes
what the module actually does. Tests redirect the SQLite database into a
per-test sandbox by patching code_index.agent_cli.ROOT, and the context-pack
tests replace episodic_memory / agent_notes / context_compressor at the
sys.modules boundary.
"""
import os
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import code_index


def _seed_cache_roots(keys):
    with code_index._CACHE_LOCK:
        for key in keys:
            code_index._SEMANTIC_CACHE[key] = {
                'x.py': {'symbols': '', 'excerpt': '', 'vec': {}},
            }


def _set_cache_clock(value):
    with code_index._CACHE_LOCK:
        code_index._LAST_CACHE_ACCESS = value


class TestSparseVectorHelpers(unittest.TestCase):
    def test_embed_sparse_is_l2_normalized_and_deterministic(self):
        text = 'Jarvis hybrydowy indeks kodu'
        vec = code_index._embed_sparse(text)
        self.assertAlmostEqual(sum(v * v for v in vec.values()), 1.0, places=9)
        self.assertGreater(len(vec), 0)
        self.assertEqual(code_index._embed_sparse(text), vec)

    def test_embed_sparse_camelcase_equals_spaced_words(self):
        camel = code_index._embed_sparse('getUserProfile')
        spaced = code_index._embed_sparse('get user profile')
        self.assertEqual(camel, spaced)
        # 3 subword buckets plus the 4-char prefix bucket of 'profile'
        self.assertEqual(len(camel), 4)

    def test_embed_sparse_empty_and_stopword_only_inputs(self):
        for raw in ('', '   ', None, 'the and for with from'):
            self.assertEqual(code_index._embed_sparse(raw), {})

    def test_cosine_sparse_self_symmetry_and_empty(self):
        a = code_index._embed_sparse('zanzibar wenowaty indeks')
        b = code_index._embed_sparse('zanzibar wenowaty rozjazd')
        self.assertAlmostEqual(code_index._cosine_sparse(a, a), 1.0, places=9)
        self.assertEqual(code_index._cosine_sparse(a, b), code_index._cosine_sparse(b, a))
        self.assertEqual(code_index._cosine_sparse({}, a), 0.0)
        self.assertEqual(code_index._cosine_sparse(a, {}), 0.0)


class TestFtsQueryBuilder(unittest.TestCase):
    def test_dedup_stopwords_and_wildcard_suffix(self):
        raw = 'the and getUserProfile zanzibar getuserprofile'
        self.assertEqual(code_index._fts_query(raw), '"getuserprofile"* OR "zanzibar"*')

    def test_caps_at_14_tokens(self):
        raw = ' '.join(f'tok{i}word' for i in range(20))
        expected = ' OR '.join(f'"tok{i}word"*' for i in range(14))
        self.assertEqual(code_index._fts_query(raw), expected)

    def test_stopwords_only_query_is_empty(self):
        self.assertEqual(code_index._fts_query('the and or dla jak'), '')


class TestIsSafeSource(unittest.TestCase):
    def test_secret_names_are_rejected(self):
        for name in ('.env', '.env.local', 'secrets.json', 'auth.json', '.netrc',
                     '.git-credentials', 'id_rsa', 'id_ed25519'):
            self.assertFalse(code_index._is_safe_source(Path(name)), name)

    def test_indexable_suffixes_accepted(self):
        for name in ('a.py', 'a.js', 'a.ts', 'a.tsx', 'a.jsx', 'a.css', 'a.html',
                     'a.md', 'a.json', 'a.sh', 'a.toml', 'a.yaml', 'y.yml', 'a.YAML'):
            self.assertTrue(code_index._is_safe_source(Path(name)), name)

    def test_non_indexable_and_secret_suffixes_rejected(self):
        for name in ('a.txt', 'a.bin', 'noext', 'k.pem', 'k.key', 'k.p12', 'k.pfx',
                     'k.sqlite', 'k.sqlite3', 'k.db'):
            self.assertFalse(code_index._is_safe_source(Path(name)), name)


class TestSymbolExtraction(unittest.TestCase):
    def test_python_symbols_in_bfs_walk_order_with_dedup(self):
        src = ('class Foo:\n'
               '    def bar(self): pass\n'
               'async def baz(): pass\n'
               'def dup(): pass\n'
               'def dup(): pass\n')
        # ast.walk is breadth-first: Foo + module-level defs, then nested foo/bar
        self.assertEqual(code_index._extract_symbols(Path('a.py'), src), 'Foo baz dup bar')

    def test_python_syntax_error_yields_no_symbols(self):
        self.assertEqual(code_index._extract_symbols(Path('a.py'), 'def broken(:\n'), '')

    def test_symbol_cap_is_60(self):
        src = '\n'.join(f'def f{i}(): pass' for i in range(65))
        self.assertEqual(len(code_index._extract_symbols(Path('a.py'), src).split()), 60)

    def test_js_function_class_and_paren_const(self):
        src = ('function foo(){}\n'
               'class Bar{}\n'
               'const g = (x) => x;\n'
               'const h = async (y) => y;\n'
               'const v = 5;\n')
        # 'const v = 5' has no call parenthesis, so it is not a symbol
        self.assertEqual(code_index._extract_symbols(Path('a.js'), src), 'foo Bar g h')


class TestImportExtraction(unittest.TestCase):
    def test_python_imports_first_segment_and_relative_sibling(self):
        src = ('import os\n'
               'import a.b\n'
               'c.d\n'                 # attribute access, not an import
               'from mod import x\n'
               'from . import y\n'     # no module name: dropped
               'from .sib import z\n')
        self.assertEqual(code_index._extract_imports(Path('x.py'), src), 'os a mod sib')

    def test_python_syntax_error_yields_no_imports(self):
        self.assertEqual(code_index._extract_imports(Path('x.py'), 'import os\nfrom broken\n'), '')

    def test_js_imports_from_and_require_with_stem(self):
        src = "import A from 'mod'; import B from './util'; require('grp'); import 'side-effect.css';"
        # './util' is kept as its stem 'util'; side-effect imports are dropped
        self.assertEqual(code_index._extract_imports(Path('x.js'), src), 'mod util grp')

    def test_dedup_and_cap_50(self):
        src = '\n'.join(['import os', 'import os'] + [f'import m{i}()' for i in range(55)]
                        ).replace('()', '')
        mods = code_index._extract_imports(Path('x.py'), src).split()
        self.assertEqual(len(mods), 50)
        self.assertEqual(len(set(mods)), 50)
        self.assertEqual(mods[0], 'os')


class TestValidateSafeProjectDir(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix='cit_validate_')
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(self._tmp.name)
        self.fake_home = self.tmp / 'home'
        self.fake_home.mkdir()
        self._home_patcher = patch.dict(os.environ, {'HOME': str(self.fake_home)})
        self._home_patcher.start()
        self.addCleanup(self._home_patcher.stop)

    def test_empty_and_dotdot_rejected(self):
        with self.assertRaises(ValueError) as ctx:
            code_index.validate_safe_project_dir('   ')
        self.assertIn('Wymagana jest ścieżka', str(ctx.exception))
        with self.assertRaises(ValueError) as ctx:
            code_index.validate_safe_project_dir(str(self.tmp / 'x' / '..'))
        self.assertIn('".."', str(ctx.exception))

    def test_outside_allowed_roots_rejected(self):
        with self.assertRaises(ValueError) as ctx:
            code_index.validate_safe_project_dir('/etc')
        self.assertIn('dozwolonymi strefami', str(ctx.exception))

    def test_sensitive_parts_and_credential_dirs_rejected(self):
        for raw, fragment in (
            (str(self.tmp / '.ssh' / 'key'), 'wrażliwego'),
            (str(self.fake_home / '.mozilla' / 'x'), 'poświadczeń'),
        ):
            with self.assertRaises(ValueError) as ctx:
                code_index.validate_safe_project_dir(raw)
            self.assertIn(fragment, str(ctx.exception))

    def test_team_projects_sandbox_is_allowed(self):
        team = self.fake_home / '.jarvis-tools' / 'projects' / 'team'
        team.mkdir(parents=True)
        resolved = code_index.validate_safe_project_dir(team)
        self.assertEqual(resolved, team.resolve())

    def test_missing_directory_rejected(self):
        with self.assertRaises(ValueError) as ctx:
            code_index.validate_safe_project_dir(self.tmp / 'does-not-exist')
        self.assertIn('Katalog nie istnieje', str(ctx.exception))

    def test_returns_resolved_path(self):
        proj = self.tmp / 'proj'
        proj.mkdir()
        resolved = code_index.validate_safe_project_dir(str(proj))
        self.assertIsInstance(resolved, Path)
        self.assertEqual(resolved, proj.resolve())


class TestSemanticCacheEviction(unittest.TestCase):
    def setUp(self):
        code_index.evict_idle_cache(force=True)
        self.addCleanup(code_index.evict_idle_cache, force=True)
        self.addCleanup(_set_cache_clock, 0.0)

    def test_force_and_idle_eviction_semantics(self):
        self.assertEqual(code_index.evict_idle_cache(force=True), 0)  # empty cache: no-op
        _seed_cache_roots(['rootA', 'rootB'])
        _set_cache_clock(400.0)
        # A clock moved backwards counts as active: entries survive
        self.assertEqual(code_index.evict_idle_cache(now=100.0), 0)
        self.assertEqual(code_index.cache_stats()['roots_cached'], 2)
        _set_cache_clock(10.0)
        self.assertEqual(code_index.evict_idle_cache(now=400.0), 2)  # >= 300 s idle clears all
        self.assertEqual(code_index.cache_stats()['roots_cached'], 0)

    def test_idle_seconds_zero_when_never_accessed(self):
        _set_cache_clock(0.0)
        self.assertEqual(code_index.cache_stats()['idle_seconds'], 0.0)


class CodeIndexDbBase(unittest.TestCase):
    """Base class redirecting the SQLite index into a per-test sandbox."""

    def setUp(self):
        code_index.evict_idle_cache(force=True)
        self._tmp = tempfile.TemporaryDirectory(prefix='cit_db_')
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(self._tmp.name)
        self.agents_dir = self.tmp / 'agents'  # left for code_index to create (0700)
        self._cli_patcher = patch.object(
            code_index, 'agent_cli', SimpleNamespace(ROOT=self.agents_dir / 'agent_cli.py'))
        self._cli_patcher.start()
        self.addCleanup(self._cli_patcher.stop)
        self.addCleanup(code_index.evict_idle_cache, force=True)

    def make_project(self, name='proj'):
        proj = self.tmp / name
        proj.mkdir()
        return proj

    def root_key(self, proj):
        return str(Path(proj).resolve())

    def write(self, proj, rel, text):
        target = proj / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding='utf-8')
        return target

    def db_row_counts(self, root_key):
        conn = sqlite3.connect(self.agents_dir / 'code_index.sqlite3')
        try:
            files = conn.execute(
                'SELECT COUNT(*) FROM files_meta WHERE root = ?', (root_key,)).fetchone()[0]
            fts = conn.execute(
                'SELECT COUNT(*) FROM docs_fts WHERE root = ?', (root_key,)).fetchone()[0]
        finally:
            conn.close()
        return files, fts

    def db_rel_paths(self, root_key):
        conn = sqlite3.connect(self.agents_dir / 'code_index.sqlite3')
        try:
            return {row[0] for row in conn.execute(
                'SELECT rel_path FROM files_meta WHERE root = ?', (root_key,))}
        finally:
            conn.close()


class TestIndexDirectory(CodeIndexDbBase):
    def test_fresh_index_skips_secret_and_excluded_paths(self):
        proj = self.make_project()
        self.write(proj, 'a.py', 'import util\ndef alpha():\n    zanzibar\n')
        self.write(proj, 'b.py', 'def beta(): pass\n')
        self.write(proj, 'notes.md', 'zanzibar readme\n')
        self.write(proj, 'node_modules/nm.py', 'zanzibar\n')
        self.write(proj, '.git/g.py', 'zanzibar\n')
        self.write(proj, '.jarvis-cache/j.py', 'zanzibar\n')
        self.write(proj, '.env', 'SECRET=zanzibar\n')
        result = code_index.index_directory(proj)
        self.assertTrue(result['ok'])
        self.assertEqual(result['root'], self.root_key(proj))
        self.assertEqual(result['indexed'], 3)
        self.assertEqual((result['skipped'], result['removed']), (0, 0))
        self.assertIsInstance(result['elapsed_ms'], float)
        files, fts = self.db_row_counts(self.root_key(proj))
        self.assertEqual((files, fts), (3, 3))
        self.assertNotIn('node_modules/nm.py', self.db_rel_paths(self.root_key(proj)))

    def test_incremental_runs_skip_touch_and_delete(self):
        proj = self.make_project()
        a = self.write(proj, 'a.py', 'zanzibar first\n')
        self.write(proj, 'b.py', 'zanzibar second\n')
        first = code_index.index_directory(proj)
        self.assertEqual((first['indexed'], first['skipped']), (2, 0))
        second = code_index.index_directory(proj)
        self.assertEqual((second['indexed'], second['skipped']), (0, 2))
        os.utime(a, (12345.0, 12345.0))  # old timestamp forces re-index of 'a.py'
        third = code_index.index_directory(proj)
        self.assertEqual((third['indexed'], third['skipped']), (1, 1))
        a.unlink()
        fourth = code_index.index_directory(proj)
        self.assertEqual((fourth['indexed'], fourth['skipped'], fourth['removed']), (0, 1, 1))

    def test_database_and_directory_permissions(self):
        proj = self.make_project()
        self.write(proj, 'a.py', 'zanzibar\n')
        code_index.index_directory(proj)
        db = self.agents_dir / 'code_index.sqlite3'
        self.assertEqual(db.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.agents_dir.stat().st_mode & 0o777, 0o700)

    def test_per_root_file_cap(self):
        proj = self.make_project()
        for i in range(3):
            self.write(proj, f'f{i}.py', f'zanzibar {i}\n')
        with patch.object(code_index, 'MAX_FILES_PER_ROOT', 2):
            result = code_index.index_directory(proj)
        self.assertEqual((result['indexed'], result['skipped']), (2, 0))
        self.assertEqual(self.db_rel_paths(self.root_key(proj)), {'f0.py', 'f1.py'})

    def test_file_size_gate(self):
        proj = self.make_project()
        self.write(proj, 'small.py', 'zanzibar tiny\n')
        self.write(proj, 'big.py', 'x' * 200)
        with patch.object(code_index, 'MAX_INDEX_FILE_BYTES', 100):
            result = code_index.index_directory(proj)
        self.assertEqual(result['indexed'], 1)
        _, fts = self.db_row_counts(self.root_key(proj))
        self.assertEqual(fts, 1)

    def test_symlinks_are_not_indexed(self):
        proj = self.make_project()
        target = self.tmp / 'outside.py'
        target.write_text('zanzibar outside\n', encoding='utf-8')
        os.symlink(target, proj / 'link.py')
        result = code_index.index_directory(proj)
        self.assertEqual((result['indexed'], result['skipped']), (0, 0))

    def test_invalid_root_returns_error_envelope(self):
        raw = str(self.tmp / 'x' / '..')
        result = code_index.index_directory(raw)
        self.assertFalse(result['ok'])
        self.assertEqual(result['root'], raw)
        self.assertIn('".."', result['error'])
        self.assertEqual((result['indexed'], result['skipped'], result['removed']), (0, 0, 0))

    def test_indexing_invalidates_semantic_cache_for_root(self):
        proj = self.make_project()
        self.write(proj, 'a.py', 'zanzibar fresh\n')
        key = self.root_key(proj)
        _seed_cache_roots([key])
        result = code_index.index_directory(proj)
        self.assertEqual(result['indexed'], 1)
        with code_index._CACHE_LOCK:
            self.assertNotIn(key, code_index._SEMANTIC_CACHE)


class TestRelatedFiles(CodeIndexDbBase):
    def _index_sample(self):
        proj = self.make_project()
        self.write(proj, 'prod.py', 'import util\ndef alpha(): pass\n')
        self.write(proj, 'sub.py', 'from util import helper\n')
        self.write(proj, 'util.py', 'def helper(): pass\n')
        code_index.index_directory(proj)
        return proj

    def test_imports_and_imported_by_directions(self):
        proj = self._index_sample()
        self.assertEqual(code_index.related_files('prod.py', proj),
                         {'path': 'prod.py', 'imports': ['util.py'], 'imported_by': []})
        self.assertEqual(code_index.related_files('util.py', proj),
                         {'path': 'util.py', 'imports': [], 'imported_by': ['prod.py', 'sub.py']})

    def test_path_normalisation_strips_leading_separator(self):
        proj = self._index_sample()
        self.assertEqual(code_index.related_files('/prod.py', proj)['imports'], ['util.py'])
        self.assertEqual(code_index.related_files('\\prod.py', proj)['imports'], ['util.py'])

    def test_missing_stem_and_self_import_ignored(self):
        proj = self.make_project()
        self.write(proj, 'a.py', 'import ghost\nimport a\n')
        code_index.index_directory(proj)
        self.assertEqual(code_index.related_files('a.py', proj),
                         {'path': 'a.py', 'imports': [], 'imported_by': []})


class TestSearchContext(CodeIndexDbBase):
    def test_root_scoped_search_returns_scored_hits(self):
        proj = self.make_project()
        self.write(proj, 'util.py', 'def helper():\n    zanzibar\n')
        self.write(proj, 'prod.py', 'import util\ndef alpha():\n    zanzibar\n')
        hits = code_index.search_context('zanzibar', root_dir=proj)  # auto_index default True
        self.assertEqual({h['path'] for h in hits}, {'util.py', 'prod.py'})
        for hit in hits:
            self.assertEqual(hit['root'], self.root_key(proj))
            self.assertIsInstance(hit['score'], float)
            self.assertGreater(hit['score'], 0.0)
            self.assertLessEqual(len(hit['excerpt']), 320)
            self.assertIn('symbols', hit)

    def test_stopword_only_query_returns_no_hits(self):
        proj = self.make_project()
        self.write(proj, 'a.py', 'zanzibar\n')
        self.assertEqual(code_index.search_context('the and dla', root_dir=proj), [])

    def test_global_search_spans_indexed_roots(self):
        proj = self.make_project('globproj')
        self.write(proj, 'marker.py', 'zanzibar globalhit\n')
        code_index.index_directory(proj)
        hits = code_index.search_context('globalhit', root_dir=None)
        self.assertTrue(any(
            h['path'] == 'marker.py' and h['root'] == self.root_key(proj) for h in hits))

    def test_limit_zero_falls_back_to_eight(self):
        proj = self.make_project()
        for i in range(10):
            self.write(proj, f't{i}.py', f'zanzibar body{i} tail\n')
        self.assertEqual(len(code_index.search_context('zanzibar', root_dir=proj, limit=0)), 8)

    def test_limit_is_capped_at_25(self):
        proj = self.make_project()
        for i in range(30):
            self.write(proj, f't{i}.py', f'zanzibar body{i} tail\n')
        self.assertEqual(len(code_index.search_context('zanzibar', root_dir=proj, limit=999)), 25)

    def test_auto_index_false_does_not_index_unknown_root(self):
        proj = self.make_project()
        self.write(proj, 'fresh.py', 'zanzibar unseen\n')
        self.assertEqual(code_index.search_context('zanzibar', root_dir=proj, auto_index=False), [])

    def test_semantic_cache_lifecycle_around_search(self):
        proj = self.make_project()
        self.write(proj, 'a.py', 'zanzibar cacheprobe\n')
        key = self.root_key(proj)
        code_index.search_context('cacheprobe', root_dir=proj)
        with code_index._CACHE_LOCK:
            self.assertIn(key, code_index._SEMANTIC_CACHE)
        self.assertGreaterEqual(code_index.cache_stats()['roots_cached'], 1)
        code_index.evict_idle_cache(force=True)
        with code_index._CACHE_LOCK:
            self.assertNotIn(key, code_index._SEMANTIC_CACHE)
        self.assertEqual(code_index.cache_stats()['roots_cached'], 0)


class TestBuildContextPack(CodeIndexDbBase):
    """Markdown pack composition with episodic memory, agent notes and the
    AST skeletoniser patched at the sys.modules boundary."""

    def _patch_mind(self, episodes=None, notes=None, skeleton=None, episodes_raise=False):
        def _recall(query, limit=3):
            if episodes_raise:
                raise RuntimeError('episodic store offline')
            return list(episodes or [])

        fake_episodic = SimpleNamespace(recall_episodes=_recall)
        fake_notes = SimpleNamespace(search=lambda query: list(notes or []))
        fake_compressor = SimpleNamespace(
            skeletonize_python=lambda text, max_chars=1200: skeleton or '')
        return patch.dict(sys.modules, {
            'episodic_memory': fake_episodic,
            'agent_notes': fake_notes,
            'context_compressor': fake_compressor,
        })

    def test_no_sources_yields_empty_pack(self):
        proj = self.make_project()
        self.write(proj, 'a.py', 'zanzibar\n')
        with self._patch_mind():
            self.assertEqual(code_index.build_context_pack('the and dla', root_dir=proj), '')

    def test_pack_lists_hits_symbols_skeleton_and_ast_links(self):
        proj = self.make_project()
        self.write(proj, 'util.py', 'def helper():\n    zanzibar\n')
        self.write(proj, 'prod.py', 'import util\ndef alpha():\n    zanzibar\n')
        with self._patch_mind(skeleton='def skel(): pass'):
            pack = code_index.build_context_pack('zanzibar', root_dir=proj)
        self.assertTrue(pack.startswith('## Trafny kontekst'))
        self.assertIn('`util.py`', pack)
        self.assertIn('symbole: `helper`', pack)
        self.assertIn('powiązane AST: `prod.py`', pack)
        self.assertIn('powiązane AST: `util.py`', pack)
        self.assertGreater(pack.count('\n  > '), 0)
        self.assertIn('Szkielet sygnatur AST (`util.py`)', pack)
        self.assertIn('def skel(): pass', pack)

    def test_pack_includes_episodic_memory_and_agent_notes(self):
        proj = self.make_project()
        self.write(proj, 'a.py', 'zanzibar memory\n')
        episodes = [{'kind': 'decision', 'title': 'T Dez', 'summary': 'S'}]
        notes = [{'title': 'N1'}, {'path': 'p2.md'}]
        with self._patch_mind(episodes=episodes, notes=notes):
            pack = code_index.build_context_pack('zanzibar', root_dir=proj)
        self.assertIn('Pamięć epizodyczna', pack)
        self.assertIn('[decision] **T Dez**: S', pack)
        self.assertIn('Powiązane wcześniejsze notatki agentów', pack)
        self.assertIn('  - N1', pack)
        self.assertIn('  - p2.md', pack)

    def test_episodic_failure_is_isolated(self):
        proj = self.make_project()
        self.write(proj, 'a.py', 'zanzibar resilient\n')
        with self._patch_mind(episodes_raise=True):
            pack = code_index.build_context_pack('zanzibar', root_dir=proj)
        self.assertIn('`a.py`', pack)
        self.assertNotIn('Pamięć epizodyczna', pack)


if __name__ == '__main__':
    unittest.main()
