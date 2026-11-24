"""episodic_memory: FTS5 episode store, recall ranking and event hook contracts.

The store itself is real SQLite in a sandboxed root (agent_cli patched to a
tmp dir), pinning the genuine CREATE/INSERT/FTS5 behaviour: WAL schema created
on demand, 0600 file in a 0700 dir, clips and kind normalisation, BM25 recall
with the actual column-weight mapping (episode_id absorbs the first weight,
making the title column the heaviest at 5.0 — observed, documented, not
changed), the 2000-episode retention eviction, and the `handle_bus_event`
auto-recorder for owner answers, tripped circuit breakers and night shifts.
"""
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import episodic_memory
from episodic_memory import (
    MAX_EPISODES,
    VALID_KINDS,
    _fts_query,
    handle_bus_event,
    memory_stats,
    recall_episodes,
    remember_episode,
)


class EpisodicBase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.db_file = self.tmp / 'agents' / 'episodic_memory.sqlite3'
        self.now = [1000.0]
        fakes = dict(
            agent_cli=SimpleNamespace(ROOT=self.tmp / 'agents' / 'agent_cli.py'),
            time=SimpleNamespace(time=lambda: self.now[0]),
        )
        for name, fake in fakes.items():
            patcher = patch.object(episodic_memory, name, fake)
            patcher.start()
            self.addCleanup(patcher.stop)

    def tick(self, step=10.0):
        self.now[0] += step
        return self.now[0]

    def seed(self, count, *, base=0.0):
        """Bulk-insert episodes through the module's own connection helper."""
        conn = episodic_memory._connect()
        try:
            with conn:
                for i in range(count):
                    cur = conn.execute(
                        "INSERT INTO episodes (created_at, kind, project_id, title, "
                        "summary, tags) VALUES (?, 'note', '', ?, ?, '')",
                        (base + i, f'Seed {i}', f'summar seed {i}'),
                    )
                    conn.execute(
                        "INSERT INTO episodes_fts (episode_id, kind, title, summary, tags) "
                        "VALUES (?, 'note', ?, ?, '')",
                        (cur.lastrowid, f'Seed {i}', f'summar seed {i}'),
                    )
        finally:
            conn.close()

    def counts(self):
        conn = episodic_memory._connect()
        try:
            ep = conn.execute("SELECT COUNT(*) AS c FROM episodes").fetchone()['c']
            fts = conn.execute("SELECT COUNT(*) AS c FROM episodes_fts").fetchone()['c']
        finally:
            conn.close()
        return ep, fts


class RememberAndValidate(EpisodicBase):
    def test_kind_normalisation_matrix(self):
        for kind, expected in (('decision', 'decision'), ('DECISION', 'decision'),
                               ('', 'note'), (None, 'note'), ('bogus', 'note')):
            with self.subTest(kind=kind):
                record = remember_episode('Tytuł', 'Streszczenie', kind=kind)
                self.assertEqual(record['kind'], expected)

    def test_empty_fields_refused(self):
        for title, summary in (('', 'x'), ('   ', 'x'), ('t', ''), ('t', ' \t ')):
            with self.subTest(title=title):
                with self.assertRaises(ValueError) as ctx:
                    remember_episode(title, summary)
                self.assertIn('Wymagane są pola title oraz summary',
                              str(ctx.exception))

    def test_clips_and_stripping(self):
        record = remember_episode('  T  '.join(['x'] * 500), 'y' * 5000,
                                  tags='t' * 500, project_id='p' * 200)
        self.assertEqual(len(record['title']), 200)
        self.assertEqual(len(record['summary']), 3000)
        self.assertEqual(len(record['tags']), 240)
        self.assertEqual(len(record['project_id']), 80)

    def test_tags_forms(self):
        record = remember_episode('T', 'S', tags=['alpha', '', 'beta', '  '])
        self.assertEqual(record['tags'], 'alpha beta')
        # the plain-string form only strips the ends; inner spacing is kept
        record = remember_episode('T', 'S', tags=' gamma  delta ')
        self.assertEqual(record['tags'], 'gamma  delta')

    def test_record_shape_persisted_and_fts_synced(self):
        self.tick()
        record = remember_episode('Wybór bazy', 'Używamy SQLite z FTS5',
                                  kind='bugfix', tags=['db', 'fts'],
                                  project_id='proj-1')
        self.assertEqual(
            record, {'id': 1, 'created_at': self.now[0], 'kind': 'bugfix',
                     'project_id': 'proj-1', 'title': 'Wybór bazy',
                     'summary': 'Używamy SQLite z FTS5', 'tags': 'db fts'})
        self.assertEqual(self.db_file.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.db_file.parent.stat().st_mode & 0o777, 0o700)
        episodes, fts = self.counts()
        self.assertEqual((episodes, fts), (1, 1))
        # the row is retrievable through the FTS join the recall path uses
        hit = recall_episodes('sqlite fts', limit=5)
        self.assertEqual(len(hit), 1)
        self.assertEqual(hit[0]['id'], record['id'])


class FtsQueryBuilding(EpisodicBase):
    def test_token_filtering_and_dedupe(self):
        # 1-2 char tokens and stopwords (PL+EN) are dropped; order preserved
        self.assertEqual(_fts_query('Ala ma kota'), '"ala"* OR "kota"*')
        self.assertEqual(_fts_query('the and for with'), '')
        self.assertEqual(_fts_query('kota kota kota'), '"kota"*')
        self.assertEqual(_fts_query('plik kod przy przez'), '')

    def test_polish_diacritics_and_case_folding(self):
        self.assertEqual(_fts_query('ŻÓŁW żółć żółw'),
                         '"żółw"* OR "żółć"*')

    def test_cap_twelve_tokens(self):
        query = ' '.join(f'tok{i}' for i in range(20))
        built = _fts_query(query)
        self.assertEqual(len(built.split(' OR ')), 12)
        self.assertIn('"tok0"*', built)
        self.assertNotIn('"tok12"*', built)

    def test_garbage_and_empty_return_no_query(self):
        for raw in ('', '!!! ???', 12):
            self.assertEqual(_fts_query(raw), '')
        # digit runs of length >= 3 are valid tokens
        self.assertEqual(_fts_query(12345), '"12345"*')


class RecallLatest(EpisodicBase):
    def test_empty_query_returns_latest_first(self):
        for i in range(3):
            self.tick()
            remember_episode(f'Ep {i}', f'Treść {i}', kind='decision',
                             project_id=f'p{i}')
        rows = recall_episodes()
        self.assertEqual([r['title'] for r in rows], ['Ep 2', 'Ep 1', 'Ep 0'])
        self.assertEqual(rows[0]['project_id'], 'p2')
        # the latest branch carries no BM25 score
        self.assertNotIn('score', rows[0])
        self.assertEqual(sorted(rows[0]),
                         ['created_at', 'id', 'kind', 'project_id',
                          'summary', 'tags', 'title'])

    def test_kind_filter_on_latest_branch(self):
        for kind in ('decision', 'bugfix', 'decision', 'note'):
            self.tick()
            remember_episode(f'Ep {kind} {self.now[0]}', 'Treść', kind=kind)
        rows = recall_episodes(kind='DECISION')
        self.assertEqual(len(rows), 2)
        self.assertTrue(all(r['kind'] == 'decision' for r in rows))
        # newest decision first
        self.assertGreater(rows[0]['created_at'], rows[1]['created_at'])

    def test_limit_clamps(self):
        for i in range(8):
            self.tick()
            remember_episode(f'Ep {i}', 'Treść')
        self.assertEqual(len(recall_episodes(limit=0)), 6)      # falsy -> default 6
        self.assertEqual(len(recall_episodes(limit=99)), 8)    # capped at 30, 8 exist
        self.assertEqual(len(recall_episodes(limit=-5)), 1)
        self.assertEqual(len(recall_episodes(limit=3)), 3)


class RecallFts(EpisodicBase):
    def test_prefix_match_and_score_key(self):
        self.tick()
        remember_episode('Ogłoszenie', 'Migracja na kubernetes w produkcji')
        rows = recall_episodes('kuber', limit=5)     # prefix hit
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['title'], 'Ogłoszenie')
        self.assertIn('score', rows[0])
        self.assertEqual(sorted(rows[0]),
                         ['created_at', 'id', 'kind', 'project_id', 'score',
                          'summary', 'tags', 'title'])
        # On a 1-row corpus BM25 ranks collapse to ~1e-06 and the published
        # score is rounded to 3 decimals: 0.0 (ranking itself stays correct).
        self.assertEqual(rows[0]['score'], 0.0)

    def test_score_becomes_visible_on_a_fuller_corpus(self):
        self.seed(15)
        self.tick()
        remember_episode('Ogłoszenie', 'Migracja na kubernetes w produkcji')
        rows = recall_episodes('kubernetes', limit=5)
        self.assertEqual([r['title'] for r in rows], ['Ogłoszenie'])
        self.assertGreater(rows[0]['score'], 0.0)     # e.g. 3.346 on 16 rows

    def test_title_match_ranks_above_summary_match(self):
        # bm25(episodes_fts, 0.0, 2.0, 5.0, 2.5, 3.0) maps the five weights onto
        # (episode_id, kind, title, summary, tags) — episode_id absorbs 0.0, so
        # the effective weights are kind 2.0 / title 5.0 / summary 2.5 / tags 3.0
        # and a title hit outranks a summary hit. Pinned as observed behaviour.
        self.tick()
        remember_episode('kubernetes w tytule', 'nic istotnego')
        self.tick()
        remember_episode('Inny kontekst', 'Kluczowa sprawa: kubernetes w produkcji')
        rows = recall_episodes('kubernetes', limit=5)
        self.assertEqual(len(rows), 2)
        # order comes straight from SQLite's raw bm25 rank (title hit first);
        # the published, 3-decimal-rounded scores tie at 0.0 on this micro corpus
        self.assertEqual(rows[0]['title'], 'kubernetes w tytule')
        self.assertGreaterEqual(rows[0]['score'], rows[1]['score'])

    def test_polish_diacritics_match(self):
        remember_episode('Notatka o żółwiu', 'zupełnie osobna treść')
        rows = recall_episodes('żółw', limit=5)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['title'], 'Notatka o żółwiu')

    def test_kind_filter_inside_fts(self):
        remember_episode('Wyjątek w deployu', 'kubernetes crash', kind='incident')
        remember_episode('Runbook', 'kubernetes procedura', kind='maintenance')
        rows = recall_episodes('kubernetes', kind='incident', limit=5)
        self.assertEqual([r['title'] for r in rows], ['Wyjątek w deployu'])

    def test_fts_operational_error_returns_empty(self):
        remember_episode('Cokolwiek', 'treść')
        with patch.object(episodic_memory, '_fts_query', lambda raw: '")('):
            self.assertEqual(recall_episodes('cokolwiek'), [])

    def test_no_hits_returns_empty(self):
        remember_episode('Cokolwiek', 'treść')
        self.assertEqual(recall_episodes('nieistniejącytokenxyz'), [])


class Retention(EpisodicBase):
    def test_overflow_evicts_oldest_and_keeps_fts_in_sync(self):
        self.seed(MAX_EPISODES)                      # exactly at the limit: no eviction
        self.assertEqual(self.counts(), (MAX_EPISODES, MAX_EPISODES))
        self.tick(step=100000.0)
        record = remember_episode('Nowy incydent', 'przepełnienie magazynu',
                                  kind='incident')
        episodes, fts = self.counts()
        self.assertEqual((episodes, fts), (MAX_EPISODES, MAX_EPISODES))
        # the oldest seed was evicted from both tables, the new one persisted
        conn = episodic_memory._connect()
        try:
            gone = conn.execute(
                "SELECT COUNT(*) AS c FROM episodes WHERE title = 'Seed 0'"
            ).fetchone()['c']
            kept = conn.execute(
                "SELECT COUNT(*) AS c FROM episodes WHERE title = 'Seed 1'"
            ).fetchone()['c']
        finally:
            conn.close()
        self.assertEqual((gone, kept), (0, 1))
        self.assertEqual(recall_episodes('nowy incydent')[0]['id'], record['id'])

    def test_exact_limit_does_not_evict(self):
        self.seed(MAX_EPISODES - 1)
        remember_episode('Dwutysięczny', 'brak przepełnienia')
        conn = episodic_memory._connect()
        try:
            oldest = conn.execute(
                "SELECT COUNT(*) AS c FROM episodes WHERE title = 'Seed 0'"
            ).fetchone()['c']
        finally:
            conn.close()
        self.assertEqual(oldest, 1)
        self.assertEqual(self.counts(), (MAX_EPISODES, MAX_EPISODES))


class MemoryStats(EpisodicBase):
    def test_shape_and_grouping(self):
        for i in range(7):
            self.tick()
            kind = ('decision', 'bugfix', 'decision')[i % 3]
            remember_episode(f'Ep {i}', 'Treść', kind=kind)
        stats = memory_stats()
        self.assertEqual(stats['ok'], True)
        self.assertEqual(stats['total'], 7)
        self.assertEqual(stats['by_kind'], {'decision': 5, 'bugfix': 2})
        # recent is capped at 5, no summary column
        self.assertEqual(len(stats['recent']), 5)
        self.assertEqual(sorted(stats['recent'][0]),
                         ['created_at', 'id', 'kind', 'project_id', 'tags', 'title'])
        newest_first = [r['created_at'] for r in stats['recent']]
        self.assertEqual(newest_first, sorted(newest_first, reverse=True))

    def test_valid_kinds_constant(self):
        self.assertEqual(
            VALID_KINDS,
            ('decision', 'bugfix', 'preference', 'incident', 'maintenance', 'note'))


class BusEventHook(EpisodicBase):
    def test_owner_answered_records_decision(self):
        self.tick()
        handle_bus_event({'topic': 'owner.answered', 'data': {
            'question': 'Czy użyć Postgresa?',
            'answer': 'Nie, zostajemy przy SQLite',
            'from': 'architekt',
            'source': 'web-ui',
            'project_id': 'proj-9'}})
        rows = recall_episodes(kind='decision')
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['title'], 'Decyzja właściciela: Czy użyć Postgresa?')
        self.assertEqual(
            rows[0]['summary'],
            'Pytanie agenta (architekt): Czy użyć Postgresa?\n'
            'Odpowiedź właściciela: Nie, zostajemy przy SQLite')
        self.assertEqual(rows[0]['tags'], 'owner architekt web-ui')
        self.assertEqual(rows[0]['project_id'], 'proj-9')

    def test_circuit_tripped_records_incident_with_defaults(self):
        handle_bus_event({'topic': 'router.circuit_tripped',
                          'data': {'error_kind': 'rate_limit',
                                   'error_hint': 'HTTP 429 po 60 s'}})
        rows = recall_episodes(kind='incident')
        self.assertEqual(rows[0]['title'],
                         'Bezpiecznik API agenta agent: rate_limit')
        self.assertIn('HTTP 429', rows[0]['summary'])
        self.assertEqual(rows[0]['tags'], 'agent rate_limit circuit_breaker')

        self.tick()
        handle_bus_event({'topic': 'router.circuit_tripped',
                          'data': {'agent': 'claude'}})
        rows = recall_episodes(kind='incident')
        self.assertEqual(rows[0]['title'], 'Bezpiecznik API agenta claude: error')

    def test_night_shift_completed_records_maintenance_with_qa_tag(self):
        self.tick()
        payload = {'viewer_qa_ok': True, 'fixed': 2, 'modules': ['preflight']}
        handle_bus_event({'topic': 'night_shift.completed', 'data': payload})
        rows = recall_episodes(kind='maintenance')
        self.assertEqual(rows[0]['title'], 'Zakończono cykl Nocnej Zmiany')
        self.assertEqual(rows[0]['summary'],
                         json.dumps(payload, ensure_ascii=False))
        self.assertEqual(rows[0]['tags'], 'night_shift qa_ok')

        self.tick()
        handle_bus_event({'topic': 'night_shift.completed', 'data': {}})
        rows = recall_episodes(kind='maintenance')
        self.assertEqual(rows[0]['tags'], 'night_shift qa_issue')

    def test_ignored_events_record_nothing(self):
        before = memory_stats()['total']
        handle_bus_event('not a dict')
        handle_bus_event({'topic': 'unknown.topic', 'data': {'x': 1}})
        handle_bus_event({'topic': 'owner.answered',
                         'data': 'not-a-dict'})
        handle_bus_event({'topic': 'owner.answered',
                         'data': {'question': 'Q?', 'answer': ''}})
        handle_bus_event({'topic': 'owner.answered',
                          'data': {'answer': 'A', 'question': '  '}})
        self.assertEqual(memory_stats()['total'], before)

    def test_store_failure_is_swallowed(self):
        def boom(*args, **kwargs):
            raise RuntimeError('db down')

        with patch.object(episodic_memory, 'remember_episode', boom):
            self.assertIsNone(handle_bus_event(
                {'topic': 'night_shift.completed', 'data': {}}))
        self.assertEqual(memory_stats()['total'], 0)


if __name__ == '__main__':
    unittest.main()
