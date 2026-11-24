"""Consent for agent runs: one-time, bound to one task, and spoken if requested."""
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

import agent_consent
from operator_modules import agents as agents_module


class ConsentStoreRaceTests(unittest.TestCase):
    """The store is written from both the grant and the consume route."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        env = patch.object(agent_consent, 'STORE', Path(self.tmp.name) / 'consent.json')
        env.start()
        self.addCleanup(env.stop)

    def test_concurrent_saves_leave_one_consistent_generation(self):
        # ThreadingHTTPServer serves /agents/consent and /agents/run in
        # parallel: the static '.tmp' suffix used to serialize both writers
        # onto one file, so one save could clobber or read the other's temp.
        # With per-save temps every save lands whole.
        grants = []
        lock = threading.Lock()
        errors: list[Exception] = []

        def do_grant(i):
            try:
                g = agent_consent.grant('claude', f'zadanie race {i}')
                with lock:
                    grants.append(g)
            except Exception as error:  # pragma: no cover - reported below
                with lock:
                    errors.append(error)

        threads = [threading.Thread(target=do_grant, args=(i,)) for i in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        self.assertEqual(errors, [])
        rows = agent_consent._load()
        self.assertEqual(len(rows), 8)
        # The store file stays whole; no temp files survive.
        leftovers = [p.name for p in Path(self.tmp.name).iterdir()
                     if p.name.endswith('.tmp')]
        self.assertEqual(leftovers, [])


class ConsentTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        env = patch.object(agent_consent, 'STORE', Path(self.tmp.name) / 'consent.json')
        env.start()
        self.addCleanup(env.stop)

    def test_an_affirmative_must_be_a_whole_answer(self):
        for phrase in ('tak', 'Tak.', 'zgadzam się', 'ZGADZAM SIE', 'yes', 'approve',
                       'uruchom agenta', 'go ahead'):
            with self.subTest(phrase=phrase):
                self.assertTrue(agent_consent.is_affirmative(phrase), phrase)
        for phrase in ('tak, ale najpierw sprawdź pliki', 'nie', 'może później',
                       'zgadzam się, ale nie teraz', 'no'):
            with self.subTest(phrase=phrase):
                self.assertFalse(agent_consent.is_affirmative(phrase), phrase)

    def test_a_grant_is_single_use(self):
        grant = agent_consent.grant('claude', 'zadanie')
        agent_consent.consume(grant['token'], 'claude', 'zadanie')
        with self.assertRaises(agent_consent.ConsentError) as caught:
            agent_consent.consume(grant['token'], 'claude', 'zadanie')
        self.assertIn('already used', str(caught.exception))

    def test_a_grant_for_one_task_cannot_unlock_another(self):
        grant = agent_consent.grant('claude', 'zadanie A')
        with self.assertRaises(agent_consent.ConsentError) as caught:
            agent_consent.consume(grant['token'], 'claude', 'zadanie B')
        self.assertIn('different task', str(caught.exception))
        with self.assertRaises(agent_consent.ConsentError):
            agent_consent.consume(grant['token'], 'opencode', 'zadanie A')

    def test_a_grant_expires(self):
        import time as clock
        granted_at = clock.time()
        grant = agent_consent.grant('claude', 'zadanie')
        later = granted_at + agent_consent.TTL_SECONDS + 5
        with patch.object(agent_consent.time, 'time', return_value=later):
            with self.assertRaises(agent_consent.ConsentError) as caught:
                agent_consent.consume(grant['token'], 'claude', 'zadanie')
        self.assertIn('expired', str(caught.exception))

    def test_a_garbage_token_is_refused(self):
        for token in ('', None, 'not-a-token', 'x' * 32):
            with self.subTest(token=token):
                with self.assertRaises(agent_consent.ConsentError):
                    agent_consent.consume(token, 'claude', 'zadanie')

    def test_spoken_consent_requires_the_phrase(self):
        with self.assertRaises(agent_consent.ConsentError):
            agent_consent.grant_spoken('claude', 'zadanie', 'nie, poczekaj')
        grant = agent_consent.grant_spoken('claude', 'zadanie', 'zgadzam się')
        self.assertTrue(grant['spoken'])
        row = agent_consent.consume(grant['token'], 'claude', 'zadanie')
        self.assertTrue(row['spoken'])

    def test_the_store_is_private(self):
        agent_consent.grant('claude', 'zadanie')
        self.assertEqual(agent_consent.STORE.stat().st_mode & 0o777, 0o600)


class AgentToolTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        for name, value in (('STORE', Path(self.tmp.name) / 'consent.json'),):
            env = patch.object(agent_consent, name, value)
            env.start()
            self.addCleanup(env.stop)

    def test_run_without_a_consent_token_is_allowed(self):
        with patch('agent_cli.run', return_value={'ok': True, 'status': 'done'}) as run:
            result = agents_module.agents({'action': 'run', 'agent': 'claude', 'task': 'x'}, {})
        self.assertTrue(result['ok'])
        self.assertEqual(result['consent'], 'direct')
        run.assert_called_once()

    def test_run_consumes_the_token_and_reports_how_it_was_given(self):
        grant = agent_consent.grant_spoken('claude', 'zadanie', 'tak')
        with patch('agent_cli.run', return_value={'ok': True, 'status': 'done'}) as run:
            result = agents_module.agents({'action': 'run', 'agent': 'claude',
                                           'task': 'zadanie', 'consent': grant['token']}, {})
        self.assertTrue(result['ok'])
        self.assertEqual(result['consent'], 'spoken')
        run.assert_called_once()
        self.assertTrue(run.call_args.kwargs['approved'])

    def test_a_used_token_cannot_start_a_second_run(self):
        grant = agent_consent.grant('claude', 'zadanie')
        with patch('agent_cli.run', return_value={'ok': True}):
            agents_module.agents({'action': 'run', 'agent': 'claude', 'task': 'zadanie',
                                  'consent': grant['token']}, {})
            with patch('agent_cli.run') as second:
                result = agents_module.agents({'action': 'run', 'agent': 'claude',
                                               'task': 'zadanie', 'consent': grant['token']}, {})
        self.assertFalse(result['ok'])
        self.assertEqual(result['outcome'], 'needs_consent')
        second.assert_not_called()

    def test_list_is_available_without_consent(self):
        result = agents_module.agents({'action': 'list'}, {})
        self.assertTrue(result['ok'])
        self.assertEqual(len(result['agents']), 4)
        self.assertIn('read-only', result['sandbox'])

    def test_the_tool_declares_the_consent_requirement(self):
        self.assertIn('consent', agents_module.TOOL['input_schema']['properties'])
        self.assertIn('REQUIRES', agents_module.TOOL['description'])
        self.assertTrue(agents_module.TOOL['approval'])

    def test_settings_cannot_be_changed_through_an_unknown_agent(self):
        result = agents_module.agents({'action': 'config', 'agent': 'nope',
                                       'settings': {'model': 'x'}}, {})
        self.assertFalse(result['ok'])


if __name__ == '__main__':
    unittest.main()
