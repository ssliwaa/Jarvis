"""Jev must be an accelerator: absent key, timeouts and bad answers fall back."""
import json
import unittest
from unittest import mock

import jev_decision
from operator_modules import mail_triage


class _Response:
    def __init__(self, payload):
        self.payload = payload

    def read(self, _limit=None):
        return json.dumps(self.payload).encode('utf-8')

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


class DecideTests(unittest.TestCase):
    def setUp(self):
        self._original = jev_decision._key

    def tearDown(self):
        jev_decision._key = self._original

    def test_no_key_means_not_configured_and_no_request(self):
        jev_decision._key = lambda: ''
        self.assertFalse(jev_decision.available())
        with mock.patch('urllib.request.build_opener') as opener:
            with self.assertRaises(jev_decision.JevError):
                jev_decision.decide('state', {'q': jev_decision.noul('q', 'Yes?')})
        opener.assert_not_called()

    def test_the_key_is_sent_as_a_bearer_header_and_never_returned(self):
        jev_decision._key = lambda: 'sk_secret_value'
        captured = {}

        class _Opener:
            def open(self, request, timeout=None):
                captured['headers'] = dict(request.header_items())
                captured['body'] = json.loads(request.data)
                return _Response({'model': 'jev-1.14.0',
                                  'answers': {'needs_me': {'type': 'noul', 'noul': 0.97}}})

        with mock.patch('urllib.request.build_opener', return_value=_Opener()):
            result = jev_decision.decide('state', {'needs_me': jev_decision.noul('needs_me', 'Yes?')})
        self.assertTrue(result['ok'])
        self.assertIn('sk_secret_value', captured['headers']['Authorization'])
        self.assertNotIn('sk_secret_value', json.dumps(result))
        self.assertEqual(captured['body']['model'], 'jev-1.14.0')
        self.assertEqual(captured['body']['state'], 'state')

    def test_a_redirect_is_refused_so_a_lookalike_cannot_relay(self):
        handler = jev_decision._NoRedirect()
        with self.assertRaises(jev_decision.JevError):
            handler.redirect_request(None, None, 302, 'Found', {}, 'https://jev.quest/v1/systemone')

    def test_an_http_error_does_not_echo_the_body(self):
        import urllib.error

        jev_decision._key = lambda: 'sk_secret_value'

        class _Opener:
            def open(self, request, timeout=None):
                raise urllib.error.HTTPError('u', 401, 'Unauthorized', {}, None)

        with mock.patch('urllib.request.build_opener', return_value=_Opener()):
            with self.assertRaises(jev_decision.JevError) as raised:
                jev_decision.decide('s', {'q': jev_decision.noul('q', 'Yes?')})
        self.assertIn('401', str(raised.exception))
        self.assertNotIn('sk_secret_value', str(raised.exception))

    def test_questions_are_bounded(self):
        jev_decision._key = lambda: 'sk_x'
        with self.assertRaises(jev_decision.JevError):
            jev_decision.decide('s', {})
        with self.assertRaises(jev_decision.JevError):
            jev_decision.decide('s', {f'q{i}': jev_decision.noul(f'q{i}', 'x') for i in range(9)})

    def test_the_official_host_is_the_only_endpoint(self):
        self.assertEqual(jev_decision.OFFICIAL_HOST, 'api.typesafe.ai')
        self.assertEqual(jev_decision.ENDPOINT, 'https://api.typesafe.ai/v1/systemone')
        self.assertNotIn('thejevai.com', jev_decision.ENDPOINT)

    def test_choice_and_score_use_the_official_criteria_shape(self):
        choice = jev_decision.choice('category', 'Which?', ['a', 'b'])
        self.assertEqual(choice['criteria'], {'a': None, 'b': None})
        self.assertNotIn('options', choice)
        described = jev_decision.choice('category', 'Which?', {'a': 'first', 'b': 'second'})
        self.assertEqual(described['criteria'], {'a': 'first', 'b': 'second'})
        score = jev_decision.score('urgency', 'How urgent?', ['calm', 'urgent'])
        self.assertEqual(score['criteria'], ['calm', 'urgent'])
        with self.assertRaises(jev_decision.JevError):
            jev_decision.score('urgency', 'How urgent?')
        with self.assertRaises(jev_decision.JevError):
            jev_decision.choice('category', 'Which?', [])

    def test_official_answers_are_read_as_choice_score_and_noul(self):
        answers = {'answers': {
            'needs_me': {'type': 'noul', 'noul': 0.82},
            'category': {'type': 'choice', 'choice': 'szkoła', 'confidence': 0.9,
                         'probabilities': {'szkoła': 0.9}},
            'urgency': {'type': 'score', 'score': 3.5, 'confidence': 0.8,
                        'legend': {}, 'probabilities': {}},
        }}
        self.assertAlmostEqual(jev_decision.answer_for(answers, 'needs_me'), 0.82)
        self.assertEqual(jev_decision.answer_for(answers, 'category'), 'szkoła')
        self.assertEqual(jev_decision.answer_for(answers, 'urgency'), 3.5)
        self.assertIsNone(jev_decision.answer_for({'answers': {}}, 'category'))

    def test_a_noul_probability_is_a_boolean_not_a_truthy_number(self):
        low = {'answers': {'q': {'type': 'noul', 'noul': 0.03}}}
        high = {'answers': {'q': {'type': 'noul', 'noul': 0.97}}}
        self.assertFalse(jev_decision.yes(low, 'q'))
        self.assertTrue(jev_decision.yes(high, 'q'))
        self.assertFalse(jev_decision.yes(high, 'q', threshold=0.99))
        self.assertIsNone(jev_decision.answer_for(low, 'missing'))

    def test_an_empty_answer_set_is_a_failure(self):
        jev_decision._key = lambda: 'sk_x'

        class _Opener:
            def open(self, request, timeout=None):
                return _Response({'model': 'jev-1.14.0', 'answers': {}})

        with mock.patch('urllib.request.build_opener', return_value=_Opener()):
            with self.assertRaises(jev_decision.JevError):
                jev_decision.decide('s', {'q': jev_decision.noul('q', 'Yes?')})


class TriageTests(unittest.TestCase):
    MESSAGES = [
        {'subject': 'Faktura za październik — termin dziś', 'from': 'biuro@firma.pl', 'date': '1'},
        {'subject': 'Newsletter: wyprzedaż -40%', 'from': 'no-reply@sklep.pl', 'date': '2'},
        {'subject': 'Sprawdzian z matematyki', 'from': 'wychowawca@sp.pl', 'date': '3'},
    ]

    def _listing(self):
        return {'ok': True, 'count': len(self.MESSAGES), 'messages': list(self.MESSAGES)}

    def test_without_a_key_the_rules_decide_and_say_so(self):
        with mock.patch.object(jev_decision, 'available', return_value=False), \
             mock.patch('operator_modules.email_agent.list_messages',
                        return_value=self._listing()):
            result = mail_triage.triage(limit=3)
        self.assertTrue(result['ok'])
        self.assertEqual(result['source'], 'rules')
        self.assertTrue(all(row['source'] == 'rules' for row in result['messages']))
        self.assertGreaterEqual(result['needs_me'], 1)
        self.assertEqual(result['messages'][0]['needs_me'], True)

    def test_jev_answers_are_used_when_it_is_configured(self):
        answer = {'ok': True, 'ms': 90, 'model': 'jev-1.14.0',
                  'answers': {
                      'needs_me': {'type': 'noul', 'noul': 0.93},
                      'category': {'type': 'choice', 'choice': 'szkoła',
                                   'confidence': 0.9, 'probabilities': {'szkoła': 0.9}},
                      'urgency': {'type': 'score', 'score': 3.4, 'confidence': 0.8,
                                  'legend': {}, 'probabilities': {}}}}
        with mock.patch.object(jev_decision, 'available', return_value=True), \
             mock.patch.object(jev_decision, 'decide', return_value=answer), \
             mock.patch('operator_modules.email_agent.list_messages',
                        return_value=self._listing()):
            result = mail_triage.triage(limit=3)
        self.assertEqual(result['source'], 'jev')
        self.assertTrue(all(row['source'] == 'jev' for row in result['messages']))
        self.assertEqual(result['messages'][0]['category'], 'szkoła')
        self.assertEqual(result['messages'][0]['urgency'], 85)

    def test_a_low_noul_probability_does_not_mark_mail_as_needing_me(self):
        answer = {'ok': True, 'ms': 10, 'model': 'jev-1.14.0',
                  'answers': {
                      'needs_me': {'type': 'noul', 'noul': 0.02},
                      'category': {'type': 'choice', 'choice': 'powiadomienie'},
                      'urgency': {'type': 'score', 'score': 0.5}}}
        with mock.patch.object(jev_decision, 'available', return_value=True), \
             mock.patch.object(jev_decision, 'decide', return_value=answer), \
             mock.patch('operator_modules.email_agent.list_messages',
                        return_value=self._listing()):
            result = mail_triage.triage(limit=3)
        self.assertTrue(all(not row['needs_me'] for row in result['messages']))

    def test_a_category_outside_the_rubric_degrades_to_rules(self):
        answer = {'ok': True, 'ms': 10, 'model': 'jev-1.14.0',
                  'answers': {
                      'needs_me': {'type': 'noul', 'noul': 0.9},
                      'category': {'type': 'choice', 'choice': 'cokolwiek'},
                      'urgency': {'type': 'score', 'score': 2}}}
        with mock.patch.object(jev_decision, 'available', return_value=True), \
             mock.patch.object(jev_decision, 'decide', return_value=answer), \
             mock.patch('operator_modules.email_agent.list_messages',
                        return_value=self._listing()):
            result = mail_triage.triage(limit=3)
        self.assertEqual(result['source'], 'rules')
        self.assertIn('category', result['degraded'])

    def test_a_jev_failure_mid_run_degrades_to_rules_without_losing_rows(self):
        with mock.patch.object(jev_decision, 'available', return_value=True), \
             mock.patch.object(jev_decision, 'decide',
                               side_effect=jev_decision.JevError('timeout')), \
             mock.patch('operator_modules.email_agent.list_messages',
                        return_value=self._listing()):
            result = mail_triage.triage(limit=3)
        self.assertEqual(result['count'], 3)
        self.assertEqual(result['source'], 'rules')
        self.assertIn('timeout', result['degraded'])
        self.assertTrue(all(row['source'] == 'rules' for row in result['messages']))

    def test_limit_is_capped_and_a_bad_action_is_refused(self):
        # Every call that can reach Jev stays inside the patch: a stored key in
        # the operator's own config must not decide this test's outcome.
        with mock.patch('operator_modules.email_agent.list_messages',
                        return_value=self._listing()) as listing, \
             mock.patch.object(jev_decision, 'available', return_value=False):
            mail_triage.triage(limit=500)
            self.assertFalse(mail_triage.mail_triage({'action': 'send'})['ok'])
            self.assertEqual(mail_triage.mail_triage({'action': 'status'})['fallback'], 'rules')
        self.assertEqual(listing.call_args.kwargs['limit'], mail_triage.MAX_TRIAGE)

    def test_a_question_mark_in_a_price_alert_preview_is_not_a_request(self):
        # Pepper alerts carry "?" in their body; that must not read as "reply please".
        message = {'subject': "Twój alert 'dysk ssd'", 'from': 'Pepper <noreply@pepper.pl>',
                   'preview': 'Czy chcesz zobaczyć ofertę? Dostawa od 9,99 zł'}
        row = mail_triage._rules(message)
        self.assertFalse(row['needs_me'])
        self.assertNotIn('pyta lub prosi o odpowiedź', row['reasons'])

    def test_a_security_alert_from_no_reply_is_still_the_users_business(self):
        # Google sends real alerts from no-reply; treating that as bulk hid them.
        message = {'subject': 'Alert bezpieczeństwa', 'from': 'Google <no-reply@accounts.google.com>'}
        row = mail_triage._rules(message)
        self.assertTrue(row['needs_me'])
        self.assertEqual(row['category'], 'konto')

    def test_a_newsletter_is_demoted_with_honest_reasons(self):
        message = {'subject': 'Newsletter: promocja -40%', 'from': 'sklep <hello@newsletter.sklep.pl>'}
        row = mail_triage._rules(message)
        self.assertFalse(row['needs_me'])
        self.assertEqual(row['reasons'], ['wysyłka masowa'])

    def test_the_tool_description_promises_read_only(self):
        self.assertIn('Read-only', mail_triage.TOOL['description'])
        self.assertFalse(mail_triage.TOOL['approval'])


class RouterUpgradeTests(unittest.TestCase):
    """Jev may sharpen an unsure route, and may never take one away."""

    def setUp(self):
        import router
        self.router = router

    def test_the_question_that_failed_now_reaches_the_web_lane(self):
        decision = self.router.classify('Check in Internet what is currently going on in France')
        self.assertEqual(decision['action'], 'web')
        self.assertEqual(decision['label'], 'WEB RESEARCH')

    def test_a_conceptual_internet_question_stays_in_chat(self):
        self.assertEqual(self.router.classify('jak działa internet?')['action'], 'notes')

    def test_without_a_key_no_jev_call_is_made(self):
        with mock.patch.object(jev_decision, 'available', return_value=False), \
             mock.patch.object(jev_decision, 'decide') as decide:
            decision = self.router.classify('opowiedz mi o sytuacji we Francji')
        decide.assert_not_called()
        self.assertEqual(decision['action'], 'general')

    def test_a_jev_yes_upgrades_to_the_web_lane(self):
        answer = {'ok': True, 'ms': 80, 'model': 'jev-1.14.0',
                  'answers': {'needs_live': {'type': 'noul', 'noul': 0.88}}}
        with mock.patch.object(jev_decision, 'available', return_value=True), \
             mock.patch.object(jev_decision, 'decide', return_value=answer):
            decision = self.router.classify('opowiedz mi o sytuacji we Francji')
        self.assertEqual(decision['action'], 'web')
        self.assertIn('Jev', decision['reason'])

    def test_a_jev_no_changes_nothing(self):
        answer = {'ok': True, 'answers': {'needs_live': {'type': 'noul', 'noul': 0.12}}}
        with mock.patch.object(jev_decision, 'available', return_value=True), \
             mock.patch.object(jev_decision, 'decide', return_value=answer):
            decision = self.router.classify('opowiedz mi o sytuacji we Francji')
        self.assertEqual(decision['action'], 'general')

    def test_a_jev_failure_keeps_the_rule_decision(self):
        with mock.patch.object(jev_decision, 'available', return_value=True), \
             mock.patch.object(jev_decision, 'decide',
                               side_effect=jev_decision.JevError('timeout')):
            decision = self.router.classify('opowiedz mi o sytuacji we Francji')
        self.assertEqual(decision['action'], 'general')

    def test_jev_never_touches_an_operator_or_stop_decision(self):
        with mock.patch.object(jev_decision, 'available', return_value=True), \
             mock.patch.object(jev_decision, 'decide') as decide:
            self.assertEqual(self.router.classify('zatrzymaj to zadanie')['action'], 'job_control')
            self.assertEqual(self.router.classify('otwórz notatnik')['action'], 'operator')
        decide.assert_not_called()
