"""Briefing contract with real local system data and a fake app shell."""
import os
import unittest
SANDBOXED = os.environ.get("JARVIS_VERIFY_SANDBOX") == "1"
from types import SimpleNamespace
from unittest.mock import patch

import briefing


@unittest.skipIf(SANDBOXED, "needs the developer's local env (vault/Hermes/Piper/desktop); skipped in CI")
class BriefingTests(unittest.TestCase):
    def test_briefing_adds_weather_commute_and_both_training_variants(self):
        from operator_modules import commute_weather
        sample = {'schedule': {'day': 'Wtorek', 'leave_home': '07:27', 'km_train': '07:45',
                               'running_plan': 'Easy run', 'gym_a': 'Pull', 'gym_b': 'Push'},
                  'weather': {'available': True, 'temperature_c': 11, 'precipitation_mm': 0.0,
                              'wind_kmh': 12, 'location': 'Testville'}}
        with patch.object(commute_weather, 'commute_weather', return_value=sample):
            result = briefing.build()
        self.assertIn('07:27', result['text'])
        self.assertIn('07:45', result['text'])
        self.assertIn('11', result['text'])
        self.assertIn('Pull', result['text'])
        self.assertIn('Push', result['text'])
        self.assertNotIn('active variant A', result['text'])
        self.assertEqual(result['sections']['daily_plan']['schedule']['day'], 'Wtorek')
        self.assertIn('07:27', result['spoken'])

    def test_briefing_says_when_weather_and_calendar_are_unavailable(self):
        from operator_modules import commute_weather
        with patch.object(commute_weather, 'commute_weather', return_value={
                'schedule': {}, 'weather': {'available': False, 'reason': 'offline'}}):
            result = briefing.build()
        self.assertIn('niedostępna', result['text'].lower())
        self.assertIn('kalendarz', result['text'].lower())

    def test_briefing_includes_real_calendar_and_mail_when_the_account_is_on(self):
        from operator_modules import calendar_agent, commute_weather, email_agent
        cal = {'ok': True, 'events': [{'summary': 'Sprawdzian z matmy',
                                       'start': '2026-10-27T10:00:00+01:00', 'end': '', 'location': ''}]}
        with patch.object(commute_weather, 'commute_weather', return_value={'schedule': {}, 'weather': {'available': False}}), \
             patch.object(calendar_agent, 'calendar_agent', return_value=cal), \
             patch.object(email_agent, 'email_agent', return_value={'ok': True, 'unseen': 6785, 'messages': 7471}):
            result = briefing.build(include_account=True)
        self.assertIn('Sprawdzian z matmy', result['text'])
        self.assertIn('6785', result['text'])

    def test_briefing_stays_honest_when_the_account_fails(self):
        from operator_modules import calendar_agent, commute_weather, email_agent
        with patch.object(commute_weather, 'commute_weather', return_value={'schedule': {}, 'weather': {'available': False}}), \
             patch.object(calendar_agent, 'calendar_agent', return_value={'ok': False, 'error': 'offline'}), \
             patch.object(email_agent, 'email_agent', return_value={'ok': False, 'error': 'offline'}):
            result = briefing.build(include_account=True)
        self.assertIn('Kalendarz: brak danych', result['text'])
        self.assertNotIn('Poczta:', result['text'])

    def test_briefing_has_system_and_galaxy_sections(self):
        app = SimpleNamespace(load_graph=lambda: {"nodes": [1, 2], "links": [1]},
                              session_store=SimpleNamespace(recent=lambda limit: []),
                              scheduler=None, memory=None)
        result = briefing.build(app)
        self.assertIn("Daily briefing", result["heading"])
        self.assertIn("2 notes and 1 connections", result["text"])
        self.assertGreater(result["sections"]["system"]["memory"]["total"], 0)


if __name__ == "__main__":
    unittest.main()
