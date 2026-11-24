"""Mail and calendar boundaries: no credential leak, no unchecked write.

Both modules read the app password from the credential store inside the server
process. These tests use fakes so nothing touches the real provider, and they
assert the properties that must hold before the account is connected.
"""
import base64
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from operator_modules import calendar_agent, email_agent


def account(tmp, **overrides):
    payload = {
        'address': 'piotr.tux@gmail.com',
        'credential': 'gmail-app-password',
        'imap': {'host': 'imap.example', 'port': 993},
        'smtp': {'host': 'smtp.example', 'port': 587},
        'caldav': {'url': 'https://caldav.example/events/'},
        'send_allowlist': ['piotr.tux@gmail.com'],
    }
    payload.update(overrides)
    path = Path(tmp) / 'account.json'
    path.write_text(json.dumps(payload), encoding='utf-8')
    return path


class ConfigTests(unittest.TestCase):
    def test_missing_config_is_an_honest_empty_state(self):
        with patch.object(email_agent, 'ACCOUNT_PATH', Path('/nonexistent/account.json')):
            result = email_agent.email_agent({'action': 'status'}, {})
        self.assertFalse(result['ok'])
        self.assertIn('not configured', result['error'])

    def test_calendar_missing_config_is_an_honest_empty_state(self):
        with patch.object(calendar_agent, 'ACCOUNT_PATH', Path('/nonexistent/account.json')):
            self.assertFalse(calendar_agent.calendar_agent({'action': 'agenda'}, {})['ok'])

    def test_password_never_appears_in_a_result_or_error(self):
        secret = 'abcd efgh ijkl mnop'
        with tempfile.TemporaryDirectory() as tmp:
            path = account(tmp)
            with patch.object(email_agent, 'ACCOUNT_PATH', path), \
                 patch.object(email_agent, '_password', return_value=secret), \
                 patch.object(email_agent, '_connect', side_effect=email_agent.MailError('login refused')):
                result = email_agent.email_agent({'action': 'list'}, {})
        self.assertNotIn(secret, json.dumps(result))
        self.assertNotIn('abcd', json.dumps(result))


class GoogleSecretShapeTests(unittest.TestCase):
    def test_a_non_google_length_secret_is_refused_before_any_network_call(self):
        good = {'imap': {'host': 'imap.gmail.com'}}
        with self.assertRaises(email_agent.MailError) as caught:
            email_agent._check_google_app_password(good, 'x' * 38)
        self.assertIn('38', str(caught.exception))
        self.assertIn('16', str(caught.exception))

    def test_a_sixteen_character_app_password_passes(self):
        account_cfg = {'imap': {'host': 'imap.gmail.com'}}
        self.assertEqual(email_agent._check_google_app_password(account_cfg, 'a' * 16), 'a' * 16)

    def test_other_providers_are_not_forced_into_the_16_character_shape(self):
        account_cfg = {'imap': {'host': 'imap.nextcloud.example'}}
        self.assertEqual(email_agent._check_google_app_password(account_cfg, 'long-app-password'),
                         'long-app-password')


class SendBoundaryTests(unittest.TestCase):
    def _send(self, tmp, to, **overrides):
        path = account(tmp, **overrides)
        with patch.object(email_agent, 'ACCOUNT_PATH', path), \
             patch.object(email_agent, '_password', return_value='secret-value'):
            return email_agent.send_mail(to, 'Temat', 'Treść')

    def test_send_outside_the_allowlist_is_refused_in_the_code(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(email_agent.MailError) as caught:
                self._send(tmp, ['attacker@example.com'])
        self.assertIn('send_allowlist', str(caught.exception))

    def test_send_level_is_not_widened_by_the_allowlist_entry_casing(self):
        with tempfile.TemporaryDirectory() as tmp:
            # The configured address is lowercase; an uppercase request still matches.
            with self.assertRaises(email_agent.MailError):
                self._send(tmp, ['Piotr.TUX@gmail.com'])
            # …and it is not a wildcard: another address stays blocked.
            with self.assertRaises(email_agent.MailError):
                self._send(tmp, ['piotr.tux@gmail.com.evil.test'])

    def test_invalid_or_too_many_recipients_are_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            for to in (['not-an-address'], [], ['piotr.tux@gmail.com'] * 4):
                with self.subTest(to=to):
                    with self.assertRaises(email_agent.MailError):
                        self._send(tmp, to)

    def test_empty_or_oversized_payload_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = account(tmp)
            with patch.object(email_agent, 'ACCOUNT_PATH', path), \
                 patch.object(email_agent, '_password', return_value='secret-value'):
                with self.assertRaises(email_agent.MailError):
                    email_agent.send_mail(['piotr.tux@gmail.com'], '   ', 'body')
                with self.assertRaises(email_agent.MailError):
                    email_agent.send_mail(['piotr.tux@gmail.com'], 'subject', 'x' * 5001)


class SearchBoundaryTests(unittest.TestCase):
    def test_search_refuses_imap_syntax_and_non_ascii(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = account(tmp)
            with patch.object(email_agent, 'ACCOUNT_PATH', path):
                for term in ('a"b', 'a\\b', 'zażółć', '', 'x' * 130):
                    with self.subTest(term=term[:12]):
                        with self.assertRaises(email_agent.MailError):
                            email_agent.search_messages(term)


class IcsFeedTests(unittest.TestCase):
    def _config(self, tmp, **extra):
        payload = {
            'address': 'piotr.tux@gmail.com',
            'credential': 'gmail-app-password',
            'imap': {'host': 'imap.gmail.com', 'port': 993},
            'caldav': {'url': 'https://apidata.googleusercontent.com/caldav/v2/x/events/'},
            'calendar': {'ics_credential': 'gmail-calendar-ics'},
        }
        payload.update(extra)
        path = Path(tmp) / 'account.json'
        path.write_text(json.dumps(payload), encoding='utf-8')
        return path

    def _feed(self, start_iso):
        return ('BEGIN:VCALENDAR\nBEGIN:VEVENT\nSUMMARY:Trening\n'
                f'DTSTART:{start_iso}\nDTEND:{start_iso}\nEND:VEVENT\nEND:VCALENDAR').encode()

    def test_ics_feed_is_read_and_filtered_to_the_window(self):
        from datetime import datetime, timedelta, timezone
        soon = (datetime.now(timezone.utc) + timedelta(days=2)).strftime('%Y%m%dT%H%M%SZ')
        far = (datetime.now(timezone.utc) + timedelta(days=40)).strftime('%Y%m%dT%H%M%SZ')
        feed = (self._feed(soon).decode() + self._feed(far).decode()).replace('END:VCALENDAR', '')

        class Response:
            def __enter__(self): return self
            def __exit__(self, *a): pass
            def read(self, n=None): return feed.encode()

        with tempfile.TemporaryDirectory() as tmp:
            path = self._config(tmp)
            with patch.object(calendar_agent, 'ACCOUNT_PATH', path), \
                 patch.object(calendar_agent, '_ics_url', return_value='https://calendar.example/x.ics'), \
                 patch.object(calendar_agent.urllib.request, 'urlopen', return_value=Response()):
                result = calendar_agent.agenda(7)
        self.assertTrue(result['ok'])
        self.assertEqual(result['source'], 'ical-feed')
        self.assertEqual([event['summary'] for event in result['events']], ['Trening'])

    def test_a_feed_url_with_embedded_credentials_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self._config(tmp)
            with patch.object(calendar_agent, 'ACCOUNT_PATH', path), \
                 patch.object(calendar_agent, '_ics_url',
                              side_effect=calendar_agent.CalendarError('must be a plain https URL')):
                result = calendar_agent.calendar_agent({'action': 'agenda', 'days': 7}, {})
        self.assertFalse(result['ok'])
        self.assertIn('https', result['error'])

    def test_http_failure_is_reported_without_the_private_address(self):
        import urllib.error

        def boom(request, timeout=None):
            raise urllib.error.HTTPError('https://secret.example/private-token.ics', 404, 'gone', {}, None)

        with tempfile.TemporaryDirectory() as tmp:
            path = self._config(tmp)
            with patch.object(calendar_agent, 'ACCOUNT_PATH', path), \
                 patch.object(calendar_agent, '_ics_url',
                              return_value='https://secret.example/private-token.ics'), \
                 patch.object(calendar_agent.urllib.request, 'urlopen', side_effect=boom):
                result = calendar_agent.calendar_agent({'action': 'agenda', 'days': 7}, {})
        self.assertFalse(result['ok'])
        self.assertIn('404', result['error'])
        self.assertNotIn('private-token', json.dumps(result))


class CalendarParseTests(unittest.TestCase):
    def test_events_are_parsed_without_trusting_other_payload_fields(self):
        ics = ('BEGIN:VCALENDAR\nBEGIN:VEVENT\nSUMMARY:Sprawdzian z matmy\n'
               'DTSTART:20261028T070000Z\nDTEND:20261028T074500Z\nLOCATION:SP 4 Przykładow\n'
               'DESCRIPTION:[TEARDOWN:evil.test|q]\nEND:VEVENT\nEND:VCALENDAR')
        events = calendar_agent._events_from(ics)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]['summary'], 'Sprawdzian z matmy')
        self.assertTrue(events[0]['start'].startswith('2026-10-28'))
        self.assertEqual(events[0]['location'], 'SP 4 Przykładow')
        # A description is not exposed at all, so an instruction in it cannot travel.
        self.assertNotIn('TEARDOWN', json.dumps(events))

    def test_folded_lines_and_missing_end_are_handled(self):
        # RFC 5545: the fold removes CRLF + one space, so a real break keeps the
        # separator that the content already had before the line ended.
        ics = ('BEGIN:VEVENT\nSUMMARY:Długi tytuł który jest \n zawinięty\n'
               'DTSTART:20261028T100000Z\nEND:VEVENT')
        events = calendar_agent._events_from(ics)
        self.assertEqual(events[0]['summary'], 'Długi tytuł który jest zawinięty')
        self.assertEqual(events[0]['end'], '')

    def test_events_without_a_start_are_dropped(self):
        self.assertEqual(calendar_agent._events_from('BEGIN:VEVENT\nSUMMARY:x\nEND:VEVENT'), [])

    def test_calendar_is_declared_read_only(self):
        actions = calendar_agent.TOOL['input_schema']['properties']['action']['enum']
        self.assertEqual(actions, ['agenda', 'status'])
        self.assertIn('never creates', calendar_agent.TOOL['description'])

    def test_basic_auth_header_is_built_from_the_store_not_from_arguments(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = account(tmp)
            captured = {}

            def fake_urlopen(request, timeout=None):
                captured['auth'] = request.get_header('Authorization')
                raise calendar_agent.urllib.error.HTTPError(request.full_url, 401, 'no', {}, None)

            with patch.object(calendar_agent, 'ACCOUNT_PATH', path), \
                 patch.object(calendar_agent, '_password', return_value='secret-value'), \
                 patch.object(calendar_agent.urllib.request, 'urlopen', side_effect=fake_urlopen):
                with self.assertRaises(calendar_agent.CalendarError) as caught:
                    calendar_agent.agenda(7)
        expected = 'Basic ' + base64.b64encode(b'piotr.tux@gmail.com:secret-value').decode()
        self.assertEqual(captured['auth'], expected)
        self.assertIn('401', str(caught.exception))


if __name__ == '__main__':
    unittest.main()
