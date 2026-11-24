"""connectors_hub: vault, SSRF perimeter, integrations and the MCP stdio client.

This suite pins the credentials vault (0600 file / 0700 dir, corrupted JSON
fallback to an empty registry, masking with trailing 4 chars for long secrets
and 8 bullets for short ones, the merge round-trip where bullet-masked or
None values never overwrite stored secrets), the SSRF gate (https-only by
default, loopback/link-local/multicast blocked in both modes, the
169.254.169.254 cloud metadata endpoint blocked even with allow_lan, private
IPs gated per integration, DNS hostnames not resolved), connector
configuration (provider allowlist from the 18-entry catalog, id sanitisation
and 48-char clip, ics_url/ha_url/webhook validation applied provider-aware,
mcp_stdio command_str shlex parsing that never overwrites an explicit
command), entry resolution (provider fallback in dict insertion order,
zero-config providers, toolset disable gates), the Google OAuth2 token
refresh flow (POST to oauth2.googleapis.com with the four grant fields,
refresh winning over a direct token), gmail SMTP send (write gate confirmed=
True, app password space-stripping, default host/port), telegram send
(4000-char clip, bot token in the API path), the MCP stdio JSON-RPC client
against a real python subprocess (namespacing mcp__<alias>__<tool>, allowlist
filtering, tool-call gating before spawn, error and no-response paths, env
passthrough), ICS parsing (window filtering, parameter names split on ';',
folded lines unfolded without the continuation space, cap 25), and the action
router (unknown actions, zero-config cron and web_search, toolset gates,
masked passthrough to toolsets_catalog run_* functions) plus briefing and
list views.

All assertions were pinned empirically before writing. The vault is
redirected into a per-test sandbox by patching connectors_hub.agent_cli.ROOT.
"""
import json
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import connectors_hub

MCP_ECHO_HELPER = """
import json, os, sys
for line in sys.stdin:
    line = line.strip()
    if not line.startswith('{'):
        continue
    try:
        msg = json.loads(line)
    except Exception:
        continue
    if msg.get('id') == 2:
        out = {'jsonrpc': '2.0', 'id': 2, 'result': {
            'tools': [{'name': 'echo_tool'}, {'name': 'other_tool'}],
            'env_seen': os.environ.get('PROBE_ENV', '')}}
        sys.stdout.write(json.dumps(out) + '\\n')
        sys.stdout.flush()
"""

MCP_ERROR_HELPER = """
import json, sys
sys.stdout.write(json.dumps({'id': 2, 'error': {'code': -32000, 'message': 'boom'}}) + '\\n')
sys.stdout.flush()
"""


def echo_command():
    return [sys.executable, '-c', MCP_ECHO_HELPER]


class FakeResponse:
    def __init__(self, payload):
        self.payload = payload if isinstance(payload, bytes) else json.dumps(payload).encode()

    def read(self, size=-1):
        return self.payload

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class ConnectorsHubBase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix='cht_')
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(self._tmp.name)
        self.agents_dir = self.tmp / 'agents'  # created by _vault_path (0700)
        self._cli_patcher = patch.object(
            connectors_hub, 'agent_cli', SimpleNamespace(ROOT=self.agents_dir / 'agent_cli.py'))
        self._cli_patcher.start()
        self.addCleanup(self._cli_patcher.stop)

    @property
    def vault_path(self):
        return self.agents_dir / 'connectors_vault.json'

    def configure(self, cid, provider, settings, **kwargs):
        return connectors_hub.configure_connector(cid, provider, settings, **kwargs)


class TestVaultIO(ConnectorsHubBase):
    def test_load_defaults_for_missing_corrupt_and_shape_vault(self):
        self.assertEqual(connectors_hub._load_vault(), {'connectors': {}, 'disabled_toolsets': []})
        # _vault_path() already created the 0700 directory during the first load
        self.vault_path.write_text('not json at all', encoding='utf-8')
        self.assertEqual(connectors_hub._load_vault(), {'connectors': {}, 'disabled_toolsets': []})
        self.vault_path.write_text('{"connectors": {"a": {"x": 1}}}', encoding='utf-8')
        vault = connectors_hub._load_vault()
        self.assertEqual(vault['connectors'], {'a': {'x': 1}})
        self.assertEqual(vault['disabled_toolsets'], [])  # setdefault repairs shape

    def test_save_roundtrip_and_permissions(self):
        self.configure('g1', 'gmail', {'email': 'a@b.c', 'app_password': 'supersecret123'})
        vault = connectors_hub._load_vault()
        self.assertEqual(vault['connectors']['g1']['provider'], 'gmail')
        self.assertEqual(vault['connectors']['g1']['settings']['app_password'], 'supersecret123')
        self.assertEqual(self.vault_path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.agents_dir.stat().st_mode & 0o777, 0o700)

    def test_mask_config_table(self):
        masked = connectors_hub._mask_config({
            'api_key': 'abcdefghij12345',   # long: bullets + last four
            'topic': 'short',               # short secret: 8 bullets
            'env': {'A': 'zzz'},            # env values fully masked
            'note': 'clear',                # non-secret: passthrough
            'password': '',                 # falsy secret: passthrough (nothing to leak)
        })
        self.assertEqual(masked, {
            'api_key': '••••2345',
            'topic': '••••••••',
            'env': {'A': '••••••••'},
            'note': 'clear',
            'password': '',
        })

    def test_set_toolset_enabled_cycle(self):
        with self.assertRaises(ValueError) as ctx:
            connectors_hub.set_toolset_enabled('nope', True)
        self.assertIn('Nieznany toolset', str(ctx.exception))
        disabled = connectors_hub.set_toolset_enabled('productivity', False)
        self.assertEqual(disabled, {'ok': True, 'toolset': 'productivity',
                                    'enabled': False, 'disabled_toolsets': ['productivity']})
        self.assertEqual(connectors_hub._load_vault()['disabled_toolsets'], ['productivity'])
        enabled = connectors_hub.set_toolset_enabled('productivity', True)
        self.assertEqual(enabled['disabled_toolsets'], [])

    def test_remove_connector(self):
        self.configure('g1', 'gmail', {'email': 'a@b.c'})
        self.assertEqual(connectors_hub.remove_connector('g1'), {'ok': True, 'removed': True})
        self.assertNotIn('g1', connectors_hub._load_vault()['connectors'])
        self.assertEqual(connectors_hub.remove_connector('g1'), {'ok': True, 'removed': False})


class TestValidateRemoteUrl(unittest.TestCase):
    def test_https_public_url_accepted_and_stripped(self):
        self.assertEqual(connectors_hub.validate_remote_url('  https://example.com/x  '),
                         'https://example.com/x')

    def test_scheme_gates_and_messages(self):
        with self.assertRaises(ValueError) as ctx:
            connectors_hub.validate_remote_url('http://example.com/x')
        self.assertIn('Wymagany jest zewnętrzny adres HTTPS.', str(ctx.exception))
        with self.assertRaises(ValueError) as ctx:
            connectors_hub.validate_remote_url('rtsp://example.com/x', allow_lan=True)
        self.assertIn('Wymagany jest zewnętrzny adres HTTP/HTTPS.', str(ctx.exception))
        with self.assertRaises(ValueError):
            connectors_hub.validate_remote_url('https:///path')
        with self.assertRaises(ValueError):
            connectors_hub.validate_remote_url('')
        self.assertEqual(connectors_hub.validate_remote_url('http://example.com/x', allow_lan=True),
                         'http://example.com/x')

    def test_loopback_blocked_in_both_modes(self):
        for url in ('https://localhost/x', 'https://127.0.0.1:8123/', 'http://[::1]:80/',
                    'https://0.0.0.0/x'):
            with self.assertRaises(ValueError) as ctx:
                connectors_hub.validate_remote_url(url, allow_lan=True)
            self.assertIn('loopback', str(ctx.exception))

    def test_cloud_metadata_blocked_even_for_lan(self):
        # 169.254.169.254 (link-local) stays blocked with allow_lan=True
        with self.assertRaises(ValueError) as ctx:
            connectors_hub.validate_remote_url('http://169.254.169.254/latest/meta-data',
                                               allow_lan=True)
        self.assertIn('link-local', str(ctx.exception))

    def test_private_ip_gate_per_integration(self):
        with self.assertRaises(ValueError) as ctx:
            connectors_hub.validate_remote_url('https://172.16.0.9/x')
        self.assertIn('Prywatne adresy IP', str(ctx.exception))
        # allow_lan admits private ranges (home assistant use case)
        self.assertEqual(connectors_hub.validate_remote_url('http://192.168.1.5:8123/',
                                                            allow_lan=True),
                         'http://192.168.1.5:8123/')


class TestConfigureConnector(ConnectorsHubBase):
    def test_unknown_provider_rejected_with_catalog(self):
        with self.assertRaises(ValueError) as ctx:
            self.configure('x', 'nope', {})
        self.assertIn('Nieobsługiwana integracja', str(ctx.exception))
        self.assertIn('gmail', str(ctx.exception))

    def test_id_sanitisation_default_and_clip(self):
        self.assertEqual(self.configure('', 'gmail', {}).get('id'), 'gmail')
        self.assertEqual(self.configure('Zielony Kanal!!', 'telegram', {}).get('id'),
                         'Zielony_Kanal__')
        self.assertEqual(len(self.configure('T' * 60, 'telegram', {})['id']), 48)

    def test_masked_merge_keeps_previous_secret(self):
        self.configure('g1', 'gmail', {'email': 'a@b.c', 'app_password': 'supersecret123'})
        self.configure('g1', 'gmail', {'app_password': '••••t123', 'email': 'new@b.c'})
        settings = connectors_hub._load_vault()['connectors']['g1']['settings']
        self.assertEqual(settings['app_password'], 'supersecret123')  # bullets never stored
        self.assertEqual(settings['email'], 'new@b.c')
        self.configure('g2', 'gmail', {'email': 'x@y.z', 'app_password': None})
        self.assertNotIn('app_password',
                         connectors_hub._load_vault()['connectors']['g2']['settings'])

    def test_ics_url_ssrf_enforced_by_provider(self):
        with self.assertRaises(ValueError) as ctx:
            self.configure('cal', 'google_calendar', {'ics_url': 'http://example.com/cal.ics'})
        self.assertIn('HTTPS', str(ctx.exception))
        self.configure('cal', 'google_calendar', {'ics_url': 'https://example.com/cal.ics'})
        self.assertEqual(connectors_hub._load_vault()['connectors']['cal']['settings']['ics_url'],
                         'https://example.com/cal.ics')

    def test_home_assistant_lan_url_allowed_discord_webhook_https_only(self):
        self.configure('ha', 'home_assistant', {'ha_url': 'http://192.168.1.5:8123'})
        self.assertEqual(connectors_hub._load_vault()['connectors']['ha']['settings']['ha_url'],
                         'http://192.168.1.5:8123')
        with self.assertRaises(ValueError):
            self.configure('dc', 'discord', {'webhook_url': 'http://discord.com/api/webhooks/1/abc'})

    def test_mcp_stdio_command_str_parsed_once(self):
        self.configure('m1', 'mcp_stdio',
                       {'command_str': 'python3 -c pass --flag "a b"'})
        settings = connectors_hub._load_vault()['connectors']['m1']['settings']
        self.assertEqual(settings['command'], ['python3', '-c', 'pass', '--flag', 'a b'])
        self.configure('m1', 'mcp_stdio', {'command_str': 'other command'})
        settings = connectors_hub._load_vault()['connectors']['m1']['settings']
        self.assertEqual(settings['command'], ['python3', '-c', 'pass', '--flag', 'a b'])

    def test_envelope_masks_returned_settings(self):
        result = self.configure('g1', 'gmail',
                                {'email': 'a@b.c', 'app_password': 'supersecret123'})
        self.assertEqual(result['settings']['app_password'], '••••t123')
        self.assertEqual(result['settings']['email'], 'a@b.c')


class TestEntryResolution(ConnectorsHubBase):
    def test_unconfigured_provider_raises(self):
        with self.assertRaises(ValueError) as ctx:
            connectors_hub._get_entry('ghost', provider='github')
        self.assertIn('nie jest jeszcze skonfigurowana', str(ctx.exception))

    def test_zero_config_entry_and_provider_fallback_order(self):
        zero = connectors_hub._get_entry(provider='web_search', allow_zero_config=True)
        self.assertEqual(zero, {'id': 'web_search', 'provider': 'web_search',
                                'enabled': True, 'settings': {}})
        self.configure('first', 'gmail', {'email': 'a@b.c'})
        self.configure('second', 'gmail', {'email': 'z@z.z'})
        # provider fallback resolves the FIRST matching entry in insertion order
        self.assertEqual(connectors_hub._get_entry(provider='gmail')['id'], 'first')

    def test_toolset_disabled_gates_all_paths(self):
        self.configure('g1', 'gmail', {'email': 'a@b.c'})
        connectors_hub.set_toolset_enabled('productivity', False)
        with self.assertRaises(ValueError) as ctx:
            connectors_hub._get_entry(provider='gmail')
        self.assertIn('Zestaw narzędzi', str(ctx.exception))
        with self.assertRaises(ValueError):
            connectors_hub._get_entry('g1', provider='gmail')
        connectors_hub.set_toolset_enabled('productivity', True)
        self.assertEqual(connectors_hub._get_entry('g1')['id'], 'g1')


class TestGoogleToken(ConnectorsHubBase):
    def test_direct_token_and_missing_config(self):
        self.assertEqual(connectors_hub._google_access_token({'access_token': 'direct2'}), 'direct2')
        with self.assertRaises(ValueError) as ctx:
            connectors_hub._google_access_token({})
        self.assertIn('Brak tokenu Google OAuth2', str(ctx.exception))

    def test_refresh_flow_wins_with_proper_grant_body(self):
        captured = []

        def fake_urlopen(req, timeout=None):
            captured.append((req.full_url, req.data, req.get_method()))
            return FakeResponse({'access_token': 'refreshed-tok'})

        settings = {'client_id': 'ci', 'client_secret': 'cs', 'refresh_token': 'rt',
                    'access_token': 'direct-tok'}
        with patch('urllib.request.urlopen', fake_urlopen):
            token = connectors_hub._google_access_token(settings)
        self.assertEqual(token, 'refreshed-tok')  # refresh wins over the direct token
        url, body, method = captured[0]
        self.assertEqual(url, 'https://oauth2.googleapis.com/token')
        self.assertEqual(method, 'POST')
        fields = set(json.loads(json.dumps({}))) | set(
            chunk.split('=')[0] for chunk in body.decode().split('&'))
        self.assertEqual(fields, {'client_id', 'client_secret', 'grant_type', 'refresh_token'})


class TestGmailSend(ConnectorsHubBase):
    def test_write_gate_requires_explicit_confirmation(self):
        with self.assertRaises(ValueError) as ctx:
            connectors_hub.gmail_send_message('x@y.z', 'subj', 'body', confirmed=False)
        self.assertIn('wymaga jawnego potwierdzenia', str(ctx.exception))

    def test_missing_credentials_rejected_before_smtp(self):
        self.configure('g1', 'gmail', {'email': 'a@b.c'})
        with self.assertRaises(ValueError) as ctx:
            connectors_hub.gmail_send_message('x@y.z', 's', 'b', confirmed=True, connector_id='g1')
        self.assertIn('Wysyłka SMTP wymaga', str(ctx.exception))

    def test_smtp_happy_path_strips_password_spaces(self):
        calls = []

        class FakeSMTP:
            def __init__(self, host, port, timeout=None):
                calls.append(('init', host, port))

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

            def login(self, user, password):
                calls.append(('login', user, password))

            def send_message(self, msg):
                calls.append(('send', msg['To'], msg['Subject']))

        self.configure('g1', 'gmail', {'email': 'me@gmail.com', 'app_password': 'app pw123456'})
        with patch.object(connectors_hub.smtplib, 'SMTP_SSL', FakeSMTP):
            out = connectors_hub.gmail_send_message('dest@x.y', 'Hello', 'Body text',
                                                    confirmed=True, connector_id='g1')
        self.assertEqual(out, {'ok': True, 'sent_to': 'dest@x.y', 'subject': 'Hello'})
        self.assertEqual(calls[0], ('init', 'smtp.gmail.com', 465))  # defaults
        self.assertEqual(calls[1], ('login', 'me@gmail.com', 'apppw123456'))  # spaces removed


class TestTelegram(ConnectorsHubBase):
    def test_missing_fields_rejected(self):
        self.configure('tg', 'telegram', {'chat_id': '9'})
        with self.assertRaises(ValueError) as ctx:
            connectors_hub.telegram_send('hi', connector_id='tg')
        self.assertIn('bot_token oraz chat_id', str(ctx.exception))

    def test_send_clips_4000_and_parses_reply(self):
        self.configure('tg', 'telegram', {'bot_token': 'b:tok', 'chat_id': '12345'})
        captured = []

        def fake_urlopen(req, timeout=None):
            captured.append((req.full_url, json.loads(req.data.decode())))
            return FakeResponse({'ok': True, 'result': {'message_id': 42}})

        with patch('urllib.request.urlopen', fake_urlopen):
            out = connectors_hub.telegram_send('x' * 5000, connector_id='tg')
        url, body = captured[0]
        self.assertEqual(url, 'https://api.telegram.org/botb:tok/sendMessage')
        self.assertEqual(body['chat_id'], '12345')
        self.assertEqual(len(body['text']), 4000)  # clipped
        self.assertEqual(out, {'ok': True, 'message_id': 42})


class TestMcpStdio(unittest.TestCase):
    def test_tools_list_namespacing_and_env_passthrough(self):
        result = connectors_hub.mcp_stdio_request(
            echo_command(), method='tools/list', env_overrides={'PROBE_ENV': 'yes'},
            server_alias='my-srv')
        tools = result['result']['tools']
        self.assertEqual([t['namespaced'] for t in tools],
                         ['mcp__my_srv__echo_tool', 'mcp__my_srv__other_tool'])
        self.assertEqual(result['result']['env_seen'], 'yes')  # env reached the child

    def test_allowlist_filters_tools_and_sanitises_alias(self):
        result = connectors_hub.mcp_stdio_request(
            echo_command(), method='tools/list', allowed_tools={'echo_tool'},
            server_alias='srv!')
        tools = result['result']['tools']
        self.assertEqual([t['name'] for t in tools], ['echo_tool'])
        self.assertEqual(tools[0]['namespaced'], 'mcp__srv___echo_tool')  # '!' -> '_'

    def test_call_gate_and_command_validation(self):
        with self.assertRaises(ValueError) as ctx:
            connectors_hub.mcp_stdio_request(
                echo_command(), method='tools/call', params={'name': 'other'},
                allowed_tools={'echo_tool'}, server_alias='s')
        self.assertIn('allowed_tools', str(ctx.exception))
        with self.assertRaises(ValueError) as ctx:
            connectors_hub.mcp_stdio_request([], method='tools/list')
        self.assertIn('musi być niepustą listą', str(ctx.exception))

    def test_no_response_and_error_response_paths(self):
        with self.assertRaises(ValueError) as ctx:
            connectors_hub.mcp_stdio_request([sys.executable, '-c', 'pass'],
                                             method='tools/list')
        self.assertIn('nie zwrócił odpowiedzi JSON-RPC (kod=0)', str(ctx.exception))
        with self.assertRaises(ValueError) as ctx:
            connectors_hub.mcp_stdio_request([sys.executable, '-c', MCP_ERROR_HELPER],
                                             method='tools/list')
        self.assertIn('Błąd MCP: ', str(ctx.exception))

    def test_parse_allowlist_matrix(self):
        self.assertEqual(connectors_hub._parse_allowlist({'allowed_tools': ['a', ' b ', '']}),
                         {'a', 'b'})
        self.assertEqual(connectors_hub._parse_allowlist({'allowed_tools': []}), None)
        self.assertEqual(connectors_hub._parse_allowlist({'allowed_tools': 'x,y,z'}),
                        {'x', 'y', 'z'})
        self.assertEqual(connectors_hub._parse_allowlist({'allowed_tools': ''}), None)
        self.assertEqual(connectors_hub._parse_allowlist({}), None)


class TestParseIcs(unittest.TestCase):
    SAMPLE = (
        'BEGIN:VCALENDAR\n'
        'BEGIN:VEVENT\n'
        'UID:1\n'
        'DTSTART:20261201T120000Z\n'
        'DTEND:20261201T130000Z\n'
        'SUMMARY:Spotkanie zespołu\n'
        'LOCATION:Warszawa\n'
        'STATUS:TENTATIVE\n'
        'END:VEVENT\n'
        'BEGIN:VEVENT\n'
        'UID:2\n'
        'DTSTART:20261201T090000Z\n'
        'DTEND:20261201T093000Z\n'
        'SUMMARY:Second\n'
        'END:VEVENT\n'
        'BEGIN:VEVENT\n'
        'UID:3\n'
        'DTSTART:20300101T000000Z\n'
        'SUMMARY:Far future\n'
        'END:VEVENT\n'
        'BEGIN:VEVENT\n'
        'UID:4\n'
        'DTSTART;TZID=Europe/Warsaw:20261202T110000\n'
        'SUMMARY:Zoned param\n'
        'END:VEVENT\n'
        'BEGIN:VEVENT\n'
        'UID:5\n' 'DTSTART:20261203T100000Z\n'
        'END:VEVENT\n'
        'BEGIN:VEVENT\n'
        'UID:6\n'
        'DTSTART:20261201T120000Z\n'
        'SUMMARY:Folded\\ncontinued\\, comma\n'
        'END:VEVENT\n'
        'END:VCALENDAR')

    def test_window_filtering_fields_and_sorting(self):
        ref = datetime(2026, 12, 1, 8, 0, tzinfo=timezone.utc)
        events = connectors_hub.parse_ics_events(self.SAMPLE, days_ahead=7, now_dt=ref)
        self.assertEqual([e['summary'] for e in events],
                         ['Second', 'Spotkanie zespo\u0142u', 'Folded continued, comma',
                          'Zoned param', '(bez tytułu)'])
        # aware comparisons across offsets stay robust via fromisoformat round-trip
        self.assertEqual(datetime.fromisoformat(events[0]['start']),
                         datetime(2026, 12, 1, 9, 0, tzinfo=timezone.utc))
        self.assertEqual(datetime.fromisoformat(events[3]['start']),
                         datetime(2026, 12, 2, 10, 0, tzinfo=timezone.utc))  # TZID naive -> local
        self.assertEqual(events[1]['location'], 'Warszawa')
        self.assertEqual(events[1]['status'], 'TENTATIVE')
        self.assertEqual(datetime.fromisoformat(events[1]['end']),
                         datetime(2026, 12, 1, 13, 0, tzinfo=timezone.utc))
        self.assertEqual(events[2]['end'], '')  # folded event has no DTEND
        self.assertEqual(events[4]['summary'], '(bez tytu\u0142u)')
        self.assertEqual(events[4]['summary'], '(bez tytu\u0142u)')

    def test_caps_fold_and_missing_dtstart(self):
        ref = datetime(2026, 12, 1, 8, 0, tzinfo=timezone.utc)
        big = '\n'.join(
            f'BEGIN:VEVENT\nUID:c{i}\nDTSTART:20261202T100000Z\nSUMMARY:E{i}\nEND:VEVENT'
            for i in range(26))
        grouped = 'BEGIN:VCALENDAR\n' + big + '\nEND:VCALENDAR'
        self.assertEqual(len(connectors_hub.parse_ics_events(grouped, days_ahead=7,
                                                             now_dt=ref)), 25)
        folded = ('BEGIN:VCALENDAR\nBEGIN:VEVENT\nUID:f\nSUMMARY:Long\n '
                  'Title\nDTSTART:20261202T100000Z\nEND:VEVENT\nEND:VCALENDAR')
        events = connectors_hub.parse_ics_events(folded, now_dt=ref)
        self.assertEqual(events[0]['summary'], 'LongTitle')  # unfold drops continuation space
        self.assertEqual(connectors_hub.parse_ics_events(
            'BEGIN:VEVENT\nSUMMARY:No dtstart\nEND:VEVENT', now_dt=ref), [])


class TestActionRouter(ConnectorsHubBase):
    def test_unknown_action_raises(self):
        with self.assertRaises(ValueError) as ctx:
            connectors_hub.execute_connector_action('does_not_exist', {})
        self.assertIn('Nieznana akcja integracji', str(ctx.exception))

    def test_calendar_events_ics_end_to_end(self):
        self.configure('gcal', 'google_calendar', {'ics_url': 'https://example.com/cal.ics'})
        start = datetime.now(timezone.utc) + timedelta(days=2)
        ics = ('BEGIN:VCALENDAR\nBEGIN:VEVENT\n'
               f'DTSTART:{start.strftime("%Y%m%dT%H%M%SZ")}\n'
               'DTEND:20261202T230000Z\n'
               'SUMMARY:Dyna kolacja\nEND:VEVENT\nEND:VCALENDAR\n')
        with patch('urllib.request.urlopen',
                   lambda req, timeout=None: FakeResponse(ics.encode())):
            out = connectors_hub.execute_connector_action(
                'calendar_events', {'connector_id': 'gcal', 'days_ahead': 7})
        self.assertTrue(out['ok'])
        self.assertEqual(out['mode'], 'ics')
        self.assertEqual(out['count'], 1)
        self.assertEqual(out['events'][0]['summary'], 'Dyna kolacja')

    def test_gmail_send_write_gate_via_router(self):
        with self.assertRaises(ValueError) as ctx:
            connectors_hub.execute_connector_action(
                'gmail_send', {'to': 'x@y.z', 'subject': 's', 'body': 'b'})
        self.assertIn('wymaga jawnego potwierdzenia', str(ctx.exception))

    def test_cron_zero_config_with_toolset_gate_and_passthrough(self):
        connectors_hub.set_toolset_enabled('automation', False)
        with self.assertRaises(ValueError) as ctx:
            connectors_hub.execute_connector_action('cron_list', {})
        self.assertIn("Zestaw narzędzi 'automation'", str(ctx.exception))
        connectors_hub.set_toolset_enabled('automation', True)
        seen = []

        def fake_cron(action, body):
            seen.append((action, body))
            return {'ok': True, 'via': 'cron_manage'}

        with patch.object(connectors_hub.toolsets_catalog, 'cron_manage', fake_cron):
            out = connectors_hub.execute_connector_action('cron_create', {'payload': 1})
        self.assertEqual(out, {'ok': True, 'via': 'cron_manage'})
        self.assertEqual(seen, [('cron_create', {'payload': 1})])  # body passed through

    def test_web_search_zero_config_and_discord_settings_passthrough(self):
        seen = []

        def fake_web(action, settings, body, validate):
            seen.append(('web', settings, body.get('query'), validate))
            return {'ok': True, 'via': 'web'}

        with patch.object(connectors_hub.toolsets_catalog, 'run_web_tools', fake_web):
            out = connectors_hub.execute_connector_action('web_search', {'query': 'hello'})
        self.assertEqual(out, {'ok': True, 'via': 'web'})
        self.assertEqual(seen[0][1], {})  # zero-config provider: empty settings
        self.assertEqual(seen[0][2], 'hello')
        self.assertIs(seen[0][3], connectors_hub.validate_remote_url)  # SSRF gate handed over

        with self.assertRaises(ValueError):
            connectors_hub.execute_connector_action('discord_send', {})
        self.configure('dc', 'discord',
                      {'webhook_url': 'https://discord.com/api/webhooks/1/abc'})

        def fake_messaging(action, settings, body, validate):
            seen.append(('msg', settings.get('webhook_url')))
            return {'ok': True, 'via': 'msg'}

        with patch.object(connectors_hub.toolsets_catalog, 'run_messaging_extra', fake_messaging):
            out = connectors_hub.execute_connector_action('discord_send', {'content': 'hi'})
        self.assertEqual(out, {'ok': True, 'via': 'msg'})
        self.assertEqual(seen[-1][1], 'https://discord.com/api/webhooks/1/abc')

    def test_mcp_list_tools_through_router(self):
        self.configure('mcpy', 'mcp_stdio', {'command': echo_command()})
        out = connectors_hub.execute_connector_action('mcp_list_tools', {'connector_id': 'mcpy'})
        self.assertTrue(out['ok'])
        self.assertEqual([t['namespaced'] for t in out['result']['tools']],
                         ['mcp__mcpy__echo_tool', 'mcp__mcpy__other_tool'])


class TestBriefingAndList(ConnectorsHubBase):
    def test_briefing_digest_counts(self):
        self.configure('g1', 'gmail', {'email': 'a@b.c', 'app_password': 'p'})
        self.configure('tg', 'telegram', {'bot_token': 'b:t', 'chat_id': '9'})
        digest = connectors_hub.briefing_digest()
        self.assertEqual(digest['configured_count'], 2)
        self.assertEqual(digest['providers'], ['gmail', 'telegram'])
        self.assertEqual(digest['catalog_total'], 18)
        self.assertEqual(digest['toolsets_total'], 8)
        self.assertEqual(digest['disabled_toolsets'], [])
        self.assertGreaterEqual(digest['active_tools_count'], 4)  # cron zero-config tools

    def test_list_connectors_status_matrix(self):
        self.configure('tg', 'telegram', {'bot_token': 'b:t', 'chat_id': '9'})
        view = connectors_hub.list_connectors()
        self.assertEqual(len(view['toolsets']), 8)
        self.assertEqual(len(view['supported_providers']), 18)
        self.assertIsInstance(view['mcp_presets'], list)
        status = {c['provider']: c['status'] for c in view['catalog']}
        self.assertEqual(status['telegram'], 'connected')
        self.assertEqual(status['gmail'], 'available')       # catalogued but not configured
        self.assertEqual(status['open_meteo'], 'ready_zero_key')
        # connector items are masked; raw token never leaves the vault
        item = next(c for c in view['connectors'] if c['id'] == 'tg')
        self.assertEqual(item['settings']['bot_token'], '••••••••')
        # toolset switch flips every provider inside that toolset
        connectors_hub.set_toolset_enabled('messaging', False)
        view2 = connectors_hub.list_connectors()
        status2 = {c['provider']: c['status'] for c in view2['catalog']}
        self.assertEqual(status2['telegram'], 'disabled')
        self.assertFalse(next(t for t in view2['toolsets'] if t['id'] == 'messaging')['enabled'])


if __name__ == '__main__':
    unittest.main()
