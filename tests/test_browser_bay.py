"""Unit tests for the ephemeral Chrome bay's validation and WebSocket codec."""
import socket
import struct
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import browser_bay


def _recv_exact(sock, count):
    data = b''
    while len(data) < count:
        chunk = sock.recv(count - len(data))
        if not chunk:
            raise AssertionError('socket closed')
        data += chunk
    return data


def _read_client_frame(sock):
    first, second = _recv_exact(sock, 2)
    opcode = first & 0x0F
    assert second & 0x80, 'client frames must be masked'
    length = second & 0x7F
    if length == 126:
        length = struct.unpack('!H', _recv_exact(sock, 2))[0]
    elif length == 127:
        length = struct.unpack('!Q', _recv_exact(sock, 8))[0]
    mask = _recv_exact(sock, 4)
    payload = _recv_exact(sock, length) if length else b''
    return opcode, bytes(byte ^ mask[index % 4] for index, byte in enumerate(payload))


def _server_frame(opcode, payload=b'', fin=True):
    first = (0x80 if fin else 0) | opcode
    length = len(payload)
    if length < 126:
        header = bytes([first, length])
    elif length < 65536:
        header = bytes([first, 126]) + struct.pack('!H', length)
    else:
        header = bytes([first, 127]) + struct.pack('!Q', length)
    return header + payload


class ValidationTests(unittest.TestCase):
    def test_urls_are_http_only_and_credential_free(self):
        self.assertEqual(browser_bay.validate_url('https://example.com/a?b=1'), 'https://example.com/a?b=1')
        self.assertEqual(browser_bay.validate_url('http://127.0.0.1:8000/'), 'http://127.0.0.1:8000/')
        for bad in ('file:///etc/passwd', 'ftp://example.com', 'https://user:pass@example.com',
                    'https://example.com/has space', '', 'javascript:alert(1)'):
            with self.subTest(bad=bad), self.assertRaises(browser_bay.BrowserError):
                browser_bay.validate_url(bad)

    def test_profile_process_matching_is_exact_not_a_substring(self):
        rows = [
            (101, ['chrome', '--user-data-dir=/tmp/job-a']),
            (102, ['chrome', '--user-data-dir=/tmp/job-a2']),
            (103, ['chrome', '--other', '/tmp/job-a']),
        ]
        with patch.object(browser_bay, '_iter_processes', return_value=rows):
            self.assertEqual(browser_bay._profile_pids('/tmp/job-a'), [101])

    def test_job_ids_cannot_escape_the_profile_root(self):
        self.assertEqual(browser_bay.validate_job_id('job-1'), 'job-1')
        for bad in ('../escape', '.', '..', 'a/b', '', 'x' * 65):
            with self.subTest(bad=bad), self.assertRaises(browser_bay.BrowserError):
                browser_bay.validate_job_id(bad)


class ObserveTests(unittest.TestCase):
    def test_a_late_navigation_reports_the_final_identity(self):
        class FakeWS:
            def __init__(self):
                self.states = iter(['complete', 'complete', 'interactive',
                                    'interactive', 'complete'])
                self.titles = iter(['Old title', 'New title'])
                self.urls = iter(['https://example.com/old', 'https://example.com/new'])

            def evaluate(self, expression):
                if expression == 'document.readyState':
                    return next(self.states, 'complete')
                if expression == 'document.title':
                    return next(self.titles, '')
                if expression == 'location.href':
                    return next(self.urls, '')
                if 'scrollY' in expression:
                    return 0
                return {}

        bay = object.__new__(browser_bay.BrowserJob)
        bay.url = 'https://example.com/old'
        bay.load_timeout = 5
        bay.intro_wait = 0
        bay.launch_started = time.monotonic()
        bay.scroll_page = False
        bay.job_id = 'job-1'
        bay.headless = True
        bay.profile = Path('/tmp/profile')
        bay.process = None
        bay.chrome_path = '/usr/bin/chrome'
        bay.sandbox = False
        bay.version = {}
        bay.target = {'webSocketDebuggerUrl': 'ws://debug', 'id': 't1'}
        bay._wait_target = lambda: bay.target
        ws = FakeWS()
        with patch.object(browser_bay, 'CDPWebSocket') as socket_class:
            socket_class.return_value.connect.return_value = ws
            facts = bay._observe()
        self.assertEqual(facts['url'], 'https://example.com/new')
        self.assertEqual(facts['title'], 'New title')
        self.assertEqual(facts['ready_state'], 'complete')


class TargetTests(unittest.TestCase):
    def page(self, url, target_id='T'):
        return {'type': 'page', 'url': url, 'id': target_id,
                'webSocketDebuggerUrl': f'ws://127.0.0.1:9333/devtools/page/{target_id}'}

    def test_www_and_redirects_choose_the_real_page(self):
        blank = self.page('about:blank', 'blank')
        site = self.page('https://www.example.com/', 'site')
        self.assertEqual(browser_bay.choose_target([blank, site], 'https://example.com/')['id'], 'site')
        redirected = self.page('https://www.example.org/landing', 'redirected')
        self.assertEqual(browser_bay.choose_target([blank, redirected], 'http://example.com/')['id'], 'redirected')

    def test_internal_pages_and_targets_without_ws_are_ignored(self):
        internal = self.page('chrome://newtab/', 'internal')
        broken = {'type': 'page', 'url': 'https://example.com/', 'id': 'broken'}
        self.assertIsNone(browser_bay.choose_target([internal, broken], 'https://example.com/'))


class WebSocketCodecTests(unittest.TestCase):
    def setUp(self):
        self.client, self.server = socket.socketpair()
        self.addCleanup(self.client.close)
        self.addCleanup(self.server.close)
        self.ws = browser_bay.CDPWebSocket('ws://127.0.0.1:9333/devtools/page/test')
        self.ws.sock = self.client
        self.ws.buffer = b''

    def test_client_frames_are_masked_and_large_frames_use_64bit_lengths(self):
        payload = b'x' * 70000
        self.ws._send_frame(0x1, payload)
        opcode, received = _read_client_frame(self.server)
        self.assertEqual(opcode, 0x1)
        self.assertEqual(received, payload)

    def test_fragmented_reply_and_ping_are_handled(self):
        self.server.sendall(_server_frame(0x1, b'{"a":', fin=False))
        self.server.sendall(_server_frame(0x9, b'ping'))
        self.server.sendall(_server_frame(0x0, b'1}', fin=True))
        opcode, payload = self.ws.recv_message(time.monotonic() + 2)
        self.assertEqual((opcode, payload), (0x1, b'{"a":1}'))
        pong_opcode, pong_payload = _read_client_frame(self.server)
        self.assertEqual((pong_opcode, pong_payload), (0xA, b'ping'))

    def test_large_single_frame_reply_is_read_completely(self):
        payload = b'z' * 70000
        self.server.sendall(_server_frame(0x1, payload))
        opcode, received = self.ws.recv_message(time.monotonic() + 2)
        self.assertEqual(opcode, 0x1)
        self.assertEqual(received, payload)


class LaunchFailureTests(unittest.TestCase):
    def test_a_missing_chrome_binary_raises_a_clean_browser_error(self):
        # A missing binary used to surface as a raw FileNotFoundError with the
        # freshly opened chrome.log fd left dangling forever.
        job = browser_bay.BrowserJob('http://example.test/', 'definitely-not-chrome',
                                     job_id='unittest-bay', port=9333)
        with tempfile.TemporaryDirectory() as tmp:
            job.profile = Path(tmp)
            (job.profile / 'chrome.log')  # the log lives under the temp profile
            with self.assertRaises(browser_bay.BrowserError) as caught:
                job._launch()
        self.assertIn('definitely-not-chrome', str(caught.exception))
        self.assertIsNone(job._log)  # the fd was closed before the raise


if __name__ == '__main__':
    unittest.main()
