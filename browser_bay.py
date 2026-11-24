"""Ephemeral Chrome for REA teardowns.

Each job gets a brand-new profile under ~/.jarvis-tools/rea/profiles/JOB_ID,
Chrome exposes CDP on loopback port 9333, and the profile is removed in a
finally-style close even when the page or REA fails. Standard library only.

The browser is deliberately narrow: Runtime.evaluate is used only for read-only
page facts, and Input.dispatchMouseEvent mouseWheel is the only input action.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import platform
import re
import secrets
import shlex
import shutil
import signal
import socket
import struct
import subprocess
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import urlopen

import rea_limits

try:
    import fcntl
except ImportError:  # Windows: the thread lock still serialises this process.
    fcntl = None

REA_ROOT = Path.home() / '.jarvis-tools' / 'rea'
PROFILES_ROOT = REA_ROOT / 'profiles'
DEBUG_PORT = 9333
CDP_ENDPOINT = f'http://127.0.0.1:{DEBUG_PORT}'
WINDOW_WIDTH, WINDOW_HEIGHT = 1280, 820
INTRO_WAIT = rea_limits.BROWSER_INTRO_WAIT
ENDPOINT_TIMEOUT = rea_limits.BROWSER_ENDPOINT_TIMEOUT
LOAD_TIMEOUT = rea_limits.BROWSER_LOAD_TIMEOUT
TARGET_TIMEOUT = rea_limits.BROWSER_TARGET_TIMEOUT
MAX_MESSAGE = 64 * 1024 * 1024
MAX_HEADER = 64 * 1024
JOB_RE = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z')
_WS_GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'
_LOCK = threading.Lock()


class BrowserError(RuntimeError):
    """The ephemeral browser could not complete or clean up a job."""


class BrowserBusy(BrowserError):
    """Another teardown owns port 9333."""


class BrowserCleanupError(BrowserError):
    """Chrome or its profile survived the close path."""


def _utc_stamp():
    return datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')


def new_job_id():
    return f'job-{_utc_stamp()}-{secrets.token_hex(4)}'


def validate_job_id(job_id):
    if not isinstance(job_id, str) or job_id in ('.', '..') or not JOB_RE.fullmatch(job_id):
        raise BrowserError('JOB_ID must be 1-64 characters of letters, digits, dot, underscore or hyphen.')
    return job_id


def validate_url(url):
    if not isinstance(url, str) or not url or len(url) > 2048:
        raise BrowserError('A non-empty HTTP(S) URL is required.')
    if any(ord(char) < 0x20 or char == ' ' for char in url):
        raise BrowserError('The URL contains whitespace or control characters.')
    try:
        parsed = urlsplit(url)
        hostname = parsed.hostname
    except ValueError:
        raise BrowserError('The URL is not valid.') from None
    if parsed.scheme not in ('http', 'https') or not hostname:
        raise BrowserError('Only absolute http:// and https:// URLs are allowed.')
    if parsed.username is not None or parsed.password is not None:
        raise BrowserError('Credentials must not be placed in the URL.')
    return url


def _port_open(port=DEBUG_PORT):
    sock = socket.socket()
    try:
        return sock.connect_ex(('127.0.0.1', port)) == 0
    finally:
        sock.close()


def _iter_processes():
    """Yield (pid, argv) for local processes using only the standard library."""
    system = platform.system()
    if system == 'Linux':
        proc = Path('/proc')
        for entry in proc.iterdir():
            if not entry.name.isdigit():
                continue
            try:
                raw = (entry / 'cmdline').read_bytes()
            except OSError:
                continue
            argv = [part.decode('utf-8', 'replace') for part in raw.split(b'\0') if part]
            if argv:
                yield int(entry.name), argv
    elif system == 'Darwin':
        try:
            output = subprocess.run(['ps', '-axo', 'pid=,command='], capture_output=True,
                                    text=True, timeout=10).stdout
        except (OSError, subprocess.SubprocessError):
            return
        for line in output.splitlines():
            parts = line.strip().split(None, 1)
            if len(parts) == 2 and parts[0].isdigit():
                try:
                    argv = shlex.split(parts[1])
                except ValueError:
                    argv = parts[1].split()
                yield int(parts[0]), argv
    elif system == 'Windows':
        try:
            output = subprocess.run(
                ['powershell', '-NoProfile', '-Command',
                 'Get-CimInstance Win32_Process | Select-Object ProcessId,CommandLine | ConvertTo-Json -Compress'],
                capture_output=True, text=True, timeout=15).stdout
            rows = json.loads(output) if output.strip() else []
        except (OSError, subprocess.SubprocessError, ValueError):
            return
        for row in rows if isinstance(rows, list) else [rows]:
            pid, command = row.get('ProcessId'), row.get('CommandLine')
            if isinstance(pid, int) and isinstance(command, str):
                yield pid, shlex.split(command, posix=False)


def _profile_pids(profile):
    # Exact argument match: the old substring check made profile "job-a"
    # claim every process for "job-a2" and kill another live browser.
    needle = f'--user-data-dir={profile}'
    own = os.getpid()
    return [pid for pid, argv in _iter_processes()
            if pid != own and needle in argv]


def _pid_still_matches(pid, predicate):
    for candidate, argv in _iter_processes():
        if candidate == pid:
            return bool(predicate(argv))
    return False


def _alive(pid):
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def _terminate_pids(pids, grace=2.0, check=None):
    pids = [pid for pid in dict.fromkeys(int(pid) for pid in pids) if pid > 1 and pid != os.getpid()]
    if check is not None:
        pids = [pid for pid in pids if _pid_still_matches(pid, check)]
    for pid in pids:
        try:
            os.kill(pid, signal.SIGTERM)
        except OSError:
            pass
    deadline = time.monotonic() + grace
    while time.monotonic() < deadline and any(_alive(pid) for pid in pids):
        time.sleep(0.1)
    remaining = [pid for pid in pids if _alive(pid)]
    if check is not None:
        # The pid may have exited and been reused during the grace period.
        remaining = [pid for pid in remaining if _pid_still_matches(pid, check)]
    kill_signal = getattr(signal, 'SIGKILL', signal.SIGTERM)
    for pid in remaining:
        try:
            os.kill(pid, kill_signal)
        except OSError:
            pass
    return remaining


def _sandbox_blocked():
    if platform.system() != 'Linux':
        return False
    try:
        return Path('/proc/sys/kernel/apparmor_restrict_unprivileged_userns').read_text().strip() == '1'
    except OSError:
        return False


def choose_target(pages, requested_url):
    """Pick the page target for the site, tolerating www and redirects."""
    requested = urlsplit(requested_url)
    wanted = (requested.hostname or '').lower()

    def key(host):
        host = (host or '').lower()
        return host[4:] if host.startswith('www.') else host

    def http_page(target):
        try:
            parsed = urlsplit(target.get('url') or '')
            return (target.get('type') == 'page' and parsed.scheme in ('http', 'https')
                    and bool(parsed.hostname) and bool(target.get('webSocketDebuggerUrl')))
        except ValueError:
            return False

    usable = [target for target in pages if http_page(target)]
    matching = [target for target in usable
                if key(urlsplit(target['url']).hostname) == key(wanted)]
    if matching:
        return matching[0]
    # A redirect to a different host still leaves exactly one real page.
    if len(usable) == 1:
        return usable[0]
    return usable[0] if usable else None


class CDPWebSocket:
    """Minimal RFC 6455 client for Chrome DevTools Protocol."""

    def __init__(self, ws_url, timeout=15.0):
        self.ws_url = ws_url
        self.timeout = timeout
        self.sock = None
        self.buffer = b''
        self.ident = 0
        self._closed = False

    def connect(self):
        parsed = urlsplit(self.ws_url)
        if parsed.scheme != 'ws' or not parsed.hostname:
            raise BrowserError('CDP WebSocket URL must use ws://.')
        if parsed.hostname not in ('127.0.0.1', 'localhost', '::1'):
            raise BrowserError('CDP WebSocket must be loopback-only.')
        if parsed.username is not None or parsed.password is not None:
            raise BrowserError('CDP WebSocket must not contain credentials.')
        port = parsed.port or 80
        path = parsed.path or '/'
        if parsed.query:
            path += '?' + parsed.query
        host_header = f'[{parsed.hostname}]' if ':' in parsed.hostname else parsed.hostname
        if port != 80:
            host_header += f':{port}'
        key = base64.b64encode(os.urandom(16)).decode('ascii')
        request = (
            f'GET {path} HTTP/1.1\r\n'
            f'Host: {host_header}\r\n'
            'Upgrade: websocket\r\n'
            'Connection: Upgrade\r\n'
            f'Sec-WebSocket-Key: {key}\r\n'
            'Sec-WebSocket-Version: 13\r\n'
            '\r\n'
        ).encode('ascii')
        self.sock = socket.create_connection((parsed.hostname, port), timeout=self.timeout)
        self.sock.sendall(request)
        raw = b''
        while b'\r\n\r\n' not in raw:
            if len(raw) > MAX_HEADER:
                raise BrowserError('CDP handshake response was too large.')
            chunk = self.sock.recv(4096)
            if not chunk:
                raise BrowserError('CDP handshake closed before headers arrived.')
            raw += chunk
        head, self.buffer = raw.split(b'\r\n\r\n', 1)
        lines = head.decode('iso-8859-1').split('\r\n')
        if not lines or ' 101 ' not in f' {lines[0]} ':
            raise BrowserError(f'CDP handshake failed: {lines[0] if lines else "empty response"}')
        headers = {}
        for line in lines[1:]:
            if ':' in line:
                name, value = line.split(':', 1)
                headers[name.strip().lower()] = value.strip()
        expected = base64.b64encode(hashlib.sha1((key + _WS_GUID).encode('ascii')).digest()).decode('ascii')
        if headers.get('sec-websocket-accept') != expected:
            raise BrowserError('CDP handshake returned the wrong Sec-WebSocket-Accept.')
        if headers.get('upgrade', '').lower() != 'websocket':
            raise BrowserError('CDP handshake did not upgrade to WebSocket.')
        return self

    def _read_exact(self, count, deadline):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise BrowserError('CDP WebSocket read timed out.')
        self.sock.settimeout(max(0.1, min(remaining, 30.0)))
        while len(self.buffer) < count:
            chunk = self.sock.recv(max(4096, count - len(self.buffer)))
            if not chunk:
                raise BrowserError('CDP WebSocket closed unexpectedly.')
            self.buffer += chunk
        data, self.buffer = self.buffer[:count], self.buffer[count:]
        return data

    def _read_frame(self, deadline):
        first, second = self._read_exact(2, deadline)
        fin = bool(first & 0x80)
        opcode = first & 0x0F
        masked = bool(second & 0x80)
        length = second & 0x7F
        if length == 126:
            length = struct.unpack('!H', self._read_exact(2, deadline))[0]
        elif length == 127:
            length = struct.unpack('!Q', self._read_exact(8, deadline))[0]
        if length > MAX_MESSAGE:
            raise BrowserError('CDP frame exceeded the 64 MB safety limit.')
        mask = self._read_exact(4, deadline) if masked else None
        payload = self._read_exact(length, deadline) if length else b''
        if mask:
            payload = bytes(byte ^ mask[index % 4] for index, byte in enumerate(payload))
        return fin, opcode, payload

    def _send_frame(self, opcode, payload=b''):
        if isinstance(payload, str):
            payload = payload.encode('utf-8')
        length = len(payload)
        header = bytearray([0x80 | opcode])
        mask = os.urandom(4)
        if length < 126:
            header.append(0x80 | length)
        elif length < 65536:
            header.append(0x80 | 126)
            header.extend(struct.pack('!H', length))
        else:
            header.append(0x80 | 127)
            header.extend(struct.pack('!Q', length))
        header.extend(mask)
        masked = bytes(byte ^ mask[index % 4] for index, byte in enumerate(payload))
        self.sock.sendall(bytes(header) + masked)

    def send_json(self, value):
        self._send_frame(0x1, json.dumps(value, ensure_ascii=False).encode('utf-8'))

    def recv_message(self, deadline):
        fragments, fragment_opcode = [], None
        while True:
            fin, opcode, payload = self._read_frame(deadline)
            if opcode == 0x9:  # ping
                self._send_frame(0xA, payload)
                continue
            if opcode == 0xA:  # pong
                continue
            if opcode == 0x8:
                try:
                    self._send_frame(0x8, struct.pack('!H', 1000))
                except OSError:
                    pass
                raise BrowserError('CDP WebSocket closed by Chrome.')
            if opcode in (0x1, 0x2):
                if fragments:
                    raise BrowserError('CDP received a new message before a fragmented one finished.')
                if fin:
                    return opcode, payload
                fragments, fragment_opcode = [payload], opcode
                continue
            if opcode == 0x0:
                if not fragments:
                    raise BrowserError('CDP received a continuation without a first frame.')
                fragments.append(payload)
                if fin:
                    return fragment_opcode, b''.join(fragments)
                continue
            raise BrowserError(f'CDP received unsupported opcode {opcode}.')

    def call(self, method, params=None, timeout=30.0):
        self.ident += 1
        ident = self.ident
        self.send_json({'id': ident, 'method': method, 'params': params or {}})
        deadline = time.monotonic() + timeout
        while True:
            opcode, payload = self.recv_message(deadline)
            if opcode != 0x1:
                continue
            try:
                message = json.loads(payload.decode('utf-8'))
            except (ValueError, UnicodeError):
                continue
            if message.get('id') != ident:
                continue  # CDP event, not our response.
            if 'error' in message:
                error = message['error']
                raise BrowserError(f"CDP {method} failed: {error.get('message') or error}")
            return message.get('result', {})

    def evaluate(self, expression, timeout=20.0):
        """Runtime.evaluate, read-only by construction: no user-supplied expression."""
        result = self.call('Runtime.evaluate', {
            'expression': expression,
            'returnByValue': True,
            'awaitPromise': True,
            'userGesture': False,
        }, timeout=timeout)
        if result.get('exceptionDetails'):
            details = result['exceptionDetails']
            raise BrowserError(f"Page evaluation failed: {details.get('text') or details}")
        remote = result.get('result') or {}
        if remote.get('type') == 'undefined':
            return None
        return remote.get('value')

    def wheel(self, delta_y=900, timeout=20.0):
        self.call('Input.dispatchMouseEvent', {
            'type': 'mouseWheel',
            'x': WINDOW_WIDTH // 2,
            'y': WINDOW_HEIGHT // 2,
            'deltaX': 0,
            'deltaY': int(delta_y),
            'modifiers': 0,
            'pointerType': 'mouse',
            'button': 'none',
        }, timeout=timeout)

    def close(self):
        if self._closed:
            return
        self._closed = True
        if self.sock is not None:
            try:
                self._send_frame(0x8, struct.pack('!H', 1000))
            except OSError:
                pass
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None


class BrowserJob:
    """One Chrome launch, one profile, one CDP page target, one guaranteed close."""

    def __init__(self, url, chrome_path, job_id=None, headless=False, scroll=True,
                 load_timeout=LOAD_TIMEOUT, intro_wait=INTRO_WAIT, port=DEBUG_PORT):
        self.url = validate_url(url)
        self.chrome_path = str(chrome_path)
        self.job_id = validate_job_id(job_id or new_job_id())
        self.headless = bool(headless)
        self.scroll_page = bool(scroll)
        self.load_timeout = float(load_timeout)
        self.intro_wait = max(0.0, float(intro_wait))
        self.port = int(port)
        self.profile = PROFILES_ROOT / self.job_id
        self.process = None
        self.ws = None
        self.target = None
        self.facts = {}
        self.cleanup = None
        self.sandbox = True
        self.launch_started = 0.0
        self._thread_locked = False
        self._lock_fd = None
        self._log = None
        self._closed = False
        self._profile_created = False

    def _acquire(self):
        if not _LOCK.acquire(blocking=False):
            raise BrowserBusy('Another teardown owns the browser; port 9333 is busy.')
        self._thread_locked = True
        try:
            PROFILES_ROOT.mkdir(parents=True, exist_ok=True, mode=0o700)
            if fcntl is not None:
                self._lock_fd = os.open(PROFILES_ROOT / '.browser.lock', os.O_CREAT | os.O_RDWR, 0o600)
                try:
                    fcntl.flock(self._lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    raise BrowserBusy('Another Jarvis process owns the browser lock; port 9333 is busy.') from None
        except Exception:
            self._release()
            raise

    def _release(self):
        if self._lock_fd is not None:
            try:
                if fcntl is not None:
                    fcntl.flock(self._lock_fd, fcntl.LOCK_UN)
            except OSError:
                pass
            try:
                os.close(self._lock_fd)
            except OSError:
                pass
            self._lock_fd = None
        if self._thread_locked:
            self._thread_locked = False
            try:
                _LOCK.release()
            except RuntimeError:
                pass

    def _prepare_profile(self):
        if self.profile.exists():
            raise BrowserError(f'Profile {self.job_id} already exists; every teardown needs a fresh profile.')
        if PROFILES_ROOT.is_dir():
            for entry in PROFILES_ROOT.iterdir():
                if entry == self.profile or entry.name.startswith('.') or not entry.is_dir():
                    continue
                if not _profile_pids(entry):
                    shutil.rmtree(entry, ignore_errors=True)
        self.profile.mkdir(mode=0o700)
        self._profile_created = True

    def _clear_profile(self):
        _terminate_pids(_profile_pids(self.profile), grace=1.0,
                        check=lambda argv: f'--user-data-dir={self.profile}' in argv)
        shutil.rmtree(self.profile, ignore_errors=True)
        if self.profile.exists():
            raise BrowserError(f'Could not clear profile {self.profile}.')
        self.profile.mkdir(mode=0o700)
        self._profile_created = True

    def _kill_stale_owned(self):
        stale = []
        for pid, argv in _iter_processes():
            joined = ' '.join(argv)
            if f'--remote-debugging-port={self.port}' in joined and any(
                    arg.startswith('--user-data-dir=') and str(PROFILES_ROOT) in arg for arg in argv):
                stale.append(pid)
        if stale:
            _terminate_pids(stale, grace=2.0, check=lambda argv: (
                f'--remote-debugging-port={self.port}' in argv
                and any(arg.startswith('--user-data-dir=') and str(PROFILES_ROOT) in arg
                        for arg in argv)))

    def _ensure_port_free(self):
        if not _port_open(self.port):
            return
        self._kill_stale_owned()
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline:
            if not _port_open(self.port):
                return
            time.sleep(0.1)
        raise BrowserBusy(f'Port {self.port} is already in use by something Jarvis does not own; refusing to attach.')

    def _command(self, no_sandbox):
        args = [
            self.chrome_path,
            f'--user-data-dir={self.profile}',
            f'--remote-debugging-port={self.port}',
            '--remote-debugging-address=127.0.0.1',
            '--no-first-run',
            '--no-default-browser-check',
            '--disable-extensions',
            f'--window-size={WINDOW_WIDTH},{WINDOW_HEIGHT}',
            '--window-position=0,0',
            '--disable-background-networking',
            '--disable-sync',
            '--metrics-recording-only',
            '--mute-audio',
        ]
        if self.headless:
            args.append('--headless=new')
        if no_sandbox:
            args.append('--no-sandbox')
        args.append(self.url)
        return args

    def _read_log(self):
        try:
            if self._log is not None:
                self._log.flush()
            data = (self.profile / 'chrome.log').read_text(encoding='utf-8', errors='replace')
            return data[-4000:]
        except OSError:
            return ''

    def _wait_endpoint(self):
        deadline = time.monotonic() + ENDPOINT_TIMEOUT
        last = ''
        while time.monotonic() < deadline:
            if self.process is not None and self.process.poll() is not None:
                return None, f'Chrome exited with code {self.process.returncode}'
            try:
                with urlopen(f'{CDP_ENDPOINT}/json/version', timeout=1.0) as response:
                    if response.status == 200:
                        data = json.load(response)
                        if isinstance(data, dict) and data.get('webSocketDebuggerUrl'):
                            return data, ''
                last = f'HTTP {response.status}'
            except (HTTPError, URLError, TimeoutError, OSError, ValueError) as error:
                last = type(error).__name__
            time.sleep(0.15)
        return None, f'timed out after {ENDPOINT_TIMEOUT:.0f}s ({last})'

    def _launch(self):
        no_sandbox = _sandbox_blocked()
        for attempt in range(2):
            if attempt:
                self._clear_profile()
            self.sandbox = not no_sandbox
            try:
                self._log = open(self.profile / 'chrome.log', 'wb')
                self.launch_started = time.monotonic()
                self.process = subprocess.Popen(
                    self._command(no_sandbox), cwd=str(REA_ROOT),
                    stdin=subprocess.DEVNULL, stdout=self._log, stderr=subprocess.STDOUT,
                    start_new_session=(os.name == 'posix'),
                )
            except OSError as error:
                # A missing chrome binary or an unopenable profile used to leak
                # the just-opened log fd and surface as a raw FileNotFoundError.
                self._close_log()
                raise BrowserError(
                    f'Chrome did not start from {self.chrome_path}: {error}') from None
            version, reason = self._wait_endpoint()
            if version is not None:
                self.version = version
                self.endpoint_seconds = round(time.monotonic() - self.launch_started, 2)
                return
            tail = self._read_log()
            self._terminate_process()
            if not no_sandbox and 'No usable sandbox' in tail:
                no_sandbox = True
                continue
            raise BrowserError(f'Chrome did not expose CDP on 127.0.0.1:{self.port}: {reason}. {tail[-1200:]}')
        raise BrowserError('Chrome could not start with or without the Linux sandbox.')

    def _close_log(self):
        if self._log is not None:
            try:
                self._log.close()
            except OSError:
                pass
            self._log = None

    def _terminate_process(self):
        process = self.process
        if process is None:
            self._close_log()
            return
        try:
            if process.poll() is None and os.name == 'posix':
                os.killpg(os.getpgid(process.pid), signal.SIGTERM)
            elif process.poll() is None:
                process.terminate()
        except OSError:
            pass
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            try:
                if os.name == 'posix':
                    os.killpg(os.getpgid(process.pid), signal.SIGKILL)
                else:
                    process.kill()
            except OSError:
                pass
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass
        self._close_log()

    def _wait_target(self):
        deadline = time.monotonic() + TARGET_TIMEOUT
        last = []
        while time.monotonic() < deadline:
            try:
                with urlopen(f'{CDP_ENDPOINT}/json/list', timeout=2.0) as response:
                    pages = json.load(response)
            except (HTTPError, URLError, TimeoutError, OSError, ValueError) as error:
                last = [type(error).__name__]
                time.sleep(0.15)
                continue
            if isinstance(pages, list):
                target = choose_target(pages, self.url)
                if target is not None:
                    return target
                last = [f'{page.get("type")}:{page.get("url")}' for page in pages]
            time.sleep(0.15)
        raise BrowserError(f'No page target for {urlsplit(self.url).hostname} appeared ({last[-4:]}).')

    def _observe(self):
        self.target = self._wait_target()
        self.ws = CDPWebSocket(self.target['webSocketDebuggerUrl'], timeout=20.0).connect()
        state = None
        deadline = time.monotonic() + self.load_timeout
        while time.monotonic() < deadline:
            try:
                state = self.ws.evaluate('document.readyState')
            except BrowserError:
                state = None
            if state == 'complete':
                break
            time.sleep(0.1)
        if state != 'complete':
            raise BrowserError(f'Page did not reach document.readyState=complete within {self.load_timeout:.0f}s (last={state!r}).')
        load_seconds = round(time.monotonic() - self.launch_started, 2)
        if self.intro_wait:
            time.sleep(self.intro_wait)
        # A late navigation (redirect, lazy reload) can leave the document
        # 'interactive' again after the load gate, so a single sample here
        # reported a mid-navigation moment. Wait for the page to settle; the
        # receipt still requires 'complete'. Read the URL/title *after* the
        # settle gate (a late navigation used to pair the old identity with
        # the new document's readyState).
        settle_deadline = time.monotonic() + min(rea_limits.BROWSER_SETTLE_SECONDS,
                                                 self.load_timeout)
        ready_state = None
        title = final_url = ''
        for _ in range(2):
            while time.monotonic() < settle_deadline:
                try:
                    ready_state = self.ws.evaluate('document.readyState')
                except BrowserError:
                    ready_state = None
                if ready_state == 'complete':
                    break
                time.sleep(0.1)
            title = self.ws.evaluate('document.title') or ''
            final_url = self.ws.evaluate('location.href') or self.target.get('url') or self.url
            try:
                ready_state = self.ws.evaluate('document.readyState')
            except BrowserError:
                ready_state = None
            if ready_state == 'complete' or time.monotonic() >= settle_deadline:
                break
            # A navigation started between the settle and the identity read;
            # wait for it to finish and read the identity again.
            ready_state = None
        ready_state = ready_state or state
        viewport = self.ws.evaluate('({width: window.innerWidth, height: window.innerHeight})') or {}
        before = self.ws.evaluate('window.scrollY') or 0
        scrolled = False
        if self.scroll_page:
            for _ in range(3):
                self.ws.wheel(delta_y=900)
                time.sleep(0.15)
            time.sleep(0.5)
        after = self.ws.evaluate('window.scrollY') or 0
        try:
            before, after = float(before), float(after)
        except (TypeError, ValueError):
            before, after = 0.0, 0.0
        scrolled = after > before
        self.facts = {
            'ok': True,
            'job_id': self.job_id,
            'headless': self.headless,
            'url_requested': self.url,
            'url': str(final_url),
            'title': str(title)[:500],
            'ready_state': ready_state,
            'load_seconds': load_seconds,
            'endpoint_seconds': getattr(self, 'endpoint_seconds', load_seconds),
            'intro_wait_seconds': self.intro_wait,
            'scroll_y_before': before,
            'scroll_y_after': after,
            'scrolled': scrolled,
            'viewport': viewport if isinstance(viewport, dict) else {},
            'window_size': [WINDOW_WIDTH, WINDOW_HEIGHT],
            'profile': str(self.profile),
            'chrome_pid': self.process.pid if self.process else None,
            'chrome_path': self.chrome_path,
            'sandbox': self.sandbox,
            'cdp_endpoint': CDP_ENDPOINT,
            'target_id': self.target.get('id'),
            'web_socket_debugger_url': self.target.get('webSocketDebuggerUrl'),
            'browser_websocket_url': (self.version or {}).get('webSocketDebuggerUrl'),
            'rea_connect': {
                'browser': {
                    'mode': 'connect',
                    'cdp_endpoint': CDP_ENDPOINT,
                    'target_id': self.target.get('id'),
                }
            },
        }
        return dict(self.facts)

    def start(self):
        self._acquire()
        try:
            self._prepare_profile()
            self._ensure_port_free()
            self._launch()
            return self._observe()
        except BaseException:
            self.close(raise_on_error=False)
            raise

    def close(self, raise_on_error=True):
        if self._closed:
            if raise_on_error and self.cleanup and not self.cleanup.get('ok'):
                raise BrowserCleanupError('; '.join(self.cleanup.get('errors') or ['Browser cleanup previously failed.']))
            return self.cleanup or {}
        self._closed = True
        errors = []
        try:
            if self.ws is not None:
                self.ws.close()
                self.ws = None
        except Exception as error:
            errors.append(f'WebSocket close: {type(error).__name__}')
        try:
            self._terminate_process()
        except Exception as error:
            errors.append(f'Chrome termination: {type(error).__name__}')
        try:
            remaining = _terminate_pids(
                _profile_pids(self.profile), grace=2.0,
                check=lambda argv: f'--user-data-dir={self.profile}' in argv)
        except Exception as error:
            remaining = []
            errors.append(f'Profile process scan: {type(error).__name__}')
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline and _port_open(self.port):
            time.sleep(0.1)
        port_released = not _port_open(self.port)
        if not port_released:
            errors.append(f'Port {self.port} is still listening after Chrome termination.')
        profile_removed = not self.profile.exists() if not self._profile_created else False
        lingering = []
        if self._profile_created:
            for _ in range(10):
                try:
                    shutil.rmtree(self.profile)
                except FileNotFoundError:
                    profile_removed = True
                    break
                except OSError:
                    pass
                if not self.profile.exists():
                    profile_removed = True
                    break
                time.sleep(0.2)
            if not profile_removed:
                errors.append(f'Profile {self.profile} could not be deleted.')
            lingering = _profile_pids(self.profile)
            for _ in range(10):
                if not lingering:
                    break
                _terminate_pids(
                    lingering, grace=1.0,
                    check=lambda argv: f'--user-data-dir={self.profile}' in argv)
                time.sleep(0.2)
                lingering = _profile_pids(self.profile)
            if lingering:
                errors.append(f'Chrome processes still reference the profile: {lingering}.')
        self._release()
        self.cleanup = {
            'ok': not errors,
            'chrome_pid': self.process.pid if self.process else None,
            'terminated': self.process is not None and self.process.poll() is not None,
            'killed_pids': remaining,
            'lingering_pids': lingering,
            'profile': str(self.profile),
            'owned': self._profile_created,
            'profile_removed': profile_removed,
            'port': self.port,
            'port_released': port_released,
            'errors': errors,
        }
        if errors and raise_on_error:
            raise BrowserCleanupError('; '.join(errors))
        return self.cleanup


def open_site(url, chrome_path, job_id=None, headless=False, scroll=True,
              load_timeout=LOAD_TIMEOUT, intro_wait=INTRO_WAIT):
    """Open, observe, optionally wheel-scroll, and always close one ephemeral Chrome."""
    job = BrowserJob(url, chrome_path, job_id=job_id, headless=headless, scroll=scroll,
                     load_timeout=load_timeout, intro_wait=intro_wait)
    facts = None
    cleanup = {}
    try:
        facts = job.start()
    finally:
        cleanup = job.close(raise_on_error=False)
    facts['cleanup'] = cleanup
    if not cleanup.get('ok'):
        raise BrowserCleanupError('; '.join(cleanup.get('errors') or ['Browser cleanup failed.']))
    return facts


def with_browser(url, chrome_path, callback, job_id=None, headless=False, scroll=True):
    """Keep the browser alive for a callback (for example a REA connect scenario), then close."""
    job = BrowserJob(url, chrome_path, job_id=job_id, headless=headless, scroll=scroll)
    job.start()
    try:
        return callback(job)
    finally:
        job.close(raise_on_error=True)
