"""REA reverse-engineering bay: diagnosis and bounded JSON command execution.

Python standard library only. This module is soft-imported by server.py; a
missing or broken bay must never stop Jarvis from booting. No network calls and
no package installation happen here. REA is invoked directly through the
resolved Node binary so startup does not depend on the user's shell PATH.
"""
from __future__ import annotations

import json
import os
import platform
import re
import shutil
import signal
import subprocess
import tempfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

import rea_limits

try:  # The ephemeral browser is optional at import time; diagnosis explains it.
    import browser_bay
except Exception:  # ImportError, syntax errors, or a platform missing a stdlib piece.
    browser_bay = None

if browser_bay is not None:
    BrowserError = browser_bay.BrowserError
    BrowserBusy = browser_bay.BrowserBusy
else:  # Stable names so server error handling does not depend on the optional import.
    class BrowserError(RuntimeError):
        pass

    class BrowserBusy(BrowserError):
        pass

TOOLS_ROOT = Path.home() / '.jarvis-tools'
REA_ROOT = TOOLS_ROOT / 'rea'
PACKAGE_NAME = 'rea-agents'
PACKAGE_ROOT = REA_ROOT / 'node_modules' / PACKAGE_NAME
REA_SCRIPT = PACKAGE_ROOT / 'scripts' / 'rea.mjs'
OFFICIAL_REPOSITORY = 'github.com/morluto/rea'
# Pinned at build time; never resolved from npm at runtime.
PINNED_VERSION = '6.7.0'
NODE_ENGINE_RANGE = '^22.19.0 || ^24.11.0 || >=26.0.0'
DEFAULT_TIMEOUT = rea_limits.REA_TIMEOUT_DEFAULT
MAX_TIMEOUT = rea_limits.REA_TIMEOUT_MAX
MAX_OUTPUT = rea_limits.REA_STDERR_BYTES
# The JSON scan runs over the whole capture: `--full-output` includes script
# sources and a short tail would be a fragment of a valid document. Above this
# bound the command is refused instead of buffering without limit.
MAX_STDOUT = rea_limits.REA_STDOUT_BYTES
_CACHE_SECONDS = 5.0
_cache_lock = threading.Lock()
_cache_value = None
_cache_at = 0.0


class Cancelled(RuntimeError):
    """The user cancelled while an REA command was running."""


class NotReady(Exception):
    """The bay cannot run a teardown request yet."""

    def __init__(self, diag):
        self.diag = diag
        super().__init__(one_line_answer(diag))


def _version_tuple(text):
    match = re.search(r'(\d+)\.(\d+)(?:\.(\d+))?', str(text))
    return tuple(int(part or 0) for part in match.groups()) if match else None


def node_supported(version):
    """REA engines: ^22.19.0 || ^24.11.0 || >=26.0.0 (odd majors excluded)."""
    parsed = _version_tuple(version)
    if not parsed:
        return False
    major, minor, _patch = parsed
    if major == 22:
        return minor >= 19
    if major == 24:
        return minor >= 11
    return major >= 26


def _node_candidates():
    seen = set()
    candidates = []
    explicit = os.environ.get('JARVIS_NODE') or os.environ.get('NODE_BINARY')
    if explicit:
        candidates.append(Path(explicit))
    found = shutil.which('node')
    if found:
        candidates.append(Path(found))
    home = Path.home()
    system = platform.system()
    if system == 'Windows':
        for env in ('PROGRAMFILES', 'PROGRAMFILES(X86)', 'LOCALAPPDATA'):
            base = os.environ.get(env)
            if base:
                candidates.append(Path(base) / 'nodejs' / 'node.exe')
                candidates.append(Path(base) / 'Programs' / 'nodejs' / 'node.exe')
        candidates.extend(Path(base) / 'node.exe' for base in
                          (home / 'scoop/apps/nodejs/current', home / 'AppData/Roaming/nvm'))
    else:
        for base in ('/usr/local/bin', '/usr/bin', '/opt/homebrew/bin', '/opt/local/bin',
                     '/snap/bin', '/opt/node/bin', str(home / '.local/bin'),
                     str(home / '.nvm/versions/node')):
            candidates.append(Path(base) / 'node')
        candidates.extend(sorted((home / '.nvm/versions/node').glob('*/bin/node')))
        candidates.extend(sorted((home / '.volta/bin').glob('node')))
        candidates.extend(sorted((home / '.hermes/tools').glob('node-*/bin/node')))
        candidates.extend(sorted((home / '.local/share/fnm/node-versions').glob('*/installation/bin/node')))
    result = []
    for path in candidates:
        key = str(path)
        if key not in seen and path.is_file() and os.access(path, os.X_OK):
            seen.add(key)
            result.append(path)
    return result


def find_node():
    """Return the best usable Node executable, preferring a supported version."""
    fallback = None
    for path in _node_candidates():
        try:
            probe = subprocess.run([str(path), '--version'], capture_output=True, text=True,
                                   timeout=8, stdin=subprocess.DEVNULL)
        except (OSError, subprocess.SubprocessError):
            continue
        version = probe.stdout.strip().lstrip('v') or probe.stderr.strip().lstrip('v')
        if probe.returncode != 0 or not _version_tuple(version):
            continue
        entry = {'path': str(path), 'version': version, 'supported': node_supported(version)}
        if entry['supported']:
            # Short-circuit: the candidate order already encodes priority
            # (explicit env, PATH, system dirs, version managers), so the
            # first supported hit is the best usable one; probing the rest
            # used to spawn up to a dozen processes on every boot.
            return entry
        if fallback is None:
            fallback = entry
    return fallback


def _chrome_candidates():
    system = platform.system()
    home = Path.home()
    candidates = []
    explicit = os.environ.get('CHROME_PATH') or os.environ.get('GOOGLE_CHROME_SHIM')
    if explicit:
        candidates.append((Path(explicit), 'configured'))
    if system == 'Darwin':
        candidates.extend([
            (Path('/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'), 'google-chrome'),
            (home / 'Applications/Google Chrome.app/Contents/MacOS/Google Chrome', 'google-chrome'),
            (Path('/Applications/Chromium.app/Contents/MacOS/Chromium'), 'chromium'),
        ])
    elif system == 'Windows':
        for env in ('PROGRAMFILES', 'PROGRAMFILES(X86)', 'LOCALAPPDATA'):
            base = os.environ.get(env)
            if base:
                candidates.append((Path(base) / 'Google/Chrome/Application/chrome.exe', 'google-chrome'))
                candidates.append((Path(base) / 'Chromium/Application/chrome.exe', 'chromium'))
    else:
        for name, kind in (('google-chrome', 'google-chrome'), ('google-chrome-stable', 'google-chrome'),
                           ('chromium', 'chromium'), ('chromium-browser', 'chromium')):
            found = shutil.which(name)
            if found:
                candidates.append((Path(found), kind))
        candidates.extend([
            (Path('/opt/google/chrome/chrome'), 'google-chrome'),
            (Path('/snap/bin/chromium'), 'chromium'),
        ])
    # Official Google "Chrome for Testing" builds shipped by Playwright.
    caches = [home / '.cache/ms-playwright']
    if system == 'Darwin':
        caches.append(home / 'Library/Caches/ms-playwright')
    elif system == 'Windows':
        caches.append(home / 'AppData/Local/ms-playwright')
    for cache in caches:
        for pattern in ('chromium-*/chrome-linux64/chrome',
                        'chromium-*/chrome-mac*/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing',
                        'chromium-*/chrome-win/chrome.exe'):
            candidates.extend((path, 'chrome-for-testing') for path in sorted(cache.glob(pattern), reverse=True))
    seen = set()
    result = []
    for path, kind in candidates:
        key = str(path)
        if key not in seen and path.is_file() and os.access(path, os.X_OK):
            seen.add(key)
            result.append((path, kind))
    return result


def find_chrome():
    """Find an official Chrome for Testing build first, then a desktop browser.

    Snap Chromium is deliberately not preferred: its confinement can deny the
    fresh profile directory under ~/.jarvis-tools, which looks like a Chrome
    crash rather than a browser-selection problem.
    """
    priority = {'configured': 0, 'chrome-for-testing': 1, 'google-chrome': 2, 'chromium': 3}
    candidates = sorted(_chrome_candidates(), key=lambda item: priority.get(item[1], 9))
    for path, kind in candidates:
        version = None
        try:
            probe = subprocess.run([str(path), '--version'], capture_output=True, text=True,
                                   timeout=10, stdin=subprocess.DEVNULL)
            version = (probe.stdout or probe.stderr).strip().splitlines()[0][:160] or None
        except (OSError, subprocess.SubprocessError, IndexError):
            pass
        if not version:
            # Keep hunting: the first candidate used to win even when its probe
            # crashed, and shadows a working Chrome-for-Testing in the local cache.
            continue
        return {'found': True, 'path': str(path), 'kind': kind, 'version': version}
    return {'found': False, 'path': None, 'kind': None, 'version': None}


def _read_json(path):
    try:
        return json.loads(Path(path).read_text(encoding='utf-8'))
    except (OSError, ValueError, UnicodeError):
        return None


def rea_status():
    manifest = _read_json(REA_ROOT / 'package.json') or {}
    dependencies = manifest.get('dependencies') if isinstance(manifest, dict) else {}
    pinned = dependencies.get(PACKAGE_NAME) if isinstance(dependencies, dict) else None

    def exact(value):
        return isinstance(value, str) and bool(re.fullmatch(r'\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?', value))

    installed_manifest = _read_json(PACKAGE_ROOT / 'package.json') or {}
    installed = installed_manifest.get('version') if isinstance(installed_manifest, dict) else None
    repository = installed_manifest.get('repository') if isinstance(installed_manifest, dict) else None
    if isinstance(repository, dict):
        repository = repository.get('url')
    repository = repository if isinstance(repository, str) else None
    return {
        'root': str(REA_ROOT),
        'installed': installed,
        'pinned': pinned,
        'pinned_exact': exact(pinned),
        'entrypoint': str(REA_SCRIPT),
        'entrypoint_exists': REA_SCRIPT.is_file(),
        'repository': repository,
        'repository_official': bool(repository) and OFFICIAL_REPOSITORY in repository.lower(),
        'package_present': (PACKAGE_ROOT / 'package.json').is_file(),
    }


def install_commands(version=PINNED_VERSION):
    return [
        'mkdir -p ~/.jarvis-tools/rea',
        'cd ~/.jarvis-tools/rea',
        'npm init -y',
        f'npm install {PACKAGE_NAME}@{version} --save-exact --ignore-scripts',
    ]


def _install_line(version=PINNED_VERSION):
    return ' && '.join(install_commands(version))


def diagnose(force=False):
    global _cache_value, _cache_at
    with _cache_lock:
        now = time.monotonic()
        if not force and _cache_value is not None and now - _cache_at < _CACHE_SECONDS:
            return json.loads(json.dumps(_cache_value))

    node = find_node()
    chrome = find_chrome()
    rea = rea_status()
    problems = []
    if not node or not node.get('path') or not node.get('version'):
        problems.append('Node.js is not installed. Install Node.js 22.19+ (or 24.11+) and reopen the server.')
    elif not node['supported']:
        problems.append(f"Node.js v{node['version']} is not supported; install Node.js 22.19+ or 24.11+.")
    if not rea['package_present']:
        problems.append(f'REA is not installed. Run: {_install_line()}')
    else:
        if not rea['pinned_exact']:
            problems.append(f"REA is not pinned to an exact version; reinstall with: npm install {PACKAGE_NAME}@{rea['installed'] or PINNED_VERSION} --save-exact --ignore-scripts")
        if not rea['installed']:
            problems.append(f"REA's installed version cannot be read; reinstall with: {_install_line()}")
        elif rea['pinned_exact'] and rea['installed'] != rea['pinned']:
            problems.append(f"REA is installed at {rea['installed']} but pinned to {rea['pinned']}; reinstall with: {_install_line(rea['pinned'])}")
        if not rea['entrypoint_exists']:
            problems.append(f"REA's CLI entrypoint is missing at {REA_SCRIPT}; reinstall with: {_install_line()}")
        if rea['repository'] and not rea['repository_official']:
            problems.append('The installed rea-agents package does not point at github.com/morluto/rea; remove it and reinstall from the official package.')
    if not chrome['found']:
        problems.append('Google Chrome was not found. Install Google Chrome from https://www.google.com/chrome/ (on Linux, a Chromium or Chrome for Testing build is also accepted).')
    if browser_bay is None:
        problems.append('browser_bay.py could not be imported; ephemeral teardown browsers are offline.')

    payload = {
        'ready': not problems,
        'rea': rea,
        'node': node or {'path': None, 'version': None, 'supported': False},
        'chrome': chrome,
        'browser': {
            'available': browser_bay is not None,
            'profile_root': str(browser_bay.PROFILES_ROOT) if browser_bay is not None else None,
            'port': browser_bay.DEBUG_PORT if browser_bay is not None else None,
            'window_size': [browser_bay.WINDOW_WIDTH, browser_bay.WINDOW_HEIGHT] if browser_bay is not None else None,
        },
        'engine_range': NODE_ENGINE_RANGE,
        'platform': platform.system().lower(),
        'limits': rea_limits.snapshot(),
        'problems': problems,
        'checked_at': datetime.now(timezone.utc).isoformat(timespec='seconds'),
        'pinned_target': PINNED_VERSION,
    }
    with _cache_lock:
        _cache_value = json.loads(json.dumps(payload))
        _cache_at = time.monotonic()
    return payload


def diag():
    return diagnose()


def one_line_answer(diag_result):
    """A single in-character line that names exactly what to install."""
    problems = (diag_result or {}).get('problems') or []
    if not problems:
        return 'The reverse-engineering bay is ready, sir; REA is installed, pinned and waiting.'
    parts = []
    for problem in problems:
        text = str(problem).replace('\n', ' ').strip().rstrip('.')
        parts.append(text)
    return ('Not yet, sir; the reverse-engineering bay needs attention: '
            + '; '.join(parts)[:600] + '. Nothing has been torn down.')


def _extract_json(text):
    stripped = text.strip()
    if not stripped:
        return None, 'empty output'
    try:
        return json.loads(stripped), None
    except ValueError:
        pass
    start, end = stripped.find('{'), stripped.rfind('}')
    if start >= 0 and end > start:
        try:
            return json.loads(stripped[start:end + 1]), None
        except ValueError:
            pass
    return None, 'output was not valid JSON'


def run(command, target=None, arguments=None, timeout=DEFAULT_TIMEOUT, cancel=None):
    """Run one REA command with --json. Returns a structured result, never crashes."""
    status = diag()
    if not status['ready']:
        raise NotReady(status)
    if not isinstance(command, str) or not re.fullmatch(r'[a-z][a-z0-9-]{0,63}', command):
        return {'ok': False, 'error': 'invalid_command', 'answer':
                'That is not a valid REA command, sir; nothing was executed.',
                'receipt': {'exit_code': None, 'duration_ms': 0}}
    if target is not None and (not isinstance(target, str) or not target.strip()
                               or len(target) > 4096 or '\x00' in target or '\n' in target):
        return {'ok': False, 'error': 'invalid_target', 'answer':
                'That target is not usable, sir; nothing was executed.',
                'receipt': {'exit_code': None, 'duration_ms': 0}}
    if arguments is None:
        arguments = []
    if (not isinstance(arguments, list) or len(arguments) > 32
            or any(not isinstance(item, str) or len(item) > 4096 or '\x00' in item or '\n' in item
                   for item in arguments)):
        return {'ok': False, 'error': 'invalid_arguments', 'answer':
                'Those REA arguments are not usable, sir; nothing was executed.',
                'receipt': {'exit_code': None, 'duration_ms': 0}}
    try:
        timeout = int(timeout)
    except (TypeError, ValueError):
        timeout = DEFAULT_TIMEOUT
    timeout = max(10, min(MAX_TIMEOUT, timeout))

    node = status['node']['path']
    argv = [node, str(REA_SCRIPT), command]
    if target is not None:
        argv.append(target)
    argv.extend(arguments)
    argv.append('--json')
    # REA is a pinned third-party Node package. Do not hand it the server's
    # whole environment: DEEPSEEK_API_KEY and other Jarvis secrets used to be
    # inherited by every REA child. Only what a browser/Node run needs.
    allowed_env = ('HOME', 'LANG', 'LC_ALL', 'LC_CTYPE', 'TMPDIR', 'USER', 'LOGNAME',
                   'DISPLAY', 'WAYLAND_DISPLAY', 'XDG_RUNTIME_DIR', 'XDG_SESSION_TYPE',
                   'DBUS_SESSION_BUS_ADDRESS', 'XAUTHORITY', 'PATH')
    environment = {name: os.environ[name] for name in allowed_env if name in os.environ}
    environment['PATH'] = os.path.dirname(node) + os.pathsep + environment.get('PATH', '')
    def stop_process():
        try:
            if platform.system() == 'Windows':
                process.kill()
            else:
                os.killpg(os.getpgid(process.pid), signal.SIGKILL)
        except OSError:
            pass
        try:
            process.wait(timeout=10)
        except (subprocess.TimeoutExpired, OSError):
            pass

    started = time.monotonic()
    out_file = tempfile.TemporaryFile()
    err_file = tempfile.TemporaryFile()
    try:
        try:
            process = subprocess.Popen(argv, cwd=str(REA_ROOT), env=environment,
                                       stdout=out_file, stderr=err_file, text=False,
                                       stdin=subprocess.DEVNULL,
                                       start_new_session=(platform.system() != 'Windows'))
        except (OSError, ValueError):
            return {'ok': False, 'error': 'not_executable', 'command': command, 'target': target,
                    'answer': 'REA could not be started, sir; check the bay with /teardown/diag.',
                    'receipt': {'exit_code': None,
                                'duration_ms': int((time.monotonic() - started) * 1000)}}
        deadline = time.monotonic() + timeout
        timed_out = overflow = False
        # Spool to files and poll: PIPE+communicate buffered the whole stream in
        # RAM before the MAX_STDOUT check, so a noisy page could OOM the server.
        while process.poll() is None:
            if cancel is not None and cancel.is_set():
                stop_process()
                raise Cancelled('The teardown was cancelled; no note was filed.')
            try:
                out_size = os.fstat(out_file.fileno()).st_size
                err_size = os.fstat(err_file.fileno()).st_size
            except OSError:
                out_size = err_size = 0
            if out_size > MAX_STDOUT or err_size > MAX_STDOUT:
                overflow = True
                stop_process()
                break
            if time.monotonic() >= deadline:
                timed_out = True
                stop_process()
                break
            time.sleep(0.05)
        if timed_out:
            return {'ok': False, 'error': 'timeout', 'command': command, 'target': target,
                    'answer': f'REA did not finish {command} within {timeout} seconds, sir; it was stopped.',
                    'receipt': {'exit_code': None,
                                'duration_ms': int((time.monotonic() - started) * 1000)}}
        duration = int((time.monotonic() - started) * 1000)
        out_file.seek(0)
        err_file.seek(0)
        raw_stdout = out_file.read(MAX_STDOUT + 1).decode('utf-8', 'replace')
        raw_stderr = err_file.read(MAX_OUTPUT + 1).decode('utf-8', 'replace')
    finally:
        out_file.close()
        err_file.close()
    # `--full-output` captures whole script sources and easily exceeds the tail
    # cap, and a truncated JSON tail is not parseable at all. Parse the complete
    # capture (bounded by MAX_STDOUT) and keep the small tail only for errors.
    if overflow or len(raw_stdout) > MAX_STDOUT:
        return {'ok': False, 'error': 'output_too_large', 'command': command, 'target': target,
                'answer': f'REA produced more than {MAX_STDOUT // 1_000_000} MB of output for '
                          f'{command}, sir; it was not parsed.',
                'receipt': {'exit_code': process.returncode, 'duration_ms': duration}}
    result, parse_error = _extract_json(raw_stdout)
    ok = process.returncode == 0 and parse_error is None
    stderr = raw_stderr[-MAX_OUTPUT:]
    payload = {
        'ok': ok,
        'command': command,
        'target': target,
        'result': result,
        'error': None if ok else ('json_parse' if process.returncode == 0 else 'rea_error'),
        'stderr': stderr[-8000:],
        'receipt': {'exit_code': process.returncode, 'duration_ms': duration},
    }
    if ok:
        payload['answer'] = f'REA completed {command} with exit code 0, sir; the JSON evidence is attached.'
    elif process.returncode == 0:
        payload['answer'] = f'REA finished {command} but produced no parseable JSON, sir; the raw tail is attached.'
    else:
        payload['answer'] = f'REA reported failure for {command} (exit code {process.returncode}), sir; the error tail is attached.'
    return payload


def browser_visit(url, job_id=None, headless=False, scroll=True):
    """Open one ephemeral Chrome, observe it, then close it and remove its profile."""
    status = diag()
    if not status['ready']:
        raise NotReady(status)
    if browser_bay is None:
        raise BrowserError('browser_bay.py could not be imported; the browser bay is offline.')
    chrome = find_chrome()
    if not chrome.get('found'):
        raise BrowserError('Chrome was not found; install Google Chrome or Chromium first.')
    return browser_bay.open_site(url, chrome['path'], job_id=job_id, headless=headless, scroll=scroll)


def browser_job(url, job_id=None, headless=False, scroll=True):
    """Build a live BrowserJob for a REA connect scenario; the caller owns close()."""
    status = diag()
    if not status['ready']:
        raise NotReady(status)
    if browser_bay is None:
        raise BrowserError('browser_bay.py could not be imported; the browser bay is offline.')
    chrome = find_chrome()
    if not chrome.get('found'):
        raise BrowserError('Chrome was not found; install Google Chrome or Chromium first.')
    return browser_bay.BrowserJob(url, chrome['path'], job_id=job_id, headless=headless, scroll=scroll)


def with_browser(url, callback, job_id=None, headless=False, scroll=True):
    """Keep one browser alive while callback(job) runs, then close it in a finally block."""
    job = browser_job(url, job_id=job_id, headless=headless, scroll=scroll)
    job.start()
    try:
        return callback(job)
    finally:
        job.close(raise_on_error=True)


def health_fields():
    """Small non-secret summary for embedding in other diagnostics."""
    status = diagnose()
    return {'ready': status['ready'], 'rea_version': status['rea']['installed'],
            'pinned': status['rea']['pinned'], 'node': status['node']['version'],
            'chrome': status['chrome']['found'], 'browser': status['browser']['available'],
            'problems': status['problems']}
