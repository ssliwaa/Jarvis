"""instance_reload: port-guard, hot-reload controller and debounced watcher.

The controller guards the real `jarvis.service`: this host actually runs the
service under systemd (INVOCATION_ID is set in the environment!), so every test
patches `subprocess.run`/`Popen`, `os.execv`, `os.kill` and controls the env —
one probe iteration restarted the real service, which is logged in AGENT_LOG.
The source-mtime scan runs on a real tmp tree and `is_port_open` against real
loopback sockets; everything else (urllib, threads, clock) is faked. Pinned:
mtime scan rules, instance_status stale boundary, systemd probe argv,
wait_for_healthy retry shape (max(1.0, timeout) deadline), trigger_self_reload
execv/systemd modes and SIGTERM fallbacks, reload_external POST headers,
the handle_address_in_use decision matrix and the debounced watcher (window
reset logic, busy deferral, exact Polish prints).
"""
import io
import os
import shutil
import signal
import socket
import sys
import tempfile
import unittest
import urllib.error
import urllib.request
from contextlib import contextmanager, redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import instance_reload as ir
from instance_reload import (
    WATCH_SKIP_DIRS,
    _any_agent_busy,
    handle_address_in_use,
    is_port_open,
    is_systemd_service_active,
    latest_source_mtime,
    probe_running_instance,
    reload_external_instance,
    trigger_self_reload,
    wait_for_healthy,
)


class FakeResp:
    def __init__(self, status=200, body=b'{}'):
        self.status = status
        self._body = body

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


class Sentinel(Exception):
    """Escapes the otherwise-infinite watcher loop from inside fake sleep."""


class FakeThread:
    captured = []

    def __init__(self, target=None, name=None, daemon=None):
        FakeThread.captured.append(SimpleNamespace(target=target, name=name, daemon=daemon))

    def start(self):
        pass


class ReloadBase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        # module-global reload state must not leak between tests
        self.addCleanup(setattr, ir, '_RELOADING', False)
        ir._RELOADING = False

    @staticmethod
    @contextmanager
    def clean_env():
        """Ensure INVOCATION_ID (ambient on this host) is absent for the block."""
        with patch.dict(os.environ):
            os.environ.pop('INVOCATION_ID', None)
            yield

    @staticmethod
    def touching(tmp, rel, mtime):
        path = tmp / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('x', encoding='utf-8')
        os.utime(path, (mtime, mtime))
        return path


class SourceMtime(ReloadBase):
    def test_scan_rules(self):
        self.touching(self.tmp, 'runtime.py', 100.0)
        self.touching(self.tmp, 'notes.txt', 2400.0)            # wrong suffix, ignored
        self.touching(self.tmp, '.hidden.py', 2000.0)          # dotfile ignored
        self.touching(self.tmp, '.venv/deep/mod.py', 3000.0)   # skip dir
        self.touching(self.tmp, 'tests/t.py', 4000.0)          # skip dir
        self.touching(self.tmp, 'artifacts/x.py', 5000.0)      # skip dir
        self.touching(self.tmp, 'viewer/app.js', 305.0)
        self.touching(self.tmp, 'viewer/main.css', 310.0)
        self.touching(self.tmp, 'viewer/idx.html', 307.0)
        self.touching(self.tmp, 'viewer/readme.md', 4000.0)    # wrong suffix inside viewer
        self.touching(self.tmp, 'operator_modules/deep/mod.py', 1500.0)
        # top-level .py, viewer assets (py/js/css/html) and operator_modules count;
        # dotfiles, .txt/.md and skip-dir contents never reach the max
        self.assertEqual(latest_source_mtime(self.tmp), 1500.0)

    def test_missing_or_file_root_is_zero(self):
        self.assertEqual(latest_source_mtime(self.tmp / 'nope'), 0.0)
        f = self.touching(self.tmp, 'a.py', 123.0)
        self.assertEqual(latest_source_mtime(f), 0.0)   # iterdir on a file: OSError

    def test_skip_dirs_constant(self):
        for name in ('tests', 'artifacts', '.venv', 'node_modules', 'dist', '__pycache__'):
            self.assertIn(name, WATCH_SKIP_DIRS)


class StatusAndSystemd(ReloadBase):
    def test_status_shape_stale_boundary_and_systemd_flag(self):
        self.touching(self.tmp, 'x.py', 900.0)
        with patch.object(ir, 'BOOT_TIME', 1000.0), \
                patch.object(ir.time, 'time', lambda: 1003.25), \
                patch.object(ir, 'is_systemd_service_active', lambda u='x': False), \
                self.clean_env():
            status = ir.instance_status(self.tmp)
        self.assertEqual(status, {'ok': True, 'pid': os.getpid(), 'boot_time': 1000.0,
                                  'uptime_s': 3.2, 'latest_source_mtime': 900.0,
                                  'stale': False, 'systemd_managed': False})
        # boundary: stale only once mtime exceeds boot + 1.0
        for mtime, expected in ((1001.0, False), (1001.6, True)):
            with self.subTest(mtime=mtime):
                self.touching(self.tmp, 'x.py', mtime)
                with patch.object(ir, 'BOOT_TIME', 1000.0), \
                        patch.object(ir, 'is_systemd_service_active', lambda u='x': False), \
                        self.clean_env():
                    self.assertEqual(ir.instance_status(self.tmp)['stale'], expected)
        # INVOCATION_ID alone marks the instance systemd-managed
        with patch.object(ir, 'BOOT_TIME', 1000.0), \
                patch.dict(os.environ, {'INVOCATION_ID': 'inv-x'}), \
                patch.object(ir, 'is_systemd_service_active',
                             lambda u='jarvis.service': False):
            self.assertTrue(ir.instance_status(self.tmp)['systemd_managed'])

    def test_is_systemd_service_active(self):
        calls = []

        def fake_run(argv, **kwargs):
            calls.append((argv, kwargs))
            return SimpleNamespace(returncode=fake_run.rc)

        for rc, expected in ((0, True), (3, False)):
            with self.subTest(rc=rc):
                fake_run.rc = rc
                with patch.object(ir.subprocess, 'run', fake_run):
                    self.assertEqual(is_systemd_service_active(), expected)
        self.assertEqual(calls[-1][0],
                         ['systemctl', '--user', 'is-active', '--quiet', 'jarvis.service'])
        self.assertEqual(calls[-1][1], {'capture_output': True, 'timeout': 3, 'check': False})
        # custom unit flows through; OSError -> False
        with patch.object(ir.subprocess, 'run', fake_run):
            is_systemd_service_active('jarvis-other.service')
        self.assertEqual(calls[-1][0][4], 'jarvis-other.service')

        def broken_run(argv, **kwargs):
            raise OSError('no systemd namespace')

        with patch.object(ir.subprocess, 'run', broken_run):
            self.assertFalse(is_systemd_service_active())

    def test_is_port_open_real_sockets(self):
        srv = socket.socket()
        srv.bind(('127.0.0.1', 0))
        srv.listen(1)
        port = srv.getsockname()[1]
        self.addCleanup(srv.close)
        self.assertTrue(is_port_open('127.0.0.1', port))
        srv.close()
        self.assertFalse(is_port_open('127.0.0.1', port))
        # unresolvable host must not raise
        self.assertFalse(is_port_open('nonexistent.invalid', 1, timeout=0.05))


class HealthAndProbe(unittest.TestCase):
    def test_wait_for_healthy_retry_shape(self):
        attempts = []
        sleeps = []

        def resp_200(req, timeout=None):
            attempts.append(req.full_url)
            return FakeResp(200, b'ok')

        clock = iter([10.0, 10.5])
        with patch.object(urllib.request, 'urlopen', resp_200), \
                patch.object(ir.time, 'sleep', lambda t: sleeps.append(t)), \
                patch.object(ir.time, 'monotonic', lambda: next(clock)):
            self.assertTrue(wait_for_healthy('127.0.0.1', 8123, timeout_s=99.0))
        self.assertEqual(attempts, ['http://127.0.0.1:8123/health'])   # first try wins
        self.assertEqual(sleeps, [])

        # non-200 retries until deadline; requests carry Host + 1.5 s timeout
        attempts.clear()
        sleeps.clear()
        seen = []

        def resp_503(req, timeout=None):
            seen.append((req.full_url, dict(req.header_items()), timeout))
            return FakeResp(503)

        # timeout_s=0.5: max(1.0, .5) -> 1.0s window; monotonic feeds deadline
        # first (100.0 -> deadline 101.0), then the while checks
        clock = iter([100.0, 100.5, 101.0])
        with patch.object(urllib.request, 'urlopen', resp_503), \
                patch.object(ir.time, 'sleep', lambda t: sleeps.append(t)), \
                patch.object(ir.time, 'monotonic', lambda: next(clock)):
            self.assertFalse(wait_for_healthy('127.0.0.1', 8123, timeout_s=0.5))
        self.assertEqual(len(seen), 1)
        self.assertEqual(seen[0][0], 'http://127.0.0.1:8123/health')
        self.assertEqual(seen[0][1]['Host'], '127.0.0.1:8123')
        self.assertEqual(seen[0][2], 1.5)
        self.assertEqual(sleeps, [0.35])

        # terminal connection errors loop just the same
        def always_raise(req, timeout=None):
            raise ConnectionError('refused')

        clock = iter([50.0, 50.1, 51.2, 60.0])
        with patch.object(urllib.request, 'urlopen', always_raise), \
                patch.object(ir.time, 'sleep', lambda t: sleeps.append(t)), \
                patch.object(ir.time, 'monotonic', lambda: next(clock)):
            self.assertFalse(wait_for_healthy('127.0.0.1', 8124, timeout_s=5.0))

    def test_probe_running_instance(self):
        seen = []

        def fake_urlopen(req, timeout=None):
            seen.append((req.full_url, dict(req.header_items())))
            return FakeResp(200, b'{"pid": 42, "stale": true}')

        with patch.object(urllib.request, 'urlopen', fake_urlopen):
            self.assertEqual(probe_running_instance('localhost', 9000),
                             {'pid': 42, 'stale': True})
        self.assertEqual(seen, [('http://localhost:9000/mission/instance',
                                 {'Host': 'localhost:9000'})])

        def json_list(req, timeout=None):
            return FakeResp(200, b'[1, 2]')

        with patch.object(urllib.request, 'urlopen', json_list):
            self.assertIsNone(probe_running_instance('localhost', 9000))

        def raise_404(req, timeout=None):
            raise urllib.error.HTTPError(req.full_url, 404, 'missing', {}, None)

        with patch.object(urllib.request, 'urlopen', raise_404):
            self.assertIsNone(probe_running_instance('localhost', 9000))


class BusyGate(unittest.TestCase):
    def test_three_busy_sources_and_swallowed_errors(self):
        def modules(bg=None, agents=(), waves=None, raising=False):
            def live_progress(agent_id):
                if raising:
                    raise RuntimeError('boom')
                return {'running': agent_id in agents}

            if bg is None:
                bg = False
            background_lane = SimpleNamespace(
                get_lane=lambda: SimpleNamespace(snapshot=lambda: {'running': bg}))
            agent_cli = SimpleNamespace(
                agent_ids=lambda: ['klorek', 'hermes'],
                live_progress=live_progress)
            agent_team = SimpleNamespace(
                active_waves=lambda: waves if waves is not None else [])
            return {'background_lane': background_lane, 'agent_cli': agent_cli,
                    'agent_team': agent_team}

        with patch.dict(sys.modules, modules(bg=True)):
            self.assertTrue(_any_agent_busy())
        with patch.dict(sys.modules, modules(agents={'hermes'})):
            self.assertTrue(_any_agent_busy())
        with patch.dict(sys.modules, modules(waves=[{'id': 'w1'}])):
            self.assertTrue(_any_agent_busy())
        with patch.dict(sys.modules, modules()):
            self.assertFalse(_any_agent_busy())
        # an exploding live_progress is swallowed per agent -> quiet lane
        with patch.dict(sys.modules, modules(raising=True)):
            self.assertFalse(_any_agent_busy())


class SelfReload(ReloadBase):
    def effects(self):
        return {'execv': None, 'kill': [], 'popen': [], 'sleep': []}

    def patches(self, effects, httpd=None):
        class Httpd:
            def __init__(self):
                self.calls = []

            def shutdown(self):
                self.calls.append('shutdown')

            def server_close(self):
                self.calls.append('close')

        httpd_obj = httpd if httpd is not None else Httpd()

        def fake_execv(path, argv):
            effects['execv'] = (path, argv)

        def fake_kill(pid, sig):
            effects['kill'].append((pid, sig))

        def fake_popen(argv, **kwargs):
            effects['popen'].append((argv, kwargs))
            return object()

        stack = [
            patch.object(ir.threading, 'Thread', FakeThread),
            patch.object(ir.os, 'execv', fake_execv),
            patch.object(ir.os, 'kill', fake_kill),
            patch.object(ir.subprocess, 'Popen', fake_popen),
            patch.object(ir.time, 'sleep', lambda t: effects['sleep'].append(t)),
        ]
        for p in stack:
            p.start()
            self.addCleanup(p.stop)
        return httpd_obj

    def test_execv_mode(self):
        FakeThread.captured.clear()
        effects = self.effects()
        httpd = self.patches(effects)
        with self.clean_env():
            result = trigger_self_reload(httpd, delay_s=0.7)
            self.assertEqual(result, {'ok': True, 'reloading': True,
                                      'pid': os.getpid(), 'mode': 'execv'})
            self.assertEqual(len(FakeThread.captured), 1)
            FakeThread.captured[0].target()      # worker inline
        self.assertEqual(effects['sleep'], [0.7])
        self.assertEqual(httpd.calls, ['shutdown', 'close'])
        self.assertEqual(effects['execv'][0], sys.executable)
        self.assertEqual(effects['execv'][1], [sys.executable, *sys.argv])
        self.assertEqual(effects['kill'], [])
        # the debounce guard: a second request while reloading is a no-op
        again = trigger_self_reload()
        self.assertEqual(again, {'ok': True, 'reloading': True,
                                 'already_scheduled': True})
        self.assertEqual(len(FakeThread.captured), 1)

    def test_systemd_mode_and_sigterm_fallbacks(self):
        FakeThread.captured.clear()
        effects = self.effects()
        httpd = self.patches(effects)        # execv/kill/popen fakes all onto `effects`
        with patch.dict(os.environ, {'INVOCATION_ID': 'inv-1'}):
            result = trigger_self_reload()      # no httpd under systemd
            self.assertEqual(result, {'ok': True, 'reloading': True,
                                      'pid': os.getpid(), 'mode': 'systemd'})
            self.assertEqual(httpd.calls, [])   # systemd path never touches httpd
            FakeThread.captured[0].target()
        self.assertEqual(effects['popen'][0][0],
                         ['systemctl', '--user', 'restart', 'jarvis.service'])
        self.assertEqual(effects['popen'][0][1]['start_new_session'], True)
        self.assertIsNone(effects['execv'])
        self.assertEqual(effects['kill'], [])

        # Popen failure falls back to SIGTERM for systemd to respawn us
        def broken_popen(argv, **kwargs):
            raise OSError('no such executable')

        FakeThread.captured.clear()
        ir._RELOADING = False
        with patch.object(ir.subprocess, 'Popen', broken_popen), \
                patch.dict(os.environ, {'INVOCATION_ID': 'inv-2'}):
            trigger_self_reload()
            FakeThread.captured[0].target()
        self.assertEqual(effects['kill'], [(os.getpid(), signal.SIGTERM)])

        # execv failure outside systemd ends the same way
        def broken_execv(path, argv):
            raise OSError('cannot exec')

        FakeThread.captured.clear()
        ir._RELOADING = False
        with patch.object(ir.os, 'execv', broken_execv), self.clean_env():
            trigger_self_reload()
            FakeThread.captured[0].target()
        self.assertEqual(effects['kill'],
                         [(os.getpid(), signal.SIGTERM)] * 2)


class ExternalReload(unittest.TestCase):
    def test_systemctl_path_and_post_fallback_flow(self):
        reqs = []
        sleeps = []
        systemctl = []

        def fake_run(argv, **kwargs):
            systemctl.append((argv, kwargs))
            return SimpleNamespace(returncode=0, stdout=b'', stderr=b'')

        def urlopen_fake(req, timeout=None):
            reqs.append((req, timeout))
            return FakeResp(200, b'{"ok": true}')

        with patch.object(ir, 'is_systemd_service_active', lambda u='x': True), \
                patch.object(ir.subprocess, 'run', fake_run), \
                patch.object(urllib.request, 'urlopen', urlopen_fake), \
                patch.object(ir.time, 'sleep', lambda t: sleeps.append(t)), \
                patch.object(ir.time, 'monotonic', lambda: 10.0):
            self.assertTrue(reload_external_instance('127.0.0.1', 8123))
        self.assertEqual(systemctl[-1][0],
                         ['systemctl', '--user', 'restart', 'jarvis.service'])
        self.assertEqual(systemctl[-1][1], {'capture_output': True, 'timeout': 10,
                                            'check': False})
        self.assertEqual([r.get_method() for r, _ in reqs], ['GET'])  # /health probe

        # standalone server: POST /mission/reload then /health
        reqs.clear()
        sleeps.clear()
        with patch.object(ir, 'is_systemd_service_active', lambda u='x': False), \
                patch.object(ir.subprocess, 'run', fake_run), \
                patch.object(urllib.request, 'urlopen', urlopen_fake), \
                patch.object(ir.time, 'sleep', lambda t: sleeps.append(t)), \
                patch.object(ir.time, 'monotonic', lambda: 10.0):
            self.assertTrue(reload_external_instance('127.0.0.1', 8123))
        post = [r for r, _ in reqs if r.get_method() == 'POST'][0]
        self.assertEqual(post.full_url, 'http://127.0.0.1:8123/mission/reload')
        self.assertEqual(post.data, b'{}')
        self.assertEqual(dict(post.header_items()),
                         {'Host': '127.0.0.1:8123', 'Origin': 'http://127.0.0.1:8123',
                          'Content-type': 'application/json', 'Content-length': '2'})
        self.assertEqual([r[1] for r in reqs], [3.0, 1.5])   # POST then health timeouts
        self.assertEqual(sleeps, [0.5])                      # settle before health check

    def test_health_failure_paths(self):
        # systemd restart succeeds but /health never turns green -> False
        def fake_run(argv, **kwargs):
            return SimpleNamespace(returncode=0, stdout=b'', stderr=b'')

        def dead_health(req, timeout=None):
            raise ConnectionError('nope')

        # clock feeds: systemd-wait deadline + checks, then the trailing 4s wait
        clock = iter([1.0, 2.0, 3.0, 99.0, 1.0, 2.0, 3.0, 99.0])
        with patch.object(ir, 'is_systemd_service_active', lambda u='x': True), \
                patch.object(ir.subprocess, 'run', fake_run), \
                patch.object(urllib.request, 'urlopen', dead_health), \
                patch.object(ir.time, 'sleep', lambda t: None), \
                patch.object(ir.time, 'monotonic', lambda: next(clock)):
            self.assertFalse(reload_external_instance('127.0.0.1', 8751))
        # POST endpoint missing entirely -> final health wait decides
        clock = iter([1.0, 2.0, 3.0, 99.0, 1.0, 2.0, 3.0, 99.0])
        with patch.object(ir, 'is_systemd_service_active', lambda u='x': False), \
                patch.object(ir.subprocess, 'run', fake_run), \
                patch.object(urllib.request, 'urlopen', dead_health), \
                patch.object(ir.time, 'sleep', lambda t: None), \
                patch.object(ir.time, 'monotonic', lambda: next(clock)):
            self.assertFalse(reload_external_instance('127.0.0.1', 8752))


class Conflict(ReloadBase):
    def run_conflict(self, state, force=False):
        out = io.StringIO()
        healths = []
        reloads = []
        probes = []

        def fake_health(host, port, timeout_s=None):
            healths.append(timeout_s)
            return state.get('healthy', True)

        def fake_reload(host, port):
            reloads.append((host, port))
            return state.get('reload', False)

        with patch.object(ir, 'is_port_open',
                          lambda h, p, timeout=0.8: state.get('open', True)), \
                patch.object(ir, 'probe_running_instance',
                             lambda h, p: probes.append(1) or state.get('info')), \
                patch.object(ir, 'reload_external_instance', fake_reload), \
                patch.object(ir, 'wait_for_healthy', fake_health), \
                patch.dict(os.environ, {'JARVIS_RELOAD_ON_CONFLICT':
                                        state.get('conflict', '1')}), \
                redirect_stdout(out):
            ok = handle_address_in_use('127.0.0.1', 8123, self.tmp, force_reload=force)
        return ok, out.getvalue(), healths, reloads, probes

    def test_closed_port_acts_on_nothing(self):
        ok, out, healths, reloads, probes = self.run_conflict({'open': False})
        self.assertFalse(ok)
        self.assertEqual((out, healths, reloads, probes), ('', [], [], []))

    def test_fresh_instance_attaches_without_reload(self):
        ok, out, healths, reloads, _ = self.run_conflict({'info': {'stale': False},
                                                          'healthy': True})
        self.assertTrue(ok)
        self.assertEqual(out, 'http://127.0.0.1:8123 (attached to running Jarvis '
                              'instance)\n')
        self.assertEqual(reloads, [])            # fresh -> no reload demanded
        self.assertEqual(healths, [5.0])         # attach probe window

    def test_stale_or_pre_instance_reloads_when_guard_permits(self):
        ok, out, _, reloads, _ = self.run_conflict({'info': {'stale': True},
                                                    'reload': True, 'healthy': False})
        self.assertTrue(ok)
        self.assertEqual(out, 'http://127.0.0.1:8123 (reloaded running Jarvis '
                              'instance)\n')
        self.assertEqual(reloads, [('127.0.0.1', 8123)])
        self.assertTrue(self.run_conflict({'info': None, 'reload': True})[0])
        self.assertTrue(self.run_conflict({'info': {'stale': False}, 'reload': True},
                                          force=True)[0])

    def test_guard_zero_reload_failure_and_total_failure(self):
        # JARVIS_RELOAD_ON_CONFLICT=0: never reload even a stale instance
        ok, out, _, reloads, _ = self.run_conflict({'info': {'stale': True},
                                                    'conflict': '0', 'reload': False})
        self.assertTrue(ok)
        self.assertEqual(reloads, [])
        self.assertIn('attached', out)
        # reload attempted but failing -> attach still possible
        ok, out, _, reloads, _ = self.run_conflict({'info': {'stale': True},
                                                    'reload': False, 'healthy': True})
        self.assertTrue(ok)
        self.assertEqual(reloads, [('127.0.0.1', 8123)])
        self.assertIn('attached', out)
        # nothing works at all
        ok, out, _, _, _ = self.run_conflict({'info': {'stale': True},
                                              'reload': False, 'healthy': False})
        self.assertFalse(ok)
        self.assertEqual(out, '')


class Watcher(ReloadBase):
    def run_watcher(self, events, stop_after, *, busy=lambda: False, mono=None, boot=500.0):
        """events: {n_th_sleep: mtime}; loop escapes via Sentinel after stop_after sleeps."""
        FakeThread.captured.clear()
        app = self.touching(self.tmp, 'app.py', 900.0)
        self.addCleanup(os.utime, app, (900.0, 900.0))
        sleeps = []
        reloads = []
        out = io.StringIO()
        clock = iter(mono or [10.0, 20.0, 30.0])

        def fake_sleep(seconds):
            sleeps.append(seconds)
            if len(sleeps) in events:
                mtime = events[len(sleeps)]
                os.utime(app, (mtime, mtime))
            if len(sleeps) > stop_after:
                raise Sentinel()

        with patch.dict(os.environ, {'JARVIS_AUTO_RELOAD': '1'}), \
                patch.object(ir.threading, 'Thread', FakeThread), \
                patch.object(ir, 'BOOT_TIME', boot), \
                patch.object(ir, 'trigger_self_reload',
                             lambda httpd=None, delay_s=0.25:
                                 reloads.append((httpd, delay_s))), \
                patch.object(ir, '_any_agent_busy', busy), \
                patch.object(ir.time, 'sleep', fake_sleep), \
                patch.object(ir.time, 'monotonic', lambda: next(clock)), \
                redirect_stdout(out):
            from instance_reload import start_auto_reload_watcher
            start_auto_reload_watcher('httpd-obj', self.tmp, poll_interval=4.0,
                                      debounce_s=2.5)
            escaped = False
            if FakeThread.captured:
                try:
                    FakeThread.captured[0].target()
                except Sentinel:
                    escaped = True
        return {'threads': FakeThread.captured, 'reloads': reloads,
                'sleeps': sleeps, 'escaped': escaped, 'out': out.getvalue()}

    def test_disabled_by_env_and_thread_shape(self):
        FakeThread.captured.clear()
        with patch.dict(os.environ, {'JARVIS_AUTO_RELOAD': '0'}), \
                patch.object(ir.threading, 'Thread', FakeThread):
            from instance_reload import start_auto_reload_watcher
            start_auto_reload_watcher('httpd', self.tmp)
        self.assertEqual(FakeThread.captured, [])      # off switch: no watcher at all

        result = self.run_watcher({}, 1)
        self.assertEqual(len(result['threads']), 1)
        self.assertEqual(result['threads'][0].name, 'jarvis-auto-reload-watcher')
        self.assertTrue(result['threads'][0].daemon)

    def test_quiet_tree_never_reloads(self):
        result = self.run_watcher({}, 2, boot=2000.0)   # baseline swallows the 900
        self.assertEqual(result['reloads'], [])
        self.assertTrue(result['escaped'])

    def test_settled_edit_triggers_with_delay_point2(self):
        result = self.run_watcher({1: 2000.0}, 3, mono=[10.0, 20.0, 30.0])
        self.assertEqual(result['reloads'], [('httpd-obj', 0.2)])
        self.assertEqual(result['out'], '[auto-reload] Wykryto zmiany w modułach Python '
                                        '— przeładowywanie instancji Jarvisa…\n')
        self.assertFalse(result['escaped'])             # loop returned after trigger

    def test_debounce_window_must_settle(self):
        result = self.run_watcher({1: 2000.0}, 4, mono=[10.0, 11.0, 11.5, 11.7])
        self.assertEqual(result['reloads'], [])
        self.assertEqual(result['out'], '')
        self.assertTrue(result['escaped'])

    def test_busy_agent_defers_once_then_reloads(self):
        busy_values = iter([True, False, False])
        result = self.run_watcher({1: 2000.0}, 4, busy=lambda: next(busy_values),
                                  mono=[10.0, 20.0, 30.0, 40.0])
        self.assertEqual(result['reloads'], [('httpd-obj', 0.2)])
        self.assertEqual(result['out'].count('praca agenta/zespołu'), 1)   # deferred once
        self.assertEqual(result['out'],
                          '[auto-reload] zmiany gotowe, ale trwa praca agenta/zespołu '
                          '— przeładuję po jej zakończeniu\n[auto-reload] Wykryto zmiany '
                          'w modułach Python — przeładowywanie instancji Jarvisa…\n')

    def test_continuously_changing_files_never_settle(self):
        result = self.run_watcher({1: 2000.0, 2: 2100.0, 3: 2200.0}, 5,
                                   mono=[10.0, 11.0, 12.0, 13.0, 14.0])
        self.assertEqual(result['reloads'], [])       # pending resets, window restarts
        self.assertEqual(result['out'], '')

    def test_edit_must_exceed_baseline_by_half_second(self):
        ok = self.run_watcher({1: 950.2}, 3, mono=[10.0, 20.0, 30.0], boot=949.7)
        self.assertEqual(ok['reloads'], [])
        self.assertTrue(ok['escaped'])
        hit = self.run_watcher({1: 950.4}, 3, mono=[10.0, 20.0, 30.0], boot=949.7)
        self.assertEqual(hit['reloads'], [('httpd-obj', 0.2)])


if __name__ == '__main__':
    unittest.main()
