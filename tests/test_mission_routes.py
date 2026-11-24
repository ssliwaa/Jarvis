"""mission_routes: Mission Control, live SSE and multi-agent team route contracts.

`mission_routes` is a pure dispatcher: every backend is imported inside the
route body, so tests intercept the imports through `patch.dict(sys.modules)`
fakes and pin only the HTTP side. Covered: the SSE cursor protocol (query
`after` beats the Last-Event-ID header even when blank or garbage, replay then
keepalive pings, broken-pipe disconnect swallowed), team chat/nudge/start
defaults, error envelopes, the `/mission/status` mega-aggregate with its exact
call args and slicing, safe-path gates and the big `/mission/action` matrix —
including `verify_backup` path confinement.

POST origin enforcement is NOT pinned here: `server.do_POST` calls
`validate_post_origin()` centrally before dispatching. Every stateful backend
(connectors vault, backups dir, databases) is faked — probing these routes
against real modules touches the live state vault, which the /mission/action
dispatcher does not sandbox itself.
"""
import io
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch
from urllib.parse import urlsplit

import mission_routes
from errors import AppError

SAFE_ROOT = Path('/tmp/jarvis-safe-root')


def fake_validator(raw):
    """Sentinel validator: SAFE_ROOT for anything benign, ValueError on 'bad'."""
    raw = str(raw)
    if 'bad' in raw.lower():
        raise ValueError('ścieżka poza obszarem roboczym')
    return SAFE_ROOT


def fake_code_index():
    return SimpleNamespace(
        validate_safe_project_dir=MagicMock(side_effect=fake_validator),
        search_context=MagicMock(return_value=[{'hit': 1}]),
        related_files=MagicMock(return_value={'related': ['a.py']}),
        cache_stats=MagicMock(return_value={'files': 4}),
    )


class BrokenPipeFile:
    def write(self, _data):
        raise BrokenPipeError('client gone')

    def flush(self):
        pass


class FakeHandler:
    """Everything mission_routes touches on the HTTP handler."""

    def __init__(self, path='/', body=None, headers=None, audio=b'AUDIO',
                 app_root=None, wfile=None):
        self.path = path
        self.body = {} if body is None else body
        self.headers = {} if headers is None else headers
        self.audio = audio
        self.origin_checks = 0
        self.json_sent = []
        self.resp = None
        self.hdrs = {}
        self.wfile = io.BytesIO() if wfile is None else wfile
        self.server = SimpleNamespace(
            app=None if app_root is None else SimpleNamespace(root=app_root))

    def validate_origin(self):
        self.origin_checks += 1

    def send_json(self, status, payload):
        self.json_sent.append((status, payload))

    def read_json_body(self):
        return self.body

    def read_audio_body(self):
        return self.audio

    def send_response(self, code):
        self.resp = code

    def send_header(self, key, value):
        self.hdrs[key] = value

    def end_headers(self):
        pass


def sse_bytes(event_id):
    return f'event: t\ndata: {event_id}\n\n'.encode()


def make_event(event_id):
    return {'id': event_id, 'topic': 't', 'payload': None}


class RouteTestCase(unittest.TestCase):
    def run_get(self, path, modules, **handler_kw):
        handler = FakeHandler(path=path, **handler_kw)
        with patch.dict(sys.modules, modules):
            handled = mission_routes.get_mission(handler, urlsplit(path))
        return handled, handler

    def run_post(self, path, body, modules, default_root=Path('/d'), **handler_kw):
        handler = FakeHandler(path=path, body=body, **handler_kw)
        with patch.dict(sys.modules, modules):
            handled = mission_routes.post_mission(handler, path.split('?')[0], default_root)
        return handled, handler

    def fire_action(self, body, fakes, default_root=Path('/d')):
        handled, handler = self.run_post('/mission/action', body, fakes, default_root)
        self.assertTrue(handled)
        return handler


class TestDispatch(RouteTestCase):
    def test_get_unknown_path_not_handled(self):
        handled, handler = self.run_get('/nowhere', {})
        self.assertFalse(handled)
        self.assertEqual(handler.origin_checks, 0)
        self.assertEqual(handler.json_sent, [])

    def test_post_unknown_path_not_handled(self):
        handled, handler = self.run_post('/nowhere', {'x': 1}, {})
        self.assertFalse(handled)
        self.assertEqual(handler.json_sent, [])


class TestSseStream(RouteTestCase):
    def _event_bus(self, recent_events, batches=None):
        recent = MagicMock(return_value=recent_events)
        wait = MagicMock(
            side_effect=list(batches) if batches is not None else None,
            return_value=[])
        return SimpleNamespace(recent=recent, wait_next=wait,
                               format_sse=MagicMock(
                                   side_effect=lambda ev: sse_bytes(ev['id'])),
                               latest_id=MagicMock(return_value=99))

    def test_once_stream_replays_and_stops(self):
        # once=1 -> headers + replay, NO wait_next polling loop.
        bus = self._event_bus([make_event(1), make_event(2)], batches=[[make_event(9)]])
        handled, handler = self.run_get('/mission/events?once=1', {'event_bus': bus})
        self.assertTrue(handled)
        self.assertEqual(handler.resp, 200)
        self.assertEqual(handler.hdrs['Content-Type'], 'text/event-stream; charset=utf-8')
        self.assertEqual(handler.hdrs['Cache-Control'], 'no-store')
        self.assertEqual(handler.hdrs['Connection'], 'close')
        self.assertEqual(handler.hdrs['X-Accel-Buffering'], 'no')
        out = handler.wfile.getvalue()
        self.assertTrue(out.startswith(b': connected\n\n'))
        self.assertIn(b'data: 1\n', out)
        self.assertIn(b'data: 2\n', out)
        self.assertNotIn(b'data: 9\n', out)
        bus.wait_next.assert_not_called()

    def test_live_stream_pings_and_cursor_advance(self):
        # Stream mode: replay batch first, then one wait batch, then pings.
        bus = self._event_bus([make_event(1), make_event(2)],
                              batches=[[make_event(5), make_event(6)]] + [[]] * 39)
        handled, handler = self.run_get('/mission/events', {'event_bus': bus})
        self.assertTrue(handled)
        self.assertEqual(handler.hdrs['Connection'], 'keep-alive')
        bus.recent.assert_called_once_with(after_id=0, limit=40)
        first_args = bus.wait_next.call_args_list[0].kwargs
        self.assertEqual(first_args, {'after_id': 2, 'timeout': 15.0})
        second_args = bus.wait_next.call_args_list[1].kwargs
        self.assertEqual(second_args, {'after_id': 6, 'timeout': 15.0})
        self.assertEqual(bus.wait_next.call_count, 40)
        out = handler.wfile.getvalue()
        self.assertIn(b'data: 1\n', out)
        self.assertIn(b'data: 5\n', out)
        self.assertIn(b'data: 6\n', out)
        self.assertEqual(out.count(b': ping\n\n'), 39)

    def test_cursor_precedence_matrix(self):
        # Query `after` wins over the Last-Event-ID header even when blank or
        # garbage; only a missing query key falls back to the header.
        cases = [
            ('/mission/events?after=abc', {'Last-Event-ID': '7'}, 0),
            ('/mission/events', {'Last-Event-ID': '7'}, 7),
            ('/mission/events?after=5', {'Last-Event-ID': '2'}, 5),
            ('/mission/events?after=', {'Last-Event-ID': '9'}, 0),
        ]
        for path, headers, expected in cases:
            with self.subTest(path=path):
                bus = self._event_bus([])
                self.run_get(path, {'event_bus': bus}, headers=headers)
                bus.recent.assert_called_once_with(after_id=expected, limit=40)

    def test_broken_pipe_swallowed(self):
        bus = self._event_bus([])
        handled, handler = self.run_get('/mission/events?once=1', {'event_bus': bus},
                                        wfile=BrokenPipeFile())
        self.assertTrue(handled)
        self.assertEqual(handler.origin_checks, 1)
        self.assertEqual(handler.json_sent, [])


class TestTeamGet(RouteTestCase):
    def _team(self):
        return SimpleNamespace(
            TeamError=type('TeamError', (Exception,), {}),
            list_projects=MagicMock(return_value=[{'id': 'p1'}]),
            project_status=MagicMock(return_value={'project': 'x', 'agents': []}),
            read_messages=MagicMock(return_value=[{'m': 1}]),
        )

    def test_team_list_and_project_status(self):
        team = self._team()
        handled, handler = self.run_get('/agents/team', {'agent_team': team})
        self.assertTrue(handled)
        self.assertEqual(handler.json_sent, [(200, {'ok': True, 'projects': [{'id': 'p1'}]})])
        team.list_projects.assert_called_once_with()

        team2 = self._team()
        handled, handler = self.run_get('/agents/team?project_id=abc',
                                        {'agent_team': team2})
        self.assertTrue(handled)
        team2.project_status.assert_called_once_with('abc')
        self.assertEqual(handler.json_sent,
                         [(200, {'ok': True, 'project': 'x', 'agents': []})])

    def test_team_messages_limit_values(self):
        for query, limit in (('', 50), ('?limit=', 50), ('?limit=7', 7)):
            team = self._team()
            with self.subTest(query=query):
                handled, handler = self.run_get('/agents/team/messages' + query,
                                                {'agent_team': team},
                                                body=None)
                self.assertTrue(handled)
                team.read_messages.assert_called_once_with('', limit=limit)
                self.assertEqual(handler.json_sent[0][0], 200)
                self.assertEqual(handler.json_sent[0][1]['messages'], [{'m': 1}])

    def test_team_messages_bad_limit_answers_team_error(self):
        team = self._team()
        handled, handler = self.run_get('/agents/team/messages?limit=zz', {'agent_team': team})
        self.assertTrue(handled)
        status, payload = handler.json_sent[0]
        self.assertEqual(status, 400)
        self.assertFalse(payload['ok'])
        self.assertEqual(payload['error']['code'], 'TEAM_ERROR')
        self.assertIn("int() with base 10", payload['error']['message'])


class TestAgentsGet(RouteTestCase):
    def test_router_watchdog_owner_questions(self):
        router = SimpleNamespace(router_summary=MagicMock(return_value={'agents': ['a']}))
        handled, handler = self.run_get('/agents/router', {'agent_router': router})
        self.assertTrue(handled)
        self.assertEqual(handler.json_sent, [(200, {'ok': True, 'agents': ['a']})])

        watchdog = SimpleNamespace(watchdog_status=MagicMock(
            return_value={'ok': True, 'state': 'idle'}))
        handled, handler = self.run_get('/agents/watchdog', {'health_watchdog': watchdog})
        self.assertTrue(handled)
        # Body is the module envelope passed through 1:1, no 'ok' merge.
        self.assertEqual(handler.json_sent, [(200, {'ok': True, 'state': 'idle'})])

        voice = SimpleNamespace(pending_owner_questions=MagicMock(
            return_value=[{'q': 1}]))
        handled, handler = self.run_get('/agents/owner-questions?project_id=pj',
                                        {'voice_bridge': voice})
        self.assertTrue(handled)
        voice.pending_owner_questions.assert_called_once_with('pj')
        self.assertEqual(handler.json_sent,
                         [(200, {'ok': True, 'questions': [{'q': 1}]})])

    def test_context_ok_and_forbidden_root(self):
        ci = fake_code_index()
        handled, handler = self.run_get('/agents/context?q=kod&root=proj',
                                        {'code_index': ci})
        self.assertTrue(handled)
        ci.search_context.assert_called_once_with('kod', root_dir=str(SAFE_ROOT))
        self.assertEqual(handler.json_sent,
                         [(200, {'ok': True, 'hits': [{'hit': 1}]})])

        ci2 = fake_code_index()
        with self.assertRaises(AppError) as ctx:
            self.run_get('/agents/context?root=/bad/path', {'code_index': ci2})
        self.assertEqual(ctx.exception.code, 'FORBIDDEN_PATH')
        self.assertEqual(ctx.exception.status, 400)
        ci2.search_context.assert_not_called()


class TestMissionGet(RouteTestCase):
    def test_graph_hops_envelope_and_bad_hops(self):
        kg = SimpleNamespace(graph_summary=MagicMock(return_value={'nodes': 2}),
                             detect_anomalies=MagicMock(return_value=[]),
                             query_subgraph=MagicMock(return_value={'edges': []}))
        handled, handler = self.run_get('/mission/graph?q=fly&hops=3', {'knowledge_graph': kg})
        self.assertTrue(handled)
        kg.query_subgraph.assert_called_once_with('fly', hops=3)
        self.assertEqual(handler.json_sent,
                         [(200, {'ok': True, 'summary': {'nodes': 2},
                                 'anomalies': [], 'subgraph': {'edges': []}})])

        kg2 = SimpleNamespace(graph_summary=MagicMock(return_value={}),
                              detect_anomalies=MagicMock(return_value=[]),
                              query_subgraph=MagicMock(return_value={}))
        with self.assertRaises(AppError) as ctx:
            self.run_get('/mission/graph?hops=zz', {'knowledge_graph': kg2})
        self.assertEqual(ctx.exception.code, 'INVALID_HOPS')
        self.assertEqual(ctx.exception.status, 400)
        kg2.query_subgraph.assert_not_called()

        kg3 = SimpleNamespace(graph_summary=MagicMock(return_value={}),
                              detect_anomalies=MagicMock(return_value=[]),
                              query_subgraph=MagicMock(return_value={}))
        handled, _ = self.run_get('/mission/graph', {'knowledge_graph': kg3})
        self.assertTrue(handled)
        kg3.query_subgraph.assert_called_once_with('', hops=2)

    def test_mission_passthroughs(self):
        autopilot = SimpleNamespace(list_runs=MagicMock(return_value=[{'id': 'r'}]))
        handled, handler = self.run_get('/mission/autopilot', {'autopilot_engine': autopilot})
        self.assertTrue(handled)
        autopilot.list_runs.assert_called_once_with(limit=12)
        self.assertEqual(handler.json_sent, [(200, {'ok': True, 'runs': [{'id': 'r'}]})])

        doctor = SimpleNamespace(run_diagnostics=MagicMock(
            return_value={'ok': True, 'checks': []}))
        handled, handler = self.run_get('/mission/doctor', {'system_doctor': doctor})
        self.assertTrue(handled)
        # The GET doctor is read-only: auto-heal must stay explicitly off.
        doctor.run_diagnostics.assert_called_once_with(auto_heal=False)
        self.assertEqual(handler.json_sent, [(200, {'ok': True, 'checks': []})])

        briefing = SimpleNamespace(generate_briefing=MagicMock(
            return_value={'ok': True, 'digest': 'x'}))
        handled, handler = self.run_get('/mission/briefing', {'morning_briefing': briefing})
        self.assertTrue(handled)
        self.assertEqual(handler.json_sent, [(200, {'ok': True, 'digest': 'x'})])

        connectors = SimpleNamespace(list_connectors=MagicMock(
            return_value={'ok': True, 'connectors': ['c']}))
        handled, handler = self.run_get('/mission/connectors',
                                         {'connectors_hub': connectors})
        self.assertTrue(handled)
        self.assertEqual(handler.json_sent,
                         [(200, {'ok': True, 'connectors': ['c']})])

    def test_instance_status_root_resolution(self):
        inst = SimpleNamespace(instance_status=MagicMock(return_value={'ok': True}))
        handled, handler = self.run_get('/mission/instance',
                                        {'instance_reload': inst},
                                        app_root='/the/app/root')
        self.assertTrue(handled)
        inst.instance_status.assert_called_once_with('/the/app/root')
        self.assertEqual(handler.json_sent, [(200, {'ok': True})])

        inst2 = SimpleNamespace(instance_status=MagicMock(return_value={'ok': True}))
        handled, _ = self.run_get('/mission/instance', {'instance_reload': inst2})
        self.assertTrue(handled)
        inst2.instance_status.assert_called_once_with(
            Path(mission_routes.__file__).resolve().parent)

    def test_status_aggregate_shape_and_calls(self):
        grid = MagicMock()
        grid.summary = MagicMock(return_value={'niches': 0})
        modules = {
            'event_bus': SimpleNamespace(latest_id=MagicMock(return_value=42)),
            'wayland_voice': SimpleNamespace(dnd_status=MagicMock(return_value={'dnd': False})),
            'hardware_guard': SimpleNamespace(snapshot=MagicMock(return_value={'cpu': 3})),
            'connectors_hub': SimpleNamespace(briefing_digest=MagicMock(return_value={'digest': 1})),
            'knowledge_graph': SimpleNamespace(graph_summary=MagicMock(return_value={'nodes': 2})),
            'autopilot_engine': SimpleNamespace(list_runs=MagicMock(return_value=[{'id': 'r'}])),
            'code_index': fake_code_index(),
            'semantic_cache': SimpleNamespace(cache_summary=MagicMock(return_value={'hits': 5})),
            'morning_briefing': SimpleNamespace(generate_briefing=MagicMock(
                return_value={'ok': True, 'digest': 'd'})),
            'episodic_memory': SimpleNamespace(memory_stats=MagicMock(return_value={'episodes': 1})),
            'agent_team': SimpleNamespace(list_projects=MagicMock(
                return_value=[{'pid': i} for i in range(8)])),
            'agent_router': SimpleNamespace(router_summary=MagicMock(return_value={'agents': ['x']})),
            'health_watchdog': SimpleNamespace(watchdog_status=MagicMock(return_value={'ok': True})),
            'voice_bridge': SimpleNamespace(pending_owner_questions=MagicMock(
                return_value=['q1', 'q2'])),
            'budget_guard': SimpleNamespace(status=MagicMock(return_value={'budget': 'ok'})),
            'night_shift': SimpleNamespace(latest_report=MagicMock(return_value={'report': None})),
            'evolve_engine': SimpleNamespace(MapElitesGrid=MagicMock(return_value=grid)),
            'workflow_miner': SimpleNamespace(
                mine_patterns=MagicMock(return_value=[{'id': i} for i in range(7)]),
                list_macros=MagicMock(return_value=[{'id': i} for i in range(11)])),
            'time_travel': SimpleNamespace(list_timepoints=MagicMock(return_value=[{'tp': 1}])),
            'state_backup': SimpleNamespace(list_backups=MagicMock(return_value=[{'b': 1}])),
        }
        handled, handler = self.run_get('/mission/status', modules)
        self.assertTrue(handled)
        self.assertEqual(handler.origin_checks, 1)
        status, payload = handler.json_sent[0]
        self.assertEqual(status, 200)
        self.assertEqual(payload, {
            'ok': True, 'sse_latest_id': 42, 'dnd': {'dnd': False},
            'hardware': {'cpu': 3}, 'connectors': {'digest': 1},
            'cortex': {'nodes': 2}, 'autopilot_runs': [{'id': 'r'}],
            'code_cache': {'files': 4}, 'semantic_cache': {'hits': 5},
            'briefing': {'ok': True, 'digest': 'd'}, 'episodic_memory': {'episodes': 1},
            'projects': [{'pid': i} for i in range(8)],
            'router': {'agents': ['x']}, 'watchdog': {'ok': True},
            'owner_questions': ['q1', 'q2'], 'budget': {'budget': 'ok'},
            'night_shift': {'report': None}, 'map_elites': {'niches': 0},
            'workflows': {'patterns': [{'id': i} for i in range(6)],
                          'macros': [{'id': i} for i in range(10)]},
            'timepoints': [{'tp': 1}], 'backups': [{'b': 1}],
        })
        modules['agent_team'].list_projects.assert_called_once_with(8)
        modules['autopilot_engine'].list_runs.assert_called_once_with(limit=5)
        modules['workflow_miner'].mine_patterns.assert_called_once_with()
        modules['workflow_miner'].list_macros.assert_called_once_with()
        modules['time_travel'].list_timepoints.assert_called_once_with(limit=10)
        modules['state_backup'].list_backups.assert_called_once_with(limit=8)
        modules['evolve_engine'].MapElitesGrid.assert_called_once_with()
        grid.summary.assert_called_once_with()


class TestPostTeam(RouteTestCase):
    def _team(self, error=None):
        wave = MagicMock(return_value={'ok': True, 'wave': True})
        new = MagicMock(return_value={'ok': True, 'new': True})
        chat = MagicMock(return_value={'id': 'm1', 'text': 'hello'})
        nudge = MagicMock(return_value={'ok': True, 'nudged': True})
        stop = MagicMock(return_value={'ok': True, 'stopped': True})
        if error is not None:
            for m in (wave, new, chat, nudge, stop):
                m.side_effect = error
        team = SimpleNamespace(TeamError=type('TeamError', (Exception,), {}),
                               AgentError=type('AgentError', (Exception,), {}),
                               start_parallel_wave=wave, start_team_project=new,
                               post_message=chat, nudge_agent=nudge,
                               stop_project=stop,
                               read_messages=MagicMock(return_value=[{'m': 1}]))
        cli = SimpleNamespace(AgentError=team.AgentError)
        return team, cli

    def _team_modules(self, team, cli, extra=None):
        modules = {'agent_team': team, 'agent_cli': cli}
        if extra:
            modules.update(extra)
        return modules

    def test_chat_defaults_and_message_priority(self):
        team, cli = self._team()
        body = {'project_id': 'p', 'message': 'hello', 'text': 'ignored'}
        handled, handler = self.run_post('/agents/team/chat', body,
                                         self._team_modules(team, cli))
        self.assertTrue(handled)
        team.post_message.assert_called_once_with(
            'p', sender='owner', text='hello', to='all', kind='chat')
        team.read_messages.assert_called_once_with('p', limit=30)
        self.assertEqual(handler.json_sent[0][0], 200)
        payload = handler.json_sent[0][1]
        self.assertEqual(payload['posted'], {'id': 'm1', 'text': 'hello'})
        self.assertEqual(payload['messages'], [{'m': 1}])

    def test_stop_passthrough(self):
        team, cli = self._team()
        handled, handler = self.run_post('/agents/team/stop', {'project_id': 'p'},
                                          self._team_modules(team, cli))
        self.assertTrue(handled)
        team.stop_project.assert_called_once_with('p')
        self.assertEqual(handler.json_sent,
                         [(200, {'ok': True, 'stopped': True})])

    def test_nudge_defaults_and_202(self):
        team, cli = self._team()
        body = {'project_id': 'p', 'agent': 'reviewer', 'message': 'go',
               'paths': 'not-a-list'}
        handled, handler = self.run_post('/agents/team/nudge', body,
                                          self._team_modules(team, cli))
        self.assertTrue(handled)
        status, payload = handler.json_sent[0]
        self.assertEqual(status, 202)
        team.nudge_agent.assert_called_once_with(
            'p', 'reviewer', 'go', role='collaborator', paths=None,
            approved=True, consent='local-ui')

        team2, cli2 = self._team()
        self.run_post('/agents/team/nudge',
                       {'project_id': 'p', 'agent': 'r', 'message': 'go',
                        'paths': ['a.py'], 'role': 'tester'},
                       self._team_modules(team2, cli2))
        team2.nudge_agent.assert_called_once_with(
            'p', 'r', 'go', role='tester', paths=['a.py'],
            approved=True, consent='local-ui')

    def test_start_wave_when_project_id_without_goal(self):
        team, cli = self._team()
        body = {'project_id': 'proj1', 'assignments': 'not-a-list',
                'review_agent': 'rev', 'goal': '   '}
        handled, handler = self.run_post('/agents/team/start', body,
                                          self._team_modules(team, cli))
        self.assertTrue(handled)
        self.assertEqual(handler.json_sent[0][0], 202)
        team.start_parallel_wave.assert_called_once_with(
            'proj1', assignments=None, review_agent='rev',
            approved=True, consent='local-ui')
        team.start_team_project.assert_not_called()
        # 'participants' is a new-project-only field.
        self.assertNotIn('participants',
                         team.start_parallel_wave.call_args.kwargs)

    def test_start_new_project_defaults(self):
        team, cli = self._team()
        body = {'goal': 'build it', 'max_rounds': '5', 'use_worktrees': False}
        handled, handler = self.run_post('/agents/team/start', body,
                                         self._team_modules(team, cli))
        self.assertTrue(handled)
        self.assertEqual(handler.json_sent[0][0], 202)
        kwargs = team.start_team_project.call_args.kwargs
        self.assertEqual(kwargs, {
            'goal': 'build it', 'participants': None, 'assignments': None,
            'title': '', 'project_id': '', 'review_agent': '',
            'architect_agent': '', 'plan_first': False, 'max_rounds': 5,
            'max_total_runs': 12, 'max_project_minutes': 30,
            'use_worktrees': False, 'seed_dir': '', 'approved': True,
            'consent': 'local-ui',
        })

    def test_start_seed_dir_gate(self):
        team, cli = self._team()
        ci = fake_code_index()
        self.run_post('/agents/team/start',
                      {'goal': 'g', 'seed_dir': 'ok-seed'},
                      self._team_modules(team, cli, {'code_index': ci}))
        self.assertEqual(team.start_team_project.call_args.kwargs['seed_dir'],
                         str(SAFE_ROOT))
        ci.validate_safe_project_dir.assert_called_once_with('ok-seed')

        team2, cli2 = self._team()
        with self.assertRaises(AppError) as ctx:
            self.run_post('/agents/team/start',
                          {'goal': 'g', 'seed_dir': '/bad/seed'},
                          self._team_modules(team2, cli2, {'code_index': ci}))
        self.assertEqual(ctx.exception.code, 'TEAM_ERROR')
        self.assertEqual(ctx.exception.status, 400)
        team2.start_team_project.assert_not_called()

    def test_team_error_agent_error_value_error_map_to_app_error(self):
        for error, label in (
                (type('TE', (Exception,), {})('team explosion'), 'TeamError'),
                (type('AE', (Exception,), {})('cli explosion'), 'AgentError'),
                (ValueError('bad value'), 'ValueError')):
            with self.subTest(label=label):
                team, cli = self._team()
                team.TeamError = type('TeamError', (Exception,), {})
                team.AgentError = type('AgentError', (Exception,), {})
                if label == 'AgentError':
                    error = team.AgentError('cli explosion')
                elif label == 'TeamError':
                    error = team.TeamError('team explosion')
                cli.AgentError = team.AgentError
                team.start_team_project.side_effect = error
                with self.assertRaises(AppError) as ctx:
                    self.run_post('/agents/team/start', {'goal': 'g'},
                                  self._team_modules(team, cli))
                self.assertEqual(ctx.exception.code, 'TEAM_ERROR')
                self.assertEqual(ctx.exception.status, 400)
                self.assertEqual(ctx.exception.message, str(error))


class TestOwnerReply(RouteTestCase):
    def _voice(self, error=None, result=None):
        return SimpleNamespace(
            transcribe_and_answer=MagicMock(side_effect=error,
                                            return_value=result or {'ok': True, 'answer': 'a'}),
            answer_owner_question=MagicMock(side_effect=error,
                                            return_value=result or {'answered': 'a'}),
        )

    def test_audio_reply_uses_query_ids_and_body(self):
        voice = self._voice()
        path = '/agents/owner-reply?req_id=r1&project_id=p1'
        handled, handler = self.run_post(
            path, {}, {'voice_bridge': voice},
            headers={'Content-Type': 'audio/ogg; codecs=opus'})
        self.assertTrue(handled)
        voice.transcribe_and_answer.assert_called_once_with(
            b'AUDIO', req_id='r1', project_id='p1')
        self.assertEqual(handler.json_sent, [(200, {'ok': True, 'answer': 'a'})])

    def test_audio_reply_failure_envelope(self):
        voice = self._voice(error=RuntimeError('ASR down'))
        path = '/agents/owner-reply?req_id=r1'
        with self.assertRaises(AppError) as ctx:
            self.run_post(path, {}, {'voice_bridge': voice},
                          headers={'Content-Type': 'audio/x'})
        self.assertEqual(ctx.exception.code, 'VOICE_REPLY_ERROR')
        self.assertEqual(ctx.exception.status, 400)
        self.assertIn('ASR down', ctx.exception.message)

    def test_json_reply_defaults_and_value_error(self):
        voice = self._voice()
        body = {'answer': '', 'message': 'ans', 'req_id': 'r', 'project_id': 'p'}
        handled, handler = self.run_post('/agents/owner-reply', body,
                                         {'voice_bridge': voice},
                                         headers={'Content-Type': 'application/json'})
        self.assertTrue(handled)
        voice.answer_owner_question.assert_called_once_with(
            'ans', req_id='r', project_id='p', source='web-ui')
        self.assertEqual(handler.json_sent,
                         [(200, {'ok': True, 'question': {'answered': 'a'}})])

        voice2 = self._voice(error=ValueError('unknown question'))
        with self.assertRaises(AppError) as ctx:
            self.run_post('/agents/owner-reply', {}, {'voice_bridge': voice2},
                          headers={'Content-Type': 'application/json'})
        self.assertEqual(ctx.exception.code, 'VOICE_REPLY_ERROR')
        self.assertEqual(ctx.exception.status, 400)
        self.assertIn('unknown question', ctx.exception.message)


class TestRollbackAndWatchdog(RouteTestCase):
    def test_rollback_target_fallback_and_error_envelope(self):
        review = SimpleNamespace(
            ReviewError=type('ReviewError', (Exception,), {}),
            rollback_last_checkpoint=MagicMock(return_value={'ok': True, 'restored': 3}))
        handled, handler = self.run_post(
            '/agents/rollback', {'target': '/target/x'},
            {'agent_review': review}, app_root='/app/root')
        self.assertTrue(handled)
        review.rollback_last_checkpoint.assert_called_once_with('/target/x', commit_hash='')
        self.assertEqual(handler.json_sent, [(200, {'ok': True, 'restored': 3})])

        review2 = SimpleNamespace(
            ReviewError=type('ReviewError', (Exception,), {}),
            rollback_last_checkpoint=MagicMock(return_value={}))
        handled, handler = self.run_post(
            '/agents/rollback', {'commit_hash': 'abc'},
            {'agent_review': review2}, app_root='/app/root')
        self.assertTrue(handled)
        # No target in body and no project_root in query -> app root string.
        review2.rollback_last_checkpoint.assert_called_once_with('/app/root', commit_hash='abc')

        review3 = SimpleNamespace(
            ReviewError=type('ReviewError', (Exception,), {}),
            rollback_last_checkpoint=None)
        review3.rollback_last_checkpoint = MagicMock(
            side_effect=review3.ReviewError('nope'))
        with self.assertRaises(AppError) as ctx:
            self.run_post('/agents/rollback', {}, {'agent_review': review3})
        self.assertEqual(ctx.exception.code, 'ROLLBACK_ERROR')
        self.assertEqual(ctx.exception.status, 400)

    def test_watchdog_scan_defaults_and_path_gate(self):
        watchdog = SimpleNamespace(scan_logs=MagicMock(return_value={'ok': True, 'spikes': []}))
        ci = fake_code_index()
        handled, handler = self.run_post(
            '/agents/watchdog/scan', {}, {'health_watchdog': watchdog, 'code_index': ci})
        self.assertTrue(handled)
        watchdog.scan_logs.assert_called_once_with(
            window_minutes=10, threshold=3, auto_repair=False, project_root=None)

        watchdog2 = SimpleNamespace(scan_logs=MagicMock(return_value={'ok': True}))
        ci2 = fake_code_index()
        self.run_post('/agents/watchdog/scan',
                      {'project_root': 'proj', 'window_minutes': '5',
                       'threshold': '9', 'auto_repair': 1},
                      {'health_watchdog': watchdog2, 'code_index': ci2})
        watchdog2.scan_logs.assert_called_once_with(
            window_minutes=5, threshold=9, auto_repair=True,
            project_root=str(SAFE_ROOT))

        ci3 = fake_code_index()
        with self.assertRaises(AppError) as ctx:
            self.run_post('/agents/watchdog/scan',
                          {'project_root': '/bad/x'},
                          {'health_watchdog': watchdog, 'code_index': ci3})
        self.assertEqual(ctx.exception.code, 'FORBIDDEN_PATH')
        self.assertEqual(ctx.exception.status, 400)


class TestMissionAction(RouteTestCase):
    def setUp(self):
        self.ci = fake_code_index()
        self.base = {'code_index': self.ci}

    def test_unknown_action_answers_mission_error(self):
        with self.assertRaises(AppError) as ctx:
            self.fire_action({'action': 'nope'}, self.base)
        self.assertEqual(ctx.exception.code, 'MISSION_ERROR')
        self.assertEqual(ctx.exception.status, 400)
        self.assertIn('Nieznana akcja Mission Control', ctx.exception.message)

    def test_backend_failure_answers_mission_error(self):
        doctor = SimpleNamespace(run_diagnostics=MagicMock(
            side_effect=RuntimeError('boom')))
        with self.assertRaises(AppError) as ctx:
            self.fire_action({'action': 'run_doctor'},
                             {**self.base, 'system_doctor': doctor})
        self.assertEqual(ctx.exception.code, 'MISSION_ERROR')
        self.assertEqual(ctx.exception.status, 400)
        self.assertIn('boom', ctx.exception.message)

    def test_forbidden_project_dir_maps_to_mission_error(self):
        qa = SimpleNamespace(audit_viewer=MagicMock(return_value={}))
        with self.assertRaises(AppError) as ctx:
            self.fire_action({'action': 'qa_audit', 'project_dir': '/bad/x'},
                             {**self.base, 'qa_gate': qa})
        # Inside /mission/action the generic Exception handler wins:
        # ValueError from the validator, not FORBIDDEN_PATH.
        self.assertEqual(ctx.exception.code, 'MISSION_ERROR')
        qa.audit_viewer.assert_not_called()

    def test_path_gated_ops_table(self):
        rows = [
            ({'action': 'qa_audit', 'project_dir': 'proj'}, ('qa_gate', 'audit_viewer'),
             (SAFE_ROOT,), {}),
            ({'action': 'security_scan', 'include_tests': True},
             ('security_scanner', 'scan_directory'), (SAFE_ROOT,), {'include_tests': True}),
            ({'action': 'run_doctor'}, ('system_doctor', 'run_diagnostics'),
             (), {'project_dir': SAFE_ROOT, 'auto_heal': True}),
            ({'action': 'plan_task', 'goal': 'g', 'max_files': '4'},
             ('task_planner', 'plan_goal'), ('g',), {'project_dir': SAFE_ROOT, 'max_files': 4}),
            ({'action': 'storage_report'}, ('storage_health', 'inspect_storage'),
             (), {'project_dir': SAFE_ROOT}),
            ({'action': 'prune_backups', 'keep_latest': '5'},
             ('storage_health', 'prune_mcp_backups'), (SAFE_ROOT,), {'keep_latest': 5}),
            ({'action': 'blast_radius'}, ('change_impact', 'analyze_blast_radius'),
             (SAFE_ROOT,), {'changed_files': None}),
            ({'action': 'sync_sri', 'fix': False}, ('change_impact', 'sync_viewer_sri'),
             (SAFE_ROOT,), {'fix': False}),
        ]
        mocks = {}
        fakes = dict(self.base)
        for _, (module, fn), *_ in rows:
            funcs = mocks.setdefault(module, {})
            if fn not in funcs:
                m = MagicMock(return_value={'ok': True, 'fn': fn})
                funcs[fn] = m
                if module in fakes:
                    setattr(fakes[module], fn, m)
                else:
                    fakes[module] = SimpleNamespace(**{fn: m})
        for body, (module, fn), args, kwargs in rows:
            with self.subTest(action=body['action']):
                handler = self.fire_action(body, fakes)
                self.assertEqual(handler.json_sent[0][0], 200)
                mocks[module][fn].assert_called_once_with(*args, **kwargs)
                self.assertEqual(handler.json_sent[0][1], {'ok': True, 'fn': fn})

    def test_graph_and_autopilot_actions(self):
        kg = SimpleNamespace(rebuild_code_graph=MagicMock(return_value={'ok': True, 'n': 1}),
                             query_subgraph=MagicMock(return_value={'nodes': []}),
                             upsert_triple=MagicMock(return_value={'ok': True}))
        ap = SimpleNamespace(run_autopilot=MagicMock(return_value={'ok': True, 'run': 1}))
        fakes = {**self.base, 'knowledge_graph': kg, 'autopilot_engine': ap}
        handler = self.fire_action({'action': 'build_graph', 'project_dir': 'p'}, fakes)
        kg.rebuild_code_graph.assert_called_once_with(SAFE_ROOT)
        self.assertEqual(handler.json_sent[0][1], {'ok': True, 'n': 1})

        self.fire_action({'action': 'graph_query', 'query': 'fly', 'hops': '3'}, fakes)
        kg.query_subgraph.assert_called_once_with('fly', hops=3)

        self.fire_action({'action': 'graph_remember', 'subject': 's', 'relation': 'r',
                          'object': 'o'}, fakes)
        kg.upsert_triple.assert_called_once_with(
            's', 'r', 'o', subj_kind='entity', obj_kind='entity')

        self.fire_action({'action': 'autopilot_run', 'goal': 'g'}, fakes)
        ap.run_autopilot.assert_called_once_with(
            'g', SAFE_ROOT, execute_team=False, rebuild_graph=True, force=False)

    def test_automation_actions(self):
        auto = SimpleNamespace(
            automation_status=MagicMock(return_value={'ok': True, 'jobs': []}),
            create_automation=MagicMock(return_value={'ok': True, 'id': 'j1'}),
            install_preset=MagicMock(return_value={'ok': True, 'preset': 'p'}),
            run_job_by_id=MagicMock(return_value={'ok': True, 'ran': True}))
        fakes = {**self.base, 'automation_engine': auto}
        self.fire_action({'action': 'automation_status'}, fakes)
        auto.automation_status.assert_called_once_with()

        self.fire_action({'action': 'automation_create', 'name': 'n', 'schedule': 'daily',
                          'action_params': 'not-a-dict'}, fakes)
        auto.create_automation.assert_called_once_with(
            'n', 'daily', action_type='briefing', action_params={}, deliver='local')

        self.fire_action({'action': 'automation_preset', 'preset_id': 'morning'}, fakes)
        auto.install_preset.assert_called_once_with('morning')

        self.fire_action({'action': 'automation_run_now', 'job_id': 'j1'}, fakes)
        auto.run_job_by_id.assert_called_once_with('j1', SAFE_ROOT)

    def test_connector_actions(self):
        hub = SimpleNamespace(
            configure_connector=MagicMock(return_value={'ok': True, 'id': 'x'}),
            remove_connector=MagicMock(return_value={'ok': True}),
            list_connectors=MagicMock(return_value={'ok': True, 'connectors': []}),
            set_toolset_enabled=MagicMock(return_value={'ok': True}),
            get_active_tool_schemas=MagicMock(return_value=['s1', 's2']),
            execute_connector_action=MagicMock(return_value={'ok': True, 'done': 1}))
        fakes = {**self.base, 'connectors_hub': hub}

        # provider-only body: provider doubles as the connector id.
        self.fire_action({'action': 'connector_configure', 'provider': 'gmail',
                          'settings': {'k': 'v'}}, fakes)
        hub.configure_connector.assert_called_once_with(
            'gmail', 'gmail', {'k': 'v'}, enabled=True)

        hub.configure_connector.reset_mock()
        self.fire_action({'action': 'connector_configure', 'connector_id': 'cid',
                          'provider': 'prov', 'enabled': False}, fakes)
        hub.configure_connector.assert_called_once_with('cid', 'prov', {}, enabled=False)

        handler = self.fire_action({'action': 'connector_remove',
                                    'connector_id': 'cid'}, fakes)
        hub.remove_connector.assert_called_once_with('cid')
        self.assertEqual(handler.json_sent[0][1], {'ok': True})

        self.fire_action({'action': 'connector_list'}, fakes)
        hub.list_connectors.assert_called_once_with()

        self.fire_action({'action': 'toolset_toggle', 'toolset': 'automation',
                          'enabled': False}, fakes)
        hub.set_toolset_enabled.assert_called_once_with('automation', False)

        handler = self.fire_action({'action': 'tool_schemas'}, fakes)
        self.assertEqual(handler.json_sent[0][1],
                         {'ok': True, 'count': 2, 'schemas': ['s1', 's2']})

        # No params dict -> the request body itself is passed through.
        handler = self.fire_action({'action': 'connector_exec',
                                    'connector_action': 'gmail_inbox',
                                    'mark': 'seen'}, fakes)
        hub.execute_connector_action.assert_called_once_with(
            'gmail_inbox', {'action': 'connector_exec',
                            'connector_action': 'gmail_inbox', 'mark': 'seen'})

    def test_memory_related_and_time_travel_actions(self):
        ep = SimpleNamespace(remember_episode=MagicMock(return_value={'id': 'e1'}),
                             recall_episodes=MagicMock(return_value=[{'id': 'e1'}]))
        tt = SimpleNamespace(record_timepoint=MagicMock(return_value={'tp': 1}),
                             fork_timepoint=MagicMock(return_value={'ok': True}))
        fakes = {**self.base, 'episodic_memory': ep, 'time_travel': tt}

        handler = self.fire_action({'action': 'remember_episode', 'title': 'dec'}, fakes)
        ep.remember_episode.assert_called_once_with(
            title='dec', summary='', kind='decision', tags='', project_id='')
        self.assertEqual(handler.json_sent[0][1], {'ok': True, 'episode': {'id': 'e1'}})

        handler = self.fire_action({'action': 'recall_episodes', 'limit': '3'}, fakes)
        ep.recall_episodes.assert_called_once_with(query='', limit=3, kind='')
        self.assertEqual(handler.json_sent[0][1],
                         {'ok': True, 'episodes': [{'id': 'e1'}]})

        handler = self.fire_action({'action': 'related_files', 'path': 'a.py'}, fakes)
        self.ci.related_files.assert_called_once_with('a.py', SAFE_ROOT)
        self.assertEqual(handler.json_sent[0][1],
                         {'ok': True, 'related': ['a.py']})

        self.fire_action({'action': 'record_timepoint', 'messages': 'nope'}, fakes)
        tt.record_timepoint.assert_called_once_with(
            session_id='default', turn_index=0, project_dir=SAFE_ROOT,
            messages=None, label='')

        self.fire_action({'action': 'fork_timepoint', 'timepoint_id': 'tp1',
                          'restore_files': True, 'title': 'T'}, fakes)
        tt.fork_timepoint.assert_called_once_with('tp1', restore_files=True, new_title='T')

    def test_workflow_git_and_night_shift_actions(self):
        wf = SimpleNamespace(compile_macro=MagicMock(return_value={'ok': True, 'macro': 'm'}),
                             record_event=MagicMock(return_value={'ev': 1}))
        gpb = SimpleNamespace(review_ref_in_sandbox=MagicMock(return_value={'ok': True}),
                              create_branch_from_outbox=MagicMock(return_value={'ok': True}))
        ns = SimpleNamespace(run_night_shift=MagicMock(return_value={'ok': True, 'did': 1}),
                             install_user_timer=MagicMock(return_value={'ok': True}))
        bc = SimpleNamespace(configure_limits=MagicMock(return_value={'ok': True}))
        fakes = {**self.base, 'workflow_miner': wf, 'git_pr_bridge': gpb,
                 'night_shift': ns, 'budget_guard': bc}

        handler = self.fire_action({'action': 'compile_macro', 'pattern_id': 'p1',
                                     'name': 'macro'}, fakes)
        wf.compile_macro.assert_called_once_with('p1', name='macro')
        self.assertEqual(handler.json_sent[0][1], {'ok': True, 'macro': 'm'})

        handler = self.fire_action({'action': 'record_workflow', 'kind': 'edit',
                                    'target': 'f.py', 'params': {'a': 1}}, fakes)
        wf.record_event.assert_called_once_with('edit', target='f.py', params={'a': 1})
        self.assertEqual(handler.json_sent[0][1]['event'], {'ev': 1})

        self.fire_action({'action': 'pr_review', 'ref': 'feature'}, fakes)
        gpb.review_ref_in_sandbox.assert_called_once_with(
            SAFE_ROOT, 'feature', remote='', test_target='')

        self.fire_action({'action': 'pr_branch', 'branch': 'b',
                          'outbox_source': 'ob', 'open_pr': True}, fakes)
        gpb.create_branch_from_outbox.assert_called_once_with(
            SAFE_ROOT, 'b', 'ob', commit_message='', open_pr=True)

        handler = self.fire_action({'action': 'night_shift',
                                     'modules': ['m'], 'auto_repair': True}, fakes)
        ns.run_night_shift.assert_called_once_with(
            modules=['m'], auto_repair=True, force=True)
        self.assertEqual(handler.json_sent[0][1], {'ok': True, 'did': 1})

        self.fire_action({'action': 'install_night_timer'}, fakes)
        ns.install_user_timer.assert_called_once_with(enable=False)

        self.fire_action({'action': 'budget_config', 'daily_limit_usd': '1.5'}, fakes)
        bc.configure_limits.assert_called_once_with(
            daily_limit_usd='1.5', monthly_limit_usd=None, soft_ratio=None)

    def test_cache_actions_compute_watermark(self):
        cache = SimpleNamespace(
            directory_watermark=MagicMock(return_value=1111.0),
            put=MagicMock(return_value={'ok': True, 'stored': True}),
            get=MagicMock(return_value={'hit': True, 'match_kind': 'semantic'}),
            clear=MagicMock(return_value={'ok': True, 'removed': 2}),
            cache_summary=MagicMock(return_value={'hits': 1}))
        fakes = {**self.base, 'semantic_cache': cache}

        handler = self.fire_action({'action': 'cache_store', 'prompt': 'p',
                                    'response_text': 'r'}, fakes)
        cache.directory_watermark.assert_called_once_with(SAFE_ROOT)
        cache.put.assert_called_once_with(
            'p', 'r', scope='default', watermark=1111.0, model='cloud', est_usd=0.002)
        self.assertEqual(handler.json_sent[0][1], {'ok': True, 'stored': True})

        handler = self.fire_action({'action': 'cache_lookup', 'prompt': 'p',
                                    'est_usd': 0.5, 'scope': 's1'}, fakes)
        cache.get.assert_called_once_with('p', scope='s1', watermark=1111.0)
        self.assertEqual(handler.json_sent[0][1],
                         {'ok': True, 'hit': True, 'entry': {'hit': True, 'match_kind': 'semantic'},
                          'summary': {'hits': 1}})

        handler = self.fire_action({'action': 'cache_clear', 'scope': 's1'}, fakes)
        cache.clear.assert_called_once_with('s1')
        self.assertEqual(handler.json_sent[0][1], {'ok': True, 'removed': 2})

    def test_compress_context_modes(self):
        comp = SimpleNamespace(
            skeletonize_python=MagicMock(return_value='PY-SKELETON'),
            compress_logs=MagicMock(return_value='LOG-COMPRESSED'),
            compression_stats=MagicMock(return_value={'ratio': 0.5}))
        fakes = {**self.base, 'context_compressor': comp}

        handler = self.fire_action({'action': 'compress_context', 'mode': 'python',
                                    'source': 'def f(): pass'}, fakes)
        comp.skeletonize_python.assert_called_once_with(
            'def f(): pass', keep_symbols=None, max_chars=3200)
        self.assertEqual(handler.json_sent[0][1],
                         {'ok': True, 'compressed': 'PY-SKELETON',
                          'stats': {'ratio': 0.5}})

        handler = self.fire_action({'action': 'compress_context', 'source': 'LOGS',
                                    'max_chars': '77', 'keep_symbols': ['f']}, fakes)
        comp.compress_logs.assert_called_once_with('LOGS', max_chars=77)
        self.assertEqual(handler.json_sent[0][1]['compressed'], 'LOG-COMPRESSED')

    def test_backup_actions_and_verify_confinement(self):
        with tempfile.TemporaryDirectory() as tmp:
            backups_dir = Path(tmp) / 'backups'
            backups_dir.mkdir()
            backup_fake = SimpleNamespace(
                _backups_dir=MagicMock(return_value=backups_dir),
                create_backup=MagicMock(return_value={'ok': True, 'file': 'x.jenc'}),
                verify_backup=MagicMock(return_value={'ok': True, 'verified': True}))
            fakes = {**self.base, 'state_backup': backup_fake}

            handler = self.fire_action({'action': 'create_backup',
                                        'passphrase': 'pw'}, fakes)
            backup_fake.create_backup.assert_called_once_with(
                passphrase='pw', age_recipient='')
            self.assertEqual(handler.json_sent[0][1], {'ok': True, 'file': 'x.jenc'})

            inside = backups_dir / 'x.jenc'
            handler = self.fire_action({'action': 'verify_backup',
                                        'path': str(inside),
                                        'passphrase': 'pw'}, fakes)
            backup_fake.verify_backup.assert_called_once_with(inside, passphrase='pw')
            self.assertEqual(handler.json_sent[0][1], {'ok': True, 'verified': True})

            with self.assertRaises(AppError) as ctx:
                self.fire_action({'action': 'verify_backup', 'path': '/etc/passwd'}, fakes)
            self.assertEqual(ctx.exception.code, 'MISSION_ERROR')
            self.assertIn('Weryfikacja dozwolona wyłącznie', ctx.exception.message)


if __name__ == '__main__':
    unittest.main()
