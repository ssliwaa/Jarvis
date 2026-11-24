"""Mission Control, Live SSE Stream, & Multi-Agent Team HTTP routes.

Follows the `studio_routes.py` pattern: each function returns `True` when it
handles the request and sends the HTTP response, keeping `server.py` lean while
preserving all `validate_origin()` and `validate_safe_project_dir()` security gates.
"""

from __future__ import annotations

from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from errors import AppError


def _serve_sse_stream(handler, parsed) -> None:
    """Stream Server-Sent Events (`text/event-stream`) from `event_bus`."""
    import event_bus
    query = parse_qs(parsed.query, keep_blank_values=True)
    header_last = handler.headers.get('Last-Event-ID') or ''
    raw_after = (query.get('after') or [header_last or '0'])[0]
    try:
        cursor = max(0, int(raw_after or 0))
    except ValueError:
        cursor = 0
    once = (query.get('once') or ['0'])[0] in ('1', 'true', 'yes')

    handler.send_response(200)
    handler.send_header('Content-Type', 'text/event-stream; charset=utf-8')
    handler.send_header('Cache-Control', 'no-store')
    handler.send_header('Connection', 'close' if once else 'keep-alive')
    handler.send_header('X-Accel-Buffering', 'no')
    handler.end_headers()

    try:
        handler.wfile.write(b': connected\n\n')
        for ev in event_bus.recent(after_id=cursor, limit=40):
            handler.wfile.write(event_bus.format_sse(ev))
            cursor = max(cursor, int(ev['id']))
        handler.wfile.flush()
        if once:
            return

        for _ in range(40):
            batch = event_bus.wait_next(after_id=cursor, timeout=15.0)
            if batch:
                for ev in batch:
                    handler.wfile.write(event_bus.format_sse(ev))
                    cursor = max(cursor, int(ev['id']))
            else:
                handler.wfile.write(b': ping\n\n')
            handler.wfile.flush()
    except (BrokenPipeError, ConnectionResetError, OSError):
        return


def get_mission(handler, parsed) -> bool:
    """Handle Mission Control, SSE, and Multi-Agent Team GET routes; returns True if handled."""
    if parsed.path == '/mission/events':
        handler.validate_origin()
        _serve_sse_stream(handler, parsed)
        return True

    if parsed.path in ('/agents/team', '/agents/team/messages'):
        handler.validate_origin()
        import agent_team
        query = parse_qs(parsed.query, keep_blank_values=True)
        project_id = (query.get('project_id') or query.get('id') or [''])[0].strip()
        try:
            if parsed.path == '/agents/team/messages':
                limit = int((query.get('limit') or ['50'])[0] or 50)
                body = {'ok': True, 'project_id': project_id,
                        'messages': agent_team.read_messages(project_id, limit=limit)}
            elif project_id:
                body = {'ok': True, **agent_team.project_status(project_id)}
            else:
                body = {'ok': True, 'projects': agent_team.list_projects()}
        except (agent_team.TeamError, ValueError) as error:
            handler.send_json(400, {'ok': False, 'error': {'code': 'TEAM_ERROR',
                                                           'message': str(error)}})
            return True
        handler.send_json(200, body)
        return True

    if parsed.path in ('/agents/router', '/agents/watchdog', '/agents/owner-questions', '/agents/context'):
        handler.validate_origin()
        query = parse_qs(parsed.query, keep_blank_values=True)
        if parsed.path == '/agents/router':
            import agent_router
            handler.send_json(200, {'ok': True, **agent_router.router_summary()})
            return True
        if parsed.path == '/agents/watchdog':
            import health_watchdog
            handler.send_json(200, health_watchdog.watchdog_status())
            return True
        if parsed.path == '/agents/owner-questions':
            import voice_bridge
            pid = (query.get('project_id') or [''])[0].strip()
            handler.send_json(200, {'ok': True, 'questions': voice_bridge.pending_owner_questions(pid)})
            return True
        import code_index
        q = (query.get('q') or [''])[0].strip()
        raw_root = (query.get('root') or [''])[0].strip()
        try:
            safe_root = str(code_index.validate_safe_project_dir(raw_root)) if raw_root else None
        except ValueError as error:
            raise AppError('FORBIDDEN_PATH', str(error), 400) from None
        handler.send_json(200, {'ok': True, 'hits': code_index.search_context(q, root_dir=safe_root)})
        return True

    if parsed.path == '/mission/instance':
        handler.validate_origin()
        import instance_reload
        app = getattr(getattr(handler, 'server', None), 'app', None)
        root_dir = getattr(app, 'root', None) or Path(__file__).resolve().parent
        handler.send_json(200, instance_reload.instance_status(root_dir))
        return True

    if parsed.path == '/mission/connectors':
        handler.validate_origin()
        import connectors_hub
        handler.send_json(200, connectors_hub.list_connectors())
        return True

    if parsed.path == '/mission/graph':
        handler.validate_origin()
        import knowledge_graph
        query = parse_qs(parsed.query, keep_blank_values=True)
        q = (query.get('q') or [''])[0].strip()
        try:
            hops = int((query.get('hops') or ['2'])[0] or 2)
        except ValueError:
            raise AppError('INVALID_HOPS', 'Liczba skoków grafu musi być liczbą całkowitą.', 400) from None
        handler.send_json(200, {
            'ok': True,
            'summary': knowledge_graph.graph_summary(),
            'anomalies': knowledge_graph.detect_anomalies(),
            'subgraph': knowledge_graph.query_subgraph(q, hops=hops),
        })
        return True

    if parsed.path == '/mission/autopilot':
        handler.validate_origin()
        import autopilot_engine
        handler.send_json(200, {'ok': True, 'runs': autopilot_engine.list_runs(limit=12)})
        return True

    if parsed.path == '/mission/doctor':
        handler.validate_origin()
        import system_doctor
        handler.send_json(200, system_doctor.run_diagnostics(auto_heal=False))
        return True

    if parsed.path == '/mission/briefing':
        handler.validate_origin()
        import morning_briefing
        handler.send_json(200, morning_briefing.generate_briefing())
        return True

    if parsed.path == '/mission/status':
        handler.validate_origin()
        import agent_router
        import agent_team
        import autopilot_engine
        import budget_guard
        import code_index
        import connectors_hub
        import episodic_memory
        import event_bus
        import evolve_engine
        import hardware_guard
        import health_watchdog
        import knowledge_graph
        import morning_briefing
        import night_shift
        import semantic_cache
        import state_backup
        import time_travel
        import voice_bridge
        import wayland_voice
        import workflow_miner
        handler.send_json(200, {
            'ok': True,
            'sse_latest_id': event_bus.latest_id(),
            'dnd': wayland_voice.dnd_status(),
            'hardware': hardware_guard.snapshot(),
            'connectors': connectors_hub.briefing_digest(),
            'cortex': knowledge_graph.graph_summary(),
            'autopilot_runs': autopilot_engine.list_runs(limit=5),
            'code_cache': code_index.cache_stats(),
            'semantic_cache': semantic_cache.cache_summary(),
            'briefing': morning_briefing.generate_briefing(),
            'episodic_memory': episodic_memory.memory_stats(),
            'projects': agent_team.list_projects(8),
            'router': agent_router.router_summary(),
            'watchdog': health_watchdog.watchdog_status(),
            'owner_questions': voice_bridge.pending_owner_questions(),
            'budget': budget_guard.status(),
            'night_shift': night_shift.latest_report(),
            'map_elites': evolve_engine.MapElitesGrid().summary(),
            'workflows': {
                'patterns': workflow_miner.mine_patterns()[:6],
                'macros': workflow_miner.list_macros()[:10],
            },
            'timepoints': time_travel.list_timepoints(limit=10),
            'backups': state_backup.list_backups(limit=8),
        })
        return True

    return False


def post_mission(handler, path: str, default_root: Path) -> bool:
    """Handle Mission Control and Multi-Agent Team POST routes; returns True if handled."""
    if path in ('/agents/team/start', '/agents/team/chat', '/agents/team/nudge', '/agents/team/stop'):
        import agent_cli
        import agent_team
        import code_index
        body = handler.read_json_body() or {}
        project_id = str(body.get('project_id') or body.get('id') or '').strip()
        try:
            if path == '/agents/team/chat':
                msg = agent_team.post_message(
                    project_id,
                    sender=str(body.get('sender') or 'owner'),
                    text=str(body.get('message') or body.get('text') or ''),
                    to=str(body.get('to') or 'all'),
                    kind=str(body.get('kind') or 'chat'),
                )
                handler.send_json(200, {'ok': True, 'posted': msg,
                                        'messages': agent_team.read_messages(project_id, limit=30)})
                return True
            if path == '/agents/team/stop':
                handler.send_json(200, agent_team.stop_project(project_id))
                return True
            if path == '/agents/team/nudge':
                res = agent_team.nudge_agent(
                    project_id,
                    str(body.get('agent') or ''),
                    str(body.get('message') or body.get('task') or ''),
                    role=str(body.get('role') or 'collaborator'),
                    paths=body.get('paths') if isinstance(body.get('paths'), list) else None,
                    approved=True,
                    consent='local-ui',
                )
                handler.send_json(202, res)
                return True
            goal = str(body.get('goal') or body.get('task') or '').strip()
            if project_id and not goal:
                res = agent_team.start_parallel_wave(
                    project_id,
                    assignments=body.get('assignments') if isinstance(body.get('assignments'), list) else None,
                    review_agent=str(body.get('review_agent') or ''),
                    approved=True,
                    consent='local-ui',
                )
            else:
                raw_seed = str(body.get('seed_dir') or '').strip()
                safe_seed = str(code_index.validate_safe_project_dir(raw_seed)) if raw_seed else ''
                res = agent_team.start_team_project(
                    goal=goal,
                    participants=body.get('participants') if isinstance(body.get('participants'), list) else None,
                    assignments=body.get('assignments') if isinstance(body.get('assignments'), list) else None,
                    title=str(body.get('title') or ''),
                    project_id=project_id,
                    review_agent=str(body.get('review_agent') or ''),
                    architect_agent=str(body.get('architect_agent') or ''),
                    plan_first=bool(body.get('plan_first')),
                    max_rounds=int(body.get('max_rounds') or 3),
                    max_total_runs=int(body.get('max_total_runs') or 12),
                    max_project_minutes=int(body.get('max_project_minutes') or 30),
                    use_worktrees=bool(body.get('use_worktrees', True)),
                    seed_dir=safe_seed,
                    approved=True,
                    consent='local-ui',
                )
            handler.send_json(202, res)
            return True
        except (agent_team.TeamError, agent_cli.AgentError, ValueError) as error:
            raise AppError('TEAM_ERROR', str(error), 400) from None

    if path in ('/agents/rollback', '/agents/watchdog/scan', '/agents/owner-reply'):
        if path == '/agents/owner-reply':
            import voice_bridge
            content_type = str(handler.headers.get('Content-Type') or '')
            query = parse_qs(urlsplit(handler.path).query, keep_blank_values=True)
            if content_type.startswith('audio/'):
                audio = handler.read_audio_body()
                req_id = (query.get('req_id') or [''])[0].strip()
                pid = (query.get('project_id') or [''])[0].strip()
                try:
                    res = voice_bridge.transcribe_and_answer(audio, req_id=req_id, project_id=pid)
                except Exception as error:
                    raise AppError('VOICE_REPLY_ERROR', str(error), 400) from None
                handler.send_json(200, res)
                return True
            body = handler.read_json_body() or {}
            try:
                answered = voice_bridge.answer_owner_question(
                    str(body.get('answer') or body.get('message') or ''),
                    req_id=str(body.get('req_id') or ''),
                    project_id=str(body.get('project_id') or ''),
                    source='web-ui',
                )
            except ValueError as error:
                raise AppError('VOICE_REPLY_ERROR', str(error), 400) from None
            handler.send_json(200, {'ok': True, 'question': answered})
            return True

        body = handler.read_json_body() or {}
        if path == '/agents/rollback':
            import agent_review
            fallback_root = str(getattr(getattr(handler.server, 'app', None), 'root', default_root))
            target = str(body.get('target') or '').strip() or fallback_root
            try:
                restored = agent_review.rollback_last_checkpoint(
                    target,
                    commit_hash=str(body.get('commit_hash') or ''),
                )
            except agent_review.ReviewError as error:
                raise AppError('ROLLBACK_ERROR', str(error), 400) from None
            handler.send_json(200, restored)
            return True

        import code_index
        import health_watchdog
        raw_proj = str(body.get('project_root') or '').strip()
        try:
            safe_proj = str(code_index.validate_safe_project_dir(raw_proj)) if raw_proj else None
        except ValueError as error:
            raise AppError('FORBIDDEN_PATH', str(error), 400) from None
        res = health_watchdog.scan_logs(
            window_minutes=int(body.get('window_minutes') or 10),
            threshold=int(body.get('threshold') or 3),
            auto_repair=bool(body.get('auto_repair')),
            project_root=safe_proj,
        )
        handler.send_json(200, res)
        return True

    if path == '/mission/action':
        import code_index
        body = handler.read_json_body() or {}
        act = str(body.get('action') or '').strip()
        try:
            if act == 'night_shift':
                import night_shift
                out = night_shift.run_night_shift(
                    modules=body.get('modules'),
                    auto_repair=bool(body.get('auto_repair')),
                    force=bool(body.get('force', True)),
                )
            elif act == 'install_night_timer':
                import night_shift
                out = night_shift.install_user_timer(enable=bool(body.get('enable', False)))
            elif act == 'qa_audit':
                import qa_gate
                safe_proj = code_index.validate_safe_project_dir(str(body.get('project_dir') or default_root))
                out = qa_gate.audit_viewer(safe_proj)
            elif act == 'security_scan':
                import security_scanner
                safe_proj = code_index.validate_safe_project_dir(str(body.get('project_dir') or default_root))
                out = security_scanner.scan_directory(safe_proj, include_tests=bool(body.get('include_tests')))
            elif act == 'run_doctor':
                import system_doctor
                safe_proj = code_index.validate_safe_project_dir(str(body.get('project_dir') or default_root))
                out = system_doctor.run_diagnostics(
                    project_dir=safe_proj,
                    auto_heal=bool(body.get('auto_heal', True)),
                )
            elif act == 'plan_task':
                import task_planner
                safe_proj = code_index.validate_safe_project_dir(str(body.get('project_dir') or default_root))
                out = task_planner.plan_goal(
                    str(body.get('goal') or ''),
                    project_dir=safe_proj,
                    max_files=int(body.get('max_files') or 10),
                )
            elif act == 'storage_report':
                import storage_health
                safe_proj = code_index.validate_safe_project_dir(str(body.get('project_dir') or default_root))
                out = storage_health.inspect_storage(project_dir=safe_proj)
            elif act == 'prune_backups':
                import storage_health
                safe_proj = code_index.validate_safe_project_dir(str(body.get('project_dir') or default_root))
                out = storage_health.prune_mcp_backups(
                    safe_proj,
                    keep_latest=int(body.get('keep_latest') or 30),
                )
            elif act == 'blast_radius':
                import change_impact
                safe_proj = code_index.validate_safe_project_dir(str(body.get('project_dir') or default_root))
                cfiles = body.get('changed_files') if isinstance(body.get('changed_files'), list) else None
                out = change_impact.analyze_blast_radius(safe_proj, changed_files=cfiles)
            elif act == 'sync_sri':
                import change_impact
                safe_proj = code_index.validate_safe_project_dir(str(body.get('project_dir') or default_root))
                out = change_impact.sync_viewer_sri(safe_proj, fix=bool(body.get('fix', True)))
            elif act == 'build_graph':
                import knowledge_graph
                safe_proj = code_index.validate_safe_project_dir(str(body.get('project_dir') or default_root))
                out = knowledge_graph.rebuild_code_graph(safe_proj)
            elif act == 'graph_query':
                import knowledge_graph
                out = knowledge_graph.query_subgraph(
                    str(body.get('query') or ''),
                    hops=int(body.get('hops') or 2),
                )
            elif act == 'graph_remember':
                import knowledge_graph
                out = knowledge_graph.upsert_triple(
                    str(body.get('subject') or ''),
                    str(body.get('relation') or ''),
                    str(body.get('object') or ''),
                    subj_kind=str(body.get('subj_kind') or 'entity'),
                    obj_kind=str(body.get('obj_kind') or 'entity'),
                )
            elif act == 'autopilot_run':
                import autopilot_engine
                safe_proj = code_index.validate_safe_project_dir(str(body.get('project_dir') or default_root))
                out = autopilot_engine.run_autopilot(
                    str(body.get('goal') or ''),
                    safe_proj,
                    execute_team=bool(body.get('execute_team', False)),
                    rebuild_graph=bool(body.get('rebuild_graph', True)),
                    force=bool(body.get('force', False)),
                )
            elif act == 'connector_configure':
                import connectors_hub
                out = connectors_hub.configure_connector(
                    str(body.get('connector_id') or body.get('provider') or ''),
                    str(body.get('provider') or ''),
                    body.get('settings') if isinstance(body.get('settings'), dict) else {},
                    enabled=bool(body.get('enabled', True)),
                )
            elif act == 'connector_remove':
                import connectors_hub
                out = connectors_hub.remove_connector(str(body.get('connector_id') or ''))
            elif act == 'connector_list':
                import connectors_hub
                out = connectors_hub.list_connectors()
            elif act == 'toolset_toggle':
                import connectors_hub
                out = connectors_hub.set_toolset_enabled(
                    str(body.get('toolset') or ''),
                    bool(body.get('enabled', True)),
                )
            elif act == 'tool_schemas':
                import connectors_hub
                schemas = connectors_hub.get_active_tool_schemas()
                out = {'ok': True, 'count': len(schemas), 'schemas': schemas}
            elif act == 'automation_status':
                import automation_engine
                out = automation_engine.automation_status()
            elif act == 'automation_create':
                import automation_engine
                out = automation_engine.create_automation(
                    str(body.get('name') or ''),
                    str(body.get('schedule') or ''),
                    action_type=str(body.get('action_type') or 'briefing'),
                    action_params=body.get('action_params') if isinstance(body.get('action_params'), dict) else {},
                    deliver=str(body.get('deliver') or 'local'),
                )
            elif act == 'automation_preset':
                import automation_engine
                out = automation_engine.install_preset(str(body.get('preset_id') or ''))
            elif act == 'automation_run_now':
                import automation_engine
                safe_proj = code_index.validate_safe_project_dir(str(body.get('project_dir') or default_root))
                out = automation_engine.run_job_by_id(str(body.get('job_id') or ''), safe_proj)
            elif act == 'connector_exec':
                import connectors_hub
                out = connectors_hub.execute_connector_action(
                    str(body.get('connector_action') or ''),
                    body.get('params') if isinstance(body.get('params'), dict) else body,
                )
            elif act == 'related_files':
                safe_proj = code_index.validate_safe_project_dir(str(body.get('project_dir') or default_root))
                out = {'ok': True, **code_index.related_files(str(body.get('path') or ''), safe_proj)}
            elif act == 'remember_episode':
                import episodic_memory
                ep = episodic_memory.remember_episode(
                    title=str(body.get('title') or ''),
                    summary=str(body.get('summary') or ''),
                    kind=str(body.get('kind') or 'decision'),
                    tags=body.get('tags') or '',
                    project_id=str(body.get('project_id') or ''),
                )
                out = {'ok': True, 'episode': ep}
            elif act == 'recall_episodes':
                import episodic_memory
                eps = episodic_memory.recall_episodes(
                    query=str(body.get('query') or ''),
                    limit=int(body.get('limit') or 6),
                    kind=str(body.get('kind') or ''),
                )
                out = {'ok': True, 'episodes': eps}
            elif act == 'cache_store':
                import semantic_cache
                safe_proj = code_index.validate_safe_project_dir(str(body.get('project_dir') or default_root))
                wm = semantic_cache.directory_watermark(safe_proj)
                out = semantic_cache.put(
                    str(body.get('prompt') or ''),
                    str(body.get('response_text') or ''),
                    scope=str(body.get('scope') or 'default'),
                    watermark=wm,
                    model=str(body.get('model') or 'cloud'),
                    est_usd=float(body.get('est_usd') or 0.002),
                )
            elif act == 'cache_lookup':
                import semantic_cache
                safe_proj = code_index.validate_safe_project_dir(str(body.get('project_dir') or default_root))
                wm = semantic_cache.directory_watermark(safe_proj)
                hit = semantic_cache.get(
                    str(body.get('prompt') or ''),
                    scope=str(body.get('scope') or 'default'),
                    watermark=wm,
                )
                out = {'ok': True, 'hit': bool(hit), 'entry': hit, 'summary': semantic_cache.cache_summary()}
            elif act == 'cache_clear':
                import semantic_cache
                out = semantic_cache.clear(str(body.get('scope') or ''))
            elif act == 'compress_context':
                import context_compressor
                mode = str(body.get('mode') or 'logs')
                raw_src = str(body.get('source') or '')
                if mode == 'python':
                    comp = context_compressor.skeletonize_python(
                        raw_src,
                        keep_symbols=body.get('keep_symbols') if isinstance(body.get('keep_symbols'), list) else None,
                        max_chars=int(body.get('max_chars') or 3200),
                    )
                else:
                    comp = context_compressor.compress_logs(raw_src, max_chars=int(body.get('max_chars') or 4000))
                out = {'ok': True, 'compressed': comp, 'stats': context_compressor.compression_stats(raw_src, comp)}
            elif act == 'budget_config':
                import budget_guard
                out = budget_guard.configure_limits(
                    daily_limit_usd=body.get('daily_limit_usd'),
                    monthly_limit_usd=body.get('monthly_limit_usd'),
                    soft_ratio=body.get('soft_ratio'),
                )
            elif act == 'create_backup':
                import state_backup
                out = state_backup.create_backup(
                    passphrase=str(body.get('passphrase') or ''),
                    age_recipient=str(body.get('age_recipient') or ''),
                )
            elif act == 'verify_backup':
                import state_backup
                raw_bkp = Path(str(body.get('path') or '')).expanduser().resolve()
                bkp_dir = state_backup._backups_dir().resolve()
                if bkp_dir not in raw_bkp.parents:
                    raise ValueError('Weryfikacja dozwolona wyłącznie dla archiwów w katalogu kopii Jarvisa.')
                out = state_backup.verify_backup(
                    raw_bkp,
                    passphrase=str(body.get('passphrase') or ''),
                )
            elif act == 'compile_macro':
                import workflow_miner
                out = workflow_miner.compile_macro(
                    str(body.get('pattern_id') or ''),
                    name=str(body.get('name') or ''),
                )
            elif act == 'record_workflow':
                import workflow_miner
                out = {'ok': True, 'event': workflow_miner.record_event(
                    str(body.get('kind') or ''),
                    target=str(body.get('target') or ''),
                    params=body.get('params') if isinstance(body.get('params'), dict) else None,
                )}
            elif act == 'record_timepoint':
                import time_travel
                safe_pdir = code_index.validate_safe_project_dir(str(body.get('project_dir') or default_root))
                out = {'ok': True, 'timepoint': time_travel.record_timepoint(
                    session_id=str(body.get('session_id') or 'default'),
                    turn_index=int(body.get('turn_index') or 0),
                    project_dir=safe_pdir,
                    messages=body.get('messages') if isinstance(body.get('messages'), list) else None,
                    label=str(body.get('label') or ''),
                )}
            elif act == 'fork_timepoint':
                import time_travel
                out = time_travel.fork_timepoint(
                    str(body.get('timepoint_id') or ''),
                    restore_files=bool(body.get('restore_files')),
                    new_title=str(body.get('title') or ''),
                )
            elif act == 'pr_review':
                import git_pr_bridge
                safe_repo = code_index.validate_safe_project_dir(str(body.get('repo_dir') or default_root))
                out = git_pr_bridge.review_ref_in_sandbox(
                    safe_repo,
                    str(body.get('ref') or ''),
                    remote=str(body.get('remote') or ''),
                    test_target=str(body.get('test_target') or ''),
                )
            elif act == 'pr_branch':
                import git_pr_bridge
                safe_repo = code_index.validate_safe_project_dir(str(body.get('repo_dir') or default_root))
                out = git_pr_bridge.create_branch_from_outbox(
                    safe_repo,
                    str(body.get('branch') or ''),
                    str(body.get('outbox_source') or ''),
                    commit_message=str(body.get('commit_message') or ''),
                    open_pr=bool(body.get('open_pr')),
                )
            else:
                raise ValueError(f'Nieznana akcja Mission Control: {act!r}')
        except Exception as error:
            raise AppError('MISSION_ERROR', str(error), 400) from None
        handler.send_json(200, out)
        return True

    return False
