"""P2 studio routes: local office and system endpoints, split out of server.Handler.

Each function returns True when it wrote a response, so the caller keeps the
original route order while the server file no longer owns every branch.
"""
from __future__ import annotations

from pathlib import Path
from urllib.parse import parse_qs

from errors import AppError

try:
    import web_research
except Exception:
    web_research = None
try:
    import service_control
except Exception:
    service_control = None
try:
    import system_monitor
except Exception:
    system_monitor = None
try:
    import app_identity
except Exception:
    app_identity = None
try:
    import file_organizer
except Exception:
    file_organizer = None
try:
    import documents
except Exception:
    documents = None
try:
    import clipboard
except Exception:
    clipboard = None
try:
    import briefing
except Exception:
    briefing = None
try:
    import checkpoint_maintenance
    import checkpoint_manager
except Exception:
    checkpoint_manager = None
    checkpoint_maintenance = None


def get_p2(handler, parsed):
    """Handle the P2 GET routes; returns True when the response was sent."""
    if parsed.path == '/research':
        handler.validate_origin()
        if web_research is None:
            handler.send_json(503, {'ok': False, 'results': []})
            return True
        query = parse_qs(parsed.query).get('q', [''])[0].strip()
        if not query:
            handler.send_json(400, {'ok': False, 'error': {'code': 'INVALID_RESEARCH', 'message': 'A query is required.'}})
            return True
        try:
            results = web_research.search(query, 8)
        except web_research.ResearchError as error:
            handler.send_json(502, {'ok': False, 'error': {'code': 'RESEARCH_FAILED', 'message': str(error)[:300]}})
            return True
        handler.send_json(200, {'ok': True, 'query': query, 'results': results})
        return True
    if parsed.path == '/services':
        handler.validate_origin()
        if service_control is None:
            handler.send_json(503, {'ok': False, 'available': False,
                                    'error': {'code': 'SERVICES_UNAVAILABLE'}})
            return True
        handler.send_json(200, {'ok': True, **service_control.status()})
        return True
    if parsed.path == '/system':
        handler.validate_origin()
        if system_monitor is None:
            handler.send_json(503, {'ok': False, 'error': {'code': 'SYSTEM_UNAVAILABLE'}})
            return True
        handler.send_json(200, {'ok': True, **system_monitor.snapshot()})
        return True
    if parsed.path == '/apps':
        handler.validate_origin()
        if app_identity is None:
            handler.send_json(503, {'ok': False, 'apps': [], 'windows': []})
            return True
        query = parse_qs(parsed.query).get('q', [''])[0][:100]
        handler.send_json(200, {'ok': True, **app_identity.find(query)})
        return True
    if parsed.path == '/organizer':
        handler.validate_origin()
        if file_organizer is None:
            handler.send_json(503, {'ok': False, 'error': {'code': 'ORGANIZER_UNAVAILABLE'}})
            return True
        query = parse_qs(parsed.query)
        root = (query.get('root') or [str(Path.home() / 'Desktop')])[0]
        try:
            older = int((query.get('older_days') or ['365'])[0])
            handler.send_json(200, {'ok': True, **file_organizer.scan(root, max(1, min(older, 3650)))})
        except (file_organizer.OrganizerError, OSError, ValueError) as error:
            handler.send_json(400, {'ok': False, 'error': {'code': 'ORGANIZER_FAILED', 'message': str(error)[:300]}})
        return True
    if parsed.path == '/documents':
        handler.validate_origin()
        if documents is None:
            handler.send_json(503, {'ok': False, 'documents': []})
            return True
        handler.send_json(200, {'ok': True, 'documents': documents.list_documents(30),
                                'templates': documents.list_templates()})
        return True
    if parsed.path == '/clipboard':
        handler.validate_origin()
        if clipboard is None:
            handler.send_json(503, {'ok': False, 'error': {'code': 'CLIPBOARD_UNAVAILABLE'}})
            return True
        try:
            handler.send_json(200, clipboard.read())
        except clipboard.ClipboardError as error:
            handler.send_json(409, {'ok': False, 'error': {'code': 'CLIPBOARD_EMPTY', 'message': str(error)[:300]}})
        return True
    if parsed.path == '/briefing':
        handler.validate_origin()
        if briefing is None:
            handler.send_json(503, {'ok': False, 'error': {'code': 'BRIEFING_UNAVAILABLE'}})
            return True
        handler.send_json(200, {'ok': True, **briefing.build(
            handler.server.app, getattr(handler.server, 'scheduler', None), include_account=True)})
        return True
    if parsed.path == '/dashboard':
        handler.validate_origin()
        if briefing is None or system_monitor is None:
            handler.send_json(503, {'ok': False})
            return True
        handler.send_json(200, {'ok': True, 'briefing': briefing.build(
            handler.server.app, getattr(handler.server, 'scheduler', None), include_account=True),
            'system': system_monitor.snapshot()})
        return True
    if parsed.path == '/checkpoints':
        handler.validate_origin()
        manager = getattr(handler.server.app, 'checkpoints', None)
        if manager is None:
            handler.send_json(503, {'ok': False, 'checkpoints': [],
                                    'error': {'code': 'CHECKPOINTS_UNAVAILABLE',
                                              'message': 'The checkpoint store is not installed.'}})
            return True
        path = (parse_qs(parsed.query).get('path') or [''])[0].strip()
        try:
            checkpoints = manager.list_checkpoints(path) if path else manager.list_all_checkpoints()
            handler.send_json(200, {'ok': True, 'checkpoints': checkpoints,
                                    'path': path or None,
                                    'status': manager.status()})
        except Exception as error:
            handler.send_json(400, {'ok': False, 'checkpoints': [],
                                    'error': {'code': 'CHECKPOINT_FAILED',
                                              'message': f'{type(error).__name__}: {error}'[:300]}})
        return True
    if parsed.path == '/checkpoints/status':
        handler.validate_origin()
        manager = getattr(handler.server.app, 'checkpoints', None)
        if manager is None:
            handler.send_json(503, {'ok': False,
                                    'error': {'code': 'CHECKPOINTS_UNAVAILABLE'}})
            return True
        handler.send_json(200, manager.status())
        return True
    if parsed.path == '/reminders':
        handler.validate_origin()
        try:
            from operator_modules import reminders
            query = parse_qs(parsed.query)
            status_filter = (query.get('status') or [None])[0]
            ctx = {'state_root': getattr(handler.server.app, 'state_root', None)}
            result = reminders.reminders({'action': 'list', 'status': status_filter}, ctx)
            handler.send_json(200, result)
        except Exception as error:
            handler.send_json(500, {'ok': False, 'error': {'code': 'REMINDERS_FAILED', 'message': str(error)[:200]}})
        return True
    if parsed.path == '/watch':
        handler.validate_origin()
        try:
            from operator_modules import watch_pages
            ctx = {'state_root': getattr(handler.server.app, 'state_root', None)}
            result = watch_pages.watch_pages({'action': 'list'}, ctx)
            handler.send_json(200, result)
        except Exception as error:
            handler.send_json(500, {'ok': False, 'error': {'code': 'WATCH_FAILED', 'message': str(error)[:200]}})
        return True
    return False


def post_p2(handler, path):
    """Handle the P2 POST routes; returns True when the response was sent."""
    if path == '/apps':
        if app_identity is None:
            raise AppError('APP_IDENTITY_UNAVAILABLE', 'Desktop app identity is not installed.', 503)
        payload = handler.read_json_body()
        if not isinstance(payload, dict) or set(payload) - {'action', 'query', 'confirm'}:
            raise AppError('INVALID_APP', 'An app action is malformed.', 400)
        action = str(payload.get('action') or 'find')
        query = str(payload.get('query') or '')
        if action == 'focus':
            result = app_identity.focus(query)
        elif action == 'launch':
            result = app_identity.launch(query)
        elif action == 'close':
            result = app_identity.close(query, confirm=payload.get('confirm') is True)
        else:
            result = app_identity.find(query)
        handler.send_json(200, {'ok': bool(result.get('ok', True)), 'result': result})
        return True
    if path == '/organizer':
        if file_organizer is None:
            raise AppError('ORGANIZER_UNAVAILABLE', 'The file organizer is not installed.', 503)
        payload = handler.read_json_body()
        if not isinstance(payload, dict) or set(payload) - {'action', 'root', 'older_days', 'paths', 'batch', 'confirm'}:
            raise AppError('INVALID_ORGANIZER', 'An organizer request is malformed.', 400)
        action = str(payload.get('action') or 'scan')
        if 'root' in payload and not isinstance(payload.get('root'), str):
            raise AppError('INVALID_ORGANIZER', 'root must be a path string.', 400)
        if 'paths' in payload and (not isinstance(payload.get('paths'), list)
                                   or any(not isinstance(item, str) for item in payload['paths'])):
            raise AppError('INVALID_ORGANIZER', 'paths must be a list of strings.', 400)
        if 'batch' in payload and not isinstance(payload.get('batch'), str):
            raise AppError('INVALID_ORGANIZER', 'batch must be a string.', 400)
        try:
            older_days = int(payload.get('older_days') or 365)
        except (TypeError, ValueError):
            raise AppError('INVALID_ORGANIZER', 'older_days must be an integer.', 400) from None
        if older_days < 0:
            raise AppError('INVALID_ORGANIZER', 'older_days cannot be negative.', 400)
        try:
            if action == 'scan':
                result = file_organizer.scan(payload.get('root') or str(Path.home() / 'Desktop'), older_days)
            elif action == 'trash':
                result = file_organizer.trash(payload.get('paths') or [], confirm=payload.get('confirm') is True)
            elif action == 'preview':
                result = file_organizer.preview(payload.get('root') or str(Path.home() / 'Desktop'), older_days)
            elif action == 'archive':
                result = file_organizer.archive(payload.get('root') or str(Path.home() / 'Desktop'),
                                                older_days,
                                                confirm=payload.get('confirm') is True)
            elif action == 'restore_archive':
                result = file_organizer.restore_archive(str(payload.get('batch') or ''),
                                                        confirm=payload.get('confirm') is True)
            elif action == 'restore':
                result = file_organizer.restore(str(payload.get('batch') or ''), confirm=payload.get('confirm') is True)
            else:
                raise file_organizer.OrganizerError('Unknown organizer action.')
        except (file_organizer.OrganizerError, OSError, ValueError, TypeError) as error:
            raise AppError('ORGANIZER_FAILED', str(error)[:400], 400) from None
        handler.send_json(200, {'ok': True, 'result': result})
        return True
    if path == '/documents/open':
        if documents is None:
            raise AppError('DOCUMENTS_UNAVAILABLE', 'The document builder is not installed.', 503)
        payload = handler.read_json_body()
        if (not isinstance(payload, dict) or set(payload) != {'name', 'confirm'}
                or not isinstance(payload.get('name'), str) or not payload['name']):
            raise AppError('INVALID_DOCUMENT', 'Document open needs a name and confirm:true.', 400)
        try:
            result = documents.open_document(payload['name'], confirm=payload.get('confirm') is True)
        except documents.DocumentError as error:
            raise AppError('DOCUMENT_FAILED', str(error)[:400], 400) from None
        handler.send_json(200, {'ok': bool(result.get('ok')), 'result': result})
        return True
    if path == '/documents':
        if documents is None:
            raise AppError('DOCUMENTS_UNAVAILABLE', 'The document builder is not installed.', 503)
        payload = handler.read_json_body()
        if not isinstance(payload, dict) or set(payload) - {'kind', 'title', 'body', 'rows', 'template'}:
            raise AppError('INVALID_DOCUMENT', 'A document request is malformed.', 400)
        try:
            result = documents.generate(payload.get('kind', 'docx'), payload.get('title', 'Untitled'),
                                        payload.get('body', ''), payload.get('rows'), payload.get('template', 'plain'))
        except documents.DocumentError as error:
            raise AppError('DOCUMENT_FAILED', str(error)[:400], 400) from None
        handler.send_json(200, {'ok': True, 'document': result})
        return True
    if path == '/checkpoints/diff':
        manager = getattr(handler.server.app, 'checkpoints', None)
        if manager is None:
            raise AppError('CHECKPOINTS_UNAVAILABLE', 'The checkpoint store is not installed.', 503)
        payload = handler.read_json_body()
        if not isinstance(payload, dict) or set(payload) != {'path', 'hash'}:
            raise AppError('INVALID_CHECKPOINT', 'A checkpoint diff needs path and hash.', 400)
        if not isinstance(payload.get('path'), str) or not isinstance(payload.get('hash'), str):
            raise AppError('INVALID_CHECKPOINT', 'path and hash must be strings.', 400)
        result = manager.diff(payload['path'], payload['hash'])
        handler.send_json(200, {'ok': bool(result.get('success')), 'result': result})
        return True
    if path == '/checkpoints/restore':
        manager = getattr(handler.server.app, 'checkpoints', None)
        if manager is None:
            raise AppError('CHECKPOINTS_UNAVAILABLE', 'The checkpoint store is not installed.', 503)
        payload = handler.read_json_body()
        allowed = {'path', 'hash', 'file', 'safe', 'confirm'}
        if (not isinstance(payload, dict) or set(payload) - allowed
                or payload.get('confirm') is not True
                or not isinstance(payload.get('path'), str)
                or not isinstance(payload.get('hash'), str)
                or ('file' in payload and not isinstance(payload.get('file'), str))
                or ('safe' in payload and not isinstance(payload.get('safe'), bool))):
            raise AppError('CONFIRM_REQUIRED',
                           'Checkpoint restore needs path, hash, confirm:true and optional file/safe.',
                           400)
        result = manager.restore(payload['path'], payload['hash'],
                                 payload.get('file') or None,
                                 safe=payload.get('safe', True))
        handler.send_json(200, {'ok': bool(result.get('success')), 'result': result})
        return True
    if path == '/checkpoints/prune':
        manager = getattr(handler.server.app, 'checkpoints', None)
        if manager is None:
            raise AppError('CHECKPOINTS_UNAVAILABLE', 'The checkpoint store is not installed.', 503)
        payload = handler.read_json_body()
        allowed = {'retention_days', 'delete_orphans', 'confirm'}
        if (not isinstance(payload, dict) or set(payload) - allowed
                or payload.get('confirm') is not True
                or ('delete_orphans' in payload and not isinstance(payload.get('delete_orphans'), bool))):
            raise AppError('CONFIRM_REQUIRED',
                           'Checkpoint pruning needs confirm:true.', 400)
        try:
            retention = int(payload.get('retention_days') or 30)
        except (TypeError, ValueError):
            raise AppError('INVALID_CHECKPOINT', 'retention_days must be an integer.', 400) from None
        if retention < 0 or retention > 3650:
            raise AppError('INVALID_CHECKPOINT', 'retention_days is out of range.', 400)
        result = manager.prune(retention, payload.get('delete_orphans') is True)
        handler.send_json(200, {'ok': bool(result.get('errors', 0) == 0), 'result': result})
        return True
    if path == '/reminders':
        payload = handler.read_json_body()
        if not isinstance(payload, dict):
            raise AppError('INVALID_REMINDER', 'A reminder request must be an object.', 400)
        try:
            from operator_modules import reminders
            ctx = {'state_root': getattr(handler.server.app, 'state_root', None)}
            result = reminders.reminders(payload, ctx)
            handler.send_json(200, result)
        except Exception as error:
            raise AppError('REMINDER_FAILED', str(error)[:300], 400) from None
        return True
    if path == '/watch':
        payload = handler.read_json_body()
        if not isinstance(payload, dict):
            raise AppError('INVALID_WATCH', 'A watch request must be an object.', 400)
        try:
            from operator_modules import watch_pages
            ctx = {'state_root': getattr(handler.server.app, 'state_root', None)}
            result = watch_pages.watch_pages(payload, ctx)
            handler.send_json(200, result)
        except Exception as error:
            raise AppError('WATCH_FAILED', str(error)[:300], 400) from None
        return True
    return False
