"""Opt-in, local-only heartbeat for failed scheduled jobs.

No model calls or network requests. Background checks run via the existing
scheduler; a delivery is recorded only after the desktop notification succeeds.
"""
from __future__ import annotations

import fcntl
import html
import json
import os
import tempfile
import time
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path

from operator_modules.desktop_notify import _send_os_notification

DEFAULTS = {'enabled': False, 'quiet_start': 22, 'quiet_end': 7, 'daily_limit': 6}


@contextmanager
def _state(root):
    root = Path(root)
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    path = root / 'heartbeat.json'
    fd = os.open(root / 'heartbeat.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        try:
            with path.open(encoding='utf-8') as stream:
                data = json.load(stream)
            if not isinstance(data, dict) or not isinstance(data.get('config'), dict):
                raise ValueError('Invalid heartbeat state')
        except FileNotFoundError:
            data = {'config': dict(DEFAULTS), 'sent': []}
        if not isinstance(data.get('sent'), list):
            raise ValueError('Invalid heartbeat history')
        yield data, path
    finally:
        os.close(fd)


def _save(path, data):
    fd, tmp = tempfile.mkstemp(prefix='.heartbeat-', dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            json.dump(data, stream, ensure_ascii=False)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def _config(data):
    config = data['config']
    if (type(config.get('enabled')) is not bool
            or type(config.get('quiet_start')) is not int
            or type(config.get('quiet_end')) is not int
            or type(config.get('daily_limit')) is not int
            or not 0 <= config['quiet_start'] <= 23
            or not 0 <= config['quiet_end'] <= 24
            or not 1 <= config['daily_limit'] <= 30):
        raise ValueError('Invalid heartbeat configuration')
    return config


def configure(root, *, enabled, quiet_start=22, quiet_end=7, daily_limit=6):
    config = {'enabled': enabled, 'quiet_start': quiet_start,
              'quiet_end': quiet_end, 'daily_limit': daily_limit}
    _config({'config': config})
    with _state(root) as (data, path):
        data['config'] = config
        _save(path, data)
    return dict(config)


def status(root):
    with _state(root) as (data, _):
        return {'ok': True, 'config': dict(_config(data))}


def _quiet(hour, start, end):
    if start == end:
        return False
    return start <= hour < end if start < end else hour >= start or hour < end


def _notify(body):
    return _send_os_notification('Jarvis', html.escape(body[:400]))


def check(root, schedules, now=None):
    now = time.time() if now is None else now
    with _state(root) as (data, path):
        config = _config(data)
        if not config['enabled']:
            return {'ok': True, 'status': 'disabled', 'delivered': 0}
        hour = datetime.fromtimestamp(now).astimezone().hour
        if _quiet(hour, config['quiet_start'], config['quiet_end']):
            return {'ok': True, 'status': 'quiet', 'delivered': 0}
        sent = [entry for entry in data['sent'] if isinstance(entry, dict)
                and isinstance(entry.get('at'), (int, float))
                and now - 86400 <= entry['at'] <= now]
        if len(sent) >= config['daily_limit']:
            return {'ok': True, 'status': 'limit', 'delivered': 0}
        seen = {entry.get('key') for entry in sent}
        failures = []
        for row in schedules:
            if not isinstance(row, dict) or row.get('last_status') not in ('error', 'failed', 'timeout'):
                continue
            key = f"{row.get('id')}:{row.get('last_run')}"
            if row.get('id') and row.get('last_run') and key not in seen:
                failures.append((key, str(row.get('name') or 'Scheduled task')[:100]))
        if not failures:
            return {'ok': True, 'status': 'silent', 'delivered': 0}
        key, name = failures[0]
        if not _notify(f'Zaplanowane zadanie nie powiodło się: {name}'):
            return {'ok': False, 'status': 'delivery_failed', 'delivered': 0}
        sent.append({'key': key, 'at': now})
        data['sent'] = sent[-30:]
        _save(path, data)
        return {'ok': True, 'status': 'sent', 'delivered': 1}


def heartbeat(arguments, context=None):
    args = arguments or {}
    context = context or {}
    job = context.get('job')
    service = getattr(job, 'service', None)
    root = Path(context.get('state_root') or getattr(service, 'state_root', None)
                or Path.home() / '.jarvis-tools')
    action = args.get('action', 'status')
    try:
        if action == 'status':
            return status(root)
        if action == 'configure':
            return {'ok': True, 'config': configure(
                root, enabled=args.get('enabled'), quiet_start=args.get('quiet_start', 22),
                quiet_end=args.get('quiet_end', 7), daily_limit=args.get('daily_limit', 6))}
        return {'ok': False, 'error': 'Unsupported action'}
    except (OSError, ValueError, TypeError):
        return {'ok': False, 'error': 'Heartbeat state or configuration unavailable'}


TOOL = {
    'name': 'heartbeat',
    'description': 'Configure the opt-in local heartbeat for failed scheduled jobs; quiet hours and a daily notification limit apply. It never calls a model.',
    'input_schema': {'type': 'object', 'properties': {
        'action': {'type': 'string', 'enum': ['status', 'configure']},
        'enabled': {'type': 'boolean'},
        'quiet_start': {'type': 'integer', 'minimum': 0, 'maximum': 23},
        'quiet_end': {'type': 'integer', 'minimum': 0, 'maximum': 24},
        'daily_limit': {'type': 'integer', 'minimum': 1, 'maximum': 30},
    }, 'required': ['action'], 'additionalProperties': False},
    'handler': heartbeat, 'approval': True,
}
