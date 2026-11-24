"""Durable local reminders with conditional triggers, recurrence, and proactive briefings.

Importing this module starts no thread and sends no notification. A lifecycle
owner (such as ``operator_schedule.Scheduler``) calls ``run_due()`` or
``notify_job_finished()`` to evaluate triggers and announce results.
"""
from __future__ import annotations

import html
import json
import os
import re
import shutil
import sqlite3
import subprocess
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

MAX_REMINDERS = 500
MAX_TEXT = 500
DISPLAY_FORMAT = '%Y-%m-%d %H:%M'
VALID_TRIGGERS = ('time', 'on_active', 'after_job')


class ReminderError(Exception):
    """A reminder could not be stored or queried; nothing was changed."""


def _now():
    return datetime.now(timezone.utc)


def _quiet_hours(moment=None) -> bool:
    local = (moment or _now()).astimezone()
    return local.hour >= 22 or local.hour < 7


def _user_is_active(max_idle_seconds: int = 300) -> bool:
    """Detect whether the user is actively at the Linux session without intrusive probes.

    Checks ``loginctl`` IdleHint first, then ``xprintidle`` under X11. If neither
    probe is available on the host, defaults to True so an ``on_active`` reminder
    is never stuck forever on headless/Wayland setups.
    """
    if shutil.which('loginctl'):
        try:
            proc = subprocess.run(
                ['loginctl', 'show-user', str(os.getuid()), '-p', 'IdleHint'],
                capture_output=True, text=True, timeout=2, check=False,
            )
            if proc.returncode == 0 and proc.stdout:
                kv = dict(line.split('=', 1) for line in proc.stdout.splitlines() if '=' in line)
                hint = kv.get('IdleHint', '').strip().lower()
                if hint == 'no':
                    return True
                if hint == 'yes':
                    return False
        except (OSError, subprocess.SubprocessError):
            pass
    if shutil.which('xprintidle') and os.environ.get('DISPLAY'):
        try:
            proc = subprocess.run(
                ['xprintidle'], capture_output=True, text=True, timeout=2, check=False
            )
            if proc.returncode == 0 and proc.stdout.strip().isdigit():
                return (int(proc.stdout.strip()) / 1000.0) <= max_idle_seconds
        except (OSError, subprocess.SubprocessError, ValueError):
            pass
    return True


def _send_notification(title: str, body: str) -> bool:
    safe_body = html.escape(str(body or '')[:500])
    try:
        from operator_modules.desktop_notify import _send_os_notification
        return bool(_send_os_notification(title, safe_body))
    except Exception:
        pass
    if not shutil.which('notify-send'):
        return False
    try:
        proc = subprocess.run(
            ['notify-send', '-a', 'Jarvis', title, safe_body],
            timeout=5,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        return proc.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def _parse_due(value, *, allow_now: bool = False, clock=None):
    """Accept an ISO 8601 instant or relative shorthand (+15m, +2h, +1d)."""
    now_fn = clock or _now
    if allow_now and (value is None or str(value).strip() == '' or str(value).strip().lower() == 'now'):
        return now_fn().astimezone(timezone.utc)
    if not isinstance(value, str) or not value.strip():
        raise ReminderError('A due time is required.')
    raw = value.strip()
    rel = re.fullmatch(r'\+(\d+)\s*([smhdw])', raw, re.I)
    if rel:
        amount = int(rel.group(1))
        unit = rel.group(2).lower()
        factor = {'s': 1, 'm': 60, 'h': 3600, 'd': 86400, 'w': 604800}[unit]
        return (now_fn() + timedelta(seconds=amount * factor)).astimezone(timezone.utc)
    try:
        parsed = datetime.fromisoformat(raw.replace('Z', '+00:00'))
    except ValueError as error:
        raise ReminderError('The due time must be an ISO 8601 date/time or relative offset (+30m, +2h).') from error
    if parsed.tzinfo is None:
        parsed = parsed.astimezone()
    return parsed.astimezone(timezone.utc)


def _parse_every(every_seconds) -> int:
    if every_seconds is None or every_seconds == 0 or every_seconds == '':
        return 0
    if isinstance(every_seconds, bool):
        raise ReminderError('Recurrence interval must be an integer number of seconds.')
    try:
        val = int(every_seconds)
    except (TypeError, ValueError):
        raise ReminderError('Recurrence interval must be an integer number of seconds.') from None
    if val < 0:
        raise ReminderError('Recurrence interval cannot be negative.')
    if 0 < val < 300 or val > 365 * 86400:
        raise ReminderError('Recurring reminders must repeat between 300 seconds (5 min) and 365 days.')
    return val


class ReminderStore:
    def __init__(self, root=None, clock=None):
        self.root = Path(root or Path.home() / '.jarvis-tools' / 'reminders')
        self._clock = clock or _now

    @property
    def path(self):
        return self.root / 'reminders.sqlite3'

    def _prepare(self):
        try:
            self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
            info = self.root.lstat()
        except OSError as error:
            raise ReminderError(f'Could not prepare reminder folder: {type(error).__name__}.') from error
        if not self.root.is_dir() or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise ReminderError('The reminder folder must be private and owned by you.')
        try:
            fd = os.open(self.path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
            os.close(fd)
        except OSError as error:
            raise ReminderError(f'Could not open reminder database: {type(error).__name__}.') from error

    @staticmethod
    def _ensure_schema(db):
        db.execute(
            'CREATE TABLE IF NOT EXISTS reminders ('
            'id TEXT PRIMARY KEY, text TEXT NOT NULL, due_at TEXT NOT NULL, '
            'status TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL, '
            "trigger_kind TEXT NOT NULL DEFAULT 'time', "
            "trigger_target TEXT NOT NULL DEFAULT '', "
            'every_seconds INTEGER NOT NULL DEFAULT 0, '
            'with_briefing INTEGER NOT NULL DEFAULT 0)'
        )
        existing_cols = {row[1] for row in db.execute('PRAGMA table_info(reminders)').fetchall()}
        migrations = (
            ('trigger_kind', "TEXT NOT NULL DEFAULT 'time'"),
            ('trigger_target', "TEXT NOT NULL DEFAULT ''"),
            ('every_seconds', 'INTEGER NOT NULL DEFAULT 0'),
            ('with_briefing', 'INTEGER NOT NULL DEFAULT 0'),
        )
        for col_name, col_def in migrations:
            if col_name not in existing_cols:
                db.execute(f'ALTER TABLE reminders ADD COLUMN {col_name} {col_def}')
        db.execute('CREATE INDEX IF NOT EXISTS reminders_due ON reminders(status, due_at)')

    @contextmanager
    def _connect(self):
        self._prepare()
        db = None
        try:
            db = sqlite3.connect(self.path, timeout=10)
            with db:
                self._ensure_schema(db)
                yield db
        except sqlite3.Error as error:
            raise ReminderError(f'Reminder database error: {error}') from error
        finally:
            if db is not None:
                db.close()

    _SELECT_COLS = (
        'id, text, due_at, status, created_at, updated_at, '
        'trigger_kind, trigger_target, every_seconds, with_briefing'
    )

    @staticmethod
    def _row(row):
        return {
            'id': row[0],
            'text': row[1],
            'due_at': row[2],
            'status': row[3],
            'created_at': row[4],
            'updated_at': row[5],
            'trigger_kind': row[6] or 'time',
            'trigger_target': row[7] or '',
            'every_seconds': int(row[8] or 0),
            'with_briefing': bool(row[9]),
        }

    def _stamp(self):
        return self._clock().astimezone(timezone.utc).isoformat()

    def create(
        self,
        text,
        due_at=None,
        *,
        trigger_kind: str = 'time',
        trigger_target: str = '',
        every_seconds: int = 0,
        with_briefing: bool = False,
    ):
        if not isinstance(text, str) or not text.strip():
            raise ReminderError('A reminder needs a description.')
        text = text.strip()
        if len(text) > MAX_TEXT:
            raise ReminderError(f'A reminder may be at most {MAX_TEXT} characters.')
        kind = str(trigger_kind or 'time').strip().lower()
        if kind not in VALID_TRIGGERS:
            raise ReminderError(f"Unsupported trigger_kind; choose from {', '.join(VALID_TRIGGERS)}.")
        target_str = re.sub(r'\s+', ' ', str(trigger_target or '')).strip()[:120]
        due = _parse_due(due_at, allow_now=(kind in ('on_active', 'after_job')), clock=self._clock)
        every = _parse_every(every_seconds)
        stamp = self._stamp()
        item = {
            'id': uuid.uuid4().hex,
            'text': text,
            'due_at': due.isoformat(),
            'status': 'pending',
            'created_at': stamp,
            'updated_at': stamp,
            'trigger_kind': kind,
            'trigger_target': target_str,
            'every_seconds': every,
            'with_briefing': bool(with_briefing),
        }
        with self._connect() as db:
            count = db.execute("SELECT COUNT(*) FROM reminders WHERE status = 'pending'").fetchone()[0]
            if count >= MAX_REMINDERS:
                raise ReminderError('The pending reminder limit is reached.')
            db.execute(
                'INSERT INTO reminders (' + self._SELECT_COLS + ') VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                (
                    item['id'], item['text'], item['due_at'], item['status'],
                    item['created_at'], item['updated_at'], item['trigger_kind'],
                    item['trigger_target'], item['every_seconds'], int(item['with_briefing']),
                ),
            )
        return item

    def list(self, status=None):
        if status is not None and status not in ('pending', 'done', 'cancelled'):
            raise ReminderError('Invalid reminder status; choose pending, done or cancelled.')
        query = f'SELECT {self._SELECT_COLS} FROM reminders'
        params = ()
        if status is not None:
            query += ' WHERE status = ?'
            params = (status,)
        query += ' ORDER BY due_at, created_at'
        with self._connect() as db:
            return [self._row(row) for row in db.execute(query, params).fetchall()]

    def due(self, now=None, *, include_event_bound: bool = False):
        """Pending reminders whose earliest eligible time has arrived."""
        moment = (now or self._clock()).astimezone(timezone.utc).isoformat()
        with self._connect() as db:
            if include_event_bound:
                rows = db.execute(
                    f'SELECT {self._SELECT_COLS} FROM reminders '
                    'WHERE status = ? AND due_at <= ? ORDER BY due_at',
                    ('pending', moment),
                ).fetchall()
            else:
                rows = db.execute(
                    f'SELECT {self._SELECT_COLS} FROM reminders '
                    "WHERE status = ? AND due_at <= ? AND trigger_kind IN ('time', 'on_active') "
                    'ORDER BY due_at',
                    ('pending', moment),
                ).fetchall()
        return [self._row(row) for row in rows]

    def due_for_job(self, job_id: str = '', job_name: str = '', now=None):
        """Pending ``after_job`` reminders matching the finished job (or wildcard)."""
        moment = (now or self._clock()).astimezone(timezone.utc).isoformat()
        jid = str(job_id or '').strip().casefold()
        jname = str(job_name or '').strip().casefold()
        with self._connect() as db:
            rows = db.execute(
                f'SELECT {self._SELECT_COLS} FROM reminders '
                "WHERE status = ? AND trigger_kind = 'after_job' AND due_at <= ? ORDER BY due_at",
                ('pending', moment),
            ).fetchall()
        matched = []
        for raw in rows:
            item = self._row(raw)
            wanted = item['trigger_target'].casefold()
            if not wanted or wanted == '*' or wanted == jid or (jname and wanted in jname):
                matched.append(item)
        return matched

    def _update(self, reminder_id, **changes):
        if not isinstance(reminder_id, str) or not reminder_id:
            raise ReminderError('A reminder id is required.')
        fields = dict(changes)
        fields['updated_at'] = self._stamp()
        assignments = ', '.join(f'{name} = ?' for name in fields)
        with self._connect() as db:
            cursor = db.execute(
                f'UPDATE reminders SET {assignments} WHERE id = ? AND status = ?',
                (*fields.values(), reminder_id, 'pending'),
            )
            if cursor.rowcount != 1:
                raise ReminderError('No pending reminder with that id.')
        return self.get(reminder_id)

    def get(self, reminder_id):
        with self._connect() as db:
            row = db.execute(
                f'SELECT {self._SELECT_COLS} FROM reminders WHERE id = ?',
                (reminder_id,),
            ).fetchone()
        if row is None:
            raise ReminderError('No reminder with that id.')
        return self._row(row)

    def advance_or_complete(self, reminder_id, now=None):
        """Advance recurring reminders to their next future slot, or mark one-shot ones done."""
        item = self.get(reminder_id)
        every = int(item.get('every_seconds') or 0)
        if every <= 0:
            return self.complete(reminder_id)
        current_moment = (now or self._clock()).astimezone(timezone.utc)
        try:
            scheduled = datetime.fromisoformat(item['due_at']).astimezone(timezone.utc)
        except ValueError:
            scheduled = current_moment
        step = timedelta(seconds=every)
        next_due = scheduled + step
        while next_due <= current_moment:
            next_due += step
        return self._update(reminder_id, due_at=next_due.isoformat())

    def snooze(self, reminder_id, due_at):
        return self._update(reminder_id, due_at=_parse_due(due_at, clock=self._clock).isoformat())

    def complete(self, reminder_id):
        return self._update(reminder_id, status='done')

    def cancel(self, reminder_id):
        return self._update(reminder_id, status='cancelled')


def compose_briefing(root=None, include_mail: bool = False, clock=None) -> dict:
    """Synthesize a zero-LLM proactive local status briefing (reminders, watches, schedules, load)."""
    now_fn = clock or _now
    moment = now_fn()
    state_root = Path(root or Path.home() / '.jarvis-tools')
    store = ReminderStore(state_root / 'reminders', clock=now_fn)

    try:
        pending_all = store.list(status='pending')
    except ReminderError:
        pending_all = []
    horizon_iso = (moment + timedelta(hours=24)).astimezone(timezone.utc).isoformat()
    now_iso = moment.astimezone(timezone.utc).isoformat()
    overdue = [r for r in pending_all if r['due_at'] <= now_iso]
    upcoming_24h = [r for r in pending_all if now_iso < r['due_at'] <= horizon_iso]

    watch_count = 0
    watch_pending_events = 0
    watch_errors = 0
    watch_db = state_root / 'watch-pages' / 'watches.sqlite3'
    if watch_db.is_file():
        try:
            conn = sqlite3.connect(f'file:{watch_db}?mode=ro', uri=True, timeout=3)
            try:
                for (raw_json,) in conn.execute('SELECT data FROM watches').fetchall():
                    watch_count += 1
                    row = json.loads(raw_json)
                    watch_pending_events += len(row.get('pending') or [])
                    if row.get('last_error'):
                        watch_errors += 1
            finally:
                conn.close()
        except (sqlite3.Error, ValueError, OSError):
            pass

    sched_enabled = 0
    sched_failed = 0
    sched_path = state_root / 'schedules.json'
    if sched_path.is_file():
        try:
            sched_rows = json.loads(sched_path.read_text(encoding='utf-8'))
            if isinstance(sched_rows, list):
                for srow in sched_rows:
                    if isinstance(srow, dict) and srow.get('enabled', True):
                        sched_enabled += 1
                        if srow.get('last_status') in ('error', 'failed', 'timeout', 'timeout-running'):
                            sched_failed += 1
        except (OSError, ValueError):
            pass

    unseen_mail = None
    if include_mail:
        try:
            from operator_modules.email_agent import ACCOUNT_PATH, mailbox_status
            if ACCOUNT_PATH.is_file():
                mstat = mailbox_status()
                if mstat.get('ok'):
                    unseen_mail = int(mstat.get('unseen') or 0)
        except Exception:
            unseen_mail = None

    disk_free_gb = None
    load_1m = None
    try:
        load_1m = round(os.getloadavg()[0], 2)
    except (OSError, AttributeError):
        pass
    try:
        disk_free_gb = round(shutil.disk_usage(str(Path.home())).free / (1024 ** 3), 1)
    except OSError:
        pass

    parts = [f"Zaległe przypomnienia: {len(overdue)}, kolejne 24h: {len(upcoming_24h)}"]
    if watch_count:
        w_part = f"Obserwowane strony: {watch_count}"
        if watch_pending_events:
            w_part += f" ({watch_pending_events} oczekujących alertów)"
        if watch_errors:
            w_part += f" [{watch_errors} z błędem sieci]"
        parts.append(w_part)
    if sched_enabled:
        s_part = f"Harmonogramy: {sched_enabled} aktywnych"
        if sched_failed:
            s_part += f" ({sched_failed} wymaga uwagi)"
        parts.append(s_part)
    if unseen_mail is not None:
        parts.append(f"Nieprzeczytane maile: {unseen_mail}")
    sys_bits = []
    if load_1m is not None:
        sys_bits.append(f"load {load_1m}")
    if disk_free_gb is not None:
        sys_bits.append(f"wolne {disk_free_gb} GB")
    if sys_bits:
        parts.append("System: " + ", ".join(sys_bits))

    summary_text = " | ".join(parts)
    return {
        'ok': True,
        'generated_at': moment.astimezone().strftime(DISPLAY_FORMAT),
        'overdue_count': len(overdue),
        'upcoming_24h_count': len(upcoming_24h),
        'overdue': overdue[:5],
        'upcoming_24h': upcoming_24h[:5],
        'watches': {'total': watch_count, 'pending_alerts': watch_pending_events, 'errors': watch_errors},
        'schedules': {'enabled': sched_enabled, 'failed': sched_failed},
        'unseen_mail': unseen_mail,
        'system': {'load_1m': load_1m, 'disk_free_gb': disk_free_gb},
        'summary': summary_text,
    }


def _deliver_items(store: ReminderStore, items: list[dict], state_root: Path, moment, clock=None) -> int:
    delivered = 0
    briefing_cache = None
    for item in items:
        try:
            due_dt = datetime.fromisoformat(item['due_at']).astimezone()
            stamp = due_dt.strftime(DISPLAY_FORMAT)
        except ValueError:
            stamp = item['due_at']
        body = f"{item['text']} ({stamp})"
        if item.get('with_briefing'):
            if briefing_cache is None:
                briefing_cache = compose_briefing(state_root, include_mail=False, clock=clock)['summary']
            body = f"{body} — {briefing_cache}"
        if _send_notification('Jarvis — przypomnienie', body):
            try:
                store.advance_or_complete(item['id'], now=moment)
                delivered += 1
            except ReminderError:
                continue
    return delivered


def run_due(root=None, limit=10, respect_quiet_hours=True, clock=None, active_probe=None) -> int:
    """Deliver due ``time`` and ``on_active`` reminders without starting an AI job."""
    now_fn = clock or _now
    moment = now_fn()
    if respect_quiet_hours and _quiet_hours(moment):
        return 0
    state_root = Path(root or Path.home() / '.jarvis-tools')
    store = ReminderStore(state_root / 'reminders', clock=now_fn)
    candidates = store.due(now=moment, include_event_bound=False)[:max(1, int(limit or 10))]
    if not candidates:
        return 0
    is_active = None
    eligible = []
    for item in candidates:
        if item.get('trigger_kind') == 'on_active':
            if is_active is None:
                probe = active_probe or _user_is_active
                is_active = bool(probe())
            if not is_active:
                continue
        eligible.append(item)
    if not eligible:
        return 0
    return _deliver_items(store, eligible, state_root, moment, clock=now_fn)


def notify_job_finished(root=None, job_id: str = '', job_name: str = '', status: str = 'done',
                        respect_quiet_hours: bool = True, clock=None) -> int:
    """Evaluate and deliver ``after_job`` reminders when an Operator/scheduled job finishes."""
    if status in ('queued', 'running', 'awaiting_approval'):
        return 0
    now_fn = clock or _now
    moment = now_fn()
    if respect_quiet_hours and _quiet_hours(moment):
        return 0
    state_root = Path(root or Path.home() / '.jarvis-tools')
    store = ReminderStore(state_root / 'reminders', clock=now_fn)
    matched = store.due_for_job(job_id=job_id, job_name=job_name, now=moment)
    if not matched:
        return 0
    return _deliver_items(store, matched, state_root, moment, clock=now_fn)


def reminders(arguments, context=None):
    args = arguments if isinstance(arguments, dict) else {}
    action = args.get('action', 'list')
    root = (context or {}).get('state_root')
    state_root = Path(root) if root else (Path.home() / '.jarvis-tools')
    store = ReminderStore(state_root / 'reminders')
    try:
        if action == 'list':
            return {'ok': True, 'reminders': store.list(args.get('status'))}
        if action == 'due':
            return {'ok': True, 'due': store.due(include_event_bound=True)}
        if action == 'briefing':
            brief = compose_briefing(
                state_root, include_mail=bool(args.get('include_mail', False))
            )
            if args.get('notify') is True:
                brief['notified'] = _send_notification('Jarvis — Proaktywny Briefing', brief['summary'])
            return brief
        if action == 'create':
            item = store.create(
                args.get('text'),
                args.get('due_at'),
                trigger_kind=args.get('trigger_kind', 'time'),
                trigger_target=args.get('trigger_target', ''),
                every_seconds=args.get('every_seconds', 0),
                with_briefing=bool(args.get('with_briefing', False)),
            )
            return {'ok': True, 'reminder': item}
        if action == 'snooze':
            return {'ok': True, 'reminder': store.snooze(args.get('id'), args.get('due_at'))}
        if action == 'complete':
            return {'ok': True, 'reminder': store.complete(args.get('id'))}
        if action == 'cancel':
            return {'ok': True, 'reminder': store.cancel(args.get('id'))}
    except ReminderError as error:
        return {'ok': False, 'error': str(error)}
    return {'ok': False, 'error': 'Unsupported action.'}


TOOL = {
    'name': 'reminders',
    'description': (
        'Create and manage durable local reminders and proactive briefings: '
        'list, due, create, snooze, complete, cancel, briefing. '
        'Supports ISO 8601 or relative due_at (+30m, +2h), conditional triggers '
        "(trigger_kind='time'|'on_active'|'after_job'), recurring every_seconds, "
        'and optional with_briefing digest.'
    ),
    'input_schema': {
        'type': 'object',
        'properties': {
            'action': {
                'type': 'string',
                'enum': ['list', 'due', 'create', 'snooze', 'complete', 'cancel', 'briefing'],
            },
            'id': {'type': 'string'},
            'text': {'type': 'string'},
            'due_at': {
                'type': 'string',
                'description': "ISO 8601 date/time, relative offset ('+30m', '+2h'), or 'now' for event triggers.",
            },
            'status': {'type': 'string', 'enum': ['pending', 'done', 'cancelled']},
            'trigger_kind': {
                'type': 'string',
                'enum': ['time', 'on_active', 'after_job'],
                'description': "Fire at due_at ('time'), when user is active ('on_active'), or after a job ('after_job').",
            },
            'trigger_target': {
                'type': 'string',
                'description': "Optional job id or schedule name substring when trigger_kind='after_job'.",
            },
            'every_seconds': {
                'type': 'integer',
                'minimum': 0,
                'description': 'Optional recurrence interval in seconds (minimum 300 when non-zero).',
            },
            'with_briefing': {
                'type': 'boolean',
                'description': 'Attach a proactive status briefing when this reminder fires.',
            },
            'include_mail': {
                'type': 'boolean',
                'description': "Check unread IMAP count during action='briefing' when mail is configured.",
            },
            'notify': {
                'type': 'boolean',
                'description': "Send desktop notification immediately when action='briefing'.",
            },
        },
        'required': ['action'],
        'additionalProperties': False,
    },
    'handler': reminders,
    'approval': False,
}
