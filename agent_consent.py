"""One-time consent for starting an external agent, including spoken consent.

Starting an agent spends the owner's money and runs code, so it is never
implicit: a run needs a grant that is bound to one agent and one task, expires
quickly and can be used once. A grant is issued either by an explicit click
(``grant``) or by an affirmative phrase the server itself heard through the
microphone (``grant_spoken``) — the client cannot vouch for its own audio.
"""
from __future__ import annotations

import hashlib
import json
import re
import threading
import time
import uuid
from pathlib import Path

ROOT = Path.home() / '.jarvis-tools' / 'agents'
STORE = ROOT / 'consent.json'
TTL_SECONDS = 180
MAX_ENTRIES = 32

# grant() and consume() each do a read-modify-write cycle over STORE.
# Serialize them so parallel calls cannot lose each other's updates.
STORE_LOCK = threading.Lock()

# An affirmative must be a whole short answer, not a sentence that merely contains
# "tak": "tak, ale najpierw sprawdź X" is not consent for the run in hand.
_AFFIRMATIVE = re.compile(
    r"^\s*(?:tak|yes|ok|okej|okay|zgoda|zgadzam\s+się|zgadzam\s+sie|potwierdzam|"
    r"zatwierdzam|approve|approved|confirm|confirmed|i\s+agree|go\s+ahead|"
    r"uruchom(?:\s+agenta)?|run\s+it|do\s+it)\s*[.!]*\s*$", re.I)


class ConsentError(Exception):
    """No valid consent for this run; nothing was started."""


def digest(agent_id, task):
    """Bind a grant to the exact agent and task text."""
    payload = f'{agent_id}\x00{" ".join(str(task or "").split())}'.encode('utf-8')
    return hashlib.sha256(payload).hexdigest()[:32]


def is_affirmative(text):
    return bool(_AFFIRMATIVE.match(str(text or '').strip()))


def _load():
    try:
        rows = json.loads(STORE.read_text(encoding='utf-8'))
    except (OSError, ValueError):
        return []
    return rows if isinstance(rows, list) else []


def _save(rows):
    STORE.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    now = time.time()
    rows = [row for row in rows if isinstance(row, dict)
            and isinstance(row.get('expires_at'), (int, float)) and row['expires_at'] > now]
    rows = rows[-MAX_ENTRIES:]
    # The static '.tmp' suffix raced between the grant and consume threads
    # (ThreadingHTTPServer serves /agents/consent and /agents/run in
    # parallel); atomic_io's mkstemp gives every save its own temp file,
    # cleans up on failure and refuses symlinked targets.
    from atomic_io import atomic_write_text
    atomic_write_text(STORE, json.dumps(rows, indent=2), dir_mode=None)


def grant(agent_id, task, spoken=False):
    """Issue one grant for this agent+task pair."""
    token = uuid.uuid4().hex
    # One store guard: grant and consume are read-modify-write cycles served
    # by parallel threads (ThreadingHTTPServer); without the lock the second
    # writer's _save clobbers the first's row (a lost grant or a token that
    # resets to unused).
    with STORE_LOCK:
        rows = _load()
        rows.append({'token': token, 'agent': agent_id, 'digest': digest(agent_id, task),
                     'spoken': bool(spoken), 'created_at': time.time(),
                     'expires_at': time.time() + TTL_SECONDS, 'used': False})
        _save(rows)
    return {'token': token, 'expires_in': TTL_SECONDS, 'spoken': bool(spoken),
            'agent': agent_id}


def grant_spoken(agent_id, task, transcript):
    """Spoken consent: the phrase must be an affirmative on its own."""
    if not is_affirmative(transcript):
        raise ConsentError(
            'The phrase heard was not a clear yes. Say exactly "zgadzam się" or "tak, uruchom".')
    return grant(agent_id, task, spoken=True)


def consume(token, agent_id, task):
    """Spend a grant. Returns the grant; raises when it does not fit."""
    if not isinstance(token, str) or not re.fullmatch(r'[0-9a-f]{32}', token):
        raise ConsentError('A consent token is required before an agent can start.')
    with STORE_LOCK:
        rows = _load()
        expected = digest(agent_id, task)
        for row in rows:
            if row.get('token') != token:
                continue
            if row.get('used'):
                raise ConsentError('That consent was already used.')
            if row.get('expires_at', 0) <= time.time():
                raise ConsentError('That consent expired; ask again.')
            if row.get('digest') != expected:
                # A grant for one task must never unlock a different one.
                raise ConsentError('That consent was given for a different task.')
            row['used'] = True
            _save(rows)
            return row
    raise ConsentError('No consent with that token exists.')


def pending():
    now = time.time()
    return [{'agent': row.get('agent'), 'spoken': row.get('spoken'),
             'expires_in': round(row.get('expires_at', 0) - now)}
            for row in _load() if not row.get('used') and row.get('expires_at', 0) > now]


def grant_click(agent_id, task):
    return grant(agent_id, task, spoken=False)
