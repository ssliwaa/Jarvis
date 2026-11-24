"""Jev (TypeSafe System One) as an optional decision layer — never an authority.

Jev answers *typed questions* about a state and returns choices, scores and
probabilities instead of prose. Jarvis uses it only where a decision is being
made today by a regex or a paid LLM call, and always as an optional accelerator:
with no key, a timeout, a bad answer or any transport error the caller falls back
to its existing rules. Nothing here may decide permissions, approvals or whether
an action really happened — those stay in code.

Security notes that matter for this service:
- Only ``api.typesafe.ai``, the host named in TypeSafe's official documentation,
  is used. ``thejevai.com`` states that it is independently operated and not
  affiliated with TypeSafe, so it is not an official endpoint; a redirect is
  refused rather than followed and no other host is contacted.
- The key is read from the local credential store by name and never appears in a
  result, a log line or an error message.
"""
from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request

OFFICIAL_HOST = 'api.typesafe.ai'
ENDPOINT = f'https://{OFFICIAL_HOST}/v1/systemone'
DEFAULT_MODEL = 'jev-1.14.0'
CREDENTIAL = 'jev-api-key'
TIMEOUT = 6.0
MAX_RESPONSE = 512 * 1024
MAX_STATE = 8000
MAX_QUESTIONS = 8
MAX_OPTIONS = 20          # our bound; the API accepts up to 255 choice keys
MAX_SCORE_LEVELS = 10     # the API's ordered score rubric limit


class JevError(Exception):
    """Jev could not be asked; the caller must fall back to its own rules."""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise JevError('Jev answered with a redirect; refused.')


def _key():
    try:
        from operator_tools import SecretStore
        item = SecretStore().get(CREDENTIAL)
    except Exception:
        return ''
    return str(item.get('value') or '').strip()


def available():
    """True only when a key is stored; no network call is made here."""
    return bool(_key())


def model_name():
    return os.environ.get('JEV_MODEL', DEFAULT_MODEL)


def choice(id_, instructions, options):
    """Build a choice question.

    ``options`` may be a list of labels or a ``label -> description`` mapping.
    The official API calls this mapping ``criteria``; the old ``options`` list
    shape is not part of its contract.
    """
    if isinstance(options, dict):
        criteria = {str(label)[:80]: (None if description is None else str(description)[:200])
                    for label, description in options.items()}
    else:
        criteria = {str(option)[:80]: None for option in options or []}
    if not 1 <= len(criteria) <= MAX_OPTIONS:
        raise JevError(f'A choice question needs 1 to {MAX_OPTIONS} options.')
    if any(not label for label in criteria):
        raise JevError('Every choice option needs a non-empty label.')
    return {'type': 'choice', 'instructions': str(instructions)[:400], 'criteria': criteria}


def noul(id_, instructions):
    """A yes/no question ("noul" in Jev's vocabulary)."""
    return {'type': 'noul', 'instructions': str(instructions)[:400]}


def score(id_, instructions, criteria=None):
    """Build a score question; ``criteria`` is an ordered 1–10 level rubric."""
    if not isinstance(criteria, (list, tuple)) or not 1 <= len(criteria) <= MAX_SCORE_LEVELS:
        raise JevError(f'A score question needs 1 to {MAX_SCORE_LEVELS} criteria levels.')
    return {'type': 'score', 'instructions': str(instructions)[:400],
            'criteria': [str(level)[:200] for level in criteria]}


def _validate(questions):
    if not isinstance(questions, dict) or not 1 <= len(questions) <= MAX_QUESTIONS:
        raise JevError(f'Between 1 and {MAX_QUESTIONS} questions are required.')
    for name, spec in questions.items():
        if not isinstance(name, str) or not name:
            raise JevError('Every question needs a name.')
        if not isinstance(spec, dict):
            raise JevError('Each question must be a typed object.')
        kind = spec.get('type')
        if kind == 'choice':
            criteria = spec.get('criteria')
            if not isinstance(criteria, dict) or not 1 <= len(criteria) <= 255:
                raise JevError('A choice question needs 1 to 255 criteria keys.')
        elif kind == 'score':
            criteria = spec.get('criteria')
            if not isinstance(criteria, list) or not 1 <= len(criteria) <= MAX_SCORE_LEVELS:
                raise JevError(f'A score question needs 1 to {MAX_SCORE_LEVELS} criteria levels.')
        elif kind != 'noul':
            raise JevError('Each question must be choice, noul or score.')


def decide(state, questions, timeout=TIMEOUT):
    """Ask Jev for typed decisions. Raises JevError; callers must fail closed."""
    key = _key()
    if not key:
        raise JevError('Jev is not configured: no stored credential for jev-api-key.')
    _validate(questions)
    body = {'model': model_name(), 'state': state, 'questions': questions}
    try:
        payload = json.dumps(body, ensure_ascii=False).encode('utf-8')
    except (TypeError, ValueError):
        raise JevError('The decision state is not valid JSON.') from None
    if len(payload) > MAX_STATE + 4096:
        raise JevError('The state is too large for a bounded decision.')
    opener = urllib.request.build_opener(_NoRedirect())
    request = urllib.request.Request(ENDPOINT, data=payload, method='POST',
                                     headers={'Authorization': f'Bearer {key}',
                                              'Content-Type': 'application/json',
                                              'User-Agent': 'Jarvis/1.0 (local)'})
    started = time.time()
    try:
        with opener.open(request, timeout=max(1.0, min(float(timeout), 20.0))) as response:
            raw = response.read(MAX_RESPONSE)
    except JevError:
        raise
    except urllib.error.HTTPError as error:
        # Never echo the response body: it can contain the key on a relay.
        try:
            error.close()
        except Exception:
            pass
        raise JevError(f'Jev answered HTTP {error.code}.') from None
    except (urllib.error.URLError, OSError) as error:
        raise JevError(f'Jev could not be reached ({type(error).__name__}).') from None
    elapsed = round((time.time() - started) * 1000)
    try:
        parsed = json.loads(raw)
    except ValueError:
        raise JevError('Jev returned data that is not JSON.') from None
    if not isinstance(parsed, dict):
        raise JevError('Jev returned an unexpected shape.')
    answers = parsed.get('answers')
    if not isinstance(answers, dict) or not answers:
        raise JevError('Jev returned no usable answers.')
    usage = parsed.get('usage') if isinstance(parsed.get('usage'), dict) else {}
    return {'ok': True, 'answers': answers, 'model': parsed.get('model') or model_name(),
            'ms': elapsed, 'state_bytes': len(payload), 'usage': usage}


def _entry(result, name):
    answers = result.get('answers') if isinstance(result, dict) else None
    return answers.get(name) if isinstance(answers, dict) else None


def answer_for(result, name, default=None):
    """Read one question's value: choice label, score number or noul probability."""
    entry = _entry(result, name)
    if isinstance(entry, dict):
        for key in ('choice', 'score', 'noul', 'value', 'selected', 'answer', 'label'):
            if entry.get(key) is not None:
                return entry[key]
        return default
    return default if entry is None else entry


def yes(result, name, threshold=0.5, default=False):
    """Interpret a noul answer as a boolean using its calibrated yes probability."""
    entry = _entry(result, name)
    value = entry.get('noul', entry.get('value', entry.get('answer'))) if isinstance(entry, dict) else entry
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return float(value) >= float(threshold)
    if isinstance(value, str):
        text = value.strip().lower()
        if text in ('true', 'yes', 'tak', '1', 'y'):
            return True
        if text in ('false', 'no', 'nie', '0', 'n'):
            return False
        try:
            return float(text) >= float(threshold)
        except ValueError:
            return default
    return default


def status():
    """Safe summary for the UI and preflight: no key, no secrets."""
    return {'configured': available(), 'model': model_name(), 'endpoint': ENDPOINT,
            'credential': CREDENTIAL}
