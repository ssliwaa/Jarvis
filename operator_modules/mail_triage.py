"""Sorting the inbox into "needs me" and "can wait" — Jev when configured, rules otherwise.

This is the first place Jev is allowed to help, because it is a bounded decision
over text the user already owns: does this message need a person, what kind of
message is it, how urgent is it. The rules path is not a placeholder — it is the
fallback that runs when there is no key, when Jev times out, or when its answer
cannot be read, and every row says which path produced it.

Nothing here sends, deletes, moves or marks anything as read: the mailbox is
opened read-only through ``email_agent``.
"""
from __future__ import annotations

import re

import jev_decision

MAX_TRIAGE = 12
CATEGORIES = ('płatność', 'szkoła', 'dostawa', 'konto', 'spotkanie', 'powiadomienie', 'inne')
# TypeSafe's choice primitive wants criteria as label -> description; the
# descriptions make the category boundaries explicit to the model.
CATEGORY_CRITERIA = {
    'płatność': 'faktury, przelewy, subskrypcje, rachunki, zaległości',
    'szkoła': 'sprawdziany, oceny, nauczyciel, plan lekcji, zebrania',
    'dostawa': 'przesyłki, kurier, zamówienia, tracking, zwroty',
    'konto': 'hasła, logowanie, weryfikacja, bezpieczeństwo konta',
    'spotkanie': 'zaproszenia, terminy, kalendarz, harmonogram',
    'powiadomienie': 'newslettery, promocje, powiadomienia masowe',
    'inne': 'wiadomości, które nie pasują do pozostałych kategorii',
}
# TypeSafe's score primitive returns a probability-weighted level index, so the
# five ordered levels map linearly onto 0–100 urgency.
URGENCY_LEVELS = ('nie pilne', 'mało pilne', 'średnio pilne', 'pilne', 'bardzo pilne')

_PAYMENT = re.compile(r'faktur|płatn|platn|przelew|zaleg|subskryp|rachun|invoice|payment', re.I)
_SCHOOL = re.compile(r'szkoł|szkol|sprawdzian|kartkówk|ocen|nauczyciel|wychowawc|lekcj|plan lekcji|'
                     r'zebran|wywiadówk|egzamin|school|exam', re.I)
_DELIVERY = re.compile(r'dostaw|przesyłk|przesylk|kurier|paczka|tracking|shipped|delivery', re.I)
_ACCOUNT = re.compile(r'hasło|haslo|password|logowani|login|weryfikacj|kod|2fa|security alert|'
                      r'zabezpiecz|bezpieczeństw|bezpieczenstw|nowe urzadzenie|nowe urządzenie', re.I)
_MEETING = re.compile(r'spotkani|zaproszeni|meeting|calendar|termin|harmonogram|umów|umow', re.I)
# "no-reply" alone is not bulk: Google sends real security alerts from it.
_BULK = re.compile(r'newsletter|promocj|wyprzedaż|rabat|unsubscribe|marketing', re.I)
_NOREPLY = re.compile(r'no-?reply', re.I)
_URGENT = re.compile(r'dziś|dzis|jutro|termin|deadline|pilne|piln|natychmiast|urgent|asap|'
                     r'24 ?h|do godziny|ostateczn', re.I)
_ASKING = re.compile(r'\?|potwierd|odpowiedz|odpisz|proszę o|prosze o|prześlij|przeslij|'
                     r'czy możesz|czy mozesz|please|confirm|reply', re.I)


def _text(message):
    subject = str(message.get('subject') or '')
    sender = str(message.get('from') or '')
    preview = str(message.get('preview') or message.get('snippet') or '')
    return subject, sender, preview, f'{subject}\n{sender}\n{preview}'[:1500]


def _category(text):
    for pattern, name in ((_PAYMENT, 'płatność'), (_SCHOOL, 'szkoła'), (_DELIVERY, 'dostawa'),
                          (_ACCOUNT, 'konto'), (_MEETING, 'spotkanie'), (_BULK, 'powiadomienie')):
        if pattern.search(text):
            return name
    return 'inne'


def _rules(message):
    """Deterministic triage: no network, no model, explainable reasons."""
    subject, sender, _preview, text = _text(message)
    category = _category(text)
    bulk = bool(_BULK.search(sender) or _BULK.search(subject))
    noreply = bool(_NOREPLY.search(sender))
    urgent = bool(_URGENT.search(text))
    # A question mark buried in a price alert's preview is noise; the subject is
    # the only place where "please confirm / reply" really means the user.
    asking = bool(_ASKING.search(subject))
    # A billing, school, account or meeting message is the user's business even
    # without a question mark; bulk mail never is.
    needs = not bulk and (asking or urgent or category in ('płatność', 'szkoła', 'konto', 'spotkanie'))
    score = 10
    if asking:
        score += 25
    if urgent:
        score += 35
    if category in ('płatność', 'szkoła', 'konto'):
        score += 15
    if noreply and not bulk:
        score += 5
    if bulk:
        score = min(score, 20)
    reasons = []
    if bulk:
        # A question mark in a newsletter's preview is not the user's business,
        # so its reasons say why it was demoted instead of why it looked urgent.
        reasons.append('wysyłka masowa')
    else:
        if asking:
            reasons.append('pyta lub prosi o odpowiedź')
        if urgent:
            reasons.append('słowo o terminie')
        if category != 'inne':
            reasons.append(f'typ: {category}')
        if not reasons:
            reasons.append('brak sygnałów')
    return {'needs_me': needs, 'category': category, 'urgency': min(100, score),
            'source': 'rules', 'reasons': reasons}


def _jev(message):
    """One bounded question set per message; anything odd falls back to rules."""
    _subject, _sender, _preview, text = _text(message)
    questions = {'needs_me': jev_decision.noul('needs_me', 'Czy ta wiadomość wymaga decyzji '
                                                            'lub odpowiedzi człowieka?'),
                 'category': jev_decision.choice('category', 'Jaki to rodzaj wiadomości?',
                                                  CATEGORY_CRITERIA),
                 'urgency': jev_decision.score('urgency', 'Jak pilna jest ta wiadomość?',
                                                URGENCY_LEVELS)}
    result = jev_decision.decide(text, questions, timeout=5.0)
    raw_needs = jev_decision.answer_for(result, 'needs_me')
    category = jev_decision.answer_for(result, 'category')
    urgency = jev_decision.answer_for(result, 'urgency')
    if raw_needs is None or category is None:
        raise jev_decision.JevError('Jev answered without needs_me or category.')
    if category not in CATEGORIES:
        raise jev_decision.JevError('Jev answered with a category outside the rubric.')
    try:
        level = max(0.0, min(float(urgency), len(URGENCY_LEVELS) - 1))
    except (TypeError, ValueError):
        urgency_value = 50
    else:
        urgency_value = round(level / (len(URGENCY_LEVELS) - 1) * 100)
    return {'needs_me': jev_decision.yes(result, 'needs_me'),
            'category': category, 'urgency': urgency_value,
            'source': 'jev', 'reasons': [f'Jev, {result.get("ms")} ms, {result.get("model")}']}


def triage(limit=MAX_TRIAGE, prefer_jev=True):
    """Return the newest unread messages with a decision attached to each."""
    from operator_modules import email_agent

    limit = max(1, min(int(limit or MAX_TRIAGE), MAX_TRIAGE))
    listing = email_agent.list_messages(limit=limit, unread_only=True)
    if not listing.get('ok'):
        return listing
    configured = prefer_jev and jev_decision.available()
    rows = []
    degraded = None
    for message in listing.get('messages') or []:
        choice = None
        if configured:
            try:
                choice = _jev(message)
            except Exception as error:  # fail closed: any Jev problem means rules
                degraded = str(error)[:160]
                configured = False
        if choice is None:
            choice = _rules(message)
        row = {'subject': message.get('subject'), 'from': message.get('from'),
               'date': message.get('date')}
        row.update(choice)
        rows.append(row)
    rows.sort(key=lambda row: (not row['needs_me'], -row['urgency']))
    return {'ok': True, 'source': 'jev' if configured else 'rules',
            'jev_configured': jev_decision.available(), 'degraded': degraded,
            'count': len(rows), 'needs_me': sum(1 for row in rows if row['needs_me']),
            'messages': rows}


def mail_triage(arguments, context=None):
    """Operator tool: sort unread mail into needs-me and can-wait."""
    action = str((arguments or {}).get('action') or 'triage').strip().lower()
    if action == 'status':
        status = jev_decision.status()
        return {'ok': True, 'action': 'status',
                'jev': {'configured': status['configured'], 'model': status['model']},
                'fallback': 'rules' if not status['configured'] else 'jev'}
    if action != 'triage':
        return {'ok': False, 'error': f'Unknown action: {action}', 'allowed': ['triage', 'status']}
    try:
        return triage(limit=(arguments or {}).get('limit') or MAX_TRIAGE)
    except Exception as error:  # noqa: BLE001 - never leak a traceback to the chat lane
        return {'ok': False, 'error': f'{type(error).__name__}: {str(error)[:160]}'}


TOOL = {
    'name': 'mail_triage',
    'description': ('Sort unread mail into "needs me" and "can wait", with a category and '
                    'urgency per message. Read-only: nothing is sent, moved or marked read. '
                    'Uses Jev when a credential is stored, and falls back to explainable rules.'),
    'input_schema': {
        'type': 'object',
        'properties': {
            'action': {'type': 'string', 'enum': ['triage', 'status']},
            'limit': {'type': 'integer', 'minimum': 1, 'maximum': MAX_TRIAGE},
        },
        'required': ['action'],
        'additionalProperties': False,
    },
    'handler': mail_triage,
    'approval': False,
}
