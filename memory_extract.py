"""Turn a conversation turn into a few durable facts, or into nothing.

The regex list in ``MemoryStore.SUGGESTIONS`` only catches sentences that start
the way the pattern expects, which is why personal memory stayed empty. This
module asks the model for at most three facts, validates them strictly, and
routes them: objective facts (identity, hardware, relations) are written
directly, everything else becomes a pending suggestion. A memory written from
chat is always reversible through the event log.
"""
from __future__ import annotations

import json
import re

from memory_store import CATEGORIES, slug_key

AUTO_CATEGORIES = ("identity", "hardware", "relations")
MIN_AUTO_CONFIDENCE = 0.7
MAX_FACTS = 3

SYSTEM = (
    "Jesteś ekstraktorem trwałych faktów do pamięci osobistej asystenta. "
    "Czytasz jedną turę rozmowy i zwracasz WYŁĄCZNIE obiekt JSON.\n"
    "Format: {\"facts\":[{\"category\":\"...\",\"key\":\"...\",\"value\":\"...\","
    "\"confidence\":0.0,\"quote\":\"...\"}]}\n"
    "Zasady:\n"
    "- 0-3 fakty; lepiej zero niż domysł.\n"
    "- Tylko informacje trwałe o właścicielu, jego sprzęcie, projektach, relacjach i preferencjach.\n"
    "- Nie zapisuj próśb jednorazowych, pytań, wyników wyszukiwania, treści notatek ani poleceń dla asystenta.\n"
    "- category jedna z: identity, preferences, projects, relations, hardware, rules, notes.\n"
    "- key: krótki identyfikator po polsku, małe litery, bez spacji na końcu (np. miasto, trening, kino_wersja).\n"
    "- value: jedno zwięzłe zdanie, maks. 200 znaków, bez cytowania całej wiadomości.\n"
    "- quote: dokładny fragment tekstu użytkownika, który to potwierdza, maks. 200 znaków.\n"
    "- confidence: 0.0-1.0, tylko gdy fakt jest wprost powiedziany.\n"
    "- Fakty muszą pochodzić z WIADOMOŚCI UŻYTKOWNIKA; odpowiedź asystenta to wyłącznie kontekst "
    "i nie wolno na jej podstawie dopisywać faktów.\n"
    "Jeśli nic trwałego nie ma: {\"facts\":[]}."
)

FIRST_PERSON = re.compile(
    r"\b(ja|jestem|mam|mnie|mi|mój|moja|moje|mieszkam|uczę|ucze|chodzę|chodze|trenuję|trenuje|"
    r"wolę|wole|preferuję|preferuje|używam|uzywam|pracuję|pracuje|studiuję|studiuje|nazywam)\b",
    re.I)


def should_capture(text) -> bool:
    """Cheap gate before spending a model call on a turn.

    Questions about the vault ("what does the note say?") and one-line commands
    are not about the owner, and capturing them is how a memory store fills up
    with noise.  Short first-person statements ("I live in Testville.") are
    kept with a lower length floor.
    """
    value = str(text or "").strip()
    if not value or value.startswith(("/", "!", "[")):
        return False
    has_first_person = bool(FIRST_PERSON.search(value))
    min_len = 16 if has_first_person else 40
    if len(value) < min_len:
        return False
    if value.endswith("?") and not has_first_person:
        return False
    return True


def build_prompt(message, answer=""):
    parts = ["WIADOMOŚĆ UŻYTKOWNIKA:", str(message or "")[:2000]]
    if answer:
        parts += ["", "ODPOWIEDŹ ASYSTENTA:", str(answer or "")[:1200]]
    return "\n".join(parts)


def parse(raw):
    """Accept plain JSON, fenced JSON, or JSON surrounded by prose."""
    text = str(raw or "").strip()
    if not text:
        return []
    fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.S)
    if fenced:
        text = fenced.group(1)
    else:
        start, end = text.find("{"), text.rfind("}")
        if start == -1 or end <= start:
            return []
        text = text[start:end + 1]
    try:
        data = json.loads(text)
    except (TypeError, ValueError):
        return []
    facts = data.get("facts") if isinstance(data, dict) else None
    return [fact for fact in facts if isinstance(fact, dict)] if isinstance(facts, list) else []


def _slug(text):
    """Thin wrapper over memory_store.slug_key: THE key-normalizer for memory."""
    return slug_key(text)


def validate(facts, limit=MAX_FACTS):
    output, seen = [], set()
    for fact in facts[:limit]:
        category = str(fact.get("category") or "").strip().lower()
        if category not in CATEGORIES:
            continue
        key = _slug(fact.get("key"))
        value = str(fact.get("value") or "").strip()
        if len(key) < 2 or not 2 <= len(value) <= 300:
            continue
        try:
            confidence = float(fact.get("confidence", 0.5))
        except (TypeError, ValueError):
            confidence = 0.5
        confidence = max(0.0, min(1.0, confidence))
        quote = str(fact.get("quote") or "").strip()[:200]
        signature = (category, key, value.casefold())
        if signature in seen:
            continue
        seen.add(signature)
        output.append({"category": category, "key": key, "value": value,
                       "confidence": round(confidence, 2), "quote": quote})
    return output


def extract(client, message, answer="", model=None, max_tokens=400):
    """One cheap completion; returns validated facts or raises nothing."""
    if client is None:
        return []
    kwargs = {"max_tokens": max_tokens, "temperature": 0,
              "system": SYSTEM, "messages": [{"role": "user", "content": build_prompt(message, answer)}]}
    if model:
        kwargs["model"] = model
    try:
        response = client.messages.create(**kwargs)
    except TypeError:
        kwargs.pop("temperature", None)
        response = client.messages.create(**kwargs)
    text = ""
    for block in getattr(response, "content", []) or []:
        if getattr(block, "type", "") == "text":
            text += getattr(block, "text", "")
    return validate(parse(text))


def capture(store, facts, source="chat", auto_categories=AUTO_CATEGORIES,
            min_confidence=MIN_AUTO_CONFIDENCE):
    """Write objective facts, queue the rest for approval."""
    written, proposed = [], []
    for fact in facts:
        if fact["category"] in auto_categories and fact["confidence"] >= min_confidence:
            row = store.remember(fact["category"], fact["key"], fact["value"],
                                 importance=0.6, source=source, quote=fact["quote"],
                                 confidence=fact["confidence"])
            written.append({"id": row.get("id"), "key": row.get("key"),
                            "action": row.get("action"), "value": row.get("value")})
        else:
            suggestion = store.propose(fact["category"], fact["key"], fact["value"],
                                       reason=f"{source} ({fact['confidence']:.2f})",
                                       confidence=fact["confidence"], quote=fact["quote"],
                                       source=source)
            if suggestion:
                proposed.append(suggestion)
    return {"written": written, "proposed": proposed}
