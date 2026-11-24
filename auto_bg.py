"""Smart Natural-Language Background Task Detector for Jarvis.

Decides automatically whether a spoken or typed request should run in the
non-blocking BackgroundLane without requiring `/bg`.
"""
from __future__ import annotations

import re

EXPLICIT_BG_RE = re.compile(
    r"(?:^\s*(?:/bg|/background)\b|"
    r"\b(?:w\s+tle|na\s+tle|w\s+bekgrandzie|w\s+backgroundzie|in\s+(?:the\s+)?background|"
    r"asynchronicznie|asynchronously|równolegle|rownolegle|po\s+cichu|"
    r"nie\s+blokuj\w*|bez\s+blokowania|without\s+blocking|"
    r"w\s+międzyczasie|w\s+miedzyczasie|meanwhile|in\s+the\s+meantime|"
    r"daj\s+(?:mi\s+)?znać\s+(?:jak|gdy|kiedy)\s+skończ\w*|daj\s+(?:mi\s+)?znac\s+(?:jak|gdy|kiedy)\s+skoncz\w*|"
    r"zawołaj\s+(?:jak|gdy)\s+skończ\w*|powiadom\s+(?:mnie\s+)?(?:jak|gdy|kiedy)\s+skończ\w*|"
    r"let\s+me\s+know\s+when\s+(?:it'?s\s+|you'?re\s+)?done|notify\s+me\s+when\s+done)\b)",
    re.I,
)

FORCE_FOREGROUND_RE = re.compile(
    r"\b(?:kliknij|kliknąć|kliknac|wypełnij|wypelnij|przewiń|przewin|zrób\s+zrzut|"
    r"na\s+ekranie|w\s+przeglądarce|w\s+przegladarce|otwórz\s+(?:okno|kartę|karte|stronę|strone|przeglądarkę|opera|chrome|firefox|spotify)|"
    r"click|scroll|screenshot|bring\s+to\s+front|focus\s+window|play\s+music|puść\s+muzyk\w*|ścisz|pogłoś|wycisz)\b",
    re.I,
)

AGENT_NAME_RE = re.compile(
    r"\b(?:antigravity|antygravity|anti-gravity|agy|claude(?:\s+code)?|opencode|open\s+code|hermes)\b",
    re.I,
)
AGENT_STATUS_ONLY_RE = re.compile(
    r"^\s*(?:sprawdź|sprawdz|pokaż|pokaz|jaki\s+jest|czy|check|show|list|test|przetestuj|ping)\b"
    r"[^,.;]{0,55}\b(?:status|wersj\w*|version|działaj\w*|dzialaj\w*|odpowiadaj\w*|available|installed|outbox|logi|logs)\b",
    re.I,
)
AGENT_WORK_VERB_RE = re.compile(
    r"\b(?:zleć|zlec|zlecić|zlecic|poproś|popros|powiedz|przekaż|przekaz|niech|każ|kaz|wyślij\s+do|wyslij\s+do|"
    r"zrób\w*|zrob\w*|zbuduj\w*|stwórz\w*|stworz\w*|utwórz\w*|utworz\w*|napisz\w*|zaimplementuj\w*|zaprojektuj\w*|"
    r"napraw\w*|popraw\w*|zrefaktoryzuj\w*|refaktor\w*|zoptymalizuj\w*|przeanalizuj\w*|przeskanuj\w*|"
    r"wygeneruj\w*|skompiluj\w*|wdroż\w*|wdroz\w*|przygotuj\w*|opracuj\w*|"
    r"delegate|ask|tell|have|let|make|build|create|develop|implement|write|fix|refactor|optimize|generate)\b",
    re.I,
)

HEAVY_BUILD_RE = re.compile(
    r"\b(?:zbuduj\w*|stwórz\w*|stworz\w*|utwórz\w*|utworz\w*|wygeneruj\w*|zaimplementuj\w*|zaprojektuj\w*|"
    r"build|create|develop|generate)\b"
    r".{0,45}\b(?:stron[ęy]|witryn[ęy]|landing\s*page|portfolio|aplikacj[ęe]|webapp|website)\b",
    re.I,
)


def strip_bg_prefix(task: str) -> str:
    text = str(task or "").strip()
    text = re.sub(
        r"^\s*(?:/bg[:,]?|/background[:,]?|w\s+tle[:,]?|na\s+tle[:,]?|uruchom\s+w\s+tle[:,]?|"
        r"zrób\s+w\s+tle[:,]?|zrob\s+w\s+tle[:,]?|odpal\s+w\s+tle[:,]?|"
        r"run\s+in\s+(?:the\s+)?background[:,]?)\s+",
        "",
        text,
        flags=re.I,
    ).strip()
    return text or str(task or "").strip()


def should_run_in_background(task: str, *, foreground_busy: bool = False) -> tuple[bool, str]:
    """Return `(run_in_bg, reason)` for a natural-language Operator task."""
    text = str(task or "").strip()
    if not text:
        return False, ""

    # Gate destructive work to the foreground unless the user force-routes it.
    # The disk-format patterns match real formatting verbs and drive letters
    # (a trailing group \b can never sit behind ':', so the drive form stands
    # outside it); a bare word "format" (e.g. "w formacie mobilnym") is benign.
    destructive = (
        r"\b(?:usuń|usun|skasuj|wymaż|wymaz|s?formatuj\w*|s?formatować|"
        r"s?formatowanie\s+dysk\w*|wipe\b|drop\s+table|rm\s+-rf)\b"
        r"|\bformat\s+(?:c|d):"
    )
    if re.search(destructive, text, re.I):
        if re.match(r"^\s*(?:/bg|/background)\b", text, re.I):
            return True, "explicit /bg prefix"
        return False, ""

    if EXPLICIT_BG_RE.search(text):
        return True, "explicit natural-language background phrase"

    if FORCE_FOREGROUND_RE.search(text):
        return False, ""

    # Spoken/typed delegation to an external coding agent ("powiedz antygravity żeby zbudował stronę")
    if AGENT_NAME_RE.search(text) and not AGENT_STATUS_ONLY_RE.search(text):
        if AGENT_WORK_VERB_RE.search(text):
            return True, "external coding agent delegation"

    # Multi-file website/app builds ("zbuduj responsywną stronę portfolio") or when foreground slot is busy
    if HEAVY_BUILD_RE.search(text):
        return True, "long-running website/app build" if not foreground_busy else "foreground busy; heavy build"

    return False, ""
