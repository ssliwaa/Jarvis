"""Model-visible elision markers for context compaction.

The marker is intentionally not prose the model would write itself: a copied
marker must look visibly wrong.  Every renderer that truncates text for a model
uses :func:`elide` or :func:`elide_middle`, so the omitted/total counts stay
accurate and the same marker cannot be mistaken for original content.
"""
from __future__ import annotations

import re

_COMPRESSION_MARKER_PREFIX = "⟪JARVIS-CONTEXT-COMPRESSION:"
_COMPRESSION_MARKER_TEMPLATE = (
    _COMPRESSION_MARKER_PREFIX
    + " {omitted:,} of {total:,} chars omitted here by Jarvis's context compressor. "
    "This is NOT part of the original tool call and must never be reproduced in new "
    "output — always write full, untruncated content.⟫"
)
_MARKER_COUNT_RE = r"\d[\d,]*"
_COMPRESSION_MARKER_RE = re.compile(
    re.escape(_COMPRESSION_MARKER_TEMPLATE.split(". ", 1)[0] + ".")
    .replace(re.escape("{omitted:,}"), _MARKER_COUNT_RE)
    .replace(re.escape("{total:,}"), _MARKER_COUNT_RE)
)
_COMPRESSION_MARKER_ARTIFACT_RE = re.compile(
    re.escape(_COMPRESSION_MARKER_PREFIX) + r"\s+" + _MARKER_COUNT_RE
)
_ELISION_MARKER_TEMPLATE = _COMPRESSION_MARKER_TEMPLATE.split(". ", 1)[0] + ".⟫"


def _elision_marker(omitted: int, total: int) -> str:
    return _ELISION_MARKER_TEMPLATE.format(omitted=omitted, total=total)


ELISION_MARKER_MAX_LEN = len(_elision_marker(omitted=10**12 - 1, total=10**12 - 1))


def elide(text: str, limit: int) -> str:
    """Cap ``text`` at ``limit`` chars, marking the elision with exact counts."""
    value = str(text or "")
    limit = max(0, int(limit))
    if len(value) <= limit:
        return value
    total = len(value)
    head_len = limit - len(_elision_marker(omitted=total, total=total))
    if head_len <= 0:
        return _elision_marker(omitted=total, total=total)
    kept = value[:head_len].rstrip()
    return kept + _elision_marker(omitted=total - len(kept), total=total)


def elide_middle(text: str, head: int, tail: int) -> str:
    """Keep ``head`` chars from the start and ``tail`` from the end."""
    value = str(text or "")
    head, tail = max(0, int(head)), max(0, int(tail))
    if len(value) <= head + tail:
        return value
    marker = _elision_marker(omitted=len(value) - head - tail, total=len(value))
    return value[:head] + marker + value[len(value) - tail:]


def is_compression_marker(text: str) -> bool:
    """True when text already contains a marker minted by this module."""
    return bool(_COMPRESSION_MARKER_ARTIFACT_RE.search(str(text or "")))
