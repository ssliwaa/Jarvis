"""Text sanitizer and boundary guard module for Jarvis.

Provides HTML tag stripping, markdown link scheme whitelisting, ANSI escape sequence
removal, Unicode NFKC normalization and invisible/bidi character elimination,
and prompt delimiter breakout protection.
"""

from __future__ import annotations

import html
import re
import unicodedata
from html.parser import HTMLParser
from typing import Any
from urllib.parse import urlsplit

MAX_TEXT_BYTES = 2 * 1024 * 1024  # 2 MB payload ceiling

ANSI_RE = re.compile(
    r"\x1B(?:"
    r"\[[0-?]*[ -/]*[@-~]|"  # CSI sequences
    r"\][^\x07\x1B]*(?:\x07|\x1B\\)|"  # OSC sequences
    r"[@-Z\\-_]"  # Fe escape sequences
    r")|[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]"  # ASCII control codes except \t and \n
)

ZERO_WIDTH_AND_BIDI_CHARS = frozenset({
    "\u200b",  # Zero-width space
    "\u200c",  # Zero-width non-joiner
    "\u200d",  # Zero-width joiner
    "\ufeff",  # Zero-width no-break space / BOM
    "\u2060",  # Word joiner
    "\u00ad",  # Soft hyphen
    # Bidi control characters
    "\u202a",  # Left-to-Right Embedding
    "\u202b",  # Right-to-Left Embedding
    "\u202c",  # Pop Directional Formatting
    "\u202d",  # Left-to-Right Override
    "\u202e",  # Right-to-Left Override
    "\u2066",  # Left-to-Right Isolate
    "\u2067",  # Right-to-Left Isolate
    "\u2068",  # First Strong Isolate
    "\u2069",  # Pop Directional Isolate
})

ALLOWED_LINK_SCHEMES = frozenset({"http", "https", "mailto"})
DANGEROUS_LINK_SCHEMES = frozenset({"javascript", "data", "vbscript", "file"})


class _SafeHTMLFilter(HTMLParser):
    def __init__(self, allowed_tags: set[str] | None = None) -> None:
        super().__init__(convert_charrefs=True)
        self.allowed_tags = allowed_tags or set()
        self.result: list[str] = []
        self.stripped_tags_count = 0
        self.skip_stack: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag_lower = tag.lower()
        if tag_lower in ("script", "style"):
            self.skip_stack.append(tag_lower)
            self.stripped_tags_count += 1
            return

        if self.skip_stack:
            return

        if tag_lower in self.allowed_tags:
            safe_attrs: list[str] = []
            for attr_name, attr_val in attrs:
                attr_name_lower = attr_name.lower()
                # Strip event handlers and unsafe URI schemes
                if attr_name_lower.startswith("on"):
                    continue
                val_str = attr_val or ""
                if attr_name_lower in ("href", "src"):
                    try:
                        scheme = urlsplit(val_str).scheme.lower()
                        if scheme in DANGEROUS_LINK_SCHEMES:
                            val_str = "#blocked"
                    except Exception:
                        val_str = "#blocked"
                safe_attrs.append(f'{attr_name}="{html.escape(val_str, quote=True)}"')
            attr_part = (" " + " ".join(safe_attrs)) if safe_attrs else ""
            self.result.append(f"<{tag_lower}{attr_part}>")
        else:
            self.stripped_tags_count += 1

    def handle_endtag(self, tag: str) -> None:
        tag_lower = tag.lower()
        if self.skip_stack:
            if tag_lower == self.skip_stack[-1]:
                self.skip_stack.pop()
            return

        if tag_lower in self.allowed_tags:
            self.result.append(f"</{tag_lower}>")
        else:
            self.stripped_tags_count += 1

    def handle_data(self, data: str) -> None:
        if not self.skip_stack:
            self.result.append(data)


def _strip_html(text: str, allowed_tags: list[str] | None = None) -> dict[str, Any]:
    allowed_set = {t.strip().lower() for t in allowed_tags} if allowed_tags else set()
    parser = _SafeHTMLFilter(allowed_tags=allowed_set)
    parser.feed(text)
    parser.close()
    sanitized = "".join(parser.result)
    return {
        "sanitized": sanitized,
        "stripped_tags_count": parser.stripped_tags_count,
        "allowed_tags": sorted(list(allowed_set)),
    }


def _clean_markdown(text: str) -> dict[str, Any]:
    links_modified_count = 0

    # 1. Strip HTML comments <!-- ... -->
    cleaned = re.sub(r"<!--.*?-->", "", text, flags=re.DOTALL)

    # 2. Neutralize dangerous raw tags like <script> or <iframe>
    def _strip_raw_dangerous(match: re.Match) -> str:
        nonlocal links_modified_count
        links_modified_count += 1
        return ""

    cleaned = re.sub(r"<(?:script|iframe|object|embed)[^>]*>.*?</(?:script|iframe|object|embed)>", _strip_raw_dangerous, cleaned, flags=re.IGNORECASE | re.DOTALL)
    cleaned = re.sub(r"<(?:script|iframe|object|embed)[^>]*>", _strip_raw_dangerous, cleaned, flags=re.IGNORECASE)

    # 3. Clean inline markdown links: [text](url)
    def _clean_inline_link(match: re.Match) -> str:
        nonlocal links_modified_count
        label = match.group(1)
        url = match.group(2).strip()
        try:
            scheme = urlsplit(url).scheme.lower()
            if scheme in DANGEROUS_LINK_SCHEMES:
                links_modified_count += 1
                return f"[{label}](#blocked)"
        except Exception:
            links_modified_count += 1
            return f"[{label}](#blocked)"
        return match.group(0)

    cleaned = re.sub(r"\[([^\]]+)\]\(([^)]+)\)", _clean_inline_link, cleaned)

    # 4. Clean reference links: [ref]: url
    def _clean_ref_link(match: re.Match) -> str:
        nonlocal links_modified_count
        ref = match.group(1)
        url = match.group(2).strip()
        try:
            scheme = urlsplit(url).scheme.lower()
            if scheme in DANGEROUS_LINK_SCHEMES:
                links_modified_count += 1
                return f"[{ref}]: #blocked"
        except Exception:
            links_modified_count += 1
            return f"[{ref}]: #blocked"
        return match.group(0)

    cleaned = re.sub(r"^\[([^\]]+)\]:\s*(\S+)", _clean_ref_link, cleaned, flags=re.MULTILINE)

    return {
        "sanitized": cleaned,
        "links_modified_count": links_modified_count,
    }


def _strip_ansi(text: str) -> dict[str, Any]:
    matches = ANSI_RE.findall(text)
    stripped = ANSI_RE.sub("", text)
    return {
        "sanitized": stripped,
        "stripped_sequences_count": len(matches),
    }


def _normalize_unicode(text: str) -> dict[str, Any]:
    # NFKC normalization
    normalized = unicodedata.normalize("NFKC", text)

    removed_count = 0
    cleaned_chars: list[str] = []
    for ch in normalized:
        if ch in ZERO_WIDTH_AND_BIDI_CHARS:
            removed_count += 1
        else:
            cleaned_chars.append(ch)

    sanitized = "".join(cleaned_chars)
    return {
        "sanitized": sanitized,
        "removed_characters_count": removed_count,
    }


def _wrap_untrusted(text: str, tag_label: str | None = None) -> dict[str, Any]:
    label = tag_label.strip() if tag_label and tag_label.strip() else "UNTRUSTED_CONTENT"
    # Ensure label consists only of safe alphanumeric and underscore characters
    label = re.sub(r"[^A-Za-z0-9_]", "_", label).upper()

    count = 0
    # Escape <<< and >>> sequences so untrusted text cannot break out of prompt delimiters
    def _escape_left(m: re.Match) -> str:
        nonlocal count
        count += 1
        return "< < <"

    def _escape_right(m: re.Match) -> str:
        nonlocal count
        count += 1
        return "> > >"

    escaped = re.sub(r"<<<", _escape_left, text)
    escaped = re.sub(r">>>", _escape_right, escaped)

    # Check for direct mentions of closing tag
    closing_token = f"END_{label}"
    if closing_token in escaped:
        escaped = escaped.replace(closing_token, f"END_ {label}")
        count += 1

    wrapped = f"<<<{label}>>>\n{escaped}\n<<<END_{label}>>>"

    return {
        "wrapped": wrapped,
        "tag_label": label,
        "escaped_delimiters_count": count,
    }


def _text_sanitizer_impl(arguments: dict[str, Any], context: dict[str, Any] | None = None) -> dict[str, Any]:
    action = arguments.get("action")
    if not action:
        return {"ok": False, "success": False, "data": None, "result": None, "error": "Missing required field 'action'"}

    text = arguments.get("text")
    if not isinstance(text, str):
        return {"ok": False, "success": False, "data": None, "result": None, "error": "Field 'text' must be a string"}

    if len(text.encode("utf-8", errors="ignore")) > MAX_TEXT_BYTES:
        return {
            "ok": False,
            "success": False,
            "data": None,
            "result": None,
            "error": f"Text payload exceeds maximum allowed size ({MAX_TEXT_BYTES} bytes)",
        }

    if action == "strip_html":
        allowed = arguments.get("allowed_tags")
        data = _strip_html(text, allowed)
        return {"ok": True, "success": True, "data": data, "result": data, "error": None}

    if action == "clean_markdown":
        data = _clean_markdown(text)
        return {"ok": True, "success": True, "data": data, "result": data, "error": None}

    if action == "strip_ansi":
        data = _strip_ansi(text)
        return {"ok": True, "success": True, "data": data, "result": data, "error": None}

    if action == "normalize_unicode":
        data = _normalize_unicode(text)
        return {"ok": True, "success": True, "data": data, "result": data, "error": None}

    if action == "wrap_untrusted":
        tag_label = arguments.get("tag_label")
        data = _wrap_untrusted(text, tag_label)
        return {"ok": True, "success": True, "data": data, "result": data, "error": None}

    return {"ok": False, "success": False, "data": None, "result": None, "error": f"Unsupported action: {action!r}"}


def text_sanitizer(arguments: dict[str, Any], context: dict[str, Any] | None = None) -> dict[str, Any]:
    """Execute text sanitization, boundary guarding, ANSI stripping, and prompt encapsulation."""
    try:
        return _text_sanitizer_impl(arguments, context)
    except Exception as err:
        return {
            "ok": False,
            "success": False,
            "data": None,
            "result": None,
            "error": f"Sanitization error: {type(err).__name__}: {err}",
        }


TOOL = {
    "name": "text_sanitizer",
    "description": (
        "Text sanitizer and prompt boundary guard. Strips HTML tags (with optional tag whitelist), "
        "cleans dangerous markdown link schemes (javascript/data/file), strips ANSI escape codes, "
        "normalizes Unicode (NFKC) and removes invisible/bidi characters, and encapsulates untrusted "
        "text with delimiter escaping to prevent prompt injection breakouts."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "action": {
                "type": "string",
                "enum": ["strip_html", "clean_markdown", "strip_ansi", "normalize_unicode", "wrap_untrusted"],
                "description": "Sanitization action to perform.",
            },
            "text": {
                "type": "string",
                "description": "Text content to sanitize.",
            },
            "allowed_tags": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Allowed HTML tags when action='strip_html'.",
            },
            "tag_label": {
                "type": "string",
                "description": "Context tag label for wrap_untrusted (default: 'UNTRUSTED_CONTENT').",
            },
        },
        "required": ["action", "text"],
        "additionalProperties": False,
    },
    "handler": text_sanitizer,
    "approval": False,
}
