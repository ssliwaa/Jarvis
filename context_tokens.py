"""Token estimates for context budgeting.

This is deliberately a rough, allocation-light estimator, not a tokenizer.  It
mirrors the estimator Hermes uses before an API call: ASCII is charged at four
characters per token, CJK/Hangul/Kana codepoints at one token each, and other
non-ASCII text by UTF-8 byte length.  The provider's real ``prompt_tokens``
always wins once a response arrives; the estimate is only the preflight signal.

The module also understands both message shapes that cross Jarvis:
Anthropic-style content blocks (what server.py and browser_agent.py use) and
OpenAI-style ``tool_calls`` messages (what provider_client.py sends on the
wire).
"""
from __future__ import annotations

import json
import math
import re

CHARS_PER_TOKEN = 4
_CJK_DENSE_RE = re.compile(
    "[ᄀ-ᇿ⺀-鿿ꥠ-꥿가-힯"
    "豈-﫿＀-￯]"
)


def estimate_tokens_rough(text) -> int:
    """Rough token count for text; never raises on surrogates or non-strings."""
    if text is None:
        return 0
    value = str(text)
    if not value:
        return 0
    if value.isascii():
        return (len(value) + CHARS_PER_TOKEN - 1) // CHARS_PER_TOKEN
    stripped = _CJK_DENSE_RE.sub("", value)
    dense = len(value) - len(stripped)
    return dense + (len(stripped.encode("utf-8", "replace")) + CHARS_PER_TOKEN - 1) // CHARS_PER_TOKEN


def _json_text(value) -> str:
    try:
        return json.dumps(value, ensure_ascii=False, default=str)
    except (TypeError, ValueError):
        return str(value)


def estimate_content_tokens(content) -> int:
    """Estimate a string or an Anthropic/OpenAI content-block list."""
    if content is None:
        return 0
    if isinstance(content, str):
        return estimate_tokens_rough(content)
    if isinstance(content, dict):
        return estimate_tokens_rough(_json_text(content))
    if not isinstance(content, (list, tuple)):
        return estimate_tokens_rough(content)
    total = 0
    for block in content:
        if isinstance(block, str):
            total += estimate_tokens_rough(block)
            continue
        if not isinstance(block, dict):
            total += estimate_tokens_rough(block)
            continue
        kind = str(block.get("type") or "")
        if kind == "text":
            total += estimate_tokens_rough(block.get("text") or "")
        elif kind == "tool_use":
            total += estimate_tokens_rough(block.get("name") or "")
            total += estimate_tokens_rough(_json_text(block.get("input") or {}))
        elif kind == "tool_result":
            total += estimate_tokens_rough(block.get("tool_use_id") or "")
            total += estimate_content_tokens(block.get("content"))
        elif kind in ("image", "image_url", "input_image"):
            # A real image is billed by the provider's image rules, not by the
            # base64 length. Keep a flat charge so a 4 MB data URL cannot make
            # the estimator believe the request is enormous.
            total += 1600
        else:
            total += estimate_tokens_rough(_json_text(block))
    return total


def estimate_message_tokens(message) -> int:
    """Estimate one chat message including role and tool metadata."""
    if not isinstance(message, dict):
        return 1
    total = 4  # role + separators
    total += estimate_content_tokens(message.get("content"))
    name = message.get("name")
    if name:
        total += estimate_tokens_rough(name)
    tool_calls = message.get("tool_calls")
    if isinstance(tool_calls, list):
        for call in tool_calls:
            function = call.get("function") if isinstance(call, dict) else None
            if isinstance(function, dict):
                total += estimate_tokens_rough(function.get("name") or "")
                total += estimate_tokens_rough(function.get("arguments") or "")
            else:
                total += estimate_tokens_rough(_json_text(call))
    tool_call_id = message.get("tool_call_id")
    if tool_call_id:
        total += estimate_tokens_rough(tool_call_id)
    return max(1, total)


def estimate_messages_tokens(messages) -> int:
    """Estimate a full message list.  Empty lists cost zero, not one."""
    return sum(estimate_message_tokens(message) for message in (messages or []))


def estimate_tools_tokens(tools) -> int:
    """Estimate tool declarations; schemas are re-sent on every request."""
    if not tools:
        return 0
    return sum(estimate_tokens_rough(_json_text(tool)) + 4 for tool in tools)


def estimate_request_tokens(messages, system: str = "", tools=None) -> int:
    """Estimate the complete provider request (messages + system + tools)."""
    total = estimate_messages_tokens(messages)
    total += estimate_tokens_rough(system or "")
    total += estimate_tools_tokens(tools)
    return max(0, total)


def estimate_tokens(text) -> int:
    """Compatibility alias used by context_budget."""
    return estimate_tokens_rough(text)


def ceil_tokens(value: int) -> int:
    return max(0, int(math.ceil(float(value or 0))))
