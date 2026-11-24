"""Abstract context engine contract.

A context engine decides when a conversation is close enough to the model's
window that older turns must be compacted, keeps the token accounting, and
returns a valid message list after compaction.  ``ContextCompressor`` is the
default (and currently only) implementation.

Lifecycle for one conversation::

    engine.on_session_start(session_id)
    engine.update_from_response(usage)      # after every provider response
    engine.should_compress(...)             # before the next request
    engine.compress(messages, ...)          # when it returns True
    engine.on_session_end(session_id, messages)

Token fields are intentionally plain attributes: the host reads them directly
to report usage and to decide whether a request is close to the limit.
"""
from __future__ import annotations

import copy
import json
from abc import ABC, abstractmethod
from typing import Any, Optional

from compression_marker import elide_middle
from context_tokens import estimate_messages_tokens

MEMORY_CONTEXT_MAX_CHARS = 6_000
_MEMORY_CONTEXT_HEAD_CHARS = 4_000
_MEMORY_CONTEXT_TAIL_CHARS = 1_500


def sanitize_memory_context(memory_context: str) -> str:
    """Bound and locally redact memory text before it crosses an LLM boundary."""
    text = str(memory_context or "").strip()
    if not text:
        return ""
    # Imported lazily so the leaf context module does not depend on the
    # compressor (which imports this class).
    from context_compressor import _redact_compaction_text
    sanitized = _redact_compaction_text(text)
    if len(sanitized) <= MEMORY_CONTEXT_MAX_CHARS:
        return sanitized
    return elide_middle(sanitized, _MEMORY_CONTEXT_HEAD_CHARS, _MEMORY_CONTEXT_TAIL_CHARS)


def automatic_compaction_status_message(engine: Any, *, phase: str, default_message: str, **context: Any) -> Optional[str]:
    """Host-visible status for an automatic compaction, or None to stay silent."""
    if not getattr(engine, "emit_automatic_compaction_status", True):
        return None
    formatter = getattr(engine, "get_automatic_compaction_status_message", None)
    message = formatter(phase=phase, default_message=default_message, **context) if callable(formatter) else default_message
    if message is None:
        return None
    return str(message).strip() or None


class ContextEngine(ABC):
    """Base class every context engine must implement."""

    last_prompt_tokens: int = 0
    last_completion_tokens: int = 0
    last_total_tokens: int = 0
    threshold_tokens: int = 0
    context_length: int = 0
    compression_count: int = 0
    threshold_percent: float = 0.75
    protect_first_n: int = 3
    protect_last_n: int = 6
    emit_automatic_compaction_status: bool = True

    @property
    @abstractmethod
    def name(self) -> str:
        """Short identifier (``"compressor"``)."""

    @abstractmethod
    def update_from_response(self, usage: dict[str, Any]) -> None:
        """Update tracked token usage after every LLM call."""

    @abstractmethod
    def should_compress(self, prompt_tokens: int | None = None) -> bool:
        """Return True if compaction should fire this turn."""

    def should_compress_info(self, prompt_tokens: int | None = None) -> tuple[bool, str | None]:
        """Return ``(should_compress, reason)``; reason is non-None when blocked."""
        return self.should_compress(prompt_tokens), None

    @abstractmethod
    def compress(
        self,
        messages: list[dict[str, Any]],
        current_tokens: Optional[int] = None,
        focus_topic: Optional[str] = None,
        force: bool = False,
        memory_context: str = "",
    ) -> list[dict[str, Any]]:
        """Compact ``messages`` into a valid message list that fits the budget."""

    def prune_tool_results_only(
        self, messages: list[dict[str, Any]], current_tokens: int | None = None
    ) -> tuple[list[dict[str, Any]], int]:
        """Deterministically trim old tool output without an LLM call."""
        return messages, 0

    def select_context(
        self,
        request_messages: list[dict[str, Any]],
        *,
        conversation_messages: list[dict[str, Any]] | None = None,
        incoming_message: dict[str, Any] | None = None,
        budget_tokens: int = 0,
    ) -> list[dict[str, Any]] | None:
        """Optionally replace the request context; default leaves it unchanged."""
        return None

    def on_turn_complete(self, messages: list[dict[str, Any]], usage: dict[str, Any] | None = None, **kwargs: Any) -> None:
        """Observe a finished turn. Best effort; no transcript mutation."""

    def should_compress_preflight(self, messages: list[dict[str, Any]]) -> bool:
        """Cheap rough check before a provider call; default skips."""
        return False

    def should_defer_preflight_to_real_usage(self, rough_tokens: int) -> bool:
        return False

    def get_automatic_compaction_status_message(
        self, *, phase: str, default_message: str, **context: Any
    ) -> str | None:
        return default_message if self.emit_automatic_compaction_status else None

    def has_content_to_compress(self, messages: list[dict[str, Any]]) -> bool:
        return True

    def on_session_start(self, session_id: str, **kwargs) -> None:
        """Session begins: load persisted state."""

    def on_session_end(self, session_id: str, messages: list[dict[str, Any]]) -> None:
        """Real session boundary (reset/expiry), never a normal turn."""

    def on_session_reset(self) -> None:
        """Reset per-session counters; token state starts from zero."""
        self.last_prompt_tokens = 0
        self.last_completion_tokens = 0
        self.last_total_tokens = 0
        self.compression_count = 0

    def get_tool_schemas(self) -> list[dict[str, Any]]:
        return []

    def handle_tool_call(self, name: str, args: dict[str, Any], **kwargs) -> str:
        return json.dumps({"error": f"Unknown context engine tool: {name}"})

    def get_status(self) -> dict[str, Any]:
        last_prompt = max(self.last_prompt_tokens, 0)
        return {
            "name": self.name,
            "last_prompt_tokens": last_prompt,
            "last_completion_tokens": max(self.last_completion_tokens, 0),
            "threshold_tokens": self.threshold_tokens,
            "context_length": self.context_length,
            "usage_percent": min(100, last_prompt / self.context_length * 100)
            if self.context_length else 0,
            "compression_count": self.compression_count,
        }

    def clone_for_agent(self) -> "ContextEngine":
        return copy.deepcopy(self)

    def update_model(
        self,
        model: str,
        context_length: int,
        base_url: str = "",
        api_key: str = "",
        provider: str = "",
        api_mode: str = "",
    ) -> None:
        del base_url, api_key, provider, api_mode
        self.context_length = context_length
        self.threshold_tokens = int(context_length * self.threshold_percent)

    def estimate_messages_tokens(self, messages: list[dict[str, Any]]) -> int:
        return estimate_messages_tokens(messages)
