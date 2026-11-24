"""Provider adapters for Jarvis.

DeepSeek's official API is OpenAI-compatible, while the rest of Jarvis speaks
the small Anthropic-shaped ``client.messages.create`` contract. This adapter
keeps that contract and converts messages/tools at the boundary.
"""
from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path
from types import SimpleNamespace

import anthropic
import httpx2

import usage_meter

DEEPSEEK_URL = "https://api.deepseek.com/chat/completions"
DEEPSEEK_BALANCE_URL = "https://api.deepseek.com/user/balance"
# deepseek-chat/deepseek-reasoner were retired on 2026-07-24; flash is the
# current low-latency API id (v4-pro remains the larger sibling).
DEFAULT_MODEL = "deepseek-flash"
RETIRED_MODELS = {"deepseek-chat", "deepseek-reasoner"}

# Transient transport/availability hiccups get one quiet retry each; billing
# problems (402) and real bad requests must surface immediately.
RETRYABLE_STATUSES = {408, 429, 500, 502, 503, 504}
RETRY_DELAYS = (0.75, 1.5)


class ProviderError(Exception):
    def __init__(self, status_code, body="", message="The model provider rejected the request."):
        self.status_code = int(status_code or 0)
        self.body = body
        self.message = message
        super().__init__(message)


class RetiredModelError(ProviderError):
    """A retired id, not a transport failure: the ladder may still fall back."""

    def __init__(self, model):
        self.model = str(model)
        super().__init__(404, "", f"The configured DeepSeek model {model!r} was retired "
                                  "on 2026-07-24; use deepseek-flash or deepseek-v4-pro.")


def is_retryable(error) -> bool:
    """One fallback policy for chat, Operator, memory and self-modification."""
    if isinstance(error, ProviderError):
        return error.status_code in (0, 404, 408, 429) or error.status_code >= 500
    if isinstance(error, (anthropic.AuthenticationError, anthropic.PermissionDeniedError)):
        return False
    if isinstance(error, anthropic.BadRequestError):
        body = error.body if isinstance(error.body, dict) else {}
        details = body.get("error", body)
        message = details.get("message", "") if isinstance(details, dict) else ""
        return isinstance(message, str) and any(token in message.casefold() for token in (
            "not a valid model", "model not found", "no endpoints found", "model is not available"))
    status = getattr(error, "status_code", None)
    if status in (401, 402, 403):
        return False
    return isinstance(error, (anthropic.RateLimitError, anthropic.APIConnectionError,
                              anthropic.NotFoundError, anthropic.InternalServerError, TimeoutError)) or (
        isinstance(error, anthropic.APIStatusError) and isinstance(status, int) and status >= 500)


def load_deepseek_key() -> str:
    key = os.environ.get("DEEPSEEK_API_KEY", "").strip()
    if key:
        return key
    # HERMES_HOME unset must NOT fall back to Path("") == cwd: that used to
    # read a random ./.env relative to whatever directory we started in.
    candidates = [Path.home() / ".hermes/.env"]
    hermes_home = os.environ.get("HERMES_HOME", "").strip()
    if hermes_home:
        candidates.append(Path(hermes_home).expanduser() / ".env")
    for candidate in candidates:
        try:
            for line in candidate.read_text(encoding="utf-8", errors="replace").splitlines():
                if line.startswith("DEEPSEEK_API_KEY="):
                    value = line.split("=", 1)[1].strip().strip('"').strip("'")
                    if value:
                        return value
        except OSError:
            continue
    return ""


_SURROGATE = re.compile(r"[\ud800-\udfff]")
_TOOL_NAME = re.compile(r"[^A-Za-z0-9_-]+")


def _clean_text(value) -> str:
    """Replace lone surrogates that would make the provider JSON encoder fail."""
    text = str(value if value is not None else "")
    return _SURROGATE.sub("�", text)


def _tool_name(value) -> str:
    # OpenAI and Anthropic both bound function names; a replayed invalid name
    # otherwise makes every later request fail. The transformation is stable so
    # a tool definition and its call still agree.
    name = _TOOL_NAME.sub("_", _clean_text(value)).strip("_")[:64]
    return name or "invalid_tool_call"


def _retry_after_seconds(response, fallback: float) -> float:
    """Honor a provider's Retry-After (seconds) within a bounded quiet delay."""
    try:
        headers = getattr(response, "headers", None) or {}
        raw = headers.get("retry-after") or headers.get("Retry-After")
    except Exception:
        raw = None
    try:
        value = float(str(raw).strip())
    except (TypeError, ValueError):
        return max(0.0, min(60.0, float(fallback)))
    return max(0.0, min(60.0, value))


def _tool_result_text(content) -> str:
    if isinstance(content, str):
        return _clean_text(content)
    if isinstance(content, list):
        parts = []
        for block in content:
            if isinstance(block, dict) and block.get("type") == "text":
                parts.append(_clean_text(block.get("text") or ""))
            elif isinstance(block, str):
                parts.append(_clean_text(block))
        return _clean_text("\n".join(parts))
    return _clean_text(json.dumps(content, ensure_ascii=False, default=str))


def _to_openai_messages(messages) -> list[dict]:
    converted = []
    for message in messages or []:
        if not isinstance(message, dict):
            continue
        role = message.get("role", "user")
        content = message.get("content")
        if isinstance(content, str):
            converted.append({"role": role, "content": _clean_text(content)})
            continue
        if not isinstance(content, list):
            converted.append({"role": role, "content": ""})
            continue
        text_parts, image_parts, tool_calls, tool_results = [], [], [], []
        for block in content:
            if not isinstance(block, dict):
                continue
            kind = block.get("type")
            if kind == "text":
                text = _clean_text(block.get("text") or "")
                text_parts.append(text)
                image_parts.append({"type": "text", "text": text})
            elif kind == "image" and role == "user":
                source = block.get("source") or {}
                media = source.get("media_type") if isinstance(source, dict) else None
                data = source.get("data") if isinstance(source, dict) else None
                if (not isinstance(source, dict) or source.get("type") != "base64" or media not in
                        ("image/png", "image/jpeg", "image/webp", "image/gif")
                        or not isinstance(data, str) or not re.fullmatch(r"[A-Za-z0-9+/]*={0,2}", data)):
                    raise ValueError("Unsupported image content")
                image_parts.append({"type": "image_url", "image_url": {
                    "url": f"data:{media};base64,{data}"}})
            elif kind == "tool_use":
                tool_calls.append({
                    "id": str(block.get("id") or ""),
                    "type": "function",
                    "function": {
                        "name": _tool_name(block.get("name")),
                        "arguments": _clean_text(json.dumps(
                            block.get("input") or {}, ensure_ascii=False)),
                    },
                })
            elif kind == "tool_result":
                tool_results.append({
                    "role": "tool",
                    "tool_call_id": str(block.get("tool_use_id") or ""),
                    "content": _tool_result_text(block.get("content")),
                })
        if role == "user" and any(part.get("type") == "image_url" for part in image_parts):
            if tool_calls or tool_results:
                raise ValueError("Images cannot be mixed with tool messages")
            converted.append({"role": role, "content": image_parts})
        elif role == "assistant" and tool_calls:
            converted.append({"role": role, "content": "\n".join(text_parts) or None,
                              "tool_calls": tool_calls})
        elif text_parts:
            converted.append({"role": role, "content": "\n".join(text_parts)})
        elif not tool_results:
            converted.append({"role": role, "content": ""})
        converted.extend(tool_results)
    return converted


def _to_openai_tools(tools):
    if not tools:
        return None
    result = []
    for tool in tools:
        if not isinstance(tool, dict) or not tool.get("name"):
            continue
        result.append({
            "type": "function",
            "function": {
                "name": _tool_name(tool["name"]),
                "description": str(tool.get("description") or ""),
                "parameters": tool.get("input_schema") or {"type": "object", "properties": {}},
            },
        })
    return result or None


_ORIG_HTTPX_POST = httpx2.post
_ORIG_HTTPX_STREAM = httpx2.stream


class DeepSeekMessages:
    def __init__(self, api_key: str, timeout: float = 90.0):
        self.api_key = api_key
        self.timeout = timeout
        self._http = None
        # The streaming lane cannot return usage in its text-delta contract.
        # Keep the last real usage parcel here so callers that care about the
        # context budget can read it without changing every stream consumer.
        self.last_usage = {}
        self.last_finish_reason = ""

    def _client(self):
        if self._http is None:
            self._http = httpx2.Client(timeout=self.timeout)
        return self._http

    def close(self):
        client, self._http = self._http, None
        if client is not None:
            try:
                client.close()
            except Exception:
                pass

    def _stream_chat(self, payload, request_timeout, timeout=None):
        """One streaming request; yields {'type':'text_delta','text':...} events.

        Like the batch lane, connection failures get the same quiet retries —
        but only while nothing has left the request: once the model has started
        streaming into the caller, a retry would duplicate or swap the answer.
        """
        headers = {"Authorization": "Bearer " + self.api_key,
                   "Content-Type": "application/json",
                   "Accept": "text/event-stream"}
        deadline = time.monotonic() + request_timeout
        attempt = 0
        while True:
            retry_after = RETRY_DELAYS[attempt] if attempt < len(RETRY_DELAYS) else None
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ProviderError(0, "", "DeepSeek did not answer within the request budget.")
            context = None
            try:
                stream_fn = (httpx2.stream if httpx2.stream is not _ORIG_HTTPX_STREAM
                             else self._client().stream)
                context = stream_fn(
                    "POST", DEEPSEEK_URL, headers=headers, json=payload,
                    timeout=min(request_timeout, remaining))
                # The request is sent on __enter__; it used to run inside the
                # returned generator, outside this retry loop, so a 429 or a
                # transport error skipped every retry and leaked raw httpx
                # exceptions instead of a ProviderError.
                response = context.__enter__()
            except Exception as error:
                if context is not None:
                    try:
                        context.__exit__(type(error), error, error.__traceback__)
                    except Exception:
                        pass
                if retry_after is None or time.monotonic() + retry_after >= deadline:
                    raise ProviderError(0, "", f"Could not reach DeepSeek: {type(error).__name__}.") from None
                time.sleep(retry_after)
                attempt += 1
                continue
            if response.status_code >= 400:
                try:
                    response.read()
                except Exception:
                    pass
                body = ""
                try:
                    body = response.text[:2000]
                except Exception:
                    pass
                message = "The configured DeepSeek model rejected the request."
                try:
                    detail = response.json().get("error", {})
                    message = str(detail.get("message") or message)
                except Exception:
                    pass
                try:
                    context.__exit__(None, None, None)
                except Exception:
                    pass
                delay = _retry_after_seconds(response, retry_after) if retry_after is not None else 0.0
                if (response.status_code in RETRYABLE_STATUSES and retry_after is not None
                        and time.monotonic() + delay < deadline):
                    time.sleep(delay)
                    attempt += 1
                    continue
                raise ProviderError(response.status_code, body, message) from None
            break

        def _events():
            finished = False
            try:
                called_model = str(payload.get("model") or "")
                for line in response.iter_lines():
                    if not line:
                        continue
                    text = line[5:] if line.startswith("data:") else line
                    text = text.strip()
                    if not text or text == "[DONE]":
                        continue
                    try:
                        data = json.loads(text)
                    except ValueError:
                        continue
                    usage = data.get("usage")
                    if usage is not None:  # an empty usage parcel still reports the model
                        self.last_usage = usage if isinstance(usage, dict) else {}
                        usage_meter.record(usage, str(data.get("model") or called_model))
                    choices = data.get("choices")
                    if not isinstance(choices, list) or not choices:
                        continue
                    choice = choices[0] if isinstance(choices[0], dict) else {}
                    delta = choice.get("delta") if isinstance(choice.get("delta"), dict) else {}
                    piece = delta.get("content")
                    if isinstance(piece, str) and piece and not finished:
                        yield {"type": "text_delta", "text": piece}
                    if choice.get("finish_reason"):
                        self.last_finish_reason = str(choice.get("finish_reason") or "")
                        # Keep reading: DeepSeek sends the usage parcel in a
                        # separate final chunk after finish_reason.
                        finished = True
            except ProviderError:
                raise
            except Exception as error:
                raise ProviderError(
                    0, "", f"DeepSeek stream failed: {type(error).__name__}.") from None
            finally:
                try:
                    context.__exit__(None, None, None)
                except Exception:
                    pass
        return _events()

    def create(self, *, model=DEFAULT_MODEL, max_tokens=3000, system=None, messages=None,
               tools=None, thinking=None, output_config=None, stream=False,
               timeout=None, **kwargs):
        del thinking, output_config, kwargs
        if str(model) in RETIRED_MODELS:
            raise RetiredModelError(model)
        self.last_usage = {}
        self.last_finish_reason = ""
        request_timeout = min(float(self.timeout), 90.0)
        if timeout is not None:
            try:
                request_timeout = max(1.0, min(request_timeout, float(timeout)))
            except (TypeError, ValueError):
                pass
        payload = {
            "model": model,
            "max_tokens": max(1, min(int(max_tokens or 3000), 8192)),
            "messages": _to_openai_messages(messages),
            "stream": bool(stream),
            # DeepSeek enables thinking by default, and its tool loop then
            # requires every assistant turn to echo reasoning_content. This
            # adapter's Anthropic-shaped blocks deliberately never surface
            # reasoning, so request the non-thinking mode explicitly.
            "thinking": {"type": "disabled"},
        }
        # Both lanes get the same prompt and tool declarations. The streaming
        # early return used to drop `system` (persona, grounding rules, memory,
        # Operator context, reply-language) before it was inserted.
        if system:
            payload["messages"].insert(0, {"role": "system", "content": _clean_text(system)})
        converted_tools = _to_openai_tools(tools)
        if converted_tools:
            payload["tools"] = converted_tools
        if stream:
            # The reply-first face of the chat lane streams OpenAI-chat SSE so
            # the browser sees text while the model is still writing. DeepSeek
            # only meters token usage in streams when asked explicitly.
            payload["stream_options"] = {"include_usage": True}
            return self._stream_chat(payload, request_timeout, timeout)
        attempt = 0
        deadline = time.monotonic() + request_timeout
        while True:
            retry_after = RETRY_DELAYS[attempt] if attempt < len(RETRY_DELAYS) else None
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ProviderError(0, "", "DeepSeek did not answer within the request budget.")
            try:
                post_fn = (httpx2.post if httpx2.post is not _ORIG_HTTPX_POST
                           else self._client().post)
                response = post_fn(
                    DEEPSEEK_URL,
                    headers={"Authorization": "Bearer " + self.api_key, "Content-Type": "application/json"},
                    json=payload,
                    timeout=min(request_timeout, remaining),
                )
            except Exception as error:
                if retry_after is None or time.monotonic() + retry_after >= deadline:
                    raise ProviderError(0, "", f"Could not reach DeepSeek: {type(error).__name__}.") from None
                time.sleep(retry_after)
                attempt += 1
                continue
            delay = _retry_after_seconds(response, retry_after) if retry_after is not None else 0.0
            if (response.status_code in RETRYABLE_STATUSES and retry_after is not None
                    and time.monotonic() + delay < deadline):
                time.sleep(delay)
                attempt += 1
                continue
            break
        if response.status_code >= 400:
            body = response.text[:2000]
            message = "The configured DeepSeek model rejected the request."
            try:
                detail = response.json().get("error", {})
                message = str(detail.get("message") or message)
            except Exception:
                pass
            raise ProviderError(response.status_code, body, message)
        try:
            data = response.json()
        except Exception:
            raise ProviderError(502, "", "DeepSeek returned an invalid response.") from None
        choices = data.get("choices") if isinstance(data, dict) else None
        if not isinstance(choices, list) or not choices:
            raise ProviderError(502, "", "DeepSeek returned no choices.")
        choice = choices[0] or {}
        message = choice.get("message") if isinstance(choice, dict) else None
        if not isinstance(message, dict):
            raise ProviderError(502, "", "DeepSeek returned no assistant message.")
        blocks = []
        text = message.get("content")
        if isinstance(text, str) and text.strip():
            blocks.append(SimpleNamespace(type="text", text=text))
        for call in message.get("tool_calls") or []:
            function = call.get("function") if isinstance(call, dict) else None
            if not isinstance(function, dict):
                continue
            try:
                arguments = json.loads(function.get("arguments") or "{}")
            except (TypeError, ValueError):
                arguments = {}
            blocks.append(SimpleNamespace(type="tool_use", id=str(call.get("id") or ""),
                                          name=str(function.get("name") or ""), input=arguments))
        if not blocks:
            blocks.append(SimpleNamespace(type="text", text=""))
        usage = data.get("usage") or {}
        if isinstance(usage, dict):
            self.last_usage = usage
        finish_reason = str(choice.get("finish_reason") or "") if isinstance(choice, dict) else ""
        self.last_finish_reason = finish_reason
        usage_meter.record(usage, str(data.get("model") or model))
        return SimpleNamespace(content=blocks, model=data.get("model") or model,
                               usage=usage, finish_reason=finish_reason)


class DeepSeekClient:
    def __init__(self, api_key: str, timeout: float = 90.0):
        self.messages = DeepSeekMessages(api_key, timeout)

    def close(self):
        self.messages.close()
        return None


def make_client(provider: str, key: str, timeout: float = 90.0):
    if provider == "deepseek":
        return DeepSeekClient(key, timeout)
    from anthropic import Anthropic
    return Anthropic(api_key=None, auth_token=key, base_url="https://openrouter.ai/api",
                     timeout=timeout, max_retries=0)
