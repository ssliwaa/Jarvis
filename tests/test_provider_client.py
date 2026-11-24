"""Provider adapter contracts; no network and no API key."""
import json
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import provider_client


class ProviderClientTests(unittest.TestCase):
    def test_anthropic_messages_are_converted_to_openai_tools(self):
        messages = [
            {"role": "assistant", "content": [
                {"type": "text", "text": "Opening."},
                {"type": "tool_use", "id": "call-1", "name": "open_url", "input": {"url": "https://example.test"}},
            ]},
            {"role": "user", "content": [
                {"type": "tool_result", "tool_use_id": "call-1", "content": "ok"},
            ]},
        ]
        converted = provider_client._to_openai_messages(messages)
        self.assertEqual(converted[0]["role"], "assistant")
        self.assertEqual(converted[0]["tool_calls"][0]["function"]["name"], "open_url")
        self.assertEqual(json.loads(converted[0]["tool_calls"][0]["function"]["arguments"]), {"url": "https://example.test"})
        self.assertEqual(converted[1], {"role": "tool", "tool_call_id": "call-1", "content": "ok"})

    def test_user_image_is_converted_without_losing_text(self):
        blocks = [{'type': 'text', 'text': 'Co widać?'},
                  {'type': 'image', 'source': {'type': 'base64', 'media_type': 'image/png', 'data': 'YWJj'}}]
        result = provider_client._to_openai_messages([{'role': 'user', 'content': blocks}])
        self.assertEqual(result[0]['content'], [
            {'type': 'text', 'text': 'Co widać?'},
            {'type': 'image_url', 'image_url': {'url': 'data:image/png;base64,YWJj'}}])

    def test_tool_schema_is_converted_without_losing_required_fields(self):
        tools = provider_client._to_openai_tools([{
            "name": "terminal", "description": "Run a command",
            "input_schema": {"type": "object", "properties": {"command": {"type": "string"}}, "required": ["command"]},
        }])
        self.assertEqual(tools[0]["type"], "function")
        self.assertEqual(tools[0]["function"]["parameters"]["required"], ["command"])

    @patch("provider_client.httpx2.post")
    def test_response_text_and_tool_calls_become_anthropic_blocks(self, post):
        post.return_value = SimpleNamespace(status_code=200, text="", json=lambda: {
            "model": "deepseek-flash",
            "choices": [{"message": {"content": "Let me check.",
                                     "tool_calls": [{"id": "call-2", "function": {
                                         "name": "read_file", "arguments": '{"path": "note.md"}'}}]}}],
        })
        messages = provider_client.DeepSeekMessages("sk-test").create(
            model="deepseek-flash", max_tokens=100, system="system",
            messages=[{"role": "user", "content": "read it"}],
            tools=[{"name": "read_file", "description": "Read", "input_schema": {"type": "object"}}])
        self.assertEqual([block.type for block in messages.content], ["text", "tool_use"])
        self.assertEqual(messages.content[1].input, {"path": "note.md"})
        payload = post.call_args.kwargs["json"]
        self.assertEqual(payload["messages"][0], {"role": "system", "content": "system"})
        self.assertEqual(payload["tools"][0]["function"]["name"], "read_file")
        self.assertEqual(payload["thinking"], {"type": "disabled"})

    def test_message_text_and_tool_names_are_sanitized(self):
        messages = [
            {"role": "assistant", "content": [
                {"type": "text", "text": "broken \ud800 text"},
                {"type": "tool_use", "id": "call-1", "name": "bad name!",
                 "input": {"path": "note \ud800.md"}},
            ]},
        ]
        converted = provider_client._to_openai_messages(messages)
        self.assertNotIn("\ud800", json.dumps(converted, ensure_ascii=False))
        self.assertEqual(converted[0]["tool_calls"][0]["function"]["name"], "bad_name")
        self.assertIn('"path"', converted[0]["tool_calls"][0]["function"]["arguments"])

    @patch("provider_client.httpx2.post")
    def test_a_retired_model_id_fails_clearly_before_the_network(self, post):
        with self.assertRaises(provider_client.RetiredModelError) as caught:
            provider_client.DeepSeekMessages("sk-test").create(
                model="deepseek-chat", messages=[{"role": "user", "content": "hi"}])
        self.assertIn("retired", caught.exception.message)
        self.assertEqual(caught.exception.status_code, 404)  # fallback-friendly


class _FakeStreamResponse:
    def __init__(self, status, lines):
        self.status_code = status
        self._lines = lines

    def read(self):
        return ""

    @property
    def text(self):
        return ""

    def json(self):
        return {}

    def iter_lines(self):
        return iter(self._lines)


class _FakeStreamContext:
    def __init__(self, response):
        self._response = response

    def __enter__(self):
        return self._response

    def __exit__(self, *args):
        return False


class StreamingTests(unittest.TestCase):
    def test_streaming_keeps_the_system_prompt_and_tools(self):
        lines = ["data: [DONE]"]
        with patch("provider_client.httpx2.stream", return_value=_FakeStreamContext(
                _FakeStreamResponse(200, lines))) as stream:
            list(provider_client.DeepSeekMessages("sk-test").create(
                model="deepseek-flash", system="SYSTEM-MARKER",
                messages=[{"role": "user", "content": "hi"}],
                tools=[{"name": "read_file", "description": "Read",
                        "input_schema": {"type": "object", "properties": {}}}],
                stream=True))
        payload = stream.call_args.kwargs["json"]
        self.assertEqual(payload["messages"][0], {"role": "system", "content": "SYSTEM-MARKER"})
        self.assertEqual(payload["tools"][0]["function"]["name"], "read_file")

    def test_streaming_yields_only_visible_text_deltas(self):
        lines = [
            'data: {"choices":[{"delta":{"content":"Hello"}}]}',
            'data: {"choices":[{"delta":{"content":" there"}}]}',
            "data: [DONE]",
        ]
        with patch("provider_client.httpx2.stream", return_value=_FakeStreamContext(
                _FakeStreamResponse(200, lines))):
            events = list(provider_client.DeepSeekMessages("sk-test").create(
                model="deepseek-flash", messages=[{"role": "user", "content": "hi"}],
                stream=True))
        self.assertEqual([event["text"] for event in events], ["Hello", " there"])

    def test_streaming_surfaces_http_errors_and_usage(self):
        class Capture:
            def __init__(self):
                self.rows = []
            def record(self, usage, model):
                self.rows.append((usage, model))
        capture = Capture()
        lines = ['data: {"model":"deepseek-flash","usage":{},"choices":[{"delta":{"content":"a"}}]}',
                 'data: {"choices":[{"delta":{},"finish_reason":"stop"}]}']
        with patch("provider_client.httpx2.stream", return_value=_FakeStreamContext(
                _FakeStreamResponse(200, lines))), \
             patch("provider_client.usage_meter", capture):
            events = list(provider_client.DeepSeekMessages("sk-test").create(
                messages=[{"role": "user", "content": "hi"}], stream=True))
        self.assertEqual([event["text"] for event in events], ["a"])
        self.assertEqual(len(capture.rows), 1)

        with patch("provider_client.httpx2.stream", return_value=_FakeStreamContext(
                _FakeStreamResponse(402, []))), self.assertRaises(
                provider_client.ProviderError) as caught:
            list(provider_client.DeepSeekMessages("sk-test").create(
                messages=[{"role": "user", "content": "hi"}], stream=True))
        self.assertEqual(caught.exception.status_code, 402)

    @patch("provider_client.time.sleep")
    def test_a_stream_429_is_retried_before_any_text_is_emitted(self, sleep):
        first = _FakeStreamContext(_FakeStreamResponse(429, []))
        second = _FakeStreamContext(_FakeStreamResponse(200, [
            'data: {"choices":[{"delta":{"content":"back"}}]}',
            "data: [DONE]",
        ]))
        with patch("provider_client.httpx2.stream", side_effect=[first, second]) as stream:
            events = list(provider_client.DeepSeekMessages("sk-test").create(
                messages=[{"role": "user", "content": "hi"}], stream=True))
        self.assertEqual([event["text"] for event in events], ["back"])
        self.assertEqual(stream.call_count, 2)
        sleep.assert_called_once()

    @patch("provider_client.time.sleep")
    def test_an_enter_transport_error_is_retried(self, sleep):
        class BrokenContext:
            def __enter__(self):
                raise OSError("connection reset")

            def __exit__(self, *args):
                return False

        good = _FakeStreamContext(_FakeStreamResponse(200, [
            'data: {"choices":[{"delta":{"content":"ok"}}]}', "data: [DONE]"]))
        with patch("provider_client.httpx2.stream", side_effect=[BrokenContext(), good]):
            events = list(provider_client.DeepSeekMessages("sk-test").create(
                messages=[{"role": "user", "content": "hi"}], stream=True))
        self.assertEqual([event["text"] for event in events], ["ok"])
        sleep.assert_called_once()

    def test_stream_usage_after_finish_reason_is_not_lost(self):
        class Capture:
            def __init__(self):
                self.rows = []

            def record(self, usage, model):
                self.rows.append((usage, model))

        capture = Capture()
        lines = [
            'data: {"choices":[{"delta":{"content":"a"},"finish_reason":"stop"}]}',
            'data: {"model":"deepseek-flash","usage":{"prompt_tokens":4,"completion_tokens":2},'
            '"choices":[]}',
        ]
        with patch("provider_client.httpx2.stream", return_value=_FakeStreamContext(
                _FakeStreamResponse(200, lines))), \
             patch("provider_client.usage_meter", capture):
            events = list(provider_client.DeepSeekMessages("sk-test").create(
                messages=[{"role": "user", "content": "hi"}], stream=True))
        self.assertEqual([event["text"] for event in events], ["a"])
        self.assertEqual(capture.rows[-1][0]["prompt_tokens"], 4)
        self.assertEqual(capture.rows[-1][0]["completion_tokens"], 2)

    @patch("provider_client.httpx2.post")
    def test_the_default_model_is_current_and_thinking_is_off(self, post):
        self.assertEqual(provider_client.DEFAULT_MODEL, "deepseek-flash")
        post.return_value = SimpleNamespace(status_code=200, text="", json=lambda: {
            "choices": [{"message": {"content": "ok"}}]})
        provider_client.DeepSeekMessages("sk-test").create(
            messages=[{"role": "user", "content": "hi"}])
        payload = post.call_args.kwargs["json"]
        self.assertEqual(payload["model"], "deepseek-flash")
        self.assertEqual(payload["thinking"], {"type": "disabled"})


class RetryTests(unittest.TestCase):
    """One quiet retry for transient provider hiccups; billing errors surface fast."""

    def _post_with(self, script):
        """script: list of either responses or exception instances, consumed per call."""
        calls = []

        def fake_post(*args, **kwargs):
            calls.append(kwargs.get("json"))
            if calls.__len__() > len(script):
                raise AssertionError(
                    f"expected {len(script)} HTTP calls, got {calls.__len__()}")
            step = script[len(calls) - 1]
            if isinstance(step, Exception):
                raise step
            return step

        fake_post.calls = calls
        fake_post.script = script[:]
        return fake_post

    def assertCalls(self, post, expected):
        self.assertEqual(len(post.calls), expected)

    @patch("provider_client.time.sleep")
    def test_transient_503_is_retried_once(self, sleep):
        script = [
            SimpleNamespace(status_code=503, text="overloaded"),
            SimpleNamespace(status_code=200, text="", json=lambda: {
                "model": "deepseek-flash",
                "choices": [{"message": {"content": "back."}}],
                "usage": {},
            }),
        ]
        post = self._post_with(script)
        with patch("provider_client.httpx2.post", new=post):
            out = provider_client.DeepSeekMessages("sk-test").create(
                messages=[{"role": "user", "content": "hi"}])
        self.assertCalls(post, 2)
        self.assertEqual(out.content[0].text, "back.")
        sleep.assert_called_once()

    @patch("provider_client.time.sleep")
    def test_retry_gives_up_after_two_delays(self, sleep):
        post = self._post_with([SimpleNamespace(status_code=503, text="down"),
                                SimpleNamespace(status_code=503, text="down"),
                                SimpleNamespace(status_code=503, text="down")])
        with patch("provider_client.httpx2.post", new=post):
            with self.assertRaises(provider_client.ProviderError) as caught:
                provider_client.DeepSeekMessages("sk-test").create(
                    messages=[{"role": "user", "content": "hi"}])
        self.assertCalls(post, 3)
        self.assertEqual(caught.exception.status_code, 503)

    @patch("provider_client.time.sleep")
    def test_billing_error_is_never_retried(self, sleep):
        post = self._post_with([SimpleNamespace(
            status_code=402, text="insufficient balance",
            json=lambda: {"error": {"message": "Insufficient Balance."}})])
        with patch("provider_client.httpx2.post", new=post):
            with self.assertRaises(provider_client.ProviderError) as caught:
                provider_client.DeepSeekMessages("sk-test").create(
                    messages=[{"role": "user", "content": "hi"}])
        self.assertCalls(post, 1)
        self.assertEqual(caught.exception.status_code, 402)
        sleep.assert_not_called()

    @patch("provider_client.time.sleep")
    def test_transport_failure_is_retried_then_raised(self, sleep):
        post = self._post_with([OSError("no route"), OSError("no route"),
                                OSError("no route")])
        with patch("provider_client.httpx2.post", new=post):
            with self.assertRaises(provider_client.ProviderError):
                provider_client.DeepSeekMessages("sk-test").create(
                    messages=[{"role": "user", "content": "hi"}])
        self.assertCalls(post, 3)


if __name__ == "__main__":
    unittest.main()
