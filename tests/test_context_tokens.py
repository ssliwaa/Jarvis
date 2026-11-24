"""Automated test suite for context_tokens.py (rough token estimator).

Tests the ASCII 4-chars-per-token ceiling, CJK/Hangul/Kana dense-codepoint
billing, mixed-script text, non-string inputs and unpaired surrogates
(never raises), Anthropic/OpenAI content-block shapes (text, tool_use,
tool_result, flat image charge immune to huge base64 payloads, unknown
blocks), chat-message accounting (role fee, tool_calls, tool_call_id,
non-dict floor), message-list/None zero-cost semantics, tool-declaration
overhead, aggregate request estimation, and the ceil_tokens/alias
helpers. Pure in-memory computation, no I/O, no network.
"""

from __future__ import annotations

import unittest

import context_tokens as ct


class TestEstimateTokensRough(unittest.TestCase):
    """Core estimator: ASCII ceiling, CJK dense, mixed, safety."""

    def test_ascii_ceiling(self):
        self.assertEqual(ct.estimate_tokens_rough("abcd"), 1)
        self.assertEqual(ct.estimate_tokens_rough("abcde"), 2)
        self.assertEqual(ct.estimate_tokens_rough(""), 0)
        self.assertEqual(ct.estimate_tokens_rough(None), 0)

    def test_cjk_dense_billed_per_codepoint(self):
        dense = chr(0x4F60) * 5          # CJK ideograph range
        self.assertEqual(ct.estimate_tokens_rough(dense), 5)

    def test_mixed_script_sums_both(self):
        # 2 ASCII chars ceil to 1 token + 1 dense codepoint = 2
        mixed = "ab" + chr(0x4F60)
        self.assertEqual(ct.estimate_tokens_rough(mixed), 2)

    def test_non_string_inputs_never_raise(self):
        self.assertEqual(ct.estimate_tokens_rough(12345), 2)
        self.assertGreaterEqual(ct.estimate_tokens_rough([1, 2, 3]), 1)
        # Unpaired surrogate must not blow up str()/encode()
        bad = "x" + chr(0xD800) + "y"
        self.assertIsInstance(ct.estimate_tokens_rough(bad), int)

    def test_alias_estimate_tokens(self):
        self.assertEqual(ct.estimate_tokens("abcd"), 1)
        self.assertEqual(ct.estimate_tokens(None), 0)


class TestEstimateContentTokens(unittest.TestCase):
    """Content-block shapes: text, tool_use, tool_result, images."""

    def test_string_and_dict(self):
        self.assertEqual(ct.estimate_content_tokens("abcd"), 1)
        self.assertEqual(ct.estimate_content_tokens(None), 0)
        self.assertGreaterEqual(ct.estimate_content_tokens({"a": 1}), 1)

    def test_text_blocks(self):
        blocks = ["plain", {"type": "text", "text": "abcd"}]
        # "plain" (5 ASCII chars) -> 2, text block "abcd" -> 1.
        self.assertEqual(ct.estimate_content_tokens(blocks), 3)

    def test_tool_use_block(self):
        block = {"type": "tool_use", "name": "read_file",
                 "input": {"path": "/tmp/x"}}
        estimate = ct.estimate_content_tokens([block])
        self.assertGreaterEqual(estimate, 2)

    def test_tool_result_recursive_content(self):
        block = {"type": "tool_result", "tool_use_id": "abc",
                 "content": "done output"}
        # tool_use_id "abc" -> 1, "done output" (11 chars) -> 3
        self.assertEqual(ct.estimate_content_tokens([block]), 4)

    def test_image_flat_charge_ignores_huge_payload(self):
        giant = [{"type": "image",
                  "source": {"data": "x" * 4_000_000}}]
        self.assertEqual(ct.estimate_content_tokens(giant), 1600)
        giant2 = [{"type": "input_image",
                   "image_url": {"url": "y" * 10}}]
        self.assertEqual(ct.estimate_content_tokens(giant2), 1600)

    def test_unknown_block_falls_back_to_json(self):
        block = {"type": "mystery", "payload": {"deep": [1, 2]}}
        self.assertGreaterEqual(ct.estimate_content_tokens([block]), 1)


class TestMessageEstimation(unittest.TestCase):
    """Chat message accounting: role fee, tool metadata, floors."""

    def test_role_fee_and_content(self):
        msg = {"role": "user", "content": "abcd"}
        self.assertEqual(ct.estimate_message_tokens(msg), 5)

    def test_non_dict_message_costs_one(self):
        self.assertEqual(ct.estimate_message_tokens("junk"), 1)

    def test_tool_calls_and_id_accounted(self):
        msg = {
            "role": "assistant",
            "tool_calls": [{"function": {
                "name": "fn",
                "arguments": '{"a": 1}'}}],
            "tool_call_id": "tid",
        }
        # 4 role + fn 1 + arguments 2 + tid 1
        self.assertEqual(ct.estimate_message_tokens(msg), 8)

    def test_name_field_counted(self):
        msg = {"role": "assistant", "name": "abcd", "content": None}
        self.assertEqual(ct.estimate_message_tokens(msg), 5)

    def test_message_lists_and_empty(self):
        self.assertEqual(ct.estimate_messages_tokens([]), 0)
        self.assertEqual(ct.estimate_messages_tokens(None), 0)
        two = [{"role": "user", "content": "abcd"}] * 2
        self.assertEqual(ct.estimate_messages_tokens(two), 10)

    def test_tools_overhead(self):
        self.assertEqual(ct.estimate_tools_tokens(None), 0)
        self.assertEqual(ct.estimate_tools_tokens([]), 0)
        self.assertEqual(ct.estimate_tools_tokens([{"a": 1}]),
                         ct.estimate_tokens_rough('{"a": 1}') + 4)

    def test_request_sum_and_floor(self):
        msgs = [{"role": "user", "content": "hi"}]
        total = ct.estimate_request_tokens(msgs, system="sys",
                                           tools=[{"t": 1}])
        parts = (ct.estimate_messages_tokens(msgs)
                 + ct.estimate_tokens_rough("sys")
                 + ct.estimate_tools_tokens([{"t": 1}]))
        self.assertEqual(total, parts)
        self.assertGreater(total, 0)

    def test_ceil_tokens(self):
        self.assertEqual(ct.ceil_tokens(3.2), 4)
        self.assertEqual(ct.ceil_tokens(-1), 0)
        self.assertEqual(ct.ceil_tokens(0), 0)
        self.assertEqual(ct.ceil_tokens(None), 0)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
