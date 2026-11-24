"""Context compressor contracts: pruning, boundaries, handoff and persistence."""
from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

import context_compressor as cc
import context_state
import context_tokens
import session_store


def result(text, call_id, name="terminal", args=None):
    del name, args
    return {"role": "user", "content": [{"type": "tool_result", "tool_use_id": call_id,
                                         "content": text}]}


def call(call_id, name="terminal", args=None):
    return {"role": "assistant", "content": [{"type": "tool_use", "id": call_id,
                                              "name": name, "input": args or {"command": "echo hi"}}]}


def long_task(rounds=12, result_chars=3000, arg_chars=4000):
    messages = [{"role": "user", "content": "TASK: inspect the disk and report."}]
    for index in range(rounds):
        # Tool-call arguments are never rewritten by pruning, so realistic
        # write/patch calls keep a large middle available for summarising.
        messages.append(call(f"c{index}", args={"command": f"echo {index} " + ("a" * arg_chars)}))
        messages.append(result("R" + str(index) + ":" + ("x" * result_chars), f"c{index}"))
    messages.append({"role": "assistant", "content": [{"type": "text", "text": "Done."}]})
    return messages


class Summary:
    def __init__(self, text="## Goal\nA faithful summary.\n## Critical Context\nkeep the file", finish=""):
        self.text = text
        self.finish = finish
        self.calls = []

    def __call__(self, prompt, model, max_tokens):
        self.calls.append({"prompt": prompt, "model": model, "max_tokens": max_tokens})
        return cc.SummaryResult(self.text, self.finish)


class CompressorTests(unittest.TestCase):
    def make(self, summary=None, **kwargs):
        summary = summary or Summary()
        options = dict(
            model="deepseek-flash",
            context_length=20_000,
            threshold_percent=0.50,
            protect_first_n=1,
            protect_last_n=2,
            summary_caller=summary,
            state_store=context_state.NullStateStore(),
            state_key="test:compressor",
            max_tokens=1000,
            quiet_mode=True,
        )
        options.update(kwargs)
        return cc.ContextCompressor(**options), summary

    def test_estimator_understands_anthropic_blocks_and_tools(self):
        message = {"role": "assistant", "content": [
            {"type": "text", "text": "hello"},
            {"type": "tool_use", "id": "c1", "name": "terminal", "input": {"command": "ls"}},
        ]}
        tokens = context_tokens.estimate_message_tokens(message)
        self.assertGreater(tokens, 4)
        self.assertEqual(context_tokens.estimate_messages_tokens([]), 0)
        self.assertGreater(context_tokens.estimate_request_tokens(
            [message], system="system prompt", tools=[{"name": "terminal", "input_schema": {}}]
        ), tokens)

    def test_pruning_summarises_old_results_without_rewriting_tool_arguments(self):
        compressor, _summary = self.make()
        messages = long_task()
        original_args = json.dumps(messages[1]["content"][0]["input"], sort_keys=True)
        pruned, count = compressor._prune_old_tool_results(messages, protect_tail_count=2)
        self.assertGreater(count, 0)
        self.assertEqual(json.dumps(pruned[1]["content"][0]["input"], sort_keys=True), original_args)
        old = pruned[2]["content"][0]["content"]
        self.assertIn("[terminal]", old)
        self.assertLess(len(old), 3000)
        # The newest pending round stays byte-exact.
        self.assertEqual(pruned[-2]["content"][0]["content"], messages[-2]["content"][0]["content"])

    def test_identical_tool_results_are_back_referenced_and_newest_kept(self):
        compressor, _summary = self.make()
        messages = [
            {"role": "user", "content": "go"},
            call("a"), result("same " * 100, "a"),
            call("b"), result("same " * 100, "b"),
        ]
        pruned, count = compressor._prune_old_tool_results(messages, protect_tail_count=1)
        self.assertGreaterEqual(count, 1)
        self.assertEqual(pruned[2]["content"][0]["content"], cc.DUPLICATE_TOOL_PLACEHOLDER)
        self.assertEqual(pruned[4]["content"][0]["content"], "same " * 100)

    def test_compression_inserts_a_handoff_and_preserves_tool_pairs(self):
        compressor, summary = self.make()
        messages = long_task()
        before = compressor.estimate_messages_tokens(messages)
        self.assertTrue(compressor.should_compress(before))
        compressed = compressor.compress(messages, current_tokens=before + 8_000)
        self.assertIsNot(compressed, messages)
        self.assertLess(len(compressed), len(messages))
        self.assertLess(compressor.estimate_messages_tokens(compressed), before)
        self.assertEqual(compressed[0], messages[0])
        carriers = [message for message in compressed if message.get(cc.COMPRESSED_SUMMARY_KEY)]
        self.assertEqual(len(carriers), 1)
        self.assertIn("A faithful summary", carriers[0]["content"])
        self.assertIn(cc.SUMMARY_END_MARKER, carriers[0]["content"])
        calls = set()
        results = set()
        for message in compressed:
            for block in message.get("content") or []:
                if isinstance(block, dict) and block.get("type") == "tool_use":
                    calls.add(block["id"])
                if isinstance(block, dict) and block.get("type") == "tool_result":
                    results.add(block["tool_use_id"])
        self.assertTrue(calls <= results)
        self.assertEqual(compressor.compression_count, 1)
        self.assertEqual(summary.calls[0]["model"], "deepseek-flash")
        self.assertIn("Historical Task Snapshot", summary.calls[0]["prompt"])
        self.assertIn("Detailed Session Log", summary.calls[0]["prompt"])

    def test_summary_contains_verbatim_users_and_exact_identifiers(self):
        compressor, summary = self.make(Summary(
            "## Goal\nFix `src/server.py` in commit deadbeef1234.\n"
            "## Critical Context\nkeep deadbeef1234 and src/server.py"
        ))
        messages = long_task(rounds=8)
        messages.insert(1, {"role": "user", "content": "Please keep this exact request: use port 4700."})
        messages.insert(2, {"role": "assistant", "content": [
            {"type": "text", "text": "Working on src/server.py at commit deadbeef1234."}
        ]})
        compressed = compressor.compress(messages, current_tokens=30_000)
        carrier = next(message for message in compressed if message.get(cc.COMPRESSED_SUMMARY_KEY))["content"]
        self.assertIn("User Messages (verbatim", carrier)
        self.assertIn("use port 4700", carrier)
        self.assertIn("Anchor Index", carrier)
        self.assertIn("src/server.py", carrier)
        self.assertIn("deadbeef1234", carrier)

    def test_truncated_summary_aborts_and_preserves_every_message(self):
        compressor, _summary = self.make(Summary(finish="length"))
        messages = long_task()
        compressed = compressor.compress(messages, current_tokens=30_000)
        self.assertIs(compressed, messages)
        self.assertTrue(compressor._last_compress_aborted)
        self.assertEqual(compressor.compression_count, 0)
        status = compressor.get_status()["last_telemetry"]
        self.assertEqual(status["commit_status"], "aborted")
        self.assertEqual(status["failure_class"], "summary_generation_aborted")

    def test_generic_summary_failure_uses_deterministic_fallback(self):
        def broken(prompt, model, max_tokens):
            raise RuntimeError("summary backend down")

        compressor, _summary = self.make(Summary())
        compressor.summary_caller = broken
        messages = long_task()
        compressed = compressor.compress(messages, current_tokens=30_000)
        self.assertIsNot(compressed, messages)
        carrier = next(message for message in compressed if message.get(cc.COMPRESSED_SUMMARY_KEY))["content"]
        self.assertIn("deterministic fallback", carrier)
        self.assertIn("Historical Task Snapshot", carrier)
        self.assertIn("TASK: inspect the disk", carrier)
        self.assertTrue(compressor._last_summary_fallback_used)

    def test_second_compaction_updates_the_previous_summary(self):
        summary = Summary("FIRST SUMMARY")
        compressor, _ = self.make(summary)
        messages = long_task()
        first = compressor.compress(messages, current_tokens=30_000)
        self.assertIsNot(first, messages)
        summary.text = "SECOND SUMMARY"
        # Enough fresh material after the first handoff.
        more = list(first) + long_task(rounds=5)
        second = compressor.compress(more, current_tokens=80_000, force=True)
        self.assertIsNot(second, more)
        self.assertEqual(len(summary.calls), 2)
        self.assertIn("PREVIOUS SUMMARY", summary.calls[1]["prompt"])
        self.assertIn("FIRST SUMMARY", summary.calls[1]["prompt"])
        self.assertIn("SECOND SUMMARY", compressor.summary_text())

    def test_inflight_task_is_restated_after_compaction(self):
        compressor, _summary = self.make()
        messages = [{"role": "user", "content": "Install the package and report the version."}]
        for index in range(10):
            messages.append(call(f"i{index}", args={"command": "echo " + ("a" * 3000)}))
            messages.append(result("still working " * 100, f"i{index}"))
        compressed = compressor.compress(messages, current_tokens=30_000)
        joined = json.dumps(compressed, ensure_ascii=False)
        self.assertIn(cc.INFLIGHT_TASK_REPLAY_HEADER, joined)
        self.assertIn("Install the package", joined)

    def test_completed_task_is_not_restated(self):
        compressor, _summary = self.make()
        messages = [{"role": "user", "content": "Install the package and report the version."}]
        for index in range(10):
            messages.append(call(f"d{index}", args={"command": "echo " + ("a" * 3000)}))
            messages.append(result("ok " * 200, f"d{index}"))
        messages.append({"role": "assistant",
                         "content": [{"type": "text", "text": "Version 1.2.3 is installed."}]})
        compressed = compressor.compress(messages, current_tokens=30_000)
        self.assertNotIn(cc.INFLIGHT_TASK_REPLAY_HEADER, json.dumps(compressed, ensure_ascii=False))

    def test_threshold_cooldown_and_anti_thrash(self):
        compressor, _summary = self.make()
        self.assertFalse(compressor.should_compress(0))
        self.assertTrue(compressor.should_compress(compressor.threshold_tokens))
        compressor._summary_failure_cooldown_until = compressor.clock() + 60
        should, reason = compressor.should_compress_info(compressor.threshold_tokens)
        self.assertFalse(should)
        self.assertTrue(reason.startswith("cooldown:"))
        compressor._summary_failure_cooldown_until = 0
        compressor._record_ineffective_compression_verdict(2)
        should, reason = compressor.should_compress_info(compressor.threshold_tokens)
        self.assertFalse(should)
        self.assertEqual(reason, "ineffective")

    def test_make_compressor_accepts_percent_or_fraction_and_scales_prune(self):
        from unittest.mock import patch
        with patch.dict(os.environ, {
            "JARVIS_CONTEXT_WINDOW": "20000",
            "JARVIS_CONTEXT_THRESHOLD_PERCENT": "50",
            "JARVIS_CONTEXT_SUMMARY_RATIO": "0.2",
            "JARVIS_CONTEXT_QUIET": "1",
        }, clear=False):
            compressor = cc.make_compressor("deepseek-flash")
        self.assertAlmostEqual(compressor.threshold_percent, 0.75)
        self.assertEqual(compressor.threshold_tokens, 13650)
        self.assertEqual(compressor.proactive_prune_tokens, 12000)

    def test_update_model_recomputes_threshold(self):
        compressor, _summary = self.make()
        compressor.update_model("small-local", 32_000)
        self.assertEqual(compressor.context_length, 32_000)
        self.assertLess(compressor.threshold_tokens, 32_000)
        self.assertGreaterEqual(compressor.threshold_percent, 0.75)

    def test_state_survives_a_new_instance(self):
        with tempfile.TemporaryDirectory() as directory:
            store = session_store.SessionStore(Path(directory) / "sessions.db")
            try:
                state_store = context_state.SessionStateStore(store)
                summary = Summary("PERSISTED")
                first, _ = self.make(summary, state_store=state_store, state_key="operator:persist")
                first.compress(long_task(), current_tokens=30_000)
                second, _ = self.make(Summary("unused"), state_store=state_store,
                                      state_key="operator:persist")
                self.assertIn("PERSISTED", second.summary_text())
                self.assertEqual(second.compression_count, 1)
                self.assertTrue(store.load_context_state("operator:persist")["lineage"])
            finally:
                store.close()

    def test_lease_busy_returns_the_original_list(self):
        compressor, _summary = self.make()
        messages = long_task()
        with context_state.compression_lease("test:compressor", timeout=0.01):
            compressed = compressor.compress(messages, current_tokens=30_000)
        self.assertIs(compressed, messages)
        self.assertEqual(compressor.get_status()["last_telemetry"]["failure_class"], "lease_busy")

    def test_proactive_prune_returns_identity_on_noop(self):
        compressor, _summary = self.make(proactive_prune_tokens=100)
        short = [{"role": "user", "content": "hi"}]
        result_messages, count = compressor.prune_tool_results_only(short, 1000)
        self.assertIs(result_messages, short)
        self.assertEqual(count, 0)

    def test_summary_prompt_carries_focus_and_memory(self):
        compressor, summary = self.make()
        compressor.compress(
            long_task(), current_tokens=30_000, force=True,
            focus_topic="disk usage", memory_context="user prefers concise reports",
        )
        prompt = summary.calls[0]["prompt"]
        self.assertIn('FOCUS TOPIC: "disk usage"', prompt)
        self.assertIn("user prefers concise reports", prompt)
        self.assertIn("DATA to summarize", prompt)

    def test_openai_style_tool_history_is_understood(self):
        compressor, _summary = self.make()
        messages = [
            {"role": "user", "content": "go"},
            {"role": "assistant", "content": None, "tool_calls": [
                {"id": "x1", "type": "function",
                 "function": {"name": "terminal", "arguments": '{"command":"ls"}'}}
            ]},
            {"role": "tool", "tool_call_id": "x1", "content": "file.txt"},
        ]
        ids = compressor._tool_call_map(messages)
        self.assertIn("x1", ids)
        entries = compressor._tool_result_entries(messages[2])
        self.assertEqual(entries[0][0], "x1")

    def test_external_chat_summary_survives_a_tail_only_view(self):
        with tempfile.TemporaryDirectory() as directory:
            store = session_store.SessionStore(Path(directory) / "sessions.db")
            try:
                state_store = context_state.SessionStateStore(store)
                first_summary = Summary("EXTERNAL FIRST")
                first, _ = self.make(first_summary, state_store=state_store,
                                     state_key="chat:test", external_summary=True)
                first.compress(long_task(), current_tokens=30_000)
                # Chat only sends the protected tail plus new rows; there is
                # no summary carrier in the message list.
                tail = [{"role": "user", "content": "new tail question"},
                        {"role": "assistant", "content": "new tail answer"}]
                tail.extend(long_task(rounds=8))
                second_summary = Summary("EXTERNAL SECOND")
                second, _ = self.make(second_summary, state_store=state_store,
                                      state_key="chat:test", external_summary=True)
                second.compress(tail, current_tokens=60_000, force=True)
                self.assertIn("PREVIOUS SUMMARY", second_summary.calls[0]["prompt"])
                self.assertIn("EXTERNAL FIRST", second_summary.calls[0]["prompt"])
            finally:
                store.close()

    def test_recovery_hint_points_at_the_archive(self):
        compressor, _summary = self.make(recovery_hint="Read /tmp/context-archive.jsonl")
        compressed = compressor.compress(long_task(), current_tokens=30_000)
        carrier = next(message for message in compressed if message.get(cc.COMPRESSED_SUMMARY_KEY))["content"]
        self.assertIn("Context Recovery", carrier)
        self.assertIn("/tmp/context-archive.jsonl", carrier)


class SessionStoreStateTests(unittest.TestCase):
    def test_context_state_round_trip_and_clear(self):
        with tempfile.TemporaryDirectory() as directory:
            store = session_store.SessionStore(Path(directory) / "sessions.db")
            try:
                token = "A" * 43
                store.save_context_state("chat:" + token, {"summary": "hello"})
                self.assertEqual(store.load_context_state("chat:" + token)["summary"], "hello")
                self.assertEqual(store.summary(token), "hello")
                store.clear(token)
                self.assertEqual(store.load_context_state("chat:" + token), {})
            finally:
                store.close()

    def test_turn_id_cursor_reads_only_newer_rows(self):
        with tempfile.TemporaryDirectory() as directory:
            store = session_store.SessionStore(Path(directory) / "sessions.db")
            try:
                token = "B" * 43
                store.append(token, "first", "one")
                first_id = store.latest_turn_id(token)
                store.append(token, "second", "two")
                newer = store.history_after(token, first_id)
                self.assertEqual([row["content"] for row in newer], ["second", "two"])
                self.assertGreater(store.latest_turn_id(token), first_id)
            finally:
                store.close()

    def test_context_state_rejects_invalid_keys(self):
        with tempfile.TemporaryDirectory() as directory:
            store = session_store.SessionStore(Path(directory) / "sessions.db")
            try:
                with self.assertRaises(ValueError):
                    store.load_context_state("../outside")
            finally:
                store.close()


if __name__ == "__main__":
    unittest.main()
