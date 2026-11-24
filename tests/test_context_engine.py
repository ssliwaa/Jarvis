"""context_engine: the leaf module guarding memory text before an LLM boundary.

sanitize_memory_context bounds and redacts everything the memory store can
inject into a prompt; automatic_compaction_status_message is the host-visible
status hook for automatic compactions. Both are pinned here.
"""
import unittest
from types import SimpleNamespace

import context_engine


class SanitizeMemoryContextTests(unittest.TestCase):
    def test_empty_and_whitespace_inputs_return_empty_string(self):
        self.assertEqual(context_engine.sanitize_memory_context(""), "")
        self.assertEqual(context_engine.sanitize_memory_context(None), "")
        self.assertEqual(context_engine.sanitize_memory_context("   \n\t "), "")

    def test_oversized_memory_is_bounded_without_losing_the_ends(self):
        head, tail = "HEAD-MARKER", "TAIL-MARKER"
        text = head + ("filler " * 2000) + tail
        out = context_engine.sanitize_memory_context(text)
        self.assertLessEqual(len(out), context_engine.MEMORY_CONTEXT_MAX_CHARS)
        # elide_middle keeps the informative start and end, drops the middle.
        self.assertTrue(out.startswith(head), out[:40])
        self.assertTrue(out.rstrip().endswith(tail), out[-40:])


class AutomaticCompactionStatusTests(unittest.TestCase):
    def test_silent_engine_returns_none(self):
        engine = SimpleNamespace(emit_automatic_compaction_status=False)
        self.assertIsNone(context_engine.automatic_compaction_status_message(
            engine, phase="mid", default_message="Compacting…"))

    def test_engine_without_formatter_falls_back_to_default(self):
        engine = SimpleNamespace(emit_automatic_compaction_status=True)
        out = context_engine.automatic_compaction_status_message(
            engine, phase="start", default_message="Kompaktuję kontekst.")
        self.assertEqual(out, "Kompaktuję kontekst.")

    def test_formatter_overrides_the_message(self):
        def formatter(*, phase, default_message, **ctx):
            return f"[{phase}] {default_message} (tokens={ctx.get('tokens')})"
        engine = SimpleNamespace(emit_automatic_compaction_status=True,
                                 get_automatic_compaction_status_message=formatter)
        out = context_engine.automatic_compaction_status_message(
            engine, phase="done", default_message="Done", tokens=123)
        self.assertEqual(out, "[done] Done (tokens=123)")

    def test_blank_or_none_messages_stay_silent(self):
        def blank(*args, **kwargs):
            return "   "
        engine = SimpleNamespace(emit_automatic_compaction_status=True,
                                 get_automatic_compaction_status_message=blank)
        self.assertIsNone(context_engine.automatic_compaction_status_message(
            engine, phase="mid", default_message="x"))

        engine_none = SimpleNamespace(
            emit_automatic_compaction_status=True,
            get_automatic_compaction_status_message=lambda *a, **k: None)
        self.assertIsNone(context_engine.automatic_compaction_status_message(
            engine_none, phase="mid", default_message="x"))

    def test_non_callable_formatter_is_ignored_safely(self):
        engine = SimpleNamespace(emit_automatic_compaction_status=True,
                                 get_automatic_compaction_status_message="not callable")
        out = context_engine.automatic_compaction_status_message(
            engine, phase="mid", default_message="fallback")
        self.assertEqual(out, "fallback")


if __name__ == "__main__":
    unittest.main()
