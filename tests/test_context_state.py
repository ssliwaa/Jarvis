"""context_state: compression-state persistence and the compaction lease.

The compressor's own wiring is covered by test_context_compressor.py; this
module's contracts are pinned directly instead: coercive from_dict loading
with hard bounds, the baked-in atomic file store for Operator jobs, the
fail-over composite store, and the refcounted per-conversation lease.
"""
import json
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

import context_state as cs
from context_state import (
    MAX_LINEAGE,
    MAX_STATE_BYTES,
    MAX_SUMMARY_CHARS,
    CompositeStateStore,
    CompressionLeaseBusy,
    CompressionState,
    FileStateStore,
    NullStateStore,
    SessionStateStore,
    append_lineage,
    lease_stats,
    validate_state_key,
)


class FromDictTests(unittest.TestCase):
    def test_non_dict_input_yields_default_state(self):
        for bad in (None, 42, "state", []):
            state = CompressionState.from_dict(bad)
            self.assertEqual(state.key, "")
            self.assertEqual(state.generation, 0)


    def test_round_trip_is_lossless_for_valid_payloads(self):
        state = CompressionState(key="conv:main", summary="rolling body",
                                  summary_has_user_turn=True, generation=3,
                                  compression_count=7, last_total_tokens=1200,
                                  cooldown_until=99.5, lineage=[{"kind": "compact"}],
                                  updated_at=1.5)
        restored = CompressionState.from_dict(json.loads(json.dumps(state.to_dict())))
        self.assertEqual(restored.to_dict(), state.to_dict())

    def test_coercions_tolerate_foreign_types(self):
        state = CompressionState.from_dict({
            "generation": "7",           # numeric string -> int
            "cooldown_until": "1.5",     # numeric string -> float
            "summary": 42,               # number -> str
            "summary_has_user_turn": "yes",
            "lineage": ["junk", {"k": 1}],
        })
        self.assertEqual(state.generation, 7)
        self.assertEqual(state.cooldown_until, 1.5)
        self.assertEqual(state.summary, "42")
        self.assertTrue(state.summary_has_user_turn)
        self.assertEqual(state.lineage, [{"k": 1}])

    def test_uncoercible_values_keep_defaults(self):
        state = CompressionState.from_dict({"generation": "abc", "overload_aborts": None})
        self.assertEqual(state.generation, 0)          # unparsable -> default
        self.assertEqual(state.overload_aborts, 0)    # None -> 0 for ints
        partial = CompressionState.from_dict({"summary_has_user_turn": 1})
        self.assertIs(partial.summary_has_user_turn, True)

    def test_hard_bounds_clip_loaded_state(self):
        events = [{"i": i} for i in range(MAX_LINEAGE + 10)]
        state = CompressionState.from_dict({"summary": "s" * (MAX_SUMMARY_CHARS + 5),
                                            "lineage": events})
        self.assertEqual(len(state.summary), MAX_SUMMARY_CHARS)
        self.assertEqual(state.lineage, events[-MAX_LINEAGE:])
        state2 = CompressionState.from_dict({"lineage": "not-a-list"})
        self.assertEqual(state2.lineage, [])


class ValidateKeyTests(unittest.TestCase):
    def test_accepts_typical_conversation_ids(self):
        for good in ("conv:main-1", "a.b", "chat:x-20", "operator.jobs"):
            self.assertEqual(validate_state_key(good), good[:160])

    def test_rejects_empty_and_dangerous_keys(self):
        for bad in ("", None, False, "../outside", "a b", "x" * 161, "../x"):
            with self.assertRaises(ValueError):
                validate_state_key(bad)


class AppendLineageTests(unittest.TestCase):
    def test_append_is_bounded_and_time_stamped(self):
        state = CompressionState()
        for i in range(MAX_LINEAGE + 5):
            append_lineage(state, {"kind": "compact", "i": i})
        self.assertEqual(len(state.lineage), MAX_LINEAGE)
        self.assertEqual(state.lineage[0]["i"], 5)          # oldest dropped
        self.assertTrue(all("at" in row for row in state.lineage))

    def test_rows_are_copies_of_the_caller_event(self):
        state = CompressionState()
        event = {"kind": "compact", "payload": [1]}
        append_lineage(state, event)
        event["payload"].append(2)
        self.assertEqual(state.lineage[0]["payload"], [1])


class NullStateStoreTests(unittest.TestCase):
    def test_round_trip_and_isolation(self):
        store = NullStateStore()
        value = {"a": [1, 2]}
        store.save("conv:1", value)
        value["a"].append(3)                        # caller mutation...
        self.assertEqual(store.load("conv:1"), {"a": [1, 2]})  # ...does not leak in
        self.assertEqual(store.load("missing"), {})
        store.delete("conv:1")
        self.assertEqual(store.load("conv:1"), {})
        with self.assertRaises(ValueError):
            store.save("bad key", {})


class FileStateStoreTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name) / "states"
        self.store = FileStateStore(self.root)

    def test_save_load_delete_round_trip(self):
        payload = {"summary": "zażółć gęślą jaźń", "generation": 2}
        self.store.save("conv:main", payload)
        self.assertEqual(self.store.load("conv:main"), payload)
        self.assertTrue((self.root / "conv_main.json").exists())  # ':' sanitised
        self.store.delete("conv:main")
        self.assertEqual(self.store.load("conv:main"), {})
        self.store.delete("conv:main")  # idempotent

    def test_file_permissions_are_owner_only(self):
        self.store.save("conv:x", {"a": 1})
        mode = (self.root / "conv_x.json").stat().st_mode & 0o777
        self.assertEqual(mode, 0o600)

    def test_corrupt_oversized_and_non_dict_payloads_load_empty(self):
        path = self.root / "conv_bad.json"
        path.write_text("{not json", encoding="utf-8")
        self.assertEqual(self.store.load("conv:bad"), {})
        self.store.save("conv:big-source", {"x": 1})
        (self.root / "conv_big-source.json").write_text("[1, 2]", encoding="utf-8")
        self.assertEqual(self.store.load("conv:big-source"), {})
        with open(self.root / "conv_big.json", "wb") as handle:
            handle.write(b"0" * (MAX_STATE_BYTES + 1))
        self.assertEqual(self.store.load("conv:big"), {})

    def test_oversize_save_is_refused_without_partial_writes(self):
        with self.assertRaises(ValueError):
            self.store.save("conv:big", {"blob": "x" * (MAX_STATE_BYTES + 10)})
        self.assertEqual(self.store.load("conv:big"), {})
        self.assertEqual(list(self.root.glob("conv_big*")), [])

    def test_failed_replace_leaves_no_temporary_behind(self):
        with patch("os.replace", side_effect=OSError("no can do")):
            with self.assertRaises(OSError):
                self.store.save("conv:boom", {"a": 1})
        self.assertFalse((self.root / "conv_boom.json").exists())
        self.assertEqual(list(self.root.glob("conv_boom*")), [])
        # A later save still works against the same key.
        self.store.save("conv:boom", {"a": 2})
        self.assertEqual(self.store.load("conv:boom"), {"a": 2})


class SessionStateStoreTests(unittest.TestCase):
    def test_none_store_is_a_silent_noop(self):
        store = SessionStateStore(None)
        self.assertEqual(store.load("conv:1"), {})
        store.save("conv:1", {"a": 1})
        store.delete("conv:1")

    def test_adapter_validates_and_delegates(self):
        recorded = {}

        class FakeSessions:
            def load_context_state(self, key):
                recorded["load"] = key
                return {"generation": 3}

            def save_context_state(self, key, value):
                recorded["save"] = (key, value)

            def delete_context_state(self, key):
                recorded["delete"] = key

        store = SessionStateStore(FakeSessions())
        self.assertEqual(store.load("conv:1"), {"generation": 3})
        store.save("conv:1", {"generation": 4})
        store.delete("conv:1")
        self.assertEqual(recorded, {"load": "conv:1", "save": ("conv:1", {"generation": 4}),
                                   "delete": "conv:1"})
        with self.assertRaises(ValueError):
            store.save("../evil", {})


class CompositeStateStoreTests(unittest.TestCase):
    def test_primary_value_wins_and_secondary_fills_the_gap(self):
        primary = NullStateStore()
        secondary = NullStateStore()
        secondary.save("only:there", {"from": "secondary"})
        composite = CompositeStateStore(primary, secondary)
        self.assertEqual(composite.load("only:there"), {"from": "secondary"})
        primary.save("only:there", {"from": "primary"})
        self.assertEqual(composite.load("only:there"), {"from": "primary"})

    def test_load_falls_over_when_the_primary_raises(self):
        class Exploding:
            def load(self, key):
                raise RuntimeError("down")
            def save(self, key, value):
                raise RuntimeError("down")
            def delete(self, key):
                raise RuntimeError("down")
        secondary = NullStateStore()
        secondary.save("k", {"ok": True})
        composite = CompositeStateStore(Exploding(), secondary)
        self.assertEqual(composite.load("k"), {"ok": True})

    def test_secondary_defaults_to_null_and_errors_are_swallowed(self):
        composite = CompositeStateStore(NullStateStore(), None)
        composite.save("k", {"a": 1})
        self.assertEqual(composite.load("k"), {"a": 1})
        class Missing:
            def load(self, key):
                raise RuntimeError("down")
            def save(self, key, value):
                raise RuntimeError("down")
            def delete(self, key):
                raise RuntimeError("down")
        quiet = CompositeStateStore(Missing(), Missing())
        self.assertEqual(quiet.load("k"), {})
        quiet.save("k", {"a": 1})
        quiet.delete("k")  # neither store may raise out of a mirror


class LeaseTests(unittest.TestCase):
    def test_exclusive_hold_blocks_the_second_thread(self):
        with cs.compression_lease("conv:race"):
            errors = []

            def grab():
                try:
                    with cs.compression_lease("conv:race", timeout=0.05):
                        pass
                except CompressionLeaseBusy as error:
                    errors.append(str(error))

            thread = threading.Thread(target=grab)
            thread.start()
            thread.join(timeout=5)
            self.assertFalse(thread.is_alive())
        self.assertEqual(len(errors), 1)
        self.assertIn("conv:race", errors[0])

    def test_release_frees_the_key_for_the_next_holder(self):
        with cs.compression_lease("conv:free", timeout=1):
            pass
        with cs.compression_lease("conv:free", timeout=1):
            pass

    def test_distinct_keys_do_not_block_each_other(self):
        with cs.compression_lease("conv:a"):
            with cs.compression_lease("conv:b", timeout=1):
                pass

    def test_exception_inside_the_body_still_releases(self):
        with self.assertRaises(RuntimeError):
            with cs.compression_lease("conv:boom", timeout=1):
                with cs.compression_lease("conv:boom2", timeout=1):
                    raise RuntimeError("kaboom")
        self.assertEqual(lease_stats(), {"keys": 0, "users": 0})
        with cs.compression_lease("conv:boom", timeout=1):
            pass

    def test_invalid_keys_never_touch_the_lease_table(self):
        with self.assertRaises(ValueError):
            with cs.compression_lease("../evil"):
                pass
        self.assertEqual(lease_stats()["keys"], 0)

    def test_stats_report_live_holders(self):
        self.assertEqual(lease_stats(), {"keys": 0, "users": 0})
        with cs.compression_lease("conv:stats"):
            live = lease_stats()
        self.assertEqual(live["keys"], 1)
        self.assertGreaterEqual(live["users"], 1)
        self.assertEqual(lease_stats(), {"keys": 0, "users": 0})


if __name__ == "__main__":
    unittest.main()
