"""Unit tests for `workflow_miner.py` — event sanitization, n-gram mining, macro compilation.

Dotąd jedynie happy-path end-to-end (mission_suite: 4-eventowy wzorzec + compile z poprawną
nazwą; p1_concurrency: 24 równoległe rekordy). Tu: ValueError dla pustego kind, sanitizacja
pol, trim do 1500 zdarzeń, corrupt linie w read_events, filtry mine_patterns (identyczne
sekwencje, za mało zdarzeń, non-overlap), ranking score=support*length oraz koercja/odrzucenie
nazw makr + idempotencja rejestracji. Izolacja: ROOT patchowany na świeży tmp per test.
"""
from __future__ import annotations

import json
import shutil
import sys
import time
import unittest
from pathlib import Path
from tempfile import mkdtemp
from unittest import mock

sys.path.insert(0, ".")

import workflow_miner as wm  # noqa: E402


class WorkflowMinerBase(unittest.TestCase):
    def setUp(self) -> None:
        self.base = Path(mkdtemp())
        self.addCleanup(shutil.rmtree, self.base, True)
        self.root = self.base / "state" / ".jarvis-tools" / "agents" / "root"
        self.patch_root = mock.patch.object(wm.agent_cli, "ROOT", self.root)
        self.patch_root.start()
        self.addCleanup(self.patch_root.stop)

    @property
    def workflows_dir(self) -> Path:
        return self.base / "state" / ".jarvis-tools" / "agents" / "workflows"

    def _record(self, kind: str, target: str = "", params: dict | None = None) -> dict:
        return wm.record_event(kind, target=target, params=params)

    def _seed_pattern(self, repeats: int = 3, params: dict | None = None) -> None:
        for _ in range(repeats):
            self._record("clipboard.read", target="selection")
            self._record("notes.save", target="inbox.md", params=params)


class RecordEventTests(WorkflowMinerBase):
    def test_kind_and_target_sanitized_and_shape(self):
        before = time.time()
        entry = self._record("App.FOCUS!!", target="  Firefox  ", params="not-a-dict")
        self.assertEqual(entry["kind"], "app.focus")               # lower + [_] czyszczenie
        self.assertEqual(entry["target"], "Firefox")
        self.assertEqual(entry["params"], {})                       # non-dict -> {}
        self.assertTrue(set(entry.keys()) >= {"ts", "kind", "target", "params"})
        self.assertAlmostEqual(entry["ts"], before, delta=10.0)
        stored = wm.read_events(limit=10)[0]
        self.assertEqual(stored["kind"], "app.focus")

    def test_missing_kind_raises(self):
        with self.assertRaises(ValueError) as ctx:
            self._record("!!!")
        self.assertIn("kind is required", str(ctx.exception))

    def test_events_log_trimmed_to_1500(self):
        epath = self.workflows_dir / "events.jsonl"
        epath.parent.mkdir(parents=True, exist_ok=True)
        lines = [json.dumps({"ts": float(i), "kind": f"k{i}", "target": "", "params": {}})
                 for i in range(1505)]
        epath.write_text("\n".join(lines) + "\n", encoding="utf-8")
        self._record("trim.check")
        trimmed = epath.read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(trimmed), wm.MAX_EVENTS)
        self.assertEqual(json.loads(trimmed[-1])["kind"], "trim.check")


class ReadEventsTests(WorkflowMinerBase):
    def test_missing_file_and_malformed_lines(self):
        self.assertEqual(wm.read_events(), [])

        epath = self.workflows_dir / "events.jsonl"
        epath.parent.mkdir(parents=True, exist_ok=True)
        epath.write_text(
            "\n".join([
                json.dumps({"ts": 1.0, "kind": "a", "target": "t1", "params": {}}),
                "",
                "{corrupt json",
                json.dumps({"ts": 2.0, "target": "x", "params": {}}),   # brak kind
                json.dumps({"ts": 3.0, "kind": "b", "target": "", "params": {}}),
            ]) + "\n",
            encoding="utf-8")
        rows = wm.read_events(limit=10)
        self.assertEqual([r["kind"] for r in rows], ["a", "b"])

    def test_limit_returns_tail(self):
        for i in range(5):
            self._record(f"k{i}")
        self.assertEqual([r["kind"] for r in wm.read_events(limit=2)], ["k3", "k4"])


class MinePatternsTests(WorkflowMinerBase):
    def test_recurring_bigram_with_sample_from_last_occurrence(self):
        self._seed_pattern(repeats=3, params={"tag": "clip"})
        patterns = wm.mine_patterns(min_len=2, max_len=2, min_support=2)
        top = next(p for p in patterns if p["steps"] == ["clipboard.read:selection",
                                                         "notes.save:inbox.md"])
        self.assertEqual(top["support"], 3)
        self.assertEqual(top["length"], 2)
        self.assertEqual(top["score"], 6)
        self.assertEqual(top["title"], "clipboard.read:selection → notes.save:inbox.md")
        # sample z OSTATNIEGO wystapienia, z params zachowanymi
        self.assertEqual(top["sample_steps"][1]["kind"], "notes.save")
        self.assertEqual(top["sample_steps"][1]["params"], {"tag": "clip"})
        self.assertTrue(top["id"])

    def test_identical_sequences_ignored(self):
        for _ in range(5):
            self._record("app.focus", target="same")
        self.assertEqual(wm.mine_patterns(min_len=2, max_len=4, min_support=2), [])

    def test_too_few_events_returns_empty(self):
        self._record("a")
        self._record("b")
        self.assertEqual(wm.mine_patterns(min_len=2, max_len=4, min_support=2), [])

    def test_non_overlapping_support_and_ranking(self):
        kinds = ["a", "b", "a", "b", "a", "b"]
        for k in kinds:
            self._record(k)
        patterns = wm.mine_patterns(min_len=2, max_len=2, min_support=2)
        by_steps = {tuple(p["steps"]): p for p in patterns}
        self.assertEqual(by_steps[("a", "b")]["support"], 3)   # pozycje 0, 2, 4
        self.assertEqual(by_steps[("b", "a")]["support"], 2)   # pozycje 1, 3
        self.assertEqual(patterns[0]["score"], 6)              # wierzcholek rankingu

    def test_longer_patterns_ranked_by_score(self):
        kinds = ["a", "b", "c", "a", "b", "c"]
        for k in kinds:
            self._record(k)
        patterns = wm.mine_patterns(min_len=2, max_len=3, min_support=2)
        best = patterns[0]
        self.assertEqual(best["steps"], ["a", "b", "c"])       # score 6 = 2*3
        self.assertEqual(best["support"], 2)
        self.assertEqual(best["length"], 3)
        bigram_scores = {p["score"] for p in patterns if p["length"] == 2}
        self.assertTrue(bigram_scores <= {4})                   # bigramy: 2*2


class ListMacrosTests(WorkflowMinerBase):
    def test_missing_corrupt_and_nonlist_shapes(self):
        self.assertEqual(wm.list_macros(), [])
        mpath = self.workflows_dir / "macros.json"
        mpath.parent.mkdir(parents=True, exist_ok=True)
        mpath.write_text("{corrupt", encoding="utf-8")
        self.assertEqual(wm.list_macros(), [])
        mpath.write_text(json.dumps({"name": "not-a-list"}), encoding="utf-8")
        self.assertEqual(wm.list_macros(), [])
        mpath.write_text(json.dumps([
            {"name": "ok_macro"}, 42, "str", {"name": "second"}]), encoding="utf-8")
        self.assertEqual([m["name"] for m in wm.list_macros()], ["ok_macro", "second"])


class CompileMacroTests(WorkflowMinerBase):
    def _top_pattern_id(self) -> str:
        return wm.mine_patterns(min_len=2, max_len=2, min_support=2)[0]["id"]

    def test_unknown_pattern_id_raises(self):
        with self.assertRaises(ValueError) as ctx:
            wm.compile_macro("deadbeef", name="x_y")
        self.assertIn("Nie znaleziono wzorca", str(ctx.exception))

    def test_compile_writes_callable_module_and_registers(self):
        self._seed_pattern(repeats=2)
        pid = self._top_pattern_id()
        res = wm.compile_macro(pid, name="Moja Fira!")
        self.assertTrue(res["ok"])
        record = res["macro"]
        self.assertEqual(record["name"], "moja_fira")
        self.assertEqual(record["pattern_id"], pid)
        self.assertEqual(record["support"], 2)
        self.assertIn("clipboard.read:selection → notes.save:inbox.md", record["title"])

        dest = Path(record["file"])
        self.assertTrue(dest.is_file())
        namespace: dict = {}
        exec(dest.read_text(encoding="utf-8"), namespace)  # noqa: S102 (plik auto-generowany)
        out = namespace["run_macro"](dry_run=True)
        self.assertTrue(out["ok"])
        self.assertEqual(out["macro"], "moja_fira")
        self.assertEqual(len(out["steps"]), 2)
        self.assertTrue(all(s["dry_run"] for s in out["steps"]))

        executed_calls: list[tuple] = []
        out2 = namespace["run_macro"](executor=lambda kind, tgt, params: executed_calls.append((kind, tgt)))
        self.assertEqual(len(executed_calls), 2)
        self.assertEqual(executed_calls[0][0], "clipboard.read")
        self.assertTrue(all("result" in s and "target" not in s for s in out2["steps"]))

        registered = wm.list_macros()
        self.assertEqual(len(registered), 1)
        self.assertEqual(registered[0]["name"], "moja_fira")

    def test_default_name_from_pattern_and_prefix_coercion(self):
        self._seed_pattern(repeats=2)
        pid = self._top_pattern_id()
        res = wm.compile_macro(pid)                       # pusta nazwa -> workflow_<pid6>
        self.assertTrue(res["macro"]["name"].startswith("workflow_"))
        res2 = wm.compile_macro(pid, name="1up!")
        self.assertEqual(res2["macro"]["name"][:6], "macro_")   # cyfra -> prefix macro_
        self.assertTrue(res2["macro"]["name"].endswith("1up"))

    def test_single_char_name_rejected_by_safe_re(self):
        self._seed_pattern(repeats=2)
        pid = self._top_pattern_id()
        with self.assertRaises(ValueError) as ctx:
            wm.compile_macro(pid, name="x")               # SAFE_MACRO_RE wymaga >=2 znakow
        self.assertIn("Nieprawidłowa nazwa makra", str(ctx.exception))

    def test_registration_idempotent_by_name(self):
        self._seed_pattern(repeats=2)
        pid = self._top_pattern_id()
        wm.compile_macro(pid, name="idem")
        wm.compile_macro(pid, name="idem!!!")             # czyszczenie -> ta sama nazwa
        names = [m["name"] for m in wm.list_macros()]
        self.assertEqual(names, ["idem"])

    def test_output_dir_override(self):
        self._seed_pattern(repeats=2)
        pid = self._top_pattern_id()
        out_dir = self.base / "custom-macros"
        res = wm.compile_macro(pid, name="rewritten", output_dir=out_dir)
        dest = Path(res["macro"]["file"])
        self.assertEqual(dest.parent, out_dir)
        self.assertTrue(dest.name == "rewritten.py")


if __name__ == "__main__":
    unittest.main()
