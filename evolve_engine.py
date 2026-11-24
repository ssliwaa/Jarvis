"""Next-generation evolutionary engine for Jarvis (OpenEvolve + DGM + ACE + Self-Harness).

Extends `evolution.py` and `self_modify.py` with six SOTA capabilities:
  1. MapElitesGrid       - Quality-Diversity archive (AST simplicity x speed/memory) + islands.
  2. Crossover           - Multi-parent prompt synthesis ("parent + inspirations") & artifact traces.
  3. Mutation & Breaker  - AST mutation testing + adversarial draft generator (`bench_drafts/`).
  4. EvolveBlocks        - Surgical `# EVOLVE-BLOCK-START` .. `# EVOLVE-BLOCK-END` zone enforcement.
  5. CascadeEvaluator    - Fast-fail 4-stage funnel with `tracemalloc` memory & latency profiling.
  6. SelfHarness/Skills  - PromptLab meta-evolution and portable skill distillation (`distilled_skills/`).
"""

from __future__ import annotations

import ast
import copy
import json
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import evolution

EVOLVE_START_RE = re.compile(r"^\s*#\s*EVOLVE-BLOCK-START(?::([A-Za-z0-9_-]+))?\s*$")
EVOLVE_END_RE = re.compile(r"^\s*#\s*EVOLVE-BLOCK-END\s*$")
ISLAND_COUNT = 3


def _state_dir() -> Path:
    return evolution.STATE


# --------------------------------------------------------------------------- #
# 1. Code descriptors & MAP-Elites Quality-Diversity Grid + Islands
# --------------------------------------------------------------------------- #
def compute_code_metrics(source: str) -> dict:
    """Compute deterministic structural descriptors (SLOC, AST nodes, cyclomatic branches)."""
    text = str(source or "")
    lines = [ln for ln in text.splitlines() if ln.strip() and not ln.lstrip().startswith("#")]
    sloc = len(lines)
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return {"valid_ast": False, "sloc": sloc, "ast_nodes": 99999, "branches": 999, "simplicity_bin": "rich"}

    ast_nodes = 0
    branches = 0
    branch_types = (ast.If, ast.For, ast.AsyncFor, ast.While, ast.Try, ast.With, ast.BoolOp, ast.IfExp)
    for node in ast.walk(tree):
        ast_nodes += 1
        if isinstance(node, branch_types):
            branches += 1

    if ast_nodes <= 180 and branches <= 15:
        s_bin = "compact"
    elif ast_nodes <= 650 and branches <= 60:
        s_bin = "balanced"
    else:
        s_bin = "rich"

    return {
        "valid_ast": True,
        "sloc": sloc,
        "ast_nodes": ast_nodes,
        "branches": branches,
        "simplicity_bin": s_bin,
    }


def classify_speed_bin(duration_ms: float | int | None, peak_kb: float | int | None = None) -> str:
    ms = float(duration_ms if duration_ms is not None else 250.0)
    kb = float(peak_kb if peak_kb is not None else 0.0)
    if ms <= 120.0 and (kb <= 0.0 or kb <= 2048.0):
        return "fast"
    if ms <= 600.0 and (kb <= 0.0 or kb <= 12288.0):
        return "medium"
    return "thorough"


class MapElitesGrid:
    """Quality-Diversity archive indexed by (module, island, simplicity_bin, speed_bin)."""

    def __init__(self, path: Path | None = None):
        self.path = Path(path or (_state_dir() / "map_elites.json"))

    def _load(self) -> dict:
        data = evolution._read_json(self.path, {})
        return data if isinstance(data, dict) else {}

    def _save(self, data: dict) -> None:
        evolution._write_json(self.path, data)

    def insert(self, *, module: str, node_id: str, score: float, source: str,
               duration_ms: float | None = None, peak_kb: float | None = None,
               island: int | None = None, explanation: str = "") -> dict:
        metrics = compute_code_metrics(source)
        s_bin = metrics["simplicity_bin"]
        v_bin = classify_speed_bin(duration_ms, peak_kb)
        isl = int(island if island is not None else (hash(node_id) % ISLAND_COUNT)) % ISLAND_COUNT
        cell_key = f"{s_bin}:{v_bin}"

        data = self._load()
        mod_grid = dict(data.get(module) or {})
        islands = dict(mod_grid.get("islands") or {})
        isl_cells = dict(islands.get(str(isl)) or {})

        candidate = {
            "node_id": node_id,
            "module": module,
            "island": isl,
            "cell": cell_key,
            "simplicity_bin": s_bin,
            "speed_bin": v_bin,
            "score": round(float(score or 0.0), 4),
            "duration_ms": round(float(duration_ms or 0.0), 1),
            "peak_kb": round(float(peak_kb or 0.0), 1),
            "ast_nodes": metrics["ast_nodes"],
            "branches": metrics["branches"],
            "sloc": metrics["sloc"],
            "explanation": str(explanation or "")[:220],
            "ts": round(time.time(), 3),
        }

        incumbent = isl_cells.get(cell_key)
        replaced = False
        if not isinstance(incumbent, dict):
            replaced = True
        else:
            inc_key = (
                float(incumbent.get("score") or 0.0),
                -int(incumbent.get("ast_nodes") or 99999),
                -float(incumbent.get("duration_ms") or 99999.0),
            )
            new_key = (
                candidate["score"],
                -candidate["ast_nodes"],
                -candidate["duration_ms"],
            )
            if new_key > inc_key:
                replaced = True

        if replaced:
            isl_cells[cell_key] = candidate
            islands[str(isl)] = isl_cells
            mod_grid["islands"] = islands
            mod_grid["updated_at"] = candidate["ts"]
            data[module] = mod_grid
            self._save(data)

        return {"accepted": replaced, "cell": cell_key, "island": isl, "entry": candidate}

    def migrate_islands(self, module: str) -> int:
        """Ring migration: copy best cell from island i to island (i+1) % N if superior."""
        data = self._load()
        mod_grid = data.get(module)
        if not isinstance(mod_grid, dict):
            return 0
        islands = dict(mod_grid.get("islands") or {})
        migrated = 0
        snapshot_islands = copy.deepcopy(islands)
        for idx in range(ISLAND_COUNT):
            src_cells = snapshot_islands.get(str(idx)) or {}
            if not src_cells:
                continue
            best = max(src_cells.values(), key=lambda c: (c.get("score", 0.0), -c.get("ast_nodes", 99999)))
            dst_idx = str((idx + 1) % ISLAND_COUNT)
            dst_cells = dict(islands.get(dst_idx) or {})
            cell = best["cell"]
            incumbent = dst_cells.get(cell)
            if not incumbent or (best["score"], -best["ast_nodes"]) > (incumbent.get("score", 0.0), -incumbent.get("ast_nodes", 99999)):
                clone = {**best, "island": int(dst_idx), "migrated_from": idx}
                dst_cells[cell] = clone
                islands[dst_idx] = dst_cells
                migrated += 1
        if migrated:
            mod_grid["islands"] = islands
            data[module] = mod_grid
            self._save(data)
        return migrated

    def elites(self, module: str) -> list[dict]:
        """Return deduplicated elite entries across all islands sorted by score then simplicity."""
        data = self._load()
        mod_data = data.get(module)
        # a corrupt state file may hold a non-dict module entry: skip it whole
        islands = (mod_data.get("islands") or {}) if isinstance(mod_data, dict) else {}
        seen = {}
        for isl_cells in islands.values():
            if not isinstance(isl_cells, dict):
                continue
            for entry in isl_cells.values():
                if isinstance(entry, dict) and entry.get("node_id"):
                    nid = entry["node_id"]
                    if nid not in seen or entry.get("score", 0) > seen[nid].get("score", 0):
                        seen[nid] = entry
        rows = list(seen.values())
        rows.sort(key=lambda r: (r.get("score", 0.0), -r.get("ast_nodes", 99999), -r.get("duration_ms", 99999.0)), reverse=True)
        return rows

    def sample_inspirations(self, module: str, archive: evolution.Archive | None = None,
                            exclude_id: str = "", k: int = 2) -> list[dict]:
        """Pick up to k diverse elites (different cells/islands) with their source code for crossover."""
        arch = archive or evolution.Archive()
        pool = [e for e in self.elites(module) if e.get("node_id") != exclude_id]
        chosen: list[dict] = []
        used_cells = set()
        for entry in pool:
            if len(chosen) >= k:
                break
            if entry.get("cell") in used_cells and len(pool) > k:
                continue
            src = arch.source_of(entry["node_id"])
            if not src:
                continue
            used_cells.add(entry.get("cell"))
            chosen.append({**entry, "source": src})
        return chosen

    def summary(self, module: str = "") -> dict:
        data = self._load()
        if module:
            return {"module": module, "elites": self.elites(module)}
        return {mod: {"cells": len(self.elites(mod)), "top": self.elites(mod)[:3]} for mod in sorted(data)}


# --------------------------------------------------------------------------- #
# 2. Surgical `# EVOLVE-BLOCK-START` .. `# EVOLVE-BLOCK-END` enforcement
# --------------------------------------------------------------------------- #
class EvolveBlocks:
    """Parse and enforce `# EVOLVE-BLOCK-START` .. `# EVOLVE-BLOCK-END` mutable regions."""

    @staticmethod
    def extract(source: str) -> list[dict]:
        lines = str(source or "").splitlines()
        blocks = []
        active = None
        for idx, line in enumerate(lines, 1):
            m_start = EVOLVE_START_RE.match(line)
            if m_start and active is None:
                active = {
                    "name": m_start.group(1) or f"block_{len(blocks) + 1}",
                    "start_line": idx,
                    "body_lines": [],
                }
                continue
            if EVOLVE_END_RE.match(line) and active is not None:
                active["end_line"] = idx
                active["body"] = "\n".join(active.pop("body_lines"))
                blocks.append(active)
                active = None
                continue
            if active is not None:
                active["body_lines"].append(line)
        return blocks

    @classmethod
    def verify_frozen_outside_blocks(cls, original: str, staged: str) -> tuple[bool, str]:
        """Ensure lines outside `# EVOLVE-BLOCK` markers were NOT modified when markers exist."""
        orig_blocks = cls.extract(original)
        if not orig_blocks:
            return True, ""
        staged_blocks = cls.extract(staged)
        if len(orig_blocks) != len(staged_blocks):
            return False, "Patch usunął lub zmienił liczbę znaczników # EVOLVE-BLOCK."

        def _skeleton(text: str, blocks: list[dict]) -> list[str]:
            raw_lines = text.splitlines()
            out = []
            cursor = 1
            for b in blocks:
                out.extend(raw_lines[cursor - 1:b["start_line"]])
                out.append(f"<<BLOCK:{b['name']}>>")
                cursor = b["end_line"]
            out.extend(raw_lines[cursor - 1:])
            return out

        if _skeleton(original, orig_blocks) != _skeleton(staged, staged_blocks):
            return False, "Patch zmodyfikował zamrożony kod poza strefą # EVOLVE-BLOCK."
        return True, ""


# --------------------------------------------------------------------------- #
# 3. Fast-Fail Cascade Evaluator + tracemalloc Peak Memory Telemetry
# --------------------------------------------------------------------------- #
class CascadeEvaluator:
    """4-stage fast-fail evaluation funnel (AST/Blocks -> Smoke+Mem -> Full Bench -> UnitTests)."""

    @staticmethod
    def measure_memory_and_smoke(path: Path, cases: list[dict]) -> dict:
        """Run the easiest case in bwrap while measuring peak memory via tracemalloc."""
        if not cases:
            return {"ok": True, "peak_kb": 0.0, "smoke_ms": 0.0}
        refusal = evolution.sandbox_refusal()
        if refusal:
            return {"ok": False, "error": refusal, "peak_kb": 0.0, "smoke_ms": 0.0}

        easy_case = sorted(cases, key=lambda c: int(c.get("level") or 1))[0]
        probe_code = (
            "import importlib.util, json, sys, time, tracemalloc\n"
            "path, case = sys.argv[1], json.loads(sys.argv[2])\n"
            "tracemalloc.start()\n"
            "t0 = time.perf_counter()\n"
            "spec = importlib.util.spec_from_file_location('smoke_mod', path)\n"
            "mod = importlib.util.module_from_spec(spec)\n"
            "sys.modules['smoke_mod'] = mod\n"
            "spec.loader.exec_module(mod)\n"
            "fn = getattr(mod, case.get('call') or '', None)\n"
            "ok = True\n"
            "if callable(fn) and not case.get('prepare'):\n"
            "    try:\n"
            "        fn(**(case.get('kwargs') or {}))\n"
            "    except Exception:\n"
            "        ok = bool(case.get('expect_error'))\n"
            "_cur, peak = tracemalloc.get_traced_memory()\n"
            "tracemalloc.stop()\n"
            "ms = (time.perf_counter() - t0) * 1000.0\n"
            "print(json.dumps({'ok': ok, 'peak_kb': round(peak / 1024.0, 2), 'smoke_ms': round(ms, 2)}))\n"
        )
        argv = evolution.sandbox_argv(
            [sys.executable, "-c", probe_code, str(path), json.dumps(easy_case)],
            readonly=[str(path.parent)],
        )
        try:
            proc = subprocess.run(
                argv,
                cwd=str(evolution.ROOT),
                env=evolution._bench_environment(),
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            if proc.returncode != 0:
                return {"ok": False, "error": (proc.stderr or proc.stdout)[-240:], "peak_kb": 0.0, "smoke_ms": 0.0}
            data = json.loads((proc.stdout or "").strip().splitlines()[-1])
            return data if isinstance(data, dict) else {"ok": True, "peak_kb": 0.0, "smoke_ms": 0.0}
        except Exception as exc:
            return {"ok": False, "error": str(exc)[:200], "peak_kb": 0.0, "smoke_ms": 0.0}

    @classmethod
    def evaluate_candidate(cls, module: str, staged_source: str,
                           original_source: str = "", strict_blocks: bool = True,
                           run_unittests: bool = False) -> dict:
        """Evaluate staged_source through fast-fail stages before spending full suite time."""
        metrics = compute_code_metrics(staged_source)
        if not metrics["valid_ast"]:
            return {"ok": False, "stage": "ast", "score": 0.0, "error": "Błąd składni AST", "metrics": metrics}
        if strict_blocks and original_source:
            blocks_ok, block_err = EvolveBlocks.verify_frozen_outside_blocks(original_source, staged_source)
            if not blocks_ok:
                return {"ok": False, "stage": "evolve_block", "score": 0.0, "error": block_err, "metrics": metrics}

        cases = evolution.Scorecard.bench_cases(module)
        with tempfile.TemporaryDirectory(prefix="jarvis-cascade-") as tmp:
            probe = Path(tmp) / f"{module}.py"
            probe.write_text(staged_source, encoding="utf-8")

            smoke = cls.measure_memory_and_smoke(probe, cases)
            if not smoke.get("ok"):
                return {
                    "ok": False,
                    "stage": "smoke",
                    "score": 0.0,
                    "error": smoke.get("error") or "Smoke test failed",
                    "peak_kb": smoke.get("peak_kb", 0.0),
                    "metrics": metrics,
                }

            t0 = time.time()
            bench = evolution.Scorecard.run_cases(probe, cases) if cases else {"ok": 0, "total": 0, "results": []}
            duration_ms = round((time.time() - t0) * 1000.0, 1)
            bench_ratio = (bench["ok"] / bench["total"]) if bench["total"] else 1.0

            if cases and bench["ok"] == 0:
                return {
                    "ok": False,
                    "stage": "bench",
                    "score": 0.0,
                    "bench": bench,
                    "duration_ms": duration_ms,
                    "peak_kb": smoke.get("peak_kb", 0.0),
                    "metrics": metrics,
                    "error": "Wszystkie przypadki held-out bench zakończyły się błędem.",
                }

            score_val = round(bench_ratio, 4)
            if run_unittests:
                ut = evolution.Scorecard.unittests(module)
                if ut.get("total"):
                    ut_ratio = ut["ok"] / ut["total"]
                    score_val = round((bench_ratio * 0.7 + ut_ratio * 0.3) if cases else ut_ratio, 4)

            artifacts = [
                r.get("detail") for r in (bench.get("results") or [])
                if isinstance(r, dict) and not r.get("ok") and r.get("detail")
            ][:6]

            return {
                "ok": True,
                "stage": "complete",
                "score": score_val,
                "bench": {"ok": bench["ok"], "total": bench["total"]},
                "duration_ms": duration_ms,
                "peak_kb": smoke.get("peak_kb", 0.0),
                "metrics": metrics,
                "artifacts": artifacts,
            }


# --------------------------------------------------------------------------- #
# 4. Semantic Crossover Prompt Builder ("Parent + Inspirations + Artifacts")
# --------------------------------------------------------------------------- #
def build_crossover_prompt(file_name: str, instruction: str, parent_source: str,
                           inspirations: list[dict] | None = None,
                           artifacts: list[str] | None = None,
                           max_chars: int = 120_000) -> str:
    """Combine primary parent, diverse MAP-Elites inspirations, and runtime error artifacts."""
    evolve_blocks = EvolveBlocks.extract(parent_source)
    block_note = ""
    if evolve_blocks:
        names = ", ".join(b["name"] for b in evolve_blocks)
        block_note = (
            f"\nUWAGA: Ten plik posiada strefy ewolucji `# EVOLVE-BLOCK-START` ({names}). "
            f"Modyfikuj WYŁĄCZNIE kod wewnątrz znaczników `# EVOLVE-BLOCK-START` .. `# EVOLVE-BLOCK-END`!\n"
        )

    art_block = ""
    if artifacts:
        art_block = "\nArtefakty z ostatniego wykonania / profilera (wyeliminuj te błędy):\n" + "\n".join(
            f"- {a}" for a in artifacts[:6]
        ) + "\n"

    insp_block = ""
    if inspirations:
        chunks = []
        budget_each = max(2000, min(14_000, max_chars // (len(inspirations) + 2)))
        for idx, insp in enumerate(inspirations[:2], 1):
            chunks.append(
                f"### Inspiracja #{idx} (nisza `{insp.get('cell')}`, score={insp.get('score')}, "
                f"AST={insp.get('ast_nodes')}, {insp.get('duration_ms')} ms)\n"
                f"```python\n{str(insp.get('source') or '')[:budget_each]}\n```"
            )
        insp_block = (
            "\n## Warianty elitarne z innych wysp MAP-Elites (połącz ich najlepsze cechy z kodem głównym)\n"
            + "\n\n".join(chunks)
            + "\n"
        )

    src_budget = max(10_000, max_chars - len(insp_block) - len(art_block) - 1000)
    return (
        f"File: {file_name}\n"
        f"Instruction: {instruction}\n"
        f"{block_note}{art_block}{insp_block}\n"
        f"## Kod rodzica do zmodyfikowania\n"
        f"```python\n{parent_source[:src_budget]}\n```"
    )


# --------------------------------------------------------------------------- #
# 5. AST Mutation Testing & Adversarial Breaker (ACE / TTCS with Drift Guard)
# --------------------------------------------------------------------------- #
class MutationTester:
    """Generate single-point AST mutants to measure benchmark sensitivity and uncover blind spots."""

    COMPARE_SWAPS = {
        ast.Lt: ast.LtE,
        ast.LtE: ast.Lt,
        ast.Gt: ast.GtE,
        ast.GtE: ast.Gt,
        ast.Eq: ast.NotEq,
        ast.NotEq: ast.Eq,
    }
    BINOP_SWAPS = {
        ast.Add: ast.Sub,
        ast.Sub: ast.Add,
    }

    @classmethod
    def generate_mutants(cls, source: str, limit: int = 8) -> list[dict]:
        try:
            base_tree = ast.parse(source)
        except SyntaxError:
            return []

        candidates = []
        for idx, node in enumerate(ast.walk(base_tree)):
            if isinstance(node, ast.Compare) and len(node.ops) == 1 and type(node.ops[0]) in cls.COMPARE_SWAPS:
                candidates.append(("compare", idx, getattr(node, "lineno", 0), type(node.ops[0]).__name__))
            elif isinstance(node, ast.BinOp) and type(node.op) in cls.BINOP_SWAPS:
                candidates.append(("binop", idx, getattr(node, "lineno", 0), type(node.op).__name__))
            elif isinstance(node, ast.Constant) and isinstance(node.value, bool):
                candidates.append(("bool", idx, getattr(node, "lineno", 0), str(node.value)))

        mutants = []
        for kind, target_idx, lineno, desc in candidates[:max(1, min(int(limit or 8), 20))]:
            tree_copy = ast.parse(source)
            for cur_idx, node in enumerate(ast.walk(tree_copy)):
                if cur_idx != target_idx:
                    continue
                if kind == "compare" and isinstance(node, ast.Compare):
                    new_op = cls.COMPARE_SWAPS[type(node.ops[0])]()
                    node.ops = [new_op]
                elif kind == "binop" and isinstance(node, ast.BinOp):
                    node.op = cls.BINOP_SWAPS[type(node.op)]()
                elif kind == "bool" and isinstance(node, ast.Constant):
                    node.value = not node.value
                break
            ast.fix_missing_locations(tree_copy)
            try:
                mut_src = ast.unparse(tree_copy)
            except Exception:
                continue
            if mut_src != source:
                mutants.append({
                    "kind": kind,
                    "line": lineno,
                    "original": desc,
                    "source": mut_src,
                })
        return mutants

    @classmethod
    def evaluate_suite(cls, module: str, source_path: Path | None = None,
                       cases: list[dict] | None = None, max_mutants: int = 6) -> dict:
        """Run bench cases against AST mutants; surviving mutants reveal missing edge-case tests."""
        path = Path(source_path or (evolution.ROOT / f"{module}.py"))
        suite = cases if cases is not None else evolution.Scorecard.bench_cases(module)
        if not path.is_file() or not suite:
            return {"ok": True, "module": module, "mutants": 0, "killed": 0, "kill_rate": 0.0, "survivors": []}

        source = path.read_text(encoding="utf-8")
        baseline = evolution.Scorecard.run_cases(path, suite)
        if baseline.get("ok", 0) < len(suite):
            return {
                "ok": True,
                "module": module,
                "mutants": 0,
                "killed": 0,
                "kill_rate": 0.0,
                "survivors": [],
                "note": "Bazowe przypadki bench jeszcze nie przechodzą w 100%.",
            }

        mutants = cls.generate_mutants(source, limit=max_mutants)
        if not mutants:
            return {"ok": True, "module": module, "mutants": 0, "killed": 0, "kill_rate": 1.0, "survivors": []}

        killed = 0
        survivors = []
        with tempfile.TemporaryDirectory(prefix="jarvis-mut-") as tmp:
            for idx, mut in enumerate(mutants):
                mpath = Path(tmp) / f"{module}_m{idx}.py"
                mpath.write_text(mut["source"], encoding="utf-8")
                res = evolution.Scorecard.run_cases(mpath, suite)
                if res.get("ok", 0) < len(suite):
                    killed += 1
                else:
                    survivors.append({
                        "line": mut["line"],
                        "kind": mut["kind"],
                        "original": mut["original"],
                    })

        rate = round(killed / len(mutants), 3)
        return {
            "ok": True,
            "module": module,
            "mutants": len(mutants),
            "killed": killed,
            "kill_rate": rate,
            "survivors": survivors,
        }


class AdversarialBreaker:
    """Co-evolutionary test generator storing unsealed drafts in `STATE/bench_drafts/`."""

    SYSTEM = (
        "You are an Adversarial QA Breaker for a Python module. Given the module source and "
        "lines where AST mutations survived undetected, write 2 to 4 edge-case held-out tests "
        "that expose boundary bugs or kill surviving mutants. "
        'Return ONLY JSON: {"cases":[{"call":"fn_name","kwargs":{},"expect":"val","level":3}]} '
        '(or use "expect_error": true / "expect_type": "dict"). Never use network.'
    )

    @staticmethod
    def drafts_dir() -> Path:
        d = _state_dir() / "bench_drafts"
        d.mkdir(mode=0o700, parents=True, exist_ok=True)
        return d

    @classmethod
    def generate_draft_cases(cls, module: str, client=None, model: str = "",
                             source_path: Path | None = None) -> dict:
        """Probe surviving mutants & boundary inputs and stage adversarial draft cases safely."""
        path = Path(source_path or (evolution.ROOT / f"{module}.py"))
        if not path.is_file():
            raise evolution.EvolutionError(f"Module not found: {module}.py")

        mut_report = MutationTester.evaluate_suite(module, source_path=path, max_mutants=6)
        source = path.read_text(encoding="utf-8")
        proposed_cases: list[dict] = []

        if client is not None:
            prompt_override = evolution.PromptLab().get("breaker") or cls.SYSTEM
            user_msg = (
                f"Module: {module}.py\n"
                f"Surviving AST mutants (blind spots): {json.dumps(mut_report['survivors'])}\n\n"
                f"Source:\n```python\n{source[:14_000]}\n```"
            )
            try:
                resp = client.messages.create(
                    model=model,
                    max_tokens=1400,
                    system=prompt_override,
                    messages=[{"role": "user", "content": user_msg}],
                    stream=False,
                )
                txt = "\n".join(str(getattr(b, "text", "")) for b in resp.content if getattr(b, "type", "") == "text")
                start = txt.find("{")
                if start >= 0:
                    parsed, _ = json.JSONDecoder().raw_decode(txt[start:])
                    for c in (parsed.get("cases") or []):
                        if isinstance(c, dict) and c.get("call"):
                            c.setdefault("level", 3)
                            proposed_cases.append(c)
            except Exception:
                pass

        if not proposed_cases:
            try:
                tree = ast.parse(source)
                public_fns = [
                    n for n in tree.body
                    if isinstance(n, ast.FunctionDef) and not n.name.startswith("_")
                ]
                for fn in public_fns[:4]:
                    req_args = len(fn.args.args) - len(fn.args.defaults)
                    if req_args == 0:
                        proposed_cases.append({"call": fn.name, "kwargs": {}, "expect_type": "object", "level": 2})
                    elif req_args == 1:
                        arg_name = fn.args.args[0].arg
                        for probe_val in ("", None):
                            proposed_cases.append({"call": fn.name, "kwargs": {arg_name: probe_val}, "expect_type": "object", "level": 3})
            except SyntaxError:
                pass

        verified_drafts = []
        if proposed_cases:
            probe_res = evolution.Scorecard.run_cases(path, proposed_cases[:8])
            for case, res_row in zip(proposed_cases[:8], probe_res.get("results") or []):
                item = dict(case)
                item["current_passes"] = bool(res_row.get("ok"))
                item["detail"] = str(res_row.get("detail") or "")[:160]
                verified_drafts.append(item)

        draft_file = cls.drafts_dir() / f"{module}.draft.json"
        payload = {
            "module": module,
            "created_at": round(time.time(), 3),
            "mutation_report": mut_report,
            "cases": verified_drafts,
        }
        evolution._write_json(draft_file, payload)
        return {"ok": True, "draft_file": str(draft_file), **payload}

    @classmethod
    def promote_draft(cls, module: str, only_passing: bool = True) -> dict:
        """Promote owner-approved adversarial draft cases into `bench/<module>.json` and re-seal."""
        draft_file = cls.drafts_dir() / f"{module}.draft.json"
        draft = evolution._read_json(draft_file, {})
        raw_cases = draft.get("cases") if isinstance(draft, dict) else None
        if not isinstance(raw_cases, list) or not raw_cases:
            raise evolution.EvolutionError(f"Brak szkicu kontradyktoryjnego dla modułu {module}.")

        selected = []
        for c in raw_cases:
            if not isinstance(c, dict) or not c.get("call"):
                continue
            if only_passing and not c.get("current_passes"):
                continue
            clean = {k: v for k, v in c.items() if k not in ("current_passes", "detail")}
            selected.append(clean)

        if not selected:
            return {"ok": True, "module": module, "added": 0, "sealed": False}

        bench_path = evolution.BENCH / f"{module}.json"
        existing_raw = evolution._read_json(bench_path, [])
        existing_list = existing_raw.get("cases") if isinstance(existing_raw, dict) else existing_raw
        if not isinstance(existing_list, list):
            existing_list = []

        merged = list(existing_list) + selected
        evolution.BENCH.mkdir(parents=True, exist_ok=True)
        if isinstance(existing_raw, dict):
            evolution._write_json(bench_path, {**existing_raw, "cases": merged})
        else:
            evolution._write_json(bench_path, merged)
        evolution.Bench.seal()
        evolution.Curriculum.invalidate()
        return {"ok": True, "module": module, "added": len(selected), "total": len(merged), "sealed": True}


# --------------------------------------------------------------------------- #
# 6. Self-Harness Prompt Meta-Evolution & Portable Skill Distillation
# --------------------------------------------------------------------------- #
class SkillDistiller:
    """Distill verified `improved` patches from Archive into reusable Markdown skills."""

    @staticmethod
    def skills_dir() -> Path:
        d = _state_dir() / "distilled_skills"
        d.mkdir(mode=0o700, parents=True, exist_ok=True)
        return d

    @classmethod
    def distill_from_archive(cls, archive: evolution.Archive | None = None, limit: int = 10) -> dict:
        arch = archive or evolution.Archive()
        improved = [
            r for r in arch.rows()
            if r.get("status") == "applied" and r.get("verdict") == "improved"
        ][-limit:]
        written = []
        for row in improved:
            nid = str(row.get("id") or "")
            mod = str(row.get("module") or "general")
            if not nid:
                continue
            skill_path = cls.skills_dir() / f"{mod}-{nid}.md"
            if skill_path.is_file():
                continue
            delta = round(float(row.get("score") or 0.0) - float(row.get("before") or 0.0), 4)
            lessons = evolution.Failures().for_module(mod, limit=3)
            pitfalls = "\n".join(f"- Unikaj: {item['lesson']}" for item in lessons) or "- Brak zarejestrowanych pułapek."
            content = (
                f"# Destylowana umiejętność: `{mod}` (węzeł `{nid}`)\n\n"
                f"- **Wzrost wyniku Scorecard**: `+{delta}` (`{row.get('before')}` -> `{row.get('score')}`)\n"
                f"- **Zastosowany wzorzec**: {row.get('explanation') or 'Ulepszenie zweryfikowane na held-out bench.'}\n\n"
                f"## Pułapki wykryte podczas wcześniejszych prób\n"
                f"{pitfalls}\n\n"
                f"## Bramka weryfikacji\n"
                f"- Uruchom `Scorecard.score('{mod}', Path('{mod}.py'))` oraz `scripts/lint.py`.\n"
            )
            skill_path.write_text(content, encoding="utf-8")
            written.append(skill_path.name)
        return {"ok": True, "created": len(written), "files": written, "total": len(list(cls.skills_dir().glob("*.md")))}

    @classmethod
    def load_for_module(cls, module: str, limit: int = 2) -> str:
        matches = sorted(cls.skills_dir().glob(f"{module}-*.md"))[-limit:]
        if not matches:
            return ""
        bodies = [p.read_text(encoding="utf-8", errors="replace")[:900] for p in matches]
        return "\n\n## Destylowane umiejętności z udanych ewolucji tego modułu\n" + "\n---\n".join(bodies)


class SelfHarness:
    """Evolve PromptLab system prompts from empirical failure patterns with automatic rollback."""

    @staticmethod
    def evolve_prompt_from_failures(key: str = "patcher",
                                    failures: evolution.Failures | None = None,
                                    lab: evolution.PromptLab | None = None) -> dict:
        prompt_lab = lab or evolution.PromptLab()
        fail_store = failures or evolution.Failures()
        base = evolution.PROMPT_DEFAULTS.get(key)
        if not base:
            raise evolution.EvolutionError(f"Unknown prompt key: {key}")

        top_failures = sorted(
            fail_store.rows(),
            key=lambda r: (int(r.get("count") or 1), float(r.get("ts") or 0)),
            reverse=True,
        )[:5]
        if not top_failures:
            return {"ok": True, "key": key, "updated": False, "prompt": prompt_lab.get(key)}

        guard_rules = [
            f"- NEVER repeat known failure ({r.get('module') or 'any'}): {str(r.get('lesson') or '')[:160]}"
            for r in top_failures
        ]
        evolved = base.rstrip() + "\n\nLearned Self-Harness Guardrails:\n" + "\n".join(guard_rules)
        prompt_lab.set(key, evolved)
        return {"ok": True, "key": key, "updated": True, "rules_added": len(guard_rules), "prompt": evolved}

    @staticmethod
    def audit_and_guard_prompt(key: str, archive: evolution.Archive | None = None,
                               lab: evolution.PromptLab | None = None) -> dict:
        """Auto-reset a custom PromptLab override if the last 3 patches all regressed."""
        prompt_lab = lab or evolution.PromptLab()
        arch = archive or evolution.Archive()
        recent = arch.rows()[-3:]
        if len(recent) == 3 and all(r.get("verdict") == "regressed" for r in recent):
            prompt_lab.reset(key)
            return {"ok": True, "key": key, "rolled_back": True}
        return {"ok": True, "key": key, "rolled_back": False}
