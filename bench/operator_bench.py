#!/usr/bin/env python3
"""Operator benchmark cases: the Cua Bench shape, kept deliberately small.

A case is a task plus deterministic assertions on the job's terminal state.
No model judges another model: `--run` starts a real Operator job through the
loopback API and checks the same fields a human would read.

    .venv/bin/python bench/operator_bench.py --list
    .venv/bin/python bench/operator_bench.py --run read_title
    .venv/bin/python bench/operator_bench.py --run all
"""
from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CASES = ROOT / "bench" / "operator_cases.json"
BASE = "http://127.0.0.1:4700"
TERMINAL = {"done", "stopped", "error"}


def load():
    return json.loads(CASES.read_text(encoding="utf-8"))["cases"]


def call(path, payload=None, timeout=30):
    data = json.dumps(payload).encode() if payload is not None else None
    request = urllib.request.Request(BASE + path, data=data,
                                     headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.loads(response.read() or b"{}")
    except urllib.error.URLError as error:
        raise SystemExit(f"Jarvis is not reachable at {BASE}: {error.reason}")


def run_case(case, wait=240):
    started = call("/agent/run", {"task": case["task"], "queue": True})
    job = started.get("operator") or started
    job_id = job.get("id")
    if not job_id:
        return {"name": case["name"], "ok": False, "detail": f"no job id: {started}"}
    deadline = time.time() + wait
    state = job
    while time.time() < deadline:
        snapshot = call(f"/agent/status?job_id={job_id}")
        active = snapshot.get("job")
        if active:
            state = active
            if state.get("status") in TERMINAL:
                break
        else:
            rows = call("/agent/history").get("history") or []
            hit = next((row for row in rows if row.get("id") == job_id), None)
            if hit:
                state = hit
                if hit.get("status") in TERMINAL:
                    break
        time.sleep(3)
    status = state.get("status")
    summary = str(state.get("summary") or "")
    failures = []
    if status != case.get("expect_status", "done"):
        failures.append(f"status={status}")
    for needle in case.get("expect_summary_contains", []):
        if needle.lower() not in summary.lower():
            failures.append(f"summary missing {needle!r}")
    for path, needle in case.get("expect_file", {}).items():
        target = Path(path).expanduser()
        if not target.is_file() or needle not in target.read_text(encoding="utf-8", errors="replace"):
            failures.append(f"file check failed: {target}")
    return {"name": case["name"], "ok": not failures, "detail": "; ".join(failures) or summary[:160]}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--list", action="store_true")
    parser.add_argument("--run", default="")
    parser.add_argument("--wait", type=int, default=240)
    args = parser.parse_args()
    cases = load()
    if args.list or not args.run:
        for case in cases:
            print(f"{case['name']:<16} {case['task'][:90]}")
        print(f"\n{len(cases)} cases; run one with --run <name> or --run all")
        return 0
    selected = cases if args.run == "all" else [c for c in cases if c["name"] == args.run]
    if not selected:
        print(f"No case named {args.run!r}")
        return 2
    results = [run_case(case, args.wait) for case in selected]
    for row in results:
        print(("PASS " if row["ok"] else "FAIL ") + f"{row['name']:<16} {row['detail']}")
    passed = sum(1 for row in results if row["ok"])
    print(f"\n{passed}/{len(results)} operator cases passed")
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
