"""Draft benchmarki dla modułów bez pokrycia: zostawiamy tylko przypadki, które przechodzą.

Uruchomienie: .venv/bin/python tools_draft_bench.py [modul ...]
Bez argumentów bierze wszystkie moduły runtime bez pliku bench/.
Draft nie wchodzi sam do repo — plik powstaje tylko, gdy zostaną co najmniej 3 przechodzące przypadki.
"""
import json
import sys
from pathlib import Path

import self_modify
from provider_client import load_deepseek_key, make_client

PROJECT = Path(__file__).resolve().parent
SKIP = {"self_modify", "evolution", "preflight", "build", "verify", "teardown", "operator_secrets"}
MIN_PASSING = 3


def targets(argv):
    if argv:
        return [name.removesuffix(".py") for name in argv]
    have = {path.stem for path in PROJECT.glob("bench/*.json")}
    return sorted(path.stem for path in PROJECT.glob("*.py")
                  if path.stem not in have and path.stem not in SKIP
                  and not path.stem.startswith("_"))


def main(argv):
    key = load_deepseek_key()
    client = make_client("deepseek", key, timeout=180.0)
    draft = self_modify.BenchDraft(client, self_modify.DEFAULT_MODEL)
    for module in targets(argv):
        try:
            result = draft.draft(module, limit=6)
        except Exception as error:
            print(f"- {module}: {type(error).__name__}: {str(error)[:120]}")
            continue
        good = [case for case in result["cases"] if case.get("draft_ok")]
        for case in good:
            case.pop("draft_ok", None)
        if len(good) < MIN_PASSING:
            line = f"- {module}: {len(good)}/{len(result['cases'])} przechodzi, pomijam"
            print(line)
            continue
        path = PROJECT / "bench" / f"{module}.json"
        existing = []
        if path.is_file():
            try:
                existing = [case for case in json.loads(path.read_text(encoding="utf-8")).get("cases", [])
                            if isinstance(case, dict)]
            except ValueError:
                existing = []
        keys = {(case.get("call"), json.dumps(case.get("kwargs"), sort_keys=True)) for case in existing}
        merged = existing + [case for case in good
                             if (case.get("call"), json.dumps(case.get("kwargs"), sort_keys=True)) not in keys]
        path.write_text(json.dumps({"module": module,
                                    "note": "draft + reczne; tylko przypadki zgodne z obecnym zachowaniem",
                                    "cases": merged}, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"+ {module}: {len(merged)} przypadkow (dodano {len(merged) - len(existing)})")


if __name__ == "__main__":
    main(sys.argv[1:])
