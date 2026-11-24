"""Keep the regression gate honest: no contract test may be orphaned.

`unittest discover` only sees Python. The JavaScript contract tests are run by
small Python wrappers, so a newly added `tests/test_*.js` could silently sit
outside `scripts/check.sh` — which is exactly what happened to the Edge TTS
test until it was wired in.
"""
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class TestInventory(unittest.TestCase):
    def test_every_javascript_contract_test_is_invoked(self):
        sources = "\n".join(path.read_text(encoding="utf-8")
                            for path in (ROOT / "tests").glob("test_*.py"))
        orphaned = sorted(path.name for path in (ROOT / "tests").glob("test_*.js")
                          if path.name not in sources)
        self.assertEqual(orphaned, [], "wire these into a Python test: " + ", ".join(orphaned))


if __name__ == "__main__":
    unittest.main()
