"""Unit contracts for the isolated OCR runner (surya in its own venv).

The runner is exercised here with a fake CLI binary, so no torch/surya
wheel is needed: the subprocess, staging isolation and results parsing are
the real code paths under test.
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import ocr_runner

FIXTURE_GUIDE = [{"text_lines": [{"text": "PARAGON FIRMAtest"},
                                  {"text": "sum 42,00"}]},
                  {"text_lines": [{"text": "strona druga"}]}]
"""A surya results.json shape as the runner reads it (a list of pages)."""


def fixture_file(tmp, payload=None):
    path = Path(tmp) / "fixture.json"
    path.write_text(json.dumps(payload if payload is not None else FIXTURE_GUIDE,
                               ensure_ascii=False), encoding="utf-8")
    return str(path)


def fake_cli(tmp) -> str:
    """A sh script answering like surya_ocr: OCR the staged dir, drop results."""
    script = Path(tmp) / "surya_ocr-fake"
    script.write_text(
        "#!/bin/sh\n"
        "# $1 input-dir, $3 output-dir: refuse any input dir that holds more\n"
        "# than the one staged file (the old folder-scoped call OCR'd\n"
        "# everything next to the target image).\n"
        "count=$(find \"$1\" -type f | wc -l)\n"
        "if [ \"$count\" -ne 1 ]; then echo \"staged $count files\" >&2; exit 9; fi\n"
        "cp \"$SURYA_FIXTURE\" \"$3/results.json\"\n",
        encoding="utf-8")
    script.chmod(0o755)
    return str(script)


class ProbeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def test_probe_reports_a_working_install(self):
        fake_torch = SimpleNamespace(__version__="2.1.3")
        with mock.patch.dict(sys.modules, {"torch": fake_torch}), \
                mock.patch.object(ocr_runner, "_surya_cli",
                                  return_value=str(Path(self.tmp.name) / "surya_ocr")):
            result = ocr_runner.probe()
        self.assertTrue(result["ok"])
        self.assertTrue(result["surya"])
        self.assertEqual(result["torch"], "2.1.3")

    def test_probe_reports_missing_torch_as_unavailable(self):
        with mock.patch.dict(sys.modules, {"torch": None}), \
                mock.patch.object(ocr_runner, "_surya_cli", return_value="/x/surya_ocr"):
            result = ocr_runner.probe()
        self.assertFalse(result["ok"])
        self.assertFalse(result["surya"])
        self.assertIn("torch", result["error"])

    def test_probe_reports_a_missing_cli(self):
        fake_torch = SimpleNamespace(__version__="2.1.3")
        with mock.patch.dict(sys.modules, {"torch": fake_torch}), \
                mock.patch.object(ocr_runner, "_surya_cli", return_value=""):
            result = ocr_runner.probe()
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"], "surya_ocr CLI not installed")


class ReadResultsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def test_pages_are_joined_and_garbage_is_skipped(self):
        deep = Path(self.tmp.name) / "ocr" / "page-two"
        deep.mkdir(parents=True)
        (deep / "results.json").write_text(json.dumps(FIXTURE_GUIDE), encoding="utf-8")
        (deep / "broken.json").write_bytes(b"{nope")
        self.assertEqual(ocr_runner._read_results(self.tmp.name),
                         "PARAGON FIRMAtest\nsum 42,00\nstrona druga")

    def test_an_empty_or_absent_results_tree_yields_empty_text(self):
        self.assertEqual(ocr_runner._read_results(self.tmp.name), "")
        (Path(self.tmp.name) / "empty.json").write_text(json.dumps([]), encoding="utf-8")
        self.assertEqual(ocr_runner._read_results(self.tmp.name), "")

    def test_a_page_object_beats_a_broken_sibling(self):
        # The first folder with usable text wins; later junk never overwrites it.
        page_one = Path(self.tmp.name) / "a"
        page_two = Path(self.tmp.name) / "b"
        page_one.mkdir()
        page_two.mkdir()
        (page_one / "1.json").write_text(json.dumps(
            {"text_lines": [{"text": "winner"}]}), encoding="utf-8")
        (page_two / "2.json").write_text(json.dumps(FIXTURE_GUIDE), encoding="utf-8")  # later in sort
        self.assertEqual(ocr_runner._read_results(self.tmp.name), "winner")


class RunTextTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.fixture = fixture_file(self.tmp.name)

    def test_the_staged_input_dir_holds_exactly_one_file(self):
        # The fake CLI exits 9 when the input dir holds more than one file:
        # the folder-scoped call used to OCR everything next to the target.
        image = Path(self.tmp.name) / "receipt.png"
        image.write_bytes(b"png")
        (Path(self.tmp.name) / "INNOCENT.txt").write_text("must never be OCR'd")
        with mock.patch.object(ocr_runner, "_surya_cli", return_value=fake_cli(self.tmp.name)), \
                mock.patch.dict(os.environ, {"SURYA_FIXTURE": self.fixture}):
            result = ocr_runner.run_text({"path": str(image)})
        self.assertTrue(result["ok"], result.get("error"))
        self.assertIn("sum 42,00", result["text"])
        self.assertEqual(result["engine"], "surya")

    def test_a_missing_file_fails_without_spawning(self):
        with mock.patch.object(ocr_runner, "_surya_cli", return_value=fake_cli(self.tmp.name)):
            result = ocr_runner.run_text({"path": str(Path(self.tmp.name) / "nope.png")})
        self.assertEqual(result, {"ok": False, "error": "file not found"})

    def test_a_missing_cli_fails_without_spawning(self):
        image = Path(self.tmp.name) / "receipt.png"
        image.write_bytes(b"png")
        with mock.patch.object(ocr_runner, "_surya_cli", return_value=""):
            result = ocr_runner.run_text({"path": str(image)})
        self.assertEqual(result, {"ok": False, "error": "surya_ocr CLI not installed"})

    def test_a_failing_cli_passes_stderr_through(self):
        image = Path(self.tmp.name) / "receipt.png"
        image.write_bytes(b"png")
        cli = fake_cli(self.tmp.name)
        boom = Path(self.tmp.name) / "surya_ocr-boom"
        boom.write_text("#!/bin/sh\necho 'CUDA out of memory' >&2\nexit 3\n", encoding="utf-8")
        boom.chmod(0o755)
        with mock.patch.object(ocr_runner, "_surya_cli", return_value=str(boom)):
            result = ocr_runner.run_text({"path": str(image)})
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"], "CUDA out of memory")
        self.assertIsInstance(cli, str)  # the healthy fixture stays unused

    def test_a_hanging_cli_times_out(self):
        image = Path(self.tmp.name) / "receipt.png"
        image.write_bytes(b"png")
        expired = subprocess.TimeoutExpired(cmd="surya_ocr", timeout=300)
        with mock.patch.object(ocr_runner, "_surya_cli", return_value="surya_ocr"), \
                mock.patch.object(ocr_runner.subprocess, "run", side_effect=expired):
            result = ocr_runner.run_text({"path": str(image)})
        self.assertEqual(result["ok"], False)
        self.assertEqual(result["error"], "surya timed out")

    def test_the_runner_tears_down_its_tmp_tree(self):
        image = Path(self.tmp.name) / "receipt.png"
        image.write_bytes(b"png")
        leftovers = []
        real_rmtree = ocr_runner.shutil.rmtree
        with mock.patch.object(ocr_runner, "_surya_cli", return_value=fake_cli(self.tmp.name)), \
                mock.patch.dict(os.environ, {"SURYA_FIXTURE": self.fixture}), \
                mock.patch.object(ocr_runner.shutil, "rmtree", side_effect=lambda p, **_: leftovers.append(p) or real_rmtree(p, **_)):
            ocr_runner.run_text({"path": str(image)})
        self.assertEqual(len(leftovers), 1)
        self.assertFalse(os.path.exists(leftovers[0]))
        self.assertTrue(os.path.basename(leftovers[0]).startswith("jarvis-surya-"))


if __name__ == "__main__":
    unittest.main()
