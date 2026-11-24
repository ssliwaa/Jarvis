"""OCR engine selection: tesseract layout blocks and the surya bridge."""
import os
import subprocess
import tempfile
import unittest
from unittest import mock

import ocr_backends
import operator_tools as ops

TSV = "\n".join([
    "level\tpage_num\tblock_num\tpar_num\tline_num\tword_num\tleft\ttop\twidth\theight\tconf\ttext",
    "1\t1\t0\t0\t0\t0\t0\t0\t640\t220\t-1\t",
    "5\t1\t1\t1\t1\t1\t30\t40\t80\t28\t94.3\tJarvis",
    "5\t1\t1\t1\t1\t2\t115\t40\t115\t28\t91.0\tOCR",
    "5\t1\t1\t1\t1\t3\t235\t40\t38\t28\t88.0\ttest",
    "5\t1\t1\t1\t2\t1\t30\t110\t390\t25\t90.5\tdrugalinia",
    "5\t1\t1\t1\t2\t2\t430\t110\t80\t25\t5.0\tnoise",
])


def completed(stdout):
    return subprocess.CompletedProcess(args=["tesseract"], returncode=0, stdout=stdout, stderr="")


class LayoutTests(unittest.TestCase):
    def setUp(self):
        self.ocr = ops.Ocr()
        self.ocr.binary = "/usr/bin/tesseract"
        handle, self.image = tempfile.mkstemp(suffix=".png")
        os.close(handle)
        self.addCleanup(os.unlink, self.image)

    def test_tsv_is_grouped_into_lines_with_boxes(self):
        with mock.patch.object(self.ocr, "languages", return_value=["eng", "pol"]), \
                mock.patch.object(subprocess, "run", return_value=completed(TSV)):
            result = self.ocr.layout(self.image)
        self.assertEqual(result["engine"], "tesseract-layout")
        self.assertEqual(len(result["lines"]), 2)
        self.assertEqual(result["lines"][0]["text"], "Jarvis OCR test")
        self.assertEqual(result["lines"][1]["text"], "drugalinia")
        self.assertEqual(result["lines"][0]["bbox"], [30, 40, 273, 68])
        self.assertNotIn("noise", result["text"])

    def test_low_confidence_words_are_dropped(self):
        with mock.patch.object(self.ocr, "languages", return_value=["eng"]), \
                mock.patch.object(subprocess, "run", return_value=completed(TSV)):
            result = self.ocr.layout(self.image)
        self.assertNotIn("noise", " ".join(line["text"] for line in result["lines"]))

    def test_missing_binary_is_reported(self):
        self.ocr.binary = None
        with self.assertRaises(ops.ToolError):
            self.ocr.layout(self.image)


class SuryaBridgeTests(unittest.TestCase):
    def setUp(self):
        self.ocr = ops.Ocr()
        if not self.ocr.binary:
            self.skipTest("no local tesseract binary to fall back to")
        handle, self.image = tempfile.mkstemp(suffix=".png")
        os.close(handle)
        self.addCleanup(os.unlink, self.image)

    def test_unavailable_surya_fails_closed_with_a_reason(self):
        with mock.patch.object(ocr_backends, "text", return_value=None), \
                mock.patch.object(ocr_backends, "status",
                                  return_value={"installed": True, "ready": False,
                                                "error": "surya_ocr CLI not installed"}):
            with self.assertRaises(ops.ToolError) as caught:
                self.ocr.text(self.image, engine="surya")
        self.assertIn("surya_ocr CLI not installed", str(caught.exception))

    def test_auto_falls_back_to_tesseract(self):
        with mock.patch.object(ocr_backends, "text", return_value=None), \
                mock.patch.object(self.ocr, "languages", return_value=["eng"]), \
                mock.patch.object(subprocess, "run", return_value=completed("hello world\n")):
            result = self.ocr.text(self.image, engine="auto")
        self.assertEqual(result["engine"], "tesseract")
        self.assertEqual(result["words"], 2)


if __name__ == "__main__":
    unittest.main()
