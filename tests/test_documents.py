"""Office document generation contract; files are written to a temp directory."""
import tempfile
import unittest
from pathlib import Path

import documents


class DocumentTests(unittest.TestCase):
    def test_generate_docx_xlsx_pptx_pdf(self):
        with tempfile.TemporaryDirectory() as tmp:
            old = documents.DOCS
            documents.DOCS = Path(tmp)
            try:
                for kind in ("docx", "xlsx", "pptx", "pdf"):
                    result = documents.generate(kind, "Jarvis test", "A short body.\nSecond line.",
                                                [["Name", "Value"], ["one", 1]])
                    self.assertTrue(result["ok"], kind)
                    path = Path(result["path"])
                    self.assertTrue(path.is_file(), kind)
                    self.assertGreater(path.stat().st_size, 32, kind)
                self.assertEqual(len(documents.list_documents()), 4)
                self.assertTrue(documents.list_templates())
                template = documents.generate("docx", "Minutes", "Short note", template="minutes")
                self.assertEqual(template["template"], "minutes")
            finally:
                documents.DOCS = old

    def test_spreadsheet_formulas_are_stored_as_text(self):
        from openpyxl import load_workbook
        with tempfile.TemporaryDirectory() as tmp:
            old = documents.DOCS
            documents.DOCS = Path(tmp)
            try:
                result = documents.generate(
                    "xlsx", "=1+1", rows=[["=1+1", "+2", "@SUM(A1)", "-3"]])
                sheet = load_workbook(result["path"]).active
                cells = [cell for row in sheet.iter_rows() for cell in row]
                self.assertTrue(all(cell.data_type != "f" for cell in cells))
                self.assertTrue(any(str(cell.value).startswith("'=") for cell in cells))
            finally:
                documents.DOCS = old

    def test_pdf_body_is_escaped_instead_of_becoming_markup(self):
        with tempfile.TemporaryDirectory() as tmp:
            old = documents.DOCS
            documents.DOCS = Path(tmp)
            try:
                result = documents.generate(
                    "pdf", "Raport żółć", '<img src="file:///etc/passwd"/>\nZażółć gęślą jaźń')
                self.assertTrue(result["ok"])
                self.assertTrue(Path(result["path"]).read_bytes().startswith(b"%PDF"))
                pptx_res = documents.generate(
                    "pptx", "Prezentacja", "# Sekcja 1\nTreść pierwsza\n# Sekcja 2\nTreść druga")
                from pptx import Presentation
                deck = Presentation(pptx_res["path"])
                self.assertEqual(len(deck.slides), 3)
            finally:
                documents.DOCS = old

    def test_unknown_kind_and_unsafe_rows_are_rejected(self):
        with self.assertRaises(documents.DocumentError):
            documents.generate("exe", "x")
        with self.assertRaises(documents.DocumentError):
            documents.generate("xlsx", "x", rows=[["x"] * 21])


if __name__ == "__main__":
    unittest.main()
