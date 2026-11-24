"""document_extract: the operator read path for binary office formats.

`operator_tools.FileOps.read()` routes supported documents through here, so
the parser must be pinned: format dispatch, broken archives, truncation and
the extracted content of real minimal DOCX/XLSX containers built inline.
"""
import unittest
import zipfile
from pathlib import Path

import document_extract

DOC_XML = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
    "<w:body>"
    "<w:p><w:r><w:t>First paragraph.</w:t></w:r></w:p>"
    "<w:p><w:r><w:t>tab</w:t><w:tab/><w:t>br</w:t><w:br/><w:t>end</w:t></w:r></w:p>"
    "</w:body></w:document>"
)

SHARED_XML = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<x:sst xmlns:x="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
    '<x:si><x:t>alpha</x:t></x:si><x:si><x:t>beta</x:t></x:si></x:sst>'
)
WORKBOOK_XML = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<w:workbook xmlns:w="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
    'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
    '<w:sheets><w:sheet name="Data" r:id="rId1"/></w:sheets></w:workbook>'
)
RELS_XML = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
    '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet"'
    ' Target="worksheets/sheet1.xml"/></Relationships>'
)
SHEET_XML = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<x:worksheet xmlns:x="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
    '<x:sheetData><x:row r="1">'
    '<x:c r="A1" t="s"><x:v>0</x:v></x:c>'
    '<x:c r="C1" t="inlineStr"><x:is><x:t>gamma</x:t></x:is></x:c>'
    "</x:row></x:sheetData></x:worksheet>"
)


def build_docx(target: Path) -> Path:
    with zipfile.ZipFile(target, "w") as archive:
        archive.writestr("word/document.xml", DOC_XML)
    return target


def build_xlsx(target: Path) -> Path:
    with zipfile.ZipFile(target, "w") as archive:
        archive.writestr("xl/sharedStrings.xml", SHARED_XML)
        archive.writestr("xl/workbook.xml", WORKBOOK_XML)
        archive.writestr("xl/_rels/workbook.xml.rels", RELS_XML)
        archive.writestr("xl/worksheets/sheet1.xml", SHEET_XML)
    return target


class IsSupportedTests(unittest.TestCase):
    def test_supported_extensions_match_the_contract(self):
        for ext in (".docx", ".xlsx", ".pptx", ".ipynb", ".db", ".sqlite", ".sqlite3"):
            self.assertTrue(document_extract.is_supported(f"x{ext}"), ext)
        self.assertTrue(document_extract.is_supported("UPPER.DOCX"))

    def test_plain_and_executable_files_are_not_supported(self):
        for name in ("a.txt", "a.md", "a.exe", "noext", "a.docx.bak"):
            self.assertFalse(document_extract.is_supported(name), name)


class ContainerExtractionTests(unittest.TestCase):
    def test_docx_paragraphs_tab_and_break(self, tmp_path=None):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            path = build_docx(Path(tmp) / "d.docx")
            size = path.stat().st_size
            out = document_extract.extract_document(path)
        self.assertEqual(out["format"], "docx")
        self.assertFalse(out["truncated"])
        self.assertEqual(out["text"].splitlines()[0], "First paragraph.")
        self.assertIn("tab\tbr", out["text"])
        self.assertIn("br\nend", out["text"])
        self.assertEqual(out["bytes"], size)

    def test_xlsx_shared_and_inline_strings(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            path = build_xlsx(Path(tmp) / "s.xlsx")
            out = document_extract.extract_document(path)
        self.assertEqual(out["format"], "xlsx")
        text = out["text"]
        self.assertIn("Data", text)              # sheet name header
        self.assertIn("alpha", text)             # shared string index 0 at A1
        self.assertIn("gamma", text)             # inline string at C1
        self.assertIn("\t", text)                # tab-joined row columns

    def test_unsupported_suffix_is_rejected_without_reading(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "notes.txt"
            path.write_text("hello", encoding="utf-8")
            with self.assertRaises(document_extract.DocumentError):
                document_extract.extract_document(path)

    def test_broken_archive_raises_a_document_error(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            broken = Path(tmp) / "broken.docx"
            broken.write_bytes(b"definitely not a zip file")
            with self.assertRaises(document_extract.DocumentError):
                document_extract.extract_document(broken)

    def test_missing_file_raises_a_document_error(self):
        with self.assertRaises(document_extract.DocumentError):
            document_extract.extract_document("/nonexistent/hopefully/missing.docx")

    def test_limit_truncates_and_flags(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            path = build_docx(Path(tmp) / "d.docx")
            out = document_extract.extract_document(path, limit=3)
        self.assertTrue(out["truncated"])
        self.assertLessEqual(len(out["text"]), 3)


if __name__ == "__main__":
    import unittest
    unittest.main()
