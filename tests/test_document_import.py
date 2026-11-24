import tempfile
import unittest
from pathlib import Path

from docx import Document

from operator_modules import document_import


class DocumentImportTests(unittest.TestCase):
    def test_docx_preview_extracts_real_document_without_vault_write(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            vault = root / 'vault'
            vault.mkdir()
            (vault / 'existing.md').write_text('untouched', encoding='utf-8')
            source = root / 'input.docx'
            document = Document()
            document.add_paragraph('A real document with Polish: zażółć')
            document.save(source)
            result = document_import.document_import_handler({'path': str(source)}, context={})
            self.assertTrue(result['ok'])
            self.assertEqual(result['format'], 'docx')
            self.assertIn('zażółć', result['text'])
            self.assertFalse(result['written'])
            self.assertEqual((vault / 'existing.md').read_text(encoding='utf-8'), 'untouched')
            self.assertEqual(sorted(p.name for p in vault.iterdir()), ['existing.md'])


if __name__ == '__main__':
    unittest.main()
