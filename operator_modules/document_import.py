"""Preview an office document before anything is written to the vault.

Extraction is delegated to ``document_extract.extract_document``; this module
only validates the path, bounds the preview and reports what it found. It never
writes a note: saving stays on the single existing door (``remember`` →
``Application.capture_note``), so a document preview cannot create a second
write path into the Sejf.

Document content is untrusted data. Instructions found inside a file are data,
not commands.
"""
from __future__ import annotations

import re
from pathlib import Path

import document_extract

MAX_PREVIEW_CHARS = 4000
MAX_OUTLINE_LINES = 24
_ALLOWED_ROOTS = None  # resolved lazily from Path.home()/tmp so tests stay portable


def _allowed_roots():
    import tempfile
    return [Path.home(), Path('/tmp'), Path('/mnt'), Path('/media'), Path(tempfile.gettempdir())]


def _resolve(path):
    if not isinstance(path, str) or not path.strip():
        raise ValueError('A document path is required.')
    if '\x00' in path or len(path) > 4096:
        raise ValueError('That document path is not valid.')
    target = Path(path.strip()).expanduser()
    if not target.is_absolute() or '..' in target.parts or target == Path('/'):
        raise ValueError('Choose an absolute document path.')
    roots = _allowed_roots()
    matches = [root for root in roots if target == root or root in target.parents]
    if not matches:
        raise ValueError('Document is outside the permitted folders.')
    # Only the path below the deepest permitted root is inspected: the temporary
    # directory itself can legitimately sit inside a dot-directory.
    anchor = max(matches, key=lambda item: len(item.parts))
    if any(part.startswith('.') for part in target.relative_to(anchor).parts):
        raise ValueError('Hidden paths are not read.')
    if not target.exists() or not target.is_file():
        raise ValueError('That document does not exist.')
    if target.is_symlink():
        raise ValueError('Symlinked documents are not read.')
    if not document_extract.is_supported(target):
        raise ValueError('That document format is not supported.')
    return target


def _outline(text):
    """A bounded structural sketch: first meaningful line of each block."""
    lines = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if len(line) > 120:
            line = line[:117] + '...'
        lines.append(line)
        if len(lines) >= MAX_OUTLINE_LINES:
            break
    return lines


def _suggested_title(target, text):
    for raw in text.splitlines():
        line = re.sub(r'\s+', ' ', raw).strip()
        if 3 <= len(line) <= 80 and not line.endswith(('.', ',', ';')):
            return line
    return target.stem.replace('_', ' ').replace('-', ' ').strip() or 'Imported document'


def document_import_handler(arguments, context=None):
    del context
    args = arguments or {}
    try:
        target = _resolve(args.get('path'))
        extracted = document_extract.extract_document(target)
    except (ValueError, document_extract.DocumentError) as error:
        return {'ok': False, 'error': str(error), 'written': False}
    text = extracted['text']
    return {
        'ok': True,
        'format': extracted['format'],
        'bytes': extracted['bytes'],
        'truncated': extracted['truncated'],
        'text': text[:MAX_PREVIEW_CHARS],
        'outline': _outline(text),
        'suggested_title': _suggested_title(target, text),
        'written': False,
        'note': ('Preview only; nothing was written. Use remember to save the summary '
                 'through the existing vault path.'),
    }


TOOL = {
    'name': 'document_import',
    'description': ('Preview text and structure of a local DOCX/XLSX/PPTX/IPYNB/SQLite file '
                    'before saving it. Read-only: it never writes to the Sejf; use remember to save.'),
    'input_schema': {
        'type': 'object',
        'properties': {'path': {'type': 'string', 'description': 'Absolute path to the document.'}},
        'required': ['path'],
        'additionalProperties': False,
    },
    'handler': document_import_handler,
    'approval': False,
}
