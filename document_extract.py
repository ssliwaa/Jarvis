"""Bounded text extraction for office documents and SQLite databases.

The format coverage and limits are adapted from Hermes Agent's
``tools/read_extract.py`` (MIT, Nous Research), reduced to the standard library:
DOCX, XLSX, Jupyter notebooks and SQLite. PDF and legacy Office stay with the
existing ``read_pdf``/OCR lanes. Nothing here executes document content, and
every archive member and output is capped before it reaches the model.
"""
from __future__ import annotations

import json
import re
import sqlite3
import zipfile
from pathlib import Path
from xml.etree import ElementTree as ET

MAX_DOCUMENT_BYTES = 32 * 1024 * 1024
MAX_MEMBER_BYTES = 16 * 1024 * 1024
MAX_OUTPUT_CHARS = 200_000
MAX_DB_ROWS = 200
SUPPORTED_EXTENSIONS = frozenset({".docx", ".xlsx", ".pptx", ".ipynb", ".db", ".sqlite", ".sqlite3"})

_W = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"
_S = "{http://schemas.openxmlformats.org/spreadsheetml/2006/main}"
_R = "{http://schemas.openxmlformats.org/officeDocument/2006/relationships}"
_PKG_R = "{http://schemas.openxmlformats.org/package/2006/relationships}"


class DocumentError(Exception):
    """A document could not be rendered as text; callers fall back to binary."""


def is_supported(path) -> bool:
    return Path(str(path)).suffix.casefold() in SUPPORTED_EXTENSIONS


def _safe_xml(raw: bytes):
    # ElementTree does not resolve external entities, but rejecting DTDs outright
    # keeps entity-expansion tricks out of the parser before they can amplify.
    if b"<!DOCTYPE" in raw[:4096].upper() or b"<!ENTITY" in raw[:4096].upper():
        raise DocumentError("XML document declarations are not accepted.")
    try:
        return ET.fromstring(raw)
    except ET.ParseError as error:
        raise DocumentError("The document XML could not be parsed.") from error


def _read_member(archive: zipfile.ZipFile, name: str) -> bytes:
    try:
        info = archive.getinfo(name)
    except KeyError:
        raise DocumentError(f"The document is missing {name}.") from None
    if info.file_size > MAX_MEMBER_BYTES:
        raise DocumentError("A document member is too large to extract.")
    with archive.open(info) as handle:
        raw = handle.read(MAX_MEMBER_BYTES + 1)
    if len(raw) > MAX_MEMBER_BYTES:
        raise DocumentError("A document member is too large to extract.")
    return raw


def _docx_text(path: Path) -> str:
    try:
        with zipfile.ZipFile(path) as archive:
            root = _safe_xml(_read_member(archive, "word/document.xml"))
    except (OSError, zipfile.BadZipFile) as error:
        raise DocumentError("The DOCX archive could not be read.") from error
    lines = []
    for paragraph in root.iter(f"{_W}p"):
        parts = []
        for node in paragraph.iter():
            if node.tag == f"{_W}t" and node.text:
                parts.append(node.text)
            elif node.tag == f"{_W}tab":
                parts.append("\t")
            elif node.tag == f"{_W}br":
                parts.append("\n")
        text = "".join(parts).strip()
        if text:
            lines.append(text)
    return "\n".join(lines)


def _column_index(reference: str) -> int:
    letters = re.match(r"[A-Z]+", reference or "", re.I)
    if not letters:
        return 0
    value = 0
    for character in letters.group(0).upper():
        value = value * 26 + (ord(character) - 64)
    return max(0, value - 1)


def _xlsx_text(path: Path) -> str:
    try:
        with zipfile.ZipFile(path) as archive:
            shared = []
            if "xl/sharedStrings.xml" in archive.namelist():
                root = _safe_xml(_read_member(archive, "xl/sharedStrings.xml"))
                for item in root.iter(f"{_S}si"):
                    shared.append("".join(node.text or "" for node in item.iter(f"{_S}t")))
            workbook = _safe_xml(_read_member(archive, "xl/workbook.xml"))
            rels = _safe_xml(_read_member(archive, "xl/_rels/workbook.xml.rels"))
            targets = {
                node.get("Id"): node.get("Target", "")
                for node in rels.iter(f"{_PKG_R}Relationship")
            }
            sheets = []
            for sheet in workbook.iter(f"{_S}sheet"):
                name = str(sheet.get("name") or "Sheet")[:80]
                target = targets.get(sheet.get(f"{_R}id"), "")
                target = target.lstrip("/")
                if target and not target.startswith("xl/"):
                    target = "xl/" + target
                if target and target in archive.namelist():
                    sheets.append((name, target))
            if not sheets:
                sheets = [(f"Sheet {index + 1}", name)
                          for index, name in enumerate(sorted(
                              item for item in archive.namelist()
                              if item.startswith("xl/worksheets/sheet") and item.endswith(".xml")))]
            output = []
            for name, member in sheets:
                root = _safe_xml(_read_member(archive, member))
                output.append(f"## {name}")
                rows_written = 0
                for row in root.iter(f"{_S}row"):
                    values = {}
                    for cell in row.iter(f"{_S}c"):
                        column = _column_index(str(cell.get("r") or ""))
                        if column >= 64:
                            continue
                        kind = cell.get("t")
                        raw = cell.find(f"{_S}v")
                        inline = cell.find(f"{_S}is")
                        if kind == "s" and raw is not None:
                            try:
                                value = shared[int(raw.text or "0")]
                            except (ValueError, IndexError):
                                value = ""
                        elif kind == "inlineStr" and inline is not None:
                            value = "".join(node.text or "" for node in inline.iter(f"{_S}t"))
                        else:
                            value = raw.text if raw is not None else ""
                        values[column] = str(value or "")
                    if values:
                        width = min(max(values) + 1, 64)
                        output.append("\t".join(values.get(index, "") for index in range(width)).rstrip())
                        rows_written += 1
                        if rows_written >= MAX_DB_ROWS:
                            output.append("[… sheet truncated …]")
                            break
                output.append("")
            return "\n".join(output).strip()
    except (OSError, zipfile.BadZipFile) as error:
        raise DocumentError("The XLSX archive could not be read.") from error


def _pptx_text(path: Path) -> str:
    try:
        from pptx import Presentation
    except Exception:
        raise DocumentError("The PPTX reader is not installed.") from None
    try:
        deck = Presentation(str(path))
        output = []
        for number, slide in enumerate(deck.slides, 1):
            output.append(f"## Slide {number}")
            for shape in slide.shapes:
                text = getattr(shape, "text", "")
                if isinstance(text, str) and text.strip():
                    output.append(text.strip())
            if slide.has_notes_slide:
                notes = slide.notes_slide.notes_text_frame.text
                if notes.strip():
                    output.append(f"[notes] {notes.strip()}")
        return "\n".join(output)
    except Exception as error:
        raise DocumentError("The PPTX could not be read.") from error


def _ipynb_text(path: Path) -> str:
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError) as error:
        raise DocumentError("The notebook JSON could not be read.") from error
    cells = data.get("cells") if isinstance(data, dict) else None
    if not isinstance(cells, list):
        raise DocumentError("The notebook has no cells.")
    output = []
    for number, cell in enumerate(cells[:2000], 1):
        if not isinstance(cell, dict):
            continue
        source = cell.get("source")
        if isinstance(source, list):
            source = "".join(str(part) for part in source)
        source = str(source or "").strip()
        if not source:
            continue
        kind = str(cell.get("cell_type") or "cell")
        output.append(f"### {kind} {number}\n{source}")
        if kind == "code":
            for result in (cell.get("outputs") or [])[:20]:
                if not isinstance(result, dict):
                    continue
                text = result.get("text")
                if isinstance(text, list):
                    text = "".join(str(part) for part in text)
                if text:
                    output.append(f"[output]\n{str(text)[:4000]}")
    return "\n\n".join(output)


def _sqlite_text(path: Path) -> str:
    try:
        connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=2)
    except sqlite3.Error as error:
        raise DocumentError("The SQLite database could not be opened.") from error
    try:
        connection.execute("PRAGMA query_only=ON")
        tables = [
            str(row[0]) for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' "
                "AND name NOT LIKE 'sqlite_%' ORDER BY name LIMIT 50")
        ]
        output = []
        for table in tables:
            quoted = '"' + table.replace('"', '""') + '"'
            output.append(f"## {table}")
            try:
                cursor = connection.execute(f"SELECT * FROM {quoted} LIMIT {MAX_DB_ROWS}")
                columns = [description[0] for description in cursor.description or ()]
                output.append("\t".join(str(column) for column in columns))
                for row in cursor:
                    output.append("\t".join("" if value is None else str(value)[:500]
                                            for value in row))
            except sqlite3.Error as error:
                output.append(f"[table could not be read: {type(error).__name__}]")
        return "\n".join(output)
    finally:
        connection.close()


def extract_document(path, limit: int = MAX_OUTPUT_CHARS) -> dict:
    """Return ``{text, format, bytes, truncated}`` for a supported local file."""
    target = Path(path)
    try:
        info = target.stat()
    except OSError as error:
        raise DocumentError("The document could not be read.") from error
    if not target.is_file():
        raise DocumentError("That path is not a regular file.")
    if info.st_size > MAX_DOCUMENT_BYTES:
        raise DocumentError("The document is too large to extract.")
    suffix = target.suffix.casefold()
    if suffix == ".docx":
        text, fmt = _docx_text(target), "docx"
    elif suffix == ".xlsx":
        text, fmt = _xlsx_text(target), "xlsx"
    elif suffix == ".pptx":
        text, fmt = _pptx_text(target), "pptx"
    elif suffix == ".ipynb":
        text, fmt = _ipynb_text(target), "ipynb"
    elif suffix in {".db", ".sqlite", ".sqlite3"}:
        text, fmt = _sqlite_text(target), "sqlite"
    else:
        raise DocumentError("That document format is not supported.")
    limit = max(1, min(int(limit or MAX_OUTPUT_CHARS), MAX_OUTPUT_CHARS))
    text = str(text or "")
    return {"text": text[:limit], "format": fmt, "bytes": info.st_size,
            "truncated": len(text) > limit}
