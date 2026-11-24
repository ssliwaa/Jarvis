"""Local office-document builder: DOCX, XLSX, PPTX and PDF.

The libraries are free and run locally. Output is written only under
``~/.jarvis-tools/documents`` with a generated slug; no caller-supplied path is
accepted. Each result is verified by reading the written file signature/size.
"""
from __future__ import annotations

import re
import time
import uuid
from pathlib import Path
from xml.sax.saxutils import escape

DOCS = Path.home() / ".jarvis-tools" / "documents"
MAX_BODY = 20_000
MAX_ROWS = 1_000
MAX_COLUMNS = 20
TEMPLATES = {
    "plain": {"label": "Plain document", "description": "Title and body paragraphs."},
    "report": {"label": "Report", "description": "Title, generated date and body sections."},
    "letter": {"label": "Letter", "description": "Date, salutation, body and signature."},
    "minutes": {"label": "Meeting minutes", "description": "Title, date, attendees line and notes."},
}


def list_templates():
    return [{"name": name, **meta} for name, meta in TEMPLATES.items()]


def _decorate(title: str, body: str, template: str):
    template = str(template or "plain").lower()
    if template not in TEMPLATES:
        raise DocumentError("Unknown template.")
    stamp = time.strftime("%Y-%m-%d")
    if template == "report":
        return [f"Generated {stamp}", "", *body.splitlines()]
    if template == "letter":
        return [stamp, "", "Dear Sir or Madam,", "", *body.splitlines(), "", "Yours faithfully,"]
    if template == "minutes":
        return [f"Date: {stamp}", "", "Attendees:", "", *body.splitlines()]
    return body.splitlines()


class DocumentError(Exception):
    pass


def _slug(value: str) -> str:
    value = re.sub(r"[^a-zA-Z0-9ąćęłńóśźżĄĆĘŁŃÓŚŹŻ _-]+", "", str(value or "")).strip()
    value = re.sub(r"[ _]+", "-", value).strip("-").lower()
    return (value[:60] or "document")


def _filename(title: str, kind: str) -> Path:
    DOCS.mkdir(parents=True, exist_ok=True)
    path = DOCS / f"{_slug(title)}-{time.strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:6]}.{kind}"
    return path


def _spreadsheet_cell(value) -> str:
    """Neutralise spreadsheet formulas typed as text."""
    text = str(value) if value is not None else ""
    if text[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + text
    return text


def _rows(value):
    if value is None:
        return []
    if not isinstance(value, list) or len(value) > MAX_ROWS:
        raise DocumentError("Rows must be a list with at most 1,000 entries.")
    output = []
    for row in value:
        if not isinstance(row, list) or len(row) > MAX_COLUMNS:
            raise DocumentError("Each row must be a list with at most 20 cells.")
        output.append([_spreadsheet_cell(cell) for cell in row])
    return output


def generate(kind: str, title: str, body: str = "", rows=None, template: str = "plain"):
    kind = str(kind or "docx").lower().strip()
    if kind not in ("docx", "xlsx", "pptx", "pdf"):
        raise DocumentError("Kind must be docx, xlsx, pptx or pdf.")
    title = str(title or "Untitled").strip()[:160] or "Untitled"
    body = str(body or "").strip()
    if len(body) > MAX_BODY:
        raise DocumentError("Body is too long.")
    rows = _rows(rows)
    lines = _decorate(title, body, template)
    path = _filename(title, kind)
    try:
        if kind == "docx":
            from docx import Document
            document = Document()
            document.add_heading(title, level=1)
            for paragraph in lines:
                if paragraph.strip():
                    document.add_paragraph(paragraph.strip())
            document.save(str(path))
        elif kind == "xlsx":
            from openpyxl import Workbook
            workbook = Workbook()
            sheet = workbook.active
            sheet.title = "Data"
            for row in rows or [[title], [body]]:
                sheet.append([_spreadsheet_cell(cell) for cell in row])
            workbook.save(str(path))
        elif kind == "pptx":
            from pptx import Presentation
            deck = Presentation()
            slide = deck.slides.add_slide(deck.slide_layouts[0])
            slide.shapes.title.text = title
            slide.placeholders[1].text = "Jarvis · local document"
            if body:
                nonempty = [line.strip() for line in lines if line.strip()]
                chunks, current_title, current_lines, current_chars = [], "Notes", [], 0
                for line in nonempty:
                    heading = re.match(r"^#{1,3}\s+(.+)$", line)
                    if heading:
                        if current_lines:
                            chunks.append((current_title, "\n".join(current_lines)))
                            current_lines, current_chars = [], 0
                        current_title = heading.group(1).strip()[:120] or "Notes"
                        continue
                    if current_lines and current_chars + len(line) > 1200:
                        chunks.append((current_title, "\n".join(current_lines)))
                        current_lines, current_chars = [], 0
                    current_lines.append(line)
                    current_chars += len(line) + 1
                if current_lines:
                    chunks.append((current_title, "\n".join(current_lines)))
                for slide_title, slide_body in (chunks or [("Notes", body[:2000])])[:24]:
                    body_slide = deck.slides.add_slide(deck.slide_layouts[1])
                    body_slide.shapes.title.text = slide_title
                    body_slide.placeholders[1].text = slide_body[:2000]
            deck.save(str(path))
        else:
            from reportlab.lib.pagesizes import A4
            from reportlab.lib.styles import getSampleStyleSheet
            from reportlab.pdfbase import pdfmetrics
            from reportlab.pdfbase.ttfonts import TTFont
            from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer
            styles = getSampleStyleSheet()
            for font_path in ("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
                              "/usr/share/fonts/TTF/DejaVuSans.ttf"):
                if Path(font_path).is_file():
                    try:
                        pdfmetrics.registerFont(TTFont("DejaVuSans", font_path))
                        styles["Title"].fontName = "DejaVuSans"
                        styles["Normal"].fontName = "DejaVuSans"
                    except Exception:
                        pass
                    break
            # ReportLab's Paragraph parses XML; an unescaped <img src="file:...">
            # could embed a local file. Escape everything as literal text.
            story = [Paragraph(escape(title), styles["Title"]), Spacer(1, 12)]
            for paragraph in lines:
                if paragraph.strip():
                    story.append(Paragraph(escape(paragraph.strip()), styles["BodyText"]))
                    story.append(Spacer(1, 6))
            SimpleDocTemplate(str(path), pagesize=A4).build(story)
    except Exception as error:
        try:
            path.unlink()
        except OSError:
            pass
        raise DocumentError(f"Could not generate {kind}: {type(error).__name__}: {error}") from None
    if not path.is_file() or path.stat().st_size < 32:
        raise DocumentError("The generated document failed its size check.")
    with path.open("rb") as handle:
        signature = handle.read(8)
    expected = {"docx": b"PK", "xlsx": b"PK", "pptx": b"PK", "pdf": b"%PDF"}[kind]
    if not signature.startswith(expected):
        path.unlink(missing_ok=True)
        raise DocumentError("The generated document has an invalid signature.")
    return {"ok": True, "kind": kind, "title": title, "template": template, "path": str(path),
            "bytes": path.stat().st_size, "rows": len(rows), "outcome": "done"}


def open_document(name: str, confirm=False):
    if confirm is not True:
        return {"ok": False, "outcome": "refused", "error": "Opening a document requires confirm:true."}
    candidate = (DOCS / str(name or "")).resolve()
    try:
        candidate.relative_to(DOCS.resolve())
    except ValueError:
        raise DocumentError("That document is outside the local document library.")
    if not candidate.is_file() or candidate.suffix.lower() not in (".docx", ".xlsx", ".pptx", ".pdf"):
        raise DocumentError("That document does not exist.")
    import shutil
    import subprocess
    opener = shutil.which("xdg-open")
    if not opener:
        raise DocumentError("xdg-open is not available.")
    subprocess.Popen([opener, str(candidate)], start_new_session=True,
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return {"ok": True, "outcome": "started", "path": str(candidate)}


def list_documents(limit=30):
    if not DOCS.is_dir():
        return []
    def modified(item):
        try:
            return item.stat().st_mtime
        except OSError:
            return 0.0  # a broken symlink must not break the whole listing

    rows = []
    for path in sorted(DOCS.iterdir(), key=modified, reverse=True):
        try:
            if not path.is_file() or path.suffix.lower() not in (".docx", ".xlsx", ".pptx", ".pdf"):
                continue
            stat = path.stat()
        except OSError:
            continue
        rows.append({"name": path.name, "bytes": stat.st_size,
                     "modified": stat.st_mtime, "path": str(path)})
        if len(rows) >= max(1, min(int(limit), 100)):
            break
    return rows
