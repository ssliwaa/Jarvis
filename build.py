#!/usr/bin/env python3
"""Index a markdown vault into a browser-readable galaxy (Python stdlib only)."""
from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import sys
from bisect import bisect_right
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
# The vault is user data and never ships with the repo; default to ~/notes
# and override with JARVIS_VAULT. No personal absolute paths here.
NOTES_ROOT = Path(os.environ.get('JARVIS_VAULT', str(Path.home() / 'notes'))).expanduser()
EXCERPT_LENGTH = 700


def redact_secrets(text: str) -> str:
    """Scrub common credential formats before excerpts or retrieval leave disk.

    Best effort, not a DLP guarantee: keep genuinely sensitive material outside
    this vault. The private application config is never scanned or served.
    """
    text = re.sub(r'\b(?:sk-[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9_]{20,}|'
                  r'github_pat_[A-Za-z0-9_]{20,}|AKIA[A-Z0-9]{16})\b', '[REDACTED]', text)
    assignment = re.compile(
        r'''(?im)(["']?\b[a-z0-9_]*(?:api[_-]?key|access[_-]?token|auth[_-]?token|'''
        r'''client[_-]?secret|password|passwd)\b["']?\s*[:=]\s*)'''
        r'''(?:"[^"\r\n]*"|'[^'\r\n]*'|[^\s,;}]+)''')
    text = assignment.sub(lambda match: match.group(1) + '"[REDACTED]"', text)
    return re.sub(r'(?i)(\bBearer\s+)[A-Za-z0-9._~-]{16,}', r'\1[REDACTED]', text)


def note_excerpt(content: str) -> str:
    """Show note prose rather than front matter, ids or a repeated heading."""
    content = re.sub(r'\A---\r?\n.*?\r?\n---(?:\r?\n|$)', '', content, count=1, flags=re.S)
    content = re.sub(r'\A\s*#{1,6}[^\n]*(?:\n|$)', '', content, count=1)
    return re.sub(r'\s+', ' ', content).strip()[:EXCERPT_LENGTH]


def load_notes(root: Path = NOTES_ROOT) -> list[dict]:
    root = Path(root).expanduser().resolve(strict=True)
    if not root.is_dir():
        raise ValueError('Notes root must be a directory.')
    files = sorted((p for p in root.rglob('*') if p.suffix.casefold() == '.md' and p.is_file()),
                   key=lambda p: p.relative_to(root).as_posix())
    notes = []
    total = 0
    for path in files:
        if not path.resolve().is_relative_to(root):
            raise ValueError('A markdown symlink escapes the notes root.')
        # Bound a single note and the whole build: a runaway or planted file
        # used to be read into RAM in full before any limit existed.
        with path.open('rb') as handle:
            raw = handle.read(4 * 1024 * 1024 + 1)
        total += len(raw)
        if total > 64 * 1024 * 1024:
            raise ValueError('The notes tree is too large to build in one pass.')
        if len(raw) > 4 * 1024 * 1024:
            raw = raw[:4 * 1024 * 1024]
        content = redact_secrets(raw.decode('utf-8', errors='replace'))
        excerpt = note_excerpt(content)
        notes.append({'id': len(notes), 'label': redact_secrets(path.stem),
                      'group': redact_secrets(path.parent.name), 'excerpt': excerpt,
                      'path': path.relative_to(root).as_posix(), 'content': content})
    return notes


def wikilinks(text: str) -> set[str]:
    """Aliases and heading/block anchors do not change the linked note target."""
    result = set()
    for target in re.findall(r'\[\[([^\]\n]+)\]\]', text):
        target = target.split('|', 1)[0].split('#', 1)[0].split('^', 1)[0].strip()
        target = target.replace('\\', '/').removesuffix('.md').strip('/')
        if target:
            result.add(target.casefold())
    return result


def make_graph(root: Path = NOTES_ROOT) -> dict:
    return graph_from_notes(load_notes(root))


def graph_from_notes(notes: list[dict]) -> dict:
    """Shared relationship rules; callers may preserve an existing positional order."""
    edges: set[tuple[int, int]] = set()
    references = [wikilinks(note['content']) for note in notes]
    contents = [note['content'].casefold() for note in notes]
    targets: dict[str, set[int]] = {}
    shared: dict[str, set[int]] = {}
    for note in notes:
        for name in (note['label'].casefold(), str(Path(note['path']).with_suffix('')).casefold()):
            targets.setdefault(name, set()).add(note['id'])
    for note in notes:
        index = note['id']
        for reference in references[index]:
            # Explicit path first; fall back to the title as Obsidian does.
            resolved = targets.get(reference, targets.get(reference.rsplit('/', 1)[-1], set()))
            for target in resolved:
                if index != target:
                    edges.add(tuple(sorted((index, target))))
            shared.setdefault(reference, set()).add(index)
    for indexes in shared.values():
        ordered = sorted(indexes)
        for position, source in enumerate(ordered):
            for target in ordered[position + 1:]:
                edges.add((source, target))
    # Case-insensitive, whole-title mentions; avoid Run matching runner.
    # One separator-guarded blob scan per title (n C-level regex searches)
    # replaces n x n Python-level pattern.search(content) calls per note pair.
    titles = [(note['id'], note['label'].casefold()) for note in notes]
    titles = [(note_id, title) for note_id, title in titles if title]
    if titles:
        separator = '\u241e'  # symbol for record separator; never inside a title
        pieces, starts = [], []
        offset = 0
        for content in contents:
            folded = content.casefold()
            starts.append(offset)
            offset += len(folded) + len(separator)
            pieces.extend((folded, separator))
        blob = ''.join(pieces)
        for note_id, title in titles:
            pattern = re.compile(r'(?<!\w)' + re.escape(title) + r'(?!\w)')
            for match in pattern.finditer(blob):
                position = bisect_right(starts, match.start()) - 1
                if 0 <= position < len(contents) and position != note_id:
                    edges.add(tuple(sorted((position, note_id))))
    return {'nodes': [{key: value for key, value in note.items() if key != 'content'}
                      for note in notes],
            'links': [{'source': source, 'target': target} for source, target in sorted(edges)]}


def write_graph(graph: dict, output: Path) -> None:
    encoded = json.dumps(graph, ensure_ascii=False, separators=(',', ':'))
    encoded = encoded.replace('<', '\\u003c').replace('\u2028', '\\u2028').replace('\u2029', '\\u2029')
    atomic_write(Path(output), ('const GRAPH = ' + encoded + ';\n').encode('utf-8'))


def atomic_write(output: Path, data: bytes) -> None:
    """Durable replacement using an owned, exclusive, no-follow staging file."""
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    directory = os.open(output.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    temporary = f'.{output.name}-{secrets.token_hex(12)}.tmp'
    owned = False
    inode = None
    try:
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
        owned = True
        inode = os.fstat(descriptor).st_ino
        with os.fdopen(descriptor, 'wb') as file:
            file.write(data)
            file.flush()
            os.fsync(file.fileno())
        os.replace(temporary, output.name, src_dir_fd=directory, dst_dir_fd=directory)
        os.fsync(directory)
    finally:
        if owned:
            try:
                if os.stat(temporary, dir_fd=directory, follow_symlinks=False).st_ino == inode:
                    os.unlink(temporary, dir_fd=directory)
            except FileNotFoundError:
                pass
        os.close(directory)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--notes', type=Path, default=NOTES_ROOT)
    parser.add_argument('--output', type=Path, default=PROJECT_ROOT / 'viewer/graph-data.js')
    args = parser.parse_args()
    try:
        graph = make_graph(args.notes)
        write_graph(graph, args.output)
    except (OSError, ValueError) as error:
        print(f'Index failed: {error}', file=sys.stderr)
        return 1
    print(f"Indexed {len(graph['nodes'])} markdown notes and {len(graph['links'])} links → {args.output.resolve()}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
