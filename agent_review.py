"""Compare an agent's outbox with a target tree — read-only, Jarvis applies later.

The agent never edits the project, so the only honest way to see its work is a
diff between what it left in ``outbox/`` and what is on disk. This module only
computes that diff; applying is Jarvis's job, through its own write path.
"""
from __future__ import annotations

import difflib
import os
from pathlib import Path

import agent_cli

MAX_FILES = 20
MAX_FILE_BYTES = 200_000
MAX_DIFF_LINES = 400
ALLOWED_ROOTS = ('~', '/tmp', '/mnt', '/media')
# Files the runner writes as its own report, never as project deliverables.
REPORT_FILES = frozenset({'outbox.md', 'team_summary.md'})


class ReviewError(Exception):
    """The comparison could not be made; nothing was changed."""


class ConfirmationRequired(ReviewError):
    """The target is a protected tree (Jarvis itself): the owner must confirm."""


APP_ROOT = Path(__file__).resolve().parent


def _protected_roots() -> list[Path]:
    """Trees whose overwrite must be an explicit owner decision, not an agent's idea."""
    return [APP_ROOT, Path.home() / '.jarvis-tools']


def _is_protected(target: Path) -> bool:
    for root in _protected_roots():
        try:
            root = Path(root).expanduser().resolve()
        except OSError:
            continue
        if target == root or root in target.parents:
            return True
    return False


def _resolve_target(target):
    if not isinstance(target, str) or not target.strip():
        raise ReviewError('A target directory is required.')
    path = Path(target.strip()).expanduser()
    if not path.is_absolute() or '..' in path.parts:
        raise ReviewError('The target must be an absolute path without "..".')
    roots = [Path(raw).expanduser() for raw in ALLOWED_ROOTS]
    if not any(path == root or root in path.parents for root in roots):
        raise ReviewError('The target is outside the permitted folders.')
    if not path.is_dir():
        raise ReviewError('The target directory does not exist.')
    return path


def _read(path):
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            return None
        return path.read_text(encoding='utf-8', errors='replace')
    except OSError:
        return None


def _resolve_outbox(source_id: str) -> Path:
    raw = str(source_id or '').strip()
    if raw.startswith(('team:', 'project:')):
        pid = raw.split(':', 1)[1].strip()
        import agent_team
        try:
            pdir = agent_team.project_root(pid)
            if not (pdir / 'project.json').is_file():
                raise ReviewError(f'Team project does not exist: {pid}')
            out = pdir / 'outbox'
            if not out.is_dir() or not any(out.iterdir()):
                agent_team.sync_repo_to_outbox(pid)
            return out
        except agent_team.TeamError as error:
            raise ReviewError(str(error)) from None
    try:
        return agent_cli.outbox_path(raw)
    except agent_cli.AgentError as error:
        raise ReviewError(str(error)) from None


def diff_outbox(agent_id, target):
    """Return a bounded, per-file comparison of the outbox against ``target``."""
    root = _resolve_target(target)
    outbox = _resolve_outbox(agent_id)
    if not outbox.is_dir():
        raise ReviewError('That agent has no outbox yet.')
    files = []
    reports = []
    for path in sorted(outbox.rglob('*')):
        if len(files) >= MAX_FILES:
            break
        if not path.is_file():
            continue
        relative = path.relative_to(outbox)
        if relative.name.lower() in REPORT_FILES:
            reports.append(str(relative))
            continue
        current = root / relative
        proposed_text = _read(path)
        if proposed_text is None:
            files.append({'path': str(relative), 'status': 'skipped',
                          'reason': 'too large or unreadable'})
            continue
        if current.is_file():
            current_text = _read(current)
            if current_text is None:
                files.append({'path': str(relative), 'status': 'skipped',
                              'reason': 'target file too large or unreadable'})
                continue
            if current_text == proposed_text:
                files.append({'path': str(relative), 'status': 'unchanged'})
                continue
            diff = list(difflib.unified_diff(
                current_text.splitlines(), proposed_text.splitlines(),
                fromfile=f'{relative} (current)', tofile=f'{relative} (agent)',
                lineterm='', n=2))
            added = sum(1 for line in diff if line.startswith('+') and not line.startswith('+++'))
            removed = sum(1 for line in diff if line.startswith('-') and not line.startswith('---'))
            files.append({'path': str(relative), 'status': 'changed',
                          'added': added, 'removed': removed,
                          'truncated': len(diff) > MAX_DIFF_LINES,
                          'diff': '\n'.join(diff[:MAX_DIFF_LINES])})
        else:
            files.append({'path': str(relative), 'status': 'new',
                          'bytes': len(proposed_text.encode('utf-8')),
                          'preview': proposed_text[:400]})
    changed = [row for row in files if row['status'] in ('changed', 'new')]
    return {'ok': True, 'agent': agent_id, 'target': str(root),
            'files': files, 'changed': len(changed),
            'skipped_reports': reports,
            'note': ('Read-only comparison. Nothing was written; Jarvis applies what it '
                     'decides is safe, through its own tools.')}


def apply_hint(agent_id, path):
    """Explain how Jarvis should apply one outbox file, without doing it."""
    outbox = _resolve_outbox(agent_id)
    candidate = (outbox / str(path or '')).resolve()
    try:
        candidate.relative_to(outbox.resolve())
    except (ValueError, OSError):
        raise ReviewError('That path is outside the agent outbox.') from None
    if not candidate.is_file():
        raise ReviewError('That file is not in the outbox.')
    return {'ok': True, 'source': str(candidate), 'bytes': os.path.getsize(candidate),
            'how': 'Read this file and write it through write_file/restore_file; the agent '
                   'cannot modify the project itself.'}


def apply_outbox(agent_id, target, files=None, confirm=False):
    """Apply approved files from the agent's outbox to target folder with checkpoints.

    Writing into Jarvis itself (or its state dir) needs ``confirm=True``: the UI sends
    it after the owner typed the path, while an agent that merely "deploys" its pack
    gets a refusal instead of silently rewriting the running app (which used to
    restart Jarvis mid-wave and kill its own sandbox).
    """
    root = _resolve_target(target)
    if _is_protected(root) and not confirm:
        raise ConfirmationRequired(
            f'Wdrożenie do chronionego katalogu ({root}) wymaga jawnego potwierdzenia '
            f'właściciela: wyślij "confirm": true albo użyj przycisku „Wdróż outbox”.')
    outbox = _resolve_outbox(agent_id)
    if not outbox.is_dir():
        raise ReviewError('That agent has no outbox yet.')

    candidates = []
    skipped_reports = []
    for path in sorted(outbox.rglob('*')):
        if not path.is_file():
            continue
        try:
            rel = path.relative_to(outbox)
        except (ValueError, OSError):
            continue
        # The run report is Jarvis's receipt, not a deliverable: copying outbox.md /
        # TEAM_SUMMARY.md into the project would litter it with duplicates.
        if rel.name.lower() in REPORT_FILES:
            skipped_reports.append(str(rel))
            continue
        if files is not None and str(rel) not in files and rel.name not in files:
            continue
        candidates.append((path, rel))

    if not candidates:
        return {'ok': True, 'agent': agent_id, 'target': str(root), 'applied': 0,
                'files': [], 'skipped_reports': skipped_reports}

    cp_mgr = None
    checkpoint_created = False
    try:
        import checkpoint_manager
        cp_mgr = checkpoint_manager.default_manager()
        checkpoint_created = bool(cp_mgr.ensure_checkpoint(root, reason=f"agent:{agent_id} apply"))
    except Exception:
        cp_mgr = None

    import uuid
    applied = []
    for src, rel in candidates:
        dest = root / rel
        try:
            dest_resolved = dest.resolve()
            if not (dest_resolved == root or root in dest_resolved.parents):
                continue
        except OSError:
            continue
        content = src.read_bytes()
        dest.parent.mkdir(parents=True, exist_ok=True)
        temp = dest.with_name('.' + dest.name + '.tmp-' + uuid.uuid4().hex[:8])
        temp.write_bytes(content)
        # Keep the permissions of a file that already exists; a fresh temp file
        # would otherwise widen or narrow them.
        try:
            if dest.is_file():
                os.chmod(temp, dest.stat().st_mode & 0o7777)
        except OSError:
            pass
        temp.replace(dest)
        if cp_mgr is not None:
            try:
                cp_mgr.record_agent_write(str(dest))
            except Exception:
                pass
        applied.append(str(rel))

    return {
        'ok': True,
        'agent': agent_id,
        'target': str(root),
        'applied': len(applied),
        'files': applied,
        'skipped_reports': skipped_reports,
        'checkpoint_created': checkpoint_created,
    }


def rollback_last_checkpoint(target, commit_hash: str = '') -> dict:
    """Restore target directory to its latest (or specified) shadow-git checkpoint."""
    root = _resolve_target(target)
    try:
        import checkpoint_manager
        mgr = checkpoint_manager.default_manager()
        snaps = mgr.list_checkpoints(root)
    except Exception as exc:
        raise ReviewError(f'Checkpoint store unavailable: {exc}') from None

    if not snaps and not commit_hash:
        raise ReviewError('Brak zapisanych checkpointów dla tego katalogu.')
    chosen_hash = str(commit_hash or snaps[0].get('hash') or snaps[0].get('short_hash') or '').strip()
    if not chosen_hash:
        raise ReviewError('Nie udało się ustalić skrótu checkpointu.')
    result = mgr.restore(root, chosen_hash)
    if not isinstance(result, dict) or not result.get('success', result.get('ok', False)):
        err_msg = (result or {}).get('error') or 'Przywrócenie checkpointu nie powiodło się.'
        raise ReviewError(str(err_msg))
    return {'ok': True, 'target': str(root), 'restored_to': chosen_hash, **result}
