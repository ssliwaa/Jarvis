"""Opt-in, explicit filesystem observation; this module starts no watcher.

Call FileWatch.configure(roots, consent=True) only from a trusted owner-consent
boundary, never based on a model-supplied flag. Setup baselines existing names.
A lifecycle owner may call scan_now periodically and present its proposals;
it must stop its scheduler on shutdown. Scans compare names between snapshots:
transient files and replacement at an unchanged name can be missed. No file
contents are opened, imported, moved, or deleted.
"""
from __future__ import annotations

import fcntl
import json
import os
import stat
import tempfile
import uuid
from contextlib import contextmanager
from pathlib import Path


class WatchError(Exception):
    """Observation refused or incomplete; no snapshot was committed."""


MAX_DEPTH = 24


class FileWatch:
    def __init__(self, state_dir=None):
        self.state_dir = Path(state_dir or Path.home() / '.jarvis-tools' / 'file-watch')

    @contextmanager
    def _locked(self):
        self.state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        info = self.state_dir.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise WatchError('State directory must be owned by the user and private')
        fd = os.open(self.state_dir / 'lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            if os.fstat(fd).st_uid != os.getuid() or os.fstat(fd).st_mode & 0o077:
                raise WatchError('State lock must be private')
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            os.close(fd)

    def _load(self):
        try:
            fd = os.open(self.state_dir / 'state.json', os.O_RDONLY | os.O_NOFOLLOW)
        except FileNotFoundError:
            return None
        with os.fdopen(fd, 'r', encoding='utf-8') as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
                raise WatchError('State must be owned by the user and private')
            try:
                return json.load(stream)
            except (ValueError, UnicodeError) as exc:
                raise WatchError('Invalid state') from exc

    def _save(self, state):
        fd, name = tempfile.mkstemp(prefix='.state-', dir=self.state_dir)
        try:
            with os.fdopen(fd, 'w', encoding='utf-8') as stream:
                json.dump(state, stream, ensure_ascii=True, sort_keys=True)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(name, self.state_dir / 'state.json')
            directory = os.open(self.state_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            if os.path.exists(name):
                os.unlink(name)

    @staticmethod
    def _protected(name):
        name = name.lower()
        return name.startswith('.') or name in {'config.json'} or name.endswith('.env')

    @classmethod
    def _open_root(cls, root):
        path = Path(root)
        if not path.is_absolute() or '..' in path.parts or path == Path('/'):
            raise WatchError('Choose an absolute directory below a permitted root')
        allowed = [Path.home(), Path('/tmp'), Path('/mnt'), Path('/media'), Path(tempfile.gettempdir())]
        matches = [parent for parent in allowed if path == parent or parent in path.parents]
        if not matches:
            raise WatchError('Directory outside permitted roots')
        anchor = max(matches, key=lambda item: len(item.parts))
        if any(cls._protected(part) for part in path.relative_to(anchor).parts):
            raise WatchError('Protected or hidden path')
        fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
        try:
            for part in path.parts[1:]:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd)
                fd = child
            return fd
        except OSError as exc:
            os.close(fd)
            raise WatchError('Directory unavailable or contains a symlink') from exc

    @classmethod
    def _snapshot(cls, roots, max_entries):
        seen = []
        count = 0

        def walk(fd, path, depth=0):
            nonlocal count
            if depth > MAX_DEPTH:
                raise WatchError('Directory nesting is too deep; snapshot unchanged')
            with os.scandir(fd) as entries:
                for entry in entries:
                    count += 1
                    if count > max_entries:
                        raise WatchError('Scan capacity exceeded; snapshot unchanged')
                    if cls._protected(entry.name):
                        continue
                    info = entry.stat(follow_symlinks=False)
                    child_path = path / entry.name
                    if stat.S_ISDIR(info.st_mode):
                        child = os.open(entry.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                        try:
                            walk(child, child_path, depth + 1)
                        finally:
                            os.close(child)
                    elif stat.S_ISREG(info.st_mode):
                        seen.append(str(child_path))
        try:
            for root in roots:
                fd = cls._open_root(root)
                try:
                    walk(fd, Path(root))
                finally:
                    os.close(fd)
        except OSError as exc:
            raise WatchError('Scan incomplete; snapshot unchanged') from exc
        return sorted(set(seen))

    def configure(self, roots, *, consent=False, max_entries=10000, extensions=None):
        if consent is not True:
            raise WatchError('Explicit owner consent required')
        if not isinstance(roots, (list, tuple)) or not 1 <= len(roots) <= 16:
            raise WatchError('Select 1 to 16 directories')
        if type(max_entries) is not int or not 1 <= max_entries <= 100000:
            raise WatchError('Invalid scan capacity')
        if extensions is not None:
            if (not isinstance(extensions, (list, tuple)) or not 1 <= len(extensions) <= 32
                    or any(not isinstance(ext, str) or not ext.startswith('.') or
                           len(ext) > 20 or not ext[1:].isalnum() for ext in extensions)):
                raise WatchError('Invalid extension filter')
            extensions = sorted(set(ext.lower() for ext in extensions))
        roots = sorted(set(str(Path(root)) for root in roots))
        with self._locked():
            snapshot = self._snapshot(roots, max_entries)
            self._save({'version': 1, 'enabled': True, 'roots': roots,
                        'max_entries': max_entries, 'extensions': extensions,
                        'seen': snapshot, 'pending': []})
        return self.status()

    def disable(self, *, consent=False):
        if consent is not True:
            raise WatchError('Explicit owner consent required')
        with self._locked():
            state = self._load()
            if state is not None:
                state['enabled'] = False
                state['seen'] = []
                state['pending'] = []
                self._save(state)

    def acknowledge(self, event_id):
        with self._locked():
            state = self._load()
            if not state or not state['enabled']:
                raise WatchError('File observation has not been enabled')
            pending = state['pending']
            remaining = [item for item in pending if item['id'] != event_id]
            if len(remaining) == len(pending):
                raise WatchError('Unknown proposal')
            state['pending'] = remaining
            self._save(state)

    def status(self):
        if not self.state_dir.exists():
            return {'enabled': False, 'automatic': False}
        with self._locked():
            state = self._load()
            if not state or not state['enabled']:
                return {'enabled': False, 'automatic': False}
            return {'enabled': True, 'automatic': False, 'roots': state['roots'],
                    'max_entries': state['max_entries'], 'extensions': state['extensions'],
                    'pending': state['pending']}

    def scan_now(self):
        with self._locked():
            state = self._load()
            if not state or not state['enabled']:
                raise WatchError('File observation has not been enabled')
            snapshot = self._snapshot(state['roots'], state['max_entries'])
            new = sorted(set(snapshot) - set(state['seen']))
            extensions = state['extensions']
            new = [path for path in new if extensions is None or Path(path).suffix.lower() in extensions]
            events = [{'id': uuid.uuid4().hex, 'path': path,
                       'proposal': 'offer_summary' if Path(path).suffix.lower() == '.pdf' else None}
                      for path in new]
            pending = state['pending'] + [event for event in events if event['proposal']]
            if len(pending) > state['max_entries']:
                raise WatchError('Pending proposal capacity exceeded; snapshot unchanged')
            state['seen'] = snapshot
            state['pending'] = pending
            self._save(state)
            return {'events': events, 'automatic': False}


def file_watch(arguments, context=None):
    """Expose only status and manual scans, not the owner-consent boundary."""
    del context
    action = (arguments or {}).get('action', 'status')
    watch = FileWatch()
    if action == 'status':
        return {'ok': True, **watch.status()}
    if action == 'scan_now':
        return {'ok': True, **watch.scan_now()}
    return {'ok': False, 'error': 'Unsupported action'}


TOOL = {
    'name': 'file_watch',
    'description': 'Check file observation status or manually scan opted-in directories. No automatic watcher is started.',
    'input_schema': {'type': 'object', 'properties': {'action': {'type': 'string', 'enum': ['status', 'scan_now']}}, 'additionalProperties': False},
    'handler': file_watch,
    'approval': True,
}
