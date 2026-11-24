"""A small, persistent undo stack for reversible Operator file actions.

The stack stores only facts needed to reverse the action. Writes use the backup
created by ``FileOps.write``; deletes use the trash path. It never pretends an
action is reversible when no backup/trash copy exists.
"""
from __future__ import annotations

import json
import os
import shutil
import threading
import time
import uuid
from pathlib import Path

import operator_tools as ops

STATE = ops.TOOLS / "undo.json"
MAX_DEPTH = 20
_LOCK = threading.Lock()  # push/undo read-modify-write on the stack file


class UndoError(Exception):
    pass


class UndoCenter:
    def __init__(self, path: Path | None = None, backups: Path | None = None,
                 trash: Path | None = None):
        self.path = Path(path or STATE)
        self.backups = Path(backups or ops.BACKUPS)
        self.trash = Path(trash or ops.TRASH)

    def _read(self) -> list[dict]:
        try:
            value = json.loads(self.path.read_text(encoding="utf-8"))
            return [row for row in value if isinstance(row, dict)] if isinstance(value, list) else []
        except (ValueError, UnicodeError):
            # An existing but unparseable stack must not be silently emptied by
            # the next push: preserve it beside the state file for inspection.
            try:
                corrupt = self.path.with_name(f"{self.path.name}.corrupt-{time.time_ns()}")
                os.replace(self.path, corrupt)
            except OSError:
                pass
            return []
        except OSError:
            return []

    def _write(self, rows: list[dict]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_name(f".undo-{uuid.uuid4().hex[:8]}.tmp")
        temporary.write_text(json.dumps(rows[-MAX_DEPTH:], indent=2, ensure_ascii=False), encoding="utf-8")
        try:
            temporary.chmod(0o600)
        except OSError:
            pass
        temporary.replace(self.path)

    def push(self, kind: str, path: str, *, backup: str | None = None,
             trash: str | None = None, existed: bool = False, label: str = "") -> dict:
        if kind not in {"write", "delete"}:
            raise UndoError("Unsupported undo kind.")
        row = {"kind": kind, "path": str(path), "backup": backup, "trash": trash,
               "existed": bool(existed), "label": str(label)[:200], "at": time.time()}
        with _LOCK:
            rows = self._read()
            rows.append(row)
            self._write(rows)
        return row

    def status(self) -> dict:
        rows = self._read()
        return {"ok": True, "entries": list(reversed(rows))[:MAX_DEPTH],
                "can_undo": bool(rows), "count": len(rows)}

    def undo_last(self) -> dict:
        with _LOCK:
            rows = self._read()
            if not rows:
                raise UndoError("There is nothing to undo.")
            row = rows.pop()
            kind = row.get("kind")

            def checked(raw: str, *, root: Path | None = None) -> Path:
                """Revalidate a stack entry; the JSON file is model-writable."""
                try:
                    path = ops.resolve_path(str(raw or ""), must_exist=False)
                except ops.ToolError as error:
                    raise UndoError(f"Undo entry path is not allowed: {error}") from None
                resolved = ops.real_path(path)
                if ops.is_sensitive_target(resolved):
                    raise UndoError("Undo entry points at a protected path.")
                if root is not None:
                    try:
                        resolved.relative_to(Path(os.path.realpath(root)))
                    except ValueError:
                        raise UndoError("Undo entry points outside its own storage.") from None
                return path

            target = checked(str(row.get("path") or ""))
            # Whole operation stays under the lock: a concurrent push between
            # the pop and the rewrite used to drop the new entry.
            try:
                if kind == "write":
                    if target.is_symlink():
                        raise UndoError("The undo target is a symlink; refusing to follow it.")
                    backup = checked(str(row.get("backup") or ""), root=self.backups) \
                        if row.get("backup") else None
                    if backup is not None and backup.is_file() and not backup.is_symlink():
                        target.parent.mkdir(parents=True, exist_ok=True)
                        shutil.copy2(backup, target)
                    elif not row.get("existed"):
                        if target.is_file():
                            target.unlink()
                        elif target.exists():
                            raise UndoError("The target is not a file; refusing to remove it.")
                    else:
                        raise UndoError("The write has no backup; it cannot be reversed safely.")
                elif kind == "delete":
                    trash = checked(str(row.get("trash") or ""), root=self.trash)
                    if not trash.exists() or trash.is_symlink():
                        raise UndoError("The trash copy is missing or unsafe.")
                    target.parent.mkdir(parents=True, exist_ok=True)
                    shutil.move(str(trash), str(target))
                else:
                    raise UndoError("Unknown undo entry.")
            except UndoError:
                raise
            except OSError as error:
                raise UndoError(f"Undo failed: {type(error).__name__}.") from None
            self._write(rows)
            return {"ok": True, "undone": row, "remaining": len(rows)}

    def clear(self) -> None:
        with _LOCK:
            self._write([])
