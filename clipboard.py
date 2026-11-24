"""Local clipboard reader.

Reading uses the browser/X11 selection through tkinter and never writes clipboard
contents to disk or logs. The UI handles copying back with the browser Clipboard
API, so no long-lived X selection owner is required.
"""
from __future__ import annotations

MAX_CHARS = 20_000


class ClipboardError(Exception):
    pass


def available():
    try:
        import tkinter  # noqa: F401
        return True
    except Exception:
        return False


def read():
    try:
        import tkinter as tk
    except Exception as error:
        raise ClipboardError("Tk clipboard support is unavailable.") from error
    root = None
    try:
        root = tk.Tk()
        root.withdraw()
        root.update()
        text = root.clipboard_get()
    except Exception as error:
        raise ClipboardError(f"Clipboard is empty or unavailable: {type(error).__name__}") from None
    finally:
        if root is not None:
            try:
                root.destroy()
            except Exception:
                pass
    text = str(text or "")[:MAX_CHARS]
    return {"ok": True, "text": text, "chars": len(text), "empty": not bool(text)}
