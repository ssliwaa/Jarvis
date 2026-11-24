"""Clipboard reader: text, truncation and the failure path (no X11 needed)."""
import sys
import types
import unittest
from unittest import mock

import clipboard


class FakeRoot:
    def __init__(self, text=None, error=None):
        self._text = text
        self._error = error
        self.withdrawn = False
        self.updated = False
        self.destroyed = False

    def withdraw(self):
        self.withdrawn = True

    def update(self):
        self.updated = True

    def clipboard_get(self):
        if self._error:
            raise self._error
        return self._text

    def destroy(self):
        self.destroyed = True


def fake_tkinter(root):
    module = types.ModuleType("tkinter")
    module.Tk = lambda: root
    return module


class ReadTests(unittest.TestCase):
    def test_read_returns_text_and_chars(self):
        root = FakeRoot("hello clipboard")
        with mock.patch.dict(sys.modules, {"tkinter": fake_tkinter(root)}):
            result = clipboard.read()
        self.assertTrue(result["ok"])
        self.assertEqual(result["text"], "hello clipboard")
        self.assertEqual(result["chars"], 15)
        self.assertFalse(result["empty"])
        self.assertTrue(root.withdrawn)
        self.assertTrue(root.destroyed)

    def test_read_caps_long_text(self):
        root = FakeRoot("x" * (clipboard.MAX_CHARS + 50))
        with mock.patch.dict(sys.modules, {"tkinter": fake_tkinter(root)}):
            result = clipboard.read()
        self.assertEqual(result["chars"], clipboard.MAX_CHARS)
        self.assertEqual(len(result["text"]), clipboard.MAX_CHARS)

    def test_read_reports_an_empty_or_unavailable_selection(self):
        root = FakeRoot(error=RuntimeError("no selection"))
        with mock.patch.dict(sys.modules, {"tkinter": fake_tkinter(root)}):
            with self.assertRaises(clipboard.ClipboardError) as caught:
                clipboard.read()
        self.assertIn("RuntimeError", str(caught.exception))
        self.assertTrue(root.destroyed)

    def test_read_requires_tkinter(self):
        with mock.patch.dict(sys.modules, {"tkinter": None}):
            with self.assertRaises(clipboard.ClipboardError):
                clipboard.read()

    def test_available_follows_the_import(self):
        with mock.patch.dict(sys.modules, {"tkinter": types.ModuleType("tkinter")}):
            self.assertTrue(clipboard.available())
        with mock.patch.dict(sys.modules, {"tkinter": None}):
            self.assertFalse(clipboard.available())


if __name__ == "__main__":
    unittest.main()
