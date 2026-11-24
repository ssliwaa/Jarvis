"""Unit tests for `studio_routes.py` — P2 GET/POST routing, validation gates, fallbacky 503.

Dotąd test_studio_routes_expansion pokrywa 3 ścieżki (reminders GET/POST, watch GET).
Tu reszta routingu: /research (happy + empty + ResearchError + unavailable), /services,
/system, /apps, /organizer (clamp older_days, OrganizerError), /clipboard (409),
/dashboard, /checkpoints (list/status/diff/restore/prune z walidacją confirm), /documents
(open + generate), /watch POST. Wszystkie zależności fałszowane atrybutami modułu.
"""
from __future__ import annotations

import sys
import unittest
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, ".")

import studio_routes as sr  # noqa: E402
from errors import AppError  # noqa: E402


class _OrganizerError(Exception):
    pass


class _ResearchError(Exception):
    pass


class _ClipboardError(Exception):
    pass


class _DocumentError(Exception):
    pass


def _handler(app_attrs: dict | None = None, body=None) -> SimpleNamespace:
    """Fałszywy handler: send_json zapisuje wywołania; app trafi pod server.app."""
    calls: list = []

    class _H:
        pass

    h = _H()
    h.server = SimpleNamespace(app=SimpleNamespace(**(app_attrs or {})))
    h.validate_origin = lambda: None
    h.read_json_body = lambda: body
    h.send_json = lambda status, payload=None: calls.append((status, payload))
    h.calls = calls
    return h


def _parsed(path: str, query: str = "") -> SimpleNamespace:
    return SimpleNamespace(path=path, query=query)


class StudioRoutesBase(unittest.TestCase):
    def setUp(self) -> None:
        self.patched: list = []
        self.addCleanup(self._restore)

    def _set(self, name: str, value) -> None:
        ctx = mock.patch.object(sr, name, value)
        ctx.start()
        self.patched.append(ctx)

    def _restore(self) -> None:
        for ctx in reversed(self.patched):
            ctx.stop()


class GetP2Tests(StudioRoutesBase):
    def test_unknown_paths_return_false(self):
        h = _handler()
        self.assertFalse(sr.get_p2(h, _parsed("/nic")))
        self.assertFalse(sr.post_p2(h, "/nic"))
        self.assertEqual(h.calls, [])

    def test_research_full_matrix(self):
        # happy
        fake = SimpleNamespace(search=lambda q, n: [{"title": f"{q}-{n}"}],
                               ResearchError=_ResearchError)
        self._set("web_research", fake)
        h = _handler()
        self.assertTrue(sr.get_p2(h, _parsed("/research", "q=shell+code")))
        self.assertEqual(h.calls[0][0], 200)
        self.assertEqual(h.calls[0][1]["results"][0]["title"], "shell code-8")
        # puste zapytanie
        h = _handler()
        sr.get_p2(h, _parsed("/research", "q="))
        self.assertEqual(h.calls[0][0], 400)
        self.assertEqual(h.calls[0][1]["error"]["code"], "INVALID_RESEARCH")
        # ResearchError -> 502
        def boom(q, n):
            raise _ResearchError("rate limit")
        self._set("web_research", SimpleNamespace(search=boom, ResearchError=_ResearchError))
        h = _handler()
        sr.get_p2(h, _parsed("/research", "q=x"))
        self.assertEqual(h.calls[0][0], 502)
        self.assertEqual(h.calls[0][1]["error"]["code"], "RESEARCH_FAILED")
        # modul niedostepny -> 503
        self._set("web_research", None)
        h = _handler()
        sr.get_p2(h, _parsed("/research", "q=x"))
        self.assertEqual(h.calls[0][0], 503)

    def test_services_and_system_snapshot_gates(self):
        self._set("service_control", SimpleNamespace(status=lambda: {"services": [1]}))
        h = _handler()
        sr.get_p2(h, _parsed("/services"))
        self.assertEqual(h.calls[0], (200, {"ok": True, "services": [1]}))
        self._set("service_control", None)
        h = _handler()
        sr.get_p2(h, _parsed("/services"))
        self.assertEqual(h.calls[0][0], 503)

        self._set("system_monitor", SimpleNamespace(snapshot=lambda: {"cpu": 3.5}))
        h = _handler()
        sr.get_p2(h, _parsed("/system"))
        self.assertEqual(h.calls[0][1], {"ok": True, "cpu": 3.5})
        self._set("system_monitor", None)
        h = _handler()
        sr.get_p2(h, _parsed("/system"))
        self.assertEqual(h.calls[0][0], 503)

    def test_organizer_get_clamps_older_days_and_handles_error(self):
        seen: dict = {}

        def fake_scan(root, days):
            seen["args"] = (root, days)
            return {"files": [root]}
        self._set("file_organizer", SimpleNamespace(scan=fake_scan,
                                                    OrganizerError=_OrganizerError))
        h = _handler()
        sr.get_p2(h, _parsed("/organizer", "root=/tmp&older_days=99999"))
        self.assertEqual(h.calls[0][0], 200)
        self.assertEqual(seen["args"], ("/tmp", 3650))              # clamp max 3650
        self.assertEqual(h.calls[1][0] if len(h.calls) > 1 else None, None)

        def boom(root, days):
            raise _OrganizerError("brak dostepu")
        self._set("file_organizer", SimpleNamespace(scan=boom, OrganizerError=_OrganizerError))
        h = _handler()
        sr.get_p2(h, _parsed("/organizer", ""))
        self.assertEqual(h.calls[0][0], 400)
        self.assertEqual(h.calls[0][1]["error"]["code"], "ORGANIZER_FAILED")

    def test_clipboard_read_and_409_on_error(self):
        self._set("clipboard", SimpleNamespace(read=lambda: {"ok": True, "text": "abc"},
                                               ClipboardError=_ClipboardError))
        h = _handler()
        sr.get_p2(h, _parsed("/clipboard"))
        self.assertEqual(h.calls[0], (200, {"ok": True, "text": "abc"}))

        def boom():
            raise _ClipboardError("schowek pusty")
        self._set("clipboard", SimpleNamespace(read=boom, ClipboardError=_ClipboardError))
        h = _handler()
        sr.get_p2(h, _parsed("/clipboard"))
        self.assertEqual(h.calls[0][0], 409)
        self.assertEqual(h.calls[0][1]["error"]["code"], "CLIPBOARD_EMPTY")

    def test_checkpoints_get_matrix(self):
        manager = SimpleNamespace(
            list_checkpoints=lambda p: [{"path": p}],
            list_all_checkpoints=lambda: [{"path": "ALL"}],
            status=lambda: {"enabled": True})
        h = _handler({"checkpoints": manager})
        sr.get_p2(h, _parsed("/checkpoints", "path=/www"))
        self.assertEqual(h.calls[0][0], 200)
        self.assertEqual(h.calls[0][1]["checkpoints"], [{"path": "/www"}])
        self.assertEqual(h.calls[0][1]["path"], "/www")

        h = _handler({"checkpoints": manager})
        sr.get_p2(h, _parsed("/checkpoints", ""))
        self.assertEqual(h.calls[0][1]["checkpoints"], [{"path": "ALL"}])
        self.assertEqual(h.calls[0][1]["path"], None)

        self._set("checkpoint_manager", None)                        # dystraktor; route nie uzywa
        h = _handler({"checkpoints": manager})
        sr.get_p2(h, _parsed("/checkpoints/status", ""))
        self.assertEqual(h.calls[0], (200, {"enabled": True}))

        failing = SimpleNamespace(list_all_checkpoints=lambda: (_ for _ in ()).throw(ValueError("boom")),
                                  status=lambda: {})
        h = _handler({"checkpoints": failing})
        sr.get_p2(h, _parsed("/checkpoints", ""))
        self.assertEqual(h.calls[0][0], 400)
        self.assertEqual(h.calls[0][1]["error"]["code"], "CHECKPOINT_FAILED")

        h = _handler({})                                            # brak managera
        sr.get_p2(h, _parsed("/checkpoints", ""))
        self.assertEqual(h.calls[0][0], 503)

    def test_dashboard_combines_briefing_and_system(self):
        self._set("briefing", SimpleNamespace(build=lambda app, sched, include_account: {"brief": True}))
        self._set("system_monitor", SimpleNamespace(snapshot=lambda: {"cpu": 1}))
        h = _handler({"scheduler": "S"})
        sr.get_p2(h, _parsed("/dashboard"))
        self.assertEqual(h.calls[0][0], 200)
        self.assertEqual(h.calls[0][1]["briefing"], {"brief": True})
        self.assertEqual(h.calls[0][1]["system"], {"cpu": 1})

        self._set("briefing", None)
        h = _handler({})
        sr.get_p2(h, _parsed("/dashboard"))
        self.assertEqual(h.calls[0], (503, {"ok": False}))

    def test_reminders_get_with_status_filter_and_failure(self):
        seen: dict = {}

        def fake_reminders(args, ctx):
            seen["args"] = args
            seen["ctx"] = ctx
            return {"ok": True, "reminders": []}
        pkg = SimpleNamespace(reminders=SimpleNamespace(reminders=fake_reminders))
        with mock.patch.dict(sys.modules, {"operator_modules": pkg}):
            h = _handler({"state_root": "/tmp/state"})
            sr.get_p2(h, _parsed("/reminders", "status=done"))
            self.assertEqual(h.calls[0][0], 200)
            self.assertEqual(seen["args"], {"action": "list", "status": "done"})
            self.assertEqual(seen["ctx"], {"state_root": "/tmp/state"})

            def boom(args, ctx):
                raise RuntimeError("kaboom")
            pkg2 = SimpleNamespace(reminders=SimpleNamespace(reminders=boom))
            with mock.patch.dict(sys.modules, {"operator_modules": pkg2}):
                h = _handler({"state_root": "/x"})
                sr.get_p2(h, _parsed("/reminders", ""))
                self.assertEqual(h.calls[0][0], 500)
                self.assertEqual(h.calls[0][1]["error"]["code"], "REMINDERS_FAILED")


class PostP2Tests(StudioRoutesBase):
    def test_apps_post_actions_and_validation(self):
        seen: dict = {}

        def fake_focus(q):
            seen["focus"] = q
            return {"ok": True}
        self._set("app_identity", SimpleNamespace(find=lambda q: {"ok": True, "q": q},
                                                  focus=fake_focus,
                                                  launch=lambda q: {"ok": True},
                                                  close=lambda q, confirm: {"ok": confirm}))
        h = _handler(body={"action": "focus", "query": "firefox"})
        self.assertTrue(sr.post_p2(h, "/apps"))
        self.assertEqual(h.calls[0][0], 200)
        self.assertEqual(seen["focus"], "firefox")

        h = _handler(body={"action": "close", "query": "x", "confirm": True})
        sr.post_p2(h, "/apps")
        self.assertEqual(h.calls[0][1]["result"], {"ok": True})

        with self.assertRaises(AppError) as ctx:
            sr.post_p2(_handler(body={"action": "find", "extra": 1}), "/apps")
        self.assertEqual(ctx.exception.code, "INVALID_APP")
        self.assertEqual(ctx.exception.status, 400)

        self._set("app_identity", None)
        with self.assertRaises(AppError) as ctx2:
            sr.post_p2(_handler(body={}), "/apps")
        self.assertEqual(ctx2.exception.status, 503)

    def test_organizer_post_validation_and_restore_paths(self):
        calls: list = []

        def collect(name):
            def _fn(*args, **kwargs):
                calls.append((name, args, kwargs))
                return {"ok": True, "op": name}
            return _fn
        fake = SimpleNamespace(
            scan=collect("scan"), trash=collect("trash"), preview=collect("preview"),
            archive=collect("archive"), restore_archive=collect("restore_archive"),
            restore=collect("restore"), OrganizerError=_OrganizerError)
        self._set("file_organizer", fake)

        h = _handler(body={"action": "trash", "paths": ["/a"], "confirm": True})
        sr.post_p2(h, "/organizer")
        self.assertEqual(calls[0][0], "trash")
        self.assertEqual(calls[0][2], {"confirm": True})

        h = _handler(body={"action": "restore", "batch": "b-1"})
        sr.post_p2(h, "/organizer")
        self.assertEqual(calls[1][1], ("b-1",))
        self.assertEqual(calls[1][2], {"confirm": False})

        with self.assertRaises(AppError) as e1:                      # paths nie-lista
            sr.post_p2(_handler(body={"paths": "abc"}), "/organizer")
        self.assertEqual(e1.exception.code, "INVALID_ORGANIZER")
        with self.assertRaises(AppError) as e2:                      # older_days nie-int
            sr.post_p2(_handler(body={"older_days": "x"}), "/organizer")
        self.assertEqual(e2.exception.code, "INVALID_ORGANIZER")

        def boom_action(*a, **kw):
            raise _OrganizerError("unknown action")
        self._set("file_organizer", SimpleNamespace(OrganizerError=_OrganizerError,
                                                    scan=lambda *a: (_ for _ in ()).throw(boom_action())))
        with self.assertRaises(AppError) as e3:
            sr.post_p2(_handler(body={"action": "scan"}), "/organizer")
        self.assertEqual(e3.exception.code, "ORGANIZER_FAILED")

    def test_documents_open_and_generate(self):
        calls: list = []
        fake = SimpleNamespace(
            open_document=lambda name, confirm: (calls.append(("open", name, confirm)),
                                                {"ok": True})[1],
            generate=lambda kind, title, body, rows, template: (calls.append(
                ("gen", kind, title, body, rows, template)), {"path": "x"})[1],
            list_documents=lambda n: [],
            list_templates=lambda: [],
            DocumentError=_DocumentError)
        self._set("documents", fake)

        h = _handler(body={"name": "oferta.docx", "confirm": True})
        sr.post_p2(h, "/documents/open")
        self.assertEqual(h.calls[0][0], 200)
        self.assertEqual(calls[0][1], "oferta.docx")

        with self.assertRaises(AppError) as e1:                      # confirm wymagany kluczami
            sr.post_p2(_handler(body={"name": "x"}), "/documents/open")
        self.assertEqual(e1.exception.code, "INVALID_DOCUMENT")

        h = _handler(body={"kind": "pdf", "title": "T", "body": "B"})
        sr.post_p2(h, "/documents")
        self.assertEqual(h.calls[0][1]["document"]["path"], "x")
        self.assertEqual(calls[1], ("gen", "pdf", "T", "B", None, "plain"))

    def test_checkpoints_diff_restore_prune_validation(self):
        calls: list = []

        def collect(name):
            def _fn(*args, **kwargs):
                calls.append((name, args, kwargs))
                return {"success": True, "op": name}
            return _fn
        manager = SimpleNamespace(diff=collect("diff"), restore=collect("restore"),
                                  prune=collect("prune"))
        handler_attrs = {"checkpoints": manager}

        h = _handler(handler_attrs, body={"path": "/p", "hash": "h"})
        sr.post_p2(h, "/checkpoints/diff")
        self.assertEqual(h.calls[0][0], 200)

        with self.assertRaises(AppError) as e1:                      # brak confirm
            sr.post_p2(_handler(handler_attrs, body={"path": "/p", "hash": "h",
                                                     "confirm": "yes"}), "/checkpoints/restore")
        self.assertEqual(e1.exception.code, "CONFIRM_REQUIRED")

        h = _handler(handler_attrs, body={"path": "/p", "hash": "h", "confirm": True,
                                          "file": "a.py", "safe": False})
        sr.post_p2(h, "/checkpoints/restore")
        self.assertEqual(calls[1][0], "restore")
        self.assertEqual(calls[1][1], ("/p", "h", "a.py"))
        self.assertEqual(calls[1][2], {"safe": False})

        with self.assertRaises(AppError) as e2:                      # retention poza zakresem
            sr.post_p2(_handler(handler_attrs, body={"retention_days": 9999,
                                                    "confirm": True}), "/checkpoints/prune")
        self.assertEqual(e2.exception.code, "INVALID_CHECKPOINT")

        h = _handler(handler_attrs, body={"retention_days": 30, "confirm": True,
                                          "delete_orphans": True})
        sr.post_p2(h, "/checkpoints/prune")
        self.assertEqual(h.calls[0][0], 200)
        self.assertEqual(calls[2][0], "prune")
        self.assertEqual(calls[2][1], (30, True))

        with self.assertRaises(AppError) as e3:                      # brak managera
            sr.post_p2(_handler({}, body={"path": "/p", "hash": "h"}), "/checkpoints/diff")
        self.assertEqual(e3.exception.code, "CHECKPOINTS_UNAVAILABLE")
        self.assertEqual(e3.exception.status, 503)

    def test_reminders_and_watch_post_paths(self):
        calls: list = []

        def fake(args, ctx):
            calls.append(args)
            return {"ok": True, "echo": args}
        pkg = SimpleNamespace(reminders=SimpleNamespace(reminders=fake),
                              watch_pages=SimpleNamespace(watch_pages=fake))
        with mock.patch.dict(sys.modules, {"operator_modules": pkg}):
            h = _handler({"state_root": "/s"}, body={"action": "create", "text": "kup mleko"})
            sr.post_p2(h, "/reminders")
            self.assertEqual(h.calls[0][0], 200)
            self.assertEqual(calls[0]["text"], "kup mleko")

            with self.assertRaises(AppError) as e1:                  # payload nie-dict
                sr.post_p2(_handler({"state_root": "/s"}, body=[1, 2]), "/reminders")
            self.assertEqual(e1.exception.code, "INVALID_REMINDER")

            pkg2 = SimpleNamespace(watch_pages=SimpleNamespace(watch_pages=lambda a, c: (_ for _ in ()).throw(ValueError("x"))))
            with mock.patch.dict(sys.modules, {"operator_modules": pkg2}):
                with self.assertRaises(AppError) as e2:              # wyjatek -> AppError
                    sr.post_p2(_handler({"state_root": "/s"}, body={"action": "x"}), "/watch")
                self.assertEqual(e2.exception.code, "WATCH_FAILED")
                self.assertEqual(e2.exception.status, 400)


if __name__ == "__main__":
    unittest.main()
