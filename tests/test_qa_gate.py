"""Unit tests for qa_gate: deterministic viewer/ audit, fully offline.

`audit_viewer` only touches paths under a tmp project root, and the Node
syntax pass runs through a patched `_find_node` + fake `subprocess.run`,
so nothing here shells out for real (plus one integration test guarded by
skipIf against a real Node binary).

Remote-script tests do not seed viewer/capabilities.js: the ordering rule
only applies while capabilities.js exists on disk, so keeping it off-disk
lets each test exercise exactly one validation.

Polish issue strings are matched through `fold` (NFKD -> ASCII) so this
file stays pure ASCII except em-dashes.
"""
import subprocess
import tempfile
import unicodedata
import unittest
from pathlib import Path
from unittest import mock

import qa_gate

_GOOD_REMOTE = (
    '<script src="https://cdn.example/x@1.2.3/y.js" '
    'integrity="sha384-AbC+/12=" crossorigin="anonymous"></script>'
)


def fold(text):
    """ASCII view of a Polish issue string (tests stay pure-ASCII)."""
    return unicodedata.normalize("NFKD", str(text)).encode(
        "ascii", "ignore").decode()


class _Project(unittest.TestCase):
    """tmp project tree + helpers to seed viewer files."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.viewer = self.root / "viewer"

    def seed(self, html, files=()):
        """Write viewer/index.html + relative files; return project root."""
        self.viewer.mkdir(parents=True, exist_ok=True)
        (self.viewer / "index.html").write_text(html, encoding="utf-8")
        for rel, content in files:
            path = self.viewer / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
        return self.root

    def audit(self, html, files=(), node=None):
        """Seed a project and run audit_viewer with `_find_node` pinned."""
        root = self.seed(html, files)
        with mock.patch.object(qa_gate, "_find_node", lambda: node):
            return qa_gate.audit_viewer(root)


class TestFindNode(unittest.TestCase):
    """_find_node: PATH first, then executable ~/.hermes/tools slots."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name)

    def install_hermes_node(self, version, executable=True):
        node_dir = self.home / ".hermes" / "tools" / version / "bin"
        node_dir.mkdir(parents=True)
        binary = node_dir / "node"
        binary.write_text("#!/bin/sh\n", encoding="utf-8")
        if executable:
            binary.chmod(0o755)
        return binary

    def patch_home(self):
        patcher = mock.patch.object(qa_gate.Path, "home",
                                    return_value=self.home)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_which_hit_short_circuits_hermes_scan(self):
        with mock.patch.object(qa_gate.shutil, "which",
                               lambda name: "/opt/node"):
            self.assertEqual(qa_gate._find_node(), "/opt/node")

    def test_hermes_slot_highest_version_wins(self):
        self.patch_home()
        self.install_hermes_node("node-v18.0.0")
        self.install_hermes_node("node-v20.1.0")
        with mock.patch.object(qa_gate.shutil, "which", lambda name: None):
            found = qa_gate._find_node()
        self.assertEqual(Path(found).name, "node")
        self.assertIn("node-v20.1.0", found)

    def test_hermes_slot_requires_exec_bit(self):
        self.patch_home()
        self.install_hermes_node("node-v22.9.9", executable=False)
        with mock.patch.object(qa_gate.shutil, "which", lambda name: None):
            self.assertIsNone(qa_gate._find_node())

    def test_falls_back_to_older_slot_when_newer_not_executable(self):
        self.patch_home()
        self.install_hermes_node("node-v20.0.0", executable=False)
        self.install_hermes_node("node-v18.0.0", executable=True)
        with mock.patch.object(qa_gate.shutil, "which", lambda name: None):
            found = qa_gate._find_node()
        self.assertIn("node-v18.0.0", found)

    def test_no_hermes_and_no_which_returns_none(self):
        self.patch_home()
        with mock.patch.object(qa_gate.shutil, "which", lambda name: None):
            self.assertIsNone(qa_gate._find_node())


class TestViewerHTMLParser(unittest.TestCase):
    """_ViewerHTMLParser: scripts, stylesheets and id collection."""

    def parse(self, html):
        parser = qa_gate._ViewerHTMLParser()
        parser.feed(html)
        return parser

    def test_scripts_store_sri_fields_with_defaults(self):
        # <script> switches html.parser into RAWTEXT mode, so both tags
        # must be explicitly closed for two entries to be collected.
        parser = self.parse(
            '<script src="a.js" integrity="sha384-x"></script>'
            "<script src=\"b.js\" crossorigin='anonymous'></script>")
        self.assertEqual([s["src"] for s in parser.scripts], ["a.js", "b.js"])
        self.assertEqual(parser.scripts[0]["integrity"], "sha384-x")
        self.assertEqual(parser.scripts[0]["crossorigin"], "")
        self.assertEqual(parser.scripts[1]["integrity"], "")
        self.assertEqual(parser.scripts[1]["crossorigin"], "anonymous")
        self.assertEqual(parser.ids, set())

    def test_stylesheet_links_collected_others_ignored(self):
        parser = self.parse(
            '<link rel="stylesheet" href="a.css">'
            '<link rel="icon" href="x.png">'
            '<link rel="stylesheet" href="https://cdn/b.css">')
        self.assertEqual(parser.stylesheets, ["a.css", "https://cdn/b.css"])

    def test_ids_collected_from_any_tag(self):
        parser = self.parse('<div id="one">x</div><p id="two">y</p>')
        self.assertEqual(parser.ids, {"one", "two"})

    def test_inline_script_without_src_ignored(self):
        parser = self.parse("<script>console.log(1)</script>")
        self.assertEqual(parser.scripts, [])


class TestAuditViewer(_Project):
    """audit_viewer: structural rules with the Node pass disabled."""

    def test_missing_index_skips_cleanly(self):
        self.viewer.mkdir()
        result = qa_gate.audit_viewer(self.root)
        self.assertEqual(result, {"ok": True, "skipped": True,
                                  "issues": [], "checked_js": 0})

    def test_missing_viewer_directory_skips_cleanly(self):
        result = qa_gate.audit_viewer(self.root)
        self.assertEqual(result, {"ok": True, "skipped": True,
                                  "issues": [], "checked_js": 0})

    def test_empty_html_reports_missing_scripts(self):
        result = self.audit("<html></html>")
        self.assertFalse(result["ok"])
        self.assertFalse(result["skipped"])
        self.assertEqual(result["scripts_count"], 0)
        issue, = result["issues"]
        self.assertIn("brak tag", fold(issue))
        self.assertIn("script", fold(issue))

    def test_capabilities_last_when_present_passes(self):
        html = ('<script src="app.js"></script>'
                '<script src="capabilities.js"></script>')
        result = self.audit(
            html, files=[("app.js", "1"), ("capabilities.js", "2")])
        self.assertEqual(result["issues"], [])
        self.assertTrue(result["ok"])
        self.assertEqual(result["scripts_count"], 2)

    def test_capabilities_not_last_flagged(self):
        html = ('<script src="capabilities.js"></script>'
                '<script src="app.js"></script>')
        result = self.audit(
            html, files=[("app.js", "1"), ("capabilities.js", "2")])
        self.assertFalse(result["ok"])
        ordering = [i for i in result["issues"] if "ostatnim" in fold(i)]
        self.assertEqual(len(ordering), 1)
        self.assertIn("app.js", ordering[0])

    def test_ordering_check_skipped_without_capabilities_file(self):
        # The ordering rule only applies while capabilities.js is on disk.
        html = ('<script src="capabilities.js"></script>'
                '<script src="app.js"></script>')
        result = self.audit(html, files=[("app.js", "1")])
        folds = [fold(i) for i in result["issues"]]
        self.assertTrue(all("ostatnim" not in i for i in folds))
        self.assertTrue(
            any("capabilities.js" in i and "skryptu" in i for i in folds))

    def test_remote_script_with_semver_sri_and_anonymous_passes(self):
        result = self.audit(_GOOD_REMOTE)
        self.assertEqual(result["issues"], [])
        self.assertTrue(result["ok"])
        self.assertEqual(result["scripts_count"], 1)

    def test_remote_script_without_semver_flagged(self):
        html = ('<script src="https://cdn.example/latest/y.js" '
                'integrity="sha384-AbC" crossorigin="anonymous"></script>')
        result = self.audit(html)
        issue, = result["issues"]
        folded = fold(issue)
        self.assertIn("wersji semver", folded)
        self.assertIn("y.js", folded)

    def test_remote_bad_integrity_and_missing_crossorigin_one_issue(self):
        # One broken remote script produces a single combined SRI issue.
        html = ('<script src="https://cdn.example/x@1.0.0/y.js" '
                'integrity="sha256-AbC"></script>')
        result = self.audit(html)
        issue, = result["issues"]
        folded = fold(issue)
        self.assertIn("SRI", folded)
        self.assertIn("crossorigin", folded)
        self.assertFalse(result["ok"])

    def test_remote_good_integrity_wrong_crossorigin_flagged(self):
        html = ('<script src="https://cdn.example/x@1.0.0/a.js" '
                'integrity="sha384-AbC" crossorigin="use-credentials">'
                "</script>")
        result = self.audit(html)
        issue, = result["issues"]
        self.assertIn("SRI", fold(issue))
        self.assertFalse(result["ok"])

    def test_local_script_query_string_ignored_for_existence(self):
        result = self.audit('<script src="app.js?v=3"></script>',
                            files=[("app.js", "1")])
        self.assertEqual(result["issues"], [])
        self.assertTrue(result["ok"])

    def test_local_script_missing_reported_without_query(self):
        result = self.audit('<script src="app.js?v=3"></script>')
        issue, = result["issues"]
        self.assertIn("viewer/app.js", fold(issue))

    def test_missing_stylesheet_reported(self):
        html = ('<link rel="stylesheet" href="style.css">'
                '<script src="app.js"></script>')
        result = self.audit(html, files=[("app.js", "1")])
        issue, = result["issues"]
        self.assertIn("arkusza styl", fold(issue))
        self.assertIn("viewer/style.css", issue)

    def test_innerhtml_forbidden_only_on_strict_surfaces(self):
        html = '<script src="app.js"></script>'
        result = self.audit(html, files=[
            ("app.js", "el.innerHTML = x;"),          # allowed surface
            ("agents.js", "el.innerHTML = x;"),       # strict surface
            ("mission.js", "el.innerHTML = x;"),       # strict surface
        ])
        issues = [fold(i) for i in result["issues"]]
        xss = [i for i in issues if "innerHTML" in i]
        self.assertEqual(len(xss), 2)
        self.assertTrue(all("XSS" in i for i in xss))
        self.assertFalse(result["ok"])

    def test_strict_surface_clean_produces_no_issue(self):
        html = '<script src="agents.js"></script>'
        result = self.audit(html, files=[("agents.js", "el.textContent = y;")])
        self.assertEqual(result["issues"], [])
        self.assertTrue(result["ok"])


class TestNodeSyntaxPass(_Project):
    """The Node --check pass runs through a fake subprocess seam."""

    def audit_with_fake_node(self, node, outcome):
        """Patch _find_node + subprocess.run; return (result, argvs)."""
        captured = []

        def fake_run(argv, *extra, **kwargs):
            captured.append(list(argv))
            return outcome

        with mock.patch.object(qa_gate, "_find_node", lambda: node), \
                mock.patch.object(qa_gate, "subprocess",
                                  _SubprocessModule(fake_run)):
            result = qa_gate.audit_viewer(self.root)
        return result, captured

    def test_syntax_pass_counts_and_invokes_sorted(self):
        html = ('<script src="b.js"></script>'
                '<script src="a.js"></script>')
        self.seed(html, files=[("a.js", "var x;"), ("b.js", "var y;")])
        passing = subprocess.CompletedProcess([], 0)
        result, captured = self.audit_with_fake_node("/fake/node", passing)
        self.assertTrue(result["ok"])
        self.assertFalse(result["skipped"])
        self.assertEqual(result["checked_js"], 2)
        self.assertEqual([argv[:2] for argv in captured],
                         [["/fake/node", "--check"],
                          ["/fake/node", "--check"]])
        self.assertEqual([Path(argv[-1]).name for argv in captured],
                         ["a.js", "b.js"])

    def test_syntax_error_first_line_only_and_truncated(self):
        html = '<script src="bad.js"></script>'
        self.seed(html, files=[("bad.js", "!!!")])
        long_line = "e" * 300
        failing = subprocess.CompletedProcess(
            [], 1, stdout="", stderr=long_line + "\nsecond line\n")
        result, captured = self.audit_with_fake_node("/fake/node", failing)
        self.assertFalse(result["ok"])
        self.assertEqual(result["checked_js"], 1)
        issue, = result["issues"]
        folded = fold(issue)
        # NFKD has no decomposition for the Polish stroke-l letter, so it
        # vanishes entirely: the folded artifact is "skadni JS".
        self.assertIn("skadni JS", folded)
        self.assertIn("bad.js", folded)
        self.assertNotIn("second line", issue)  # only the first line
        self.assertIn("e" * 200, issue)         # err_line[:200] tail cut
        self.assertNotIn("e" * 201, issue)

    def test_no_node_means_no_js_checks(self):
        html = '<script src="capabilities.js"></script>'
        result = self.audit(html, files=[("capabilities.js", "1")], node=None)
        self.assertEqual(result["checked_js"], 0)
        self.assertEqual(result["issues"], [])

    @unittest.skipIf(qa_gate._find_node() is None, "node unavailable")
    def test_real_node_integration(self):
        html = ('<script src="good.js"></script>'
                '<script src="bad.js"></script>')
        self.seed(html, files=[
            ("good.js", "var x = 1;\n"),
            ("bad.js", "var x = ;\n"),
        ])
        result = qa_gate.audit_viewer(self.root)
        self.assertFalse(result["ok"])
        self.assertEqual(result["checked_js"], 2)
        issue, = result["issues"]
        self.assertIn("skadni JS", fold(issue))
        self.assertIn("bad.js", fold(issue))


class _SubprocessModule:
    """Minimal stand-in for the subprocess module: only run()."""

    def __init__(self, run):
        self.run = run


if __name__ == "__main__":
    unittest.main()
