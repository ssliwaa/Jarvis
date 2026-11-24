"""Skill library tests."""
import os
import tempfile
import unittest
from pathlib import Path

import skills_store

SANDBOXED = os.environ.get("JARVIS_VERIFY_SANDBOX") == "1"


class SkillStoreTests(unittest.TestCase):
    def test_list_view_search_and_bad_name(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            folder = root / "demo-skill"
            folder.mkdir()
            (folder / "SKILL.md").write_text(
                "---\nname: demo-skill\ndescription: Use when testing skills.\n---\n\n# Demo\n\nRun the test.\n",
                encoding="utf-8")
            store = skills_store.SkillStore(root)
            rows = store.list()
            self.assertEqual(rows[0]["name"], "demo-skill")
            self.assertIn("Run the test", store.view("demo-skill")["content"])
            self.assertTrue(store.search("test"))
            with self.assertRaises(ValueError):
                store.view("../etc/passwd")

    def test_nested_hermes_roots_are_found_and_prioritised(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bundled = root / "bundled"
            hermes = root / "hermes"
            plugins = root / "plugins"
            # bundled skill, one level deep
            (bundled / "alpha").mkdir(parents=True)
            (bundled / "alpha" / "SKILL.md").write_text(
                "---\nname: alpha\ndescription: bundled copy\n---\n\nbundled body\n", encoding="utf-8")
            # hermes skill, two levels deep, same name: must not shadow the bundled one
            (hermes / "category" / "alpha").mkdir(parents=True)
            (hermes / "category" / "alpha" / "SKILL.md").write_text(
                "---\nname: alpha\ndescription: hermes copy\n---\n\nhermes body\n", encoding="utf-8")
            # hermes skill only in hermes
            (hermes / "category" / "beta").mkdir(parents=True)
            (hermes / "category" / "beta" / "SKILL.md").write_text(
                "---\nname: beta\ndescription: nested skill\n---\n\nbeta body\n", encoding="utf-8")
            # plugin skill, deeper still
            (plugins / "plug" / "skills" / "gamma").mkdir(parents=True)
            (plugins / "plug" / "skills" / "gamma" / "SKILL.md").write_text(
                "---\nname: gamma\ndescription: plugin skill\n---\n\ngamma body\n", encoding="utf-8")
            # junk that must be skipped
            (hermes / "node_modules" / "junk").mkdir(parents=True)
            (hermes / "node_modules" / "junk" / "SKILL.md").write_text(
                "---\nname: junk\n---\n", encoding="utf-8")
            (hermes / "too" / "deep" / "x" / "y" / "z").mkdir(parents=True)
            (hermes / "too" / "deep" / "x" / "y" / "z" / "SKILL.md").write_text(
                "---\nname: toodeep\n---\n", encoding="utf-8")

            store = skills_store.SkillStore(bundled, hermes, plugins)
            names = [row["name"] for row in store.list()]
            self.assertEqual(names, ["alpha", "beta", "gamma"])
            self.assertIn("bundled body", store.view("alpha")["content"])
            self.assertIn("nested skill", store.view("beta")["description"])
            self.assertIn("plugin skill", store.search("gamma")[0]["description"])
            self.assertFalse(store.search(""))

    @unittest.skipIf(SANDBOXED, "the Hermes profile is hidden in the verification sandbox")
    def test_hermes_profile_skills_are_visible_to_jarvis(self):
        """Live contract: the user's Hermes library is readable, not executed."""
        store = skills_store.SkillStore()
        rows = store.list()
        self.assertGreaterEqual(len(rows), 10)
        self.assertTrue(any(".hermes" in row["path"] for row in rows),
                        "the Hermes skill root is not wired into the store")


if __name__ == "__main__":
    unittest.main()
