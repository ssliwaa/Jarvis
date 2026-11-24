"""Deep research: planner, per-question citations and failure isolation."""
import unittest
from unittest import mock

import web_research


def source(url, question):
    return {"url": url, "title": url.rsplit("/", 1)[-1], "snippet": "", "id": "W1",
            "question": question}


class DeepResearchTests(unittest.TestCase):
    def test_plan_is_cleaned_deduplicated_and_capped(self):
        plan = web_research.plan_questions(
            "tv 65 cali", lambda query, limit: ["1. tv 65 cali", "TV 65 CALI", "", "tv oled"], 3)
        self.assertEqual(plan, ["tv 65 cali", "tv oled"])

    def test_broken_planner_falls_back_to_the_query(self):
        def broken(query, limit):
            raise RuntimeError("no model")
        self.assertEqual(web_research.plan_questions("q", broken, 3), ["q"])

    def test_sources_are_merged_deduplicated_and_labelled(self):
        def fake_research(query, limit=5, fetch_top=2, timeout=15):
            data = {
                "tv 65": [source("https://a/1", query), source("https://a/2", query)],
                "tv oled": [source("https://a/2", query), source("https://a/3", query)],
            }
            return {"query": query, "sources": data[query]}

        with mock.patch.object(web_research, "research", side_effect=fake_research):
            report = web_research.deep_research(
                "tv 65 cali", planner=lambda query, limit: ["tv 65", "tv oled"], limit=5)
        self.assertEqual(report["plan"], ["tv 65", "tv oled"])
        self.assertEqual([item["url"] for item in report["sources"]],
                         ["https://a/1", "https://a/2", "https://a/3"])
        self.assertEqual([item["id"] for item in report["sources"]], ["W1", "W2", "W3"])
        self.assertEqual(report["sources"][0]["question"], "tv 65")
        self.assertEqual(report["sources"][2]["question"], "tv oled")

    def test_one_failing_sub_question_does_not_destroy_the_rest(self):
        def fake_research(query, limit=5, fetch_top=2, timeout=15):
            if query == "bad":
                raise web_research.ResearchError("blocked")
            return {"query": query, "sources": [source("https://ok/1", query)]}

        with mock.patch.object(web_research, "research", side_effect=fake_research):
            report = web_research.deep_research(
                "q", planner=lambda query, limit: ["bad", "good"], limit=5)
        self.assertEqual(len(report["sources"]), 1)
        self.assertEqual(report["sources"][0]["url"], "https://ok/1")

    def test_empty_query_is_rejected(self):
        with self.assertRaises(web_research.ResearchError):
            web_research.deep_research("   ")


if __name__ == "__main__":
    unittest.main()
