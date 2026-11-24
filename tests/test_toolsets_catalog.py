"""toolsets_catalog: execution runners, cron store, HTML extraction and schema export.

This suite pins the catalogue engine behind connectors_hub: the readable-text
HTML stripper (script/style/noscript/svg/nav/footer skipped, chunks
whitespace-normalised, max_chars cap), the cron job store (0600 file / 0700
directory, corrupted JSON fallback, newest-first insertion, 50-job cap,
toggle/remove semantics), every run_* execution boundary behind the patched
module-level `_json_http` helper (Home Assistant domain filtering and the
confirmed=True call gate with entity_id injection into service_data, Notion's
default title and cfg-level parent_page_id fallback with the 1900-char
content clip, Todoist caps, the Obsidian vault path validated through
code_index.validate_safe_project_dir with hidden-directory exclusion and the
stamped Daily note, Home Assistant/Notion/GitHub write gates), the web tool
backends (ddg zero-key parsing, tavily api_key in the body, brave
X-Subscription-Token, searxng base-url key, ddg fallback on empty key),
messaging routing (discord webhook validation, ntfy topic quoting into
https://ntfy.sh/<topic>, slack webhook vs token paths), developer tools
(linear Authorization without the Bearer prefix, GitHub repo-format gating and
confirm gates), weather coords parsing (malformed coordinates surface the raw
ValueError — pinned as-is), Spotify verbs with POST for next/previous and PUT
otherwise, remote MCP HTTP JSON-RPC framing with Bearer auth, and the LLM
schema exporter (zero-config readiness, enabled-connector matching, toolset
disabling dropping even zero-config tools, the jarvis__<prov>__<tool> naming).

All assertions were pinned empirically before writing. Network calls are
stubbed at the `_json_http` module boundary and via urllib.request.urlopen;
the cron store is redirected to a per-test sandbox by patching
toolsets_catalog.agent_cli.ROOT.
"""
import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import toolsets_catalog

FAKE_HTML = (
    '<html><body>'
    '<nav>Menu nawigacji</nav>'
    '<h1>Tytul glowny</h1>'
    '<script>alert("x");</script>'
    '<style>.x{color:red}</style>'
    '<p>Akapit pierwszy   z   przesunięciami.</p>'
    '<footer>Stopka</footer>'
    '<svg>circle</svg>'
    '<noscript>enable js</noscript>'
    '</body></html>'
)


class FakeRawResponse:
    status = 200

    def __init__(self, payload, status=200):
        self.payload = payload if isinstance(payload, bytes) else str(payload).encode()
        self.status = status

    def read(self, size=-1):
        return self.payload

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class RunnerBase(unittest.TestCase):
    """Patches the module-level `_json_http` boundary used by all run_* helpers."""

    def setUp(self):
        self.calls = []
        self.payloads = {}
        base = self

        def fake_json_http(url, *, method="GET", headers=None, body=None, timeout=12.0):
            base.calls.append({"url": url, "method": method,
                               "headers": dict(headers or {}), "body": body})
            return base.payloads.get(url, {})

        self._patcher = patch.object(toolsets_catalog, "_json_http", fake_json_http)
        self._patcher.start()
        self.addCleanup(self._patcher.stop)
        self.validator_seen = []

    def validator(self, url):
        self.validator_seen.append(url)
        return url

    def stub(self, url, payload):
        self.payloads[url] = payload

    def last(self):
        return self.calls[-1]


class TestHtmlCleaner(unittest.TestCase):
    def test_skips_chrome_tags_and_normalises_whitespace(self):
        cleaned = toolsets_catalog.html_to_clean_text(FAKE_HTML)
        self.assertEqual(cleaned.split("\n"), ["Tytul glowny",
                                               "Akapit pierwszy z przesunięciami."])

    def test_caps_at_max_chars(self):
        self.assertEqual(len(toolsets_catalog.html_to_clean_text("word " * 4000,
                                                                 max_chars=800)), 800)

    def test_empty_inputs(self):
        self.assertEqual(toolsets_catalog.html_to_clean_text(""), "")
        self.assertEqual(toolsets_catalog.html_to_clean_text(None), "")


class CronStoreBase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="tzc_")
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(self._tmp.name)
        self.agents_dir = self.tmp / "agents"
        self._cli = patch.object(toolsets_catalog, "agent_cli",
                                 SimpleNamespace(ROOT=self.agents_dir / "agent_cli.py"))
        self._cli.start()
        self.addCleanup(self._cli.stop)

    @property
    def cron_path(self):
        return self.agents_dir / "scheduled_jobs.json"


class TestCronStore(CronStoreBase):
    def test_list_empty_and_corrupt_fallbacks(self):
        self.assertEqual(toolsets_catalog.cron_manage("cron_list", {}),
                         {"ok": True, "count": 0, "jobs": []})
        # the first cron_manage call already created the 0700 directory
        self.cron_path.write_text("broken{", encoding="utf-8")
        self.assertEqual(toolsets_catalog.cron_manage("cron_list", {})["count"], 0)
        self.cron_path.write_text('{"a": 1}', encoding="utf-8")  # not a list
        self.assertEqual(toolsets_catalog.cron_manage("cron_list", {})["count"], 0)

    def test_create_defaults_caps_and_persists(self):
        made = toolsets_catalog.cron_manage(
            "cron_create", {"name": "Poranek", "prompt": "Sprawdz poczte", "deliver": "telegram"})
        job = made["job"]
        self.assertTrue(job["id"].startswith("cron-"))
        self.assertEqual(len(job["id"]), 13)  # "cron-" (5) + 8 hex chars
        self.assertEqual(job["schedule"], "daily 08:30")
        self.assertEqual(job["deliver"], "telegram")
        self.assertTrue(job["enabled"])
        self.assertEqual(toolsets_catalog.cron_manage("cron_create", {"prompt": "Nazwa z promptu"})
                         ["job"]["name"], "Nazwa z promptu")
        defaults = toolsets_catalog.cron_manage("cron_create", {"name": "X"})["job"]
        self.assertEqual((defaults["deliver"], defaults["schedule"]), ("local", "daily 08:30"))
        with self.assertRaises(ValueError):
            toolsets_catalog.cron_manage("cron_create", {})
        self.assertEqual(self.cron_path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.agents_dir.stat().st_mode & 0o777, 0o700)

    def test_newest_first_and_cap_50(self):
        for i in range(51):
            toolsets_catalog.cron_manage("cron_create", {"name": f"job{i}"})
        jobs = toolsets_catalog.cron_manage("cron_list", {})["jobs"]
        self.assertEqual(len(jobs), 50)
        self.assertEqual(jobs[0]["name"], "job50")  # newest first
        self.assertNotIn("job0", [j["name"] for j in jobs])  # oldest evicted

    def test_toggle_flips_persists_and_missing_raises(self):
        jid = toolsets_catalog.cron_manage("cron_create", {"name": "A"})["job"]["id"]
        first = toolsets_catalog.cron_manage("cron_toggle", {"job_id": jid})
        self.assertFalse(first["job"]["enabled"])
        second = toolsets_catalog.cron_manage("cron_toggle", {"job_id": jid})
        self.assertTrue(second["job"]["enabled"])
        with self.assertRaises(ValueError) as ctx:
            toolsets_catalog.cron_manage("cron_toggle", {"job_id": "cron-zzz"})
        self.assertIn("Nie znaleziono zadania", str(ctx.exception))

    def test_remove_and_unknown_action(self):
        jid = toolsets_catalog.cron_manage("cron_create", {"name": "A"})["job"]["id"]
        self.assertEqual(toolsets_catalog.cron_manage("cron_remove", {"job_id": jid}),
                         {"ok": True, "removed": True})
        self.assertEqual(toolsets_catalog.cron_manage("cron_remove", {"job_id": jid}),
                         {"ok": True, "removed": False})
        with self.assertRaises(ValueError) as ctx:
            toolsets_catalog.cron_manage("cron_bogus", {})
        self.assertIn("Nieznana operacja cron", str(ctx.exception))


class TestHomeAssistant(RunnerBase):
    CFG = {"ha_url": "http://192.168.1.5:8123", "api_key": "TOK"}

    def test_config_gate_and_domain_filter(self):
        with self.assertRaises(ValueError) as ctx:
            toolsets_catalog.run_home_assistant("ha_list_entities", {}, {})
        self.assertIn("ha_url oraz api_key", str(ctx.exception))
        states = [{"entity_id": "light.biuro", "state": "on",
                   "attributes": {"friendly_name": "Biuro"}},
                  {"entity_id": "sensor.temp", "state": "21.5", "attributes": {}}]
        self.stub("http://192.168.1.5:8123/api/states", states)
        out = toolsets_catalog.run_home_assistant(
            "ha_list_entities", self.CFG, {"domain": "sensor"})
        self.assertEqual(out["count"], 1)  # domain prefix filter applied
        entity = out["entities"][0]
        self.assertEqual(entity["entity_id"], "sensor.temp")
        self.assertEqual(entity["friendly_name"], "sensor.temp")  # fallback to id

    def test_get_state_quotes_and_requires_entity(self):
        self.stub("http://x/api/states/sensor.temp", {"entity_id": "sensor.temp", "state": "21.5"})
        out = toolsets_catalog.run_home_assistant(
            "ha_get_state", {"ha_url": "http://x", "api_key": "T"}, {"entity_id": "sensor.temp"})
        self.assertEqual(out["entity"]["state"], "21.5")
        with self.assertRaises(ValueError):
            toolsets_catalog.run_home_assistant(
                "ha_get_state", {"ha_url": "http://x", "api_key": "T"}, {})

    def test_services_domains(self):
        self.stub("http://x/api/services", [{"domain": "light"}, {"domain": "climate"}])
        out = toolsets_catalog.run_home_assistant(
            "ha_list_services", {"ha_url": "http://x", "api_key": "T"}, {})
        self.assertEqual(out, {"ok": True, "domains": ["light", "climate"]})

    def test_call_service_gates_and_injects_entity(self):
        cfg = {"ha_url": "http://x", "api_key": "T"}
        with self.assertRaises(ValueError) as ctx:
            toolsets_catalog.run_home_assistant(
                "ha_call_service", cfg, {"service": "light.turn_on"})
        self.assertIn("wymaga confirmed=True", str(ctx.exception))
        with self.assertRaises(ValueError):
            toolsets_catalog.run_home_assistant(
                "ha_call_service", cfg, {"confirmed": True, "service": "badformat"})
        self.stub("http://x/api/services/light/turn_on", [{"ok": 1}, {"ok": 2}])
        out = toolsets_catalog.run_home_assistant(
            "ha_call_service", cfg,
            {"confirmed": True, "service": "light.turn_on",
             "entity_id": "light.biuro", "service_data": {"brightness": 3}})
        self.assertEqual(out, {"ok": True, "service": "light.turn_on", "changed": 2})
        # entity_id is injected into the POST body via setdefault
        self.assertEqual(self.last()["body"], {"brightness": 3, "entity_id": "light.biuro"})
        self.assertEqual(self.last()["method"], "POST")
        with self.assertRaises(ValueError):
            toolsets_catalog.run_home_assistant("ha_nope", cfg, {})


class TestNotion(RunnerBase):
    def test_gate_and_search_shape(self):
        with self.assertRaises(ValueError):
            toolsets_catalog.run_notion("notion_search", {}, {})
        self.stub("https://api.notion.com/v1/search",
                  {"results": [{"id": "p1", "object": "page", "url": "https://n.so/p1"}]})
        out = toolsets_catalog.run_notion("notion_search", {"api_key": "k"}, {"query": "hello"})
        self.assertEqual(out["count"], 1)
        self.assertEqual(out["results"][0]["id"], "p1")
        self.assertEqual(self.last()["body"], {"query": "hello", "page_size": 12})

    def test_create_gates_and_defaults(self):
        with self.assertRaises(ValueError) as ctx:
            toolsets_catalog.run_notion("notion_create_page", {"api_key": "k"}, {})
        self.assertIn("wymaga confirmed=True", str(ctx.exception))
        with self.assertRaises(ValueError):
            toolsets_catalog.run_notion("notion_create_page", {"api_key": "k"}, {"confirmed": True})
        self.stub("https://api.notion.com/v1/pages", {"id": "np", "url": "u"})
        toolsets_catalog.run_notion(
            "notion_create_page", {"api_key": "k"},
            {"confirmed": True, "parent_page_id": "p1", "content": "C" * 3000})
        body = self.last()["body"]
        self.assertEqual(body["properties"]["title"]["title"][0]["text"]["content"],
                         "Notatka Jarvisa")  # default title
        text = body["children"][0]["paragraph"]["rich_text"][0]["text"]["content"]
        self.assertEqual(len(text), 1900)  # content clipped
        # cfg-level parent fallback
        self.stub("https://api.notion.com/v1/pages", {"id": "cfg", "url": "u2"})
        toolsets_catalog.run_notion(
            "notion_create_page", {"api_key": "k", "parent_page_id": "CFGPAGE"},
            {"confirmed": True})
        self.assertEqual(self.last()["body"]["parent"]["page_id"], "CFGPAGE")


class TestTodoist(RunnerBase):
    def test_gate_and_task_listing(self):
        with self.assertRaises(ValueError):
            toolsets_catalog.run_todoist("todoist_tasks", {}, {})
        self.stub("https://api.todoist.com/rest/v2/tasks",
                  [{"id": str(i), "content": f"Z{i}", "due": {"string": "today"}}
                   for i in range(30)])
        out = toolsets_catalog.run_todoist("todoist_tasks", {"api_key": "k"}, {})
        self.assertEqual(out["count"], 25)  # capped listing

    def test_add_task_content_gate_and_due_string(self):
        with self.assertRaises(ValueError):
            toolsets_catalog.run_todoist("todoist_add_task", {"api_key": "k"}, {})
        self.stub("https://api.todoist.com/rest/v2/tasks", {"id": "n1", "content": "Nowe"})
        out = toolsets_catalog.run_todoist(
            "todoist_add_task", {"api_key": "k"},
            {"content": "Nowe", "due_string": "tomorrow"})
        self.assertEqual(out, {"ok": True, "id": "n1", "content": "Nowe"})
        self.assertEqual(self.last()["body"], {"content": "Nowe", "due_string": "tomorrow"})


class TestObsidian(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="tzob_")
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(self._tmp.name)
        self.vault = self.tmp / "vault"
        self.vault.mkdir()
        (self.vault / "alpha.md").write_text(
            "Notatka o **subwoferach** domowych genelnie.\n", encoding="utf-8")
        (self.vault / "beta.md").write_text("Inna tresc calkowicie.\n", encoding="utf-8")
        hidden = self.vault / ".hidden"
        hidden.mkdir()
        (hidden / "h.md").write_text("ukryte\n", encoding="utf-8")
        self.cfg = {"vault_path": str(self.vault)}

    def test_gate_and_safe_directory_validation(self):
        with self.assertRaises(ValueError):
            toolsets_catalog.run_obsidian("obsidian_search", {}, {"query": "x"})
        # unsuitable paths must be rejected by code_index.validate_safe_project_dir
        with self.assertRaises(ValueError):
            toolsets_catalog.run_obsidian(
                "obsidian_search", {"vault_path": str(self.tmp / "missing-vault")}, {})

    def test_search_matches_content_stem_and_skips_hidden(self):
        by_content = toolsets_catalog.run_obsidian("obsidian_search", self.cfg, {"query": "subwofer"})
        self.assertEqual([n["note"] for n in by_content["notes"]], ["alpha.md"])
        self.assertLessEqual(len(by_content["notes"][0]["preview"]), 200)
        by_stem = toolsets_catalog.run_obsidian("obsidian_search", self.cfg, {"query": "beta"})
        self.assertEqual([n["note"] for n in by_stem["notes"]], ["beta.md"])
        empty_q = toolsets_catalog.run_obsidian("obsidian_search", self.cfg, {})
        self.assertEqual(sorted(n["note"] for n in empty_q["notes"]), ["alpha.md", "beta.md"])

    def test_daily_append_stamps_and_accumulates(self):
        with self.assertRaises(ValueError):
            toolsets_catalog.run_obsidian("obsidian_daily_append", self.cfg, {})
        first = toolsets_catalog.run_obsidian("obsidian_daily_append", self.cfg, {"text": "Pierwszy"})
        toolsets_catalog.run_obsidian("obsidian_daily_append", self.cfg, {"text": "Drugi"})
        self.assertEqual(first["note"], f"Daily/{datetime.now().strftime('%Y-%m-%d')}.md")
        lines = [line for line in (self.vault / "Daily" /
                                   f"{datetime.now().strftime('%Y-%m-%d')}.md"
                                   ).read_text(encoding="utf-8").split("\n") if line]
        self.assertTrue(lines[0].startswith("# "))  # header created on first append
        self.assertTrue(lines[1].startswith("- **"))  # timestamped bullet
        self.assertTrue(lines[1].endswith("Pierwszy"))
        self.assertTrue(lines[-1].endswith("Drugi"))

    def test_unknown_action(self):
        with self.assertRaises(ValueError):
            toolsets_catalog.run_obsidian("obsidian_nope", self.cfg, {})


class TestWebTools(RunnerBase):
    def test_extract_validates_and_cleans(self):
        payload = "<html><body><p>Tresc strony.</p><script>bad()</script></body></html>"
        with patch("urllib.request.urlopen",
                   lambda req, timeout=None: FakeRawResponse(payload)):
            out = toolsets_catalog.run_web_tools(
                "web_extract", {}, {"url": "https://example.com/doc"}, self.validator)
        self.assertTrue(out["ok"])
        self.assertEqual(out["url"], "https://example.com/doc")
        self.assertEqual(out["content"], "Tresc strony.")
        self.assertNotIn("bad()", out["content"])
        self.assertEqual(self.validator_seen, ["https://example.com/doc"])

    def test_ddg_zero_key_parse_and_query_gate(self):
        base = "https://api.duckduckgo.com/?q=python&format=json&no_html=1&skip_disambig=1"
        self.stub(base, {"AbstractText": "Python to jezyk.", "AbstractURL": "https://py.org",
                         "Heading": "Python",
                         "RelatedTopics": [{"Text": "Temat A", "FirstURL": "https://a"},
                                           {"Text": "Temat B", "FirstURL": "https://b"},
                                           "not-a-dict"]})
        out = toolsets_catalog.run_web_tools("web_search", {}, {"query": "python"}, self.validator)
        self.assertEqual(out["backend"], "ddg")
        self.assertEqual(out["results"][0]["title"], "Python")  # from Heading
        self.assertEqual(len(out["results"]), 3)  # abstract + 2 dict topics; string skipped
        with self.assertRaises(ValueError) as ctx:
            toolsets_catalog.run_web_tools("web_search", {}, {}, self.validator)
        self.assertIn("Podaj frazę wyszukiwania", str(ctx.exception))

    def test_backend_selection_and_ddg_fallback(self):
        self.stub("https://api.tavily.com/search",
                  {"results": [{"title": "T1", "url": "https://t1", "content": "c1"}]})
        out = toolsets_catalog.run_web_tools(
            "web_search", {"backend": "tavily", "api_key": "tv"}, {"query": "x"}, self.validator)
        self.assertEqual(out["backend"], "tavily")
        self.assertEqual(self.last()["body"], {"api_key": "tv", "query": "x", "max_results": 6})
        self.stub("https://api.search.brave.com/res/v1/web/search?q=x&count=6",
                  {"web": {"results": [{"title": "B", "url": "u", "description": "d"}]}})
        out = toolsets_catalog.run_web_tools(
            "web_search", {"backend": "brave", "api_key": "bv"}, {"query": "x"}, self.validator)
        self.assertEqual(out["results"][0]["snippet"], "d")  # from description
        self.assertEqual(self.last()["headers"], {"X-Subscription-Token": "bv"})
        self.stub("https://searx.local/search?q=x&format=json",
                  {"results": [{"title": "S", "url": "u", "content": "c"}]})
        out = toolsets_catalog.run_web_tools(
            "web_search", {"backend": "searxng", "api_key": "https://searx.local"},
            {"query": "x"}, self.validator)
        self.assertEqual(self.last()["url"],
                         "https://searx.local/search?q=x&format=json")  # key used as base url
        base = "https://api.duckduckgo.com/?q=x&format=json&no_html=1&skip_disambig=1"
        self.stub(base, {"AbstractText": "A", "RelatedTopics": []})
        out = toolsets_catalog.run_web_tools(
            "web_search", {"backend": "tavily", "api_key": ""}, {"query": "x"}, self.validator)
        self.assertEqual(out["backend"], "ddg")  # empty key falls back to zero-key ddg


class TestMessagingExtra(RunnerBase):
    def test_discord_send_validates_and_posts_content(self):
        self.stub("https://discord.com/api/webhooks/1/abc", {})
        out = toolsets_catalog.run_messaging_extra(
            "discord_send", {"webhook_url": "https://discord.com/api/webhooks/1/abc"},
            {"text": "hello"}, self.validator)
        self.assertEqual(out, {"ok": True, "delivered": "discord"})
        self.assertEqual(self.validator_seen, ["https://discord.com/api/webhooks/1/abc"])
        self.assertEqual(self.last()["body"], {"content": "hello"})
        self.assertEqual(self.last()["method"], "POST")

    def test_ntfy_topic_quoting_and_full_url(self):
        seen_urls = []

        def capture_urlopen(req, timeout=None):
            seen_urls.append((req.full_url, req.data, req.get_method()))
            return FakeRawResponse(b"{}")

        with patch("urllib.request.urlopen", capture_urlopen):
            out = toolsets_catalog.run_messaging_extra(
                "ntfy_publish", {"topic": "my private topic"}, {"text": "alert"},
                self.validator)
        self.assertEqual(out, {"ok": True, "delivered": "ntfy"})
        # raw topic is quoted into the public ntfy.sh base and posted as body
        self.assertEqual(seen_urls[0], ("https://ntfy.sh/my%20private%20topic",
                                         b"alert", "POST"))
        self.stub("https://ntfy.example.com/custom", {})
        with patch("urllib.request.urlopen", capture_urlopen):
            toolsets_catalog.run_messaging_extra(
                "ntfy_publish", {"topic": "https://ntfy.example.com/custom"},
                {"text": "a"}, self.validator)
        self.assertEqual(self.validator_seen, ["https://ntfy.example.com/custom"])
        self.assertEqual(seen_urls[1][0], "https://ntfy.example.com/custom")
        with self.assertRaises(ValueError):
            toolsets_catalog.run_messaging_extra("ntfy_publish", {}, {"text": "a"},
                                                 self.validator)

    def test_slack_webhook_path_prefers_webhook_over_token(self):
        self.stub("https://hooks.slack.com/services/T00/B00/xx", {})
        out = toolsets_catalog.run_messaging_extra(
            "slack_send", {"channel": "https://hooks.slack.com/services/T00/B00/xx"},
            {"text": "hi"}, self.validator)
        self.assertEqual(out, {"ok": True, "delivered": "slack_webhook"})
        self.assertEqual(self.last()["body"], {"text": "hi"})
        with self.assertRaises(ValueError) as ctx:
            toolsets_catalog.run_messaging_extra("slack_send", {"channel": "C123"},
                                                 {"text": "hi"}, self.validator)
        self.assertIn("Slack wymaga", str(ctx.exception))

    def test_slack_token_path_and_history(self):
        self.stub("https://slack.com/api/chat.postMessage", {"ok": True, "ts": "123.456"})
        out = toolsets_catalog.run_messaging_extra(
            "slack_send", {"channel": "C123", "bot_token": "xoxb"},
            {"text": "hi"}, self.validator)
        self.assertEqual(out, {"ok": True, "ts": "123.456"})
        self.assertEqual(self.last()["headers"]["Authorization"], "Bearer xoxb")
        self.stub("https://slack.com/api/conversations.history?channel=C123&limit=10",
                  {"ok": True, "messages": [{"text": "m", "ts": "1"}]})
        out = toolsets_catalog.run_messaging_extra(
            "slack_history", {"channel": "C123", "bot_token": "xoxb"}, {}, self.validator)
        self.assertEqual(out, {"ok": True, "messages": [{"text": "m", "ts": "1"}]})


class TestDeveloperTools(RunnerBase):
    def test_api_gate_and_linear_query(self):
        with self.assertRaises(ValueError):
            toolsets_catalog.run_developer_tools("github_issues", {}, {})
        self.stub("https://api.linear.app/graphql",
                  {"data": {"viewer": {"assignedIssues": {"nodes": [
                      {"identifier": "ENG-1", "title": "T", "state": {"name": "Todo"}}]}}}})
        out = toolsets_catalog.run_developer_tools("linear_issues", {"api_key": "lin"}, {})
        self.assertEqual(out["issues"][0]["identifier"], "ENG-1")
        self.assertEqual(self.last()["headers"], {"Authorization": "lin"})  # no Bearer prefix

    def test_github_notifications_and_repo_format_gate(self):
        self.stub("https://api.github.com/notifications?per_page=15",
                  [{"repository": {"full_name": "o/r"}, "subject": {"title": "Issue 1"}}])
        out = toolsets_catalog.run_developer_tools("github_notifications", {"api_key": "gh"}, {})
        self.assertEqual(out["notifications"], [{"repo": "o/r", "title": "Issue 1"}])
        with self.assertRaises(ValueError):
            toolsets_catalog.run_developer_tools("github_issues", {"api_key": "gh"}, {})

    def test_github_issues_and_confirm_gate(self):
        self.stub("https://api.github.com/repos/o/r/issues?state=open&per_page=15",
                  [{"number": 1, "title": "T", "html_url": "u"}])
        out = toolsets_catalog.run_developer_tools(
            "github_issues", {"api_key": "gh"}, {"repo": "o/r"})
        self.assertEqual(out["issues"], [{"number": 1, "title": "T", "url": "u"}])
        with self.assertRaises(ValueError) as ctx:
            toolsets_catalog.run_developer_tools(
                "github_create_issue", {"api_key": "gh"}, {"repo": "o/r", "title": "x"})
        self.assertIn("wymaga confirmed=True", str(ctx.exception))
        self.stub("https://api.github.com/repos/o/r/issues", {"number": 9, "html_url": "u9"})
        out = toolsets_catalog.run_developer_tools(
            "github_create_issue", {"api_key": "gh"},
            {"confirmed": True, "repo": "o/r", "title": "x", "body": "b"})
        self.assertEqual(out, {"ok": True, "number": 9, "url": "u9"})
        self.assertEqual(self.last()["method"], "POST")
        self.assertEqual(self.last()["body"], {"title": "x", "body": "b"})


class TestMediaWeather(RunnerBase):
    def test_weather_coords_override_and_url_shape(self):
        url = ("https://api.open-meteo.com/v1/forecast?latitude=52.23&longitude=21.01"
               "&current=temperature_2m,wind_speed_10m,precipitation&timezone=auto")
        self.stub(url, {"current": {"temperature_2m": 12.5}})
        out = toolsets_catalog.run_media_weather(
            "weather_forecast", {"coords": "1,2"}, {"coords": "52.23, 21.01"})
        self.assertEqual(out["coords"], "52.23,21.01")  # normalised
        self.assertEqual(out["current"], {"temperature_2m": 12.5})
        self.assertEqual(self.last()["url"], url)

    def test_malformed_coords_raise_value_error(self):
        with self.assertRaises(ValueError):
            toolsets_catalog.run_media_weather("weather_forecast", {}, {"coords": "bad,parts"})

    def test_spotify_gate_now_playing_and_verbs(self):
        with self.assertRaises(ValueError):
            toolsets_catalog.run_media_weather("spotify_now_playing", {}, {})
        self.stub("https://api.spotify.com/v1/me/player/currently-playing",
                  {"is_playing": True,
                   "item": {"name": "Song", "artists": [{"name": "A"}, {"name": "B"}]}})
        out = toolsets_catalog.run_media_weather("spotify_now_playing", {"access_token": "t"}, {})
        self.assertEqual(out, {"ok": True, "is_playing": True, "track": "Song",
                              "artists": "A, B"})
        self.stub("https://api.spotify.com/v1/me/player/next", {})
        out = toolsets_catalog.run_media_weather(
            "spotify_playback", {"access_token": "t"}, {"command": "next"})
        self.assertEqual(out, {"ok": True, "command": "next"})
        self.assertEqual(self.last()["method"], "POST")  # next/previous use POST
        self.stub("https://api.spotify.com/v1/me/player/pause", {})
        toolsets_catalog.run_media_weather(
            "spotify_playback", {"access_token": "t"}, {"command": "pause"})
        self.assertEqual(self.last()["method"], "PUT")  # everything else uses PUT


class TestMcpHttp(RunnerBase):
    def test_list_and_call_framing_with_bearer(self):
        self.stub("https://mcp.example.com/rpc", {"result": {"tools": [{"name": "x"}]}})
        out = toolsets_catalog.run_mcp_http(
            "mcp_http_list", {"endpoint_url": "https://mcp.example.com/rpc"}, {}, self.validator)
        self.assertEqual(out, {"ok": True, "result": {"tools": [{"name": "x"}]}})
        self.assertEqual(self.last()["body"],
                         {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}})
        self.assertEqual(self.validator_seen, ["https://mcp.example.com/rpc"])
        self.stub("https://mcp.example.com/rpc", {"result": {"content": []}})
        out = toolsets_catalog.run_mcp_http(
            "mcp_http_call",
            {"endpoint_url": "https://mcp.example.com/rpc", "api_key": "k"},
            {"tool_name": "t", "arguments": {"a": 1}}, self.validator)
        self.assertEqual(self.last()["body"]["method"], "tools/call")
        self.assertEqual(self.last()["body"]["params"], {"name": "t", "arguments": {"a": 1}})
        self.assertEqual(self.last()["headers"], {"Authorization": "Bearer k"})

    def test_rpc_error_raises_clean_value_error(self):
        self.stub("https://mcp.example.com/rpc", {"error": {"code": -1, "message": "boom"}})
        with self.assertRaises(ValueError) as ctx:
            toolsets_catalog.run_mcp_http(
                "mcp_http_list", {"endpoint_url": "https://mcp.example.com/rpc"}, {},
                self.validator)
        self.assertIn("Błąd zdalnego MCP HTTP", str(ctx.exception))


class TestExportSchemas(unittest.TestCase):
    def test_zero_config_basline_is_seven_tools(self):
        schemas = toolsets_catalog.export_llm_tool_schemas({}, set())
        self.assertEqual(len(schemas), 7)
        self.assertEqual([s["name"] for s in schemas], [
            "jarvis__cronjob__cron_list", "jarvis__cronjob__cron_create",
            "jarvis__cronjob__cron_toggle", "jarvis__cronjob__cron_remove",
            "jarvis__open_meteo__weather_forecast",
            "jarvis__web_search__web_search", "jarvis__web_search__web_extract",
        ])

    def test_enabled_connectors_add_and_disabled_entries_do_not(self):
        configured = {
            "g1": {"id": "g1", "provider": "gmail", "enabled": True, "settings": {}},
            "off": {"id": "off", "provider": "telegram", "enabled": False, "settings": {}},
        }
        schemas = toolsets_catalog.export_llm_tool_schemas(configured, set())
        providers = {s["provider"] for s in schemas}
        self.assertEqual(providers, {"cronjob", "gmail", "open_meteo", "web_search"})
        self.assertEqual(len(schemas), 9)
        self.assertTrue(all(
            s["provider"] != "telegram" for s in schemas))  # disabled entry never exported

    def test_disabled_toolset_drops_even_zero_config_tools(self):
        configured = {"g1": {"id": "g1", "provider": "gmail", "enabled": True, "settings": {}}}
        schemas = toolsets_catalog.export_llm_tool_schemas(configured, {"automation", "media_weather"})
        self.assertEqual({s["provider"] for s in schemas}, {"gmail", "web_search"})
        self.assertEqual(len(schemas), 4)

    def test_schema_shape_and_read_only_flags(self):
        schemas = toolsets_catalog.export_llm_tool_schemas(
            {"g1": {"id": "g1", "provider": "gmail", "enabled": True, "settings": {}}}, set())
        sample = next(s for s in schemas if s["name"] == "jarvis__gmail__gmail_send")
        self.assertEqual(sample, {"name": "jarvis__gmail__gmail_send", "toolset": "productivity",
                                  "provider": "gmail", "read_only": False,
                                  "description": "Wyślij wiadomość e-mail (wymaga potwierdzenia)."})
        self.assertIn("read_only", schemas[0])


if __name__ == "__main__":
    unittest.main()
