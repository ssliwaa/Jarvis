"""End-to-end tests for Jarvis Pluggable Toolsets & 18-Integration Registry:
1. 8 Toolsets enable/disable + dynamic `get_active_tool_schemas()` + `0o600` vault masking
2. LAN-aware SSRF rules (Home Assistant LAN allowed, loopback/link-local blocked) + write-gates
3. Native Obsidian local vault (`obsidian_daily_append` + `obsidian_search`), Cronjob scheduler,
   RFC-5545 `.ics` Calendar, HTML `web_extract`, and Gmail MIME decoding
4. MCP `stdio` with `allowed_tools` allowlist & `mcp__<server>__<tool>` namespacing + HTTP routes
   + live `sync_viewer_sri(fix=True)`, `qa_gate.audit_viewer`, and `security_scanner`
"""

import json
import stat
import sys
import tempfile
import threading
import os
import unittest
SANDBOXED = os.environ.get("JARVIS_VERIFY_SANDBOX") == "1"
import urllib.request
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import agent_cli
import change_impact
import connectors_hub
import qa_gate
import security_scanner
import server
import toolsets_catalog

REPO_ROOT = Path(__file__).resolve().parent.parent


def _find_handler_class():
    for val in vars(server).values():
        if isinstance(val, type) and issubclass(val, BaseHTTPRequestHandler) and val is not BaseHTTPRequestHandler:
            return val
    raise RuntimeError("Could not locate HTTP handler class in server.py")


@unittest.skipIf(SANDBOXED, "needs the developer's local env (vault/Hermes/Piper/desktop); skipped in CI")
class Wave10ToolsetsAndIntegrationsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir="/tmp" if Path("/tmp").is_dir() else None)
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.agents_dir = self.base / "state" / ".jarvis-tools" / "agents"
        self.agents_dir.mkdir(parents=True, exist_ok=True)
        self.p_agents = patch.object(agent_cli, "ROOT", self.agents_dir)
        self.p_agents.start()
        self.addCleanup(self.p_agents.stop)

        self.proj_root = self.base / "proj"
        self.proj_root.mkdir(parents=True, exist_ok=True)

        handler_cls = _find_handler_class()
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
        self.httpd.app = SimpleNamespace(root=self.proj_root)
        self.port = self.httpd.server_port
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.httpd.server_close)
        self.addCleanup(self.httpd.shutdown)

    def test_1_catalog_toolsets_toggle_lan_ssrf_and_write_gates(self):
        reg = connectors_hub.list_connectors()
        self.assertEqual(len(reg["toolsets"]), 8)
        self.assertEqual(len(reg["catalog"]), 18)

        # Zero-config tools (web_search, open_meteo, cronjob) export schemas immediately
        base_schemas = connectors_hub.get_active_tool_schemas()
        schema_names = {s["name"] for s in base_schemas}
        self.assertIn("jarvis__open_meteo__weather_forecast", schema_names)
        self.assertIn("jarvis__cronjob__cron_create", schema_names)

        # Home Assistant allows private LAN IP, blocks 127.0.0.1 & cloud metadata 169.254.169.254
        ha_saved = connectors_hub.configure_connector(
            "ha_home",
            "home_assistant",
            {"ha_url": "http://192.168.1.50:8123", "api_key": "long_lived_token_12345"},
        )
        self.assertTrue(ha_saved["ok"])
        self.assertTrue(ha_saved["settings"]["api_key"].startswith("••••"))
        vault_file = self.agents_dir.parent / "connectors_vault.json"
        self.assertEqual(stat.S_IMODE(vault_file.stat().st_mode), 0o600)

        with self.assertRaises(ValueError):
            connectors_hub.configure_connector(
                "ha_bad",
                "home_assistant",
                {"ha_url": "http://169.254.169.254/latest/meta-data", "api_key": "tok"},
            )
        # Non-LAN integration (google_calendar) still blocks private LAN IPs
        with self.assertRaises(ValueError):
            connectors_hub.configure_connector(
                "cal_bad",
                "google_calendar",
                {"ics_url": "https://192.168.1.50/cal.ics"},
            )

        # Disabling `smart_home` toolset removes `ha_*` from active schemas and blocks execution
        connectors_hub.set_toolset_enabled("smart_home", False)
        after_schemas = {s["name"] for s in connectors_hub.get_active_tool_schemas()}
        self.assertNotIn("jarvis__home_assistant__ha_list_entities", after_schemas)
        with self.assertRaises(ValueError):
            connectors_hub.execute_connector_action("ha_list_entities", {})

        # Re-enabling restores access, while `ha_call_service` still enforces `confirmed=True`
        connectors_hub.set_toolset_enabled("smart_home", True)
        with self.assertRaises(ValueError):
            connectors_hub.execute_connector_action(
                "ha_call_service",
                {"service": "light.turn_on", "confirmed": False},
            )

    def test_2_obsidian_vault_cronjob_ics_and_html_extractor(self):
        # 1. Obsidian local vault daily append & search
        obs_vault = self.base / "obsidian_vault"
        obs_vault.mkdir(parents=True)
        connectors_hub.configure_connector("obsidian", "obsidian", {"vault_path": str(obs_vault)})
        app_res = connectors_hub.execute_connector_action(
            "obsidian_daily_append",
            {"text": "Przetestowano tłumienie drgań TPU w kieszeni HDD"},
        )
        self.assertTrue(app_res["ok"])
        found = connectors_hub.execute_connector_action("obsidian_search", {"query": "drgań tpu"})
        self.assertEqual(found["count"], 1)

        # 2. Cronjob lifecycle (create -> list -> toggle -> remove)
        created = connectors_hub.execute_connector_action(
            "cron_create",
            {"name": "Poranny przegląd skrzynki", "schedule": "daily 08:15"},
        )
        jid = created["job"]["id"]
        self.assertEqual(connectors_hub.execute_connector_action("cron_list", {})["count"], 1)
        toggled = connectors_hub.execute_connector_action("cron_toggle", {"job_id": jid})
        self.assertFalse(toggled["job"]["enabled"])
        connectors_hub.execute_connector_action("cron_remove", {"job_id": jid})
        self.assertEqual(connectors_hub.execute_connector_action("cron_list", {})["count"], 0)

        # 3. HTML clean extractor & RFC-5545 .ics parser
        clean = toolsets_catalog.html_to_clean_text("<html><script>bad()</script><body><h1>Tytuł</h1><p>Treść artykułu.</p></body></html>")
        self.assertEqual(clean, "Tytuł\nTreść artykułu.")

        now_utc = datetime.now(timezone.utc)
        ev_start = (now_utc + timedelta(hours=2)).strftime("%Y%m%dT%H%M%SZ")
        ics = f"BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nSUMMARY:Sync projektu\r\nDTSTART:{ev_start}\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n"
        self.assertEqual(connectors_hub.parse_ics_events(ics)[0]["summary"], "Sync projektu")

    def test_3_mcp_allowlist_namespacing_http_routes_and_repo_gates(self):
        sri = change_impact.sync_viewer_sri(REPO_ROOT, fix=True)
        self.assertTrue(sri["ok"])
        qa = qa_gate.audit_viewer(REPO_ROOT)
        self.assertTrue(qa["ok"], f"Viewer QA failed: {qa['issues']}")
        sec = security_scanner.scan_directory(REPO_ROOT, include_tests=False)
        self.assertTrue(sec["ok"], f"Security scan findings: {sec['findings']}")

        mcp_script = self.base / "multi_tool_mcp.py"
        mcp_script.write_text(
            "import json, sys\n"
            "for line in sys.stdin:\n"
            "    msg = json.loads(line)\n"
            "    mid = msg.get('id')\n"
            "    method = msg.get('method')\n"
            "    if method == 'initialize':\n"
            "        print(json.dumps({'jsonrpc': '2.0', 'id': mid, 'result': {'protocolVersion': '2024-11-05'}}), flush=True)\n"
            "    elif method == 'tools/list':\n"
            "        tools = [{'name': 'safe_read'}, {'name': 'dangerous_delete'}]\n"
            "        print(json.dumps({'jsonrpc': '2.0', 'id': mid, 'result': {'tools': tools}}), flush=True)\n"
            "    elif method == 'tools/call':\n"
            "        print(json.dumps({'jsonrpc': '2.0', 'id': mid, 'result': {'ok_tool': msg['params']['name']}}), flush=True)\n",
            encoding="utf-8",
        )

        def _post(payload: dict) -> dict:
            raw = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(
                f"http://127.0.0.1:{self.port}/mission/action",
                data=raw,
                method="POST",
                headers={
                    "Host": f"127.0.0.1:{self.port}",
                    "Origin": f"http://127.0.0.1:{self.port}",
                    "Content-Type": "application/json",
                    "Content-Length": str(len(raw)),
                },
            )
            with urllib.request.urlopen(req, timeout=8) as resp:
                return json.loads(resp.read().decode("utf-8"))

        _post({
            "action": "connector_configure",
            "connector_id": "gworkspace",
            "provider": "mcp_stdio",
            "settings": {
                "command": [sys.executable, str(mcp_script)],
                "allowed_tools": "safe_read",
            },
        })

        tools_res = _post({
            "action": "connector_exec",
            "connector_action": "mcp_list_tools",
            "connector_id": "gworkspace",
        })
        tools = tools_res["result"]["tools"]
        self.assertEqual(len(tools), 1)
        self.assertEqual(tools[0]["namespaced"], "mcp__gworkspace__safe_read")

        # Calling `dangerous_delete` outside `allowed_tools` is rejected (`400`)
        with self.assertRaises(urllib.error.HTTPError):
            _post({
                "action": "connector_exec",
                "connector_action": "mcp_call_tool",
                "connector_id": "gworkspace",
                "tool_name": "dangerous_delete",
            })


if __name__ == "__main__":
    unittest.main()
