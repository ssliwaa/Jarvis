"""Hermes-Inspired Pluggable Toolsets, Catalog & Native Integrations (`toolsets_catalog.py`).

Implements the modular Toolset & Integration Registry architecture directly inside Jarvis:
  - 8 logical Toolsets (`productivity`, `smart_home`, `web_research`, `messaging`,
    `developer`, `media_weather`, `automation`, `mcp`) that can be enabled/disabled per surface.
  - 17 first-class connectable integrations with declarative setup schemas, write-gates,
    zero-key ready tools (`web_search` DuckDuckGo, `open_meteo`, `cronjob`, `obsidian`),
    Home Assistant (`ha_*`), Notion, Todoist, GitHub, Linear, Slack, Discord, Telegram,
    ntfy, Spotify, Gmail, Google Calendar, plus `mcp_stdio` and remote `mcp_http`.
  - Dynamic LLM Function-Calling Schema Exporter (`export_llm_tool_schemas`) with
    `mcp__<server>__<tool>` namespacing and per-server tool allowlists.
"""

from __future__ import annotations

import json
import os
import time
import urllib.parse
import urllib.request
import uuid
from datetime import datetime
from html.parser import HTMLParser
from pathlib import Path

import agent_cli
import code_index

TOOLSETS_META = {
    "productivity": {
        "label": "Produktywność i Notatki",
        "description": "Kalendarz Google, Gmail, Notion, Todoist oraz lokalny sejf Obsidian.",
    },
    "smart_home": {
        "label": "Smart Home (Home Assistant)",
        "description": "Odczyt czujników, stanów encji i wywoływanie usług Home Assistant (ha_*).",
    },
    "web_research": {
        "label": "Web Search i Ekstrakcja",
        "description": "Wyszukiwarki (DuckDuckGo, SearXNG, Brave, Tavily, Exa, Firecrawl) oraz web_extract.",
    },
    "messaging": {
        "label": "Komunikatory i Powiadomienia",
        "description": "Telegram, Slack, Discord oraz powiadomienia push ntfy.",
    },
    "developer": {
        "label": "Dev i Zarządzanie Kodem",
        "description": "Powiadomienia, zgłoszenia i zadania w GitHub oraz Linear.",
    },
    "media_weather": {
        "label": "Media i Pogoda",
        "description": "Sterowanie odtwarzaczem Spotify oraz lokalna prognoza Open-Meteo.",
    },
    "automation": {
        "label": "Automatyzacja (Cron)",
        "description": "Cykliczne zadania, przypomnienia i wyzwalacze harmonogramu.",
    },
    "mcp": {
        "label": "Serwery MCP (stdio + HTTP)",
        "description": "Lokalne i zdalne serwery Model Context Protocol z filtrowaniem narzędzi.",
    },
}


INTEGRATION_CATALOG: dict[str, dict] = {
    "google_calendar": {
        "title": "Kalendarz Google / iCal",
        "toolset": "productivity",
        "zero_config": False,
        "setup_hint": "Wklej prywatny adres iCal (.ics) lub skonfiguruj token OAuth2 Google Calendar API v3.",
        "fields": [
            {"key": "ics_url", "label": "Prywatny link .ics (HTTPS)", "secret": True},
            {"key": "access_token", "label": "Token OAuth2 (opcjonalnie do zapisu)", "secret": True},
        ],
        "tools": [
            {"name": "calendar_events", "read_only": True, "desc": "Pobierz nadchodzące spotkania z kalendarza."},
            {"name": "calendar_create", "read_only": False, "desc": "Utwórz nowe wydarzenie w Kalendarzu Google."},
        ],
    },
    "gmail": {
        "title": "Gmail (IMAP/SMTP lub OAuth2)",
        "toolset": "productivity",
        "zero_config": False,
        "setup_hint": "Podaj adres Gmail i 16-znakowe Hasło aplikacji Google (lub token OAuth2).",
        "fields": [
            {"key": "email", "label": "Adres e-mail Gmail", "secret": False},
            {"key": "app_password", "label": "Hasło aplikacji (16 znaków)", "secret": True},
        ],
        "tools": [
            {"name": "gmail_inbox", "read_only": True, "desc": "Odczytaj nieprzeczytane wiadomości ze skrzynki."},
            {"name": "gmail_send", "read_only": False, "desc": "Wyślij wiadomość e-mail (wymaga potwierdzenia)."},
        ],
    },
    "notion": {
        "title": "Notion Workspace",
        "toolset": "productivity",
        "zero_config": False,
        "setup_hint": "Utwórz Internal Integration Token na notion.so/my-integrations i udostępnij mu wybrane strony.",
        "fields": [
            {"key": "api_key", "label": "Notion Integration Token", "secret": True},
            {"key": "parent_page_id", "label": "Domyślne ID strony nadrzędnej (opcjonalnie)", "secret": False},
        ],
        "tools": [
            {"name": "notion_search", "read_only": True, "desc": "Przeszukaj strony i bazy danych w Notion."},
            {"name": "notion_create_page", "read_only": False, "desc": "Utwórz nową notatkę/stronę w Notion."},
        ],
    },
    "todoist": {
        "title": "Todoist",
        "toolset": "productivity",
        "zero_config": False,
        "setup_hint": "Skopiuj token API z Ustawienia -> Integracje -> Dla programistów w Todoist.",
        "fields": [
            {"key": "api_key", "label": "Todoist API Token", "secret": True},
        ],
        "tools": [
            {"name": "todoist_tasks", "read_only": True, "desc": "Pobierz aktywne zadania z Todoist."},
            {"name": "todoist_add_task", "read_only": False, "desc": "Dodaj nowe zadanie z terminem wykonania."},
        ],
    },
    "obsidian": {
        "title": "Obsidian (Lokalny Vault Markdown)",
        "toolset": "productivity",
        "zero_config": False,
        "setup_hint": "Wskaż ścieżkę katalogu swojego sejfu Obsidian na dysku (wewnątrz katalogu domowego).",
        "fields": [
            {"key": "vault_path", "label": "Ścieżka katalogu Vault (np. ~/Dokumenty/Obsidian)", "secret": False},
        ],
        "tools": [
            {"name": "obsidian_search", "read_only": True, "desc": "Przeszukaj lokalne notatki Markdown w Obsidianie."},
            {"name": "obsidian_daily_append", "read_only": False, "desc": "Dopisz wpis do dzisiejszej notatki dziennej."},
        ],
    },
    "home_assistant": {
        "title": "Home Assistant (Smart Home)",
        "toolset": "smart_home",
        "zero_config": False,
        "allow_lan": True,
        "setup_hint": "Podaj adres instancji HA (np. http://192.168.1.100:8123) i Long-Lived Access Token z profilu użytkownika.",
        "fields": [
            {"key": "ha_url", "label": "Adres Home Assistant (HTTP/HTTPS)", "secret": False},
            {"key": "api_key", "label": "Long-Lived Access Token (HASS_TOKEN)", "secret": True},
        ],
        "tools": [
            {"name": "ha_list_entities", "read_only": True, "desc": "Wypisz encje i czujniki Home Assistant (opcjonalny filtr domeny)."},
            {"name": "ha_get_state", "read_only": True, "desc": "Pobierz dokładny stan i atrybuty wskazanej encji."},
            {"name": "ha_list_services", "read_only": True, "desc": "Wypisz dostępne usługi sterowania w Home Assistant."},
            {"name": "ha_call_service", "read_only": False, "desc": "Wywołaj usługę urządzenia (np. light.turn_on, climate.set_temperature)."},
        ],
    },
    "web_search": {
        "title": "Web Search & Extract (Multi-Backend)",
        "toolset": "web_research",
        "zero_config": True,
        "allow_lan": True,
        "setup_hint": "Działa od razu bez klucza przez DuckDuckGo lub po podaniu SearXNG / Brave / Tavily / Exa / Firecrawl.",
        "fields": [
            {"key": "backend", "label": "Silnik (ddg | searxng | brave | tavily | exa | firecrawl)", "secret": False},
            {"key": "api_key", "label": "Klucz API lub adres SearXNG (opcjonalnie dla ddg)", "secret": True},
        ],
        "tools": [
            {"name": "web_search", "read_only": True, "desc": "Wyszukaj informacje w internecie wybranym backendem."},
            {"name": "web_extract", "read_only": True, "desc": "Pobierz i oczyść treść wskazanej strony WWW do czystego tekstu."},
        ],
    },
    "telegram": {
        "title": "Telegram Bot",
        "toolset": "messaging",
        "zero_config": False,
        "setup_hint": "Utwórz bota przez @BotFather i podaj chat_id rozmowy.",
        "fields": [
            {"key": "chat_id", "label": "Telegram chat_id", "secret": False},
            {"key": "bot_token", "label": "Token bota (@BotFather)", "secret": True},
        ],
        "tools": [
            {"name": "telegram_send", "read_only": False, "desc": "Wyślij wiadomość na Telegram."},
        ],
    },
    "slack": {
        "title": "Slack Workspace",
        "toolset": "messaging",
        "zero_config": False,
        "setup_hint": "Wklej Incoming Webhook URL lub Bot User OAuth Token + domyślny kanał.",
        "fields": [
            {"key": "channel", "label": "ID kanału lub adres Webhook HTTPS", "secret": False},
            {"key": "bot_token", "label": "Slack Bot Token (opcjonalnie przy Webhooku)", "secret": True},
        ],
        "tools": [
            {"name": "slack_send", "read_only": False, "desc": "Wyślij wiadomość na kanał Slack."},
            {"name": "slack_history", "read_only": True, "desc": "Pobierz ostatnie wiadomości z kanału Slack."},
        ],
    },
    "discord": {
        "title": "Discord Webhook / Bot",
        "toolset": "messaging",
        "zero_config": False,
        "setup_hint": "Skopiuj Webhook URL z ustawień kanału Discord -> Integracje.",
        "fields": [
            {"key": "webhook_url", "label": "Discord Webhook URL (HTTPS)", "secret": True},
        ],
        "tools": [
            {"name": "discord_send", "read_only": False, "desc": "Opublikuj powiadomienie lub raport na kanale Discord."},
        ],
    },
    "ntfy": {
        "title": "ntfy (Powiadomienia Push)",
        "toolset": "messaging",
        "zero_config": False,
        "setup_hint": "Podaj nazwę prywatnego tematu na https://ntfy.sh lub adres własnego serwera ntfy.",
        "fields": [
            {"key": "topic", "label": "Nazwa tematu ntfy ( lub pełny URL )", "secret": True},
        ],
        "tools": [
            {"name": "ntfy_publish", "read_only": False, "desc": "Wyślij natychmiastowy alert push na telefon/pulpit."},
        ],
    },
    "github": {
        "title": "GitHub Issues, PR & Powiadomienia",
        "toolset": "developer",
        "zero_config": False,
        "setup_hint": "Wygeneruj Fine-grained Personal Access Token w ustawieniach GitHub.",
        "fields": [
            {"key": "default_repo", "label": "Domyślne repozytorium (właściciel/nazwa)", "secret": False},
            {"key": "api_key", "label": "GitHub Personal Access Token", "secret": True},
        ],
        "tools": [
            {"name": "github_notifications", "read_only": True, "desc": "Pobierz nieprzeczytane powiadomienia z GitHuba."},
            {"name": "github_issues", "read_only": True, "desc": "Wypisz otwarte zgłoszenia (Issues / PR) w repozytorium."},
            {"name": "github_create_issue", "read_only": False, "desc": "Utwórz nowe zgłoszenie Issue w repozytorium GitHub."},
        ],
    },
    "linear": {
        "title": "Linear (Zadania inżynierskie)",
        "toolset": "developer",
        "zero_config": False,
        "setup_hint": "Wygeneruj Personal API Key w Linear -> Settings -> API.",
        "fields": [
            {"key": "api_key", "label": "Linear API Key", "secret": True},
        ],
        "tools": [
            {"name": "linear_issues", "read_only": True, "desc": "Pobierz przypisane zadania z Linear GraphQL."},
        ],
    },
    "spotify": {
        "title": "Spotify Odtwarzacz i Biblioteka",
        "toolset": "media_weather",
        "zero_config": False,
        "setup_hint": "Podaj token OAuth2 Spotify Web API (user-read-playback-state / user-modify-playback-state).",
        "fields": [
            {"key": "access_token", "label": "Spotify OAuth2 Access Token", "secret": True},
        ],
        "tools": [
            {"name": "spotify_now_playing", "read_only": True, "desc": "Sprawdź aktualnie odtwarzany utwór i urządzenie."},
            {"name": "spotify_search", "read_only": True, "desc": "Wyszukaj utwór, album lub playlistę w Spotify."},
            {"name": "spotify_playback", "read_only": False, "desc": "Wstrzymaj, wznów lub przełącz następny utwór."},
        ],
    },
    "open_meteo": {
        "title": "Pogoda Open-Meteo (0 kluczy API)",
        "toolset": "media_weather",
        "zero_config": True,
        "setup_hint": "Gotowe od razu bez rejestracji (domyślnie współrzędne Podkowy Leśnej / Mazowsza).",
        "fields": [
            {"key": "coords", "label": "Szerokość,Długość (domyślnie 52.12,20.73)", "secret": False},
        ],
        "tools": [
            {"name": "weather_forecast", "read_only": True, "desc": "Pobierz aktualną temperaturę, wiatr i prognozę opadów."},
        ],
    },
    "cronjob": {
        "title": "Harmonogram Zadań Cron",
        "toolset": "automation",
        "zero_config": True,
        "setup_hint": "Wbudowany w Jarvisa — twórz, wstrzymuj i przeglądaj cykliczne zadania oraz przypomnienia.",
        "fields": [],
        "tools": [
            {"name": "cron_list", "read_only": True, "desc": "Wypisz zaplanowane zadania cykliczne."},
            {"name": "cron_create", "read_only": False, "desc": "Dodaj nowe zadanie cykliczne (interwał lub godzina)."},
            {"name": "cron_toggle", "read_only": False, "desc": "Wstrzymaj lub wznów zadanie harmonogramu."},
            {"name": "cron_remove", "read_only": False, "desc": "Usuń zadanie z harmonogramu."},
        ],
    },
    "mcp_stdio": {
        "title": "Serwer MCP (Lokalny stdio)",
        "toolset": "mcp",
        "zero_config": False,
        "setup_hint": "Uruchamia dowolny serwer MCP przez stdin/stdout (np. npx, uvx, python) z opcjonalnym filtrem narzędzi.",
        "fields": [
            {"key": "command_str", "label": "Komenda uruchomieniowa (np. uvx mcp-server-sqlite ...)", "secret": False},
            {"key": "allowed_tools", "label": "Filtr dozwolonych narzędzi po przecinku (opcjonalnie)", "secret": False},
        ],
        "tools": [
            {"name": "mcp_list_tools", "read_only": True, "desc": "Wykryj narzędzia udostępniane przez lokalny serwer MCP."},
            {"name": "mcp_call_tool", "read_only": False, "desc": "Wywołaj wskazane narzędzie na serwerze MCP."},
        ],
    },
    "mcp_http": {
        "title": "Serwer MCP (Zdalny HTTP JSON-RPC)",
        "toolset": "mcp",
        "zero_config": False,
        "setup_hint": "Łączy się ze zdalnym endpointem HTTP MCP (np. firmowym bramkowaniem narzędzi lub chmurowym MCP).",
        "fields": [
            {"key": "endpoint_url", "label": "Adres HTTPS endpointu MCP", "secret": False},
            {"key": "api_key", "label": "Nagłówek Bearer Token (opcjonalnie)", "secret": True},
        ],
        "tools": [
            {"name": "mcp_http_list", "read_only": True, "desc": "Pobierz listę narzędzi ze zdalnego serwera HTTP MCP."},
            {"name": "mcp_http_call", "read_only": False, "desc": "Wywołaj narzędzie na zdalnym serwerze HTTP MCP."},
        ],
    },
}


MCP_PRESET_TEMPLATES = [
    {"id": "mcp_github", "label": "GitHub Official MCP", "command": ["npx", "-y", "@modelcontextprotocol/server-github"]},
    {"id": "mcp_gdrive", "label": "Google Drive MCP", "command": ["npx", "-y", "@modelcontextprotocol/server-gdrive"]},
    {"id": "mcp_slack", "label": "Slack MCP", "command": ["npx", "-y", "@modelcontextprotocol/server-slack"]},
    {"id": "mcp_postgres", "label": "PostgreSQL MCP", "command": ["npx", "-y", "@modelcontextprotocol/server-postgres"]},
    {"id": "mcp_filesystem", "label": "Filesystem MCP", "command": ["npx", "-y", "@modelcontextprotocol/server-filesystem"]},
]


# ---------------------------------------------------------------------------
# HTML Text Extractor (`web_extract`)
# ---------------------------------------------------------------------------

class _ReadableTextParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self._skip_depth = 0
        self.chunks: list[str] = []

    def handle_starttag(self, tag: str, attrs) -> None:
        if tag.lower() in ("script", "style", "noscript", "svg", "nav", "footer"):
            self._skip_depth += 1

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() in ("script", "style", "noscript", "svg", "nav", "footer") and self._skip_depth > 0:
            self._skip_depth -= 1

    def handle_data(self, data: str) -> None:
        if self._skip_depth == 0:
            cleaned = " ".join(data.split())
            if cleaned:
                self.chunks.append(cleaned)


def html_to_clean_text(raw_html: str, *, max_chars: int = 8000) -> str:
    parser = _ReadableTextParser()
    parser.feed(str(raw_html or ""))
    joined = "\n".join(parser.chunks)
    return joined[:max_chars]


# ---------------------------------------------------------------------------
# Built-in Cronjob Store (`cronjob`)
# ---------------------------------------------------------------------------

def _cron_path() -> Path:
    base = agent_cli.ROOT.parent
    base.mkdir(mode=0o700, parents=True, exist_ok=True)
    return base / "scheduled_jobs.json"


def _load_cron() -> list[dict]:
    p = _cron_path()
    if not p.is_file():
        return []
    try:
        raw = json.loads(p.read_text(encoding="utf-8"))
        if isinstance(raw, list):
            return raw
    except (OSError, ValueError):
        pass
    return []


def _save_cron(jobs: list[dict]) -> None:
    p = _cron_path()
    tmp = p.with_name(f".scheduled_jobs.json.tmp-{os.getpid()}")
    tmp.write_text(json.dumps(jobs, ensure_ascii=False, indent=2), encoding="utf-8")
    os.chmod(tmp, 0o600)
    tmp.replace(p)


def cron_manage(subaction: str, payload: dict) -> dict:
    jobs = _load_cron()
    if subaction == "cron_list":
        return {"ok": True, "count": len(jobs), "jobs": jobs}
    if subaction == "cron_create":
        name = str(payload.get("name") or payload.get("prompt") or "").strip()[:140]
        schedule = str(payload.get("schedule") or "daily 08:30").strip()[:64]
        prompt = str(payload.get("prompt") or name).strip()[:600]
        if not name:
            raise ValueError("Zadanie harmonogramu wymaga pola name lub prompt.")
        job = {
            "id": f"cron-{uuid.uuid4().hex[:8]}",
            "name": name,
            "schedule": schedule,
            "prompt": prompt,
            "deliver": str(payload.get("deliver") or "local").strip(),
            "enabled": True,
            "created_at": round(time.time(), 3),
        }
        jobs.insert(0, job)
        _save_cron(jobs[:50])
        return {"ok": True, "job": job}
    jid = str(payload.get("job_id") or "").strip()
    if subaction == "cron_toggle":
        for j in jobs:
            if j.get("id") == jid:
                j["enabled"] = not bool(j.get("enabled", True))
                _save_cron(jobs)
                return {"ok": True, "job": j}
        raise ValueError(f"Nie znaleziono zadania {jid!r}.")
    if subaction == "cron_remove":
        filtered = [j for j in jobs if j.get("id") != jid]
        _save_cron(filtered)
        return {"ok": True, "removed": len(filtered) != len(jobs)}
    raise ValueError(f"Nieznana operacja cron: {subaction!r}")


# ---------------------------------------------------------------------------
# Native Execution Implementations for Extended Providers
# ---------------------------------------------------------------------------

def _json_http(url: str, *, method: str = "GET", headers: dict | None = None,
               body: dict | None = None, timeout: float = 12.0):
    hdrs = {"Accept": "application/json", "User-Agent": "Jarvis-Assistant/1.0"}
    if headers:
        hdrs.update(headers)
    raw = None
    if body is not None:
        raw = json.dumps(body).encode("utf-8")
        hdrs.setdefault("Content-Type", "application/json")
    req = urllib.request.Request(url, data=raw, method=method, headers=hdrs)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        text = resp.read(2_000_000).decode("utf-8", errors="replace")
    return json.loads(text) if text.strip() else {}


def run_home_assistant(action: str, cfg: dict, params: dict) -> dict:
    base_url = str(cfg.get("ha_url") or "").strip().rstrip("/")
    tok = str(cfg.get("api_key") or "").strip()
    if not base_url or not tok:
        raise ValueError("Home Assistant wymaga skonfigurowanych pól ha_url oraz api_key (HASS_TOKEN).")
    hdrs = {"Authorization": f"Bearer {tok}"}

    if action == "ha_list_entities":
        states = _json_http(f"{base_url}/api/states", headers=hdrs)
        domain = str(params.get("domain") or "").strip().lower()
        items = []
        for s in (states if isinstance(states, list) else []):
            eid = str(s.get("entity_id") or "")
            if domain and not eid.startswith(f"{domain}."):
                continue
            items.append({
                "entity_id": eid,
                "state": s.get("state"),
                "friendly_name": (s.get("attributes") or {}).get("friendly_name", eid),
            })
        return {"ok": True, "count": len(items), "entities": items[:60]}

    if action == "ha_get_state":
        eid = urllib.parse.quote(str(params.get("entity_id") or "").strip(), safe="._")
        if not eid:
            raise ValueError("Podaj entity_id (np. sensor.temperature lub light.biuro).")
        st = _json_http(f"{base_url}/api/states/{eid}", headers=hdrs)
        return {"ok": True, "entity": st}

    if action == "ha_list_services":
        svcs = _json_http(f"{base_url}/api/services", headers=hdrs)
        return {"ok": True, "domains": [d.get("domain") for d in (svcs if isinstance(svcs, list) else [])]}

    if action == "ha_call_service":
        if not params.get("confirmed", False):
            raise ValueError("Sterowanie urządzeniem Home Assistant wymaga confirmed=True.")
        svc_full = str(params.get("service") or "").strip()
        if "." not in svc_full:
            raise ValueError("Podaj usługę w formacie domena.usługa (np. light.turn_on).")
        dom, svc = svc_full.split(".", 1)
        svc_data = dict(params.get("service_data") or {})
        if params.get("entity_id"):
            svc_data.setdefault("entity_id", params["entity_id"])
        out = _json_http(f"{base_url}/api/services/{dom}/{svc}", method="POST", headers=hdrs, body=svc_data)
        return {"ok": True, "service": svc_full, "changed": len(out) if isinstance(out, list) else 0}

    raise ValueError(f"Nieznana akcja Home Assistant: {action!r}")


def run_notion(action: str, cfg: dict, params: dict) -> dict:
    tok = str(cfg.get("api_key") or "").strip()
    if not tok:
        raise ValueError("Notion wymaga pola api_key (Internal Integration Token).")
    hdrs = {"Authorization": f"Bearer {tok}", "Notion-Version": "2022-06-28"}

    if action == "notion_search":
        q = str(params.get("query") or "").strip()
        res = _json_http("https://api.notion.com/v1/search", method="POST", headers=hdrs, body={"query": q, "page_size": 12})
        pages = []
        for it in res.get("results") or []:
            pages.append({"id": it.get("id"), "object": it.get("object"), "url": it.get("url")})
        return {"ok": True, "count": len(pages), "results": pages}

    if action == "notion_create_page":
        if not params.get("confirmed", False):
            raise ValueError("Utworzenie strony w Notion wymaga confirmed=True.")
        parent_id = str(params.get("parent_page_id") or cfg.get("parent_page_id") or "").strip()
        title = str(params.get("title") or "Notatka Jarvisa").strip()
        text = str(params.get("content") or "").strip()
        if not parent_id:
            raise ValueError("Podaj parent_page_id dla nowej strony Notion.")
        body = {
            "parent": {"page_id": parent_id},
            "properties": {"title": {"title": [{"text": {"content": title}}]}},
            "children": [{"object": "block", "type": "paragraph", "paragraph": {"rich_text": [{"text": {"content": text[:1900]}}]}}] if text else [],
        }
        created = _json_http("https://api.notion.com/v1/pages", method="POST", headers=hdrs, body=body)
        return {"ok": True, "id": created.get("id"), "url": created.get("url")}

    raise ValueError(f"Nieznana akcja Notion: {action!r}")


def run_todoist(action: str, cfg: dict, params: dict) -> dict:
    tok = str(cfg.get("api_key") or "").strip()
    if not tok:
        raise ValueError("Todoist wymaga pola api_key.")
    hdrs = {"Authorization": f"Bearer {tok}"}

    if action == "todoist_tasks":
        tasks = _json_http("https://api.todoist.com/rest/v2/tasks", headers=hdrs)
        items = [{"id": t.get("id"), "content": t.get("content"), "due": (t.get("due") or {}).get("string", "")} for t in (tasks or [])[:25]]
        return {"ok": True, "count": len(items), "tasks": items}

    if action == "todoist_add_task":
        content = str(params.get("content") or "").strip()
        if not content:
            raise ValueError("Podaj treść zadania (content).")
        body: dict = {"content": content}
        if params.get("due_string"):
            body["due_string"] = str(params["due_string"])
        created = _json_http("https://api.todoist.com/rest/v2/tasks", method="POST", headers=hdrs, body=body)
        return {"ok": True, "id": created.get("id"), "content": created.get("content")}

    raise ValueError(f"Nieznana akcja Todoist: {action!r}")


def run_obsidian(action: str, cfg: dict, params: dict) -> dict:
    raw_vault = str(cfg.get("vault_path") or "").strip()
    if not raw_vault:
        raise ValueError("Obsidian wymaga wskazania ścieżki vault_path.")
    safe_vault = code_index.validate_safe_project_dir(raw_vault)

    if action == "obsidian_search":
        q = str(params.get("query") or "").strip().lower()
        matches: list[dict] = []
        for md in sorted(safe_vault.rglob("*.md")):
            if any(part.startswith(".") for part in md.relative_to(safe_vault).parts):
                continue
            try:
                txt = md.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if not q or q in md.stem.lower() or q in txt.lower():
                matches.append({
                    "note": str(md.relative_to(safe_vault)),
                    "preview": " ".join(txt.split())[:200],
                })
                if len(matches) >= 15:
                    break
        return {"ok": True, "count": len(matches), "notes": matches}

    if action == "obsidian_daily_append":
        text = str(params.get("text") or "").strip()
        if not text:
            raise ValueError("Podaj tekst do dopisania w notatce dziennej.")
        daily_dir = safe_vault / "Daily"
        daily_dir.mkdir(parents=True, exist_ok=True)
        note_path = daily_dir / f"{datetime.now().strftime('%Y-%m-%d')}.md"
        stamp = datetime.now().strftime("%H:%M")
        existing = note_path.read_text(encoding="utf-8") if note_path.is_file() else f"# {note_path.stem}\n"
        note_path.write_text(f"{existing.rstrip()}\n- **{stamp}** {text}\n", encoding="utf-8")
        return {"ok": True, "note": str(note_path.relative_to(safe_vault))}

    raise ValueError(f"Nieznana akcja Obsidian: {action!r}")


def run_web_tools(action: str, cfg: dict, params: dict, https_validator) -> dict:
    if action == "web_extract":
        safe_url = https_validator(str(params.get("url") or ""))
        req = urllib.request.Request(safe_url, headers={"User-Agent": "Mozilla/5.0 Jarvis-Extractor/1.0"})
        with urllib.request.urlopen(req, timeout=12) as resp:
            raw_html = resp.read(1_500_000).decode("utf-8", errors="replace")
        return {"ok": True, "url": safe_url, "content": html_to_clean_text(raw_html)}

    query = str(params.get("query") or "").strip()
    if not query:
        raise ValueError("Podaj frazę wyszukiwania (query).")
    backend = str(cfg.get("backend") or "ddg").strip().lower()
    key = str(cfg.get("api_key") or "").strip()

    if backend == "tavily" and key:
        res = _json_http("https://api.tavily.com/search", method="POST", body={"api_key": key, "query": query, "max_results": 6})
        hits = [{"title": r.get("title"), "url": r.get("url"), "snippet": r.get("content", "")[:240]} for r in res.get("results") or []]
        return {"ok": True, "backend": "tavily", "results": hits}

    if backend == "brave" and key:
        q_enc = urllib.parse.urlencode({"q": query, "count": "6"})
        res = _json_http(f"https://api.search.brave.com/res/v1/web/search?{q_enc}", headers={"X-Subscription-Token": key})
        hits = [{"title": r.get("title"), "url": r.get("url"), "snippet": r.get("description", "")[:240]} for r in (res.get("web") or {}).get("results") or []]
        return {"ok": True, "backend": "brave", "results": hits}

    if backend == "searxng" and key.startswith(("http://", "https://")):
        q_enc = urllib.parse.urlencode({"q": query, "format": "json"})
        res = _json_http(f"{key.rstrip('/')}/search?{q_enc}")
        hits = [{"title": r.get("title"), "url": r.get("url"), "snippet": r.get("content", "")[:240]} for r in (res.get("results") or [])[:8]]
        return {"ok": True, "backend": "searxng", "results": hits}

    # Zero-key DuckDuckGo Instant Answer JSON fallback
    q_enc = urllib.parse.urlencode({"q": query, "format": "json", "no_html": "1", "skip_disambig": "1"})
    res = _json_http(f"https://api.duckduckgo.com/?{q_enc}")
    hits = []
    if res.get("AbstractText"):
        hits.append({"title": res.get("Heading") or query, "url": res.get("AbstractURL") or "", "snippet": res["AbstractText"]})
    for topic in (res.get("RelatedTopics") or [])[:6]:
        if isinstance(topic, dict) and topic.get("Text"):
            hits.append({"title": topic["Text"][:80], "url": topic.get("FirstURL") or "", "snippet": topic["Text"]})
    return {"ok": True, "backend": "ddg", "results": hits}


def run_messaging_extra(action: str, cfg: dict, params: dict, https_validator) -> dict:
    text = str(params.get("text") or "").strip()[:3500]
    if action == "discord_send":
        wh = https_validator(str(cfg.get("webhook_url") or ""))
        _json_http(wh, method="POST", body={"content": text})
        return {"ok": True, "delivered": "discord"}

    if action == "ntfy_publish":
        raw_topic = str(cfg.get("topic") or "").strip()
        if not raw_topic:
            raise ValueError("Podaj temat ntfy.")
        target = https_validator(raw_topic) if raw_topic.startswith("https://") else f"https://ntfy.sh/{urllib.parse.quote(raw_topic, safe='')}"
        req = urllib.request.Request(target, data=text.encode("utf-8"), method="POST")
        with urllib.request.urlopen(req, timeout=10) as resp:
            return {"ok": 200 <= resp.status < 300, "delivered": "ntfy"}

    if action == "slack_send":
        chan = str(cfg.get("channel") or "").strip()
        tok = str(cfg.get("bot_token") or "").strip()
        if chan.startswith("https://hooks.slack.com/"):
            _json_http(https_validator(chan), method="POST", body={"text": text})
            return {"ok": True, "delivered": "slack_webhook"}
        if not tok or not chan:
            raise ValueError("Slack wymaga Webhooka HTTPS lub pary channel + bot_token.")
        out = _json_http("https://slack.com/api/chat.postMessage", method="POST", headers={"Authorization": f"Bearer {tok}"}, body={"channel": chan, "text": text})
        return {"ok": bool(out.get("ok")), "ts": out.get("ts")}

    if action == "slack_history":
        chan = str(cfg.get("channel") or "").strip()
        tok = str(cfg.get("bot_token") or "").strip()
        out = _json_http(f"https://slack.com/api/conversations.history?channel={urllib.parse.quote(chan)}&limit=10", headers={"Authorization": f"Bearer {tok}"})
        return {"ok": bool(out.get("ok")), "messages": [{"text": m.get("text", ""), "ts": m.get("ts", "")} for m in out.get("messages") or []]}

    raise ValueError(f"Nieznana akcja komunikatora: {action!r}")


def run_developer_tools(action: str, cfg: dict, params: dict) -> dict:
    tok = str(cfg.get("api_key") or "").strip()
    if not tok:
        raise ValueError("Wymagany klucz API (api_key).")

    if action == "linear_issues":
        gql = {"query": "{ viewer { assignedIssues(first: 15) { nodes { identifier title state { name } } } } }"}
        out = _json_http("https://api.linear.app/graphql", method="POST", headers={"Authorization": tok}, body=gql)
        nodes = (((out.get("data") or {}).get("viewer") or {}).get("assignedIssues") or {}).get("nodes") or []
        return {"ok": True, "issues": nodes}

    hdrs = {"Authorization": f"Bearer {tok}", "X-GitHub-Api-Version": "2022-11-28"}
    repo = str(params.get("repo") or cfg.get("default_repo") or "").strip()

    if action == "github_notifications":
        notes = _json_http("https://api.github.com/notifications?per_page=15", headers=hdrs)
        return {
            "ok": True,
            "notifications": [
                {"repo": (n.get("repository") or {}).get("full_name"), "title": (n.get("subject") or {}).get("title")}
                for n in (notes if isinstance(notes, list) else [])
            ],
        }
    if not repo or "/" not in repo:
        raise ValueError("Podaj repozytorium w formacie właściciel/nazwa.")
    if action == "github_issues":
        issues = _json_http(f"https://api.github.com/repos/{repo}/issues?state=open&per_page=15", headers=hdrs)
        return {"ok": True, "issues": [{"number": i.get("number"), "title": i.get("title"), "url": i.get("html_url")} for i in (issues or [])]}
    if action == "github_create_issue":
        if not params.get("confirmed", False):
            raise ValueError("Utworzenie zgłoszenia GitHub Issue wymaga confirmed=True.")
        created = _json_http(
            f"https://api.github.com/repos/{repo}/issues",
            method="POST",
            headers=hdrs,
            body={"title": str(params.get("title") or ""), "body": str(params.get("body") or "")},
        )
        return {"ok": True, "number": created.get("number"), "url": created.get("html_url")}

    raise ValueError(f"Nieznana akcja deweloperska: {action!r}")


def run_media_weather(action: str, cfg: dict, params: dict) -> dict:
    if action == "weather_forecast":
        raw_coords = str(params.get("coords") or cfg.get("coords") or "52.12,20.73").strip()
        parts = [p.strip() for p in raw_coords.split(",")]
        lat = float(parts[0]) if len(parts) >= 2 else 52.12
        lon = float(parts[1]) if len(parts) >= 2 else 20.73
        url = (
            f"https://api.open-meteo.com/v1/forecast?latitude={lat}&longitude={lon}"
            "&current=temperature_2m,wind_speed_10m,precipitation&timezone=auto"
        )
        data = _json_http(url)
        return {"ok": True, "coords": f"{lat},{lon}", "current": data.get("current") or {}}

    tok = str(cfg.get("access_token") or "").strip()
    if not tok:
        raise ValueError("Spotify wymaga pola access_token.")
    hdrs = {"Authorization": f"Bearer {tok}"}
    if action == "spotify_now_playing":
        out = _json_http("https://api.spotify.com/v1/me/player/currently-playing", headers=hdrs)
        item = out.get("item") or {}
        artists = ", ".join(a.get("name", "") for a in item.get("artists") or [])
        return {"ok": True, "is_playing": out.get("is_playing"), "track": item.get("name"), "artists": artists}
    if action == "spotify_search":
        q = urllib.parse.urlencode({"q": str(params.get("query") or ""), "type": "track", "limit": "8"})
        out = _json_http(f"https://api.spotify.com/v1/search?{q}", headers=hdrs)
        tracks = (((out.get("tracks") or {}).get("items")) or [])
        return {"ok": True, "tracks": [{"name": t.get("name"), "uri": t.get("uri")} for t in tracks]}
    if action == "spotify_playback":
        cmd = str(params.get("command") or "pause").strip().lower()
        method = "POST" if cmd in ("next", "previous") else "PUT"
        _json_http(f"https://api.spotify.com/v1/me/player/{cmd}", method=method, headers=hdrs)
        return {"ok": True, "command": cmd}

    raise ValueError(f"Nieznana akcja media/pogoda: {action!r}")


def run_mcp_http(action: str, cfg: dict, params: dict, https_validator) -> dict:
    endpoint = https_validator(str(cfg.get("endpoint_url") or ""))
    tok = str(cfg.get("api_key") or "").strip()
    hdrs = {"Authorization": f"Bearer {tok}"} if tok else {}

    method = "tools/list" if action == "mcp_http_list" else "tools/call"
    rpc_params = {} if action == "mcp_http_list" else {
        "name": str(params.get("tool_name") or ""),
        "arguments": params.get("arguments") or {},
    }
    resp = _json_http(
        endpoint,
        method="POST",
        headers=hdrs,
        body={"jsonrpc": "2.0", "id": 1, "method": method, "params": rpc_params},
    )
    if "error" in resp:
        raise ValueError(f"Błąd zdalnego MCP HTTP: {resp['error']}")
    return {"ok": True, "result": resp.get("result")}


def export_llm_tool_schemas(configured_map: dict[str, dict], disabled_toolsets: set[str]) -> list[dict]:
    """Export active OpenAI/Gemini-compatible function declarations for enabled toolsets."""
    schemas: list[dict] = []
    for prov_id, meta in sorted(INTEGRATION_CATALOG.items()):
        tset = meta["toolset"]
        if tset in disabled_toolsets:
            continue
        is_ready = bool(meta.get("zero_config")) or any(
            c.get("provider") == prov_id and c.get("enabled", True)
            for c in configured_map.values()
        )
        if not is_ready:
            continue
        for tool in meta.get("tools") or []:
            schemas.append({
                "name": f"jarvis__{prov_id}__{tool['name']}",
                "toolset": tset,
                "provider": prov_id,
                "read_only": bool(tool.get("read_only", True)),
                "description": tool.get("desc", ""),
            })
    return schemas
