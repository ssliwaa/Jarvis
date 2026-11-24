"""Unified Toolsets & External Integrations Hub (`connectors_hub.py`).

Native pluggable toolset & integration engine for Jarvis (modeled on modular AI agent
toolset registries):
  - 8 logical Toolsets (`productivity`, `smart_home`, `web_research`, `messaging`,
    `developer`, `media_weather`, `automation`, `mcp`) with enable/disable state.
  - 18 native integrations stored in a `0o600` credential vault (`connectors_vault.json`),
    with SSRF protection, secret masking, write-gates (`confirmed=True`), `mcp_stdio` +
    `mcp_http` allowlists, and OpenAI/Gemini tool-schema export.
"""

from __future__ import annotations

import imaplib
import ipaddress
import json
import os
import re
import shlex
import smtplib
import subprocess
import time
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from email import message_from_bytes
from email.header import decode_header
from email.message import EmailMessage
from pathlib import Path

import agent_cli
import toolsets_catalog

SECRET_FIELDS = {
    "app_password", "password", "client_secret", "refresh_token",
    "access_token", "bot_token", "api_key", "ics_url", "token",
    "webhook_url", "topic",
}
SUPPORTED_PROVIDERS = set(toolsets_catalog.INTEGRATION_CATALOG.keys())
ICS_BLOCK_RE = re.compile(r"BEGIN:VEVENT(.*?)END:VEVENT", re.DOTALL)


def _vault_path() -> Path:
    base = agent_cli.ROOT.parent
    base.mkdir(mode=0o700, parents=True, exist_ok=True)
    return base / "connectors_vault.json"


def _load_vault() -> dict:
    p = _vault_path()
    if not p.is_file():
        return {"connectors": {}, "disabled_toolsets": []}
    try:
        raw = json.loads(p.read_text(encoding="utf-8"))
        if isinstance(raw, dict) and isinstance(raw.get("connectors"), dict):
            raw.setdefault("disabled_toolsets", [])
            return raw
    except (OSError, ValueError):
        pass
    return {"connectors": {}, "disabled_toolsets": []}


def _save_vault(data: dict) -> None:
    p = _vault_path()
    tmp = p.with_name(f".connectors_vault.json.tmp-{os.getpid()}")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    os.chmod(tmp, 0o600)
    tmp.replace(p)


def _mask_config(cfg: dict) -> dict:
    masked: dict = {}
    for k, v in cfg.items():
        if k in SECRET_FIELDS and v:
            s = str(v)
            masked[k] = f"••••{s[-4:]}" if len(s) > 8 else "••••••••"
        elif k == "env" and isinstance(v, dict):
            masked[k] = {ek: "••••••••" for ek in v}
        else:
            masked[k] = v
    return masked


def validate_remote_url(url: str, *, allow_lan: bool = False) -> str:
    """Validate external URLs against SSRF (always blocking loopback & cloud link-local metadata)."""
    parsed = urllib.parse.urlsplit(str(url or "").strip())
    allowed_schemes = ("https", "http") if allow_lan else ("https",)
    if parsed.scheme not in allowed_schemes or not parsed.hostname:
        req_scheme = "HTTP/HTTPS" if allow_lan else "HTTPS"
        raise ValueError(f"Wymagany jest zewnętrzny adres {req_scheme}.")
    host = parsed.hostname.lower()
    if host in ("localhost", "127.0.0.1", "::1", "0.0.0.0"):
        raise ValueError("Adresy loopback (localhost) są zablokowane przed SSRF.")
    try:
        ip = ipaddress.ip_address(host)
        if ip.is_loopback or ip.is_link_local or ip.is_multicast:
            raise ValueError("Adresy loopback i link-local metadata są zablokowane przed SSRF.")
        if ip.is_private and not allow_lan:
            raise ValueError("Prywatne adresy IP są zablokowane przed SSRF dla tej integracji.")
    except ValueError as exc:
        if "zablokowane" in str(exc):
            raise
    return str(url).strip()


def set_toolset_enabled(toolset_id: str, enabled: bool) -> dict:
    ts = str(toolset_id or "").strip().lower()
    if ts not in toolsets_catalog.TOOLSETS_META:
        raise ValueError(f"Nieznany toolset: {ts!r}")
    vault = _load_vault()
    disabled = set(vault.get("disabled_toolsets") or [])
    if enabled:
        disabled.discard(ts)
    else:
        disabled.add(ts)
    vault["disabled_toolsets"] = sorted(disabled)
    _save_vault(vault)
    return {"ok": True, "toolset": ts, "enabled": bool(enabled), "disabled_toolsets": vault["disabled_toolsets"]}


def configure_connector(connector_id: str, provider: str, settings: dict, *, enabled: bool = True) -> dict:
    """Create or update any of the 18 integrations in the `0o600` vault."""
    prov = str(provider or "").strip().lower()
    if prov not in SUPPORTED_PROVIDERS:
        raise ValueError(f"Nieobsługiwana integracja: {prov!r}. Dostępne: {sorted(SUPPORTED_PROVIDERS)}")
    cid = re.sub(r"[^a-zA-Z0-9_\-]", "_", str(connector_id or prov).strip())[:48]
    if not cid:
        raise ValueError("Brak identyfikatora integracji.")

    vault = _load_vault()
    prev = vault["connectors"].get(cid, {}).get("settings", {})
    merged = dict(prev)
    for k, v in (settings or {}).items():
        if v is None or (isinstance(v, str) and v.startswith("••••")):
            continue
        merged[k] = v

    if prov == "google_calendar" and merged.get("ics_url"):
        merged["ics_url"] = validate_remote_url(merged["ics_url"], allow_lan=False)
    elif prov == "home_assistant" and merged.get("ha_url"):
        merged["ha_url"] = validate_remote_url(merged["ha_url"], allow_lan=True)
    elif prov == "discord" and merged.get("webhook_url"):
        merged["webhook_url"] = validate_remote_url(merged["webhook_url"], allow_lan=False)
    elif prov == "mcp_http" and merged.get("endpoint_url"):
        merged["endpoint_url"] = validate_remote_url(merged["endpoint_url"], allow_lan=False)
    elif prov == "mcp_stdio" and merged.get("command_str") and not merged.get("command"):
        merged["command"] = shlex.split(str(merged["command_str"]))

    vault["connectors"][cid] = {
        "id": cid,
        "provider": prov,
        "enabled": bool(enabled),
        "updated_at": round(time.time(), 3),
        "settings": merged,
    }
    _save_vault(vault)
    return {
        "ok": True,
        "id": cid,
        "provider": prov,
        "enabled": bool(enabled),
        "settings": _mask_config(merged),
    }


def remove_connector(connector_id: str) -> dict:
    vault = _load_vault()
    removed = vault["connectors"].pop(str(connector_id or "").strip(), None) is not None
    _save_vault(vault)
    return {"ok": True, "removed": removed}


def list_connectors() -> dict:
    """Return full Toolset registry, 18-integration catalog with live status, masked configs & MCP presets."""
    vault = _load_vault()
    disabled_ts = set(vault.get("disabled_toolsets") or [])
    configured = vault["connectors"]

    items: list[dict] = []
    by_prov: dict[str, list[str]] = {}
    for cid, entry in sorted(configured.items()):
        prov = str(entry.get("provider") or "")
        if entry.get("enabled", True):
            by_prov.setdefault(prov, []).append(cid)
        items.append({
            "id": cid,
            "provider": prov,
            "enabled": bool(entry.get("enabled", True)),
            "updated_at": entry.get("updated_at"),
            "settings": _mask_config(entry.get("settings") or {}),
        })

    catalog_view: list[dict] = []
    for prov_id, meta in toolsets_catalog.INTEGRATION_CATALOG.items():
        ts = meta["toolset"]
        is_connected = bool(by_prov.get(prov_id))
        status = "disabled" if ts in disabled_ts else (
            "connected" if is_connected else ("ready_zero_key" if meta.get("zero_config") else "available")
        )
        catalog_view.append({
            "provider": prov_id,
            "title": meta["title"],
            "toolset": ts,
            "zero_config": bool(meta.get("zero_config")),
            "status": status,
            "setup_hint": meta["setup_hint"],
            "fields": meta["fields"],
            "tools": meta["tools"],
        })

    toolsets_view = [
        {
            "id": ts_id,
            "label": ts_meta["label"],
            "description": ts_meta["description"],
            "enabled": ts_id not in disabled_ts,
        }
        for ts_id, ts_meta in toolsets_catalog.TOOLSETS_META.items()
    ]

    active_schemas = toolsets_catalog.export_llm_tool_schemas(configured, disabled_ts)
    return {
        "ok": True,
        "toolsets": toolsets_view,
        "catalog": catalog_view,
        "connectors": items,
        "mcp_presets": toolsets_catalog.MCP_PRESET_TEMPLATES,
        "active_tools_count": len(active_schemas),
        "supported_providers": sorted(SUPPORTED_PROVIDERS),
    }


def get_active_tool_schemas() -> list[dict]:
    vault = _load_vault()
    return toolsets_catalog.export_llm_tool_schemas(
        vault["connectors"],
        set(vault.get("disabled_toolsets") or []),
    )


def _get_entry(connector_id: str = "", provider: str = "", *, allow_zero_config: bool = False) -> dict:
    vault = _load_vault()
    disabled_ts = set(vault.get("disabled_toolsets") or [])
    if provider:
        ts = (toolsets_catalog.INTEGRATION_CATALOG.get(provider) or {}).get("toolset")
        if ts and ts in disabled_ts:
            raise ValueError(f"Zestaw narzędzi '{ts}' jest obecnie wyłączony.")

    if connector_id and connector_id in vault["connectors"]:
        entry = vault["connectors"][connector_id]
        ep = str(entry.get("provider") or "")
        ets = (toolsets_catalog.INTEGRATION_CATALOG.get(ep) or {}).get("toolset")
        if ets and ets in disabled_ts:
            raise ValueError(f"Zestaw narzędzi '{ets}' jest obecnie wyłączony.")
        return entry

    for entry in vault["connectors"].values():
        if entry.get("provider") == provider and entry.get("enabled", True):
            return entry

    if allow_zero_config:
        return {"id": provider, "provider": provider, "enabled": True, "settings": {}}
    raise ValueError(f"Integracja {connector_id or provider!r} nie jest jeszcze skonfigurowana.")


# ---------------------------------------------------------------------------
# Google OAuth2 + Calendar + Gmail + Telegram + MCP Stdio
# ---------------------------------------------------------------------------

def _google_access_token(settings: dict) -> str:
    direct = str(settings.get("access_token") or "").strip()
    refresh = str(settings.get("refresh_token") or "").strip()
    cid = str(settings.get("client_id") or "").strip()
    csec = str(settings.get("client_secret") or "").strip()
    if refresh and cid and csec:
        form = urllib.parse.urlencode({
            "client_id": cid,
            "client_secret": csec,
            "refresh_token": refresh,
            "grant_type": "refresh_token",
        }).encode("utf-8")
        req = urllib.request.Request(
            "https://oauth2.googleapis.com/token",
            data=form,
            method="POST",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
        tok = str(payload.get("access_token") or "").strip()
        if tok:
            return tok
    if direct:
        return direct
    raise ValueError("Brak tokenu Google OAuth2 (podaj refresh_token+client_id+client_secret lub access_token).")


def _unfold_ics(raw_ics: str) -> str:
    return re.sub(r"\r?\n[ \t]", "", str(raw_ics or ""))


def _parse_ics_dt(val: str) -> datetime | None:
    clean = val.strip()
    for fmt in ("%Y%m%dT%H%M%SZ", "%Y%m%dT%H%M%S", "%Y%m%d"):
        try:
            dt = datetime.strptime(clean, fmt)
            if clean.endswith("Z"):
                return dt.replace(tzinfo=timezone.utc).astimezone()
            return dt.replace(tzinfo=datetime.now().astimezone().tzinfo)
        except ValueError:
            continue
    return None


def parse_ics_events(raw_ics: str, *, days_ahead: int = 7, now_dt: datetime | None = None) -> list[dict]:
    unfolded = _unfold_ics(raw_ics)
    ref = now_dt or datetime.now().astimezone()
    win_start = ref - timedelta(hours=2)
    win_end = ref + timedelta(days=max(1, int(days_ahead)))
    events: list[dict] = []

    for block in ICS_BLOCK_RE.findall(unfolded):
        fields: dict[str, str] = {}
        for line in block.splitlines():
            if ":" not in line:
                continue
            k_part, v_part = line.split(":", 1)
            base_k = k_part.split(";", 1)[0].strip().upper()
            fields[base_k] = v_part.strip().replace("\\n", " ").replace("\\,", ",")

        dt_start = _parse_ics_dt(fields.get("DTSTART", ""))
        if dt_start is None or not (win_start <= dt_start <= win_end):
            continue
        dt_end = _parse_ics_dt(fields.get("DTEND", ""))
        events.append({
            "summary": fields.get("SUMMARY") or "(bez tytułu)",
            "start": dt_start.isoformat(),
            "end": dt_end.isoformat() if dt_end else "",
            "location": fields.get("LOCATION") or "",
            "status": fields.get("STATUS") or "CONFIRMED",
        })

    events.sort(key=lambda e: e["start"])
    return events[:25]


def calendar_list_events(connector_id: str = "", *, days_ahead: int = 7) -> dict:
    entry = _get_entry(connector_id, provider="google_calendar")
    cfg = entry.get("settings") or {}
    ics_url = str(cfg.get("ics_url") or "").strip()

    if ics_url:
        safe_url = validate_remote_url(ics_url, allow_lan=False)
        req = urllib.request.Request(safe_url, headers={"User-Agent": "Jarvis-Assistant/1.0"})
        with urllib.request.urlopen(req, timeout=12) as resp:
            raw_ics = resp.read(2_000_000).decode("utf-8", errors="replace")
        events = parse_ics_events(raw_ics, days_ahead=days_ahead)
        return {"ok": True, "mode": "ics", "count": len(events), "events": events}

    token = _google_access_token(cfg)
    cal_id = urllib.parse.quote(str(cfg.get("calendar_id") or "primary"), safe="")
    now_utc = datetime.now(timezone.utc)
    params = urllib.parse.urlencode({
        "singleEvents": "true",
        "orderBy": "startTime",
        "timeMin": (now_utc - timedelta(hours=1)).isoformat().replace("+00:00", "Z"),
        "timeMax": (now_utc + timedelta(days=max(1, int(days_ahead)))).isoformat().replace("+00:00", "Z"),
        "maxResults": "25",
    })
    req = urllib.request.Request(
        f"https://www.googleapis.com/calendar/v3/calendars/{cal_id}/events?{params}",
        headers={"Authorization": f"Bearer {token}"},
    )
    with urllib.request.urlopen(req, timeout=12) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    items = [
        {
            "id": it.get("id", ""),
            "summary": it.get("summary") or "(bez tytułu)",
            "start": (it.get("start") or {}).get("dateTime") or (it.get("start") or {}).get("date") or "",
            "end": (it.get("end") or {}).get("dateTime") or (it.get("end") or {}).get("date") or "",
            "location": it.get("location") or "",
        }
        for it in (data.get("items") or [])
    ]
    return {"ok": True, "mode": "google_oauth", "count": len(items), "events": items}


def calendar_create_event(summary: str, start_iso: str, end_iso: str, *,
                          description: str = "", location: str = "",
                          connector_id: str = "") -> dict:
    entry = _get_entry(connector_id, provider="google_calendar")
    cfg = entry.get("settings") or {}
    token = _google_access_token(cfg)
    cal_id = urllib.parse.quote(str(cfg.get("calendar_id") or "primary"), safe="")
    payload = json.dumps({
        "summary": str(summary or "").strip(),
        "description": str(description or "").strip(),
        "location": str(location or "").strip(),
        "start": {"dateTime": str(start_iso).strip()},
        "end": {"dateTime": str(end_iso).strip()},
    }).encode("utf-8")
    req = urllib.request.Request(
        f"https://www.googleapis.com/calendar/v3/calendars/{cal_id}/events",
        data=payload,
        method="POST",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=12) as resp:
        created = json.loads(resp.read().decode("utf-8"))
    return {"ok": True, "id": created.get("id"), "summary": created.get("summary"), "htmlLink": created.get("htmlLink")}


def _decode_mime_header(raw_val: str | None) -> str:
    if not raw_val:
        return ""
    out: list[str] = []
    for part, enc in decode_header(raw_val):
        out.append(part.decode(enc or "utf-8", errors="replace") if isinstance(part, bytes) else str(part))
    return "".join(out).strip()


def gmail_list_messages(connector_id: str = "", *, limit: int = 10, unread_only: bool = True) -> dict:
    entry = _get_entry(connector_id, provider="gmail")
    cfg = entry.get("settings") or {}
    email_addr = str(cfg.get("email") or "").strip()
    app_pw = str(cfg.get("app_password") or "").strip().replace(" ", "")
    cap = max(1, min(int(limit), 25))

    if email_addr and app_pw:
        host = str(cfg.get("imap_host") or "imap.gmail.com").strip()
        port = int(cfg.get("imap_port") or 993)
        messages: list[dict] = []
        imap = imaplib.IMAP4_SSL(host, port, timeout=12)
        try:
            imap.login(email_addr, app_pw)
            imap.select("INBOX", readonly=True)
            _typ, msg_nums = imap.search(None, "UNSEEN" if unread_only else "ALL")
            ids = (msg_nums[0].split() if msg_nums and msg_nums[0] else [])[-cap:]
            for mid in reversed(ids):
                _ft, msg_data = imap.fetch(mid, "(BODY.PEEK[HEADER.FIELDS (SUBJECT FROM DATE)])")
                if not msg_data or not isinstance(msg_data[0], tuple):
                    continue
                msg = message_from_bytes(msg_data[0][1])
                messages.append({
                    "id": mid.decode("ascii", errors="ignore"),
                    "subject": _decode_mime_header(msg.get("Subject")) or "(brak tematu)",
                    "from": _decode_mime_header(msg.get("From")),
                    "date": str(msg.get("Date") or "").strip(),
                })
        finally:
            try:
                imap.logout()
            except Exception:
                pass
        return {"ok": True, "mode": "imap", "count": len(messages), "messages": messages}

    token = _google_access_token(cfg)
    params = urllib.parse.urlencode({"maxResults": str(cap), "q": "is:unread in:inbox" if unread_only else "in:inbox"})
    req = urllib.request.Request(
        f"https://gmail.googleapis.com/gmail/v1/users/me/messages?{params}",
        headers={"Authorization": f"Bearer {token}"},
    )
    with urllib.request.urlopen(req, timeout=12) as resp:
        listing = json.loads(resp.read().decode("utf-8"))
    messages = []
    for item in (listing.get("messages") or [])[:cap]:
        mid = item.get("id")
        mreq = urllib.request.Request(
            f"https://gmail.googleapis.com/gmail/v1/users/me/messages/{mid}?format=metadata"
            "&metadataHeaders=Subject&metadataHeaders=From&metadataHeaders=Date",
            headers={"Authorization": f"Bearer {token}"},
        )
        with urllib.request.urlopen(mreq, timeout=10) as mresp:
            mdata = json.loads(mresp.read().decode("utf-8"))
        hdrs = {h["name"].lower(): h["value"] for h in (mdata.get("payload", {}).get("headers") or [])}
        messages.append({
            "id": mid,
            "subject": hdrs.get("subject") or "(brak tematu)",
            "from": hdrs.get("from") or "",
            "date": hdrs.get("date") or "",
            "snippet": mdata.get("snippet") or "",
        })
    return {"ok": True, "mode": "gmail_oauth", "count": len(messages), "messages": messages}


def gmail_send_message(to_addr: str, subject: str, body_text: str, *,
                       confirmed: bool = False, connector_id: str = "") -> dict:
    if not confirmed:
        raise ValueError("Wysłanie wiadomości e-mail wymaga jawnego potwierdzenia (confirmed=True).")
    entry = _get_entry(connector_id, provider="gmail")
    cfg = entry.get("settings") or {}
    email_addr = str(cfg.get("email") or "").strip()
    app_pw = str(cfg.get("app_password") or "").strip().replace(" ", "")
    if not email_addr or not app_pw:
        raise ValueError("Wysyłka SMTP wymaga skonfigurowanego pola email oraz app_password.")

    msg = EmailMessage()
    msg["From"] = email_addr
    msg["To"] = str(to_addr).strip()
    msg["Subject"] = str(subject).strip()
    msg.set_content(str(body_text or ""))
    with smtplib.SMTP_SSL(str(cfg.get("smtp_host") or "smtp.gmail.com"), int(cfg.get("smtp_port") or 465), timeout=12) as smtp:
        smtp.login(email_addr, app_pw)
        smtp.send_message(msg)
    return {"ok": True, "sent_to": msg["To"], "subject": msg["Subject"]}


def telegram_send(text: str, *, connector_id: str = "") -> dict:
    entry = _get_entry(connector_id, provider="telegram")
    cfg = entry.get("settings") or {}
    bot_tok = str(cfg.get("bot_token") or "").strip()
    chat_id = str(cfg.get("chat_id") or "").strip()
    if not bot_tok or not chat_id:
        raise ValueError("Konektor Telegram wymaga pól bot_token oraz chat_id.")
    payload = json.dumps({"chat_id": chat_id, "text": str(text or "")[:4000]}).encode("utf-8")
    req = urllib.request.Request(
        f"https://api.telegram.org/bot{bot_tok}/sendMessage",
        data=payload,
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        out = json.loads(resp.read().decode("utf-8"))
    return {"ok": bool(out.get("ok")), "message_id": (out.get("result") or {}).get("message_id")}


def mcp_stdio_request(command: list[str], *, method: str = "tools/list",
                      params: dict | None = None, env_overrides: dict | None = None,
                      allowed_tools: set[str] | None = None,
                      server_alias: str = "mcp",
                      timeout_seconds: float = 12.0) -> dict:
    """JSON-RPC 2.0 MCP `stdio` client with per-server tool allowlist and `mcp__<srv>__<tool>` namespacing."""
    if not isinstance(command, list) or not command or not str(command[0]).strip():
        raise ValueError("Komenda serwera MCP stdio musi być niepustą listą argumentów.")
    if method == "tools/call" and allowed_tools:
        tname = str((params or {}).get("name") or "")
        if tname not in allowed_tools:
            raise ValueError(f"Narzędzie MCP {tname!r} nie znajduje się na liście allowed_tools serwera.")

    cmd_list = [str(part) for part in command]
    run_env = dict(os.environ)
    if isinstance(env_overrides, dict):
        for k, v in env_overrides.items():
            run_env[str(k)] = str(v)

    stdin_payload = "\n".join([
        json.dumps({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"protocolVersion": "2024-11-05", "capabilities": {}, "clientInfo": {"name": "jarvis-mcp-client", "version": "2.0.0"}},
        }),
        json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}}),
        json.dumps({"jsonrpc": "2.0", "id": 2, "method": method, "params": params or {}}),
    ]) + "\n"

    proc = subprocess.run(
        cmd_list,
        input=stdin_payload,
        capture_output=True,
        text=True,
        env=run_env,
        timeout=max(2.0, min(float(timeout_seconds), 45.0)),
        check=False,
    )
    responses: dict[int, dict] = {}
    for line in (proc.stdout or "").splitlines():
        s = line.strip()
        if s.startswith("{"):
            try:
                msg = json.loads(s)
                if isinstance(msg, dict) and "id" in msg:
                    responses[int(msg["id"])] = msg
            except (TypeError, ValueError):
                pass

    target = responses.get(2)
    if not target:
        err_tail = (proc.stderr or proc.stdout or "").strip()[-400:]
        raise ValueError(f"Serwer MCP stdio nie zwrócił odpowiedzi JSON-RPC (kod={proc.returncode}): {err_tail}")
    if "error" in target:
        raise ValueError(f"Błąd MCP: {target['error']}")

    result = target.get("result") or {}
    if method == "tools/list" and isinstance(result, dict) and isinstance(result.get("tools"), list):
        clean_alias = re.sub(r"[^a-zA-Z0-9_]", "_", server_alias)
        filtered = []
        for t in result["tools"]:
            raw_name = str(t.get("name") or "")
            if allowed_tools and raw_name not in allowed_tools:
                continue
            filtered.append({
                **t,
                "namespaced": f"mcp__{clean_alias}__{raw_name}",
            })
        result = {**result, "tools": filtered}
    return {"ok": True, "result": result}


def _parse_allowlist(cfg: dict) -> set[str] | None:
    raw = cfg.get("allowed_tools")
    if isinstance(raw, list):
        items = {str(x).strip() for x in raw if str(x).strip()}
        return items or None
    if isinstance(raw, str) and raw.strip():
        return {p.strip() for p in raw.split(",") if p.strip()}
    return None


# ---------------------------------------------------------------------------
# Unified Action Router Across All 18 Integrations
# ---------------------------------------------------------------------------

def execute_connector_action(action: str, payload: dict | None = None) -> dict:
    body = payload or {}
    cid = str(body.get("connector_id") or "").strip()

    if action == "calendar_events":
        return calendar_list_events(cid, days_ahead=int(body.get("days_ahead") or 7))
    if action == "calendar_create":
        return calendar_create_event(
            str(body.get("summary") or ""),
            str(body.get("start_iso") or ""),
            str(body.get("end_iso") or ""),
            description=str(body.get("description") or ""),
            location=str(body.get("location") or ""),
            connector_id=cid,
        )
    if action == "gmail_inbox":
        return gmail_list_messages(cid, limit=int(body.get("limit") or 10), unread_only=bool(body.get("unread_only", True)))
    if action == "gmail_send":
        return gmail_send_message(
            str(body.get("to") or ""),
            str(body.get("subject") or ""),
            str(body.get("body") or ""),
            confirmed=bool(body.get("confirmed", False)),
            connector_id=cid,
        )
    if action == "telegram_send":
        return telegram_send(str(body.get("text") or ""), connector_id=cid)

    if action.startswith("cron_"):
        _get_entry(cid, provider="cronjob", allow_zero_config=True)
        return toolsets_catalog.cron_manage(action, body)

    if action.startswith("ha_"):
        entry = _get_entry(cid, provider="home_assistant")
        return toolsets_catalog.run_home_assistant(action, entry.get("settings") or {}, body)

    if action.startswith("notion_"):
        entry = _get_entry(cid, provider="notion")
        return toolsets_catalog.run_notion(action, entry.get("settings") or {}, body)

    if action.startswith("todoist_"):
        entry = _get_entry(cid, provider="todoist")
        return toolsets_catalog.run_todoist(action, entry.get("settings") or {}, body)

    if action.startswith("obsidian_"):
        entry = _get_entry(cid, provider="obsidian")
        return toolsets_catalog.run_obsidian(action, entry.get("settings") or {}, body)

    if action in ("web_search", "web_extract"):
        entry = _get_entry(cid, provider="web_search", allow_zero_config=True)
        return toolsets_catalog.run_web_tools(action, entry.get("settings") or {}, body, validate_remote_url)

    if action in ("discord_send", "ntfy_publish", "slack_send", "slack_history"):
        prov = "discord" if action.startswith("discord") else ("ntfy" if action.startswith("ntfy") else "slack")
        entry = _get_entry(cid, provider=prov)
        return toolsets_catalog.run_messaging_extra(action, entry.get("settings") or {}, body, validate_remote_url)

    if action in ("github_notifications", "github_issues", "github_create_issue", "linear_issues"):
        prov = "linear" if action.startswith("linear") else "github"
        entry = _get_entry(cid, provider=prov)
        return toolsets_catalog.run_developer_tools(action, entry.get("settings") or {}, body)

    if action in ("weather_forecast", "spotify_now_playing", "spotify_search", "spotify_playback"):
        prov = "open_meteo" if action == "weather_forecast" else "spotify"
        entry = _get_entry(cid, provider=prov, allow_zero_config=(prov == "open_meteo"))
        return toolsets_catalog.run_media_weather(action, entry.get("settings") or {}, body)

    if action in ("mcp_list_tools", "mcp_call_tool"):
        entry = _get_entry(cid, provider="mcp_stdio")
        cfg = entry.get("settings") or {}
        cmd = cfg.get("command") or shlex.split(str(cfg.get("command_str") or ""))
        allow = _parse_allowlist(cfg)
        if action == "mcp_list_tools":
            return mcp_stdio_request(cmd, method="tools/list", env_overrides=cfg.get("env"), allowed_tools=allow, server_alias=entry["id"])
        return mcp_stdio_request(
            cmd,
            method="tools/call",
            params={"name": str(body.get("tool_name") or ""), "arguments": body.get("arguments") or {}},
            env_overrides=cfg.get("env"),
            allowed_tools=allow,
            server_alias=entry["id"],
        )

    if action in ("mcp_http_list", "mcp_http_call"):
        entry = _get_entry(cid, provider="mcp_http")
        return toolsets_catalog.run_mcp_http(action, entry.get("settings") or {}, body, validate_remote_url)

    raise ValueError(f"Nieznana akcja integracji: {action!r}")


def briefing_digest() -> dict:
    vault = _load_vault()
    disabled_ts = set(vault.get("disabled_toolsets") or [])
    enabled_providers = [
        e.get("provider")
        for e in vault["connectors"].values()
        if e.get("enabled", True)
    ]
    active_schemas = toolsets_catalog.export_llm_tool_schemas(vault["connectors"], disabled_ts)
    return {
        "configured_count": len(enabled_providers),
        "providers": sorted(set(p for p in enabled_providers if p)),
        "catalog_total": len(toolsets_catalog.INTEGRATION_CATALOG),
        "toolsets_total": len(toolsets_catalog.TOOLSETS_META),
        "disabled_toolsets": sorted(disabled_ts),
        "active_tools_count": len(active_schemas),
    }
