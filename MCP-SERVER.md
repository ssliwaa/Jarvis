# Jarvis jako serwer MCP (Gemini Enterprise)

Jarvis udostępnia swoje lane'y jako narzędzia MCP w dwóch transportach:

| Plik | Transport | Dla kogo |
|---|---|---|
| `jarvis_mcp_server.py` | stdio (JSON-RPC po linii, akceptuje też `Content-Length`) | klienci lokalni: Hermes, Claude Desktop i inne CLI |
| `jarvis_mcp_http.py` | Streamable HTTP + OAuth 2.0 na `127.0.0.1:4711` | Gemini Enterprise (custom MCP server data store) |

Oba korzystają z jednej tabeli narzędzi (`TOOLS` w `jarvis_mcp_server.py`) i wołają
żywy HTTP API Jarvisa na `127.0.0.1:4700`. Mostek **nie importuje** aplikacji, więc
nie ma drugiego pisarza do sejfu i nie da się z MCP zrestartować `server.py`.

## Narzędzia (12)

Odczyt (dziewięć): `ask`, `research`, `skills`, `briefing`, `system`, `status`,
`sessions_search`, `memory_recall`, `operator_status`.

Zapis/kontrola (trzy): `remember` (nowa notatka w sejfie), `memory_write`
(pamięć osobista, wymaga `confirm=true`), `operator_task` (uruchom/zatwierdź/
zatrzymaj zadanie Operatora: shell, pliki, przeglądarka, desktop).

## Uruchomienie

```bash
# lokalny mostek HTTP (bez tunelu)
.venv/bin/python jarvis_mcp_http.py

# publiczny: mostek + cloudflared quick tunnel jako usługa systemd
systemctl --user status  jarvis-mcp-public.service
systemctl --user restart jarvis-mcp-public.service
systemctl --user stop    jarvis-mcp-public.service

# bieżący publiczny adres (zmienia się przy każdym restarcie tunelu)
cat ~/.jarvis-tools/mcp-public-url.txt
```

Konfiguracja usługi: `~/.config/jarvis-mcp/env`
(`JARVIS_MCP_HTTP_READONLY=0` wystawia też zapis, `JARVIS_MCP_HTTP_ANON=0`
nigdy nie przyjmuje wywołań bez tokenu).

## Wartości do konsoli Gemini Enterprise

Uruchom `.venv/bin/python jarvis_mcp_http.py --show-setup` — wypisze aktualne
`client_id`, `client_secret` i adresy. Pozostałe pola:

| Pole w Gemini Enterprise | Wartość |
|---|---|
| MCP Server URL | `https://<host>.trycloudflare.com/mcp` (z pliku `~/.jarvis-tools/mcp-public-url.txt`) |
| Authentication | OAuth 2.0 |
| Authorization URL | `https://<host>.trycloudflare.com/authorize` |
| Token URL | `https://<host>.trycloudflare.com/token` |
| Client ID | z `--show-setup` |
| Client Secret | z `--show-setup` |
| Scopes | `jarvis.read jarvis.admin` — bez `jarvis.admin` działa tylko odczyt |
| Redirect URI | `https://vertexaisearch.cloud.google.com/oauth-redirect` (ustawia Google) |

Kroki w konsoli: **Connected Data Stores → Add MCP server → MCP Server
Configuration** → URL + OAuth 2.0 → zapisz → **włącz akcje** (Enable actions),
inaczej narzędzia nie trafią do asystenta. Przy pierwszym połączeniu Google
przekieruje na `/authorize`, gdzie trzeba podać **frazę zgody właściciela**;
token odświeżania żyje 90 dni.

## Bezpieczeństwo

- Każde żądanie `/mcp` wymaga `Authorization: Bearer`; brak tokenu → 401 z
  `WWW-Authenticate` wskazującym metadane OAuth.
- Token z zakresem `jarvis.read` **nie** wywoła `remember`, `memory_write` ani
  `operator_task` — zapis i sterowanie maszyną wymagają `jarvis.admin`, a ten
  zakres powstaje tylko po podaniu frazy zgody.
- Fraza zgody: hash w `~/.jarvis-tools/mcp-http.json` (0600). Zmiana:
  `.venv/bin/python jarvis_mcp_http.py --set-passphrase`.
- Rotacja klienta OAuth: usuń `~/.jarvis-tools/mcp-http.json` i zrestartuj
  usługę (nowy `client_id`/`client_secret`, do poprawienia w konsoli Google).
- Quick tunnel nie ma SLA ani stałego adresu; po restarcie URL się zmienia i
  trzeba go zaktualizować w Gemini Enterprise. Stały adres wymaga named tunnel
  z własną domeną w Cloudflare.
- Unit używa `Wants=jarvis.service`, nie `Requires=`: restart Jarvisa nie
  zabija już mostka, więc aktualizacja aplikacji nie zmienia publicznego URL-a.
  Restart `jarvis-mcp-public.service` nadal mintuje nowy adres.
- Każdy, kto zna URL i frazę zgody, dostaje `jarvis.admin`, czyli shell na tej
  maszynie. Traktuj frazę jak hasło roota; przy podejrzeniu wycieku zmień ją i
  zrotuj klienta.
- Odpowiedzi HTTP zawsze niosą `Connection: close`: Cloudflare potrafi
  przepchać ciało odrzuconego żądania razem z kolejnym na jednym połączeniu do
  originu, co dawało 400/501 na następnym żądaniu.

## Diagnostyka

```bash
journalctl --user -u jarvis-mcp-public.service -f          # mostek + tunel
curl -s http://127.0.0.1:4711/healthz                      # 12 narzędzi, tryb
curl -s "$(cat ~/.jarvis-tools/mcp-public-url.txt)/.well-known/oauth-authorization-server"
```

Typowe błędy: `JARVIS_UNREACHABLE` — nie działa `jarvis.service`;
`invalid_token` — token wygasł (8 h) albo odświeżanie zostało unieważnione;
`This token carries only jarvis.read` — zgoda bez zakresu `jarvis.admin`.
