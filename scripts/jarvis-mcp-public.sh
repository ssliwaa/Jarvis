#!/usr/bin/env bash
# Jarvis MCP public face: the local Streamable-HTTP bridge plus a Cloudflare
# quick tunnel in front of it.
#
# A quick tunnel mints a new hostname on every start, so the hostname is
# published to ~/.jarvis-tools/mcp-public-url.txt; jarvis_mcp_http.py reads that
# file so the OAuth metadata Gemini fetches matches the host it actually called.
#
# Stop: systemctl --user stop jarvis-mcp-public.service
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="${JARVIS_MCP_ROOT:-$(cd "$SCRIPT_DIR/.." && pwd)}"
PYTHON="${JARVIS_PYTHON:-$ROOT/.venv/bin/python}"
CLOUDFLARED="${CLOUDFLARED_BIN:-$(command -v cloudflared || printf '%s' "$HOME/.local/bin/cloudflared")}"
PORT="${JARVIS_MCP_HTTP_PORT:-4711}"
URL_FILE="${JARVIS_MCP_PUBLIC_URL_FILE:-$HOME/.jarvis-tools/mcp-public-url.txt}"

if [ ! -x "$PYTHON" ]; then
    printf '[jarvis-mcp] Python interpreter not found or not executable: %s\n' "$PYTHON" >&2
    exit 1
fi
if [ ! -x "$CLOUDFLARED" ]; then
    printf '[jarvis-mcp] cloudflared binary not found or not executable: %s\n' "$CLOUDFLARED" >&2
    exit 1
fi

mkdir -p "$(dirname "$URL_FILE")"
install -m 600 /dev/null "$URL_FILE"

cd "$ROOT" || exit 1
"$PYTHON" jarvis_mcp_http.py &
BRIDGE=$!

cleanup() {
    kill "$BRIDGE" 2>/dev/null || true
    wait "$BRIDGE" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

READY=0
for _ in $(seq 1 60); do
    if ! kill -0 "$BRIDGE" 2>/dev/null; then
        printf '[jarvis-mcp] jarvis_mcp_http.py exited prematurely.\n' >&2
        exit 1
    fi
    if curl -sf -m 1 "http://127.0.0.1:$PORT/healthz" >/dev/null 2>&1; then
        READY=1
        break
    fi
    sleep 0.5
done

if [ "$READY" -ne 1 ]; then
    printf '[jarvis-mcp] Timed out waiting for http://127.0.0.1:%s/healthz; aborting tunnel.\n' "$PORT" >&2
    exit 1
fi

"$CLOUDFLARED" tunnel --no-autoupdate --url "http://127.0.0.1:$PORT" 2>&1 |
while IFS= read -r line; do
    printf '[tunnel] %s\n' "$line"
    if [[ "$line" =~ (https://[a-z0-9-]+\.trycloudflare\.com) ]]; then
        printf '%s\n' "${BASH_REMATCH[1]}" > "$URL_FILE"
    fi
done
