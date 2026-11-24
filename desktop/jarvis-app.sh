#!/usr/bin/env bash
# Launch Jarvis in a dedicated desktop window.
set -euo pipefail
PROJECT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ELECTRON="$PROJECT/desktop/node_modules/electron/dist/electron"

if [[ ! -x "$ELECTRON" ]]; then
  if command -v electron >/dev/null 2>&1; then
    ELECTRON="$(command -v electron)"
  else
    printf '%s\n' "Jarvis desktop: Electron is missing. Run: cd $PROJECT/desktop && npm install" >&2
    if command -v notify-send >/dev/null 2>&1; then
      notify-send "Jarvis" "Electron is missing; run npm install in desktop/." || true
    fi
    exit 1
  fi
fi

args=(--ozone-platform-hint=auto "$PROJECT/desktop" "$@")
# The Chromium sandbox must stay on by default. A host can lack both usable
# paths: the SUID helper is not setuid-root and AppArmor blocks unprivileged
# user namespaces. That exact host shape gets a visible warning and the
# documented exception; every other host keeps the sandbox.
SANDBOX_HELPER="$(dirname "$ELECTRON")/chrome-sandbox"
APPARMOR_RESTRICT="$(cat /proc/sys/kernel/apparmor_restrict_unprivileged_userns 2>/dev/null || true)"
HELPER_UNUSABLE=0
if [[ ! -e "$SANDBOX_HELPER" || ! -u "$SANDBOX_HELPER" ]]; then
  HELPER_UNUSABLE=1
fi
if [[ "${JARVIS_ELECTRON_NO_SANDBOX:-0}" != "1" && "$APPARMOR_RESTRICT" == "1" \
      && "$HELPER_UNUSABLE" == "1" ]]; then
  printf '%s\n' "Jarvis desktop: no usable Chromium sandbox on this host;" \
    "running as an explicit local exception (JARVIS_ELECTRON_NO_SANDBOX=1)." >&2
  if command -v notify-send >/dev/null 2>&1; then
    notify-send "Jarvis" "Chromium sandbox is unavailable on this host; the desktop window runs without it." || true
  fi
  exec "$ELECTRON" --no-sandbox "${args[@]}"
fi
if [[ "${JARVIS_ELECTRON_NO_SANDBOX:-0}" == "1" ]]; then
  exec "$ELECTRON" --no-sandbox "${args[@]}"
fi
exec "$ELECTRON" "${args[@]}"
