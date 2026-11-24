# Jarvis desktop shell

This is the standalone desktop window for the local Jarvis server. It uses
Electron instead of a normal browser tab: no address bar, no tab strip, a
dedicated taskbar entry and the Jarvis icon.

## Launch

From the desktop:

- double-click `Jarvis` on the Desktop; or
- open the application menu and choose **Jarvis**; or
- run:

    ./desktop/jarvis-app.sh

The UI is served live from the local server, so a viewer update does not require rebuilding Electron. Press `F5` or `Ctrl+R` to reload; `Ctrl+Shift+R` bypasses the cache. Launching the desktop icon again focuses the existing window and hard-reloads it.

The shell checks `http://127.0.0.1:4700/health`. If the server is not running,
it starts `.venv/bin/python -u server.py`, waits for readiness, opens the
window, and stops that server when the window closes. If Jarvis was already
running, the shell attaches to it and leaves it running.

## Global talk key

While the app is running, `Ctrl+Shift+Space` toggles a recording from any
application: tap once to start, tap again to stop and send. The window may stay
behind another app; `backgroundThrottling` is disabled for the renderer, and a
global shortcut counts as a real user gesture for speech. If another
application already owns the combination, the in-page `Ctrl+Space`
push-to-talk still works.

## Install / repair

The Electron binary is pinned in `desktop/package.json` (`45.0.0`):

    cd desktop
    npm install

The launcher uses `desktop/node_modules/electron/dist/electron` and keeps the
Chromium sandbox enabled. If the SUID helper is not setuid-root and AppArmor
blocks unprivileged user namespaces, the launcher prints a warning and uses
the documented local exception; `JARVIS_ELECTRON_NO_SANDBOX=1` forces that
exception explicitly. Do not expose the server port.

## Files

- `main.js` — single-instance window, server lifecycle, local-origin policy, global talk key.
- `preload.js` — the single IPC bridge that delivers the talk-key event to the page.
- `jarvis-app.sh` — launcher used by the `.desktop` file.
- `Jarvis.desktop` — desktop/menu entry.
- `icon.svg` / `icon.png` — Jarvis orbit icon.

The Electron profile is `~/.jarvis-tools/desktop-profile`, separate from the
Operator Chromium profile and the REA profiles.
