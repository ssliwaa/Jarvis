'use strict';
// Jarvis desktop shell: a single local window, no browser chrome.
const { app, BrowserWindow, Menu, dialog, shell, session, globalShortcut } = require('electron');
const { spawn, spawnSync } = require('child_process');
const http = require('http');
const net = require('net');
const path = require('path');
const fs = require('fs');

const HOST = '127.0.0.1';
const PORT = 4700;
const ORIGIN = `http://${HOST}:${PORT}`;
const HEALTH = ORIGIN + '/health';
const INSTANCE_URL = ORIGIN + '/mission/instance';
const RELOAD_URL = ORIGIN + '/mission/reload';
const PROJECT = path.resolve(__dirname, '..');
const PYTHON = path.join(PROJECT, '.venv', 'bin', 'python');
const ICON = path.join(__dirname, 'icon.png');
let serverChild = null;
let mainWindow = null;

app.setName('Jarvis');
app.setPath('userData', path.join(process.env.HOME || PROJECT, '.jarvis-tools', 'desktop-profile'));

function localOrigin(value) {
  try { return new URL(value).origin === ORIGIN; } catch (_) { return false; }
}

function healthy(timeoutMs = 2500) {
  return new Promise(resolve => {
    const request = http.get(HEALTH, { timeout: timeoutMs }, response => {
      response.resume();
      resolve(response.statusCode === 200);
    });
    request.on('error', () => resolve(false));
    request.setTimeout(timeoutMs, () => {
      request.destroy();
      resolve(false);
    });
  });
}

function portInUse(timeoutMs = 700) {
  return new Promise(resolve => {
    const sock = net.createConnection({ host: HOST, port: PORT });
    let done = false;
    const finish = val => {
      if (done) return;
      done = true;
      sock.destroy();
      resolve(val);
    };
    sock.setTimeout(timeoutMs);
    sock.once('connect', () => finish(true));
    sock.once('timeout', () => finish(false));
    sock.once('error', () => finish(false));
  });
}

function fetchInstanceInfo() {
  return new Promise(resolve => {
    const req = http.get(INSTANCE_URL, { timeout: 1800, headers: { Host: `${HOST}:${PORT}` } }, res => {
      let raw = '';
      res.on('data', chunk => { raw += String(chunk || ''); });
      res.on('end', () => {
        if (res.statusCode !== 200) return resolve(null);
        try { resolve(JSON.parse(raw)); } catch (_) { resolve(null); }
      });
    });
    req.on('error', () => resolve(null));
    req.setTimeout(1800, () => {
      req.destroy();
      resolve(null);
    });
  });
}

function postBackendReload() {
  return new Promise(resolve => {
    const req = http.request(RELOAD_URL, {
      method: 'POST',
      timeout: 2200,
      headers: {
        Host: `${HOST}:${PORT}`,
        Origin: ORIGIN,
        'Content-Type': 'application/json',
        'Content-Length': '2',
      },
    }, res => {
      res.resume();
      resolve(res.statusCode === 200);
    });
    req.on('error', () => resolve(false));
    req.setTimeout(2200, () => {
      req.destroy();
      resolve(false);
    });
    req.end('{}');
  });
}

function wait(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

async function waitHealthy(maxMs = 12000) {
  const deadline = Date.now() + maxMs;
  while (Date.now() < deadline) {
    if (await healthy(1800)) return true;
    await wait(350);
  }
  return false;
}

async function reloadRunningBackend(force = false) {
  const info = await fetchInstanceInfo();
  // Reload if forced, if the running server predates `/mission/instance` (`info === null`), or if code on disk is newer (`info.stale`).
  if (!force && info && !info.stale) return false;

  const sysCheck = spawnSync('systemctl', ['--user', 'is-active', '--quiet', 'jarvis.service'], { timeout: 3000 });
  if (sysCheck.status === 0) {
    spawnSync('systemctl', ['--user', 'restart', 'jarvis.service'], { timeout: 10000 });
    await waitHealthy(12000);
    return true;
  }

  if (await postBackendReload()) {
    await wait(450);
    await waitHealthy(12000);
    return true;
  }
  return false;
}

async function ensureServer() {
  if ((await healthy()) || (await portInUse())) {
    await reloadRunningBackend(false);
    if (await waitHealthy(10000)) return false;
  }
  if (!fs.existsSync(PYTHON)) {
    throw new Error('The Python virtual environment is missing at ' + PYTHON);
  }
  serverChild = spawn(PYTHON, ['-u', 'server.py'], {
    cwd: PROJECT,
    stdio: ['ignore', 'ignore', 'pipe'],
    detached: false,
  });
  let exited = null;
  let spawnError = null;
  let stderrTail = '';
  if (serverChild.stderr) {
    serverChild.stderr.on('data', chunk => {
      stderrTail = (stderrTail + String(chunk || '')).slice(-1500);
    });
  }
  // An unhandled 'error' event from spawn (ENOENT/EACCES) used to crash the
  // Electron main process before the readiness loop could report anything.
  serverChild.once('error', error => { spawnError = error; });
  serverChild.once('exit', code => { exited = code; });
  for (let attempt = 0; attempt < 40; attempt += 1) {
    await wait(500);
    if (await healthy()) return true;
    if (spawnError) throw new Error('Jarvis server could not start: ' + spawnError.message);
    if (exited !== null) {
      // If `server.py` attached/reloaded an existing daemon cleanly (`code 0`) or collided with `jarvis.service` (`Errno 98`), attach to the live port.
      if ((exited === 0 || stderrTail.includes('Address already in use')) && (await waitHealthy(8000))) {
        serverChild = null;
        return false;
      }
      const detail = stderrTail.trim() ? '\n\n' + stderrTail.trim() : '';
      throw new Error('Jarvis server exited with code ' + exited + '.' + detail);
    }
  }
  throw new Error('Jarvis did not become ready on http://127.0.0.1:4700.');
}

function stopServer() {
  if (!serverChild) return;
  try { serverChild.kill('SIGTERM'); } catch (_) { /* already gone */ }
  serverChild = null;
}

function reloadWindow(ignoreCache = false) {
  if (!mainWindow || mainWindow.isDestroyed()) return;
  if (ignoreCache) mainWindow.webContents.reloadIgnoringCache();
  else mainWindow.webContents.reload();
}

// Tap once to start recording, tap again to send. Keeping the window hidden
// still works because backgroundThrottling is off for this renderer.
function toggleVoice() {
  if (!mainWindow || mainWindow.isDestroyed()) return;
  mainWindow.webContents.send('jarvis:push-to-talk');
}

function toggleDictate() {
  if (!mainWindow || mainWindow.isDestroyed()) return;
  mainWindow.webContents.send('jarvis:dictate');
}

// Microphone access is granted only to the local console. Without an explicit
// handler Electron can refuse `getUserMedia`, and the offline transcriber never
// gets a stream even though the OS already allowed the app.
// Default-deny: the viewer only records audio, requests notification
// permission and writes text to the clipboard. Everything else (geolocation,
// HID/serial/USB, MIDI, screen capture, fullscreen...) stays refused.
const ALLOWED_PERMISSIONS = new Set(['media', 'notifications', 'clipboard-sanitized-write']);

function grantLocalMedia() {
  const ses = session.defaultSession;
  ses.setPermissionRequestHandler((webContents, permission, callback, details) => {
    const requester = details?.requestingUrl || webContents?.getURL() || '';
    if (!ALLOWED_PERMISSIONS.has(permission) || !localOrigin(requester)) return callback(false);
    if (permission !== 'media') return callback(true);
    const types = details?.mediaTypes || [];
    const audioOnly = types.length === 0 || types.every(type => type === 'audio');
    return callback(audioOnly);
  });
  ses.setPermissionCheckHandler((webContents, permission, requestingOrigin, details) => {
    if (!ALLOWED_PERMISSIONS.has(permission)) return false;
    return localOrigin(requestingOrigin || details?.requestingUrl || webContents?.getURL() || '');
  });
  ses.setDevicePermissionHandler(() => false);
}

// One policy for every webContents, not just the first window: redirects,
// subframes and any future popup must not escape the local origin.
function secureContents(contents) {
  contents.setWindowOpenHandler(({ url }) => {
    if (/^https?:\/\//i.test(url) && !localOrigin(url)) shell.openExternal(url);
    return { action: 'deny' };
  });
  const guard = (details, url) => {
    const target = String(details?.url || url || '');
    if (!localOrigin(target) && !target.startsWith('devtools://')) {
      if (typeof details?.preventDefault === 'function') details.preventDefault();
    }
  };
  contents.on('will-navigate', guard);
  contents.on('will-redirect', guard);
  contents.on('will-frame-navigate', details => {
    const target = String(details?.url || '');
    if (!localOrigin(target) && !target.startsWith('devtools://')) details.preventDefault();
  });
  contents.on('will-attach-webview', event => event.preventDefault());
}

function createWindow() {
  const statePath = path.join(app.getPath('userData'), 'window-state.json');
  let saved = {};
  try {
    saved = JSON.parse(fs.readFileSync(statePath, 'utf8'));
  } catch (_) {
    saved = {};
  }
  const bounds = {
    width: Number.isFinite(saved.width) ? Math.max(1024, saved.width) : 1440,
    height: Number.isFinite(saved.height) ? Math.max(700, saved.height) : 900,
  };
  if (Number.isFinite(saved.x) && Number.isFinite(saved.y)) {
    bounds.x = saved.x;
    bounds.y = saved.y;
  }
  mainWindow = new BrowserWindow({
    ...bounds,
    minWidth: 1024,
    minHeight: 700,
    backgroundColor: '#05090d',
    title: 'Jarvis',
    icon: ICON,
    autoHideMenuBar: true,
    show: false,
    webPreferences: {
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      preload: path.join(__dirname, 'preload.js'),
      backgroundThrottling: false,
    },
  });
  mainWindow.setMenuBarVisibility(false);
  mainWindow.once('ready-to-show', () => {
    if (saved.maximized) mainWindow.maximize();
    mainWindow.show();
  });
  let saveStateTimer = null;
  const saveState = () => {
    if (saveStateTimer !== null) {
      clearTimeout(saveStateTimer);
      saveStateTimer = null;
    }
    if (!mainWindow || mainWindow.isDestroyed()) return;
    const value = mainWindow.isMaximized() ? { ...mainWindow.getNormalBounds(), maximized: true }
      : { ...mainWindow.getBounds(), maximized: false };
    try { fs.writeFileSync(statePath, JSON.stringify(value)); } catch (_) { /* profile may be read-only */ }
  };
  const scheduleSaveState = () => {
    if (saveStateTimer !== null) clearTimeout(saveStateTimer);
    saveStateTimer = setTimeout(saveState, 250);
  };
  mainWindow.on('resize', scheduleSaveState);
  mainWindow.on('move', scheduleSaveState);
  mainWindow.on('close', () => {
    saveState();
    if (serverChild) {
      try { serverChild.kill('SIGTERM'); } catch (_) { /* already gone */ }
    }
  });
  mainWindow.on('closed', () => { mainWindow = null; });

  mainWindow.webContents.on('before-input-event', (event, input) => {
    if (input.type !== 'keyDown') return;
    if (input.key === 'F5' || ((input.control || input.meta) && input.key.toLowerCase() === 'r')) {
      event.preventDefault();
      const hard = Boolean(input.shift);
      if (hard) {
        reloadRunningBackend(false).finally(() => reloadWindow(true));
      } else {
        reloadWindow(false);
      }
    }
  });
  mainWindow.webContents.on('did-fail-load', (_event, code, description) => {
    if (mainWindow && !mainWindow.isDestroyed()) {
      dialog.showErrorBox('Jarvis could not load', description || ('HTTP ' + code));
    }
  });

  return mainWindow.loadURL(ORIGIN + '/');
}

const lock = app.requestSingleInstanceLock();
if (!lock) {
  app.quit();
} else {
  app.on('second-instance', async () => {
    if (!mainWindow) return;
    if (mainWindow.isMinimized()) mainWindow.restore();
    mainWindow.show();
    mainWindow.focus();
    await reloadRunningBackend(false);
    reloadWindow(true);
  });

  app.on('web-contents-created', (_event, contents) => secureContents(contents));

  app.whenReady().then(async () => {
    Menu.setApplicationMenu(null);
    grantLocalMedia();
    try {
      await ensureServer();
      await createWindow();
      // System-wide talk key: tap to start, tap again to stop/send. Ctrl+Shift+Space
      // avoids the IME and editor collision of plain Ctrl+Space. If another
      // application owns it, the in-page Ctrl+Space still works.
      if (!globalShortcut.register('Control+Shift+Space', toggleVoice)) {
        console.warn('Jarvis: Ctrl+Shift+Space is owned by another application; in-page Ctrl+Space still works.');
      }
      if (!globalShortcut.register('Control+Alt+D', toggleDictate)) {
        console.warn('Jarvis: Ctrl+Alt+D is owned by another application; in-page Ctrl+Alt+D still works.');
      }
    } catch (error) {
      dialog.showErrorBox('Jarvis could not start', error.message || String(error));
      stopServer();
      app.quit();
    }
  });

  app.on('window-all-closed', () => {
    stopServer();
    app.quit();
  });
  app.on('before-quit', () => {
    globalShortcut.unregisterAll();
    stopServer();
  });
}
