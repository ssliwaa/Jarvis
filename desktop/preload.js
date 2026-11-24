'use strict';
// Minimal, read-only bridge for the system-wide talk key. The page can only
// subscribe to one event; no Node APIs, paths or IPC channels are exposed.

const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('jarvisDesktop', {
  onPushToTalk(callback) {
    if (typeof callback !== 'function') return () => {};
    const handler = () => callback();
    ipcRenderer.on('jarvis:push-to-talk', handler);
    return () => ipcRenderer.removeListener('jarvis:push-to-talk', handler);
  },
  onDictate(callback) {
    if (typeof callback !== 'function') return () => {};
    const handler = () => callback();
    ipcRenderer.on('jarvis:dictate', handler);
    return () => ipcRenderer.removeListener('jarvis:dictate', handler);
  },
});
