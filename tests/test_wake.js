'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');

(async () => {
  let opened = 0, stopped = 0, processor = null, requests = 0, resets = 0, detects = false, wakes = 0;
  const stream = { getTracks: () => [{ stop() { stopped++; } }] };
  class AudioContext {
    constructor(options) { assert.equal(options.sampleRate, 16000); this.sampleRate = 16000; this.destination = {}; }
    createMediaStreamSource() { return { connect() {}, disconnect() {} }; }
    createScriptProcessor() {
      processor = { connect() {}, disconnect() {}, onaudioprocess: null };
      return processor;
    }
    async close() {}
  }
  const context = { console, AudioContext, navigator: { mediaDevices: { async getUserMedia() { opened++; return stream; } } },
    fetch: async (url, opts) => {
      if (url === '/voice/wake/reset') { resets++; return { ok: true }; }
      requests++; assert.equal(opts.body.byteLength, 20480); return { ok: true, json: async () => ({ detected: detects }) };
    },
    Int16Array, Math };
  context.window = context;
  vm.createContext(context);
  vm.runInContext(fs.readFileSync(path.join(__dirname, '../viewer/wake.js'), 'utf8'), context);
  const wake = context.createJarvisWake({ onWake() { wakes++; } });
  assert.equal(opened, 0, 'microphone must stay off before explicit start');
  await wake.start();
  assert.equal(opened, 1);
  assert.equal(resets, 1, 'a new session clears old model audio');
  processor.onaudioprocess({ inputBuffer: { getChannelData: () => new Float32Array(10240) } });
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(requests, 1);
  await wake.stop();
  assert.equal(stopped, 1, 'stop releases microphone');
  detects = true;
  await wake.start();
  processor.onaudioprocess({ inputBuffer: { getChannelData: () => new Float32Array(10240) } });
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(wakes, 1, 'detection starts exactly one voice turn');
  assert.equal(wake.active, false, 'standby microphone stops before voice turn');
  assert.equal(stopped, 2);
  console.log('wake UI: passed');
})().catch(error => { console.error(error); process.exitCode = 1; });
