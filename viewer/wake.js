'use strict';

// Opt-in microphone listener. PCM goes only to the loopback wake-word detector;
// it is never saved or sent to the speech provider until the user says the phrase.
window.createJarvisWake = ({ onWake, onError = () => {} }) => {
  let context = null, stream = null, source = null, processor = null;
  let active = false, generation = 0, busy = false, samples = [], phase = 0, queue = [];

  async function stop() {
    active = false;
    generation += 1;
    samples = [];
    queue = [];
    try { if (processor) { processor.onaudioprocess = null; processor.disconnect(); } } catch (_) {}
    try { source?.disconnect(); } catch (_) {}
    try { stream?.getTracks().forEach(track => track.stop()); } catch (_) {}
    const old = context;
    context = stream = source = processor = null;
    if (old) { try { await old.close(); } catch (_) {} }
  }

  async function pump(token) {
    if (busy || !active || token !== generation || !queue.length) return;
    const block = queue.shift();
    busy = true;
    try {
      const response = await fetch('/voice/wake', {
        method: 'POST', headers: { 'Content-Type': 'application/octet-stream' }, body: block.buffer,
      });
      if (!response.ok) throw new Error('Wake-word detector unavailable');
      const result = await response.json();
      if (active && token === generation && result.detected === true) {
        await stop();
        await onWake();
      }
    } catch (_) {
      if (active && token === generation) { await stop(); onError('Wake-word detector unavailable'); }
    } finally {
      busy = false;
      if (active && token === generation) pump(token);
    }
  }

  async function start() {
    if (active) return;
    const token = ++generation;
    const Audio = window.AudioContext || window.webkitAudioContext;
    if (!Audio || !navigator.mediaDevices?.getUserMedia) throw new Error('Microphone unavailable');
    const reset = await fetch('/voice/wake/reset', {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}',
    });
    if (!reset.ok || token !== generation) throw new Error('Wake-word detector unavailable');
    const opened = await navigator.mediaDevices.getUserMedia({
      audio: { echoCancellation: false, noiseSuppression: false, autoGainControl: false },
    });
    if (token !== generation) { opened.getTracks().forEach(track => track.stop()); return; }
    stream = opened;
    try {
      // Ask Chromium's native resampler for 16 kHz. Dropping samples from
      // 48 kHz aliases speech and the wake model misses otherwise clear audio.
      context = new Audio({ sampleRate: 16000 });
      if (context.sampleRate !== 16000) throw new Error('Unsupported microphone sample rate');
      source = context.createMediaStreamSource(stream);
      processor = context.createScriptProcessor(4096, 1, 1);
      source.connect(processor);
      processor.connect(context.destination);
      active = true;
      phase = 0;
      samples = [];
      processor.onaudioprocess = event => {
        if (!active || token !== generation) return;
        const input = event.inputBuffer.getChannelData(0);
        for (const sample of input) {
          phase += 16000;
          if (phase >= context.sampleRate) {
            phase -= context.sampleRate;
            samples.push(Math.max(-32768, Math.min(32767, Math.round(sample * 32767))));
          }
          if (samples.length === 10240) {
            const block = new Int16Array(samples);
            samples = [];
            if (queue.length >= 25) {
              stop();
              onError('Wake-word detector is too slow; listening stopped');
              return;
            }
            queue.push(block);
            pump(token);
          }
        }
      };
    } catch (error) { await stop(); throw error; }
  }

  return { start, stop, get active() { return active; } };
};
