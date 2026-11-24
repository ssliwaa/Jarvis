'use strict';
// JarvisEvents — the SSE client for the hardened /events stream
// (audit fix P5, viewer half).
//
// Server contract (viewer_hardening.py):
//   GET /events?topics=agent/status,teardown,metrics
//   frames: "data: {\"topic\": ..., \"ts\": ..., \"payload\": ...}\n\n"
//   plus "hello" frames (event: hello) and ": heartbeat" comment frames.
//
// Client behaviour:
//   * JarvisEvents.subscribe(topics, handler) fans each frame out to the
//     handlers subscribed to frame.topic (or frame.event for the hello frame).
//   * If EventSource is missing or the stream dies for good, fall back to
//     polling a JSON endpoint (default /mission/status) instead of going dark.
//   * When the tab is hidden the connection is torn down and rebuilt when the
//     tab becomes visible again.
//
// Classic script on purpose; load it with <script defer src="events.js">
// BEFORE the first consumer.
(() => {
  if (typeof window === 'undefined' || window.JarvisEvents) return;

  const DEFAULT_TOPICS = ['agent/status', 'teardown', 'metrics'];
  const EVENTS_URL = '/events';
  const DEFAULT_POLL_URL = '/mission/status';
  const POLL_INTERVAL_MS = 5000;
  const SSE_RETRY_DELAY_MS = 3000;

  const ALLOWED_TOPICS = new Set(DEFAULT_TOPICS);

  const listeners = new Map(); // topic -> Set<handler>
  let source = null;           // active EventSource
  let pollTimer = null;        // active poll loop handle
  let sseRetryTimer = null;
  let mode = 'idle';           // 'idle' | 'sse' | 'poll'
  let active = false;          // at least one live subscription
  let paused = false;          // document hidden
  let wantedTopics = DEFAULT_TOPICS.slice();
  let pollUrl = DEFAULT_POLL_URL;

  function normalizeTopics(input) {
    const raw = Array.isArray(input)
      ? input
      : String(input === undefined || input === null ? '' : input).split(',');
    const names = raw.map((item) => String(item).trim()).filter(Boolean);
    const valid = names.filter((name) => ALLOWED_TOPICS.has(name));
    const unique = [];
    valid.forEach((name) => {
      if (!unique.includes(name)) unique.push(name);
    });
    return unique.length ? unique : DEFAULT_TOPICS.slice();
  }

  function dispatch(frame) {
    const topic = frame && (frame.topic || frame.event);
    if (!topic) return;
    const set = listeners.get(topic);
    if (!set) return;
    set.forEach((handler) => {
      try {
        handler(frame);
      } catch (error) {
        if (window.console && console.error) console.error('[JarvisEvents] handler failed', error);
      }
    });
  }

  function stopSse() {
    if (source) {
      source.close();
      source = null;
    }
    if (sseRetryTimer) {
      clearTimeout(sseRetryTimer);
      sseRetryTimer = null;
    }
  }

  function stopPolling() {
    if (pollTimer) {
      clearTimeout(pollTimer);
      pollTimer = null;
    }
  }

  function startSse() {
    if (!active || paused) return;
    stopSse();
    stopPolling();
    if (typeof EventSource !== 'function') {
      startPolling();
      return;
    }
    try {
      source = new EventSource(`${EVENTS_URL}?topics=${encodeURIComponent(wantedTopics.join(','))}`);
    } catch (error) {
      source = null;
      startPolling();
      return;
    }
    mode = 'sse';
    source.onmessage = (message) => {
      let frame = null;
      try {
        frame = JSON.parse(message.data);
      } catch (error) {
        return; // malformed frame — ignore, the server keeps talking
      }
      dispatch(frame);
    };
    source.onerror = () => {
      // EventSource reconnects on its own for transient hiccups; once it is
      // CLOSED the stream is dead for good and polling takes over.
      if (source && source.readyState === EventSource.CLOSED) {
        stopSse();
        startPolling();
      }
    };
  }

  function pollOnce() {
    fetch(pollUrl, {
      credentials: 'same-origin',
      cache: 'no-store',
      headers: { Accept: 'application/json' },
    })
      .then((response) => (response.ok ? response.json() : null))
      .then((body) => {
        if (!body) return;
        const topic = (body && (body.topic || body.event))
          || wantedTopics[0]
          || DEFAULT_TOPICS[0];
        dispatch({ topic, ts: Date.now() / 1000, payload: body });
      })
      .catch(() => {});
  }

  function startPolling() {
    if (!active || paused) return;
    stopSse();
    stopPolling();
    mode = 'poll';
    const tick = () => {
      pollOnce();
      pollTimer = setTimeout(tick, POLL_INTERVAL_MS);
    };
    tick();
  }

  function onVisibilityChange() {
    if (document.visibilityState === 'hidden') {
      // Hidden tabs do not need live frames; tear the connection down instead
      // of letting a background tab queue traffic.
      paused = true;
      stopSse();
      stopPolling();
      mode = 'idle';
      return;
    }
    paused = false;
    if (!active) return;
    if (mode === 'poll') startPolling();
    else startSse();
  }

  document.addEventListener('visibilitychange', onVisibilityChange);

  function subscribe(topics, handler, options = {}) {
    if (typeof handler !== 'function') {
      throw new TypeError('JarvisEvents.subscribe needs a handler function');
    }
    if (typeof options.pollUrl === 'string' && options.pollUrl) pollUrl = options.pollUrl;
    wantedTopics = normalizeTopics(topics);
    wantedTopics.forEach((topic) => {
      if (!listeners.has(topic)) listeners.set(topic, new Set());
      listeners.get(topic).add(handler);
    });
    active = true;
    if (!paused) startSse();
    return {
      unsubscribe: () => unsubscribe(topics, handler),
    };
  }

  function unsubscribe(topics, handler) {
    normalizeTopics(topics).forEach((topic) => {
      const set = listeners.get(topic);
      if (!set) return;
      set.delete(handler);
      if (!set.size) listeners.delete(topic);
    });
    active = listeners.size > 0;
    if (!active) {
      stopSse();
      stopPolling();
      mode = 'idle';
    }
  }

  window.JarvisEvents = Object.freeze({
    subscribe,
    unsubscribe,
    DEFAULT_TOPICS: DEFAULT_TOPICS.slice(),
    status: () => ({ mode, paused, topics: wantedTopics.slice() }),
  });
})();
