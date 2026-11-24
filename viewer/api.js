'use strict';
// JarvisAPI — the shared fetch wrapper for the viewer (audit fix P7).
//
// One place for everything the scattered fetch() calls used to get wrong:
// a request timeout via AbortController, bounded retries with backoff for
// transient failures (network errors, timeouts, 5xx) and a single error type
// (JarvisApiError) that always carries status/code so callers can show one
// message format.
//
// Classic script on purpose (fala #1 stays off ES modules): load it with
// <script defer src="api.js"></script> BEFORE the first consumer
// (voice.js / wake.js / app.js / studio.js / mission.js).
(() => {
  if (typeof window === 'undefined' || window.JarvisAPI) return;

  const DEFAULT_TIMEOUT_MS = 15000;
  const MAX_RETRIES = 2;
  const RETRY_BASE_MS = 500;

  class JarvisApiError extends Error {
    constructor(message, options = {}) {
      super(message);
      this.name = 'JarvisApiError';
      this.status = typeof options.status === 'number' ? options.status : null;
      this.code = options.code || (this.status ? `HTTP_${this.status}` : 'NETWORK');
      this.detail = options.detail === undefined ? null : options.detail;
    }
  }

  function sleep(ms) {
    return new Promise((resolve) => { setTimeout(resolve, ms); });
  }

  // Only transient failures are worth another attempt: everything that never
  // reached the server, plus real server-side trouble. A 4xx answer means the
  // caller itself is wrong and retrying would just repeat it.
  function isRetryable(error) {
    if (!(error instanceof JarvisApiError)) return false;
    if (error.status === null) return true;
    return error.status >= 500;
  }

  // attempt starts at 1: 0.5s, then ~1s, capped by MAX_RETRIES in request().
  function backoffMs(attempt) {
    const jitter = Math.floor(Math.random() * Math.min(250, RETRY_BASE_MS));
    return RETRY_BASE_MS * Math.pow(2, attempt - 1) + jitter;
  }

  function retryBudget(options) {
    const raw = typeof options.retries === 'number' ? options.retries : MAX_RETRIES;
    return Math.max(0, Math.min(MAX_RETRIES, Math.floor(raw)));
  }

  function timeoutBudget(options) {
    const raw = typeof options.timeoutMs === 'number' ? options.timeoutMs : DEFAULT_TIMEOUT_MS;
    return Math.max(1, raw);
  }

  async function attemptOnce(path, options, timeoutMs) {
    const controller = typeof AbortController === 'function' ? new AbortController() : null;
    const timer = controller
      ? setTimeout(() => controller.abort('timeout'), timeoutMs)
      : null;
    let response = null;
    try {
      response = await fetch(path, {
        method: options.method || 'GET',
        credentials: 'same-origin',
        cache: 'no-store',
        headers: { Accept: 'application/json', ...(options.headers || {}) },
        body: options.body,
        signal: controller ? controller.signal : undefined,
      });
      const contentType = response.headers.get('content-type') || '';
      if (contentType.indexOf('json') === -1) {
        const detail = await response.text().catch(() => '');
        throw new JarvisApiError(
          `The local service returned non-JSON content (${response.status}).`,
          { status: response.status, code: 'BAD_CONTENT', detail: detail.slice(0, 200) },
        );
      }
      let body = null;
      try {
        body = JSON.parse(await response.text());
      } catch (error) {
        throw new JarvisApiError('The local service returned unreadable JSON.', {
          status: response.status,
          code: 'BAD_JSON',
          detail: error,
        });
      }
      if (!response.ok || (body && body.error)) {
        const serverError = body && body.error;
        const message = (serverError && (serverError.message || serverError.answer))
          || (body && body.answer)
          || `Request failed (${response.status}).`;
        throw new JarvisApiError(message, {
          status: response.status,
          code: (serverError && serverError.code) || undefined,
          detail: serverError,
        });
      }
      return body;
    } catch (error) {
      if (error instanceof JarvisApiError) throw error;
      if (error && error.name === 'AbortError') {
        throw new JarvisApiError(
          `Request timed out after ${timeoutMs} ms: ${path}`,
          { code: 'TIMEOUT', detail: error },
        );
      }
      throw new JarvisApiError(
        `Network request to ${path} failed before the server answered: ${error && error.message}`,
        { code: 'NETWORK', detail: error },
      );
    } finally {
      if (timer !== null) clearTimeout(timer);
    }
  }

  async function request(path, options = {}) {
    const retries = retryBudget(options);
    const timeoutMs = timeoutBudget(options);
    let lastError = null;
    for (let attempt = 0; attempt <= retries; attempt += 1) {
      if (attempt > 0) await sleep(backoffMs(attempt));
      try {
        return await attemptOnce(path, options, timeoutMs);
      } catch (error) {
        lastError = error;
        if (!isRetryable(error)) throw error;
      }
    }
    throw lastError;
  }

  function get(path, options = {}) {
    return request(path, { ...options, method: 'GET' });
  }

  function post(path, payload, options = {}) {
    return request(path, {
      ...options,
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...(options.headers || {}) },
      body: JSON.stringify(payload === undefined ? {} : payload),
    });
  }

  window.JarvisAPI = Object.freeze({
    request,
    get,
    post,
    ApiError: JarvisApiError,
  });
})();
