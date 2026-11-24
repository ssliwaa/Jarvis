"""Lazy local embeddings with idle unload.

A small multilingual model turns text into vectors for semantic recall. It is
not a service: it loads on the first query, stays in RAM while the Jarvis
process works, and a watchdog drops it after ``JARVIS_EMBEDDING_IDLE`` seconds
of silence (default 300). ``JARVIS_EMBEDDINGS=off`` removes the lane entirely.

The model is a static embedding table (potion-multilingual-128M): on this CPU a
query costs single-digit milliseconds, so the unload window is about memory,
not speed.
"""
from __future__ import annotations

import os
import threading
import time

DEFAULT_MODEL = "minishlab/potion-multilingual-128M"
DEFAULT_IDLE = 300
WATCH_INTERVAL = 15


def _flag(name, default):
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() not in {"0", "off", "false", "no"}


def _trim_memory():
    try:
        import ctypes
        ctypes.CDLL('libc.so.6').malloc_trim(0)
    except Exception:
        pass


class Embeddings:
    def __init__(self, model_name=None, idle_seconds=None, loader=None):
        self.model_name = model_name or os.environ.get("JARVIS_EMBEDDING_MODEL") or DEFAULT_MODEL
        self._loader = loader
        try:
            self.idle_seconds = int(idle_seconds if idle_seconds is not None
                                    else os.environ.get("JARVIS_EMBEDDING_IDLE", DEFAULT_IDLE))
        except (TypeError, ValueError):
            self.idle_seconds = DEFAULT_IDLE
        self.idle_seconds = max(30, self.idle_seconds)
        # Check often enough that a short idle window is honoured promptly,
        # without waking up every second for the default five minutes.
        self.interval = max(5, min(WATCH_INTERVAL, self.idle_seconds // 4))
        self._model = None
        self._lock = threading.Lock()
        self._last_used = 0.0
        self.loads = 0
        self.unloads = 0
        self.embedded = 0
        self._closed = threading.Event()
        self._watchdog = threading.Thread(target=self._watch, name="jarvis-embeddings", daemon=True)
        self._watchdog.start()

    # -- capability ----------------------------------------------------
    @staticmethod
    def enabled() -> bool:
        return _flag("JARVIS_EMBEDDINGS", True)

    @staticmethod
    def available() -> bool:
        try:
            import fastembed  # noqa: F401
            return True
        except Exception:
            return False

    @staticmethod
    def ready() -> bool:
        return Embeddings.enabled() and Embeddings.available()

    # -- lifecycle -----------------------------------------------------
    def _watch(self):
        while not self._closed.wait(self.interval):
            try:
                self._maybe_unload()
            except Exception:
                pass

    def _maybe_unload(self):
        with self._lock:
            if self._model is None:
                return
            if self._last_used and time.time() - self._last_used < self.idle_seconds:
                return
            self._model = None
            self.unloads += 1

    def _load(self):
        with self._lock:
            if self._model is None:
                if self._loader is not None:
                    self._model = self._loader(self.model_name)
                else:
                    from fastembed import TextEmbedding
                    self._model = TextEmbedding(self.model_name)
                self.loads += 1
            self._last_used = time.time()
            return self._model

    def unload(self) -> bool:
        with self._lock:
            if self._model is None:
                return False
            self._model = None
            self.unloads += 1
        _trim_memory()
        return True

    def close(self):
        self._closed.set()
        self.unload()

    # -- inference -----------------------------------------------------
    def embed(self, texts):
        items = [str(text or "") for text in texts]
        if not items:
            return []
        model = self._load()
        vectors = [vector for vector in model.embed(items)]
        with self._lock:
            self._last_used = time.time()
            self.embedded += len(vectors)
        return vectors

    def embed_query(self, text):
        vectors = self.embed([text])
        return vectors[0] if vectors else None

    def status(self):
        with self._lock:
            loaded = self._model is not None
            idle = round(time.time() - self._last_used, 1) if self._last_used else None
        return {"enabled": self.enabled(), "available": self.available(), "loaded": loaded,
                "model": self.model_name, "idle_seconds": self.idle_seconds,
                "idle_for": idle, "loads": self.loads, "unloads": self.unloads,
                "embedded_texts": self.embedded}


_EMBEDDER = None
_EMBEDDER_LOCK = threading.Lock()


def default_embedder() -> Embeddings:
    global _EMBEDDER
    with _EMBEDDER_LOCK:
        if _EMBEDDER is None:
            _EMBEDDER = Embeddings()
        return _EMBEDDER
