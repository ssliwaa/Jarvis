"""Local wake-word inference only; audio is never stored or sent to a provider."""
from __future__ import annotations

import hashlib
import importlib.util
import threading
from pathlib import Path

MODEL_ROOT = Path.home() / '.jarvis-tools' / 'wakeword' / 'models'
MODEL_HASHES = {
    'melspectrogram.onnx': 'ba2b0e0f8b7b875369a2c89cb13360ff53bac436f2895cced9f479fa65eb176f',
    'embedding_model.onnx': '70d164290c1d095d1d4ee149bc5e00543250a7316b59f31d056cff7bd3075c1f',
    'hey_jarvis_v0.1.onnx': '94a13cfe60075b132f6a472e7e462e8123ee70861bc3fb58434a73712ee0d2cb',
}


def available():
    return bool(importlib.util.find_spec('openwakeword') and
                all((MODEL_ROOT / name).is_file() for name in MODEL_HASHES))


def _load():
    for name, expected in MODEL_HASHES.items():
        path = MODEL_ROOT / name
        if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise ValueError('Wake-word model checksum mismatch')
    from openwakeword.model import Model
    return Model(wakeword_models=[str(MODEL_ROOT / 'hey_jarvis_v0.1.onnx')],
                 inference_framework='onnx', ncpu=1,
                 melspec_model_path=str(MODEL_ROOT / 'melspectrogram.onnx'),
                 embedding_model_path=str(MODEL_ROOT / 'embedding_model.onnx'))


class Detector:
    def __init__(self, loader=_load):
        self.loader = loader
        self.model = None
        self.lock = threading.Lock()

    def process(self, audio):
        if not isinstance(audio, bytes) or not 2560 <= len(audio) <= 64000 or len(audio) % 2560:
            raise ValueError('Expected 16 kHz mono PCM in 80 ms blocks, up to two seconds')
        import numpy as np
        with self.lock:
            if self.model is None:
                self.model = self.loader()
            samples = np.frombuffer(audio, dtype='<i2')
            detected = False
            for offset in range(0, len(samples), 1280):
                scores = self.model.predict(samples[offset:offset + 1280])
                detected |= float(scores.get('hey_jarvis_v0.1', 0.0)) >= 0.5
            if detected:
                self.model.reset()
            return {'ok': True, 'engine': 'openwakeword', 'detected': detected}

    def reset(self):
        with self.lock:
            if self.model is not None:
                self.model.reset()


detector = Detector()
