#!/usr/bin/env python3
"""
AI Authenticator — CNN-LSTM Hardware Fingerprint Engine
=========================================================
Loads the trained device_authenticator.h5 model and uses it to
distinguish real ESP32 hardware from software spoofing attacks.

How it works:
  1. Keeps a per-device rolling buffer of the last SEQ=10 heartbeats.
  2. Once the buffer is full, runs a CNN-LSTM prediction.
  3. Returns (is_legitimate, confidence) so iot_server can penalise spoofers.

Designed to run as a side-car to score_heartbeat() — the rule-based
scorer handles fast decisions, the AI model catches sophisticated spoofing.
"""

import collections
import os
import pickle
import threading
from typing import Optional, Tuple

import numpy as np

# ── Config ──────────────────────────────────────────────────────────────
_BASE    = os.path.dirname(os.path.abspath(__file__))
_ROOT    = os.path.dirname(_BASE)
MODEL_H5   = os.environ.get("MODEL_PATH",
           os.path.join(_ROOT, "ml_models", "device_authenticator.h5"))
MODEL_PKL  = os.environ.get("MODEL_PKL_PATH",
             os.path.join(_ROOT, "ml_models", "device_authenticator.pkl"))
SCALER_PKL = os.environ.get("SCALER_PATH",
             os.path.join(_ROOT, "ml_models", "scaler.pkl"))

SEQ   = 10          # Sequence length expected by the LSTM
FEATS = ["rssi", "packet_size", "free_heap",
         "inter_packet_delay", "temperature", "humidity"]

# Spoof threshold — if model output < this, device is flagged
SPOOF_THRESHOLD = float(os.environ.get("AI_SPOOF_THRESHOLD", "0.45"))

# Module-level singletons ──────────────────────────────────────────────
_lock   = threading.Lock()
_model  = None
_scaler = None
_ready  = False
_backend = None   # "keras" or "sklearn"

# Per-device rolling buffers: {device_id: deque([feature_vector, ...])}
_buffers: dict = {}


def _load_model() -> bool:
    """Attempt to load the model and sklearn scaler. Supports Keras h5 and sklearn pkl. Thread-safe."""
    global _model, _scaler, _ready, _backend

    if _ready:
        return True

    with _lock:
        if _ready:          # double-check after lock
            return True

        if not os.path.exists(SCALER_PKL):
            print(f"[AI_AUTH] ⚠️  Scaler not found at {SCALER_PKL} — "
                  "cannot normalise features.")
            return False

        try:
            with open(SCALER_PKL, "rb") as f:
                _scaler = pickle.load(f)
        except Exception as exc:
            print(f"[AI_AUTH] ❌ Failed to load scaler: {exc}")
            return False

        # Try Keras h5 first
        if os.path.exists(MODEL_H5):
            try:
                os.environ.setdefault("TF_CPP_MIN_LOG_LEVEL", "3")
                from tensorflow.keras.models import load_model  # type: ignore
                _model = load_model(MODEL_H5, compile=False)
                _backend = "keras"
                _ready = True
                print(f"[AI_AUTH] ✅ Keras CNN-LSTM model loaded — "
                      f"real-time hardware fingerprinting ACTIVE")
                return True
            except Exception as exc:
                print(f"[AI_AUTH] Keras load failed ({exc}), trying sklearn fallback...")

        # Try sklearn pkl fallback
        if os.path.exists(MODEL_PKL):
            try:
                with open(MODEL_PKL, "rb") as f:
                    _model = pickle.load(f)
                _backend = "sklearn"
                _ready = True
                print(f"[AI_AUTH] ✅ sklearn RandomForest model loaded — "
                      f"hardware fingerprinting ACTIVE (fallback mode)")
                return True
            except Exception as exc:
                print(f"[AI_AUTH] ❌ Failed to load sklearn model: {exc}")
                return False

        print(f"[AI_AUTH] ⚠️  No model found at {MODEL_H5} or {MODEL_PKL} — "
              "falling back to rule-based scoring only.\n"
              "Run: python3 ml_models/train_model.py")
        return False


def _extract_features(data: dict) -> Optional[list]:
    """Extract the 6 feature values from a heartbeat payload."""
    try:
        return [
            float(data.get("rssi")              or -100),
            float(data.get("packet_size")       or 0),
            float(data.get("free_heap")         or 0),
            float(data.get("inter_packet_delay") or 0),
            float(data.get("temperature")       or 25.0),
            float(data.get("humidity")          or 50.0),
        ]
    except (TypeError, ValueError):
        return None


def predict_legitimacy(
    device_id: str,
    data: dict,
) -> Optional[Tuple[bool, float, int]]:
    """
    Buffer a heartbeat sample and run CNN-LSTM prediction when ready.

    Returns:
        None  — if the buffer has fewer than SEQ samples (warming up).
        (is_legitimate, confidence, buffer_size) — when a prediction is made.
            is_legitimate: True  → device looks like real hardware.
                           False → timing fingerprint matches a spoof.
            confidence:    float 0-1 (raw model sigmoid output).
            buffer_size:   how many samples are in the buffer.
    """
    # Ensure model is loaded (lazy, first call)
    if not _load_model():
        return None

    feats = _extract_features(data)
    if feats is None:
        return None

    # Per-device rolling buffer
    if device_id not in _buffers:
        _buffers[device_id] = collections.deque(maxlen=SEQ)
    buf = _buffers[device_id]
    buf.append(feats)

    if len(buf) < SEQ:
        # Not enough data yet — warming up
        return None

    try:
        # Build (1, SEQ, 6) array and normalise
        X = np.array(list(buf), dtype=np.float32)         # (SEQ, 6)
        X_flat = _scaler.transform(X)                     # normalise
        X_seq  = X_flat.reshape(1, SEQ, len(FEATS))       # (1, SEQ, 6)

        if _backend == "keras":
            prob = float(_model.predict(X_seq, verbose=0)[0][0])  # sigmoid output
        else:
            # sklearn expects (n_samples, SEQ*n_feats)
            X_flat_skl = X_seq.reshape(1, SEQ * len(FEATS))
            prob = float(_model.predict_proba(X_flat_skl)[0][1])  # P(legit)

        is_legit = prob >= SPOOF_THRESHOLD

        if not is_legit:
            print(f"[AI_AUTH] 🚨 SPOOF DETECTED | {device_id} | "
                  f"confidence={prob:.3f} (threshold={SPOOF_THRESHOLD})")
        else:
            print(f"[AI_AUTH] ✅ LEGITIMATE   | {device_id} | "
                  f"confidence={prob:.3f}")

        return is_legit, prob, len(buf)

    except Exception as exc:
        print(f"[AI_AUTH] Prediction error: {exc}")
        return None


def reset_device_buffer(device_id: str) -> None:
    """Clear a device's rolling buffer (call on reconnect/boot)."""
    if device_id in _buffers:
        _buffers[device_id].clear()


def get_buffer_status() -> dict:
    """Return buffer fill levels for all devices (used by dashboard/debug)."""
    return {dev: len(buf) for dev, buf in _buffers.items()}


# Pre-load on import so the first heartbeat doesn't pay the load cost
_load_model()
