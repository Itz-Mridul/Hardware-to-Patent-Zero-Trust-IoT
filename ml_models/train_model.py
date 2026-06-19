#!/usr/bin/env python3
"""
CNN-LSTM Hardware Fingerprint Trainer
======================================
Trains a model on heartbeat timing data to distinguish
real ESP32 hardware from software attackers / FPGA clones.

Supports two backends:
  1. TensorFlow/Keras CNN-LSTM  — preferred, produces device_authenticator.h5
  2. scikit-learn RandomForest   — fallback (no TF required), saves as .pkl
     ai_authenticator.py detects which format is present automatically.

Inputs:
    ml_models/training_data.db   (from collect_training_data.py + merge)

Outputs:
    ml_models/device_authenticator.h5   OR   ml_models/device_authenticator.pkl
    ml_models/scaler.pkl

Usage:
    python3 ml_models/train_model.py                  # auto-select backend
    SYNTHETIC_ONLY=true python3 ml_models/train_model.py
    BACKEND=sklearn python3 ml_models/train_model.py  # force sklearn
"""

import os
import pickle
import sqlite3
import sys

import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

# ── Config ────────────────────────────────────────────────────────────────────

BASE_DIR   = os.path.dirname(os.path.abspath(__file__))
DB         = os.environ.get("TRAINING_DB_PATH",
                             os.path.join(BASE_DIR, "training_data.db"))
MODEL_H5   = os.environ.get("MODEL_PATH",
                             os.path.join(BASE_DIR, "device_authenticator.h5"))
MODEL_PKL  = os.path.join(BASE_DIR, "device_authenticator.pkl")
SCALER_PKL = os.environ.get("SCALER_PATH",
                             os.path.join(BASE_DIR, "scaler.pkl"))

SEQ   = 10       # Sequence length fed to LSTM
FEATS = ["rssi", "packet_size", "free_heap",
         "inter_packet_delay", "temperature", "humidity"]

SYNTHETIC_ONLY = os.environ.get("SYNTHETIC_ONLY", "false").lower() == "true"
BACKEND        = os.environ.get("BACKEND", "auto").lower()   # "auto", "keras", "sklearn"


# ── Data loading ──────────────────────────────────────────────────────────────

def load_from_db():
    """Load heartbeat data from training_data.db. Returns (X_raw, y_raw) or None."""
    if not os.path.exists(DB):
        print(f"[TRAIN] Training DB not found at {DB}")
        return None
    try:
        conn = sqlite3.connect(DB)
        cursor = conn.cursor()
        cursor.execute(
            "SELECT rssi, packet_size, free_heap, inter_packet_delay, "
            "temperature, humidity, is_legitimate "
            "FROM heartbeats WHERE inter_packet_delay > 0 "
            "ORDER BY received_at"
        )
        rows = cursor.fetchall()
        conn.close()
        if len(rows) < SEQ + 10:
            print(f"[TRAIN] Only {len(rows)} samples — need >{SEQ+10}. Using synthetic data.")
            return None
        data = np.array(rows, dtype=np.float32)
        X_raw, y_raw = data[:, :len(FEATS)], data[:, -1]
        print(f"[TRAIN] Loaded {len(rows)} real samples "
              f"({int(y_raw.sum())} legit, {int((1-y_raw).sum())} spoof)")
        return X_raw, y_raw
    except Exception as exc:
        print(f"[TRAIN] DB read error: {exc}")
        return None


def generate_synthetic_data(n_legit=700, n_spoof=500):
    """Generate realistic synthetic ESP32 vs spoof heartbeat data."""
    rng = np.random.RandomState(42)

    def legit_rows(n):
        rows = []
        heap = 280000
        base_temp = 22.0 + rng.uniform(0, 5)
        for i in range(n):
            heap = max(150000, heap - rng.randint(0, 1500))
            if rng.random() < 0.02:
                heap = 280000
            rows.append([
                rng.uniform(-75, -50),                          # rssi
                rng.randint(200, 350),                          # packet_size
                heap,                                           # free_heap
                5000 + rng.normal(0, 150),                      # IPD with jitter
                base_temp + (i / n) * 3 + rng.normal(0, 0.3), # temp rises
                45 + rng.normal(0, 2),                          # humidity
                1,                                              # is_legitimate
            ])
        return rows

    def spoof_rows(n):
        fixed_rssi = rng.choice([-60, -65, -70])
        rows = []
        for _ in range(n):
            rows.append([
                fixed_rssi,
                rng.randint(255, 257),
                rng.randint(199990, 200010),
                5000 + rng.normal(0, 5),    # too-perfect IPD
                25.0 + rng.normal(0, 0.01),  # constant temp
                50.0 + rng.normal(0, 0.01),  # constant humidity
                0,
            ])
        return rows

    all_rows = []
    for _ in range(3):
        all_rows.extend(legit_rows(n_legit // 3))
    for _ in range(2):
        all_rows.extend(spoof_rows(n_spoof // 2))

    data = np.array(all_rows, dtype=np.float32)
    rng.shuffle(data)
    print(f"[TRAIN] Generated {len(data)} synthetic samples "
          f"({int(data[:,-1].sum())} legit, {int((1-data[:,-1]).sum())} spoof)")
    return data[:, :len(FEATS)], data[:, -1]


def make_sequences(X_raw, y_raw):
    """Rolling-window sequences of length SEQ."""
    Xs, ys = [], []
    for i in range(len(X_raw) - SEQ):
        Xs.append(X_raw[i: i + SEQ])
        ys.append(y_raw[i + SEQ])
    return np.array(Xs, dtype=np.float32), np.array(ys, dtype=np.float32)


# ── Backend: Keras CNN-LSTM ───────────────────────────────────────────────────

def train_keras(X_train, X_test, y_train, y_test, seq_len, n_feats):
    """Train and save the Keras CNN-LSTM model."""
    try:
        os.environ.setdefault("TF_CPP_MIN_LOG_LEVEL", "3")
        from tensorflow.keras.models import Sequential   # type: ignore
        from tensorflow.keras.layers import (            # type: ignore
            Conv1D, MaxPooling1D, LSTM, Dense, Dropout
        )
        from tensorflow.keras.optimizers import Adam     # type: ignore
    except ImportError:
        return False

    model = Sequential([
        Conv1D(32, kernel_size=3, activation="relu",
               input_shape=(seq_len, n_feats), padding="same"),
        MaxPooling1D(pool_size=2),
        Dropout(0.2),
        LSTM(32, return_sequences=True),
        Dropout(0.2),
        LSTM(16),
        Dropout(0.2),
        Dense(16, activation="relu"),
        Dense(1, activation="sigmoid"),
    ])
    model.compile(optimizer=Adam(1e-3),
                  loss="binary_crossentropy",
                  metrics=["accuracy"])
    model.summary()

    print("\n[TRAIN] Training CNN-LSTM (Keras)...")
    model.fit(X_train, y_train,
              validation_data=(X_test, y_test),
              epochs=20, batch_size=32, verbose=1)

    loss, acc = model.evaluate(X_test, y_test, verbose=0)
    print(f"\n{'='*50}")
    print(f"  ACCURACY:  {acc*100:.2f}%")
    print(f"  LOSS:      {loss:.4f}")
    print(f"{'='*50}")

    os.makedirs(os.path.dirname(MODEL_H5), exist_ok=True)
    model.save(MODEL_H5)
    print(f"\n✅ Keras model saved: {MODEL_H5}")
    return True


# ── Backend: scikit-learn RandomForest ───────────────────────────────────────

def train_sklearn(X_train, X_test, y_train, y_test):
    """
    Train a RandomForest on flattened sequence features.
    Flattens (n, SEQ, 6) → (n, SEQ*6) for sklearn compatibility.
    Saves as device_authenticator.pkl — ai_authenticator.py detects this
    format and uses predict_proba instead of model.predict.
    """
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.metrics import accuracy_score, classification_report

    # Flatten sequences for sklearn
    X_tr_flat = X_train.reshape(len(X_train), -1)
    X_te_flat = X_test.reshape(len(X_test), -1)

    print("\n[TRAIN] Training RandomForest (sklearn fallback — no TensorFlow)...")
    clf = RandomForestClassifier(
        n_estimators=150,
        max_depth=10,
        random_state=42,
        n_jobs=-1,
    )
    clf.fit(X_tr_flat, y_train)

    y_pred = clf.predict(X_te_flat)
    acc = accuracy_score(y_test, y_pred)

    print(f"\n{'='*50}")
    print(f"  ACCURACY:  {acc*100:.2f}%")
    print(classification_report(y_test, y_pred,
                                target_names=["SPOOF", "LEGIT"]))
    print(f"{'='*50}")

    os.makedirs(os.path.dirname(MODEL_PKL), exist_ok=True)
    with open(MODEL_PKL, "wb") as f:
        pickle.dump(clf, f)
    print(f"\n✅ sklearn model saved: {MODEL_PKL}")
    return True


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    print("\n" + "=" * 60)
    print("  CNN-LSTM Hardware Fingerprint Trainer")
    print("  Zero-Trust IoT — Patent Claim C2")
    print("=" * 60)

    # 1. Load data
    result = None if SYNTHETIC_ONLY else load_from_db()
    if result is None:
        print("[TRAIN] Using synthetic training data.")
        X_raw, y_raw = generate_synthetic_data()
    else:
        X_raw, y_raw = result

    # 2. Build sequences
    X_seq, y_seq = make_sequences(X_raw, y_raw)
    print(f"\n[TRAIN] Sequences: {len(X_seq)} | Shape: {X_seq.shape}")

    # 3. Normalise
    n_samples, seq_len, n_feats = X_seq.shape
    X_flat = X_seq.reshape(-1, n_feats)
    scaler = StandardScaler()
    X_flat_scaled = scaler.fit_transform(X_flat)
    X_scaled = X_flat_scaled.reshape(n_samples, seq_len, n_feats)

    # 4. Split
    X_train, X_test, y_train, y_test = train_test_split(
        X_scaled, y_seq, test_size=0.2, random_state=42, stratify=y_seq
    )

    # 5. Save scaler first (needed by both backends)
    os.makedirs(BASE_DIR, exist_ok=True)
    with open(SCALER_PKL, "wb") as f:
        pickle.dump(scaler, f)
    print(f"[TRAIN] Scaler saved: {SCALER_PKL}")

    # 6. Train using best available backend
    success = False
    if BACKEND in ("auto", "keras"):
        success = train_keras(X_train, X_test, y_train, y_test, seq_len, n_feats)
        if not success and BACKEND == "keras":
            print("[TRAIN] ❌ Keras backend not available and BACKEND=keras was forced.")
            sys.exit(1)

    if not success:
        print("[TRAIN] TensorFlow not available — falling back to sklearn RandomForest.")
        success = train_sklearn(X_train, X_test, y_train, y_test)

    if not success:
        print("[TRAIN] ❌ No backend available.")
        sys.exit(1)

    print(f"\nModel is ready for real-time inference in ai_authenticator.py")
    print(f"  SPOOF_THRESHOLD = 0.45 (score < 0.45 → SPOOF_ATTACK alert)")
    print(f"\nNext: python3 pi_backend/dashboard.py")


if __name__ == "__main__":
    main()
