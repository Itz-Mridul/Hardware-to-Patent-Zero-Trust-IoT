#!/usr/bin/env python3
"""
ML Accuracy Test — validates the trained fingerprint model
can distinguish legitimate ESP32 heartbeats from software attackers.
"""

import os
import sqlite3
import pickle
import tempfile
import pytest
import pandas as pd

BASE_DIR = os.path.dirname(os.path.abspath(os.path.join(__file__, "..")))
MODEL_PATH = os.path.join(BASE_DIR, "pi_backend", "fingerprint_model.pkl")
ATTACK_DB  = os.path.join(BASE_DIR, "tests", "attack_data.db")
LEGIT_DB   = os.path.join(BASE_DIR, "pi_backend", "training_data.db")


def load_model():
    if not os.path.exists(MODEL_PATH):
        pytest.skip(f"Model not trained yet: {MODEL_PATH}")
    with open(MODEL_PATH, "rb") as f:
        return pickle.load(f)


def load_attack_samples(n=20):
    if not os.path.exists(ATTACK_DB):
        pytest.skip(f"Attack DB not found: {ATTACK_DB}")
    with sqlite3.connect(ATTACK_DB) as conn:
        df = pd.read_sql_query(
            """SELECT inter_packet_delay, rssi, free_heap, packet_size
               FROM heartbeats WHERE is_legitimate = 0 LIMIT ?""",
            conn, params=(n,)
        )
    if df.empty:
        pytest.skip("No attack samples found in DB")
    return df


def load_legit_samples(n=20):
    if not os.path.exists(LEGIT_DB):
        pytest.skip(f"Training DB not found: {LEGIT_DB}")
    with sqlite3.connect(LEGIT_DB) as conn:
        df = pd.read_sql_query(
            """SELECT inter_packet_delay, rssi, free_heap, packet_size
               FROM heartbeats WHERE is_legitimate = 1 LIMIT ?""",
            conn, params=(n,)
        )
    if df.empty:
        pytest.skip("No legitimate samples found in training DB")
    return df


class TestMLAccuracy:
    def test_model_file_exists(self):
        if not os.path.exists(MODEL_PATH):
            pytest.skip(
                f"Model not trained yet ({MODEL_PATH}). "
                "Run: python3 pi_backend/train_authentication_model.py"
            )

    def test_model_rejects_attack_samples(self):
        model = load_model()
        df = load_attack_samples(20)
        predictions = model.predict(df)
        rejection_rate = (predictions == 0).mean()
        assert rejection_rate >= 0.7, (
            f"Model only rejected {rejection_rate:.0%} of attack samples (need ≥ 70%)"
        )

    def test_model_authenticates_legit_samples(self):
        model = load_model()
        df = load_legit_samples(20)
        predictions = model.predict(df)
        auth_rate = (predictions == 1).mean()
        assert auth_rate >= 0.7, (
            f"Model only authenticated {auth_rate:.0%} of legit samples (need ≥ 70%)"
        )

    def test_model_has_expected_features(self):
        model = load_model()
        expected = {"inter_packet_delay", "rssi", "free_heap", "packet_size"}
        # RandomForest stores feature_names_in_ if trained with a DataFrame
        if hasattr(model, "feature_names_in_"):
            actual = set(model.feature_names_in_)
            assert expected == actual, f"Feature mismatch: {actual}"
