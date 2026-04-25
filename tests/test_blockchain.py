#!/usr/bin/env python3
"""
Blockchain Integration Tests
Tests that forensic events are hashed and cached for on-chain submission.
Does NOT require Ganache to be running — tests use the local cache layer.
"""

import os
import sqlite3
import pytest

import pi_backend.iot_server as iot_server


@pytest.fixture()
def temp_db(monkeypatch, tmp_path):
    db_path = tmp_path / "security.db"
    monkeypatch.setattr(iot_server, "DB_PATH", str(db_path))
    # Also patch forensic logger DB path
    import pi_backend.forensic_logger as fl
    monkeypatch.setattr(fl, "DB_PATH", str(db_path))
    import pi_backend.thermal_monitor as tm
    monkeypatch.setattr(tm, "DB_PATH", str(db_path))
    iot_server.init_db()
    yield str(db_path)


class TestForensicLogger:
    def test_rejected_event_stored(self, temp_db):
        from pi_backend.forensic_logger import log_access_attempt
        h = log_access_attempt(
            device_id="ATTACKER_01",
            result="REJECTED",
            reason="IPD far too fast (200ms vs 5000ms expected)",
            trust_score=8.0,
            submit_to_chain=False,
        )
        assert len(h) == 64  # SHA-256 hex

        with sqlite3.connect(temp_db) as conn:
            row = conn.execute(
                "SELECT * FROM access_log WHERE device_id = 'ATTACKER_01'"
            ).fetchone()
        assert row is not None
        assert row[2] == "REJECTED"  # result column

    def test_authenticated_event_stored(self, temp_db):
        from pi_backend.forensic_logger import log_access_attempt
        log_access_attempt(
            device_id="ESP32_GATEWAY_001",
            result="AUTHENTICATED",
            reason="Heartbeat matches expected cadence",
            trust_score=95.0,
        )
        with sqlite3.connect(temp_db) as conn:
            row = conn.execute(
                "SELECT result FROM access_log WHERE device_id = 'ESP32_GATEWAY_001'"
            ).fetchone()
        assert row[0] == "AUTHENTICATED"

    def test_event_hash_is_deterministic(self, temp_db):
        from pi_backend.forensic_logger import _hash_event
        h1 = _hash_event("DEV", "REJECTED", "fast IPD", 1000)
        h2 = _hash_event("DEV", "REJECTED", "fast IPD", 1000)
        assert h1 == h2

    def test_different_events_have_different_hashes(self, temp_db):
        from pi_backend.forensic_logger import _hash_event
        h1 = _hash_event("DEV_A", "REJECTED", "fast IPD", 1000)
        h2 = _hash_event("DEV_B", "AUTHENTICATED", "normal IPD", 1001)
        assert h1 != h2

    def test_get_recent_access_log(self, temp_db):
        from pi_backend.forensic_logger import log_access_attempt, get_recent_access_log
        log_access_attempt("D1", "REJECTED", "test", 10.0)
        log_access_attempt("D2", "AUTHENTICATED", "test", 90.0)
        results = get_recent_access_log(limit=10)
        assert len(results) == 2

    def test_thermal_event_stored(self, temp_db):
        from pi_backend.thermal_monitor import handle_thermal_event
        handle_thermal_event(device_id="ESP32_ENV", temperature=75.0)
        with sqlite3.connect(temp_db) as conn:
            row = conn.execute(
                "SELECT event_type FROM alerts WHERE event_type = 'EMERGENCY_THERMAL'"
            ).fetchone()
        assert row is not None
