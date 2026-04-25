#!/usr/bin/env python3
"""
End-to-End Tests for the Zero-Trust IoT Security Gateway.

Covers all four "Ultimate Heist" attack scenarios:
  1. Digital Ghost  — software-spoof via fast-IPD heartbeats
  2. Optical Deepfake — RGB challenge-response color mismatch
  3. Brute Force    — Dead-Man heartbeat drop → lockdown
  4. Silent Burn    — Thermal spike → emergency kill
"""

import sqlite3
import time

import pytest

import pi_backend.iot_server as iot_server

# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────

@pytest.fixture()
def temp_db(monkeypatch, tmp_path):
    """Each test gets its own fresh SQLite database, shared across all modules."""
    db_path = str(tmp_path / "security.db")
    monkeypatch.setattr(iot_server, "DB_PATH", db_path)

    import pi_backend.forensic_logger as fl
    import pi_backend.thermal_monitor as tm
    monkeypatch.setattr(fl, "DB_PATH", db_path)
    monkeypatch.setattr(tm, "DB_PATH", db_path)

    iot_server.init_db()
    yield db_path


def _status(device_id):
    with sqlite3.connect(iot_server.DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT * FROM device_status WHERE device_id = ?", (device_id,)
        ).fetchone()
        return dict(row) if row else None


# ─────────────────────────────────────────────
# Attack 1: Digital Ghost — Network Spoofing
# ─────────────────────────────────────────────

class TestAttack1_DigitalGhost:
    """
    Attacker clones the RFID card and injects fast spoofed packets.
    Intel CPU scheduling jitter produces IPDs far too small vs ESP32's 5s cadence.
    """

    def test_fast_ipd_heavily_penalised(self, temp_db):
        """A packet with IPD < 1000 ms must get a large negative delta and REJECTED."""
        delta, classification, _ = iot_server.score_heartbeat(250, -50)
        assert delta <= -30
        assert classification == "REJECTED"

    def test_sustained_spoofing_drops_trust_below_block_threshold(self, temp_db):
        """After enough spoofed packets, trust must fall below BLOCK_THRESHOLD.

        We set the device as ONLINE with grace_period=0 so spoofed packets
        are evaluated immediately (not shielded by the reconnect grace window).
        """
        device_id = "ESP32_SOFTWARE_ATTACKER"
        # Register the device without a grace period so packets are scored
        iot_server.save_device_status(
            device_id,
            status="ONLINE",
            last_seen=time.time(),
            grace_period_until=0.0,   # no grace — packets evaluated immediately
            trust_score=100.0,
            last_rssi=-45,
            last_ipd=5000,
            last_transition=time.time(),
            status_source="test",
            connection_state="ONLINE",
            last_event="test_setup",
        )
        with iot_server.app.app_context():
            for _ in range(8):  # 8 × −40 penalty = −320 → trust clamps to 0
                iot_server.evaluate_heartbeat({
                    "device_id": device_id,
                    "inter_packet_delay": 200,   # software scheduler jitter
                    "rssi": -45,
                    "timestamp": int(time.time() * 1000),
                })

        state = _status(device_id)
        assert state["trust_score"] < iot_server.BLOCK_THRESHOLD

    def test_legitimate_device_is_not_penalised(self, temp_db):
        """A well-behaved device with IPD ~5000ms must be AUTHENTICATED."""
        delta, classification, _ = iot_server.score_heartbeat(5050, -60)
        assert delta >= 0
        assert classification == "AUTHENTICATED"


# ─────────────────────────────────────────────
# Attack 2: Optical Deepfake — RGB Challenge
# ─────────────────────────────────────────────

class TestAttack2_OpticalDeepfake:
    """Pre-recorded deepfake video shows wrong ambient color → denied."""

    def test_color_challenge_generation_is_random(self):
        from pi_backend.rgb_challenge import generate_color_challenge
        challenges = {generate_color_challenge() for _ in range(50)}
        assert len(challenges) >= 3

    def test_matching_color_response_passes(self):
        from pi_backend.rgb_challenge import verify_color_response
        assert verify_color_response(expected="BLUE", received="BLUE") is True

    def test_wrong_color_response_fails(self):
        from pi_backend.rgb_challenge import verify_color_response
        assert verify_color_response(expected="CYAN", received="WHITE") is False

    def test_no_response_fails(self):
        from pi_backend.rgb_challenge import verify_color_response
        assert verify_color_response(expected="RED", received=None) is False

    def test_case_insensitive_match(self):
        from pi_backend.rgb_challenge import verify_color_response
        assert verify_color_response(expected="GREEN", received="green") is True


# ─────────────────────────────────────────────
# Attack 3: Brute Force — Dead-Man's Switch
# ─────────────────────────────────────────────

class TestAttack3_BruteForce:
    """Wi-Fi jammer kills heartbeat → Dead-Man Switch locks all relays."""

    def test_device_goes_offline_on_lwt(self, temp_db):
        device_id = "ESP32_GATEWAY_001"
        iot_server.handle_status_message(
            "mailbox/status",
            {"device_id": device_id, "status": "ONLINE", "connection_state": "BOOT"},
        )
        iot_server.handle_status_message(
            "mailbox/status",
            {"device_id": device_id, "status": "OFFLINE"},
        )
        state = _status(device_id)
        assert state["status"] == "OFFLINE"

    def test_offline_device_trust_is_frozen(self, temp_db):
        """Silence != spoofing: trust must not decay while device is OFFLINE."""
        device_id = "ESP32_GATEWAY_FROZEN"
        iot_server.handle_status_message(
            "mailbox/status",
            {"device_id": device_id, "status": "ONLINE", "connection_state": "BOOT"},
        )
        iot_server.handle_status_message(
            "mailbox/status",
            {"device_id": device_id, "status": "OFFLINE"},
        )
        trust_before = _status(device_id)["trust_score"]

        with iot_server.app.app_context():
            iot_server.evaluate_heartbeat(
                {"device_id": device_id, "inter_packet_delay": 100, "rssi": -80,
                 "timestamp": int(time.time() * 1000)}
            )
        assert _status(device_id)["trust_score"] == trust_before

    def test_reconnect_opens_grace_period(self, temp_db):
        device_id = "ESP32_GATEWAY_001"
        iot_server.save_device_status(
            device_id,
            status="OFFLINE",
            last_seen=time.time(),
            grace_period_until=0.0,
            trust_score=72.0,
            last_rssi=-88,
            last_ipd=9000,
            last_transition=time.time(),
            status_source="mqtt",
            connection_state="BROKER_WILL",
            last_event="offline",
        )
        with iot_server.app.app_context():
            response, http_code, _ = iot_server.evaluate_heartbeat({
                "device_id": device_id,
                "timestamp": int(time.time() * 1000),
                "rssi": -55,
                "inter_packet_delay": 5100,
                "connection_state": "RECONNECTED",
            })
        assert http_code == 200
        body = response.get_json()
        assert body["status"] == "AUTHENTICATED"
        assert body["grace_period_until"] > time.time()


# ─────────────────────────────────────────────
# Attack 4: Silent Burn — Thermal Sabotage
# ─────────────────────────────────────────────

class TestAttack4_SilentBurn:
    """Hacker overheats Pi via SSH; air-gapped DHT22 detects it and cuts power."""

    def test_thermal_alert_stored_in_db(self, temp_db):
        from pi_backend.thermal_monitor import handle_thermal_event
        handle_thermal_event(device_id="ESP32_ENV_MONITOR", temperature=75.0)
        with sqlite3.connect(temp_db) as conn:
            row = conn.execute(
                "SELECT * FROM alerts WHERE event_type = 'EMERGENCY_THERMAL'",
            ).fetchone()
        assert row is not None

    def test_normal_temperature_does_not_alert(self, temp_db):
        from pi_backend.thermal_monitor import handle_thermal_event
        handle_thermal_event(device_id="ESP32_ENV_MONITOR", temperature=42.0)
        with sqlite3.connect(temp_db) as conn:
            row = conn.execute(
                "SELECT * FROM alerts WHERE event_type = 'EMERGENCY_THERMAL'",
            ).fetchone()
        assert row is None

    def test_threshold_boundary(self, temp_db):
        from pi_backend.thermal_monitor import handle_thermal_event
        handle_thermal_event(device_id="ESP32_ENV_MONITOR", temperature=70.0)
        with sqlite3.connect(temp_db) as conn:
            row = conn.execute(
                "SELECT * FROM alerts WHERE event_type = 'EMERGENCY_THERMAL'",
            ).fetchone()
        assert row is not None


# ─────────────────────────────────────────────
# Blockchain Forensic Evidence Logging
# ─────────────────────────────────────────────

class TestBlockchainForensicLogging:
    def test_rejected_event_is_cached(self, temp_db):
        from pi_backend.forensic_logger import log_access_attempt
        log_access_attempt(
            device_id="ESP32_SOFTWARE_ATTACKER",
            result="REJECTED",
            reason="IPD too fast (spoofing detected)",
            trust_score=10.0,
        )
        with sqlite3.connect(temp_db) as conn:
            row = conn.execute(
                "SELECT * FROM access_log WHERE result = 'REJECTED'",
            ).fetchone()
        assert row is not None

    def test_authenticated_event_is_cached(self, temp_db):
        from pi_backend.forensic_logger import log_access_attempt
        log_access_attempt(
            device_id="ESP32_GATEWAY_001",
            result="AUTHENTICATED",
            reason="Heartbeat matches expected cadence",
            trust_score=95.0,
        )
        with sqlite3.connect(temp_db) as conn:
            row = conn.execute(
                "SELECT * FROM access_log WHERE result = 'AUTHENTICATED'",
            ).fetchone()
        assert row is not None


# ─────────────────────────────────────────────
# Status Message Handling
# ─────────────────────────────────────────────

class TestStatusMessageHandling:
    def test_boot_status_opens_grace_period(self, temp_db):
        device_id = "ESP32_FRESH"
        iot_server.handle_status_message(
            "mailbox/status",
            {"device_id": device_id, "status": "ONLINE", "connection_state": "BOOT"},
            retained=True,
        )
        state = _status(device_id)
        assert state["status"] == "ONLINE"
        assert state["grace_period_until"] > time.time()

    def test_plain_string_offline_payload(self, temp_db):
        device_id = "ESP32_PLAIN"
        iot_server.handle_status_message(
            "mailbox/status",
            b'{"device_id": "ESP32_PLAIN", "status": "OFFLINE"}',
        )
        state = _status(device_id)
        assert state["status"] == "OFFLINE"
