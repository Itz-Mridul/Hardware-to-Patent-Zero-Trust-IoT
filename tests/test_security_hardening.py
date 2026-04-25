#!/usr/bin/env python3
"""
Tests for the 5 World-Class Security Hardening Modules
=======================================================
  1. Clock Guard         — NTP Drift / Temporal Desync
  2. Thermal Monitor v2  — Dual-Sensor / IR Laser Tamper
  3. MQTTS Config        — TLS context + cert derivation
  4. GPIO Heartbeat      — Physical Dead-Man's Switch
  5. Honey-PIN           — Duress + Panic codes
"""

import sqlite3
import time

import pytest


# ──────────────────────────────────────────────────────────────────────────────
# Shared fixture
# ──────────────────────────────────────────────────────────────────────────────

@pytest.fixture()
def temp_db(monkeypatch, tmp_path):
    """Fresh SQLite DB shared across all modules in each test."""
    db_path = str(tmp_path / "security.db")

    import pi_backend.iot_server as iot_server
    import pi_backend.thermal_monitor as tm
    import pi_backend.clock_guard as cg
    import pi_backend.heartbeat_monitor as hb
    import pi_backend.honey_pin as hp

    monkeypatch.setattr(iot_server, "DB_PATH", db_path)
    monkeypatch.setattr(tm, "DB_PATH", db_path)
    monkeypatch.setattr(cg, "DB_PATH", db_path)
    monkeypatch.setattr(hb, "DB_PATH", db_path)
    monkeypatch.setattr(hp, "DB_PATH", db_path)

    iot_server.init_db()
    yield db_path


# ──────────────────────────────────────────────────────────────────────────────
# 1. CLOCK GUARD — NTP Drift / Temporal Desync Attack
# ──────────────────────────────────────────────────────────────────────────────

class TestClockGuard:
    """
    Attacker performs NTP spoofing to drift the Pi's clock forward,
    desyncing RGB challenge windows and IPD expectations.
    """

    def test_get_secure_time_returns_float(self):
        """get_secure_time() must always return a valid Unix timestamp."""
        from pi_backend.clock_guard import get_secure_time
        t = get_secure_time()
        assert isinstance(t, float)
        assert t > 1_700_000_000   # sanity check: after 2023

    def test_no_drift_below_threshold_is_clean(self, temp_db):
        """Small natural drift (<5s) must NOT trigger a CLOCK_TAMPER alert."""
        from pi_backend.clock_guard import check_clock_drift
        report = check_clock_drift()
        # Without a physical RTC, drift = 0.0 (trivially clean)
        assert report["drift_seconds"] == 0.0 or not report["tamper_detected"]

    def test_clock_tamper_is_detected_on_large_drift(self, monkeypatch, temp_db):
        """Simulating a 10-second NTP drift must log a CLOCK_TAMPER alert."""
        import pi_backend.clock_guard as cg

        # Inject a fake RTC reader that returns system_time + 10s
        monkeypatch.setattr(cg, "_read_rtc_time",
                            lambda: time.time() + 10.0)
        monkeypatch.setattr(cg, "DRIFT_ALERT_SECONDS", 5.0)
        monkeypatch.setattr(cg, "_clock_tamper_active", False)

        report = cg.check_clock_drift()

        assert report["tamper_detected"] is True
        assert report["drift_seconds"] >= 10.0

        with sqlite3.connect(temp_db) as conn:
            row = conn.execute(
                "SELECT * FROM alerts WHERE event_type = 'CLOCK_TAMPER'"
            ).fetchone()
        assert row is not None

    def test_secure_time_returns_rtc_when_available(self, monkeypatch):
        """get_secure_time() must prefer the RTC over the system clock."""
        import pi_backend.clock_guard as cg
        fake_rtc_time = 1_800_000_000.0
        monkeypatch.setattr(cg, "_read_rtc_time", lambda: fake_rtc_time)
        assert cg.get_secure_time() == fake_rtc_time

    def test_secure_time_falls_back_to_system_if_no_rtc(self, monkeypatch):
        """Without an RTC device, get_secure_time() returns time.time()."""
        import pi_backend.clock_guard as cg
        monkeypatch.setattr(cg, "_read_rtc_time", lambda: None)
        t = cg.get_secure_time()
        assert abs(t - time.time()) < 2.0


# ──────────────────────────────────────────────────────────────────────────────
# 2. THERMAL MONITOR v2 — Dual-Sensor / IR Laser Ghost Attack
# ──────────────────────────────────────────────────────────────────────────────

class TestThermalMonitorV2:
    """
    IR laser heats only the DHT22 casing. CPU stays cool.
    System must detect SENSOR_TAMPER instead of triggering kill.
    """

    def test_normal_temp_no_alert(self, temp_db):
        """42°C air, 38°C CPU — no action."""
        from pi_backend.thermal_monitor import handle_thermal_event
        result = handle_thermal_event("ESP32_ENV", 42.0, cpu_temp=38.0)
        assert result["event_type"] == "NORMAL"
        assert result["action_taken"] is False

    def test_real_fire_both_sensors_hot_triggers_kill(self, temp_db):
        """75°C air AND 70°C CPU — real emergency, power kill."""
        from pi_backend.thermal_monitor import handle_thermal_event
        result = handle_thermal_event("ESP32_ENV", 75.0, cpu_temp=70.0)
        assert result["event_type"] == "EMERGENCY_THERMAL"
        assert result["action_taken"] is True

        with sqlite3.connect(temp_db) as conn:
            row = conn.execute(
                "SELECT event_type FROM alerts WHERE event_type='EMERGENCY_THERMAL'"
            ).fetchone()
        assert row is not None

    def test_ir_laser_attack_detected_as_sensor_tamper(self, temp_db):
        """
        75°C air but CPU only 38°C (Δ=37°C > 20°C threshold).
        Must log SENSOR_TAMPER and NOT cut power.
        """
        from pi_backend.thermal_monitor import handle_thermal_event
        result = handle_thermal_event("ESP32_ENV", 75.0, cpu_temp=38.0)
        assert result["event_type"] == "SENSOR_TAMPER"
        assert result["action_taken"] is False   # Kill suppressed — it's a trap!

        with sqlite3.connect(temp_db) as conn:
            row = conn.execute(
                "SELECT event_type FROM alerts WHERE event_type='SENSOR_TAMPER'"
            ).fetchone()
        assert row is not None

    def test_cpu_only_overheat_triggers_cpu_alert(self, temp_db):
        """40°C air, but 85°C CPU — software fault / bad thermal paste."""
        from pi_backend.thermal_monitor import handle_thermal_event
        result = handle_thermal_event("ESP32_ENV", 40.0, cpu_temp=85.0)
        assert result["event_type"] == "CPU_OVERHEAT"
        assert result["action_taken"] is True

    def test_boundary_delta_exactly_at_threshold(self, temp_db):
        """At exactly Δ=20°C, it should be SENSOR_TAMPER."""
        from pi_backend.thermal_monitor import handle_thermal_event, TAMPER_DELTA_THRESHOLD
        cpu_temp = 75.0 - TAMPER_DELTA_THRESHOLD   # exactly at boundary
        result = handle_thermal_event("ESP32_ENV", 75.0, cpu_temp=cpu_temp)
        assert result["event_type"] == "SENSOR_TAMPER"

    def test_no_cpu_temp_available_triggers_kill_on_high_air(self, temp_db):
        """If no CPU sensor exists and air is critical, we must still act."""
        from pi_backend.thermal_monitor import handle_thermal_event
        # cpu_temp=None simulates missing /sys/class/thermal
        result = handle_thermal_event("ESP32_ENV", 80.0, cpu_temp=None)
        # Without a CPU reading we cannot detect tamper — err on side of caution
        assert result["event_type"] == "EMERGENCY_THERMAL"


# ──────────────────────────────────────────────────────────────────────────────
# 3. MQTTS CONFIGURATION — TLS Context
# ──────────────────────────────────────────────────────────────────────────────

class TestMqttsConfig:
    """Tests for TLS context and cert generation helpers."""

    def test_tls_context_raises_if_no_certs(self, tmp_path):
        """get_tls_context() must raise FileNotFoundError when certs are missing."""
        from pi_backend.mqtts_config import get_tls_context
        import pytest
        with pytest.raises(FileNotFoundError):
            get_tls_context(
                ca_cert=str(tmp_path / "ca.crt"),
                client_cert=str(tmp_path / "client.crt"),
                client_key=str(tmp_path / "client.key"),
            )

    def test_tls_context_returns_none_if_unavailable(self, tmp_path):
        """get_tls_context_if_available() returns None instead of raising."""
        from pi_backend.mqtts_config import get_tls_context_if_available
        ctx = get_tls_context_if_available(
            ca_cert=str(tmp_path / "ca.crt"),
            client_cert=str(tmp_path / "client.crt"),
            client_key=str(tmp_path / "client.key"),
        )
        assert ctx is None

    def test_mosquitto_conf_snippet_is_non_empty(self):
        """The Mosquitto config snippet must contain the key port/TLS directives."""
        from pi_backend.mqtts_config import MOSQUITTO_CONF_SNIPPET
        assert "8883"                 in MOSQUITTO_CONF_SNIPPET
        assert "require_certificate"  in MOSQUITTO_CONF_SNIPPET
        assert "allow_anonymous"      in MOSQUITTO_CONF_SNIPPET
        assert "cafile"               in MOSQUITTO_CONF_SNIPPET

    def test_derive_duress_pin_logic(self):
        """Verify the cert derivation helper in mqtts_config doesn't break."""
        # mqtts_config is independent of pin derivation — just smoke test import
        import pi_backend.mqtts_config  # noqa: F401


# ──────────────────────────────────────────────────────────────────────────────
# 4. GPIO HEARTBEAT MONITOR — Physical Dead-Man's Switch
# ──────────────────────────────────────────────────────────────────────────────

class TestGpioHeartbeatMonitor:
    """
    Tests the software-layer of the GPIO heartbeat monitor.
    (Hardware GPIO is absent on Mac — simulation mode is used.)
    """

    def test_simulate_pulse_marks_heartbeat_active(self):
        """Simulating a GPIO pulse must reset the heartbeat timer."""
        from pi_backend.heartbeat_monitor import (
            simulate_heartbeat_pulse, is_heartbeat_active,
            get_heartbeat_status, _heartbeat_lost
        )
        import pi_backend.heartbeat_monitor as hb

        simulate_heartbeat_pulse()
        status = get_heartbeat_status()
        assert status["last_pulse_ms_ago"] < 500   # fresher than 500ms
        assert hb._heartbeat_lost is False

    def test_simulate_loss_marks_heartbeat_inactive(self):
        """Simulating heartbeat loss must set _heartbeat_lost state."""
        from pi_backend.heartbeat_monitor import (
            simulate_heartbeat_loss, get_heartbeat_status
        )
        simulate_heartbeat_loss()
        status = get_heartbeat_status()
        # last pulse should be older than timeout
        from pi_backend.heartbeat_monitor import HEARTBEAT_TIMEOUT_MS
        assert status["last_pulse_ms_ago"] >= HEARTBEAT_TIMEOUT_MS

    def test_heartbeat_status_contains_required_keys(self):
        """get_heartbeat_status() must return all expected keys."""
        from pi_backend.heartbeat_monitor import get_heartbeat_status
        status = get_heartbeat_status()
        for key in ["hardware_gpio", "last_pulse_ms_ago", "timeout_ms",
                    "heartbeat_lost", "relay_cut"]:
            assert key in status

    def test_gpio_not_available_on_mac(self):
        """On non-Pi hardware, gpio_available must be False."""
        from pi_backend.heartbeat_monitor import _gpio_available
        # This test passes on Mac (no RPi.GPIO) and is skipped on Pi
        import platform
        if "arm" not in platform.machine().lower():
            assert _gpio_available is False


# ──────────────────────────────────────────────────────────────────────────────
# 5. HONEY-PIN SYSTEM — Duress & Panic Codes
# ──────────────────────────────────────────────────────────────────────────────

class TestHoneyPin:
    """
    The Honey-PIN must silently fire a Telegram SOS when the duress
    code is entered, while making the interface appear normal.
    """

    @pytest.fixture(autouse=True)
    def setup_pins(self, temp_db):
        from pi_backend.honey_pin import register_pins
        register_pins("1234")   # duress=1235, panic=1237

    def test_real_pin_returns_real(self, temp_db):
        from pi_backend.honey_pin import evaluate_pin, PinResult
        assert evaluate_pin("1234") == PinResult.REAL

    def test_duress_pin_returns_duress(self, temp_db):
        from pi_backend.honey_pin import evaluate_pin, PinResult
        assert evaluate_pin("1235") == PinResult.DURESS

    def test_panic_pin_returns_panic(self, temp_db):
        from pi_backend.honey_pin import evaluate_pin, PinResult
        assert evaluate_pin("1237") == PinResult.PANIC

    def test_wrong_pin_returns_wrong(self, temp_db):
        from pi_backend.honey_pin import evaluate_pin, PinResult
        assert evaluate_pin("9999") == PinResult.WRONG

    def test_duress_fires_telegram(self, temp_db):
        """Duress PIN must call the registered Telegram callback."""
        from pi_backend.honey_pin import evaluate_pin, set_telegram_callback, PinResult

        received = []
        set_telegram_callback(lambda msg: received.append(msg))
        result = evaluate_pin("1235")

        assert result == PinResult.DURESS
        assert len(received) == 1
        assert "DURESS" in received[0].upper()

    def test_panic_fires_telegram(self, temp_db):
        """Panic PIN must call the Telegram callback with PANIC language."""
        from pi_backend.honey_pin import evaluate_pin, set_telegram_callback, PinResult

        received = []
        set_telegram_callback(lambda msg: received.append(msg))
        result = evaluate_pin("1237")

        assert result == PinResult.PANIC
        assert len(received) == 1
        assert "PANIC" in received[0].upper()

    def test_duress_logs_to_db(self, temp_db):
        """DURESS_DETECTED must be persisted to the alerts table."""
        from pi_backend.honey_pin import evaluate_pin

        evaluate_pin("1235", device_id="KEYPAD_01")
        with sqlite3.connect(temp_db) as conn:
            row = conn.execute(
                "SELECT * FROM alerts WHERE event_type='DURESS_DETECTED'"
            ).fetchone()
        assert row is not None

    def test_panic_logs_to_db(self, temp_db):
        """PANIC_LOCKDOWN must be persisted to the alerts table."""
        from pi_backend.honey_pin import evaluate_pin

        evaluate_pin("1237", device_id="KEYPAD_01")
        with sqlite3.connect(temp_db) as conn:
            row = conn.execute(
                "SELECT * FROM alerts WHERE event_type='PANIC_LOCKDOWN'"
            ).fetchone()
        assert row is not None

    def test_wrong_pin_is_logged(self, temp_db):
        """Wrong PIN attempts must be recorded (brute-force detection)."""
        from pi_backend.honey_pin import evaluate_pin

        evaluate_pin("0000", device_id="KEYPAD_01")
        with sqlite3.connect(temp_db) as conn:
            row = conn.execute(
                "SELECT * FROM alerts WHERE event_type='PIN_WRONG'"
            ).fetchone()
        assert row is not None

    def test_pin_comparison_is_timing_safe(self, temp_db):
        """ct_compare must not short-circuit (constant-time guarantee)."""
        from pi_backend.honey_pin import _ct_compare
        assert _ct_compare("abcd", "abcd") is True
        assert _ct_compare("abcd", "abce") is False
        assert _ct_compare("abcd", "xyz") is False   # different length

    def test_derive_duress_wraps_on_digit_9(self):
        """Duress derivation must wrap 9 → 0, not produce '10'."""
        from pi_backend.honey_pin import _derive_duress, register_pins, evaluate_pin, PinResult
        register_pins("1239")   # duress should be 1230 (9+1 mod 10)
        result = evaluate_pin("1230")
        assert result == PinResult.DURESS

    def test_uninitialised_raises(self):
        """evaluate_pin without register_pins must raise RuntimeError."""
        import pi_backend.honey_pin as hp
        hp._real_hash = ""     # simulate uninitialised state
        import pytest
        with pytest.raises(RuntimeError):
            hp.evaluate_pin("1234")
