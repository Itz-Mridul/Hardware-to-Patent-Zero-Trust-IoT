#!/usr/bin/env python3
"""
GPIO Heartbeat Monitor — Physical Dead-Man's Switch (Hardware Layer)
======================================================================
Closes the "Last-Will Race Condition" loophole.

Weakness:
    MQTT Last-Will-Testament has a software processing lag (~50–500ms)
    between a device going offline and the broker executing the LWT.
    An attacker flooding the broker (MQTT DDoS) can widen this gap and
    race a forged "Unlock" command into the system during the chaos.

Closure:
    This module monitors a dedicated GPIO "heartbeat wire" from the ESP32.
    The ESP32 must toggle a specific GPIO pin HIGH every 200ms.
    If the Pi detects >200ms of LOW — regardless of what MQTT says —
    it immediately:
        1. Cuts power to the door relay (via another GPIO output).
        2. Logs a HEARTBEAT_LOSS alert in the database.
        3. Publishes a LOCKDOWN command to MQTT (as a secondary layer).

    This is the hardware-enforced kill-switch that operates BELOW the
    software stack. Even if the MQTT broker is flooded or the Python
    server is crashed, the GPIO watchdog still runs.

    Hardware wiring:
        ESP32 GPIO 26  ─────────────────► Pi GPIO 17 (BCM)  [heartbeat IN]
        Pi GPIO 18 (BCM) ───────────────► Relay MOSFET Gate [power OUT]
        Common GND     ─────────────────► Both boards

Simulation mode (Mac / no GPIO):
    If RPi.GPIO is not installed, the module prints warnings but does
    not crash. In tests, the heartbeat state is managed via
    simulate_heartbeat_pulse() and simulate_heartbeat_loss().
"""

import os
import sqlite3
import threading
import time
from typing import Optional

# ── Configuration ──────────────────────────────────────────────────────────────
HEARTBEAT_PIN          = int(os.environ.get("HEARTBEAT_GPIO_IN",  "17"))
RELAY_KILL_PIN         = int(os.environ.get("RELAY_KILL_GPIO_OUT", "18"))
HEARTBEAT_TIMEOUT_MS   = float(os.environ.get("HEARTBEAT_TIMEOUT_MS", "200"))
MONITOR_POLL_INTERVAL  = float(os.environ.get("HB_POLL_INTERVAL_S",   "0.05"))  # 50ms

_BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH   = os.environ.get("IOT_DB_PATH", os.path.join(_BASE_DIR, "security.db"))

# ── GPIO abstraction ──────────────────────────────────────────────────────────
_gpio_available = False
GPIO = None

try:
    import RPi.GPIO as GPIO          # type: ignore
    _gpio_available = True
except ImportError:
    pass   # Running on Mac / CI — use simulation mode


# ── Internal state ─────────────────────────────────────────────────────────────
_last_pulse_time: float  = time.time()
_heartbeat_lost:  bool   = False
_monitor_running: bool   = False
_sim_pin_state:   bool   = True      # Simulated HIGH by default


# ── Public API ─────────────────────────────────────────────────────────────────

def start_heartbeat_monitor(mqtt_client=None) -> None:
    """
    Starts the hardware heartbeat monitor in a background daemon thread.

    Call once at server startup, immediately after init_db().

    Args:
        mqtt_client: Optional paho client for LOCKDOWN broadcast.
    """
    global _monitor_running

    if _monitor_running:
        return
    _monitor_running = True

    _setup_gpio()

    t = threading.Thread(
        target=_monitor_loop,
        args=(mqtt_client,),
        name="GPIOHeartbeatMonitor",
        daemon=True,
    )
    t.start()
    mode = "hardware GPIO" if _gpio_available else "simulation"
    print(f"[HB_MONITOR] Physical heartbeat monitor started ({mode}). "
          f"Timeout={HEARTBEAT_TIMEOUT_MS:.0f}ms, "
          f"Pin=GPIO{HEARTBEAT_PIN} → relay=GPIO{RELAY_KILL_PIN}")


def is_heartbeat_active() -> bool:
    """
    Returns True if the ESP32 heartbeat wire is currently HIGH (alive).
    Used by iot_server.py evaluate_heartbeat() to add a hardware layer check.
    """
    if _gpio_available:
        return bool(GPIO.input(HEARTBEAT_PIN))
    return _sim_pin_state


def record_pulse() -> None:
    """
    Updates the last-seen pulse timestamp.
    Called on every RISING EDGE interrupt from the GPIO (or simulation).
    """
    global _last_pulse_time, _heartbeat_lost
    _last_pulse_time = time.time()
    _heartbeat_lost  = False


# ── Test simulation helpers ────────────────────────────────────────────────────

def simulate_heartbeat_pulse() -> None:
    """Simulates an active GPIO HIGH pulse for unit tests."""
    global _sim_pin_state
    _sim_pin_state = True
    record_pulse()


def simulate_heartbeat_loss() -> None:
    """Simulates the GPIO going LOW (no pulse) for unit tests."""
    global _sim_pin_state, _last_pulse_time
    _sim_pin_state   = False
    _last_pulse_time = time.time() - (HEARTBEAT_TIMEOUT_MS / 1000.0) - 1.0


def get_heartbeat_status() -> dict:
    """Returns current heartbeat monitor status (for dashboard API)."""
    age_ms = (time.time() - _last_pulse_time) * 1000
    return {
        "hardware_gpio":    _gpio_available,
        "last_pulse_ms_ago": round(age_ms, 1),
        "timeout_ms":       HEARTBEAT_TIMEOUT_MS,
        "heartbeat_lost":   _heartbeat_lost,
        "relay_cut":        _heartbeat_lost,
    }


# ── Internal ────────────────────────────────────────────────────────────────────

def _setup_gpio() -> None:
    global _last_pulse_time

    if not _gpio_available:
        print(f"[HB_MONITOR] RPi.GPIO not found — running in simulation mode")
        return

    GPIO.setmode(GPIO.BCM)
    GPIO.setwarnings(False)
    GPIO.setup(HEARTBEAT_PIN,  GPIO.IN,  pull_up_down=GPIO.PUD_DOWN)
    GPIO.setup(RELAY_KILL_PIN, GPIO.OUT, initial=GPIO.HIGH)  # HIGH = relay ENGAGED

    # Edge interrupt — fires on every rising edge (ESP32 pulse)
    GPIO.add_event_detect(
        HEARTBEAT_PIN, GPIO.RISING,
        callback=lambda ch: record_pulse(),
        bouncetime=10,
    )
    _last_pulse_time = time.time()
    print(f"[HB_MONITOR] GPIO configured: IN=BCM{HEARTBEAT_PIN}, "
          f"OUT=BCM{RELAY_KILL_PIN}")


def _monitor_loop(mqtt_client) -> None:
    """
    Polling watchdog.  Runs every MONITOR_POLL_INTERVAL seconds.
    If no pulse has been seen within HEARTBEAT_TIMEOUT_MS, trips the relay.
    """
    global _heartbeat_lost

    while True:
        time.sleep(MONITOR_POLL_INTERVAL)
        age_ms = (time.time() - _last_pulse_time) * 1000

        if age_ms > HEARTBEAT_TIMEOUT_MS and not _heartbeat_lost:
            _heartbeat_lost = True
            _trip_relay()
            _store_alert(age_ms)
            _mqtt_broadcast(mqtt_client, age_ms)
            print(
                f"[HB_MONITOR] 🔴 HEARTBEAT LOST — "
                f"No pulse for {age_ms:.0f}ms. Relay CUT. "
                f"(threshold={HEARTBEAT_TIMEOUT_MS:.0f}ms)"
            )

        elif age_ms <= HEARTBEAT_TIMEOUT_MS and _heartbeat_lost:
            # Device came back — restore relay
            _heartbeat_lost = False
            _restore_relay()
            print(f"[HB_MONITOR] ✅ Heartbeat restored — relay re-engaged.")


def _trip_relay() -> None:
    """Cuts power to the door relay (GPIO LOW = MOSFET off = fail-secure)."""
    if _gpio_available:
        GPIO.output(RELAY_KILL_PIN, GPIO.LOW)


def _restore_relay() -> None:
    """Re-engages the relay when heartbeat resumes."""
    if _gpio_available:
        GPIO.output(RELAY_KILL_PIN, GPIO.HIGH)


def _store_alert(age_ms: float) -> None:
    details = (
        f"HEARTBEAT_LOSS: No GPIO pulse for {age_ms:.0f}ms "
        f"(threshold={HEARTBEAT_TIMEOUT_MS:.0f}ms). "
        f"Relay cut independently of MQTT. Possible jammer or MQTT DDoS."
    )
    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute(
                "INSERT INTO alerts (device_id, event_type, timestamp, details) "
                "VALUES (?, ?, ?, ?)",
                ("ESP32_GATEWAY", "HEARTBEAT_LOSS", int(time.time()), details),
            )
            conn.commit()
    except sqlite3.OperationalError:
        pass


def _mqtt_broadcast(client, age_ms: float) -> None:
    if client is None:
        return
    import json
    try:
        payload = json.dumps({
            "event":       "HEARTBEAT_LOSS",
            "age_ms":      round(age_ms, 1),
            "action":      "RELAY_CUT",
            "timestamp":   int(time.time()),
        })
        client.publish("security/lockdown", payload, qos=2, retain=False)
    except Exception as exc:
        print(f"[HB_MONITOR] MQTT publish failed: {exc}")
