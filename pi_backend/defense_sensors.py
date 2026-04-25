#!/usr/bin/env python3
"""
Pi Physical Defense Sensors — SW-420 + DHT22 Integration
=========================================================
Phase 2: Physical Defense Scripts (Hardware Interrupts)

This script runs as a dedicated daemon on the Raspberry Pi and manages
the two physical sensors wired directly to the GPIO header:

  1. SW-420 Vibration Sensor (Kinetic Tamper Detection)
     ┌─────────────────────────────────────────────────────┐
     │  SW-420 OUT → GPIO 17 (BCM) — with 10kΩ pull-down  │
     │  SW-420 VCC → 3.3V                                  │
     │  SW-420 GND → GND                                   │
     └─────────────────────────────────────────────────────┘
     Behaviour: A vibration/tilt fires a RISING EDGE interrupt.
     Response:  Immediately calls emergency_wipe() to zero all
                keys in RAM, then logs PHYSICAL_TAMPER to DB
                and broadcasts lockdown via MQTT.

  2. DHT22 Temperature/Humidity Sensor (Ambient Air Monitoring)
     ┌─────────────────────────────────────────────────────┐
     │  DHT22 DATA → GPIO 4 (BCM) — with 4.7kΩ pull-up   │
     │  DHT22 VCC  → 3.3V                                  │
     │  DHT22 GND  → GND                                   │
     └─────────────────────────────────────────────────────┘
     Behaviour: Reads temperature every 5 seconds.
     Response:  Passes reading to thermal_monitor.handle_thermal_event()
                which performs dual-sensor validation (DHT22 vs SoC temp).

Run on Pi:
    python3 pi_backend/defense_sensors.py

Alternatively, this module's functions are imported by iot_server.py
which starts both monitors as background threads on startup.
"""

import os
import signal
import sqlite3
import sys
import threading
import time
import json
from typing import Optional

# ── GPIO abstraction ────────────────────────────────────────────────────────
_GPIO_AVAILABLE = False
GPIO = None

try:
    import RPi.GPIO as GPIO    # type: ignore
    _GPIO_AVAILABLE = True
except ImportError:
    pass   # Mac / CI — simulation mode

# ── Configuration ───────────────────────────────────────────────────────────
SW420_PIN          = int(os.environ.get("SW420_GPIO_PIN",    "17"))
DHT22_PIN          = int(os.environ.get("DHT22_GPIO_PIN",    "4"))
DHT22_INTERVAL_S   = float(os.environ.get("DHT22_INTERVAL_S", "5"))
DEBOUNCE_MS        = int(os.environ.get("SW420_DEBOUNCE_MS", "500"))

_BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH   = os.environ.get("IOT_DB_PATH", os.path.join(_BASE_DIR, "security.db"))
MQTT_BROKER = os.environ.get("MQTT_BROKER", "localhost")

# ── Shared state ────────────────────────────────────────────────────────────
_last_tamper_time: float = 0.0
_tamper_count:     int   = 0
_mqtt_client            = None   # Injected at startup


# ═══════════════════════════════════════════════════════════════════════════
# SW-420 Vibration / Tamper Detection
# ═══════════════════════════════════════════════════════════════════════════

def _on_vibration_interrupt(channel: int) -> None:
    """
    GPIO interrupt handler — fires on RISING EDGE from SW-420.

    This function runs in a separate thread (GPIO event thread),
    so it must be thread-safe and non-blocking.
    """
    global _last_tamper_time, _tamper_count

    now = time.time()
    if now - _last_tamper_time < (DEBOUNCE_MS / 1000.0):
        return   # Debounce — ignore mechanical bounce

    _last_tamper_time = now
    _tamper_count    += 1

    print(f"\n[TAMPER] 🔴 SW-420 TRIGGERED! Count={_tamper_count} @ {now:.3f}")
    print("[TAMPER] ⚡ EXECUTING VOLATILE MEMORY WIPE...")

    # ── 1. Zero all cryptographic keys in RAM immediately ─────────────────
    try:
        from pi_backend.key_vault import emergency_wipe
        emergency_wipe()
        print("[TAMPER] ✅ Key vault wiped.")
    except Exception as exc:
        print(f"[TAMPER] Key wipe error: {exc}")

    # ── 2. Log the tamper event to the forensic database ──────────────────
    _log_tamper_event("PHYSICAL_TAMPER", _tamper_count, channel)

    # ── 3. Publish lockdown command to all ESP32 nodes ────────────────────
    if _mqtt_client:
        try:
            payload = json.dumps({
                "event":     "PHYSICAL_TAMPER",
                "action":    "RELAY_CUT",
                "count":     _tamper_count,
                "timestamp": int(now),
            })
            _mqtt_client.publish("security/lockdown", payload, qos=2, retain=False)
            print("[TAMPER] Lockdown broadcast sent.")
        except Exception as exc:
            print(f"[TAMPER] MQTT publish error: {exc}")

    # ── 4. Alert via Telegram ──────────────────────────────────────────────
    _send_tamper_telegram(_tamper_count)


def start_tamper_monitor(mqtt_client=None) -> None:
    """
    Configures the SW-420 GPIO interrupt and starts monitoring.
    Call once at server startup.

    Args:
        mqtt_client: Active paho MQTT client for lockdown broadcasts.
    """
    global _mqtt_client
    _mqtt_client = mqtt_client

    if not _GPIO_AVAILABLE:
        print(f"[TAMPER] RPi.GPIO not available — running in simulation mode.")
        print(f"         (On Pi: SW-420 → GPIO BCM {SW420_PIN})")
        return

    GPIO.setmode(GPIO.BCM)
    GPIO.setwarnings(False)
    GPIO.setup(SW420_PIN, GPIO.IN, pull_up_down=GPIO.PUD_DOWN)
    GPIO.add_event_detect(
        SW420_PIN,
        GPIO.RISING,
        callback=_on_vibration_interrupt,
        bouncetime=DEBOUNCE_MS,
    )
    print(f"[TAMPER] SW-420 monitor active (GPIO BCM {SW420_PIN}, "
          f"debounce={DEBOUNCE_MS}ms)")


def simulate_tamper_event() -> None:
    """Simulates a SW-420 trigger for testing without hardware."""
    _on_vibration_interrupt(channel=SW420_PIN)


# ═══════════════════════════════════════════════════════════════════════════
# DHT22 Temperature / Humidity Reader
# ═══════════════════════════════════════════════════════════════════════════

def _read_dht22() -> Optional[dict]:
    """
    Reads temperature and humidity from DHT22 sensor.

    Tries three methods:
        1. adafruit_dht library (preferred — handles 1-Wire protocol)
        2. Adafruit CircuitPython DHT
        3. Returns None if neither is available (Mac / CI)
    """
    # Method 1: adafruit_dht (pip install adafruit-circuitpython-dht)
    try:
        import adafruit_dht          # type: ignore
        import board                 # type: ignore

        pin_map = {
            4:  board.D4,
            17: board.D17,
            27: board.D27,
            22: board.D22,
        }
        board_pin = pin_map.get(DHT22_PIN)
        if board_pin is None:
            raise ValueError(f"DHT22_PIN {DHT22_PIN} not in pin_map")

        sensor = adafruit_dht.DHT22(board_pin, use_pulseio=False)
        temp_c  = sensor.temperature
        humidity = sensor.humidity
        sensor.exit()

        if temp_c is not None and humidity is not None:
            return {"temperature": round(float(temp_c), 2),
                    "humidity":    round(float(humidity), 2)}

    except ImportError:
        pass
    except Exception as exc:
        # DHT22 is sensitive — transient read errors are normal
        pass

    # Method 2: Fallback simulated reading for development
    if os.environ.get("DHT22_SIMULATE", "false").lower() == "true":
        import random
        return {
            "temperature": round(20.0 + random.uniform(-2, 2), 2),
            "humidity":    round(45.0 + random.uniform(-5, 5), 2),
        }

    return None


def _dht22_monitor_loop() -> None:
    """
    Background thread: reads DHT22 every DHT22_INTERVAL_S seconds and
    passes the reading through dual-sensor thermal validation.
    """
    print(f"[DHT22] Monitor loop started (interval={DHT22_INTERVAL_S}s, "
          f"GPIO BCM {DHT22_PIN})")

    while True:
        reading = _read_dht22()

        if reading:
            temp = reading["temperature"]
            hum  = reading["humidity"]

            _store_environment_reading(temp, hum)

            # Publish to MQTT for dashboard display
            if _mqtt_client:
                try:
                    payload = json.dumps({
                        "device_id":   "PI_DHT22",
                        "temperature": temp,
                        "humidity":    hum,
                        "timestamp":   int(time.time()),
                    })
                    _mqtt_client.publish("mailbox/environment", payload, qos=0)
                except Exception:
                    pass

            # Pass through dual-sensor thermal validation
            try:
                from pi_backend.thermal_monitor import handle_thermal_event
                result = handle_thermal_event(
                    device_id="PI_DHT22",
                    temperature=temp,
                    mqtt_client=_mqtt_client,
                )
                event = result.get("event_type", "NORMAL")
                if event != "NORMAL":
                    print(f"[DHT22] ⚠️  Thermal event: {event} "
                          f"(air={temp}°C)")
            except Exception as exc:
                print(f"[DHT22] Thermal check error: {exc}")
        else:
            # No reading — could be sensor wiring or library issue
            if _GPIO_AVAILABLE:
                print(f"[DHT22] Read failed — check wiring on GPIO {DHT22_PIN}")

        time.sleep(DHT22_INTERVAL_S)


def start_dht22_monitor(mqtt_client=None) -> threading.Thread:
    """
    Starts the DHT22 monitor as a daemon background thread.

    Args:
        mqtt_client: Active paho MQTT client for environment publishing.

    Returns:
        The background thread (already started, daemon=True).
    """
    global _mqtt_client
    if mqtt_client:
        _mqtt_client = mqtt_client

    t = threading.Thread(target=_dht22_monitor_loop,
                         name="DHT22Monitor", daemon=True)
    t.start()
    return t


# ═══════════════════════════════════════════════════════════════════════════
# DB + Telegram helpers
# ═══════════════════════════════════════════════════════════════════════════

def _log_tamper_event(event_type: str, count: int, channel: int) -> None:
    details = (
        f"SW-420 VIBRATION DETECTED on GPIO {channel}. "
        f"Tamper count={count}. "
        f"Emergency volatile memory wipe executed. "
        f"All cryptographic keys zeroed from RAM."
    )
    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute(
                "INSERT INTO alerts (device_id, event_type, timestamp, details) "
                "VALUES (?, ?, ?, ?)",
                ("SW420_SENSOR", event_type, int(time.time()), details),
            )
            conn.commit()
    except sqlite3.OperationalError as exc:
        print(f"[TAMPER] DB write skipped: {exc}")


def _store_environment_reading(temperature: float, humidity: float) -> None:
    """Persist the latest DHT22 reading for the dashboard environment endpoint."""
    try:
        now = time.time()
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute(
                """
                INSERT INTO heartbeats (
                    device_id, timestamp, temperature, humidity, rssi, free_heap,
                    inter_packet_delay, packet_size, received_at, is_legitimate
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "PI_DHT22",
                    int(now),
                    temperature,
                    humidity,
                    None,
                    None,
                    None,
                    None,
                    now,
                    1,
                ),
            )
            conn.commit()
    except sqlite3.OperationalError as exc:
        print(f"[DHT22] DB write skipped: {exc}")


def _send_tamper_telegram(count: int) -> None:
    try:
        import requests
        token   = os.environ.get("TELEGRAM_BOT_TOKEN", "")
        chat_id = os.environ.get("TELEGRAM_CHAT_ID", "")
        if not token or not chat_id:
            return
        msg = (
            "🚨 <b>PHYSICAL TAMPER DETECTED</b> 🚨\n\n"
            "<b>Sensor:</b> SW-420 Vibration\n"
            f"<b>Count:</b> {count}\n"
            "<b>Action:</b> Volatile memory wipe executed.\n"
            "All cryptographic keys have been zeroed.\n\n"
            "⚠️ <b>Physical security breach in progress!</b>"
        )
        requests.post(
            f"https://api.telegram.org/bot{token}/sendMessage",
            json={"chat_id": chat_id, "text": msg, "parse_mode": "HTML"},
            timeout=5,
        )
    except Exception as exc:
        print(f"[TAMPER] Telegram error: {exc}")


def get_tamper_alerts(limit: int = 50) -> list:
    """Returns recent physical tamper events for the dashboard."""
    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT * FROM alerts WHERE event_type='PHYSICAL_TAMPER' "
                "ORDER BY timestamp DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(r) for r in rows]
    except sqlite3.OperationalError:
        return []


def get_sensor_status() -> dict:
    """Returns current sensor health for the dashboard /api/sensors endpoint."""
    return {
        "gpio_available": _GPIO_AVAILABLE,
        "sw420_pin":      SW420_PIN,
        "dht22_pin":      DHT22_PIN,
        "tamper_count":   _tamper_count,
        "last_tamper_at": _last_tamper_time or None,
    }


# ═══════════════════════════════════════════════════════════════════════════
# Standalone service entry point
# ═══════════════════════════════════════════════════════════════════════════

def _start_mqtt() -> object:
    """Starts a minimal MQTT client for publishing sensor events."""
    try:
        import paho.mqtt.client as mqtt_lib
        client = mqtt_lib.Client(mqtt_lib.CallbackAPIVersion.VERSION2,
                                 client_id="PI_SENSOR_DAEMON")
        client.connect(MQTT_BROKER, int(os.environ.get("MQTT_PORT", "1883")), 60)
        client.loop_start()
        return client
    except Exception as exc:
        print(f"[SENSOR] MQTT unavailable: {exc}")
        return None


def main() -> None:
    print("=" * 60)
    print("  Zero-Trust Physical Defense Sensors")
    print("  Press Ctrl+C to stop.")
    print("=" * 60)

    client = _start_mqtt()

    start_tamper_monitor(mqtt_client=client)
    start_dht22_monitor(mqtt_client=client)

    # Graceful shutdown on Ctrl+C / SIGTERM
    def _shutdown(sig, frame):
        print("\n[SENSOR] Shutting down...")
        if _GPIO_AVAILABLE:
            GPIO.cleanup()
        sys.exit(0)

    signal.signal(signal.SIGINT,  _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    print("[SENSOR] Both sensors active. Monitoring...")

    # Keep main thread alive so daemon threads keep running
    while True:
        time.sleep(10)


if __name__ == "__main__":
    main()
