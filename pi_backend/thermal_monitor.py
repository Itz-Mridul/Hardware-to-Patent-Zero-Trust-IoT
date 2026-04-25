#!/usr/bin/env python3
"""
Thermal Monitor Module — Hardened v2 (Dual-Sensor Validation)
==============================================================
Closes the "Thermal Ghost" loophole.

Original weakness:
    A focused IR laser could heat the $2 DHT22 plastic casing to 70°C
    in seconds without the Pi's CPU warming at all, triggering a
    self-inflicted hardware kill that gives the attacker physical access.

New defence — Differential Temperature Logic:
    We compare TWO independent temperature sources:

    1. Air Temperature  → DHT22 sensor (via MQTT from the ESP32)
    2. SoC Temperature  → Pi's own silicon die (vcgencmd measure_temp
                          or /sys/class/thermal/thermal_zone0/temp)

    Decision table:
    ┌──────────────────┬────────────────────┬────────────────────────────────┐
    │ Air ≥ 70°C?      │ CPU ≥ 60°C?        │ Action                         │
    ├──────────────────┼────────────────────┼────────────────────────────────┤
    │ No               │ No                 │ Normal — no action              │
    │ No               │ Yes                │ CPU_OVERHEAT — real emergency   │
    │ Yes              │ Yes                │ EMERGENCY_THERMAL — real fire   │
    │ Yes              │ No (Δ > 20°C gap)  │ SENSOR_TAMPER — IR laser attack │
    └──────────────────┴────────────────────┴────────────────────────────────┘
"""

import os
import sqlite3
import subprocess
import time
from typing import Optional

# ── Thresholds (all overridable via env vars) ──────────────────────────────────
THERMAL_KILL_THRESHOLD  = float(os.environ.get("THERMAL_KILL_THRESHOLD",  "70.0"))
CPU_KILL_THRESHOLD      = float(os.environ.get("CPU_KILL_THRESHOLD",      "80.0"))
CPU_WARN_THRESHOLD      = float(os.environ.get("CPU_WARN_THRESHOLD",      "60.0"))
TAMPER_DELTA_THRESHOLD  = float(os.environ.get("TAMPER_DELTA_THRESHOLD",  "20.0"))

_BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH   = os.environ.get("IOT_DB_PATH", os.path.join(_BASE_DIR, "security.db"))
LOCKDOWN_TOPIC = "security/lockdown"


# ── SoC temperature reader ─────────────────────────────────────────────────────

def get_pi_cpu_temp() -> Optional[float]:
    """
    Reads the Raspberry Pi's internal SoC temperature.

    Tries three methods in order:
        1. /sys/class/thermal/thermal_zone0/temp  (Linux sysfs, most reliable)
        2. vcgencmd measure_temp                   (Pi-specific binary)
        3. Returns None if both fail (Mac / CI env)
    """
    # Method 1: sysfs (works on Pi and most Linux SBCs)
    sysfs = "/sys/class/thermal/thermal_zone0/temp"
    if os.path.exists(sysfs):
        try:
            with open(sysfs) as f:
                return int(f.read().strip()) / 1000.0  # millidegrees → °C
        except (OSError, ValueError):
            pass

    # Method 2: vcgencmd (Pi-specific, may not be in PATH)
    try:
        result = subprocess.run(
            ["vcgencmd", "measure_temp"],
            capture_output=True, text=True, timeout=2
        )
        # Output: "temp=47.8'C"
        raw = result.stdout.strip()
        if raw.startswith("temp="):
            return float(raw.removeprefix("temp=").removesuffix("'C"))
    except (FileNotFoundError, subprocess.TimeoutExpired, ValueError):
        pass

    return None   # graceful fallback for non-Pi environments


# ── Main decision engine ───────────────────────────────────────────────────────

def handle_thermal_event(
    device_id: str,
    temperature: float,          # Air temp from DHT22 via ESP32
    mqtt_client=None,
    cpu_temp: Optional[float] = None,   # Injected by tests; auto-read if None
) -> dict:
    """
    Dual-sensor thermal evaluation engine.

    Args:
        device_id:    Reporting ESP32 ID.
        temperature:  Air temperature (°C) from DHT22.
        mqtt_client:  Optional paho client for lockdown MQTT broadcast.
        cpu_temp:     Override CPU temp (used in unit tests). Auto-reads if None.

    Returns:
        A dict with keys: event_type, action_taken, air_temp, cpu_temp, details
    """
    if cpu_temp is None:
        cpu_temp = get_pi_cpu_temp()

    timestamp = int(time.time())

    # ── Case 1: Normal ─────────────────────────────────────────────────────────
    air_hot = temperature >= THERMAL_KILL_THRESHOLD
    cpu_hot = (cpu_temp is not None) and (cpu_temp >= CPU_WARN_THRESHOLD)
    cpu_critical = (cpu_temp is not None) and (cpu_temp >= CPU_KILL_THRESHOLD)

    if not air_hot and not cpu_critical:
        return {
            "event_type": "NORMAL",
            "action_taken": False,
            "air_temp": temperature,
            "cpu_temp": cpu_temp,
            "details": "Temperature nominal.",
        }

    # ── Case 2: CPU Overheat only (no air spike) ───────────────────────────────
    if not air_hot and cpu_critical:
        details = (
            f"CPU OVERHEAT: SoC={cpu_temp:.1f}°C ≥ {CPU_KILL_THRESHOLD}°C "
            f"(air={temperature:.1f}°C — normal). Software/thermal paste fault."
        )
        _store_alert(device_id, "CPU_OVERHEAT", timestamp, details)
        _mqtt_lockdown(mqtt_client, "CPU_OVERHEAT", device_id, temperature, cpu_temp, timestamp)
        print(f"[THERMAL] ⚠️  CPU OVERHEAT: {device_id} SoC={cpu_temp:.1f}°C")
        return {
            "event_type": "CPU_OVERHEAT",
            "action_taken": True,
            "air_temp": temperature,
            "cpu_temp": cpu_temp,
            "details": details,
        }

    # ── Case 3: Sensor Tamper (air hot, CPU cool — IR laser / lighter attack) ──
    delta = temperature - (cpu_temp if cpu_temp is not None else temperature)
    if air_hot and not cpu_hot and delta >= TAMPER_DELTA_THRESHOLD:
        details = (
            f"SENSOR TAMPER DETECTED: Air={temperature:.1f}°C ≥ threshold, "
            f"but SoC={cpu_temp:.1f}°C — Δ={delta:.1f}°C > {TAMPER_DELTA_THRESHOLD}°C. "
            f"Probable IR laser or focused heat source on DHT22 casing."
        )
        _store_alert(device_id, "SENSOR_TAMPER", timestamp, details)
        print(f"[THERMAL] 🎯 SENSOR TAMPER: {device_id} — air={temperature:.1f}°C, "
              f"cpu={cpu_temp}°C")
        # We do NOT power-kill here — that's what the attacker wants.
        # Instead we raise a silent alert and ignore the rogue reading.
        return {
            "event_type": "SENSOR_TAMPER",
            "action_taken": False,   # Withhold the kill — it's a trap
            "air_temp": temperature,
            "cpu_temp": cpu_temp,
            "details": details,
        }

    # ── Case 4: Both sensors agree — real emergency ────────────────────────────
    details = (
        f"CRITICAL: Air={temperature:.1f}°C ≥ {THERMAL_KILL_THRESHOLD}°C "
        f"AND SoC={cpu_temp}°C. Real thermal emergency — power kill triggered."
    )
    _store_alert(device_id, "EMERGENCY_THERMAL", timestamp, details)
    _mqtt_lockdown(mqtt_client, "EMERGENCY_THERMAL", device_id, temperature, cpu_temp, timestamp)
    print(f"[THERMAL] 🔥 EMERGENCY: {device_id} @ air={temperature:.1f}°C "
          f"cpu={cpu_temp}°C — lockdown!")
    return {
        "event_type": "EMERGENCY_THERMAL",
        "action_taken": True,
        "air_temp": temperature,
        "cpu_temp": cpu_temp,
        "details": details,
    }


# ── MQTT broadcast ─────────────────────────────────────────────────────────────

def _mqtt_lockdown(client, event_type, device_id, air_temp, cpu_temp, timestamp):
    if client is None:
        return
    import json
    try:
        payload = json.dumps({
            "event": event_type,
            "device_id": device_id,
            "air_temp": air_temp,
            "cpu_temp": cpu_temp,
            "timestamp": timestamp,
            "action": "POWER_CUT",
        })
        client.publish(LOCKDOWN_TOPIC, payload, qos=2, retain=False)
    except Exception as exc:
        print(f"[THERMAL] MQTT publish failed: {exc}")


# ── DB helpers ─────────────────────────────────────────────────────────────────

def _store_alert(device_id: str, event_type: str, timestamp: int, details: str) -> None:
    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute(
                "INSERT INTO alerts (device_id, event_type, timestamp, details) "
                "VALUES (?, ?, ?, ?)",
                (device_id, event_type, timestamp, details),
            )
            conn.commit()
    except sqlite3.OperationalError as exc:
        print(f"[THERMAL] DB write skipped: {exc}")


def get_thermal_alerts(limit: int = 50) -> list:
    """Returns recent thermal events for the dashboard."""
    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT * FROM alerts "
                "WHERE event_type IN "
                "('EMERGENCY_THERMAL','SENSOR_TAMPER','CPU_OVERHEAT') "
                "ORDER BY timestamp DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(r) for r in rows]
    except sqlite3.OperationalError:
        return []
