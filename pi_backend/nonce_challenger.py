#!/usr/bin/env python3
"""
Dynamic Nonce Challenger — FPGA Replay Defeat
==============================================
Patent Claim 4: "The nonce-based mathematical challenge system that changes
CPU timing per authentication, defeating FPGA replay attacks."

How it works:
    Every 30 seconds, the Pi sends a random nonce to the ESP32.
    The ESP32 must find the smallest integer `x` such that (nonce + x) % 1000 == 0.
    The ESP32 reports its solve time in microseconds.

    FPGA clones solve in < 10µs (dedicated silicon).
    Real ESP32 solves in 50–2000µs (general-purpose CPU).
    This timing difference is the detection signal.

Topics:
    Pi → ESP32:   perimeter/nonce_challenge   {device_id, nonce, timeout_ms}
    ESP32 → Pi:   perimeter/nonce_response    {device_id, nonce, solution, solve_time_us}

Run standalone:
    python3 pi_backend/nonce_challenger.py

Or import and call issue_challenge() from the main AI engine.
"""

import json
import logging
import os
import random
import sqlite3
import time
import threading

from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [NONCE] %(levelname)s: %(message)s",
)
log = logging.getLogger(__name__)

MQTT_BROKER = os.environ.get("MQTT_BROKER", "localhost")
MQTT_PORT = int(os.environ.get("MQTT_PORT", "1883"))
CHALLENGE_INTERVAL_S = int(os.environ.get("NONCE_INTERVAL_S", "30"))
CHALLENGE_TIMEOUT_S = float(os.environ.get("NONCE_TIMEOUT_S", "8.0"))
FPGA_THRESHOLD_US = int(os.environ.get("FPGA_THRESHOLD_US", "10"))
TARGET_DEVICE = os.environ.get("NONCE_TARGET_DEVICE", "ESP32_CAM_PERIMETER")

_BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("IOT_DB_PATH", os.path.join(_BASE_DIR, "security.db"))

# Active pending challenges: {device_id: {nonce, sent_at, expected}}
pending: dict = {}


def expected_solution(nonce: int) -> int:
    """
    Find the smallest x >= 0 such that (nonce + x) % 1000 == 0.
    This is a trivial computation for the ESP32 but creates a unique
    answer per nonce, preventing replay of old solutions.
    """
    remainder = nonce % 1000
    if remainder == 0:
        return 0
    return 1000 - remainder


def issue_challenge(client, device_id: str) -> None:
    """Issue a unique nonce challenge to a specific device."""
    seed = int(time.time() * 1000) ^ random.randint(0, 0xFFFF)
    nonce = seed % 1000000

    pending[device_id] = {
        "nonce": nonce,
        "sent_at": time.time(),
        "expected": expected_solution(nonce),
    }

    payload = json.dumps({
        "device_id": device_id,
        "nonce": nonce,
        "timeout_ms": int(CHALLENGE_TIMEOUT_S * 1000),
    })
    client.publish("perimeter/nonce_challenge", payload)
    log.info(f"🔢 Nonce challenge issued to {device_id}: nonce={nonce}")


def _verify_response(data: dict) -> tuple[str, str]:
    """
    Verify a nonce response.
    Returns (status, reason) tuple.
    """
    dev = data.get("device_id", "")
    nonce = data.get("nonce", -1)
    solution = data.get("solution", -1)
    solve_us = data.get("solve_time_us", 0)

    if dev not in pending:
        return "REJECTED", f"Unsolicited nonce response from {dev}"

    p = pending.pop(dev)
    elapsed = time.time() - p["sent_at"]

    if elapsed > CHALLENGE_TIMEOUT_S:
        return "TIMEOUT", f"Nonce response from {dev} arrived {elapsed:.1f}s late"

    if solution != p["expected"]:
        return "WRONG_SOLUTION", (
            f"Wrong nonce solution from {dev}: "
            f"got {solution}, expected {p['expected']}"
        )

    # FPGA detection: real ESP32 takes 50-2000µs; FPGA < 10µs
    if solve_us < FPGA_THRESHOLD_US:
        return "FPGA_SUSPECTED", (
            f"FPGA replay suspected from {dev}: "
            f"solve_time={solve_us}µs < {FPGA_THRESHOLD_US}µs threshold"
        )

    return "VERIFIED", f"Nonce verified for {dev} in {solve_us}µs"


def _log_nonce_event(device_id: str, event_type: str, details: str) -> None:
    """Persist nonce verification results to the alerts table."""
    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute(
                "INSERT INTO alerts (device_id, event_type, timestamp, details) "
                "VALUES (?, ?, ?, ?)",
                (device_id, event_type, int(time.time()), details),
            )
            conn.commit()
    except sqlite3.OperationalError as exc:
        log.warning(f"DB write skipped: {exc}")


def on_message(client, userdata, msg):
    """Handle nonce responses from ESP32 devices."""
    if msg.topic != "perimeter/nonce_response":
        return

    try:
        d = json.loads(msg.payload.decode())
    except (json.JSONDecodeError, UnicodeDecodeError):
        log.warning("Invalid nonce response payload")
        return

    dev = d.get("device_id", "UNKNOWN")
    status, reason = _verify_response(d)

    if status == "VERIFIED":
        log.info(f"✅ {reason}")
    else:
        log.warning(f"⚠️ {status}: {reason}")
        _log_nonce_event(dev, f"NONCE_{status}", reason)

        # Broadcast FPGA alerts
        if status == "FPGA_SUSPECTED":
            client.publish("dashboard/threat", json.dumps({
                "level": "RED",
                "reason": "FPGA_REPLAY_ATTACK",
                "device": dev,
            }))
            client.publish("alerts/telegram", json.dumps({
                "message": (
                    f"⚡ FPGA REPLAY ATTACK SUSPECTED!\n"
                    f"Device: {dev}\n"
                    f"Solve time: {d.get('solve_time_us', '?')}µs\n"
                    f"Threshold: {FPGA_THRESHOLD_US}µs"
                ),
            }))


def on_connect(client, userdata, flags, reason_code, properties=None):
    """Subscribe to nonce response topic on MQTT connect."""
    if reason_code == 0:
        client.subscribe("perimeter/nonce_response")
        log.info("✅ Nonce challenger connected to MQTT")


def _challenge_loop(client):
    """Background thread issuing periodic challenges."""
    while True:
        try:
            issue_challenge(client, TARGET_DEVICE)
        except Exception as exc:
            log.error(f"Challenge issue failed: {exc}")
        time.sleep(CHALLENGE_INTERVAL_S)


def start_nonce_challenger(mqtt_client=None) -> threading.Thread:
    """
    Start the nonce challenger as a background daemon thread.

    Args:
        mqtt_client: Active paho MQTT client. If None, creates its own.

    Returns:
        The background thread (already started, daemon=True).
    """
    if mqtt_client is None:
        try:
            import paho.mqtt.client as mqtt_lib
            mqtt_client = mqtt_lib.Client(
                mqtt_lib.CallbackAPIVersion.VERSION2,
                client_id="PI_NONCE_CHALLENGER",
            )
            mqtt_client.on_connect = on_connect
            mqtt_client.on_message = on_message
            mqtt_client.connect(MQTT_BROKER, MQTT_PORT, 60)
            mqtt_client.loop_start()
        except Exception as exc:
            log.error(f"MQTT connection failed: {exc}")
            return None

    t = threading.Thread(
        target=_challenge_loop,
        args=(mqtt_client,),
        name="NonceChallengerLoop",
        daemon=True,
    )
    t.start()
    log.info(
        f"🔢 Nonce challenger started "
        f"(interval={CHALLENGE_INTERVAL_S}s, target={TARGET_DEVICE})"
    )
    return t


# ── Standalone entry point ─────────────────────────────────────────────────────

def main():
    """Run as a standalone service."""
    try:
        import paho.mqtt.client as mqtt
    except ImportError:
        raise SystemExit("paho-mqtt required: pip install paho-mqtt")

    log.info("🔢 Starting Nonce Challenger Service...")

    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
    client.on_connect = on_connect
    client.on_message = on_message

    while True:
        try:
            client.connect(MQTT_BROKER, MQTT_PORT, 60)
            break
        except OSError as exc:
            log.warning(f"MQTT connect failed: {exc}. Retrying in 5s...")
            time.sleep(5)

    # Start the periodic challenge thread
    threading.Thread(
        target=_challenge_loop,
        args=(client,),
        name="NonceChallengerLoop",
        daemon=True,
    ).start()

    # Block on MQTT loop
    client.loop_forever()


if __name__ == "__main__":
    main()
