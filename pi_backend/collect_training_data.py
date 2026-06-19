#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║         Zero-Trust IoT — ML Training Data Collector              ║
║            Captures Real ESP32 Hardware Fingerprints             ║
╠══════════════════════════════════════════════════════════════════╣
║  Subscribes to MQTT and records heartbeat packets into a DB.     ║
║  Captures all 6 features the CNN-LSTM needs:                     ║
║    rssi · packet_size · free_heap ·                              ║
║    inter_packet_delay · temperature · humidity                   ║
║                                                                  ║
║  Usage:                                                          ║
║    python3 pi_backend/collect_training_data.py                   ║
║                                                                  ║
║  Stop when you have 200+ samples (Ctrl+C)                        ║
║  Then run: python3 pi_backend/merge_datasets.py                  ║
╚══════════════════════════════════════════════════════════════════╝
"""

import json
import os
import sqlite3
import time

import paho.mqtt.client as mqtt

# ── Configuration ─────────────────────────────────────────────────────────────
_BASE_DIR  = os.path.dirname(os.path.abspath(__file__))
DB_PATH    = os.environ.get("TRAINING_DB_PATH",
                             os.path.join(_BASE_DIR, "training_data.db"))
MQTT_BROKER = os.environ.get("MQTT_BROKER", "10.176.62.161")
MQTT_PORT   = int(os.environ.get("MQTT_PORT", "1883"))
MQTT_TOPIC  = os.environ.get("MQTT_TOPIC",  "mailbox/heartbeat")

# Fallbacks if the ESP32 doesn't send a field (no sensors connected)
DEFAULT_RSSI        = int(os.environ.get("DEFAULT_RSSI",   "-50"))
DEFAULT_PACKET_SIZE = int(os.environ.get("DEFAULT_PKT_SZ", "256"))
DEFAULT_FREE_HEAP   = int(os.environ.get("DEFAULT_HEAP",   "200000"))
DEFAULT_TEMP        = float(os.environ.get("DEFAULT_TEMP", "0.0"))
DEFAULT_HUM         = float(os.environ.get("DEFAULT_HUM",  "0.0"))

# ── State ─────────────────────────────────────────────────────────────────────
_last_time:   float = 0.0
_sample_count: int  = 0
_start_time:  float = time.time()

BANNER_WIDTH = 68


# ── Database ──────────────────────────────────────────────────────────────────

def init_db() -> None:
    """Creates the heartbeats table with all 6 ML features."""
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS heartbeats (
                id                  INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id           TEXT    NOT NULL DEFAULT 'UNKNOWN',
                rssi                INTEGER NOT NULL DEFAULT -50,
                packet_size         INTEGER NOT NULL DEFAULT 256,
                free_heap           INTEGER NOT NULL DEFAULT 200000,
                inter_packet_delay  REAL    NOT NULL DEFAULT 0.0,
                temperature         REAL    NOT NULL DEFAULT 0.0,
                humidity            REAL    NOT NULL DEFAULT 0.0,
                is_legitimate       INTEGER NOT NULL DEFAULT 1,
                received_at         REAL    NOT NULL
            )
        """)
        conn.commit()


def insert_sample(device_id: str, rssi: int, packet_size: int,
                  free_heap: int, ipd: float,
                  temperature: float, humidity: float,
                  is_legitimate: int = 1) -> int:
    """Inserts one heartbeat sample. Returns the new row ID."""
    with sqlite3.connect(DB_PATH) as conn:
        cur = conn.execute("""
            INSERT INTO heartbeats
              (device_id, rssi, packet_size, free_heap,
               inter_packet_delay, temperature, humidity,
               is_legitimate, received_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (device_id, rssi, packet_size, free_heap,
              ipd, temperature, humidity, is_legitimate, time.time()))
        conn.commit()
        return cur.lastrowid


def sample_count_from_db() -> int:
    """Returns the current row count in the heartbeats table."""
    try:
        with sqlite3.connect(DB_PATH) as conn:
            row = conn.execute("SELECT COUNT(*) FROM heartbeats").fetchone()
            return row[0] if row else 0
    except sqlite3.OperationalError:
        return 0


# ── Pretty Print ──────────────────────────────────────────────────────────────

def _bar(value: float, max_val: float, width: int = 20, char: str = "█") -> str:
    """Returns a text progress bar."""
    filled = int((value / max_val) * width) if max_val > 0 else 0
    filled = max(0, min(filled, width))
    return char * filled + "░" * (width - filled)


def _rssi_bar(rssi: int) -> str:
    """Returns a coloured RSSI bar label."""
    if rssi >= -50:
        label = "Excellent"
    elif rssi >= -65:
        label = "Good     "
    elif rssi >= -75:
        label = "Fair     "
    else:
        label = "Weak     "
    bar = _bar(rssi + 100, 70, width=12)
    return f"{bar} {label} ({rssi} dBm)"


def print_sample(sample_id: int, device_id: str, rssi: int,
                 packet_size: int, free_heap: int, ipd: float,
                 temperature: float, humidity: float) -> None:
    """Prints a beautiful single-line sample row."""
    elapsed = time.time() - _start_time
    total_in_db = sample_count_from_db()
    progress = min(100, int(total_in_db / 200 * 100))
    prog_bar = _bar(progress, 100, width=20)

    line1 = f"  Sample #{sample_id:<5} │ Device: {device_id}"
    line2 = f"  [NET]  RSSI       : {_rssi_bar(rssi)}"
    line3 = f"  [TIME] IPD        : {ipd:<10.4f} s"
    line4 = f"  [MEM]  Free Heap  : {f'{free_heap:,}':<10} bytes"
    line5 = f"  [PKT]  Pkt Size   : {str(packet_size):<10} bytes"
    line6 = f"  [TEMP] Temp       : {temperature:<10.1f} °C"
    line7 = f"  [HUM]  Humidity   : {humidity:<10.1f} %"
    line8 = f"  Progress: [{prog_bar}] {progress:>3}%  ({_sample_count}/200)"
    line9 = f"  Elapsed: {elapsed:>6.0f}s"

    print(
        f"\n  ┌{'─' * 57}┐\n"
        f"  │{line1:<57}│\n"
        f"  ├{'─' * 57}┤\n"
        f"  │{line2:<57}│\n"
        f"  │{line3:<57}│\n"
        f"  │{line4:<57}│\n"
        f"  │{line5:<57}│\n"
        f"  │{line6:<57}│\n"
        f"  │{line7:<57}│\n"
        f"  ├{'─' * 57}┤\n"
        f"  │{line8:<57}│\n"
        f"  │{line9:<57}│\n"
        f"  └{'─' * 57}┘"
    )

    if _sample_count == 200:
        end1 = "  [OK] 200 SAMPLES REACHED! You can stop now (Ctrl+C)."
        end2 = "  Next step:"
        end3 = "    python3 pi_backend/merge_datasets.py"
        end4 = "    python3 ml_models/train_model.py"

        print(
            f"\n  ╔{'═' * 57}╗\n"
            f"  ║{end1:<57}║\n"
            f"  ║{end2:<57}║\n"
            f"  ║{end3:<57}║\n"
            f"  ║{end4:<57}║\n"
            f"  ╚{'═' * 57}╝\n"
        )


# ── MQTT Callbacks ────────────────────────────────────────────────────────────

def on_connect(client, userdata, flags, reason_code, properties=None) -> None:
    if reason_code == 0:
        client.subscribe(MQTT_TOPIC)
        db_name = os.path.basename(DB_PATH)
        line1 = f"  [OK] Connected to MQTT broker at {MQTT_BROKER}:{MQTT_PORT}"
        line2 = f"  [NET] Subscribed to: {MQTT_TOPIC}"
        line3 = f"  [DB]  Database: {db_name}"

        print(
            f"\n  ╔{'═' * 66}╗\n"
            f"  ║{line1:<66}║\n"
            f"  ║{line2:<66}║\n"
            f"  ║{line3:<66}║\n"
            f"  ╚{'═' * 66}╝\n"
        )
    else:
        print(f"  ❌  MQTT connection FAILED (code {reason_code}). Check broker settings.")


def on_message(client, userdata, message) -> None:
    global _last_time, _sample_count

    now = time.time()
    ipd = now - _last_time if _last_time else 0.0
    _last_time = now

    try:
        data = json.loads(message.payload.decode("utf-8", errors="ignore"))
    except json.JSONDecodeError:
        data = {}

    device_id   = str(data.get("device_id",  "UNKNOWN"))
    rssi        = int(data.get("rssi",         DEFAULT_RSSI))
    packet_size = int(data.get("packet_size",  DEFAULT_PACKET_SIZE))
    free_heap   = int(data.get("free_heap",    DEFAULT_FREE_HEAP))
    temperature = float(data.get("temperature", DEFAULT_TEMP))
    humidity    = float(data.get("humidity",    DEFAULT_HUM))

    sample_id = insert_sample(
        device_id, rssi, packet_size, free_heap,
        ipd, temperature, humidity, is_legitimate=1
    )
    _sample_count += 1
    print_sample(sample_id, device_id, rssi, packet_size,
                 free_heap, ipd, temperature, humidity)


# ── Entry Point ───────────────────────────────────────────────────────────────

def main() -> None:
    init_db()

    line1 = "Zero-Trust IoT — ML Training Data Collector"
    line2 = "Collecting LEGITIMATE device heartbeats"
    line3 = "  Goal   : 200 samples minimum"
    line4 = "  Action : Power on your ESP32s and wait..."
    line5 = "  Stop   : Press Ctrl+C when done."

    print(
        f"\n  ╔{'═' * 66}╗\n"
        f"  ║{line1:^66}║\n"
        f"  ║{line2:^66}║\n"
        f"  ╠{'═' * 66}╣\n"
        f"  ║{line3:<66}║\n"
        f"  ║{line4:<66}║\n"
        f"  ║{line5:<66}║\n"
        f"  ╚{'═' * 66}╝\n"
    )

    existing = sample_count_from_db()
    if existing > 0:
        print(f"  ℹ️   Found {existing} existing samples in database. Appending...\n")

    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
    client.on_connect = on_connect
    client.on_message = on_message

    try:
        client.connect(MQTT_BROKER, MQTT_PORT, 60)
        client.loop_forever()
    except KeyboardInterrupt:
        end1 = "  [OK] Collection stopped."
        end2 = f"  Total samples this session : {_sample_count}"
        end3 = f"  Total in DB                : {sample_count_from_db()}"
        end4 = "  Next step:"
        end5 = "    python3 pi_backend/merge_datasets.py"
        end6 = "    python3 ml_models/train_model.py"

        print(
            f"\n\n  ╔{'═' * 66}╗\n"
            f"  ║{end1:<66}║\n"
            f"  ║{end2:<66}║\n"
            f"  ║{end3:<66}║\n"
            f"  ╠{'═' * 66}╣\n"
            f"  ║{end4:<66}║\n"
            f"  ║{end5:<66}║\n"
            f"  ║{end6:<66}║\n"
            f"  ╚{'═' * 66}╝\n"
        )
        client.disconnect()


if __name__ == "__main__":
    main()
