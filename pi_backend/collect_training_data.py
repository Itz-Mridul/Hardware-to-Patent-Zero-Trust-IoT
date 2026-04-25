import json
import os
import sqlite3
import time

import paho.mqtt.client as mqtt


# Config
_DEFAULT_DB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "training_data.db")
DB_PATH = os.environ.get("TRAINING_DB_PATH", _DEFAULT_DB)
MQTT_BROKER = os.environ.get("MQTT_BROKER", "localhost")
MQTT_PORT = int(os.environ.get("MQTT_PORT", "1883"))
MQTT_TOPIC = os.environ.get("MQTT_TOPIC", "mailbox/heartbeat")
DEFAULT_RSSI = int(os.environ.get("DEFAULT_RSSI", "-50"))

last_time = None


def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS heartbeats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                inter_packet_delay REAL,
                rssi INTEGER,
                is_legitimate INTEGER
            )
            """
        )
        conn.commit()


def extract_rssi(payload):
    try:
        data = json.loads(payload)
    except json.JSONDecodeError:
        return DEFAULT_RSSI

    return int(data.get("rssi", DEFAULT_RSSI))


def on_connect(client, userdata, flags, reason_code, properties=None):
    if reason_code == 0:
        print("Connected to MQTT broker.")
        client.subscribe(MQTT_TOPIC)
        print(f"Subscribed to topic: {MQTT_TOPIC}")
    else:
        print(f"Failed to connect to MQTT broker. Code: {reason_code}")


def on_message(client, userdata, message):
    global last_time

    current_time = time.time()
    ipd = current_time - last_time if last_time else 0.0
    last_time = current_time

    payload = message.payload.decode("utf-8", errors="ignore")
    rssi = extract_rssi(payload)

    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO heartbeats (inter_packet_delay, rssi, is_legitimate)
            VALUES (?, ?, ?)
            """,
            (ipd, rssi, 1),
        )
        conn.commit()
        sample_id = cursor.lastrowid

    print(f"Captured Sample {sample_id}: IPD={ipd:.4f}s RSSI={rssi}")


def main():
    init_db()

    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
    client.on_connect = on_connect
    client.on_message = on_message

    print("Waiting for ESP32 heartbeats... Press Ctrl+C when you have 200+ samples.")
    print(f"Database: {DB_PATH}")

    client.connect(MQTT_BROKER, MQTT_PORT, 60)

    try:
        client.loop_forever()
    except KeyboardInterrupt:
        print("\nStopped data collection.")
        client.disconnect()


if __name__ == "__main__":
    main()
