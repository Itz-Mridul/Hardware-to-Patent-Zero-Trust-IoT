import sqlite3
import time

from flask import Flask, jsonify, request


DB_NAME = "iot_data.db"
app = Flask(__name__)


def init_db():
    conn = sqlite3.connect("/home/mridul/Hardware-to-Patent-Zero-Trust-IoT/iot_data.db")
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS heartbeats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id TEXT NOT NULL,
                rssi REAL NOT NULL,
                timestamp REAL NOT NULL
            )
            """
        )
        conn.commit()
    finally:
        conn.close()


@app.post("/verify")
def verify():
    payload = request.get_json(silent=True) or {}
    device_id = payload.get("device_id")
    rssi = payload.get("rssi")

    if device_id is None or rssi is None:
        return jsonify(
            {
                "success": False,
                "error": "Both 'device_id' and 'rssi' are required.",
            }
        ), 400

    timestamp = time.time()

    conn = sqlite3.connect(DB_NAME)
    try:
        conn.execute(
            "INSERT INTO heartbeats (device_id, rssi, timestamp) VALUES (?, ?, ?)",
            (device_id, rssi, timestamp),
        )
        conn.commit()
    finally:
        conn.close()

    return jsonify({"success": True, "message": "Heartbeat recorded."})


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5005)
