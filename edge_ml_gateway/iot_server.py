import os
import sqlite3
import time

from flask import Flask, jsonify, request


# Resolve DB path once at startup: prefer the env var, fall back to a local file.
_DEFAULT_DB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "iot_data.db")
DB_PATH = os.environ.get("IOT_DB_PATH", _DEFAULT_DB)

app = Flask(__name__)


def init_db():
    with sqlite3.connect(DB_PATH) as conn:
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

    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            "INSERT INTO heartbeats (device_id, rssi, timestamp) VALUES (?, ?, ?)",
            (device_id, rssi, timestamp),
        )
        conn.commit()

    return jsonify({"success": True, "message": "Heartbeat recorded."})


if __name__ == "__main__":
    init_db()
    print(f"[*] IoT server using database: {DB_PATH}")
    app.run(host="0.0.0.0", port=5005)
