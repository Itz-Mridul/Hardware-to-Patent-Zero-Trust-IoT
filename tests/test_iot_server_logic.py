import sqlite3
import tempfile
import time
from pathlib import Path

import pi_backend.iot_server as iot_server


def _use_temp_db(monkeypatch):
    temp_dir = tempfile.TemporaryDirectory()
    db_path = Path(temp_dir.name) / "security.db"
    monkeypatch.setattr(iot_server, "DB_PATH", str(db_path))
    iot_server.init_db()
    return temp_dir


def _get_device_status(device_id):
    with sqlite3.connect(iot_server.DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT * FROM device_status WHERE device_id = ?",
            (device_id,),
        ).fetchone()
        return dict(row) if row else None


def test_fast_ipd_is_heavily_penalized():
    delta, classification, reason = iot_server.score_heartbeat(750, -45)

    assert delta <= -30
    assert classification == "REJECTED"
    assert "fast" in reason.lower()


def test_reconnect_opens_grace_period(monkeypatch):
    temp_dir = _use_temp_db(monkeypatch)
    device_id = "ESP32_GATEWAY_001"

    try:
        with iot_server.app.app_context():
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

            payload = {
                "device_id": device_id,
                "timestamp": 123456789,
                "temperature": 24.5,
                "humidity": 54.0,
                "rssi": -55,
                "free_heap": 200000,
                "inter_packet_delay": 5100,
                "packet_size": 128,
                "connection_state": "RECONNECTED",
                "fresh_connection": True,
            }

            response, http_code, _ = iot_server.evaluate_heartbeat(payload)

            assert http_code == 200
            body = response.get_json()
            assert body["status"] == "AUTHENTICATED"
            assert body["grace_period_until"] > time.time()

        state = _get_device_status(device_id)
        assert state is not None
        assert state["status"] == "AUTHENTICATED"
        assert state["grace_period_until"] > time.time()
        assert state["trust_score"] == 72.0
    finally:
        temp_dir.cleanup()


def test_status_message_sets_grace_period(monkeypatch):
    temp_dir = _use_temp_db(monkeypatch)
    device_id = "ESP32_GATEWAY_001"

    try:
        iot_server.handle_status_message(
            "mailbox/status",
            {
                "device_id": device_id,
                "status": "ONLINE",
                "connection_state": "BOOT",
            },
            retained=True,
        )

        state = _get_device_status(device_id)
        assert state is not None
        assert state["status"] == "ONLINE"
        assert state["grace_period_until"] > time.time()
    finally:
        temp_dir.cleanup()
