import time

import pytest

import pi_backend.dashboard as dashboard
import pi_backend.iot_server as iot_server


@pytest.fixture()
def temp_db(monkeypatch, tmp_path):
    db_path = str(tmp_path / "security.db")

    import pi_backend.defense_sensors as ds
    import pi_backend.forensic_logger as fl
    import pi_backend.thermal_monitor as tm

    monkeypatch.setattr(iot_server, "DB_PATH", db_path)
    monkeypatch.setattr(dashboard, "DB_PATH", db_path)
    monkeypatch.setattr(ds, "DB_PATH", db_path)
    monkeypatch.setattr(fl, "DB_PATH", db_path)
    monkeypatch.setattr(tm, "DB_PATH", db_path)

    iot_server.init_db()
    yield db_path


def test_threat_level_counts_recent_rejected_access_log_events(temp_db):
    from pi_backend.forensic_logger import log_access_attempt

    for _ in range(3):
        log_access_attempt(
            device_id="ATTACKER_01",
            result="REJECTED",
            reason="Spoofed heartbeat",
            trust_score=10.0,
        )

    client = dashboard.app.test_client()
    response = client.get("/api/threat_level")

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["threat_score"] >= 15
    assert "REJECTED_x3" in payload["alerts"]


def test_environment_endpoint_returns_latest_dht22_reading(temp_db):
    from pi_backend.defense_sensors import _store_environment_reading

    _store_environment_reading(31.5, 62.0)
    time.sleep(0.01)
    _store_environment_reading(29.25, 58.5)

    client = dashboard.app.test_client()
    response = client.get("/api/environment")

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["device_id"] == "PI_DHT22"
    assert payload["temperature"] == 29.25
    assert payload["humidity"] == 58.5
