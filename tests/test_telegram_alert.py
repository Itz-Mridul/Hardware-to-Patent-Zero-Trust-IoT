import importlib
import pytest


def test_module_import_does_not_require_telegram_env(monkeypatch):
    monkeypatch.delenv("TELEGRAM_BOT_TOKEN", raising=False)
    monkeypatch.delenv("TELEGRAM_CHAT_ID", raising=False)

    import pi_backend.telegram_alert as telegram_alert

    module = importlib.reload(telegram_alert)

    with pytest.raises(RuntimeError):
        module._require_telegram_config()


@pytest.fixture()
def telegram_module(monkeypatch):
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "test-token")
    monkeypatch.setenv("TELEGRAM_CHAT_ID", "test-chat")

    import pi_backend.telegram_alert as telegram_alert

    return importlib.reload(telegram_alert)


def test_format_alert_message_for_mailbox_tamper(telegram_module):
    message = telegram_module.format_alert_message(
        "mailbox/tamper",
        {
            "device_id": "ESP32_CAM_01",
            "sensor": "SW-420",
            "action": "Capture evidence",
        },
    )

    assert "ESP32_CAM_01" in message
    assert "SW-420" in message
    assert "Capture evidence" in message


def test_format_alert_message_for_security_lockdown(telegram_module):
    message = telegram_module.format_alert_message(
        "security/lockdown",
        {
            "device_id": "SW420_SENSOR",
            "event": "PHYSICAL_TAMPER",
            "action": "RELAY_CUT",
        },
    )

    assert "LOCKDOWN ALERT" in message
    assert "PHYSICAL_TAMPER" in message
    assert "RELAY_CUT" in message


def test_on_connect_subscribes_to_all_topics(telegram_module):
    subscribed = []

    class FakeClient:
        def subscribe(self, topic):
            subscribed.append(topic)

    telegram_module.on_connect(FakeClient(), None, None, 0, None)

    assert subscribed == list(telegram_module.MQTT_TOPICS)
