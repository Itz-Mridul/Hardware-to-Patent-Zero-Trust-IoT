import json
import html
import os
import sys
import time
import requests
import paho.mqtt.client as mqtt

# ==========================================
# 1. CONFIGURATION
# ==========================================
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "")

MQTT_BROKER = os.environ.get("MQTT_BROKER", "127.0.0.1")
MQTT_PORT = int(os.environ.get("MQTT_PORT", "1883"))
MQTT_TOPICS = ("mailbox/tamper", "security/lockdown")

_MQTT_RETRY_DELAY_S = 5  # seconds between reconnect attempts


def _require_telegram_config():
    if TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID:
        return

    raise RuntimeError(
        "Set the TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID environment variables "
        "before running this script.\n"
        "  export TELEGRAM_BOT_TOKEN='<your-token>'\n"
        "  export TELEGRAM_CHAT_ID='<your-chat-id>'"
    )


# ==========================================
# 2. TELEGRAM FUNCTION
# ==========================================
def send_telegram_alert(message):
    _require_telegram_config()
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"

    payload = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": message,
        "parse_mode": "HTML",
    }

    try:
        response = requests.post(url, json=payload, timeout=10)

        if response.status_code == 200:
            print("Telegram alert sent successfully.")
        else:
            print(f"Telegram rejected the message: {response.status_code}")
            print(response.text)

    except requests.RequestException as e:
        print(f"Failed to connect to Telegram: {e}")


# ==========================================
# 3. MQTT CALLBACKS
# ==========================================
def on_connect(client, userdata, flags, reason_code, properties):
    if reason_code == 0:
        print("Connected to MQTT broker. Listening for tamper alerts...")
        for topic in MQTT_TOPICS:
            client.subscribe(topic)
    else:
        print(f"Failed to connect to MQTT broker. Code: {reason_code}")


def on_message(client, userdata, msg):
    payload = msg.payload.decode("utf-8", errors="replace")
    print(f"\n[ALERT TRIGGERED] Topic: {msg.topic}")
    print(f"Payload: {payload}")

    try:
        data = json.loads(payload)
        if not isinstance(data, dict):
            data = {"event": "INVALID_ALERT_PAYLOAD", "raw": str(data)}
        alert_text = format_alert_message(msg.topic, data)

        send_telegram_alert(alert_text)

    except json.JSONDecodeError:
        print("Received invalid JSON format.")


def format_alert_message(topic, data):
    device = html.escape(str(data.get("device_id", "Unknown Device")))
    event = html.escape(str(data.get("event", "UNKNOWN_EVENT")))
    sensor = html.escape(str(data.get("sensor", event.replace("_", " ").title())))
    action = html.escape(str(data.get("action", "Investigate immediately")))

    if topic == "security/lockdown":
        return (
            "🚨 <b>ZERO-TRUST LOCKDOWN ALERT</b> 🚨\n\n"
            f"<b>Target:</b> <code>{device}</code>\n"
            f"<b>Trigger:</b> <code>{event}</code>\n"
            f"<b>Action:</b> <code>{action}</code>\n"
            "⚠️ <b>System entered lockdown. Check the dashboard immediately.</b>"
        )

    return (
        "🚨 <b>ZERO-TRUST SECURITY ALERT</b> 🚨\n\n"
        f"<b>Target:</b> <code>{device}</code>\n"
        "<b>Trigger:</b> Physical Tampering Detected\n"
        f"<b>Sensor:</b> <code>{sensor}</code>\n"
        f"<b>Action:</b> <code>{action}</code>\n\n"
        "⚠️ <b>Please check the Sentry Web GUI immediately!</b>"
    )


# ==========================================
# 4. START SERVICE
# ==========================================
def main():
    try:
        _require_telegram_config()
    except RuntimeError as exc:
        print(f"ERROR: {exc}")
        sys.exit(1)

    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)

    client.on_connect = on_connect
    client.on_message = on_message

    print("Booting Zero-Trust Telegram Notifier...")
    print(f"Connecting to MQTT broker at {MQTT_BROKER}:{MQTT_PORT} ...")

    while True:
        try:
            client.connect(MQTT_BROKER, MQTT_PORT, 60)
            break
        except OSError as exc:
            print(f"Could not reach broker: {exc}. Retrying in {_MQTT_RETRY_DELAY_S}s...")
            time.sleep(_MQTT_RETRY_DELAY_S)

    client.loop_forever()


if __name__ == "__main__":
    main()
