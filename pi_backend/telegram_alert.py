#!/usr/bin/env python3
"""
Zero-Trust IoT — Telegram Alert Service
=========================================
Dual-mode service:
  1. MQTT → Telegram PUSH alerts:
       - Card DENIED  → sends the intruder's PHOTO + caption with UID/reason
       - Card GRANTED → sends a brief "✅ Access Granted" text notification
       - Tamper/Lockdown → sends emergency alert with dashboard link

  2. Telegram BOT COMMANDS (polling):
       /dashboard → replies with clickable dashboard link
       /status    → replies with current threat level + last event
       /photos    → sends the 3 most recent intruder photos
"""

import html
import io
import json
import os
import sys
import threading
import time

import requests
import paho.mqtt.client as mqtt

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# ─────────────────────────────────────────────────────────────────────────────
# 1. CONFIGURATION
# ─────────────────────────────────────────────────────────────────────────────
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip().strip('"').strip("'")
TELEGRAM_CHAT_ID   = os.environ.get("TELEGRAM_CHAT_ID",   "").strip().strip('"').strip("'")
PI_LOCAL_IP        = os.environ.get("PI_LOCAL_IP",        "10.238.130.161").strip().strip('"').strip("'")
DASHBOARD_PORT     = os.environ.get("DASHBOARD_PORT",     "5001").strip().strip('"').strip("'")
MQTT_BROKER        = os.environ.get("MQTT_BROKER",        "127.0.0.1")
MQTT_PORT          = int(os.environ.get("MQTT_PORT",      "1883"))

DASHBOARD_URL = f"http://{PI_LOCAL_IP}:{DASHBOARD_PORT}"
API_BASE      = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}"

_MQTT_RETRY_DELAY_S = 5

MQTT_TOPICS = (
    "mailbox/access",       # every card tap (GRANT + DENY)
    "mailbox/tamper",       # physical tamper
    "security/lockdown",    # system lockdown
    "alerts/telegram",      # general alert bus
)

# ─────────────────────────────────────────────────────────────────────────────
# 2. TELEGRAM SEND FUNCTIONS
# ─────────────────────────────────────────────────────────────────────────────

def _require_config():
    if not (TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID):
        raise RuntimeError(
            "Set TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID environment variables."
        )


def send_text(message: str, chat_id: str = None) -> bool:
    """Send a plain HTML text message."""
    try:
        r = requests.post(
            f"{API_BASE}/sendMessage",
            json={
                "chat_id":    chat_id or TELEGRAM_CHAT_ID,
                "text":       message,
                "parse_mode": "HTML",
            },
            timeout=10,
        )
        ok = r.status_code == 200
        if not ok:
            print(f"[Telegram] sendMessage failed {r.status_code}: {r.text[:200]}")
        return ok
    except requests.RequestException as e:
        print(f"[Telegram] Network error: {e}")
        return False


def send_photo(jpeg_bytes: bytes, caption: str, chat_id: str = None) -> bool:
    """Send a JPEG photo with an HTML caption."""
    try:
        r = requests.post(
            f"{API_BASE}/sendPhoto",
            data={
                "chat_id":    chat_id or TELEGRAM_CHAT_ID,
                "caption":    caption,
                "parse_mode": "HTML",
            },
            files={"photo": ("intruder.jpg", io.BytesIO(jpeg_bytes), "image/jpeg")},
            timeout=20,
        )
        ok = r.status_code == 200
        if not ok:
            print(f"[Telegram] sendPhoto failed {r.status_code}: {r.text[:200]}")
        return ok
    except requests.RequestException as e:
        print(f"[Telegram] Network error on sendPhoto: {e}")
        return False


# ─────────────────────────────────────────────────────────────────────────────
# 3. MESSAGE FORMATTERS
# ─────────────────────────────────────────────────────────────────────────────

def _fmt_grant(data: dict) -> str:
    name   = html.escape(str(data.get("name",      "Unknown")))
    uid    = html.escape(str(data.get("uid",       "—")))
    device = html.escape(str(data.get("device_id", "—")))
    ts     = time.strftime("%H:%M:%S", time.localtime())
    return (
        f"✅ <b>ACCESS GRANTED</b>\n\n"
        f"👤 <b>Name:</b> {name}\n"
        f"🆔 <b>Card UID:</b> <code>{uid}</code>\n"
        f"📡 <b>Device:</b> <code>{device}</code>\n"
        f"🕒 <b>Time:</b> {ts}\n\n"
        f"🔗 <a href='{DASHBOARD_URL}'>Open Dashboard</a>"
    )


def _fmt_deny_caption(data: dict) -> str:
    name   = html.escape(str(data.get("name",      "UNKNOWN")))
    uid    = html.escape(str(data.get("uid",       "—")))
    reason = html.escape(str(data.get("reason",    "Unauthorized card")))
    device = html.escape(str(data.get("device_id", "—")))
    ts     = time.strftime("%H:%M:%S", time.localtime())
    return (
        f"🚨 <b>ACCESS DENIED — INTRUDER DETECTED</b>\n\n"
        f"👤 <b>Person:</b> {name}\n"
        f"🆔 <b>Card UID:</b> <code>{uid}</code>\n"
        f"❌ <b>Reason:</b> {reason}\n"
        f"📡 <b>Device:</b> <code>{device}</code>\n"
        f"🕒 <b>Time:</b> {ts}\n\n"
        f"🔗 <a href='{DASHBOARD_URL}'>View Dashboard →</a>"
    )


def _fmt_tamper(topic: str, data: dict) -> str:
    device = html.escape(str(data.get("device_id", "Unknown")))
    event  = html.escape(str(data.get("event",     "UNKNOWN_EVENT")))
    sensor = html.escape(str(data.get("sensor",    event.replace("_", " ").title())))
    action = html.escape(str(data.get("action",    "Investigate immediately")))

    if topic == "security/lockdown":
        return (
            f"🚨 <b>ZERO-TRUST LOCKDOWN ALERT</b> 🚨\n\n"
            f"<b>Target:</b> <code>{device}</code>\n"
            f"<b>Trigger:</b> <code>{event}</code>\n"
            f"<b>Action:</b> <code>{action}</code>\n\n"
            f"⚠️ <b>System entered lockdown!</b>\n"
            f"🔗 <a href='{DASHBOARD_URL}'>Check Dashboard NOW →</a>"
        )

    return (
        f"🚨 <b>ZERO-TRUST SECURITY ALERT</b> 🚨\n\n"
        f"<b>Target:</b> <code>{device}</code>\n"
        f"<b>Trigger:</b> Physical Tampering Detected\n"
        f"<b>Sensor:</b> <code>{sensor}</code>\n"
        f"<b>Action:</b> <code>{action}</code>\n\n"
        f"⚠️ <b>Investigate immediately:</b>\n"
        f"🔗 <a href='{DASHBOARD_URL}'>Open Dashboard →</a>"
    )


# ─────────────────────────────────────────────────────────────────────────────
# 4. MQTT CALLBACKS
# ─────────────────────────────────────────────────────────────────────────────

def on_connect(client, userdata, flags, reason_code, properties):
    if reason_code == 0:
        print("[Telegram] Connected to MQTT broker. Subscribing to topics...")
        for topic in MQTT_TOPICS:
            client.subscribe(topic)
            print(f"  → Subscribed: {topic}")
    else:
        print(f"[Telegram] MQTT connect failed. Code: {reason_code}")


def on_message(client, userdata, msg):
    topic   = msg.topic
    raw     = msg.payload.decode("utf-8", errors="replace")
    print(f"\n[Telegram] [{topic}] {raw[:120]}")

    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        send_text(f"⚠️ Alert on <code>{html.escape(topic)}</code>:\n{html.escape(raw[:400])}")
        return

    if not isinstance(data, dict):
        data = {"event": "INVALID_PAYLOAD", "raw": str(data)}

    # ── Plain message from nonce_challenger / other services ──
    if "message" in data and topic == "alerts/telegram":
        send_text(data["message"])
        return

    # ── Card tap: GRANT or DENY ──
    if topic == "mailbox/access":
        decision = str(data.get("decision", data.get("result", ""))).upper()

        if decision in ("GRANT", "AUTHENTICATED", "ALLOW"):
            # Notify but also call dashboard.notify_card_tap for SSE
            _call_dashboard_notify(data, decision="GRANT")
            send_text(_fmt_grant(data))

        elif decision in ("DENY", "REJECTED", "BLOCK"):
            _call_dashboard_notify(data, decision="DENY")
            caption = _fmt_deny_caption(data)
            # Try to get the intruder photo from the ESP32-CAM
            jpeg = _fetch_latest_cam_photo()
            if jpeg:
                send_photo(jpeg, caption)
            else:
                # No photo available — send text only with a note
                send_text(caption + "\n\n📷 <i>(Photo capture pending from ESP32-CAM)</i>")
        else:
            # Unknown result — just log it
            send_text(
                f"ℹ️ Card tap: <code>{html.escape(raw[:300])}</code>"
            )
        return

    # ── Physical tamper / lockdown ──
    send_text(_fmt_tamper(topic, data))


def _call_dashboard_notify(data: dict, decision: str):
    """Fire-and-forget call to dashboard.notify_card_tap() via its in-process function."""
    try:
        from pi_backend.dashboard import notify_card_tap
        tap = dict(data)
        tap["decision"] = decision
        tap["timestamp"] = tap.get("timestamp", int(time.time()))
        notify_card_tap(tap)
    except Exception as e:
        print(f"[Telegram] dashboard.notify_card_tap error: {e}")


def _fetch_latest_cam_photo() -> bytes | None:
    """Pull the latest JPEG from the dashboard photo API."""
    try:
        r = requests.get(
            f"http://127.0.0.1:{DASHBOARD_PORT}/api/photo/ESP32_CAM_PERIMETER",
            timeout=5,
        )
        if r.status_code == 200 and r.headers.get("content-type", "").startswith("image/jpeg"):
            # Check it's a real photo (not the 1x1 placeholder which is ~75 bytes)
            if len(r.content) > 200:
                return r.content
    except Exception:
        pass
    return None


# ─────────────────────────────────────────────────────────────────────────────
# 5. TELEGRAM BOT COMMANDS (polling thread)
# ─────────────────────────────────────────────────────────────────────────────

_last_update_id = 0


def _get_updates() -> list:
    global _last_update_id
    try:
        r = requests.get(
            f"{API_BASE}/getUpdates",
            params={"offset": _last_update_id + 1, "timeout": 20, "allowed_updates": ["message"]},
            timeout=30,
        )
        if r.status_code == 200:
            return r.json().get("result", [])
    except Exception:
        pass
    return []


def _handle_command(text: str, chat_id: str):
    cmd = text.strip().lower().split()[0]

    if cmd in ("/dashboard", "/start"):
        send_text(
            f"🛡️ <b>Zero-Trust Security Dashboard</b>\n\n"
            f"🔗 <a href='{DASHBOARD_URL}'>{DASHBOARD_URL}</a>\n\n"
            f"Tap the link to open the live dashboard.",
            chat_id=chat_id,
        )

    elif cmd == "/status":
        try:
            r = requests.get(
                f"http://127.0.0.1:{DASHBOARD_PORT}/api/threat_level", timeout=5
            )
            t = r.json()
            color_emoji = {"GREEN": "🟢", "YELLOW": "🟡", "ORANGE": "🟠", "RED": "🔴"}.get(t.get("color", ""), "⚪")
            alerts_str = "\n".join(f"  • {a}" for a in t.get("alerts", [])) or "  None"
            send_text(
                f"📊 <b>System Status</b>\n\n"
                f"{color_emoji} <b>Threat Level:</b> {t.get('color', '?')} ({t.get('threat_score', '?')}%)\n"
                f"⚠️ <b>Active Alerts:</b>\n{alerts_str}\n\n"
                f"🔗 <a href='{DASHBOARD_URL}'>Open Dashboard</a>",
                chat_id=chat_id,
            )
        except Exception as e:
            send_text(f"⚠️ Could not fetch status: {html.escape(str(e))}", chat_id=chat_id)

    elif cmd == "/photos":
        try:
            r = requests.get(
                f"http://127.0.0.1:{DASHBOARD_PORT}/api/deny_photos?limit=3", timeout=5
            )
            photos = r.json()
            if not photos:
                send_text("✅ No denied access photos recorded yet.", chat_id=chat_id)
                return
            for p in photos:
                # Fetch each photo file
                photo_path = p.get("photo_path", "")
                try:
                    with open(photo_path, "rb") as f:
                        jpeg = f.read()
                    uid    = html.escape(str(p.get("uid",    "—")))
                    name   = html.escape(str(p.get("name",   "UNKNOWN")))
                    reason = html.escape(str(p.get("reason", "—")))
                    ts     = str(p.get("timestamp", ""))[:19]
                    caption = (
                        f"🚨 <b>Intruder Photo</b>\n"
                        f"🆔 UID: <code>{uid}</code>  👤 {name}\n"
                        f"❌ {reason}  🕒 {ts}"
                    )
                    send_photo(jpeg, caption, chat_id=chat_id)
                    time.sleep(0.5)
                except Exception:
                    pass
        except Exception as e:
            send_text(f"⚠️ Could not fetch photos: {html.escape(str(e))}", chat_id=chat_id)

    else:
        send_text(
            "🤖 <b>Zero-Trust Bot Commands:</b>\n\n"
            "/dashboard — Get dashboard link\n"
            "/status — Current threat level\n"
            "/photos — Last 3 intruder photos",
            chat_id=chat_id,
        )


def bot_polling_thread():
    """Background thread: polls Telegram for commands every 20s."""
    global _last_update_id
    print("[TelegramBot] Command polling started.")
    while True:
        try:
            updates = _get_updates()
            for update in updates:
                _last_update_id = update["update_id"]
                message = update.get("message", {})
                text    = message.get("text", "").strip()
                chat_id = str(message.get("chat", {}).get("id", ""))
                if text.startswith("/") and chat_id:
                    print(f"[TelegramBot] Command '{text}' from {chat_id}")
                    _handle_command(text, chat_id)
        except Exception as e:
            print(f"[TelegramBot] Polling error: {e}")
        time.sleep(1)  # getUpdates uses long-polling so this is fine


# ─────────────────────────────────────────────────────────────────────────────
# 6. MAIN — start MQTT + bot polling
# ─────────────────────────────────────────────────────────────────────────────

def main():
    try:
        _require_config()
    except RuntimeError as exc:
        print(f"ERROR: {exc}")
        sys.exit(1)

    # Start the bot command polling thread
    t = threading.Thread(target=bot_polling_thread, daemon=True)
    t.start()

    # Start MQTT listener
    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
    client.on_connect = on_connect
    client.on_message = on_message

    print(f"[Telegram] Connecting to MQTT broker at {MQTT_BROKER}:{MQTT_PORT}...")

    while True:
        try:
            client.connect(MQTT_BROKER, MQTT_PORT, 60)
            break
        except OSError as exc:
            print(f"[Telegram] Could not reach broker: {exc}. Retrying in {_MQTT_RETRY_DELAY_S}s...")
            time.sleep(_MQTT_RETRY_DELAY_S)

    print("[Telegram] Service ready. Listening for card taps and tamper events.")
    client.loop_forever()


if __name__ == "__main__":
    main()
