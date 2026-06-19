#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║   Zero-Trust IoT — SOFTWARE ROGUE SKIMMER ATTACKER          ║
║   Run from ANY laptop on the same WiFi as the Pi             ║
║                                                              ║
║   Requirements:  pip install paho-mqtt                       ║
║   Usage:         python3 software_attacker.py                ║
╚══════════════════════════════════════════════════════════════╝
"""

import json
import os
import random
import sys
import time

# ── Auto-install paho-mqtt if missing ────────────────────────────────────────
try:
    import paho.mqtt.client as mqtt
except ImportError:
    print("Installing paho-mqtt...")
    os.system(f"{sys.executable} -m pip install paho-mqtt -q")
    import paho.mqtt.client as mqtt

# ── CONFIGURATION ─────────────────────────────────────────────────────────────
PI_IP      = os.environ.get("PI_IP",   "10.238.130.161")   # ← Pi on 'Onki' WiFi
MQTT_PORT  = int(os.environ.get("MQTT_PORT", "1883"))

SPOOFED_DEVICE_ID = "ESP32_CAM_PERIMETER"   # Pretend to be the real sentry node
ATTACKER_ID       = "ESP32_ROGUE_SKIMMER"
SPOOFED_UID       = "A3F7C2B1"              # Pre-captured legitimate RFID UID
INVALID_HMAC      = "deadbeef00001111deadbeef00002222"

TOPIC_HEARTBEAT = "mailbox/heartbeat"
TOPIC_ACCESS    = "mailbox/access"
TOPIC_STATUS    = "mailbox/status"

# ─────────────────────────────────────────────────────────────────────────────

def banner():
    print("""
\033[91m╔══════════════════════════════════════════════════════════════╗
║   ██████╗  ██████╗  ██████╗ ██╗   ██╗███████╗              ║
║   ██╔══██╗██╔═══██╗██╔════╝ ██║   ██║██╔════╝              ║
║   ██████╔╝██║   ██║██║  ███╗██║   ██║█████╗                ║
║   ██╔══██╗██║   ██║██║   ██║██║   ██║██╔══╝                ║
║   ██║  ██║╚██████╔╝╚██████╔╝╚██████╔╝███████╗              ║
║   ╚═╝  ╚═╝ ╚═════╝  ╚═════╝  ╚═════╝ ╚══════╝              ║
║                                                              ║
║   ZERO-TRUST ROGUE SKIMMER — SOFTWARE EDITION               ║
║   Simulates: ESP32_ROGUE_SKIMMER                            ║
╚══════════════════════════════════════════════════════════════╝\033[0m
""")


def connect(pi_ip: str) -> mqtt.Client:
    client = mqtt.Client(client_id=ATTACKER_ID)

    def on_connect(c, u, f, rc, props=None):
        if rc == 0:
            print(f"\033[92m✅ Connected to MQTT broker at {pi_ip}:{MQTT_PORT}\033[0m")
            # Announce as rogue device — dashboard will flag it immediately
            ann = json.dumps({
                "device_id": ATTACKER_ID,
                "status":    "ONLINE",
                "role":      "ROGUE_SKIMMER",
            })
            c.publish(TOPIC_STATUS, ann)
        else:
            print(f"\033[91m❌ Connection failed: rc={rc}\033[0m")
            sys.exit(1)

    client.on_connect = on_connect
    try:
        client.connect(pi_ip, MQTT_PORT, 60)
        client.loop_start()
        time.sleep(1.0)   # wait for on_connect
    except Exception as e:
        print(f"\033[91m❌ Cannot reach {pi_ip}:{MQTT_PORT} — {e}\033[0m")
        print("   Make sure your laptop is on the same WiFi as the Pi (Onki).")
        sys.exit(1)
    return client


# ─────────────────────────────────────────────────────────────────────────────
# Attack Modes
# ─────────────────────────────────────────────────────────────────────────────

def mode1_spoof(client: mqtt.Client):
    """Mode 1: Single spoofed access request — wrong HMAC + too-fast IPD."""
    print("\n\033[93m[MODE 1] Sending SPOOF packet...\033[0m")
    payload = {
        "device_id":          SPOOFED_DEVICE_ID,  # ← Identity theft
        "rfid_uid":           SPOOFED_UID,
        "challenge_response": "RED",              # Guessing the colour challenge
        "photo_crc":          "00000000",         # No real camera
        "photo_size_bytes":   0,
        "timestamp":          int(time.time() * 1000),
        "inter_packet_delay": 200,                # ← Too fast (real device: 500ms)
        "rssi":               random.randint(-60, -50),
        "free_heap":          320000,             # ← Too large (no camera buffer)
        "packet_size":        256,
        "sig":                INVALID_HMAC,       # ← Wrong HMAC key
        "action":             "UNLOCK",           # ← The attack goal
    }
    result = client.publish(TOPIC_ACCESS, json.dumps(payload))
    if result.rc == 0:
        print(f"  \033[91m🎯 Spoof packet sent → device_id='{SPOOFED_DEVICE_ID}', action=UNLOCK\033[0m")
        print(f"  IPD=200ms (real device uses 500ms) — AI will flag this as SPOOFED")
    else:
        print(f"  ⚠️ Publish failed: rc={result.rc}")


def mode2_flood(client: mqtt.Client):
    """Mode 2: DDoS heartbeat flood — 50 packets at 20ms (impossibly fast)."""
    print("\n\033[93m[MODE 2] Starting FLOOD ATTACK — 50 rapid heartbeat packets...\033[0m")
    for i in range(50):
        payload = {
            "device_id":          SPOOFED_DEVICE_ID,
            "inter_packet_delay": 20,      # ← 20ms = impossible for real hardware
            "rssi":               random.randint(-55, -45),
            "free_heap":          320000,  # ← Suspiciously large
            "packet_size":        256,
            "timestamp":          int(time.time() * 1000),
            "sig":                INVALID_HMAC,
        }
        client.publish(TOPIC_HEARTBEAT, json.dumps(payload))
        client.loop()
        time.sleep(0.02)  # 20ms

        bar = "█" * (i + 1) + "░" * (49 - i)
        print(f"\r  \033[91m[{bar}] {i+1}/50\033[0m", end="", flush=True)

    print(f"\n  \033[91m🎯 Flood complete — 50 packets @ 20ms = 2500 pkt/s\033[0m")
    print("  Trust score for ROGUE_SKIMMER → 0%  |  Threat Radar → RED")


def mode3_replay(client: mqtt.Client):
    """Mode 3: Replay a captured legitimate packet — caught by stale timestamp."""
    print("\n\033[93m[MODE 3] Sending REPLAY of captured packet...\033[0m")
    payload = {
        "device_id":          SPOOFED_DEVICE_ID,
        "rfid_uid":           SPOOFED_UID,
        "challenge_response": "BLUE",
        "photo_crc":          "4A3F91BC",   # Real CRC from a legitimate session
        "photo_size_bytes":   38912,         # Real photo size
        "timestamp":          1714000000,    # ← OLD! (April 2024) — replay detected
        "inter_packet_delay": 500,           # Correct cadence — but timestamp stale
        "rssi":               -55,
        "free_heap":          180000,
        "packet_size":        256,
        "sig":                "c9f3a8b200deadbeef00112233445566",  # Stale sig
        "action":             "UNLOCK",
    }
    client.publish(TOPIC_ACCESS, json.dumps(payload))
    print(f"  \033[91m🎯 Replay packet sent — timestamp=1714000000 (April 2024)\033[0m")
    print("  Timestamp validator rejects: 'Packet is 400+ days old'")


def mode4_continuous(client: mqtt.Client):
    """Mode 4: Continuous erratic spoofing — keeps Threat Radar RED until stopped."""
    print("\n\033[93m[MODE 4] CONTINUOUS ATTACK — Press Ctrl+C to stop\033[0m")
    sent = 0
    try:
        last_ts = int(time.time() * 1000)
        while True:
            delay_ms = random.randint(80, 950)  # Erratic — triggers anomaly detector
            time.sleep(delay_ms / 1000.0)
            now = int(time.time() * 1000)
            ipd = now - last_ts
            last_ts = now
            payload = {
                "device_id":          SPOOFED_DEVICE_ID,
                "timestamp":          now,
                "rssi":               random.randint(-70, -40),
                "free_heap":          random.randint(280000, 340000),
                "inter_packet_delay": ipd,
                "packet_size":        random.randint(200, 280),
                "sig":                INVALID_HMAC,
            }
            client.publish(TOPIC_HEARTBEAT, json.dumps(payload))
            sent += 1
            print(f"  \033[91m🎯 [{sent:>4}] Spoof heartbeat | IPD={ipd}ms\033[0m")
    except KeyboardInterrupt:
        print(f"\n  Stopped after {sent} packets.")


# ─────────────────────────────────────────────────────────────────────────────
# Main Menu
# ─────────────────────────────────────────────────────────────────────────────

def main():
    banner()

    # Allow overriding Pi IP from command line: python3 software_attacker.py 10.x.x.x
    pi_ip = sys.argv[1] if len(sys.argv) > 1 else PI_IP
    print(f"  Target Pi : \033[96m{pi_ip}:{MQTT_PORT}\033[0m")
    print(f"  Spoofing  : \033[96m{SPOOFED_DEVICE_ID}\033[0m")
    print(f"  Attacker  : \033[96m{ATTACKER_ID}\033[0m")
    print()

    client = connect(pi_ip)

    while True:
        print("""
\033[96m╔─────────────────────────────────────────────────────╗
║  SELECT ATTACK MODE                                  ║
╠─────────────────────────────────────────────────────╣
║  1 → Spoof Attack   (bad HMAC + wrong timing)        ║
║  2 → Flood / DDoS   (50 pkts @ 20ms)                 ║
║  3 → Replay Attack  (stale captured packet)          ║
║  4 → Continuous     (keeps Threat Radar RED)         ║
║  q → Quit                                            ║
╚─────────────────────────────────────────────────────╝\033[0m""")

        choice = input("  Enter choice: ").strip().lower()

        if choice == "1":
            mode1_spoof(client)
        elif choice == "2":
            mode2_flood(client)
        elif choice == "3":
            mode3_replay(client)
        elif choice == "4":
            mode4_continuous(client)
        elif choice == "q":
            print("\n\033[92mDisconnecting...\033[0m")
            break
        else:
            print("  Invalid choice. Enter 1, 2, 3, 4, or q.")

    client.loop_stop()
    client.disconnect()
    print("Done.")


if __name__ == "__main__":
    main()
