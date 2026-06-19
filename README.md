# 🔐 Zero-Trust RFID Gateway — Hardware-to-Patent IoT Security Platform

[![Tests](https://img.shields.io/badge/tests-95%20passed-brightgreen)](tests/)
[![Blockchain](https://img.shields.io/badge/blockchain-Ganache%20%2B%20Solidity-blue)](blockchain/)
[![Platform](https://img.shields.io/badge/platform-Raspberry%20Pi%20%2B%20ESP32-red)](pi_backend/)

A **patent-pending, distributed Zero-Trust IoT security system** that authenticates physical access via RFID, captures visual evidence of unauthorized attempts using a dedicated surveillance camera, logs every event immutably on a blockchain, and dispatches real-time Telegram alerts — all orchestrated over a local MQTT network.

---

## 🏗️ System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    ZERO-TRUST IoT NETWORK                       │
│                                                                 │
│  ┌──────────────────────┐    MQTT     ┌───────────────────────┐ │
│  │  Standard ESP32      │ ──────────► │   Raspberry Pi 4      │ │
│  │  (RFID Gateway)      │ ◄────────── │   (Backend Orchestr.) │ │
│  │                      │  GRANT/DENY │                       │ │
│  │  • RC522 RFID Reader │             │  • iot_server.py      │ │
│  │  • RGB LED           │             │  • dashboard.py       │ │
│  │  • HMAC-SHA256 Auth  │             │  • blockchain_bridge  │ │
│  │  • Local UID fallback│             │  • telegram_alert     │ │
│  └──────────────────────┘             │  • defense_sensors    │ │
│                                       └───────────┬───────────┘ │
│  ┌──────────────────────┐                         │             │
│  │  ESP32-CAM           │ ◄─── photo_request ─────┘             │
│  │  (Surveillance Node) │                                       │
│  │                      │ ──── JPEG burst ────────►             │
│  │  • OV2640 Camera     │    (5 photos on DENY)                 │
│  │  • Flash LED         │                                       │
│  │  • Passive listener  │                                       │
│  └──────────────────────┘                                       │
│                                                                 │
│  ┌──────────────────────┐    Web3     ┌───────────────────────┐ │
│  │  Ganache (Mac)       │ ◄─────────► │  SecurityRegistry.sol │ │
│  │  Blockchain Emulator │             │  EvidenceRegistry.sol │ │
│  └──────────────────────┘             └───────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

---

## 🔑 Key Security Features

| Feature | Implementation |
|---|---|
| **Zero-Trust RFID Auth** | HMAC-SHA256 signed payloads, local UID fallback |
| **AI Heartbeat Scoring** | CNN-LSTM trust scoring via IPD + RSSI fingerprinting |
| **5-Shot Burst Surveillance** | ESP32-CAM captures 5 photos on every unauthorized tap |
| **Immutable Blockchain Log** | Every GRANT/DENY event hashed and written to Ganache |
| **Real-time Telegram Alerts** | Photo + event details sent instantly on DENY |
| **Anti-Replay Nonce** | Anti-FPGA challenge-response puzzle (30s intervals) |
| **Physical Tamper Detection** | SW-420 vibration sensor wipes keys on shake |
| **Thermal Sabotage Guard** | DHT22 monitors temperature anomalies |
| **Honey-PIN Trap** | Decoy PIN triggers silent lockdown mode |

---

## 📦 Hardware Required

| Device | Role | Count |
|---|---|---|
| Standard ESP32 | RFID Gateway Node | 1 |
| AI-Thinker ESP32-CAM | Surveillance Node | 1 |
| Raspberry Pi 4 | Backend Orchestrator | 1 |
| RC522 RFID Reader | Card authentication | 1 |
| MIFARE Classic Cards | Authorized user tokens | 2+ |
| RGB LED (Common Anode) | Access status indicator | 1 |
| Mac/PC | Ganache blockchain host | 1 |

### ESP32 RFID Gateway Wiring

| RC522 Pin | ESP32 Pin |
|---|---|
| SDA (SS) | GPIO 5 |
| SCK | GPIO 18 |
| MOSI | GPIO 23 |
| MISO | GPIO 19 |
| RST | GPIO 22 |
| VCC | 3.3V |
| GND | GND |
| Green LED (+) | GPIO 26 |
| Red LED (+) | GPIO 27 |
| LED Common | GND (via 220Ω) |

---

## 🚀 Quick Start

### Prerequisites
```bash
# Mac
npm install -g ganache   # or download Ganache.app

# Raspberry Pi
sudo apt install mosquitto mosquitto-clients python3-pip
pip3 install -r requirements.txt
```

### 1. Configure Authorized Users
Edit `authorized_users.json`:
```json
{
  "B2A3FB9D": { "name": "Mridul", "gender": "M", "secret_code": "1234" },
  "0205CA06": { "name": "Onkar",  "gender": "M", "secret_code": "9600" }
}
```

### 2. Configure Environment
Copy and fill `.env.example` → `.env`:
```bash
cp .env.example .env
# Edit TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID, WIFI_SSID, WIFI_PASSWORD
```

### 3. Flash ESP32 Firmware
| Firmware | Device | Path |
|---|---|---|
| `esp32_rfid_gateway.ino` | Standard ESP32 | `esp32_cam/sentry/esp32_rfid_gateway/` |
| `esp32_cam_surveillance.ino` | ESP32-CAM | `esp32_cam/sentry/esp32_cam_surveillance/` |

> Flash ESP32-CAM via web flasher: **[esp.huhn.me](https://esp.huhn.me)**

### 4. Start the System

**On Mac (one command):**
```bash
bash start_mac.sh
# Opens Ganache, auto-detects IP, syncs .env to Pi
```

**On Raspberry Pi (one command):**
```bash
bash start_all.sh
# Starts: MQTT + iot_server + dashboard + blockchain_bridge + Telegram
```

**Open Dashboard:**
```
http://<PI_IP>:5001
```

---

## 💻 Shell Shortcuts

Add to `~/.zshrc` (Mac) or `~/.bashrc` (Pi):

**Mac:**
```bash
alias iot-start='bash "/path/to/Blockchain Project/start_mac.sh"'
alias iot-stop='pkill -f ganache'
alias iot-status='curl -s http://localhost:7545'
```

**Pi:**
```bash
alias iot-start='bash ~/Master_IoT_Project/start_all.sh'
alias iot-stop='pkill -f iot_server.py; pkill -f dashboard.py; pkill -f blockchain_bridge.py'
alias iot-log='tail -f ~/Master_IoT_Project/logs/iot_server.log'
```

---

## 🔄 Access Flow

```
Card Tapped
     │
     ▼
ESP32 reads UID + verifies HMAC
     │
     ├─ Known UID? ──► GRANT locally (green LED 5s) ──► Pi logs event
     │
     └─ Unknown UID? ──► Sends to Pi for verification
                              │
                    Pi checks authorized_users.json
                              │
                    ┌─────────┴─────────┐
                  GRANT               DENY
                    │                   │
              Green LED 5s        Red LED 5s
                    │                   │
              Log to DB         Trigger ESP32-CAM
              Blockchain TX      5-photo burst
                               Telegram alert 📱
                               Blockchain TX 🔗
```

---

## 📊 Dashboard Features

| Panel | Shows |
|---|---|
| **Hardware Trust Scores** | Live IPD + RSSI trust score per device |
| **Sentry Camera** | Latest ESP32-CAM capture |
| **Security Event Feed** | Real-time GRANT/DENY stream |
| **Blockchain Ledger** | Immutable SHA-256 event log with TX hashes |
| **Tamper / Attack Summary** | SW-420, thermal, Wi-Fi jamming, AI spoofing counts |

---

## 🧪 Running Tests

```bash
cd "Blockchain Project"
source .venv/bin/activate
python3 -m pytest tests/ -v
# 95 tests — 91 passed, 4 skipped (ML model optional)
```

---

## 📁 Project Structure

```
Blockchain Project/
├── esp32_cam/sentry/
│   ├── esp32_rfid_gateway/       ← Standard ESP32 firmware
│   └── esp32_cam_surveillance/   ← ESP32-CAM firmware
├── esp32_gateway/
│   └── rogue_skimmer/            ← Attack simulation firmware
├── pi_backend/
│   ├── iot_server.py             ← Main MQTT + access control server
│   ├── dashboard.py              ← Flask web dashboard
│   ├── blockchain_bridge.py      ← Ganache connector
│   ├── telegram_alert.py         ← Telegram notifications
│   ├── defense_sensors.py        ← SW-420 + DHT22 monitoring
│   └── forensic_logger.py        ← Blockchain event logger
├── blockchain/
│   └── contracts/                ← Solidity smart contracts
├── smart_contracts/              ← SecurityRegistry.sol
├── ml_models/                    ← CNN-LSTM heartbeat model
├── tests/                        ← Full test suite (95 tests)
├── authorized_users.json         ← RFID UID whitelist
├── start_mac.sh                  ← One-command Mac startup
├── start_all.sh                  ← One-command Pi startup
└── .env                          ← Secrets & configuration
```

---

## 🔐 Security Architecture (Patent Claims)

1. **Hardware Attestation** — Boot-time fingerprint of CPU, MAC, and serial to detect Trojan components
2. **AI-LSTM Heartbeat Auth** — Statistical fingerprinting of inter-packet delay patterns
3. **HMAC-SHA256 Payloads** — All MQTT messages cryptographically signed
4. **Blockchain Forensics** — Tamper-proof SHA-256 event log on Ethereum
5. **Zero-Trust Surveillance** — Camera activates only on threat; silent otherwise
6. **Air-Gapped Kill Switch** — Arduino watchdog cuts Pi power on fault detection

---

## 👥 Authorized Users

| UID | Name | Secret Code |
|---|---|---|
| `B2A3FB9D` | Mridul | 1234 |
| `0205CA06` | Onkar | 9600 |

To add users: edit `authorized_users.json` and update the local UID whitelist in `esp32_rfid_gateway.ino`.
