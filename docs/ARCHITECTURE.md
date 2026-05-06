# System Architecture — Zero-Trust IoT Security Gateway
## Hardware-to-Patent: Multi-Layer Physical & Cryptographic Access Control

---

## System Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    ZERO-TRUST IoT SECURITY GATEWAY                          │
│                                                                             │
│  ┌──────────────────┐  Wi-Fi/MQTT   ┌───────────────────────────────────┐  │
│  │  ESP32-CAM       │──────────────▶│  Raspberry Pi 4/5 (Vault Server)  │  │
│  │  (Front Door)    │◀──────────────│                                   │  │
│  │                  │               │  • CNN-LSTM ML Engine (port 5005)  │  │
│  │  • RC522 RFID    │               │  • MQTT Broker (Mosquitto)         │  │
│  │  • RGB LED       │               │  • Flask Dashboard (port 5001)     │  │
│  │  • Door Relay    │               │  • Blockchain Bridge (port 5010)   │  │
│  │  • Camera (VGA)  │               │  • Key Vault (Volatile RAM)        │  │
│  │  • HMAC Signing  │               │  • Hardware Attestation            │  │
│  │  • Nonce Solver  │               │  • Nonce Challenger                │  │
│  └──────────────────┘               │  • RGB Validator (OpenCV)          │  │
│                                     │  • Honey-PIN System                │  │
│  ┌──────────────────┐  Wi-Fi/MQTT   │  • Forensic Logger                 │  │
│  │  ESP32-Gateway   │──────────────▶│  • Telegram Alerts                 │  │
│  │  (Telemetry)     │               └─────────────┬─────────────────────┘  │
│  │                  │                             │ USB Serial              │
│  │  • DHT22 (Temp)  │               ┌─────────────▼─────────────────────┐  │
│  │  • SW-420 (Vib)  │               │  Arduino Uno (Air-Gapped Watchdog) │  │
│  │  • Heartbeats    │               │                                   │  │
│  └──────────────────┘               │  • DHT22 (Room Temp — Pin 2)      │  │
│                                     │  • SW-420 (Vibration — Pin 3)     │  │
│  ┌──────────────────┐  Wi-Fi/MQTT   │  • Kill-Switch Relay (Pin 7)      │  │
│  │  ESP32 Rogue     │──────────────▶│  • Watchdog Timer (30s PING)      │  │
│  │  (Red Team)      │    BLOCKED    │  • No Wi-Fi. No OS. Unhackable.   │  │
│  │                  │    by CNN-    └───────────────────────────────────┘  │
│  │  Attack tool for │    LSTM AI                                           │
│  │  live demo only  │                     ┌─────────────────────────────┐  │
│  └──────────────────┘                     │  Ganache (Local Ethereum)   │  │
│                                           │  SecurityRegistry.sol       │  │
│                                           │  Immutable Event Log        │  │
│                                           └─────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Component Detail

### Node 1: ESP32-CAM (Perimeter Edge Node — "The Front Door")

**Physical Location:** Outside the secure room, mounted at door height.

| Feature | Implementation | File |
|---|---|---|
| RFID Reading | RC522 via SPI (Pins 13, 14, 15, 12) | `esp32_cam_sentry.ino` |
| RGB Challenge | Common-cathode RGB LED (Pins 33, 1, 3) | `esp32_cam_sentry.ino` |
| Door Control | Fail-secure relay, Pin 16, HIGH=Locked | `esp32_cam_sentry.ino` |
| Heartbeats | 500ms MQTT to `mailbox/heartbeat` | `esp32_cam_sentry.ino` |
| HMAC Signing | NVS-stored key, mbedtls HMAC-SHA256 | `esp32_cam_sentry.ino` |
| Nonce Solving | FPGA-defeat puzzle response | `esp32_cam_sentry.ino` |
| Camera | AI-Thinker OV2640, VGA JPEG | `esp32_cam_sentry.ino` |

**Arduino IDE Settings:** Flash Mode=DIO, CPU=240MHz, Board=AI Thinker ESP32-CAM

---

### Node 2: ESP32-Gateway (Telemetry Node — "The Heartbeat")

**Physical Location:** Inside the room, near the Pi.

| Feature | Implementation | File |
|---|---|---|
| DHT22 Sensor | Temperature + Humidity, GPIO 4 | `gateway.ino` |
| SW-420 | Vibration ISR, GPIO 5 (INPUT_PULLUP) | `gateway.ino` |
| Dual-Core | Network task on Core 0, UI on Core 1 | `gateway.ino` |
| Heartbeats | 5000ms MQTT + HTTP `/verify` | `gateway.ino` |
| LWT | Retained OFFLINE JSON on broker disconnect | `gateway.ino` |
| Tamper Alert | MQTT `mailbox/tamper` with debounce | `gateway.ino` |

---

### Node 3: Raspberry Pi 4/5 (Vault Server — "The Brain")

**Physical Location:** Inside the Pironman secure case, inside the room.

#### Service Architecture

```
Pi Services (started by start_all.sh):
  ┌─────────────────────────────────────────────────────────┐
  │ [1] iot_server.py         → Port 5005 (Flask + MQTT)    │
  │     • /verify endpoint (CNN-LSTM authentication)        │
  │     • MQTT subscriber for all mailbox/* topics          │
  │     • Device trust score management                     │
  │                                                         │
  │ [2] defense_sensors.py    → Background daemon           │
  │     • GPIO SW-420 interrupt (tamper)                    │
  │     • GPIO DHT22 poller (ambient temp)                  │
  │     • Arduino USB serial bridge (primary)               │
  │                                                         │
  │ [3] dashboard.py          → Port 5001 (Flask)           │
  │     • Real-time threat radar                            │
  │     • Device trust score display                        │
  │     • Blockchain TX log                                 │
  │     • Evidence photo viewer                             │
  │                                                         │
  │ [4] telegram_alert.py     → Background daemon           │
  │     • Forwards MQTT alerts/* to Telegram Bot API       │
  └─────────────────────────────────────────────────────────┘
```

#### Key Software Modules

| Module | Patent Claim | Description |
|---|---|---|
| `iot_server.py` | Claim 2 | CNN-LSTM heartbeat auth + trust scoring |
| `key_vault.py` | Claim 6 | XOR secret splitting + mlock() |
| `nonce_challenger.py` | Claim 4 | FPGA-defeat arithmetic puzzle |
| `rgb_validator.py` | Claim 3 | OpenCV color-space deepfake detection |
| `thermal_monitor.py` | Claim 5 | Dual-sensor differential analysis |
| `honey_pin.py` | Claim 7 | Three-tier duress PIN system |
| `hardware_attestation.py` | Claim 8 | Supply chain hardware fingerprinting |
| `blockchain_bridge.py` | Claim 1(e) | Ganache/Ethereum event logging |
| `forensic_logger.py` | Claim 1(e) | SHA-256 event hashing + DB + chain |
| `defense_sensors.py` | Claim 1(d) | Arduino serial bridge + GPIO fallback |

---

### Node 4: Arduino Uno (Air-Gapped Watchdog — "The Bodyguard")

**Physical Location:** Adjacent to the Pi, connected via USB cable.

**Why it cannot be hacked remotely:**
- No TCP/IP stack
- No Wi-Fi or Bluetooth module
- No operating system (bare metal C++)
- Communicates ONLY via hardwired USB serial to the Pi

| Feature | Implementation | File |
|---|---|---|
| DHT22 (Room Temp) | Digital Pin 2, 4.7kΩ pull-up | `watchdog.ino` |
| SW-420 (Vibration) | Digital Pin 3, INPUT_PULLUP ISR | `watchdog.ino` |
| Kill-Switch Relay | Digital Pin 7, HIGH = power cut | `watchdog.ino` |
| Pi Watchdog Timer | 30s timeout on PING keepalive | `watchdog.ino` |
| Pi PING Protocol | Pi sends `PING\n` every 10s | `defense_sensors.py` |

**Kill-Switch Wiring:**
```
Power Adapter → [COM] Relay [NO] → Pi USB-C Power Input
                     ↑
              Arduino Pin 7
              (HIGH = relay opens = power cut = RAM wiped)
```

---

### Node 5: Ethereum Blockchain (Ganache — "The Immutable Ledger")

**Type:** Local Ganache testnet (can be migrated to mainnet/L2 for production)

| Feature | Implementation | File |
|---|---|---|
| Smart Contract | SecurityRegistry.sol (Solidity 0.8.19) | `smart_contracts/SecurityRegistry.sol` |
| Event Logging | `logEvent(deviceId, eventType, dataHash, timestamp)` | `blockchain_bridge.py` |
| RFID Registry | `registerRfid(uid, owner)` + `emergencyRevoke(uid)` | `blockchain_bridge.py` |
| REST Bridge | Flask API on port 5010 | `blockchain_bridge.py` |
| Forensic Hash | SHA-256 of `device_id|result|reason|timestamp` | `forensic_logger.py` |

---

## Data Flow: Normal Access

```
1. User taps RFID card on ESP32-CAM
2. ESP32-CAM reads UID → publishes to MQTT mailbox/access
3. Pi receives → issues RGB challenge to mailbox/rgb_challenge
4. ESP32-CAM fires LED (e.g., CYAN) → captures photo → publishes JPEG
5. Pi's OpenCV validates cyan tint in photo → PASS
6. Pi issues UNLOCK command → ESP32-CAM Pin 16 LOW → door opens
7. Pi logs event: SHA-256 hash → SQLite + Ganache blockchain
8. Pi sends Telegram confirmation
```

## Data Flow: Spoofing Attack (Red Team ESP32)

```
1. Attacker presses button → rogue ESP32 injects MQTT heartbeat
2. Pi's CNN-LSTM receives packet sequence
3. inter_packet_delay too fast / too smooth → classifier scores REJECTED
4. trust_score decrements → hits BLOCK_THRESHOLD
5. Dashboard turns RED → Telegram ALERT
6. Blockchain logs SPOOF_ATTACK event
```

## Data Flow: Physical Tamper (Act 4 Demo)

```
1. Attacker shakes the Arduino / case
2. Arduino SW-420 ISR fires → vibrationDetected = true
3. Arduino sends final warning JSON to Pi via USB serial
4. Arduino Pin 7 → HIGH → relay opens → Pi power cut
5. Pi RAM cleared to zeros (volatile memory)
6. All cryptographic keys destroyed
7. Attacker has a dead, encrypted brick
```

---

## Security Threat Model

| Attack Vector | Defense Mechanism | Result |
|---|---|---|
| Software packet spoof | CNN-LSTM timing fingerprint | BLOCKED |
| Deepfake video at camera | RGB randomized challenge | BLOCKED |
| FPGA hardware clone | Nonce arithmetic timing | DETECTED |
| IR laser on DHT22 | Differential thermal analysis | IGNORED (trap) |
| Software malware overheating CPU | CPU thermal monitor | LOCKDOWN |
| Physical case vibration | Arduino SW-420 → kill-switch | POWER CUT |
| Pi OS compromise/freeze | Arduino 30s watchdog | POWER CUT |
| Admin coercion (duress) | Honey-PIN system | SOS + fake unlock |
| Hardware supply chain Trojan | Hardware attestation fingerprint | DETECTED |
| Cold boot RAM attack | Key vault zero-wipe on tamper | KEYS ZEROED |
| Log deletion by hacker | Ethereum blockchain immutability | IMPOSSIBLE |

---

*Generated: 2026-04-27*
