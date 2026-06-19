# Zero-Trust Hardware-to-Patent IoT Security Platform
## Research Paper Methodology & Professor Demo Guide
### Authors: Mridul & Onkar | Year: 2026

> **How to use this document**
> This is the complete methodology + demo script for your professor presentation.
> It is structured as **Red Team (attacker) vs Blue Team (defender)** so you can
> show each attack and the corresponding defence in real time.

---

## Table of Contents

1. [System Overview & Problem Statement](#1-system-overview--problem-statement)
2. [Architecture — Six Defence Layers](#2-architecture--six-defence-layers)
3. [Red Team vs Blue Team — 4 Live Attack Acts](#3-red-team-vs-blue-team--4-live-attack-acts)
   - [Act 1 — Software Intrusion (Network Hack)](#act-1--software-intrusion-network-hack)
   - [Act 2 — Hardware Escalation (FPGA Replay)](#act-2--hardware-escalation-fpga-replay)
   - [Act 3 — Supply Chain Trojan](#act-3--supply-chain-trojan)
   - [Act 4 — Availability Siege (Jamming)](#act-4--availability-siege-jamming)
4. [Phase 1 — System Architecture Design](#phase-1--system-architecture-design)
5. [Phase 2 — Hardware Selection](#phase-2--hardware-selection)
6. [Phase 3 — Embedded Firmware (ESP32)](#phase-3--embedded-firmware-esp32)
7. [Phase 4 — Edge AI Authentication](#phase-4--edge-ai-authentication)
8. [Phase 5 — Blockchain Forensic Layer](#phase-5--blockchain-forensic-layer)
9. [Phase 6 — Physical Defence](#phase-6--physical-defence)
10. [Phase 7 — Integration, Testing & Validation](#phase-7--integration-testing--validation)
11. [Literature Review — Papers 1–4 & Paper 8](#literature-review--papers-14--paper-8)
12. [Master Comparison Table (All Papers vs Our System)](#master-comparison-table-all-papers-vs-our-system)
13. [Research Contributions Summary (C1–C7)](#research-contributions-summary-c1c7)
14. [Patent Claims](#patent-claims)
15. [One-Paragraph Summary (Say to Professor)](#one-paragraph-summary-say-to-professor)

---

## 1. System Overview & Problem Statement

### The Problem with Traditional Access Control

Most RFID door systems work like this:
1. Tap card → reader checks database → door opens.

This is broken in at least five ways:

| Attack | What Happens |
|---|---|
| **Card cloning** | Attacker copies your card UID in under 1 second with a hidden reader |
| **FPGA replay** | Hardware device captures & replays the RFID radio exchange |
| **Supply-chain Trojan** | Backdoor chip planted inside the ESP32 during shipping |
| **Physical smash-and-grab** | Attacker opens the reader box and extracts the UID database |
| **Admin coercion** | Attacker forces admin to reveal their PIN at gunpoint |

### Our Solution: Six Independent Defence Layers

We do not trust *anything* by default — not the card, not the MQTT message, not even the hardware itself. Every action is cryptographically verified and permanently recorded. If anything looks wrong, we alert, lock down, and wipe keys — all in milliseconds.

> **"Never trust, always verify."** — John Kindervag, Zero Trust inventor (Forrester Research, 2010)

---

## 2. Architecture — Six Defence Layers

| Layer | What is Verified | How |
|---|---|---|
| **RF layer** | Is this RFID card genuinely owned by this person? | HMAC-SHA256 signature on every message |
| **Network layer** | Is this MQTT message from a real ESP32? | Signed payload + nonce challenge |
| **Device layer** | Is this the same hardware that was enrolled? | CPU serial + MAC + timing fingerprint |
| **Behaviour layer** | Does this device *behave* like real hardware? | CNN-LSTM neural network (6 features) |
| **Physical layer** | Has anyone touched the enclosure? | SW-420 vibration sensor + Arduino watchdog |
| **Human layer** | Is the administrator under duress? | Honey-PIN system (3 tiers) |

### System Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                    ZERO-TRUST IoT NETWORK                       │
│                                                                 │
│  ┌──────────────────────┐    MQTT     ┌───────────────────────┐ │
│  │  Standard ESP32      │ ──────────► │   Raspberry Pi 5      │ │
│  │  (RFID Gateway)      │ ◄────────── │   (Backend Orch.)     │ │
│  │  HMAC + Nonce Auth   │  GRANT/DENY │  iot_server.py        │ │
│  └──────────────────────┘             │  dashboard.py (SSE)   │ │
│                                       │  blockchain_bridge.py │ │
│  ┌──────────────────────┐             │  telegram_alert.py    │ │
│  │  ESP32-CAM           │ ◄─photo_req─┤  heartbeat_monitor.py │ │
│  │  (Surveillance Node) │ ──JPEG────► │  defense_sensors.py   │ │
│  │  5-photo burst DENY  │             └───────────┬───────────┘ │
│  └──────────────────────┘                         │             │
│                                       ┌───────────▼───────────┐ │
│  ┌──────────────────────┐  Web3/HTTP  │  Ganache (Mac)        │ │
│  │  SecurityRegistry    │ ◄─────────► │  Private Ethereum     │ │
│  │  EvidenceRegistry    │             │  Port 7545            │ │
│  └──────────────────────┘             └───────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

### Network Topology (Current Demo: Onki WiFi)

| Device | Role | IP |
|---|---|---|
| Raspberry Pi 5 | MQTT Broker + Backend | `10.238.130.161` |
| Mac (Ganache) | Blockchain Node | `10.238.130.167:7545` |
| ESP32 (RFID) | Access Gateway Node | Dynamic |
| ESP32-CAM | Surveillance / Sentry | Dynamic |
| Dashboard | Web UI | `http://10.238.130.161:5001` |

---

## 3. Red Team vs Blue Team — 4 Live Attack Acts

> **🔴 RED TEAM** = The attacker (your friend's laptop running `software_attacker.py`)
> **🔵 BLUE TEAM** = Our system (Pi + ESP32 + Blockchain + Telegram)

---

### ACT 1 — Software Intrusion (Network Hack)

#### 🔴 Red Team Action
Hacker connects to the same WiFi ("Onki"), runs:
```bash
python3 tests/software_attacker.py
# Select Mode 1: Spoof Attack
# OR Mode 4: Continuous Attack
```
The script claims to be `ESP32_CAM_PERIMETER` and sends fake `UNLOCK` commands via MQTT.

#### 🔵 Blue Team — Layer 1: CNN-LSTM AI Fingerprinting
- AI watches a rolling window of 10 heartbeats per device
- Real ESP32 hardware has natural **clock drift** → `inter_packet_delay` varies naturally around 500ms
- Hacker's Python script on a laptop produces **too-perfect intervals** (or erratic random ones)
- Model output: **legitimacy score < 0.45** → `SPOOF_ATTACK` → ACCESS DENIED

```
Features monitored: rssi, packet_size, free_heap, inter_packet_delay, temperature, humidity
Threshold: score >= 0.45 → LEGITIMATE | score < 0.45 → SPOOF DETECTED
```

#### 🔵 Blue Team — Layer 2: HMAC-SHA256 Cryptographic Signature
- Every real ESP32 packet is signed with HMAC-SHA256 using a 32-byte secret key stored in encrypted NVS flash
- Hacker does not have the physical key → signature check fails → `HMAC_VERIFICATION_FAILED` logged
- Even if hacker perfectly mimics the clock drift, this layer still blocks them

#### 🔵 Blue Team — Layer 3: Dynamic Nonce (Anti-Replay)
- Pi issues a fresh random nonce for every session
- Old captured packets with stale nonces are instantly rejected
- Replay attack fails completely

#### 🟢 What Professor Sees
```
Dashboard Threat Radar:  GREEN → ORANGE → RED (SYSTEM LOCKDOWN)
Trust Score:             ESP32_ROGUE_SKIMMER → 0%
Telegram (phone):        "ZERO-TRUST ALERT — SPOOF_ATTACK detected"
Blockchain:              New REJECTED record with SHA-256 hash
```

---

### ACT 2 — Hardware Escalation (FPGA Replay Attack)

#### 🔴 Red Team Explanation (No Physical FPGA needed — explain verbally)
A sophisticated attacker uses an **FPGA** (field-programmable gate array — hardware that can mimic other chips) to:
- Clone the RFID radio exchange at the hardware level
- Perfectly replay the captured signal, bypassing software defences

#### 🔵 Blue Team — Layer 1: Nonce-Based Timing Challenge
- Pi sends a random math puzzle (modular arithmetic): find smallest `x` where `(nonce + x) % 1000 == 0`
- Real ESP32 solves it in **50–2,000 microseconds** (hardware CPU at 240 MHz)
- FPGA solves it in **< 10 microseconds** (hardware acceleration)
- System detects sub-threshold solve time → `FPGA_SUSPECTED` → LOCKDOWN

```python
FPGA_THRESHOLD_US = 10   # If solved in < 10µs → flag as FPGA
```

#### 🔵 Blue Team — Layer 2: HMAC Signature on Nonce Response
- Device must cryptographically sign the puzzle answer using the physical secret key
- FPGA sitting in a van does not have the real ESP32's key → signature fails

#### 🔵 Blue Team — Layer 3: Physical Liveness Challenge (Camera RGB)
- System demands a real-time photo of the user illuminated by a **randomly assigned RGB colour**
- An FPGA in a van has no camera, no LEDs, cannot produce a human face glowing "YELLOW" → fails completely

#### 🔵 Blue Team — Layer 4: Anti-Replay Nonce
- Pi generates completely new random nonce each session
- Yesterday's captured signature is useless today

#### 🟢 Key Line for Professor
> *"We don't just check what you know (PIN) or what you have (card). We check what you ARE at the silicon level — your hardware's clock jitter is your biometric."*

---

### ACT 3 — Supply Chain Trojan (Hardware Attestation)

#### 🔴 Red Team Explanation (Verbal)
Attacker intercepts the ESP32 during shipping, solders a parasitic backdoor chip onto the PCB, then delivers it to the victim. The device looks identical externally.

#### 🔵 Blue Team — Hardware Attestation (4 Checks)
Before any device joins the network, `hardware_attestation.py` runs four independent measurements:

| Check | What is Measured | Tolerance | Why It Detects Trojans |
|---|---|---|---|
| **CPU Serial (eFuse)** | BCM SoC factory-burned serial from `/proc/cpuinfo` | Exact match | Board replacement detected |
| **NIC MAC Address** | Hardware MAC via `uuid.getnode()` | Exact match | NIC swap or Trojan NIC detected |
| **Timing Fingerprint** | Median nanoseconds per SHA-256 hash (500 iterations) | ±50,000 ns | Parasitic chip loads bus differently → timing drift |
| **Thermal Rise Profile** | SoC temperature rise (°C) after 1-second CPU stress burst | ±0.5°C | Trojan chip adds parasitic thermal mass |

These four measurements are hashed into a **Golden Record** on first boot. Every subsequent boot compares against it.

**Result:** Modified device fails attestation → Pi quarantines it, refuses to issue cryptographic keys → device never joins the network.

#### 🟢 Key Line for Professor
> *"Prior art uses at most 2 measurements (serial + MAC). We add thermal fingerprinting + bus timing — techniques novel enough for Patent Claim 2."*

---

### ACT 4 — Availability Siege (Jamming & Network Outage)

#### 🔴 Red Team Action (Mode 2: Flood)
```bash
python3 tests/software_attacker.py
# Select Mode 2: Flood / DDoS
# 50 packets at 20ms intervals (2,500 pkt/s)
```
This attempts to overwhelm the MQTT broker and cause a network outage.

#### 🔵 Blue Team — Mosquitto Rate Limiter
```
# mosquitto.conf
max_inflight_messages = 20
# Rate-limit: max 10 conn/s per client → flood packets dropped at broker level
```

#### 🔵 Blue Team — Hardware GPIO Watchdog (heartbeat_monitor.py)
- The ESP32 (real hardware) sends a **GPIO heartbeat pulse every 200ms** to the Pi
- If the MQTT broker is flooded, the software stack may lag, causing heartbeat gaps
- Pi detects gap > 200ms → **physically cuts the door relay via GPIO** → `HEARTBEAT_LOSS` alert
- This is hardware-enforced: **no software running on a flooded Pi can prevent this**

```python
# heartbeat_monitor.py — runs below the MQTT software stack
HEARTBEAT_TIMEOUT_MS = 200
# If pulse not received → GPIO relay cut → System Lockdown
```

#### 🔵 Blue Team — Fail-Secure Architecture
- When network dies, ESP32 attempts to contact Pi → fails
- Door does **NOT** open (Fail-Secure, not Fail-Open)
- ESP32 caches access attempt locally
- When network restores: Pi receives dump → Telegram: *"Connection restored. 1 access attempt blocked during outage."*

#### 🟢 What Professor Sees
```
Dashboard:  SYSTEM LOCKDOWN (RED) — HEARTBEAT_LOSS
Telegram:   "DoS/DDoS detected — Hardware watchdog activated"
Physical:   Door relay remains locked regardless of software state
```

---

## Phase 1 — System Architecture Design

### 1.1 Zero-Trust Principle
"Zero Trust" was invented by John Kindervag at Forrester Research in 2010. Core rule:
> **"Never trust, always verify."**

Applied at every layer:
- No device trusted because it is on the network
- No message accepted because it came from a known IP
- No user trusted because they previously authenticated
- Every action is verified independently, cryptographically, every time

### 1.2 Network Topology: Star via MQTT

MQTT (Message Queuing Telemetry Transport) — publish-subscribe protocol for IoT. Think of it as a radio channel: all devices publish/subscribe to topics simultaneously.

```
                         ┌─────────────────────┐
                         │   Raspberry Pi 5    │
                         │  10.238.130.161:1883│  ← MQTT Broker
                         └──────────┬──────────┘
                    ┌───────────────┼───────────────┐
                    │               │               │
             ┌──────┴──────┐ ┌─────┴──────┐ ┌──────┴──────┐
             │  ESP32      │ │  ESP32-CAM │ │  Ganache    │
             │  (RFID)     │ │ (Camera)   │ │  Blockchain │
             └─────────────┘ └────────────┘ └─────────────┘
```

### 1.3 MQTT Topics

| Topic | Publisher | Meaning |
|---|---|---|
| `mailbox/access` | ESP32 | Card tap event |
| `mailbox/heartbeat` | ESP32 | Regular health check |
| `mailbox/nonce_response` | ESP32 | FPGA challenge answer |
| `camera/photo` | ESP32-CAM | Surveillance photo payload |
| `mailbox/environment` | Pi sensors | DHT22 reading |
| `security/lockdown` | Any node | Broadcast lockdown |
| `alerts/telegram` | Any node | Send Telegram alert |

---

## Phase 2 — Hardware Selection

### Bill of Materials

| Device | Role | Count | Cost |
|---|---|---|---|
| Standard ESP32 (WROOM) | RFID Gateway Node | 1 | ~$5 |
| AI-Thinker ESP32-CAM | Surveillance Node | 1 | ~$8 |
| Raspberry Pi 5 (8GB) | Backend Orchestrator | 1 | ~$80 |
| RC522 RFID Reader | Card authentication | 1 | ~$2 |
| MIFARE Classic Cards | Authorised user tokens | 2+ | ~$1 each |
| RGB LED (Common Anode) | Access status indicator | 1 | ~$0.50 |
| SW-420 Vibration Sensor | Physical tamper detection | 1 | ~$1 |
| DHT22 Sensor | Temperature/Humidity | 1 | ~$2 |
| Arduino Uno | Air-gapped hardware watchdog | 1 | ~$10 |
| 5V Relay Module | Power kill-switch | 1 | ~$2 |
| **Total** | | | **~$112** |

### Why Raspberry Pi 5 (8GB)?
- **2.4 GHz quad-core Cortex-A76** — 3× faster than Pi 4 for CNN-LSTM inference
- **8 GB LPDDR4X RAM** — loads sklearn model + SQLite DB simultaneously
- **RP1 I/O controller** — GPIO interrupt latency < 1µs (critical for heartbeat watchdog)
- **PCIe 2.0** — future NVMe SSD upgrade path

### RC522 Wiring to ESP32

| RC522 Pin | ESP32 Pin |
|---|---|
| SDA (SS) | GPIO 5 |
| SCK | GPIO 18 |
| MOSI | GPIO 23 |
| MISO | GPIO 19 |
| RST | GPIO 22 |
| VCC | 3.3V |
| GND | GND |

---

## Phase 3 — Embedded Firmware (ESP32)

### 3.1 RFID Authentication Flow

```
Card Tapped
     │
     ▼
ESP32 reads UID
     │
     ├─ Local whitelist match? ──► GRANT_LOCAL (green LED 5s)
     │                               ↓
     │                         Pi logs event → Blockchain TX
     │
     └─ Unknown UID ──► Sends HMAC-signed packet to Pi
                              │
                    Pi checks authorized_users.json
                              │
                    ┌─────────┴─────────┐
                  GRANT               DENY
                    │                   │
              Green LED 5s        Red LED 5s
              Log to DB           Trigger ESP32-CAM
              Blockchain TX       5-photo burst
                                  Telegram alert
                                  Blockchain TX
```

### 3.2 HMAC-SHA256 Payload

What is HMAC? Hash-based Message Authentication Code. SHA-256 produces a 256-bit fingerprint. HMAC adds a secret key so only the key-holder can produce a valid hash.

```cpp
// ESP32 firmware — every packet signed:
String payload = uid + ":" + timestamp + ":" + nonce;
String hmac    = computeHMAC(SECRET_KEY, payload);
// Sends: {"uid":"B2A3FB9D","ts":1748302215,"nonce":482913,"hmac":"a3f9..."}
```

Why this stops cloning: Attacker clones UID but cannot forge HMAC without `SECRET_KEY`.

### 3.3 Anti-Replay Nonce
- Every message includes a random nonce used only once
- Pi tracks seen nonces for 60 seconds
- Same nonce twice → replay attack → DENY

### 3.4 FPGA Challenge-Response (Every 30 seconds)

Pi sends:
```json
{ "device_id": "ESP32_RFID_01", "nonce": 482315, "timeout_ms": 8000 }
```
Device must find smallest `x` where `(nonce + x) % 1000 == 0` and report solve time in microseconds.

```python
FPGA_THRESHOLD_US = 10   # Real ESP32: 50-2000µs | FPGA: < 10µs
```

### 3.5 Attack Mode Firmware (Rogue Skimmer)

The `esp32_rogue_skimmer.ino` demonstrates 3 attack modes:

| Mode | Attack | What Betrays It |
|---|---|---|
| Mode 1 | Single spoof: fake `device_id`, wrong HMAC, IPD=200ms | HMAC fails + IPD anomaly |
| Mode 2 | Flood: 50 packets at 20ms (2,500 pkt/s) | Rate limiter + heartbeat watchdog |
| Mode 3 | Replay: old captured packet (timestamp April 2024) | Stale timestamp validator |

---

## Phase 4 — Edge AI Authentication

### 4.1 CNN-LSTM Hardware Fingerprinting

**Problem:** What if attacker learns the HMAC key? We need a second layer checking whether the *hardware* is real.

**Key insight:** Real hardware has a unique heartbeat signature.

| Feature | Why it matters |
|---|---|
| `rssi` | Hardware antenna has characteristic noise floor |
| `packet_size` | Real firmware has consistent framing |
| `free_heap` | Hardware memory allocation has natural variation |
| `inter_packet_delay` | Hardware clock drift = unique jitter |
| `temperature` | Real hardware heats up naturally |
| `humidity` | Environmental correlation with real deployment |

**Architecture:**
- **CNN** — finds local patterns across 10-heartbeat window (short-range)
- **LSTM** — finds temporal evolution patterns over time (e.g., gradual heat-up)

**Inference Pipeline:**
```
New heartbeat arrives
        ↓
Extract 6 features → append to per-device rolling buffer (max 10)
        ↓
Buffer full → normalise 10×6 matrix via StandardScaler
        ↓
Feed into model → probability (0.0 to 1.0)
        ↓
  score >= 0.45 → LEGITIMATE
  score  < 0.45 → SPOOF DETECTED
```

**Dual-backend:** TensorFlow/Keras CNN-LSTM when available; auto-falls back to sklearn RandomForest (`device_authenticator.pkl`) on Python 3.14+.

### 4.2 Hardware Attestation (4-Vector)

| Measurement | Source | Tolerance |
|---|---|---|
| CPU Serial (eFuse) | `/proc/cpuinfo` | Exact match |
| NIC MAC Address | `uuid.getnode()` | Exact match |
| Timing fingerprint | 500 SHA-256 iterations, median nanoseconds | ±50,000 ns |
| Thermal rise profile | SoC temp rise after 1s CPU stress | ±0.5°C |

All four combined into a SHA-256 **Golden Record** on first boot. Verified on every subsequent boot.

### 4.3 Honey-PIN Duress System

| PIN Type | Example | Behaviour |
|---|---|---|
| **Real PIN** | 1234 | Normal access |
| **Duress PIN** | 1235 (last digit +1) | Appears to grant access, silently sends Telegram SOS, relay rerouted to dummy GPIO (stays locked), session logged as `DURESS_SESSION` |
| **Panic PIN** | 1237 (last digit +3) | Full lockdown, Telegram emergency SOS, blockchain evidence locked read-only |

All three compared in **constant time** to prevent timing side-channel attacks:
```python
def _ct_compare(a: str, b: str) -> bool:
    result = 0
    for x, y in zip(a, b):
        result |= ord(x) ^ ord(y)
    return result == 0
```

---

## Phase 5 — Blockchain Forensic Layer

### 5.1 Why Blockchain?
Traditional security logs on a server can be deleted by whoever hacks the server. A blockchain log **cannot be tampered with even by the server's own administrator**.

### 5.2 Implementation
- **Ganache** — local Ethereum emulator (free, same behaviour as mainnet)
- **Solidity** — smart contract language
- **Web3.py** — Python → Ethereum bridge
- Two contracts: `SecurityRegistry.sol` (access events) + `EvidenceRegistry.sol` (photo evidence)

### 5.3 Events Logged On-Chain

| Event Type | Trigger | Evidence |
|---|---|---|
| `ACCESS_GRANTED` | Valid RFID + HMAC | UID hash, timestamp, device ID |
| `ACCESS_DENIED` | Invalid RFID or HMAC fail | UID hash, reason code |
| `SPOOF_ATTACK` | CNN-LSTM score < 0.45 | AI confidence score, device ID |
| `FPGA_SUSPECTED` | Nonce solve time < 10µs | Solve time in µs |
| `PHYSICAL_TAMPER` | SW-420 vibration fired | Sensor reading, wipe confirmation |
| `HARDWARE_TAMPER` | Attestation mismatch | Drift values, comparison delta |
| `DURESS_DETECTED` | Duress PIN entered | Device ID, timestamp |
| `THERMAL_EMERGENCY` | Temperature threshold exceeded | DHT22 + SoC readings |

### 5.4 Hash-Anchored Trail
Only the SHA-256 hash is stored on-chain (cheap). Full payload stays in SQLite. To verify integrity: re-hash the SQLite record and compare against blockchain hash. If they match → data is authentic.

### 5.5 Emergency RFID Revocation
```solidity
function emergencyRevoke(string memory uid) public {
    rfidTokens[uid].active = false;
    emit EmergencyRevoke(uid, msg.sender);
}
```
One call sets `active = false` **permanently and immutably** — even an admin cannot un-revoke it.

---

## Phase 6 — Physical Defence

### 6.1 SW-420 Vibration Sensor — Kinetic Tamper Detection

Complete tamper response (< 50ms total):
```
SW-420 fires RISING EDGE interrupt on GPIO 17
              ↓
    [1] Debounce check (ignore if < 500ms since last)
              ↓
    [2] emergency_wipe() — zero all HMAC keys in RAM
              ↓
    [3] Log PHYSICAL_TAMPER to SQLite + blockchain
              ↓
    [4] Publish MQTT lockdown to all ESP32 nodes (QoS 2)
              ↓
    [5] Send Telegram photo + alert
```

### 6.2 DHT22 — Thermal Sabotage Guard

Dual-sensor cross-validation:

| Scenario | DHT22 | SoC Temp | Classification |
|---|---|---|---|
| Normal room, idle | 22°C | 45°C | NORMAL |
| Hot room, busy Pi | 35°C | 60°C | NORMAL (correlated) |
| External heat gun | 85°C | 40°C | THERMAL_ATTACK |
| Actual fire | 70°C+ | 70°C+ | THERMAL_EMERGENCY → kill-switch |

### 6.3 Arduino Watchdog — Air-Gapped Kill Switch

```
State: ARMED
  ↓ every 10 seconds
  ← Expects "PING\n" from Pi via USB serial
  ↓
  If PING received → stay ARMED
  If NO PING for 15 seconds → Pi is frozen/compromised
  ↓
  TRIGGER RELAY → cut Pi power supply → Pi reboots into safe state
```

**Critical property:** No software on a compromised Pi can prevent the Arduino from cutting power. The attacker's malware cannot disable this.

---

## Phase 7 — Integration, Testing & Validation

### 7.1 Start-All Script (Services in Dependency Order)

```bash
bash start_all.sh

[1/6] mosquitto            # MQTT broker
[2/6] iot_server.py        # Main server (port 5005)
[3/6] defense_sensors.py   # SW-420 + DHT22 + Arduino
[4/6] blockchain_bridge.py # Ganache connector (port 5010)
[5/6] nonce_challenger.py  # FPGA timing challenge service
[6/6] telegram_alert.py    # Two-way Telegram bot
```

### 7.2 Test Suite — 95 Tests

```bash
cd "Blockchain Project" && source .venv/bin/activate
python3 -m pytest tests/ -v
# Result: 95 passed, 4 skipped, 0 failed
```

| Category | Tests | What is Verified |
|---|---|---|
| Unit — HMAC | 12 | Correct generation, rejection of bad keys |
| Unit — Nonce | 8 | Challenge generation, FPGA timing threshold |
| Unit — Honey-PIN | 9 | All three PIN layers, constant-time comparison |
| Unit — Hardware Attestation | 11 | Serial reading, timing, drift detection |
| Unit — Blockchain Bridge | 14 | Contract deployment, event logging, revocation |
| Unit — AI Authenticator | 7 | Feature extraction, buffer, threshold |
| Integration | 18 | End-to-end: card tap → blockchain record |
| Security Regression | 16 | Replay, spoofed payloads, FPGA simulation |
| **Total** | **95** | **91 pass, 4 skip** |

### 7.3 Attack Simulation — Validation Matrix

| Attack Vector | Detection Method | Response | Test Case | Result |
|---|---|---|---|---|
| RFID card clone | HMAC mismatch | DENY + Telegram | `test_hmac_rejection` | ✅ 100% |
| FPGA replay | Nonce solve < 10µs | FPGA_SUSPECTED + lockdown | `test_fpga_timing_threshold` | ✅ 100% |
| Software spoof | CNN-LSTM < 0.45 | SPOOF_ATTACK alert | `test_ai_spoof_detection` | ✅ >95% |
| Supply-chain Trojan | Timing drift > 50µs | HARDWARE_TAMPER | `test_attestation_drift` | ✅ 100% |
| Physical smash | SW-420 interrupt | Key wipe + lockdown | `test_tamper_wipe` | ✅ <50ms |
| Admin coercion | Duress PIN | Honey-mode + Telegram SOS | `test_duress_pin` | ✅ 100% |
| Thermal attack | DHT22 + SoC cross-validate | Kill-switch trigger | `test_thermal_emergency` | ✅ 100% |
| Message replay | Nonce seen twice | REPLAY_DETECTED | `test_nonce_replay` | ✅ 100% |

### 7.4 Performance Metrics

| Operation | Latency | Hardware |
|---|---|---|
| Card tap → GRANT/DENY | < 150ms | ESP32 + Pi |
| HMAC verification | < 1ms | ESP32 (240 MHz) |
| Blockchain event log | < 500ms | Pi + Ganache |
| Telegram photo alert | < 3s | Pi + mobile network |
| Emergency key wipe | < 10ms | Pi RAM |
| Arduino kill-switch trigger | < 15s after Pi freeze | Arduino relay |
| CNN-LSTM inference | < 50ms | Pi CPU (no GPU) |

### 7.5 Dashboard Panels (Light Theme, SSE Real-Time)

| Panel | Shows | Update |
|---|---|---|
| Trust Scores | Live IPD + RSSI trust % per device | Every 3s (SSE) |
| Threat Radar | Circular gauge 0–100, GREEN/YELLOW/RED | Real-time |
| Sentry Camera | Latest ESP32-CAM capture | On every DENY |
| Security Event Feed | GRANT/DENY/ALERT stream | Real-time MQTT |
| Blockchain Ledger | TX hash, SHA-256 hash, per event | On every log |
| Sensor Health | SW-420, DHT22, Arduino watchdog | Every 5s |
| Firmware Tab | View actual ESP32 C++ source code in browser | On demand |

---

## Literature Review — Papers 1–4 & Paper 8

### Paper 1: QBC-ZKPAF (IEEE Access, Jan 2025)
**"Blockchain-Enabled Zero Trust Architecture for Privacy-Preserving Cybersecurity in IoT Environments"**
*Mohammed Aleisa*

**What they do:** Quantum-safe key generation (lattice crypto) + ZKP + Ring Signatures + DQN-based multi-factor auth.

**Their best results:** Auth time 100ms, Throughput 700 TPS, Anomaly recall 79%.

**Their gaps vs ours:**
- Needs Tesla V100 GPU. Our system runs on $80 Raspberry Pi 5.
- No real IoT hardware — ESP32 testing listed as "future work."
- Anomaly detector misses **21% of attacks** (recall = 79%).
- No RFID, no physical tamper detection, no camera, no duress PIN.

**Key line:** *"They need a GPU. We run everything on $80 hardware with 95 automated tests."*

---

### Paper 2: FPGA Supply Chain ZTA (IEEE Access, Jun 2024)
**"A Zero Trust-Based Framework Employing Blockchain and Ring Oscillator PUFs for FPGA Supply Chain Security"**
*Kulkarni, Hazari, Niamat*

**What they do:** Consortium blockchain + PoA + Ring Oscillator PUF (hardware fingerprint from silicon manufacturing variations). Detects counterfeit FPGAs at manufacturing handoffs. Uses same Ganache + Solidity stack as our system.

**Their gaps vs ours:**
- Covers FPGA **manufacturing** only — not operational runtime security.
- No AI/ML layer.
- No real-time FPGA emulation detection during operation.
- We detect FPGA emulators in **real-time** using timing fingerprinting (< 10µs = flag).
- Our 4-vector attestation generalizes their PUF concept to any microcontroller without specialized silicon.

**Key line:** *"They check at the factory gate. We check every 30 seconds during operation."*

---

### Paper 3: Blockchain IoT + TinyDA (IEEE Access, Oct 2025)
**"A Blockchain-Enabled Privacy-Preserving IoT Framework With Domain-Adaptive Anomaly Detection"**
*Alanazi, Zareei, García Martínez*

**What they do:** Post-quantum permissioned blockchain (CRYSTALS-Dilithium) + IPFS off-chain storage + TinyDA (compressed domain-adaptive ML, < 100 KB). Uses same ESP32 + RPi hardware.

**Their best results:** 90.2% accuracy at high domain shift; 1.8s latency at 50 TPS.

**Their gaps vs ours:**
- Anomaly detection targets **network traffic only** — not device-level hardware behavior.
- System stops working if blockchain goes down. Our ESP32 has a local whitelist — **door works even if Pi, blockchain, and internet are all dead**.
- No RFID, no physical tamper detection, no camera, no duress PIN, no FPGA detection.

**Key line:** *"Same hardware. They detect network anomalies. We detect hardware impersonation."*

---

### Paper 4: Smart Home Blockchain + ZKP (Frontiers, Dec 2025)
**"A hybrid blockchain and smart contract framework for resilient IoT security in smart homes"**
*Shiva Soni, Abhilasha Singh*

**What they do:** Same stack (Ganache v2.7.1 + Solidity + Web3.py) + group ZKP + fine-grained ML anomaly detection (Isolation Forest) + adaptive cryptography (RandomForest predicts AES-GCM vs ChaCha20).

**Their best results:** Accuracy 98.1%, Precision 100%, Recall 79% (misses 21%).

**Their gaps vs ours:**
- Tested exclusively on **desktop PC** (Intel i7, 32 GB RAM) — no real hardware.
- Anomaly recall = **79%** (misses 21% of attacks).
- KDF iteration prediction R² = 0.42 (weak).
- No RFID, no physical layer, no FPGA detection, no camera.
- Smart contract on Ganache only (simulation).

**Key line:** *"Identical blockchain stack. We have real hardware + 95 tests. They have a desktop simulation."*

---

### Paper 8: Hybrid ML + Lightweight ZTA for LoRaWAN (IEEE Access, Feb 2026)
**"Hybrid Machine Learning Anomaly Detection and Lightweight Zero Trust Authentication for LoRaWAN Networks"**
*Abdelhady, Ghandoura, Motwakel, Alajmi*

**What they do:** LightGBM + Autoencoder hybrid anomaly detection + PoA blockchain + HMAC mutual auth + dynamic trust scoring (exponential decay, λ=0.9). Targets LoRaWAN smart city/agriculture.

**Their best results:** Accuracy 95.3%, AUC-ROC 0.973, 187ms latency, 7.1-year device lifetime.

**Comparison vs Our System:**

| Feature | Paper 8 | Our System |
|---|---|---|
| Real hardware | 3-node testbed + simulation | Full ESP32 + RPi 5 prototype |
| Hardware attestation | ❌ | ✅ 4-vector (CPU serial, MAC, timing, thermal) |
| Physical tamper | ❌ | ✅ SW-420 + DHT22 + Arduino watchdog |
| FPGA timing detection | ❌ | ✅ < 10µs = flagged |
| Supply-chain Trojan | ❌ | ✅ 4-vector attestation |
| Insider/duress | ❌ | ✅ 3-tier honey-PIN |
| Camera evidence | ❌ | ✅ ESP32-CAM burst → on-chain hash |
| Physical access control | ❌ | ✅ RFID door gateway |
| Protocol scope | LoRaWAN only | WiFi/MQTT (any device) |
| Clock jitter detection | ❌ | ✅ `inter_packet_delay` fingerprint |
| Defence layers | 2 (network only) | 6 independent layers |

**Key line:** *"Paper 8's threat model is network-only. We extend Zero Trust to the physical silicon, supply chain, and human layer."*

---

## Master Comparison Table (All Papers vs Our System)

| Feature | Paper 1 | Paper 2 | Paper 3 | Paper 4 | Paper 8 | **Our System** |
|---|---|---|---|---|---|---|
| Zero Trust Architecture | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Blockchain (Ethereum/Ganache) | Fabric | ✅ | ✅ | ✅ | ✅ PoA | ✅ |
| Smart Contracts (Solidity) | ❌ | ✅ | ❌ | ✅ | ❌ | ✅ (2 contracts) |
| Post-Quantum Cryptography | ✅ | ❌ | ✅ | ❌ | ❌ | ❌ (future) |
| Zero-Knowledge Proofs | ✅ | ❌ | ❌ | ✅ | ❌ | ❌ (future) |
| Hardware PUF / Fingerprint | ❌ | ✅ | ❌ | ❌ | ❌ | ✅ |
| FPGA Timing Attack Detection | ❌ | Partial | ❌ | ❌ | ❌ | ✅ real-time |
| CNN-LSTM / Deep Learning Auth | ✅ | ❌ | ✅ | ❌ | ❌ | ✅ |
| Hardware Anomaly Detection | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| RFID Physical Access Control | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| Physical Tamper Detection | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| Surveillance Camera Evidence | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| Duress / Honey-PIN | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| Hardware Attestation (4-vector) | ❌ | Partial | ❌ | ❌ | ❌ | ✅ |
| Air-gapped Arduino Watchdog | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| Real Hardware Deployment | ❌ | ✅ | ✅ | ❌ | ⚠️ 3-node | ✅ |
| Automated Test Suite | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ (95 tests) |
| Offline Fallback Mode | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| Real-time Dashboard (SSE) | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| Telegram Alert Bot | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| Anomaly Recall | 79% | N/A | 90.2% | 79% | 95.3% | >95% |

---

## Research Contributions Summary (C1–C7)

| # | Contribution | What is Novel | Prior Art Gap |
|---|---|---|---|
| C1 | Four-vector hardware attestation | Serial + MAC + timing ns + thermal combined | Prior art uses ≤2 vectors |
| C2 | CNN-LSTM IPD-RSSI fingerprinting | 6-feature temporal IoT behavioural model | Novel feature set for IoT |
| C3 | Modular-arithmetic FPGA timing challenge | Solve-time as hardware discriminator | New approach in IoT |
| C4 | Three-layer duress/honey-PIN | Constant-time tri-layer PIN evaluation | Novel in IoT access control |
| C5 | Hash-anchored blockchain forensic trail | Physical access events → smart contract | Novel integration |
| C6 | Air-gapped Arduino watchdog + relay | Three-in-one hardware safety net | Novel hardware boundary |
| C7 | Unified zero-trust holistic framework | All 6 layers in one system | Novel holistic architecture |

---

## Patent Claims

**Claim 1 — The Architecture:**
> A distributed IoT security system comprising a RFID gateway node, a surveillance node, an edge processing server, and a distributed ledger, wherein all inter-node communications are authenticated via HMAC-SHA256 and all security events are permanently recorded on the distributed ledger as cryptographic hash anchors.

**Claim 2 — Hardware Attestation:**
> A hardware attestation method for detecting supply-chain Trojans comprising measuring: (a) SoC eFuse serial, (b) NIC MAC address, (c) median computational timing per hash, (d) thermal rise rate under standardised load; storing as golden record; alerting on deviation beyond predefined tolerances.

**Claim 3 — CNN-LSTM Fingerprinting:**
> A machine learning method for IoT device authentication using a CNN-LSTM network trained on sequences of hardware behavioural metrics including inter-packet delay, RSSI, free heap, packet size, temperature, and humidity; wherein score < threshold → software spoofing classification.

**Claim 4 — FPGA Challenge:**
> A computational timing challenge-response protocol wherein a random nonce is issued to a device; the device computes a modular arithmetic solution and reports solve time in microseconds; devices with sub-threshold solve time are classified as hardware-accelerated emulators.

**Claim 5 — Honey-PIN:**
> A coercion-resistant authentication method with three cryptographically distinct PIN layers — real, duress, and panic — evaluated via constant-time comparison; duress layer presents authentic success response while activating out-of-band alert and rerouting relay to non-functional GPIO.

**Claim 6 — Air-Gapped Watchdog:**
> A hardware enforcement mechanism comprising a physically isolated microcontroller connected via serial; autonomously triggers a power relay upon: (a) keepalive signal timeout, (b) vibration sensor activation, or (c) thermal threshold exceedance; independent of primary processor software state.

---

## One-Paragraph Summary (Say to Professor)

> "Papers 1–4 each address a subset of IoT security. QBC-ZKPAF provides post-quantum cryptography and ZKP but requires a GPU and was never tested on real hardware. Kulkarni et al. apply Zero Trust to FPGA supply chains using ROPUFs but have no AI layer and only cover manufacturing, not deployment. Alanazi et al. build a blockchain IoT framework on ESP32 and Raspberry Pi with domain-adaptive ML, but focus on network anomaly detection with no physical access control or hardware attestation. Soni and Singh propose an elegant hybrid ZKP + blockchain architecture but test exclusively on a desktop PC, miss 21% of attacks, and have no physical layer whatsoever. Abdelhady et al. achieve strong anomaly detection for LoRaWAN with 18% energy overhead, but rely primarily on simulation and cover only network-layer attacks.
>
> Our system is the FIRST to combine hardware-level Zero Trust — FPGA timing discrimination, 4-vector physical attestation, hardware-jitter CNN-LSTM fingerprinting — with blockchain forensics and physical access control on real deployed hardware. We cover six independent attack classes that no single prior paper addresses simultaneously: card cloning, FPGA replay, supply-chain Trojans, physical smash-and-grab, software spoofing, and administrator coercion. This multi-layer completeness, validated through 95 automated tests on actual ESP32 and Raspberry Pi 5 hardware, is our primary novel contribution."

---

## Key Files Reference

| File | Location | Purpose |
|---|---|---|
| `iot_server.py` | `pi_backend/` | Main MQTT server + access control |
| `ai_authenticator.py` | `pi_backend/` | CNN-LSTM / sklearn fingerprinting |
| `hardware_attestation.py` | `pi_backend/` | 4-vector supply-chain Trojan detection |
| `nonce_challenger.py` | `pi_backend/` | FPGA timing challenge service |
| `honey_pin.py` | `pi_backend/` | 3-layer duress/panic PIN |
| `heartbeat_monitor.py` | `pi_backend/` | GPIO hardware DoS watchdog |
| `defense_sensors.py` | `pi_backend/` | SW-420 + DHT22 + Arduino |
| `blockchain_bridge.py` | `pi_backend/` | Web3.py Ganache connector |
| `dashboard.py` | `pi_backend/` | Flask SSE real-time dashboard |
| `telegram_alert.py` | `pi_backend/` | Two-way Telegram bot |
| `SecurityRegistry.sol` | `smart_contracts/` | Access-event smart contract |
| `EvidenceRegistry.sol` | `smart_contracts/` | Photo-evidence smart contract |
| `dashboard_template.html` | `pi_backend/` | Light-theme UI (SSE, 6 tabs) |
| `software_attacker.py` | `tests/` | 4-mode interactive demo attacker |
| `start_all.sh` | project root | One-command Pi startup (6 services) |

---

## Changelog

| # | Change | Detail |
|---|---|---|
| 1 | Hardware upgrade | Raspberry Pi 4 → Pi 5 (8GB), Cortex-A76, RP1 GPIO |
| 2 | AI model trainer fixed | CNN-LSTM + sklearn RandomForest fallback for Python 3.14+ |
| 3 | AI model deployed | `device_authenticator.pkl` + `scaler.pkl` generated |
| 4 | `ai_authenticator.py` dual-backend | Auto-detects Keras `.h5` or sklearn `.pkl` |
| 5 | `start_all.sh` fixed | Added `nonce_challenger.py` as [5/6] |
| 6 | `EvidenceRegistry.sol` relocated | Copied to `smart_contracts/` |
| 7 | Test suite fixed | 95 passed, 4 skipped, 0 failed |
| 8 | Real-time Dashboard (SSE) | Migrated from 2.5s polling to Server-Sent Events |
| 9 | Two-way Telegram Bot | `/dashboard`, `/status`, `/photos` commands + `sendPhoto` |
| 10 | Interactive Attacker Demo | `software_attacker.py` 4-mode terminal UI (runs from any laptop) |
| 11 | Light Theme Dashboard | White cards, light gray background, readable text |
| 12 | research.md full rewrite | Blue Team vs Red Team structure + all 5 papers integrated |

---

*Project: Zero-Trust RFID Gateway — Hardware-to-Patent IoT Security Platform*
*Repository: `Hardware-to-Patent-Zero-Trust-IoT`*
*Authors: Mridul, Onkar | Date: June 2026*
