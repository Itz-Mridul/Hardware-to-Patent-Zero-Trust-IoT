# 🎬 Zero-Trust IoT — Live Demo Script
**Hardware-to-Patent Security Platform | Presentation Guide**

---

## 📦 Table Setup (Before Professor Arrives)

```
LEFT SIDE — "The Front Door"          RIGHT SIDE — "The Control Room"
┌─────────────────────────┐           ┌──────────────────────────────┐
│  Standard ESP32         │           │  Raspberry Pi 5 (8GB)        │
│  + RC522 RFID Reader    │           │  + Laptop showing dashboard  │
│  + RGB LED              │           │                              │
│                         │           │  ESP32-CAM (facing table)    │
│  [RFID cards nearby]    │           │  + Flash LED                 │
│  - Mridul card (real)   │           │                              │
│  - Onkar card (real)    │           │  Mac (open, Ganache running) │
│  - Any other card(fake) │           └──────────────────────────────┘
└─────────────────────────┘
```

### Pre-Demo Checklist (5 min before)
- [ ] Mac: `iot-start` → Ganache open, accounts visible
- [ ] Pi: `bash start_all.sh` → all 6 services running
- [ ] Browser open: `http://192.168.1.113:5001`  ← update if Pi IP changed
- [ ] ESP32 RFID Gateway: Serial Monitor shows heartbeats
- [ ] ESP32-CAM: Serial Monitor shows `[ 💓 ] IPD: 500ms`
- [ ] Telegram app open on phone
- [ ] Both RFID cards within reach

---

## 🎤 Presentation Script

### INTRO (1 minute)

> *"Today's IoT security assumes the network is safe. Our system assumes it's already compromised — that's what Zero-Trust means. Every device must continuously prove its identity. Every access is logged permanently. Every intruder is photographed. Let us show you how."*

Point to the table layout and explain the 3 nodes:
- **Standard ESP32** = The door lock
- **ESP32-CAM** = The silent watcher
- **Raspberry Pi** = The intelligent brain
- **Mac** = The permanent blockchain record

---

## ACT 1 — Normal Authorized Access (2 min)

### What to do:
Tap **Mridul's card** on the RC522 reader.

### What happens (explain each step):
| Event | What to point at |
|---|---|
| LED turns **GREEN** for 5 seconds | Point at the RGB LED |
| Dashboard logs `✅ GRANTED — Mridul` | Point at laptop screen |
| Blockchain table gets a new row with SHA-256 hash | Point at Forensic Ledger panel |

### What to say:
> *"The card's UID and HMAC signature are verified in under 200ms. The green light confirms access. The moment this happens, an immutable cryptographic record is written to our private Ethereum blockchain — timestamped and tamper-proof forever."*

---

## ACT 2 — Unauthorized Access + Surveillance (2 min)

### What to do:
Tap an **unknown/fake card** on the RC522 reader.

### What happens (explain each step):
| Event | What to point at |
|---|---|
| LED turns **RED** for 5 seconds | Point at the RGB LED |
| ESP32-CAM **flashes 5 times** | Point at the camera |
| Telegram receives **photo + alert** | Show phone to professor |
| Dashboard logs `❌ DENY` with intruder photos | Point at laptop screen |
| Blockchain gets DENY TX hash | Point at Forensic Ledger |

### What to say:
> *"The system detected an unrecognized credential. In the same instant — the door stays locked, and our surveillance node silently wakes up, fires its flash, and captures 5 burst photos of the intruder in 3 seconds. These photos are pushed to our Telegram channel AND permanently linked to the blockchain record. The attacker cannot deny they were there."*

---

## ACT 3 — AI Trust Scoring + Anti-Spoofing (2 min)

### What to do:
Point to the **Hardware Trust Scores** panel on the dashboard.

### What to show:
- Live trust percentage for each ESP32 node
- IPD (Inter-Packet Delay) in milliseconds
- RSSI signal strength

### What to say:
> *"Every 500 milliseconds, each ESP32 sends a cryptographically signed heartbeat. Our CNN-LSTM AI model analyzes the timing pattern — the inter-packet delay — and the signal strength. A real ESP32 has a consistent, hardware-level timing fingerprint. An FPGA clone trying to spoof it will have microsecond-level jitter that our model detects as a threat."*

> *"If the trust score drops below our threshold, the device is quarantined. No card tap is even attempted. This is hardware-level Zero-Trust."*

---

## ACT 4 — Physical Tamper Detection (1 min)

### What to do:
Lightly **shake the Raspberry Pi** (or the table near the SW-420 sensor).

### What happens:
| Event | What to point at |
|---|---|
| Dashboard shows `PHYSICAL TAMPER` alert | Tamper panel on dashboard |
| Telegram alert fires | Show phone |

### What to say:
> *"Our SW-420 vibration sensor detects physical tampering — someone trying to open the enclosure or move the device. The moment it triggers, cryptographic keys in RAM are wiped. There is nothing left to steal. The attacker gets hardware — but it's a brick."*

---

## ACT 5 — Blockchain Forensic Evidence (1 min)

### What to show:
- Open **Ganache** on Mac
- Show the **Transactions** tab — every card tap is a blockchain transaction
- Show the **SHA-256 hashes** in the dashboard matching the on-chain data

### What to say:
> *"Every single event — grant, deny, tamper, thermal anomaly — is logged here as an Ethereum transaction with a SHA-256 hash. This is court-admissible forensic evidence. You cannot alter a single entry without invalidating every hash that follows. This is why we call it Hardware-to-Patent — the evidence chain starts at the physical card and ends as permanent law."*

---

## ACT 6 — Attack Simulation with Rogue Skimmer (1 min)

### What to do:
Power on the **Rogue Skimmer ESP32** (the third ESP32 running `esp32_rogue_skimmer.ino`).

### What happens:
| Event | What to point at |
|---|---|
| Dashboard **Threat Radar** turns RED | Threat panel on dashboard |
| `AI SPOOFING` counter increments | Tamper summary panel |

### What to say:
> *"This device is simulating an FPGA hardware clone trying to replay a legitimate heartbeat. Watch the dashboard — within seconds, our AI fingerprinting detects the timing anomaly and flags it. The rogue device is quarantined before it can send a single RFID request."*

---

## 📊 Q&A Cheat Sheet

| Question | Answer |
|---|---|
| *"What if the Pi loses power?"* | ESP32 has a local UID whitelist — continues granting/denying offline |
| *"What if Ganache goes down?"* | Events are cached in SQLite locally, synced to blockchain when reconnected |
| *"Can someone jam the WiFi?"* | Heartbeat loss is detected — devices are immediately quarantined |
| *"Is this patentable?"* | Yes — see `docs/PATENT_CLAIMS.md` for 6 novel patent claims |
| *"What's the latency?"* | GRANT/DENY decision in under 200ms, photo in under 4 seconds |
| *"How many users can it support?"* | Limited by `authorized_users.json` — scalable to any size DB |

---

## 🛑 Emergency Recovery

If something breaks during demo:

**Dashboard not loading:**
```bash
# On Pi
iot-stop && iot-start
```

**ESP32 not responding:**
- Press RESET button on ESP32
- Check Serial Monitor for WiFi connection message

**Telegram not sending:**
- Verify phone has internet (not just local WiFi)
- Check `.env` has correct `TELEGRAM_BOT_TOKEN`

**Blockchain TX not appearing:**
```bash
# On Mac — check Ganache is still running
iot-status
```

---

## ⏱️ Demo Timeline

| Time | Action |
|---|---|
| 0:00 | Intro — explain architecture |
| 1:00 | ACT 1 — tap Mridul card (green LED) |
| 3:00 | ACT 2 — tap fake card (red LED + Telegram photo) |
| 5:00 | ACT 3 — show trust score panel |
| 7:00 | ACT 4 — physical tamper demo |
| 8:00 | ACT 5 — Ganache blockchain evidence |
| 9:00 | ACT 6 — rogue skimmer attack |
| 10:00 | Q&A |
