# 🔌 Complete Wiring + Upload Guide
# Zero-Trust IoT — All 3 Devices

> **3 devices to wire and flash:**
> 1. Standard ESP32 (RFID Gateway) — `esp32_rfid_gateway.ino`
> 2. ESP32-CAM (Surveillance Node) — `esp32_cam_surveillance.ino`
> 3. Arduino Uno (Watchdog) — `watchdog.ino`

> ✅ **Code Status: All 3 firmware files verified — NO changes needed.**
> The only file you edit before flashing is `network_config.h`.

---

## ⚙️ Before You Flash Anything — Edit `network_config.h`

File location: `Blockchain Project/network_config.h`

Open it and change only these 3 values:

```cpp
#define WIFI_SSID      "YourHotspotName"    // ← your WiFi name
#define WIFI_PASSWORD  "YourPassword"       // ← your WiFi password
#define PI_MQTT_BROKER "192.168.x.x"        // ← Pi's IP (run: hostname -I on Pi)
```

After editing this ONE file, reflash all 3 ESP32 boards. Done.

---

---

## 📦 DEVICE 1 — Standard ESP32 (RFID Gateway)

### What it does
- Reads RFID cards with the RC522 reader
- Computes HMAC-SHA256 and sends to Pi over MQTT
- Flashes Green LED (GRANT) or Red LED (DENY)
- Responds to FPGA nonce challenges from Pi

### Firmware file
```
esp32_cam/sentry/esp32_rfid_gateway/esp32_rfid_gateway.ino
```

---

### 🔌 Wiring Diagram

#### Part A — RC522 RFID Reader → Standard ESP32

```
RC522 Module                     Standard ESP32
┌─────────────┐                  ┌──────────────────┐
│  SDA (SS)   │ ──────────────►  │ GPIO  5          │
│  SCK        │ ──────────────►  │ GPIO 18          │
│  MOSI       │ ──────────────►  │ GPIO 23          │
│  MISO       │ ──────────────►  │ GPIO 19          │
│  RST        │ ──────────────►  │ GPIO 22          │
│  VCC        │ ──────────────►  │ 3.3V  ⚠️ NOT 5V │
│  GND        │ ──────────────►  │ GND              │
│  IRQ        │   NOT CONNECTED                     │
└─────────────┘                  └──────────────────┘
```

> ⚠️ **CRITICAL:** RC522 runs on **3.3V only**. Connecting VCC to 5V will permanently burn the chip.

#### Part B — RGB LED → Standard ESP32

Using a **Common Anode** RGB LED (most common type — the longest leg is the common pin).

```
RGB LED                         Standard ESP32
┌──────────────┐                ┌──────────────────────────────────┐
│ RED  leg (+) │ ── 220Ω ────►  │ GPIO 27                          │
│ GRN  leg (+) │ ── 220Ω ────►  │ GPIO 26                          │
│ COM  leg (-) │ ──────────►    │ GND                              │
└──────────────┘                └──────────────────────────────────┘
```

> ℹ️ **Common Anode LED logic is inverted:** The code drives a pin **LOW** to turn the LED **ON** and **HIGH** to turn it **OFF**. This is already handled in the firmware — don't worry about it.

#### Full Wiring Summary Table

| Component | Component Pin | Wire To (ESP32) |
|---|---|---|
| RC522 | SDA / SS | GPIO **5** |
| RC522 | SCK | GPIO **18** |
| RC522 | MOSI | GPIO **23** |
| RC522 | MISO | GPIO **19** |
| RC522 | RST | GPIO **22** |
| RC522 | VCC | **3.3V** |
| RC522 | GND | GND |
| Red LED | Anode (+) via 220Ω | GPIO **27** |
| Green LED | Anode (+) via 220Ω | GPIO **26** |
| LED Common | Cathode (–) | GND |

---

### 🖥️ Arduino IDE Upload Settings

| Setting | Value |
|---|---|
| Board | **ESP32 Dev Module** |
| Upload Speed | **115200** |
| Flash Frequency | 80MHz |
| Flash Mode | QIO |
| Partition Scheme | Default 4MB with spiffs |
| Port | The COM/tty port that appears when you plug in the ESP32 |

#### Required Libraries (install via Library Manager)
- `MFRC522` by GithubCommunity
- `PubSubClient` by Nick O'Leary
- `ArduinoJson` by Benoit Blanchon

#### How to Upload
1. Open `esp32_rfid_gateway/esp32_rfid_gateway.ino` in Arduino IDE
2. Select board: `ESP32 Dev Module`
3. Select the correct COM port
4. Click **Upload ▶**
5. Open Serial Monitor at `115200` baud — you should see:

```
╔══════════════════════════════════╗
║  ZERO-TRUST RFID GATEWAY  v1     ║
║  Standard ESP32 + RC522          ║
╚══════════════════════════════════╝

 [ 📡 RFID] Chip: 0x92 ✅ Official
 [ 🌐 ] Connecting WiFi......
 [ 🌐 ] IP: 192.168.1.xxx

  >>> ARMED. TAP CARD. <<<
```

---

---

## 📦 DEVICE 2 — ESP32-CAM (Surveillance Node)

### What it does
- Waits silently (passive mode, zero traffic)
- When Pi sends `mailbox/photo_request`, captures a **5-photo burst**
- Sends each JPEG over MQTT to Pi
- Flash LED blinks once per shot

### Firmware file
```
esp32_cam/sentry/esp32_cam_surveillance/esp32_cam_surveillance.ino
```

---

### 🔌 Wiring Diagram

The ESP32-CAM (AI Thinker model) has the **camera built in** — no wiring needed between camera and board. The camera ribbon cable is pre-connected at the factory.

**You only need to wire the power supply and the USB-to-Serial programmer:**

#### Part A — Power Supply

The ESP32-CAM needs **5V/2A** minimum (the camera is power-hungry).

```
Power Source                      ESP32-CAM
┌──────────────┐                  ┌──────────────────┐
│   5V  (+)    │ ──────────────►  │  5V pin          │
│   GND (-)    │ ──────────────►  │  GND             │
└──────────────┘                  └──────────────────┘
```

> ⚠️ Do **NOT** power from 3.3V — the OV2640 camera draws too much current and will cause random reboots.

#### Part B — For Flashing Only (FTDI Programmer)

The ESP32-CAM has **no USB port**. You need an FTDI USB-to-Serial adapter (FTDI232 or CH340) to flash it.

```
FTDI Adapter                      ESP32-CAM
┌──────────────┐                  ┌──────────────────────────────┐
│  5V          │ ──────────────►  │ 5V                           │
│  GND         │ ──────────────►  │ GND                          │
│  TX          │ ──────────────►  │ U0R (UART0 RX)               │
│  RX          │ ──────────────►  │ U0T (UART0 TX)               │
│              │                  │ GPIO 0 ── GND  (boot mode)   │
└──────────────┘                  └──────────────────────────────┘
```

> 🔑 **GPIO 0 must be connected to GND** while pressing Upload. After flashing is done, disconnect GPIO 0 from GND and press the RESET button on the ESP32-CAM.

#### Pin Reference Table (ESP32-CAM AI Thinker)

| ESP32-CAM Pin | Connected To | Notes |
|---|---|---|
| 5V | 5V power supply | |
| GND | Ground | |
| U0R (GPIO 3) | FTDI TX | For flashing only |
| U0T (GPIO 1) | FTDI RX | For flashing only |
| GPIO 0 | GND (during flash) | Remove after flashing |
| GPIO 4 | Flash LED (built-in) | Used in firmware for burst flash |
| All camera pins | Pre-wired on board | No user wiring needed |

---

### 🖥️ Arduino IDE Upload Settings

| Setting | Value |
|---|---|
| Board | **AI Thinker ESP32-CAM** |
| Upload Speed | **115200** |
| Flash Frequency | 80MHz |
| Flash Mode | QIO |
| Partition Scheme | **Huge APP (3MB No OTA/1MB SPIFFS)** |
| Port | FTDI adapter's COM/tty port |

> ⚠️ **Partition Scheme is important!** The camera library is large. Use **"Huge APP"** or you'll get "Sketch too big" error.

#### Required Libraries (same as RFID gateway, plus:)
- `esp32-camera` — built into the ESP32 Arduino board package (no separate install needed)
- `PubSubClient` by Nick O'Leary
- `ArduinoJson` by Benoit Blanchon

#### How to Upload
1. Wire FTDI to ESP32-CAM, connect GPIO 0 → GND
2. Open `esp32_cam_surveillance/esp32_cam_surveillance.ino`
3. Select board: **AI Thinker ESP32-CAM**
4. Select the FTDI's COM port
5. Click **Upload ▶** — hold the board's RESET button for 1 second while upload starts if it doesn't connect
6. **After "Done uploading":** disconnect GPIO 0 from GND, press RESET
7. Open Serial Monitor at `115200` baud — you should see:

```
╔══════════════════════════════════╗
║  ZERO-TRUST SURVEILLANCE NODE   ║
║  ESP32-CAM  v1                  ║
╚══════════════════════════════════╝

 [ 📷 CAM ] Camera ready ✅
 [ 🌐 ] Connecting WiFi......
 [ 🌐 ] IP: 192.168.1.xxx

  >>> SURVEILLANCE ACTIVE <<<
```

If you see `[ ⚠️ CAM ] Camera init failed`, check:
- GPIO 0 is disconnected from GND (it interferes with camera init)
- Power supply is 5V/2A minimum
- Camera ribbon cable is properly seated in the connector

---

---

## 📦 DEVICE 3 — Arduino Uno (Air-Gapped Watchdog)

### What it does
- Monitors the Raspberry Pi via USB serial keepalive (PING)
- If Pi stops sending PING for **30 seconds** → cuts Pi's power via relay
- Monitors **SW-420** vibration sensor → cuts power on any tamper
- Monitors **DHT22** temperature → cuts power if temp > 70°C
- Sends sensor data to Pi as JSON over USB serial

### Firmware file
```
arduino_watchdog/watchdog/watchdog.ino
```

---

### 🔌 Wiring Diagram

#### Part A — SW-420 Vibration Sensor → Arduino Uno

```
SW-420 Sensor                    Arduino Uno
┌──────────────┐                  ┌──────────────────┐
│  OUT         │ ──────────────►  │ Pin 3 (INT1)     │
│  VCC         │ ──────────────►  │ 5V               │
│  GND         │ ──────────────►  │ GND              │
└──────────────┘                  └──────────────────┘
```

> ℹ️ **Pin 3** is used because it supports hardware interrupts on the Arduino Uno. The firmware uses `attachInterrupt(digitalPinToInterrupt(VIB_PIN), vibrationISR, FALLING)`. Do NOT use any other pin.

#### Part B — DHT22 Temperature/Humidity Sensor → Arduino Uno

```
DHT22 Sensor                     Arduino Uno
┌──────────────┐                  ┌──────────────────────────────┐
│  VCC  (pin1) │ ──────────────►  │ 5V                           │
│  DATA (pin2) │ ── 10kΩ pull-up  │ Pin 2 + 10kΩ to 5V           │
│  NC   (pin3) │   NOT CONNECTED  │                              │
│  GND  (pin4) │ ──────────────►  │ GND                          │
└──────────────┘                  └──────────────────────────────┘
```

> ℹ️ The 10kΩ resistor goes **between the DATA pin and 5V** (pull-up resistor). This is required for the DHT22 1-Wire protocol to work correctly.

#### Part C — 5V Relay Module → Arduino Uno (Kill Switch)

The relay physically controls the Raspberry Pi's power supply. When the relay is triggered, it cuts the Pi's 5V line.

```
5V Relay Module                  Arduino Uno
┌──────────────┐                  ┌──────────────────┐
│  VCC         │ ──────────────►  │ 5V               │
│  GND         │ ──────────────►  │ GND              │
│  IN (Signal) │ ──────────────►  │ Pin 7            │
└──────────────┘                  └──────────────────┘

Relay Output Terminals (for Pi's power wire):
┌──────────────────────────────────────────────────────┐
│  COM  ──── (+) from Pi's power supply (5V red wire)  │
│  NC   ──── (+) to Pi's 5V pin                        │
│  NO   ──── (leave empty)                             │
└──────────────────────────────────────────────────────┘
```

> ℹ️ **NC = Normally Closed** = Pi is powered ON by default. When Arduino fires `digitalWrite(RELAY_PIN, HIGH)`, the relay opens → Pi loses power.

#### Full Wiring Summary Table

| Component | Component Pin | Wire To (Arduino Uno) |
|---|---|---|
| SW-420 | OUT | Pin **3** |
| SW-420 | VCC | **5V** |
| SW-420 | GND | GND |
| DHT22 | VCC (pin 1) | **5V** |
| DHT22 | DATA (pin 2) | Pin **2** + 10kΩ to 5V |
| DHT22 | GND (pin 4) | GND |
| Relay Module | VCC | **5V** |
| Relay Module | GND | GND |
| Relay Module | IN / Signal | Pin **7** |
| Relay COM | — | Pi power supply (+5V in) |
| Relay NC | — | Pi 5V power pin |
| Arduino USB | — | Raspberry Pi USB port |

---

### 🖥️ Arduino IDE Upload Settings

| Setting | Value |
|---|---|
| Board | **Arduino Uno** |
| Programmer | AVRISP mkII (default) |
| Port | Arduino's COM/tty port |

#### Required Library
- `DHT sensor library` by Adafruit — install from Library Manager

#### How to Upload
1. Plug Arduino Uno to your Mac via USB
2. Open `watchdog/watchdog.ino` in Arduino IDE
3. Select board: **Arduino Uno**
4. Select the correct COM port
5. Click **Upload ▶**
6. Open Serial Monitor at **9600 baud** (important — NOT 115200)
7. You should see:

```
=======================================================
   ZERO-TRUST WATCHDOG v3.0  |  STATUS: ARMED
=======================================================
 [INIT] Air-Gapped Kernel ............... SECURE
 [INIT] SW-420 Kinetic Sensor ........... ONLINE
 [INIT] DHT22 Thermal Monitor ........... ONLINE
 [INIT] Power Control Relay (Pin 7) ..... CLOSED
-------------------------------------------------------
 >> SYSTEM READY. MONITORING ENCLAVE.
=======================================================
```

---

### ⚙️ Watchdog Mode Switch

Inside `watchdog.ino` at line 19:

```cpp
bool HUMAN_MODE = true;   // ← change this before flashing
```

| Value | Behaviour | When to use |
|---|---|---|
| `true` | Pretty human-readable dashboard on Serial Monitor | Testing / demo |
| `false` | Strict JSON output for Raspberry Pi backend | Production / connected to Pi |

> ⚠️ **When plugging the Arduino to the Raspberry Pi (production use):** set `HUMAN_MODE = false`, reflash, then connect Arduino USB → Pi USB. The `defense_sensors.py` on the Pi reads JSON lines from the Arduino's serial port.

---

---

## 🗺️ Full System Wiring Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                                                                     │
│   ┌─────────────────────────────────┐                               │
│   │      Standard ESP32             │                               │
│   │  RC522 → GPIO 5,18,19,23,22     │                               │
│   │  Green LED → GPIO 26 (via 220Ω) │  ──── WiFi ────►  Pi MQTT    │
│   │  Red LED   → GPIO 27 (via 220Ω) │                               │
│   └─────────────────────────────────┘                               │
│                                                                     │
│   ┌─────────────────────────────────┐                               │
│   │      ESP32-CAM (AI Thinker)     │                               │
│   │  Camera: pre-wired on board     │  ──── WiFi ────►  Pi MQTT    │
│   │  Flash LED: GPIO 4 (built-in)   │                               │
│   │  Power: 5V/2A supply            │                               │
│   └─────────────────────────────────┘                               │
│                                                                     │
│   ┌─────────────────────────────────┐                               │
│   │      Arduino Uno (Watchdog)     │                               │
│   │  DHT22 → Pin 2 (+ 10kΩ)        │  ──── USB ─────►  Pi USB     │
│   │  SW-420 → Pin 3 (interrupt)     │                               │
│   │  Relay  → Pin 7                 │                               │
│   │  Relay NC ──── Pi 5V Power      │  (physically cuts Pi power)   │
│   └─────────────────────────────────┘                               │
│                                                                     │
│   ┌─────────────────────────────────┐                               │
│   │      Raspberry Pi 4             │                               │
│   │  Runs: iot_server.py            │                               │
│   │        blockchain_bridge.py     │                               │
│   │        defense_sensors.py       │                               │
│   │        dashboard.py (:5001)     │                               │
│   └─────────────────────────────────┘                               │
└─────────────────────────────────────────────────────────────────────┘
```

---

## ✅ Upload Checklist (Do in This Order)

```
[ ] 1. Edit network_config.h — set WiFi SSID, Password, Pi IP
[ ] 2. Start Pi backend: bash start_all.sh (on Pi)
[ ] 3. Flash Arduino Uno → set HUMAN_MODE=false for Pi use
[ ] 4. Flash Standard ESP32 (RFID Gateway)
[ ] 5. Flash ESP32-CAM — remember GPIO 0 → GND during upload only
[ ] 6. Connect Arduino USB → Pi USB port
[ ] 7. Open dashboard: http://<PI_IP>:5001
[ ] 8. Tap RFID card → should see GRANT/DENY on Serial + dashboard
```

---

## 🐛 Common Problems & Fixes

| Problem | Cause | Fix |
|---|---|---|
| RC522 shows `❌ NOT FOUND` | Wrong SPI pins or VCC = 5V | Check wiring, use 3.3V |
| ESP32-CAM shows `Camera init failed` | GPIO 0 still connected to GND | Remove GPIO 0 → GND, press RESET |
| ESP32-CAM shows `Camera init failed` | Underpowered (< 5V/2A) | Use a proper 5V/2A supply |
| Arduino watchdog not reading DHT22 | Missing 10kΩ pull-up resistor | Add 10kΩ between DATA and 5V |
| Watchdog not receiving PING from Pi | Wrong serial port in `.env` | Set `ARDUINO_SERIAL_PORT=/dev/ttyACM0` (or ttyUSB0) |
| ESP32 not connecting to WiFi | Wrong SSID/Password in network_config.h | Edit and reflash |
| MQTT connect failed on ESP32 | Pi IP wrong or Pi not running | Check Pi is on same network, `hostname -I` |

---

*Project: `/Users/itz-mridul/Blockchain Project`*
*Firmware verified: May 2026*
