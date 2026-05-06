# Detailed Hardware Wiring Guide
**Zero-Trust IoT Security — Hardware-to-Patent Deployment**

This guide provides the exact pin-to-pin connections for your 4-device architecture.

---

## 1. The Watchdog (Arduino Uno)
The Arduino acts as the air-gapped physical monitor. It connects to the Raspberry Pi via a **Standard USB Cable** for data, but it controls the Pi's power via the **Relay**.

| Component | Arduino Pin | Component Pin | Notes |
| :--- | :--- | :--- | :--- |
| **DHT22** | 5V | VCC | Power |
| **DHT22** | GND | GND | Ground |
| **DHT22** | **Pin 2** | DATA | 10k Pull-up resistor recommended between VCC and Data |
| **SW-420** | 5V | VCC | Power |
| **SW-420** | GND | GND | Ground |
| **SW-420** | **Pin 3** | DO (Digital Out) | Adjust sensitivity with the blue trimpot |
| **5V Relay** | 5V | VCC | Power |
| **5V Relay** | GND | GND | Ground |
| **5V Relay** | **Pin 7** | IN / SIG | Signal to trigger the power cut |

### ⚡ The "Kill-Switch" USB-C Hack:
1.  Take your **Sacrificial USB-C Extension Cable**.
2.  Carefully cut the outer insulation to expose the wires.
3.  Cut the **RED (Positive/VCC)** wire only.
4.  Connect one end of the cut Red wire to the Relay's **COM (Common)** terminal.
5.  Connect the other end of the cut Red wire to the Relay's **NC (Normally Closed)** terminal.
6.  *Result:* The Pi gets power normally. When the Arduino triggers Pin 7, the Relay clicks, breaks the Red wire connection, and the Pi dies.

---

## 2. The Front Door (ESP32-CAM)
This device handles RFID access and biometric (RGB Challenge) capture.

### RFID RC522 Connection:
| RC522 Pin | ESP32-CAM Pin | Notes |
| :--- | :--- | :--- |
| **VCC** | 3.3V | **DO NOT USE 5V** |
| **RST** | GPIO 12 | Reset |
| **GND** | GND | Ground |
| **MISO** | GPIO 2 | Master In Slave Out |
| **MOSI** | GPIO 15 | Master Out Slave In |
| **SCK** | GPIO 14 | Serial Clock |
| **SDA (SS)** | GPIO 13 | Signal Select |

### Status LEDs ("RGB" Challenge System):
*Note: The code has been updated to a 2-color mode to avoid SPI conflicts with the RFID reader.*
| Component | ESP32-CAM Pin | Wiring Instructions |
| :--- | :--- | :--- |
| **External RED LED** | GPIO 16 | Wire the LED's **Anode (long leg)** to `3.3V`, and its **Cathode (short leg)** to `GPIO 16`. |
| **"GREEN" / Flash** | GPIO 4 | **No wiring needed.** The code reuses the ESP32-CAM's built-in white flash LED. |
| **BLUE LED** | N/A | Skipped in code (`-1`). |

---

## 3. The Telemetry Node (ESP32 Standard)
*   **Wiring:** No sensors attached.
*   **Connection:** Simply plug into any USB Power source (Power bank or Wall adapter).
*   **Role:** It will broadcast Wi-Fi packets that the Pi analyzes for the "Network Fingerprint."

---

## 4. The Vault Server (Raspberry Pi 4/5)
The central brain.

1.  **Power:** Plug the "Hacked" USB-C cable (from Step 1) into the Pi's power port.
2.  **Arduino Connection:** Connect the Arduino Uno to one of the Pi's USB ports using a standard USB cable.
3.  **Network:** Configure the Pi as a **Wi-Fi Hotspot** (SSID and Password must match the ones you put in your `.ino` firmware files).
4.  **Display:** Connect to your laptop via SSH or HDMI to view the Dashboard.

---

## ✅ Pre-Flight Checklist
1.  **Check Grounds:** Ensure all devices sharing a signal have a Common Ground (GND).
2.  **Verify Voltage:** Double-check that the RC522 is on **3.3V**. 5V will destroy the chip.
3.  **Relay Logic:** Ensure the relay is wired to **NC (Normally Closed)** so the Pi stays ON by default.
4.  **USB Serial:** Ensure the USB cable between Pi and Arduino is a *Data* cable, not just a charging cable.

---

## 🛑 Common Hardware & Upload Issues (Troubleshooting)

### 1. ESP32-CAM Upload Fails ("Connecting...")
*   **The Fix (Jumper):** You MUST connect **GPIO 0 to GND** before powering on the board to put it into "Programming Mode." Remove this wire after the upload finishes.

### 2. The "invalid header: 0xffffffff" Reboot Loop
*   **The Cause:** The ESP32-CAM was flashed using the wrong memory setting.
*   **The Fix:** In the Arduino IDE, go to `Tools > Flash Mode` and change it from **QIO to DIO**. Then re-upload.

### 3. ESP32-CAM Keeps Crashing When RFID is Plugged In
*   **The Cause (Power Starvation):** The FTDI module cannot supply enough current (Amps) to power the Camera AND the RFID reader at the same time. This causes a voltage drop (Brownout) and forces a reboot.
*   **The Fix:** Power the ESP32-CAM using a dedicated 5V USB Wall Charger or plug the FTDI directly into the Raspberry Pi (which has a stronger USB power supply than a laptop hub).

### 4. Finding the FTDI Pins on ESP32-CAM
If your board does not have numbers on the serial pins:
*   **GPIO 3** is labeled as **U0R** (Connect FTDI TX here).
*   **GPIO 1** is labeled as **U0T** (Connect FTDI RX here).
