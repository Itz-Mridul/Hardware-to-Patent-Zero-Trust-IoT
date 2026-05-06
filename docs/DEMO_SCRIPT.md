# Zero-Trust IoT Security: Live Tabletop Demonstration
**A Unified Presentation Script for Team A & Team B**

This document outlines how to present the entire patent-pending architecture on a single, small conference table using your exact hardware inventory. 

## 📦 The Hardware Setup (The "Tabletop Layout")

Since you only have **one** 5V relay, we have allocated it to the **Arduino Kill-Switch**. This is your most powerful patent claim. The door locking mechanism will be simulated purely through the RGB LED (Green = Open, Red = Locked).

**Left Side of Table: "The Public Zone" (The Front Door)**
*   **Device:** ESP32-CAM.
*   **Attached:** 1x RC522 RFID Reader, 1x RGB LED.
*   **Story:** This is mounted outside the secure facility. 

**Right Side of Table: "The Secure Vault" (Inside the Room)**
*   **Device 1:** Raspberry Pi (The Brain) displaying the Dashboard on a laptop screen.
*   **Device 2:** Arduino Uno (The Bodyguard) sitting next to the Pi.
*   **Attached to Arduino:** DHT22 (Temp), SW-420 (Vibration), and the **1x 5V Relay** (spliced into the Pi's USB-C power cable).
*   **Device 3:** ESP32 Standard (Telemetry). Just plugged into power, simulating the internal network heartbeat.

---

## 🎬 The Presentation Script

### Introduction (Both Teams - 2 mins)
**Speaker:** "Welcome. Today, IoT security focuses entirely on software. If an attacker bypasses the firewall, they win. Our project introduces a zero-trust architecture that assumes the network *is already compromised*. We present a military-grade fusion of AI telemetry, blockchain forensics, and an unhackable, air-gapped physical kill-switch. We will now demonstrate how this system defends against four distinct attack vectors."

---

### ACT 1: Normal Access & Blockchain Forensics (Team A - Software)
**The Scenario:** A legitimate employee tries to enter.
1.  **Action:** You tap your RFID card on the ESP32-CAM reader.
2.  **Visual:** The RGB LED flashes a random color (e.g., CYAN).
3.  **Speaker (Team A):** "When the card is tapped, the server doesn't just open the door. It issues a randomized RGB color challenge. The camera snaps a photo, ensuring the person's face is illuminated with that exact color. This defeats iPad deepfakes—the attacker can't predict the color."
4.  **Visual:** The Dashboard screen turns Green. The RGB LED turns Green.
5.  **Speaker:** "Access is granted. Crucially, a SHA-256 hash of this event is immediately written to a local Ethereum Blockchain (Ganache). If a hacker later gains root access to the Pi, they cannot erase the forensic audit trail."

---

### ACT 2: The Network Spoofing Attack (Team A - AI Engine)
**The Scenario:** A hacker tries to inject fake packets over Wi-Fi.
1.  **Action:** Point to the standard ESP32 (Telemetry Node) sitting quietly on the table.
2.  **Speaker:** "This standard ESP32 is acting as an internal sensor, sending heartbeats to the Pi. Notice the CNN-LSTM dashboard shows a 'Trust Score' of 100%."
3.  **Action:** (Simulate) Open a terminal on your laptop and run your `spoof_attack.py` script.
4.  **Visual:** The Dashboard Trust Score rapidly drops to 0%, flashing red.
5.  **Speaker:** "An attacker is trying to clone the device's MAC address and inject fake data. However, our Deep Learning model analyzes the microsecond network jitter (inter-packet delay). It realizes the timing signature doesn't match the real hardware, and instantly blocks the attacker."

---

### ACT 3: The Duress "Honey-PIN" (Team A & B Bridge)
**The Scenario:** A manager is held at gunpoint and forced to unlock the system.
1.  **Action:** Type `9999` (The Duress PIN) into the Web Dashboard console.
2.  **Visual:** The Dashboard says "Unlocked" (Green), but a Telegram alert is secretly sent to your phone.
3.  **Speaker:** "If an admin is coerced, they enter a 'Honey-PIN'. To the attacker, the door unlocks and the system looks normal. In reality, a silent alarm is dispatched, and all critical database access is restricted using constant-time cryptographic comparisons to prevent side-channel timing attacks."

---

### ACT 4: The Out-of-Band Hardware Watchdog (Team B - Hardware)
**The Vulnerability:** A hacker launches a massive DDoS attack against the Pi. The CPU hits 100%, and the Linux OS freezes. If the Pi freezes, its software can't trigger the kill-switch, leaving the hardware defenseless against physical theft.

**The Scenario:** The hacker gives up on software, breaks into the room, and tries to smash or steal the server while it is frozen.

1.  **Speaker (Team B):** *"Professor, relying on a Linux server to monitor its own physical hardware is a fatal flaw. If the server is compromised by malware or frozen by a DDoS attack, the software can just be turned off. That is why we integrated an Arduino Uno as an 'Out-of-Band Hardware Watchdog'."*
2.  **Action:** Point to the Arduino Uno on the table.
3.  **Speaker (Team B):** *"This Arduino is completely air-gapped from the network. It has no operating system and no Wi-Fi chip. It runs a single loop of C++ code thousands of times a second. It is physically impossible to hack over the internet, and it cannot freeze from network traffic. It has one single physical job."*
4.  **Action (The Climax):** You aggressively tap or shake the Arduino Uno/Raspberry Pi setup on the table. 
5.  **Visual:** 
    *   The SW-420 Vibration sensor triggers.
    *   *CLICK!* The 5V Relay loudly snaps open.
    *   The Raspberry Pi's power lights instantly go dead.
6.  **Speaker (Team B):** *"The Arduino doesn't ask the Pi for permission. It doesn't care if the Pi is frozen. When it detects kinetic tampering, it forcefully severs the power supply to the main server. Because our vault uses volatile memory (`tmpfs`), the moment power is lost, it executes a zero-day RAM wipe. All cryptographic keys vanish into electronic dust. You cannot hack a system that isn't connected to the internet, and you cannot steal keys that no longer exist."*

### Conclusion (1 min)
**Speaker:** "By combining software-level AI fingerprinting, immutable blockchain logging, and an un-bypassable physical hardware kill-switch, we have created a multi-layered patentable architecture where compromising one layer simply traps the attacker in the next."
