# Project Summary: Zero-Trust IoT Security
**The "Cheat Sheet" for Your Presentation & Patent Defense**

---

## 🏛️ The "Bank Vault" Analogy (Simplified Overview)
*   **The Entrance (ESP32-CAM):** A guard who uses **RGB Challenges** (random lights) to ensure the person's face is real and not a deepfake on an iPad.
*   **The Hallways (ESP32 Standard):** Sensors that have unique "heartbeat fingerprints." An **AI (CNN-LSTM)** detects if someone is trying to mimic/spoof their signal.
*   **The Brain (Raspberry Pi):** The central vault manager who stores secret keys in **Volatile RAM** and logs every event to an **Immutable Blockchain (Ganache)**.
*   **The Watchdog (Arduino):** An air-gapped bodyguard with an axe (Relay) sitting next to the brain. He has no network access and cannot be hacked.

---

## 🛡️ Why we use an Arduino Watchdog (The Core Innovation)
*   **The "Anti-Freeze" Defense:** Raspberry Pi runs Linux (Complex OS). If a DDoS attack freezes the Pi, its internal security code fails. The Arduino has no OS and **cannot freeze**. It monitors the Pi independently.
*   **The "Anti-Root" Defense:** If a hacker gets "Root Access" to the Pi, they can disable its sensors. They **cannot reach the Arduino** because it is not on the network.
*   **The Dead-Man's Switch:** The Pi must say "I'm okay" every 10 seconds over USB. If it stops talking for 30 seconds, the Arduino autonomously "pulls the plug."

---

## ⚡ What is "Pulling the Plug"?
*   **The Action:** The Arduino triggers a physical **5V Relay** that is spliced into the Pi's power cable. 
*   **Digital Suicide:** By cutting the power, the Pi’s **RAM is instantly wiped**.
*   **The Result:** Cryptographic keys exist only in RAM (never on the SD card). When power is lost, the keys vanish. The hacker is left with a "brick" and no data.

---

## 🗺️ The 4 Layers of Patentable Defense
1.  **Identity Layer:** Biometric face capture + RGB Lighting Challenge (Defeats Deepfakes).
2.  **Network Layer:** CNN-LSTM Deep Learning analyzes Inter-Packet Delay (IPD) to detect Hardware Cloning/MAC Spoofing.
3.  **Forensic Layer:** High-fidelity event logs are hashed and stored on a Blockchain, ensuring the audit trail cannot be deleted by an intruder.
4.  **Physical Layer:** Air-gapped Hardware Watchdog with kinetic vibration sensing and autonomous power-severing capability.

---

## 🎤 The "Mic Drop" Monologue
*"Professor, we didn't build a smart lock; we built a defense-in-depth architecture. By offloading physical security to an air-gapped Arduino, we ensure that even if the main server is completely hijacked or frozen by a state-level network attack, the hardware will autonomously protect itself and wipe its secrets before they can be stolen."*
