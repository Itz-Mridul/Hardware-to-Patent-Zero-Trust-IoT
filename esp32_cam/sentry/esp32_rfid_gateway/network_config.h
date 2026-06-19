/*
 * ============================================================
 *  ZERO-TRUST IoT — CENTRAL NETWORK CONFIGURATION
 *  ⚠️  CHANGE THIS FILE ONLY — then reflash ALL ESP32 boards
 * ============================================================
 *
 *  Include in every .ino sketch:
 *      #include "../../../network_config.h"
 *
 *  Current network:  "Onki" WiFi  (updated 2026-06-19)
 *  Pi IP (Local):    10.176.62.161  ← MQTT broker + Dashboard runs HERE
 *  Mac IP:           10.176.62.94   (Ganache blockchain on Mac)
 *  Mobile IP:        10.176.62.196  (Hotspot source device)
 *  Pi IP (Tailscale): 100.87.37.100 (for Mac SSH / remote access)
 *
 *  ⚠️  WHEN SWITCHING NETWORKS:
 *    1. Connect Pi to new network
 *    2. Run:  hostname -I       (on Pi)  → update PI_MQTT_BROKER below
 *    3. Run:  ipconfig getifaddr en0     (on Mac) → update in .env
 *    4. Run:  bash update_network.sh <PI_IP> <MAC_IP> "SSID" "PASS"
 *    5. Recompile & reflash all 3 ESP32 boards via Arduino IDE
 *    6. On Pi: bash start_all.sh
 * ============================================================
 *  ✅ READY TO FLASH — broker confirmed live on 10.176.62.161:1883
 * ============================================================
 */

#ifndef NETWORK_CONFIG_H
#define NETWORK_CONFIG_H

// ── 📶 WiFi Credentials ─────────────────────────────────────────────────────
//  ⬇ Change SSID and PASSWORD when switching networks
#define WIFI_SSID      "Onki"
#define WIFI_PASSWORD  "123456789"

// ── 🖥️ MQTT Broker (Raspberry Pi) ───────────────────────────────────────────
//  Pi runs Mosquitto broker on this IP — all ESP32 boards connect here.
//  Pi IP on hotspot: run  hostname -I  on the Pi to confirm.
#define PI_MQTT_BROKER  "10.238.130.161"   // ← Pi IP on 'Onki' WiFi (2026-06-19)
#define MQTT_PORT       1883

// ── 🔗 Blockchain / Ganache (Mac) ────────────────────────────────────────────
//  Ganache runs on the Mac. Used by pi_backend/blockchain_bridge.py
//  (Not needed in ESP32 firmware directly, listed here for reference)
//  MAC_GANACHE_IP = "10.176.62.94"   port 7545

#endif  // NETWORK_CONFIG_H
