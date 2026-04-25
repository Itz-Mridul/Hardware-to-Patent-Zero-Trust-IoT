/*
 * ============================================================
 *  Zero-Trust Perimeter Scanner — ESP32-CAM Firmware
 *  Phase 3: Edge Node (The Front Door)
 * ============================================================
 *
 *  Hardware connections:
 *  ┌─────────────────────────────────────────────────────────┐
 *  │  RC522 RFID Reader (SPI)                                │
 *  │    SS/SDA  → GPIO 13   SCK   → GPIO 14                 │
 *  │    MOSI    → GPIO 15   MISO  → GPIO 2                  │
 *  │    RST     → GPIO 12   3.3V  → 3.3V    GND → GND      │
 *  ├─────────────────────────────────────────────────────────┤
 *  │  RGB LED (Common-Cathode, via 220Ω resistors)           │
 *  │    RED     → GPIO 14   (share with SCK — or use 4)     │
 *  │    GREEN   → GPIO 33                                    │
 *  │    BLUE    → GPIO 32                                    │
 *  │  NOTE: Use GPIO 4 for RED if SCK sharing causes issues  │
 *  ├─────────────────────────────────────────────────────────┤
 *  │  Electronic Door Relay                                  │
 *  │    Signal  → GPIO 16   VCC → 5V    GND → GND           │
 *  └─────────────────────────────────────────────────────────┘
 *
 *  Libraries required (install via Arduino Library Manager):
 *    - MFRC522         (RFID)
 *    - PubSubClient    (MQTT)
 *    - ArduinoJson     6.x (JSON payloads)
 *    - esp_camera.h    (bundled with ESP32 Arduino core)
 *
 *  Board: AI-Thinker ESP32-CAM
 *  Upload: Set GPIO 0 to GND, power cycle, then upload.
 * ============================================================
 */

#include <Arduino.h>
#include <WiFi.h>
#include <PubSubClient.h>
#include <ArduinoJson.h>
#include <SPI.h>
#include <MFRC522.h>
#include "esp_camera.h"
#include "mbedtls/md.h"         // For HMAC-SHA256 heartbeat signing

// ── Wi-Fi & MQTT credentials ───────────────────────────────────────────────
// Override these with your actual credentials or store in NVS/SPIFFS
#define WIFI_SSID        "YOUR_WIFI_SSID"
#define WIFI_PASSWORD    "YOUR_WIFI_PASSWORD"
#define MQTT_BROKER      "192.168.1.109"    // Raspberry Pi IP
#define MQTT_PORT        1883               // 8883 with TLS
#define MQTT_CLIENT_ID   "ESP32CAM_SENTRY_01"
#define DEVICE_ID        "ESP32_CAM_PERIMETER"

// MQTTS Client certificate paths (stored in SPIFFS)
// Uncomment when TLS certs are flashed via esptool
// #define USE_MQTTS
// #define CA_CERT_PATH   "/spiffs/ca.crt"
// #define CLI_CERT_PATH  "/spiffs/client.crt"
// #define CLI_KEY_PATH   "/spiffs/client.key"

// ── MQTT Topics ────────────────────────────────────────────────────────────
#define TOPIC_HEARTBEAT  "mailbox/heartbeat"
#define TOPIC_STATUS     "mailbox/status"
#define TOPIC_ACCESS     "mailbox/access"
#define TOPIC_CHALLENGE  "mailbox/rgb_challenge"   // Pi → ESP32-CAM
#define TOPIC_TAMPER     "mailbox/tamper"
#define TOPIC_LWT        "mailbox/status"

// ── Pin definitions ────────────────────────────────────────────────────────
// RC522 (SPI)
#define PIN_RFID_SS    13
#define PIN_RFID_RST   12

// RGB LED (individual GPIO, common cathode → HIGH = ON)
#define PIN_LED_RED    4
#define PIN_LED_GREEN  33
#define PIN_LED_BLUE   32

// Door relay (HIGH = LOCKED via fail-secure MOSFET, LOW = UNLOCK)
#define PIN_RELAY      16

// AI-Thinker ESP32-CAM camera pinout
#define CAM_PIN_PWDN    32
#define CAM_PIN_RESET   -1
#define CAM_PIN_XCLK    0
#define CAM_PIN_SIOD    26
#define CAM_PIN_SIOC    27
#define CAM_PIN_D7      35
#define CAM_PIN_D6      34
#define CAM_PIN_D5      39
#define CAM_PIN_D4      36
#define CAM_PIN_D3      21
#define CAM_PIN_D2      19
#define CAM_PIN_D1      18
#define CAM_PIN_D0       5
#define CAM_PIN_VSYNC   25
#define CAM_PIN_HREF    23
#define CAM_PIN_PCLK    22

// ── Timing constants ───────────────────────────────────────────────────────
#define HEARTBEAT_INTERVAL_MS   500    // 500ms heartbeat cadence
#define CHALLENGE_TIMEOUT_MS  10000    // 10s to respond to RGB challenge
#define RFID_COOLDOWN_MS       3000    // 3s lockout after card read
#define RELAY_PULSE_MS         5000    // Door open for 5 seconds

// ── Global state ───────────────────────────────────────────────────────────
WiFiClient           wifiClient;
PubSubClient         mqtt(wifiClient);
MFRC522              rfid(PIN_RFID_SS, PIN_RFID_RST);

volatile bool        challengeReceived  = false;
volatile String      currentChallenge   = "";
volatile bool        relayOpen          = false;
unsigned long        lastHeartbeat      = 0;
unsigned long        lastRfidRead       = 0;
unsigned long        lastMqttReconnect  = 0;
unsigned long        relayOpenedAt      = 0;
uint32_t             packetCount        = 0;
uint32_t             lastPacketTime     = 0;


// ═══════════════════════════════════════════════════════════════════════════
// Camera Initialisation
// ═══════════════════════════════════════════════════════════════════════════

bool initCamera() {
    camera_config_t config;
    config.ledc_channel = LEDC_CHANNEL_0;
    config.ledc_timer   = LEDC_TIMER_0;
    config.pin_d0       = CAM_PIN_D0;
    config.pin_d1       = CAM_PIN_D1;
    config.pin_d2       = CAM_PIN_D2;
    config.pin_d3       = CAM_PIN_D3;
    config.pin_d4       = CAM_PIN_D4;
    config.pin_d5       = CAM_PIN_D5;
    config.pin_d6       = CAM_PIN_D6;
    config.pin_d7       = CAM_PIN_D7;
    config.pin_xclk     = CAM_PIN_XCLK;
    config.pin_pclk     = CAM_PIN_PCLK;
    config.pin_vsync    = CAM_PIN_VSYNC;
    config.pin_href     = CAM_PIN_HREF;
    config.pin_sscb_sda = CAM_PIN_SIOD;
    config.pin_sscb_scl = CAM_PIN_SIOC;
    config.pin_pwdn     = CAM_PIN_PWDN;
    config.pin_reset    = CAM_PIN_RESET;
    config.xclk_freq_hz = 20000000;
    config.pixel_format = PIXFORMAT_JPEG;
    config.frame_size   = FRAMESIZE_VGA;   // 640×480
    config.jpeg_quality = 12;              // 0-63, lower = higher quality
    config.fb_count     = 1;

    esp_err_t err = esp_camera_init(&config);
    if (err != ESP_OK) {
        Serial.printf("[CAM] Init failed: 0x%x\n", err);
        return false;
    }
    Serial.println("[CAM] Initialised (VGA, JPEG q=12)");
    return true;
}


// ═══════════════════════════════════════════════════════════════════════════
// RGB LED Control
// ═══════════════════════════════════════════════════════════════════════════

void setRGB(bool r, bool g, bool b) {
    digitalWrite(PIN_LED_RED,   r ? HIGH : LOW);
    digitalWrite(PIN_LED_GREEN, g ? HIGH : LOW);
    digitalWrite(PIN_LED_BLUE,  b ? HIGH : LOW);
}

// Map challenge color name → LED values
void showColor(const String& color) {
    if      (color == "RED")     setRGB(1, 0, 0);
    else if (color == "GREEN")   setRGB(0, 1, 0);
    else if (color == "BLUE")    setRGB(0, 0, 1);
    else if (color == "CYAN")    setRGB(0, 1, 1);
    else if (color == "YELLOW")  setRGB(1, 1, 0);
    else if (color == "MAGENTA") setRGB(1, 0, 1);
    else if (color == "WHITE")   setRGB(1, 1, 1);
    else                          setRGB(0, 0, 0);  // OFF
}

// 3-pulse "ready" blink on startup
void startupBlink() {
    for (int i = 0; i < 3; i++) {
        setRGB(0, 1, 0); delay(150);
        setRGB(0, 0, 0); delay(100);
    }
}


// ═══════════════════════════════════════════════════════════════════════════
// Relay Control
// ═══════════════════════════════════════════════════════════════════════════

void lockDoor() {
    digitalWrite(PIN_RELAY, HIGH);   // Fail-secure: HIGH = locked
    relayOpen     = false;
    relayOpenedAt = 0;
    Serial.println("[RELAY] Locked.");
}

void unlockDoor() {
    digitalWrite(PIN_RELAY, LOW);    // LOW = energise solenoid = OPEN
    relayOpen     = true;
    relayOpenedAt = millis();
    setRGB(0, 1, 0);                // Green LED = access granted
    Serial.println("[RELAY] Unlocked (5s window).");
}


// ═══════════════════════════════════════════════════════════════════════════
// SHA-256 Heartbeat Signing (HMAC-SHA256)
// ═══════════════════════════════════════════════════════════════════════════
// Prevents a replay attacker from sending old heartbeats.
// The Pi verifies the HMAC using the shared device secret.

const char* HMAC_SECRET = "CHANGE_ME_TO_32_BYTE_SECRET_KEY!";

String signPayload(const String& payload) {
    byte hmacResult[32];
    mbedtls_md_context_t ctx;
    mbedtls_md_type_t md_type = MBEDTLS_MD_SHA256;

    mbedtls_md_init(&ctx);
    mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(md_type), 1);
    mbedtls_md_hmac_starts(&ctx,
        (const unsigned char*)HMAC_SECRET, strlen(HMAC_SECRET));
    mbedtls_md_hmac_update(&ctx,
        (const unsigned char*)payload.c_str(), payload.length());
    mbedtls_md_hmac_finish(&ctx, hmacResult);
    mbedtls_md_free(&ctx);

    String sig = "";
    for (int i = 0; i < 16; i++) {   // First 16 bytes = 32 hex chars
        if (hmacResult[i] < 16) sig += "0";
        sig += String(hmacResult[i], HEX);
    }
    return sig;
}


// ═══════════════════════════════════════════════════════════════════════════
// Heartbeat Publisher
// ═══════════════════════════════════════════════════════════════════════════

void sendHeartbeat() {
    uint32_t now    = millis();
    uint32_t ipd    = (lastPacketTime > 0) ? (now - lastPacketTime) : 0;
    lastPacketTime  = now;
    packetCount++;

    // Build JSON payload
    StaticJsonDocument<256> doc;
    doc["device_id"]           = DEVICE_ID;
    doc["timestamp"]           = (unsigned long)esp_timer_get_time() / 1000;
    doc["inter_packet_delay"]  = ipd;
    doc["rssi"]                = WiFi.RSSI();
    doc["free_heap"]           = esp_get_free_heap_size();
    doc["packet_size"]         = 256;
    doc["packet_count"]        = packetCount;

    String payload;
    serializeJson(doc, payload);

    // Sign the payload and append the sig
    doc["sig"] = signPayload(payload);
    payload = "";
    serializeJson(doc, payload);

    if (mqtt.publish(TOPIC_HEARTBEAT, payload.c_str(), false)) {
        Serial.printf("[HB] IPD=%ums RSSI=%ddBm Heap=%u\n",
                      ipd, WiFi.RSSI(), esp_get_free_heap_size());
    }
}


// ═══════════════════════════════════════════════════════════════════════════
// Camera Capture & Publish
// ═══════════════════════════════════════════════════════════════════════════

bool captureAndPublishPhoto(const String& rfidUID, const String& challenge) {
    camera_fb_t* fb = esp_camera_fb_get();
    if (!fb) {
        Serial.println("[CAM] Capture failed!");
        return false;
    }

    // Compute a simple CRC32 as the "photo hash" (sent alongside photo)
    uint32_t crc = 0xFFFFFFFF;
    for (size_t i = 0; i < fb->len; i++) {
        crc ^= fb->buf[i];
        for (int j = 0; j < 8; j++)
            crc = (crc >> 1) ^ (0xEDB88320 * (crc & 1));
    }
    crc ^= 0xFFFFFFFF;

    char hashStr[12];
    snprintf(hashStr, sizeof(hashStr), "%08X", crc);

    // Build access payload
    StaticJsonDocument<512> doc;
    doc["device_id"]          = DEVICE_ID;
    doc["rfid_uid"]           = rfidUID;
    doc["challenge_response"] = challenge;      // The color the LED showed
    doc["photo_crc"]          = String(hashStr);
    doc["photo_size_bytes"]   = fb->len;
    doc["timestamp"]          = (unsigned long)esp_timer_get_time() / 1000;
    doc["rssi"]               = WiFi.RSSI();
    doc["free_heap"]          = esp_get_free_heap_size();

    String meta;
    serializeJson(doc, meta);

    // Publish metadata on access topic
    mqtt.publish(TOPIC_ACCESS, meta.c_str());

    // Publish raw JPEG on a dedicated photo topic (binary, no retain)
    // Pi reads this and stores the image for dashboard display
    String photoTopic = "mailbox/photo/" + String(DEVICE_ID);
    mqtt.beginPublish(photoTopic.c_str(), fb->len, false);
    size_t sent = 0;
    while (sent < fb->len) {
        size_t chunk = min((size_t)512, fb->len - sent);
        mqtt.write(fb->buf + sent, chunk);
        sent += chunk;
    }
    mqtt.endPublish();

    Serial.printf("[CAM] Photo sent: %u bytes | CRC: %s | UID: %s\n",
                  fb->len, hashStr, rfidUID.c_str());

    esp_camera_fb_return(fb);
    return true;
}


// ═══════════════════════════════════════════════════════════════════════════
// RFID Access Flow — Tap & Snap
// ═══════════════════════════════════════════════════════════════════════════

void handleRFIDTap() {
    if (millis() - lastRfidRead < RFID_COOLDOWN_MS) return;
    if (!rfid.PICC_IsNewCardPresent() || !rfid.PICC_ReadCardSerial()) return;

    lastRfidRead = millis();

    // Build RFID UID string
    String uid = "";
    for (byte i = 0; i < rfid.uid.size; i++) {
        if (rfid.uid.uidByte[i] < 0x10) uid += "0";
        uid += String(rfid.uid.uidByte[i], HEX);
    }
    uid.toUpperCase();
    Serial.printf("[RFID] Card scanned: %s\n", uid.c_str());

    // Flash white to acknowledge scan
    setRGB(1, 1, 1);
    delay(200);
    setRGB(0, 0, 0);

    // Publish RFID UID to Pi — Pi will send RGB challenge back
    StaticJsonDocument<128> req;
    req["device_id"] = DEVICE_ID;
    req["rfid_uid"]  = uid;
    req["action"]    = "REQUEST_CHALLENGE";
    String reqStr;
    serializeJson(req, reqStr);
    mqtt.publish(TOPIC_ACCESS, reqStr.c_str());

    // Wait for challenge (blocking with timeout)
    challengeReceived = false;
    currentChallenge  = "";
    unsigned long waitStart = millis();

    while (!challengeReceived && (millis() - waitStart < CHALLENGE_TIMEOUT_MS)) {
        mqtt.loop();
        delay(10);
    }

    if (!challengeReceived) {
        Serial.println("[RFID] Challenge timeout — access denied.");
        setRGB(1, 0, 0);  delay(2000);  setRGB(0, 0, 0);
        rfid.PICC_HaltA();
        return;
    }

    // Fire the RGB LED with the challenged color
    Serial.printf("[RFID] Challenge received: %s — firing LED\n",
                  currentChallenge.c_str());
    showColor(currentChallenge);
    delay(500);   // Give the camera time to capture

    // Snap photo and send back to Pi for analysis
    bool ok = captureAndPublishPhoto(uid, currentChallenge);
    setRGB(0, 0, 0);

    if (!ok) {
        Serial.println("[RFID] Photo capture failed.");
    }

    rfid.PICC_HaltA();
    rfid.PCD_StopCrypto1();
}


// ═══════════════════════════════════════════════════════════════════════════
// MQTT Callbacks
// ═══════════════════════════════════════════════════════════════════════════

void onMqttMessage(char* topic, byte* payload, unsigned int length) {
    // Null-terminate payload
    char msg[length + 1];
    memcpy(msg, payload, length);
    msg[length] = '\0';

    String topicStr(topic);
    Serial.printf("[MQTT] Received on %s: %s\n", topic, msg);

    StaticJsonDocument<256> doc;
    if (deserializeJson(doc, msg) != DeserializationError::Ok) return;

    // ── RGB Challenge from Pi ──────────────────────────────────────────────
    if (topicStr == TOPIC_CHALLENGE) {
        const char* color = doc["color"];
        if (color) {
            currentChallenge  = String(color);
            challengeReceived = true;
            Serial.printf("[CHALLENGE] Color: %s\n", color);
        }
        return;
    }

    // ── Access Decision from Pi ────────────────────────────────────────────
    if (topicStr == TOPIC_ACCESS) {
        const char* action = doc["action"];
        if (!action) return;

        if (strcmp(action, "UNLOCK") == 0) {
            unlockDoor();
        } else if (strcmp(action, "LOCK") == 0) {
            lockDoor();
        } else if (strcmp(action, "DENY") == 0) {
            setRGB(1, 0, 0);   // Red = denied
            delay(2000);
            setRGB(0, 0, 0);
            Serial.println("[ACCESS] Denied by Pi.");
        }
        return;
    }

    // ── Lockdown command from Pi (thermal/tamper) ──────────────────────────
    if (topicStr == "security/lockdown") {
        lockDoor();
        setRGB(1, 0, 0);   // Steady red = emergency lockdown
        Serial.println("[LOCKDOWN] Emergency lockdown received!");
        return;
    }
}

bool reconnectMQTT() {
    Serial.print("[MQTT] Connecting...");

    // Last-Will-Testament — Pi knows we died unexpectedly
    StaticJsonDocument<128> lwt;
    lwt["device_id"] = DEVICE_ID;
    lwt["status"]    = "OFFLINE";
    String lwtStr;
    serializeJson(lwt, lwtStr);

    bool connected = mqtt.connect(
        MQTT_CLIENT_ID,
        nullptr, nullptr,         // username, password (use TLS instead)
        TOPIC_LWT, 1, true,       // LWT topic, QoS 1, retain
        lwtStr.c_str()
    );

    if (connected) {
        Serial.println(" OK");
        mqtt.subscribe(TOPIC_CHALLENGE);
        mqtt.subscribe(TOPIC_ACCESS);
        mqtt.subscribe("security/lockdown");

        // Announce ONLINE
        StaticJsonDocument<128> online;
        online["device_id"]        = DEVICE_ID;
        online["status"]           = "ONLINE";
        online["connection_state"] = "BOOT";
        String onlineStr;
        serializeJson(online, onlineStr);
        mqtt.publish(TOPIC_STATUS, onlineStr.c_str(), true);  // retain=true
    } else {
        Serial.printf(" FAILED (rc=%d)\n", mqtt.state());
    }
    return connected;
}


// ═══════════════════════════════════════════════════════════════════════════
// Setup
// ═══════════════════════════════════════════════════════════════════════════

void setup() {
    Serial.begin(115200);
    Serial.println("\n[BOOT] Zero-Trust Perimeter Scanner v1.0");

    // GPIO setup
    pinMode(PIN_LED_RED,   OUTPUT);
    pinMode(PIN_LED_GREEN, OUTPUT);
    pinMode(PIN_LED_BLUE,  OUTPUT);
    pinMode(PIN_RELAY,     OUTPUT);
    lockDoor();  // Fail-secure on boot
    setRGB(0, 0, 0);

    // Camera
    if (!initCamera()) {
        setRGB(1, 0, 0);   // Red = fatal error
        while (1) delay(1000);
    }

    // SPI + RFID
    SPI.begin();
    rfid.PCD_Init();
    rfid.PCD_SetAntennaGain(rfid.RxGain_max);
    Serial.println("[RFID] RC522 initialised");

    // Wi-Fi
    WiFi.mode(WIFI_STA);
    WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
    Serial.print("[WIFI] Connecting");
    while (WiFi.status() != WL_CONNECTED) {
        delay(500); Serial.print(".");
        setRGB(0, 0, 1);   // Blue = connecting
        delay(500);
        setRGB(0, 0, 0);
    }
    Serial.printf("\n[WIFI] Connected: %s\n", WiFi.localIP().toString().c_str());

    // MQTT
    mqtt.setServer(MQTT_BROKER, MQTT_PORT);
    mqtt.setCallback(onMqttMessage);
    mqtt.setBufferSize(8192);   // Large enough for chunked photo publish

    reconnectMQTT();
    startupBlink();
    Serial.println("[BOOT] Ready. Waiting for RFID tap...");
}


// ═══════════════════════════════════════════════════════════════════════════
// Main Loop
// ═══════════════════════════════════════════════════════════════════════════

void loop() {
    unsigned long now = millis();

    // ── MQTT keepalive ────────────────────────────────────────────────────
    if (!mqtt.connected()) {
        if (now - lastMqttReconnect > 5000) {
            lastMqttReconnect = now;
            reconnectMQTT();
        }
    } else {
        mqtt.loop();
    }

    // ── 500ms Heartbeat ────────────────────────────────────────────────────
    if (now - lastHeartbeat >= HEARTBEAT_INTERVAL_MS) {
        lastHeartbeat = now;
        if (mqtt.connected()) sendHeartbeat();
    }

    // ── RFID polling ───────────────────────────────────────────────────────
    handleRFIDTap();

    // ── Auto-relock relay after RELAY_PULSE_MS ────────────────────────────
    if (relayOpen && (now - relayOpenedAt >= RELAY_PULSE_MS)) {
        lockDoor();
        setRGB(0, 0, 0);
        Serial.println("[RELAY] Auto-locked after timeout.");
    }
}
