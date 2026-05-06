/*
 * ==============================================================================
 * 🛡️ ZERO-TRUST PERIMETER SCANNER — ESP32-CAM v3
 * ==============================================================================
 * ROLE:    Front-door hardware sentinel — RFID + Camera + HMAC + MQTT
 *
 * FLOW (v3):
 *   1. Card tapped → read Name + Gender + 4-digit code from MIFARE sectors
 *   2. YELLOW on   → waiting for Pi decision
 *   3. Send photo  → TOPIC_PHOTO/<uid>
 *   4. Send payload→ TOPIC_ACCESS  (uid/name/gender/code/sig/nonce)
 *   5. Wait ≤5 s   → Pi replies on TOPIC_DECISION
 *   6. GREEN solid = GRANT (5 s, then auto-lock)
 *      RED blink×3 = DENY (non-blocking)
 *
 * CARD LAYOUT (MIFARE Classic 1K — Sector 1):
 *   Block 4 → Name      (16 bytes, null/space padded)
 *   Block 5 → Gender[0] + SecretCode[1-4]  e.g. 'M','1','2','3','4'
 *   Block 6 → Reserved
 *   Block 7 → Sector Trailer (keys — never read)
 *   Default Key A: FF FF FF FF FF FF
 *
 * ⚠️ MANDATORY UPLOAD SETTINGS (Tools Menu):
 *   Board:            AI Thinker ESP32-CAM
 *   Flash Mode:       DIO  (QIO will hang)
 *   Partition Scheme: Huge APP (3MB No OTA/1MB SPIFFS)
 *   Flash Frequency:  80 MHz
 *
 * HARDWARE PINS (fixes from v2 kept):
 *   PIN_LED_RED   = 2   (was GPIO16 — PSRAM crash)
 *   PIN_LED_GREEN = 0   (was GPIO4  — camera flash conflict)
 *   PIN_RFID_RST  = -1  (hardwired 3.3V — frees GPIO for LED)
 *
 * ⚠️ UPLOAD: Disconnect 3.3V from RFID + LEDs before flashing!
 * ==============================================================================
 */

#include <Arduino.h>
#include <WiFi.h>
#include <PubSubClient.h>
#include <ArduinoJson.h>
#include <SPI.h>
#include <MFRC522.h>
#include "esp_camera.h"
#include "mbedtls/md.h"
#include <Preferences.h>

// ── 🌐 NETWORK ────────────────────────────────────────────────────────────────
#define WIFI_SSID               "Room203"
#define WIFI_PASSWORD           "Hostel@203"
#define MQTT_BROKER             "192.168.1.113"   // Raspberry Pi IP
#define MQTT_PORT               1883
#define MQTT_CLIENT_ID          "ESP32CAM_SENTRY_01"
#define DEVICE_ID               "ESP32_CAM_PERIMETER"

// ── 📡 TOPICS ─────────────────────────────────────────────────────────────────
#define TOPIC_HEARTBEAT         "mailbox/heartbeat"
#define TOPIC_ACCESS            "mailbox/access"         // ESP32 → Pi (card payload)
#define TOPIC_DECISION          "mailbox/decision"       // Pi → ESP32 (GRANT/DENY)
#define TOPIC_PHOTO             "mailbox/photo"          // ESP32 → Pi (raw JPEG bytes)
#define TOPIC_NONCE_CHALLENGE   "perimeter/nonce_challenge"
#define TOPIC_NONCE_RESPONSE    "perimeter/nonce_response"

// ── 📌 PINS ───────────────────────────────────────────────────────────────────
// RFID (custom SPI to avoid camera bus conflicts)
#define PIN_SPI_SCK             15
#define PIN_SPI_MISO            12
#define PIN_SPI_MOSI            13
#define PIN_RFID_SS             14
#define PIN_RFID_RST            -1    // hardwired 3.3V — no GPIO needed

// RGB LED  (ACTIVE LOW on AI Thinker board: LOW = ON, HIGH = OFF)
// FIX1: Green moved from GPIO4 (camera flash) → GPIO0
// FIX2: Red   moved from GPIO16 (PSRAM line)  → GPIO2
#define PIN_LED_RED             2
#define PIN_LED_GREEN           0

// AI-Thinker Camera (CAM_PIN_XCLK shares GPIO0 with LED green;
//   acceptable because camera is bypassed when lens is absent)
#define CAM_PIN_PWDN            32
#define CAM_PIN_RESET           -1
#define CAM_PIN_XCLK            0
#define CAM_PIN_SIOD            26
#define CAM_PIN_SIOC            27
#define CAM_PIN_D7              35
#define CAM_PIN_D6              34
#define CAM_PIN_D5              39
#define CAM_PIN_D4              36
#define CAM_PIN_D3              21
#define CAM_PIN_D2              19
#define CAM_PIN_D1              18
#define CAM_PIN_D0              5
#define CAM_PIN_VSYNC           25
#define CAM_PIN_HREF            23
#define CAM_PIN_PCLK            22

// ── ⏱️ TIMING ──────────────────────────────────────────────────────────────────
#define HEARTBEAT_INTERVAL_MS   500
#define PI_RESPONSE_TIMEOUT_MS  5000   // max wait for Pi GRANT/DENY
#define RFID_COOLDOWN_MS        3000
#define UNLOCK_DURATION_MS      5000
#define BLINK_INTERVAL_MS       200    // red blink speed
#define BLINK_COUNT             6      // 6 toggles = 3 full blinks

// ── 💾 STATE ───────────────────────────────────────────────────────────────────
WiFiClient    wifiClient;
PubSubClient  mqtt(wifiClient);
MFRC522       rfid(PIN_RFID_SS, PIN_RFID_RST);
MFRC522::MIFARE_Key mifareKey;

String        HMAC_SECRET_STR    = "";
bool          piDecisionReceived = false;
bool          piDecisionGrant    = false;

bool          relayOpen          = false;
unsigned long relayOpenedAt      = 0;
unsigned long lastHeartbeat      = 0;
unsigned long lastRfidRead       = 0;
unsigned long lastMqttReconnect  = 0;
uint32_t      lastPacketTime     = 0;

// Non-blocking blink state
bool          blinkActive        = false;
int           blinkToggleCount   = 0;
unsigned long lastBlinkToggle    = 0;
bool          blinkLedState      = false;

// ═══════════════════════════════════════════════════════════════════════════
// 💡 LED CONTROL  (ACTIVE LOW)
// ═══════════════════════════════════════════════════════════════════════════

void setRGB(bool r, bool g) {
    digitalWrite(PIN_LED_RED,   r ? LOW : HIGH);
    digitalWrite(PIN_LED_GREEN, g ? LOW : HIGH);
}

void showColor(const String& color) {
    if      (color == "RED")    setRGB(1, 0);
    else if (color == "GREEN")  setRGB(0, 1);
    else if (color == "YELLOW") setRGB(1, 1);
    else if (color == "WHITE")  setRGB(1, 1);
    else                        setRGB(0, 0);
}

// Start non-blocking red blink sequence (DENY feedback)
void startBlinkRed() {
    blinkActive      = true;
    blinkToggleCount = 0;
    blinkLedState    = false;
    lastBlinkToggle  = millis();
    setRGB(0, 0);
}

// Call every loop() iteration — advances blink without blocking
void updateBlink() {
    if (!blinkActive) return;
    if (millis() - lastBlinkToggle < BLINK_INTERVAL_MS) return;
    lastBlinkToggle = millis();
    blinkLedState   = !blinkLedState;
    setRGB(blinkLedState, 0);
    blinkToggleCount++;
    if (blinkToggleCount >= BLINK_COUNT) {
        blinkActive = false;
        setRGB(0, 0);
        Serial.println(F(" [ 🔴 LED ] Deny blink complete."));
    }
}

void lockDoor() {
    relayOpen     = false;
    relayOpenedAt = 0;
    setRGB(0, 0);
    Serial.println(F(" [ 🔒 DOOR] Vault LOCKED."));
}

// ═══════════════════════════════════════════════════════════════════════════
// 📸 CAMERA
// ═══════════════════════════════════════════════════════════════════════════

bool initCamera() {
    // ⚠️ Camera lens physically absent — bypassed to prevent boot crash.
    // Remove `return false` and uncomment block below when lens is reattached.
    return false;

    /*
    camera_config_t config;
    config.ledc_channel = LEDC_CHANNEL_0;
    config.ledc_timer   = LEDC_TIMER_0;
    config.pin_d0=CAM_PIN_D0; config.pin_d1=CAM_PIN_D1;
    config.pin_d2=CAM_PIN_D2; config.pin_d3=CAM_PIN_D3;
    config.pin_d4=CAM_PIN_D4; config.pin_d5=CAM_PIN_D5;
    config.pin_d6=CAM_PIN_D6; config.pin_d7=CAM_PIN_D7;
    config.pin_xclk=CAM_PIN_XCLK; config.pin_pclk=CAM_PIN_PCLK;
    config.pin_vsync=CAM_PIN_VSYNC; config.pin_href=CAM_PIN_HREF;
    config.pin_sscb_sda=CAM_PIN_SIOD; config.pin_sscb_scl=CAM_PIN_SIOC;
    config.pin_pwdn=CAM_PIN_PWDN; config.pin_reset=CAM_PIN_RESET;
    config.xclk_freq_hz = 20000000;
    config.pixel_format = PIXFORMAT_JPEG;
    config.frame_size   = FRAMESIZE_QVGA;
    config.jpeg_quality = 10;
    config.fb_count     = 1;
    return esp_camera_init(&config) == ESP_OK;
    */
}

// Capture and publish photo; returns CRC string (or "NOCAMERA")
String capturePhoto(const String& uid) {
    camera_fb_t* fb = NULL;   // NULL while camera is bypassed

    if (fb) {
        String photoTopic = String(TOPIC_PHOTO) + "/" + uid;
        mqtt.beginPublish(photoTopic.c_str(), fb->len, false);
        size_t sent = 0;
        while (sent < fb->len) {
            size_t chunk = min((size_t)512, fb->len - sent);
            mqtt.write(fb->buf + sent, chunk);
            sent += chunk;
        }
        mqtt.endPublish();

        // CRC-32 integrity tag
        uint32_t crc = 0xFFFFFFFF;
        for (size_t i = 0; i < fb->len; i++) {
            crc ^= fb->buf[i];
            for (int j = 0; j < 8; j++) crc = (crc >> 1) ^ (0xEDB88320 * (crc & 1));
        }
        char hashStr[9];
        snprintf(hashStr, sizeof(hashStr), "%08X", ~crc);
        Serial.printf(" [ 📸 CAM ] Photo sent. %u bytes | CRC: %s\n", fb->len, hashStr);
        esp_camera_fb_return(fb);
        return String(hashStr);
    }

    Serial.println(F(" [ ⚠️ CAM ] No camera — metadata only."));
    return "NOCAMERA";
}

// ═══════════════════════════════════════════════════════════════════════════
// 💳 MIFARE CARD READ  (Name + Gender + 4-digit Code)
// ═══════════════════════════════════════════════════════════════════════════

struct CardData {
    String uid;
    String name;
    char   gender;       // 'M' or 'F'
    String secret_code;  // 4 ASCII digits e.g. "1234"
    bool   read_ok;
};

CardData readCardData() {
    CardData d;
    d.read_ok = false;
    d.gender  = '?';

    // Build UID string
    d.uid = "";
    for (byte i = 0; i < rfid.uid.size; i++) {
        if (rfid.uid.uidByte[i] < 0x10) d.uid += "0";
        d.uid += String(rfid.uid.uidByte[i], HEX);
    }
    d.uid.toUpperCase();

    // Authenticate Sector 1 — trailer block = 4+3 = 7
    MFRC522::StatusCode status = rfid.PCD_Authenticate(
        MFRC522::PICC_CMD_MF_AUTH_KEY_A, 7, &mifareKey, &(rfid.uid));

    if (status != MFRC522::STATUS_OK) {
        Serial.printf(" [ ❌ RFID] Auth failed: %s\n", rfid.GetStatusCodeName(status));
        return d;
    }

    // Block 4 → Name (16 bytes, null/space terminated)
    byte buf[18]; byte sz = 18;
    status = rfid.MIFARE_Read(4, buf, &sz);
    if (status == MFRC522::STATUS_OK) {
        d.name = "";
        for (int i = 0; i < 16; i++) {
            if (buf[i] == 0x00) break;
            if (buf[i] < 0x20) continue;   // skip control chars
            d.name += (char)buf[i];
        }
        d.name.trim();
    } else {
        Serial.println(F(" [ ❌ RFID] Block 4 (name) read failed."));
        return d;
    }

    // Block 5 → Gender[0] + Code[1..4]
    sz = 18;
    status = rfid.MIFARE_Read(5, buf, &sz);
    if (status == MFRC522::STATUS_OK) {
        d.gender      = (char)buf[0];
        d.secret_code = "";
        for (int i = 1; i <= 4; i++) d.secret_code += (char)buf[i];
        d.read_ok = true;
    } else {
        Serial.println(F(" [ ❌ RFID] Block 5 (gender/code) read failed."));
    }

    return d;
}

// ═══════════════════════════════════════════════════════════════════════════
// 🔐 HMAC-SHA256 (first 16 bytes = 32 hex chars, matching Pi side)
// ═══════════════════════════════════════════════════════════════════════════

void loadSecretKey() {
    Preferences prefs;
    prefs.begin("vault", true);   // read-only
    HMAC_SECRET_STR = prefs.getString("sk", "");
    prefs.end();
    if (HMAC_SECRET_STR.isEmpty()) {
        Serial.println(F(" [ ⚠️ SEC ] No NVS key — using dev fallback."));
        Serial.println(F(" [ ⚠️ SEC ] Flash production key via Preferences before deploy!"));
        HMAC_SECRET_STR = "CHANGE_ME_TO_32_BYTE_SECRET_KEY!";
    } else {
        Serial.println(F(" [ 🔑 SEC ] HMAC key loaded from NVS vault."));
    }
}

// ── To flash production key once, then delete this function ────────────────
// void flashSecretKey() {
//     Preferences prefs;
//     prefs.begin("vault", false);
//     prefs.putString("sk", "YOUR_PRODUCTION_KEY_MIN_32_CHARS");
//     prefs.end();
//     Serial.println("Key written. Remove flashSecretKey() call now.");
// }

String signPayload(const String& payload) {
    byte hmacResult[32];
    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);
    mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1);
    mbedtls_md_hmac_starts(&ctx,
        (const unsigned char*)HMAC_SECRET_STR.c_str(), HMAC_SECRET_STR.length());
    mbedtls_md_hmac_update(&ctx,
        (const unsigned char*)payload.c_str(), payload.length());
    mbedtls_md_hmac_finish(&ctx, hmacResult);
    mbedtls_md_free(&ctx);
    String sig = "";
    for (int i = 0; i < 16; i++) {   // 16 bytes → 32 hex chars
        if (hmacResult[i] < 0x10) sig += "0";
        sig += String(hmacResult[i], HEX);
    }
    return sig;
}

// ═══════════════════════════════════════════════════════════════════════════
// 💓 HEARTBEAT
// ═══════════════════════════════════════════════════════════════════════════

void sendHeartbeat() {
    uint32_t now   = millis();
    uint32_t ipd   = lastPacketTime ? (now - lastPacketTime) : 0;
    lastPacketTime = now;

    StaticJsonDocument<256> doc;
    doc["device_id"]          = DEVICE_ID;
    doc["nonce"]              = (uint32_t)esp_random();
    doc["timestamp"]          = (unsigned long)esp_timer_get_time() / 1000;
    doc["inter_packet_delay"] = ipd;
    doc["rssi"]               = WiFi.RSSI();
    String payload;
    serializeJson(doc, payload);
    doc["sig"] = signPayload(payload);
    payload = "";
    serializeJson(doc, payload);

    if (mqtt.publish(TOPIC_HEARTBEAT, payload.c_str(), false))
        Serial.printf(" [ 💓 BEAT ] IPD: %4ums | RSSI: %3d dBm\n", ipd, WiFi.RSSI());
}

// ═══════════════════════════════════════════════════════════════════════════
// 🆔 RFID TAP HANDLER
// ═══════════════════════════════════════════════════════════════════════════

void handleRFIDTap() {
    if (millis() - lastRfidRead < RFID_COOLDOWN_MS) return;
    if (!rfid.PICC_IsNewCardPresent() || !rfid.PICC_ReadCardSerial()) return;

    lastRfidRead = millis();

    Serial.println(F("\n----------------------------------------------------------------"));
    Serial.println(F(" 🆔 CARD TAP DETECTED — reading sectors..."));

    // Flash WHITE = card-read acknowledgement
    setRGB(1, 1); delay(150); setRGB(0, 0);

    CardData card = readCardData();

    if (!card.read_ok) {
        Serial.println(F(" [ ❌ RFID] Card read failed — bad card or wrong key."));
        startBlinkRed();
        rfid.PICC_HaltA();
        rfid.PCD_StopCrypto1();
        return;
    }

    Serial.printf(" [ 💳 CARD] UID: %s | Name: %s | Gender: %c | Code: %s\n",
                  card.uid.c_str(), card.name.c_str(),
                  card.gender, card.secret_code.c_str());

    // YELLOW = waiting for Pi
    setRGB(1, 1);

    // Capture photo (returns "NOCAMERA" if camera bypassed)
    String photoCRC = capturePhoto(card.uid);

    // Build and sign access payload
    // NOTE: ArduinoJson serialises keys in insertion order (not sorted).
    // The Pi verifies HMAC against the raw string received before "sig" was
    // appended — so the order here MUST stay stable across firmware versions.
    StaticJsonDocument<384> doc;
    doc["device_id"]   = DEVICE_ID;
    doc["uid"]         = card.uid;
    doc["name"]        = card.name;
    doc["gender"]      = String(card.gender);
    doc["secret_code"] = card.secret_code;
    doc["photo_crc"]   = photoCRC;
    doc["nonce"]       = (uint32_t)esp_random();
    doc["timestamp"]   = (unsigned long)esp_timer_get_time() / 1000;

    String payload;
    serializeJson(doc, payload);
    doc["sig"] = signPayload(payload);   // sign base fields first, then append sig
    payload = "";
    serializeJson(doc, payload);

    mqtt.publish(TOPIC_ACCESS, payload.c_str());
    Serial.println(F(" [ 📤 MQTT] Payload sent. Waiting for Pi decision (≤5 s)..."));

    // Poll for Pi response (non-blocking via mqtt.loop())
    piDecisionReceived = false;
    unsigned long waitStart = millis();
    while (!piDecisionReceived && (millis() - waitStart < PI_RESPONSE_TIMEOUT_MS)) {
        mqtt.loop();
        delay(10);
    }

    setRGB(0, 0);   // clear yellow before result LED

    if (!piDecisionReceived) {
        Serial.println(F(" [ ⏰ TIME] Pi timeout — denying access."));
        startBlinkRed();
    } else if (piDecisionGrant) {
        Serial.println(F("\n================================================================"));
        Serial.println(F(" 🟢 ACCESS GRANTED"));
        Serial.println(F("================================================================\n"));
        relayOpen     = true;
        relayOpenedAt = millis();
        setRGB(0, 1);   // GREEN solid — auto-off after UNLOCK_DURATION_MS
    } else {
        Serial.println(F("\n================================================================"));
        Serial.println(F(" 🔴 ACCESS DENIED"));
        Serial.println(F("================================================================\n"));
        startBlinkRed();
    }

    rfid.PICC_HaltA();
    rfid.PCD_StopCrypto1();
}

// ═══════════════════════════════════════════════════════════════════════════
// 📥 MQTT CALLBACK
// ═══════════════════════════════════════════════════════════════════════════

void onMqttMessage(char* topic, byte* payload, unsigned int length) {
    String msg((char*)payload, length);
    String topicStr(topic);

    StaticJsonDocument<256> doc;
    if (deserializeJson(doc, msg) != DeserializationError::Ok) return;

    // Pi access decision (GRANT / DENY)
    if (topicStr == TOPIC_DECISION) {
        const char* decision = doc["decision"] | "";
        piDecisionGrant    = (strcmp(decision, "GRANT") == 0);
        piDecisionReceived = true;
        Serial.printf(" [ 📥 PI  ] Decision: %s\n", decision);
        return;
    }

    // Anti-FPGA nonce puzzle — solve: find x s.t. (nonce + x) % 1000 == 0
    if (topicStr == TOPIC_NONCE_CHALLENGE) {
        const char* devId = doc["device_id"] | "";
        if (strlen(devId) > 0 && String(devId) != DEVICE_ID) return;

        uint32_t nonce   = doc["nonce"] | 0;
        uint64_t t0      = esp_timer_get_time();
        uint32_t x       = 0;
        uint32_t rem     = nonce % 1000;
        if (rem != 0) x  = 1000 - rem;
        uint64_t solveUs = esp_timer_get_time() - t0;

        StaticJsonDocument<256> resp;
        resp["device_id"]     = DEVICE_ID;
        resp["nonce"]         = nonce;
        resp["solution"]      = x;
        resp["solve_time_us"] = (uint32_t)solveUs;
        String respStr;
        serializeJson(resp, respStr);
        mqtt.publish(TOPIC_NONCE_RESPONSE, respStr.c_str());
        Serial.printf(" [ 🧠 CPU ] Puzzle solved in %lluµs\n", solveUs);
        return;
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// 🚀 SETUP
// ═══════════════════════════════════════════════════════════════════════════

void setup() {
    Serial.begin(115200);
    delay(500);

    Serial.println(F("\n  ╔════════════════════════════════════════════════════╗"));
    Serial.println(F("  ║   ZERO-TRUST PERIMETER SCANNER  v3                ║"));
    Serial.println(F("  ║   Card-Data Auth + HMAC + Photo Log               ║"));
    Serial.println(F("  ╠════════════════════════════════════════════════════╣"));
    Serial.println(F("  ║  FIX1: Green LED → GPIO 0  (was GPIO4 = cam flash) ║"));
    Serial.println(F("  ║  FIX2: Red LED   → GPIO 2  (was GPIO16 = PSRAM)   ║"));
    Serial.println(F("  ║  FIX3: RFID RST  hardwired 3.3V (no GPIO needed)  ║"));
    Serial.println(F("  ╚════════════════════════════════════════════════════╝\n"));

    loadSecretKey();

    // Initialise all MIFARE key bytes to 0xFF (default Key A)
    for (byte i = 0; i < 6; i++) mifareKey.keyByte[i] = 0xFF;

    // LEDs
    pinMode(PIN_LED_RED,   OUTPUT);
    pinMode(PIN_LED_GREEN, OUTPUT);
    setRGB(0, 0);

    // Camera (bypassed when lens absent)
    if (!initCamera())
        Serial.println(F(" [ ⚠️ CAM ] Bypassed — RFID + Telemetry active."));

    // RFID — RST = -1 means MFRC522 skips RST GPIO (hardwired 3.3V)
    SPI.begin(PIN_SPI_SCK, PIN_SPI_MISO, PIN_SPI_MOSI, PIN_RFID_SS);
    rfid.PCD_Init();
    rfid.PCD_SetAntennaGain(rfid.RxGain_max);
    Serial.println(F(" [ 📡 RFID] RC522 online. RST hardwired to 3.3V."));

    // WiFi
    Serial.print(F(" [ 🌐 NET ] Connecting"));
    WiFi.mode(WIFI_STA);
    WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
    while (WiFi.status() != WL_CONNECTED) { delay(400); Serial.print("."); }
    Serial.printf("\n [ 🌐 NET ] IP: %s\n", WiFi.localIP().toString().c_str());

    // MQTT
    mqtt.setServer(MQTT_BROKER, MQTT_PORT);
    mqtt.setCallback(onMqttMessage);
    mqtt.setBufferSize(8192);

    lockDoor();
    Serial.println(F("\n  >>> ARMED. TAP CARD. <<<\n"));
}

// ═══════════════════════════════════════════════════════════════════════════
// 🔄 LOOP
// ═══════════════════════════════════════════════════════════════════════════

void loop() {
    unsigned long now = millis();

    // MQTT reconnect (non-blocking, retry every 5 s)
    if (!mqtt.connected() && (now - lastMqttReconnect > 5000)) {
        lastMqttReconnect = now;
        Serial.print(F(" [ 📡 MQTT] Connecting... "));
        if (mqtt.connect(MQTT_CLIENT_ID)) {
            Serial.println(F("OK"));
            mqtt.subscribe(TOPIC_DECISION);
            mqtt.subscribe(TOPIC_NONCE_CHALLENGE);
        } else {
            Serial.println(F("FAILED. Retry 5 s."));
        }
    }
    if (mqtt.connected()) mqtt.loop();

    // Heartbeat
    if (now - lastHeartbeat >= HEARTBEAT_INTERVAL_MS) {
        lastHeartbeat = now;
        if (mqtt.connected()) sendHeartbeat();
    }

    // RFID poll
    handleRFIDTap();

    // Non-blocking deny blink
    updateBlink();

    // Auto-relock after UNLOCK_DURATION_MS
    if (relayOpen && (now - relayOpenedAt >= UNLOCK_DURATION_MS)) {
        lockDoor();
    }
}
