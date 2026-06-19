/*
 * ==============================================================================
 * 🔐 ZERO-TRUST RFID GATEWAY — Standard ESP32 v1
 * ==============================================================================
 * Hardware:
 *   RC522 RFID Reader → Standard ESP32
 *   Green LED         → GPIO 26
 *   Red LED           → GPIO 27
 *   SCK               → GPIO 18
 *   MISO              → GPIO 19
 *   MOSI              → GPIO 23
 *   SDA (SS)          → GPIO 5
 *   RST               → GPIO 22
 *   VCC               → 3.3V
 *   GND               → GND
 * ==============================================================================
 */

#include <Arduino.h>
#include <WiFi.h>
#include <PubSubClient.h>
#include <ArduinoJson.h>
#include <SPI.h>
#include <MFRC522.h>
#include "mbedtls/md.h"
#include <Preferences.h>
// esp_task_wdt.h removed — non-blocking state machine never needs WDT reset

// ── 🌐 NETWORK — edit network_config.h to change WiFi/IP ────────────────────
#include "../../../network_config.h"
#define MQTT_BROKER          PI_MQTT_BROKER
#define MQTT_CLIENT_ID       "ESP32_RFID_GATEWAY"
#define DEVICE_ID            "ESP32_RFID_NODE"

// ── 📡 TOPICS ─────────────────────────────────────────────────────────────────
#define TOPIC_HEARTBEAT      "mailbox/heartbeat"
#define TOPIC_ACCESS         "mailbox/access"
#define TOPIC_DECISION       "mailbox/decision"
#define TOPIC_NONCE_CHALLENGE "perimeter/nonce_challenge"
#define TOPIC_NONCE_RESPONSE  "perimeter/nonce_response"

// ── 📌 PINS ───────────────────────────────────────────────────────────────────
#define PIN_SCK              18
#define PIN_MISO             19
#define PIN_MOSI             23
#define PIN_RFID_SS          5
#define PIN_RFID_RST         22
#define PIN_LED_GREEN        26    // no GPIO conflicts on standard ESP32
#define PIN_LED_RED          27

// ── ⏱️ TIMING ─────────────────────────────────────────────────────────────────
#define HEARTBEAT_MS         500
#define PI_TIMEOUT_MS        6000
#define COOLDOWN_MS          3000
#define GRANT_HOLD_MS        5000
#define DENY_HOLD_MS         5000

// ── 💾 STATE ──────────────────────────────────────────────────────────────────
WiFiClient         wifiClient;
PubSubClient       mqtt(wifiClient);
MFRC522            rfid(PIN_RFID_SS, PIN_RFID_RST);
MFRC522::MIFARE_Key mifareKey;

String  HMAC_KEY           = "";
bool    piDecisionReceived = false;
bool    piDecisionGrant    = false;

bool          relayOpen    = false;
unsigned long relayAt      = 0;
bool          denyActive   = false;
unsigned long denyAt       = 0;

unsigned long lastHeartbeat    = 0;
unsigned long lastRfidRead     = 0;
unsigned long lastMqttRetry    = 0;
uint32_t      lastPacketTime   = 0;

enum WaitState { IDLE, WAITING_PI };
WaitState     waitState    = IDLE;
unsigned long waitStarted  = 0;
String        lastUID      = "";   // saved for local fallback on Pi timeout

struct CardData {
    String uid, name, secret_code;
    char   gender;
    bool   read_ok;
};

// ── Local UID whitelist (fallback if Pi doesn't respond) ─────────────────────
// Add your authorized UIDs here — uppercase, no spaces
bool isAuthorizedLocally(const String& uid) {
    const char* authorizedUIDs[] = {
        "B2A3FB9D",   // Mridul
        "0205CA06",   // Onkar
    };
    for (auto& u : authorizedUIDs) {
        if (uid == u) return true;
    }
    return false;
}

// ═══════════════════════════════════════════════════════════════════════════
// 💡 LED (ACTIVE HIGH on standard ESP32 — HIGH = ON)
// ═══════════════════════════════════════════════════════════════════════════
// COMMON ANODE RGB LED: common pin → 3.3V
// To turn ON a color → drive its pin LOW
// To turn OFF a color → drive its pin HIGH
void led(bool r, bool g) {
    digitalWrite(PIN_LED_RED,   r ? LOW : HIGH);   // LOW = RED ON
    digitalWrite(PIN_LED_GREEN, g ? LOW : HIGH);   // LOW = GREEN ON
}

void startDeny() {
    denyActive = true;
    denyAt     = millis();
    led(1, 0);
    Serial.println(F(" [ 🔴 LED ] DENY — RED 5s"));
}

void updateDeny() {
    if (!denyActive) return;
    // Solid RED for DENY_HOLD_MS then off
    if (millis() - denyAt >= DENY_HOLD_MS) {
        denyActive = false;
        led(0, 0);
        Serial.println(F(" [ 🔴 LED ] Deny complete."));
    }
}

void startGrant() {
    relayOpen = true;
    relayAt   = millis();
    led(0, 1);
    Serial.println(F(" [ 🟢 LED ] GRANT — GREEN 5s"));
}

void lockDoor() {
    relayOpen = false;
    led(0, 0);
    Serial.println(F(" [ 🔒 ] Locked."));
}

// ═══════════════════════════════════════════════════════════════════════════
// 🔐 HMAC-SHA256
// ═══════════════════════════════════════════════════════════════════════════
void loadKey() {
    Preferences p;
    p.begin("vault", true);
    HMAC_KEY = p.getString("sk", "");
    p.end();
    if (HMAC_KEY.isEmpty()) {
        HMAC_KEY = "b3962f909a1507407466c4c962711d6d6f8ed9c98064e56592f31a13d6b035b9";
        Serial.println(F(" [ ⚠️ SEC ] Using fallback HMAC key."));
    } else {
        Serial.println(F(" [ 🔑 SEC ] HMAC key loaded from NVS."));
    }
}

String sign(const String& payload) {
    byte out[32];
    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);
    mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1);
    mbedtls_md_hmac_starts(&ctx, (const unsigned char*)HMAC_KEY.c_str(), HMAC_KEY.length());
    mbedtls_md_hmac_update(&ctx, (const unsigned char*)payload.c_str(), payload.length());
    mbedtls_md_hmac_finish(&ctx, out);
    mbedtls_md_free(&ctx);
    String sig = "";
    for (int i = 0; i < 16; i++) {
        if (out[i] < 0x10) sig += "0";
        sig += String(out[i], HEX);
    }
    return sig;
}

// ═══════════════════════════════════════════════════════════════════════════
// 💳 MIFARE READ
// ═══════════════════════════════════════════════════════════════════════════
CardData readCard() {
    CardData d = {"", "", "", '?', false};

    for (byte i = 0; i < rfid.uid.size; i++) {
        if (rfid.uid.uidByte[i] < 0x10) d.uid += "0";
        d.uid += String(rfid.uid.uidByte[i], HEX);
    }
    d.uid.toUpperCase();

    delay(50);
    MFRC522::StatusCode s;
    for (int t = 1; t <= 3; t++) {
        rfid.PCD_StopCrypto1();
        s = rfid.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, 7, &mifareKey, &rfid.uid);
        if (s == MFRC522::STATUS_OK) break;
        Serial.printf(" [ ⚠️ ] Auth try %d: %s\n", t, rfid.GetStatusCodeName(s));
        delay(30);
    }
    if (s != MFRC522::STATUS_OK) {
        Serial.println(F(" [ ❌ ] Auth failed."));
        return d;
    }

    byte buf[18]; byte sz = 18;

    // Block 4 → Name
    s = rfid.MIFARE_Read(4, buf, &sz);
    if (s != MFRC522::STATUS_OK) { Serial.println(F(" [ ❌ ] Block 4 fail.")); return d; }
    d.name = "";
    for (int i = 0; i < 16 && buf[i] != 0 && buf[i] >= 0x20; i++) d.name += (char)buf[i];
    d.name.trim();

    // Block 5 → Gender + Code
    sz = 18;
    s = rfid.MIFARE_Read(5, buf, &sz);
    if (s != MFRC522::STATUS_OK) { Serial.println(F(" [ ❌ ] Block 5 fail.")); return d; }
    d.gender = (char)buf[0];
    d.secret_code = "";
    for (int i = 1; i <= 4; i++) d.secret_code += (char)buf[i];
    d.read_ok = true;
    return d;
}

// ═══════════════════════════════════════════════════════════════════════════
// 💓 HEARTBEAT
// ═══════════════════════════════════════════════════════════════════════════
void sendHeartbeat() {
    uint32_t now = millis();
    uint32_t ipd = lastPacketTime ? (now - lastPacketTime) : 0;
    lastPacketTime = now;

    StaticJsonDocument<256> doc;
    doc["device_id"]          = DEVICE_ID;
    doc["nonce"]              = (uint32_t)esp_random();
    doc["timestamp"]          = (unsigned long)(esp_timer_get_time() / 1000);
    doc["inter_packet_delay"] = ipd;
    doc["rssi"]               = WiFi.RSSI();
    String p; serializeJson(doc, p);
    doc["sig"] = sign(p); p = ""; serializeJson(doc, p);
    mqtt.publish(TOPIC_HEARTBEAT, p.c_str());
    Serial.printf(" [ 💓 ] IPD:%4ums RSSI:%3ddBm\n", ipd, WiFi.RSSI());
}

// ═══════════════════════════════════════════════════════════════════════════
// 🆔 RFID HANDLER
// ═══════════════════════════════════════════════════════════════════════════
void handleRFID() {
    if (denyActive || relayOpen) return;
    if (millis() - lastRfidRead < COOLDOWN_MS) return;
    if (waitState == WAITING_PI) return;

    piDecisionReceived = false;
    piDecisionGrant    = false;

    if (!rfid.PICC_IsNewCardPresent()) return;
    if (!rfid.PICC_ReadCardSerial())   return;

    Serial.println(F("\n─────────────────────────────────────"));
    Serial.println(F(" 🆔 CARD DETECTED"));

    led(1, 1); delay(150); led(0, 0);   // white flash

    CardData card = readCard();

    if (!card.read_ok) {
        Serial.println(F(" [ ❌ ] Read failed — showing RED, cooldown 3s."));
        lastRfidRead = millis();   // enforce cooldown even on failed reads
        startDeny();
        rfid.PICC_HaltA(); rfid.PCD_StopCrypto1();
        return;
    }

    lastRfidRead = millis();

    Serial.printf(" [ 💳 ] UID:%s Name:%s Gender:%c Code:%s\n",
        card.uid.c_str(), card.name.c_str(), card.gender, card.secret_code.c_str());

    led(1, 1);   // yellow = waiting

    StaticJsonDocument<384> doc;
    doc["device_id"]   = DEVICE_ID;
    doc["uid"]         = card.uid;
    doc["name"]        = card.name;
    doc["gender"]      = String(card.gender);
    doc["secret_code"] = card.secret_code;
    doc["photo_crc"]   = "NOCAM";
    doc["nonce"]       = (uint32_t)esp_random();
    doc["timestamp"]   = (unsigned long)(esp_timer_get_time() / 1000);
    String payload; serializeJson(doc, payload);
    doc["sig"] = sign(payload); payload = ""; serializeJson(doc, payload);

    mqtt.publish(TOPIC_ACCESS, payload.c_str());
    Serial.println(F(" [ 📤 ] Sent to Pi. Waiting..."));

    waitState   = WAITING_PI;
    waitStarted = millis();
    lastUID     = card.uid;   // save for local fallback

    rfid.PICC_HaltA();
    rfid.PCD_StopCrypto1();
}

void processDecision() {
    if (waitState != WAITING_PI) return;

    if (piDecisionReceived) {
        waitState = IDLE;
        led(0, 0);
        if (piDecisionGrant) {
            Serial.println(F("\n ✅ ACCESS GRANTED"));
            startGrant();
        } else {
            Serial.println(F("\n ❌ ACCESS DENIED"));
            startDeny();
        }
        return;
    }

    if (millis() - waitStarted >= PI_TIMEOUT_MS) {
        waitState = IDLE;
        led(0, 0);
        Serial.println(F(" [ ⏰ ] Pi timeout — using local check."));
        // Fallback: check local whitelist so demo works without Pi
        if (isAuthorizedLocally(lastUID)) {
            Serial.println(F(" [ ✅ LOCAL] UID authorized locally — GRANT"));
            startGrant();
        } else {
            Serial.println(F(" [ ❌ LOCAL] UID not in local list — DENY"));
            startDeny();
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// 📥 MQTT CALLBACK
// ═══════════════════════════════════════════════════════════════════════════
void onMessage(char* topic, byte* payload, unsigned int len) {
    String msg((char*)payload, len);
    String t(topic);

    StaticJsonDocument<256> doc;
    if (deserializeJson(doc, msg)) return;

    if (t == TOPIC_DECISION) {
        const char* d = doc["decision"] | "";
        piDecisionGrant    = strcmp(d, "GRANT") == 0;
        piDecisionReceived = true;
        Serial.printf(" [ 📥 ] Pi: %s\n", d);
        return;
    }

    if (t == TOPIC_NONCE_CHALLENGE) {
        const char* devId = doc["device_id"] | "";
        if (strlen(devId) > 0 && String(devId) != DEVICE_ID) return;
        uint32_t nonce = doc["nonce"] | 0;
        uint32_t rem   = nonce % 1000;
        uint32_t x     = rem ? (1000 - rem) : 0;
        uint64_t t0    = esp_timer_get_time();
        uint64_t dt    = esp_timer_get_time() - t0;
        StaticJsonDocument<256> r;
        r["device_id"] = DEVICE_ID; r["nonce"] = nonce;
        r["solution"]  = x; r["solve_time_us"] = (uint32_t)dt;
        String rs; serializeJson(r, rs);
        mqtt.publish(TOPIC_NONCE_RESPONSE, rs.c_str());
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// 🚀 SETUP
// ═══════════════════════════════════════════════════════════════════════════
void setup() {
    Serial.begin(115200);
    delay(500);

    Serial.println(F("\n ╔══════════════════════════════════╗"));
    Serial.println(F("  ║  ZERO-TRUST RFID GATEWAY  v1     ║"));
    Serial.println(F("  ║  Standard ESP32 + RC522          ║"));
    Serial.println(F("  ╚══════════════════════════════════╝\n"));

    pinMode(PIN_LED_RED,   OUTPUT);
    pinMode(PIN_LED_GREEN, OUTPUT);
    led(0, 0);

    loadKey();

    for (byte i = 0; i < 6; i++) mifareKey.keyByte[i] = 0xFF;

    SPI.begin(PIN_SCK, PIN_MISO, PIN_MOSI, PIN_RFID_SS);
    rfid.PCD_Init();
    delay(100);

    byte ver = rfid.PCD_ReadRegister(rfid.VersionReg);
    Serial.printf(" [ 📡 RFID] Chip: 0x%02X %s\n", ver,
        (ver == 0x91 || ver == 0x92) ? "✅ Official" :
        (ver == 0x00 || ver == 0xFF) ? "❌ NOT FOUND" : "⚠️ Clone");

    // ── 🔍 WiFi Scan — shows ALL visible networks ──────────────────────────
    // ⚠️  HARDCODED credentials below (bypassing network_config.h for debug)
    //
    // OPTION A — Your hotspot (fix band to 2.4GHz first):
    const char* MY_SSID   = "Onki";
    const char* MY_PASS   = "123456789";
    //
    // OPTION B — Campus WiFi (strongest visible: Room203 at -42 dBm):
    // const char* MY_SSID = "Room203";
    // const char* MY_PASS = "??????????";  // ← enter Room203 password here
    //
    // MQTT_BROKER is defined globally from network_config.h → PI_MQTT_BROKER

    WiFi.mode(WIFI_STA);
    WiFi.disconnect(true);
    delay(1000);

    Serial.println(F("\n [ 🔍 ] Scanning WiFi networks..."));
    int n = WiFi.scanNetworks();
    if (n == 0) {
        Serial.println(F(" [ 🔍 ] No networks found at all!"));
    } else {
        Serial.printf(" [ 🔍 ] Found %d networks:\n", n);
        for (int i = 0; i < n; i++) {
            Serial.printf("   [%d] SSID: %-24s  RSSI: %3d dBm  Ch: %2d  Enc: %d%s\n",
                i + 1,
                WiFi.SSID(i).c_str(),
                WiFi.RSSI(i),
                WiFi.channel(i),
                WiFi.encryptionType(i),
                (WiFi.SSID(i) == MY_SSID) ? "  ← TARGET ✅" : ""
            );
        }
    }
    WiFi.scanDelete();

    Serial.printf("\n [ 🌐 ] Connecting to: \"%s\"\n", MY_SSID);
    WiFi.begin(MY_SSID, MY_PASS);
    {
        uint8_t tries = 0;
        while (WiFi.status() != WL_CONNECTED && tries < 60) {   // 60 × 500ms = 30s
            delay(500);
            tries++;
            uint8_t st = WiFi.status();
            if (tries % 4 == 0) {
                Serial.printf(" [ 🌐 ] status=%d  ", st);
                if      (st == WL_NO_SSID_AVAIL)  Serial.println(F("❌ SSID NOT FOUND"));
                else if (st == WL_CONNECT_FAILED)  Serial.println(F("❌ WRONG PASSWORD"));
                else if (st == WL_DISCONNECTED)    Serial.println(F("⏳ Associating..."));
                else if (st == WL_IDLE_STATUS)     Serial.println(F("⏳ Idle..."));
                else                               Serial.println(F("⏳ Waiting..."));
            } else { Serial.print("."); }
        }
        if (WiFi.status() != WL_CONNECTED) {
            Serial.println(F("\n [ 🌐 ] ❌ WiFi FAILED after 30s — rebooting in 5s"));
            delay(5000);
            ESP.restart();
        }
    }
    Serial.printf("\n [ 🌐 ] IP: %s\n", WiFi.localIP().toString().c_str());

    mqtt.setServer(MQTT_BROKER, MQTT_PORT);
    mqtt.setCallback(onMessage);
    mqtt.setBufferSize(4096);

    Serial.println(F("\n  >>> ARMED. TAP CARD. <<<\n"));

    led(0, 0);   // ensure LED starts OFF
}

// ═══════════════════════════════════════════════════════════════════════════
// 🔄 LOOP
// ═══════════════════════════════════════════════════════════════════════════
void loop() {
    unsigned long now = millis();

    // MQTT keep-alive
    if (!mqtt.connected() && (now - lastMqttRetry > 5000)) {
        lastMqttRetry = now;
        Serial.print(F(" [ 📡 ] MQTT reconnect... "));
        if (mqtt.connect(MQTT_CLIENT_ID)) {
            Serial.println(F("OK"));
            mqtt.subscribe(TOPIC_DECISION);
            mqtt.subscribe(TOPIC_NONCE_CHALLENGE);
        } else {
            Serial.print(F("FAILED  state="));
            Serial.println(mqtt.state());  // -4=timeout -3=denied -2=lost -1=disconnect 1=bad-proto 2=bad-id 3=unavail 4=bad-cred 5=unauth
        }
    }
    if (mqtt.connected()) mqtt.loop();

    // Heartbeat
    if (now - lastHeartbeat >= HEARTBEAT_MS) {
        lastHeartbeat = now;
        if (mqtt.connected()) sendHeartbeat();
    }

    // Core logic
    handleRFID();
    processDecision();
    updateDeny();

    // Auto-relock green
    if (relayOpen && (millis() - relayAt >= GRANT_HOLD_MS)) lockDoor();
}
