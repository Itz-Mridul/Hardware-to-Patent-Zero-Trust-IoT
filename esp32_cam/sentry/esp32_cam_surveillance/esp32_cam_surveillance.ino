/*
 * ==============================================================================
 * 📷 ZERO-TRUST SURVEILLANCE NODE — ESP32-CAM v1
 * ==============================================================================
 * Role: Visual surveillance only.
 *   - Connects to MQTT broker
 *   - Sends heartbeat telemetry
 *   - Listens for photo capture requests on "mailbox/photo_request"
 *   - Captures JPEG and publishes to "mailbox/photo/<uid>"
 *   - Onboard flash LED blinks RED on DENY, GREEN on GRANT (via broker events)
 * ==============================================================================
 */

#include <Arduino.h>
#include <WiFi.h>
#include <PubSubClient.h>
#include <ArduinoJson.h>
#include "esp_camera.h"
#include "mbedtls/md.h"
#include <Preferences.h>
#include "esp_task_wdt.h"

// ── 🌐 NETWORK ────────────────────────────────────────────────────────────────
#define WIFI_SSID            "Room203"
#define WIFI_PASSWORD        "Hostel@203"
#define MQTT_BROKER          "192.168.1.113"
#define MQTT_PORT            1883
#define MQTT_CLIENT_ID       "ESP32CAM_SURVEILLANCE"
#define DEVICE_ID            "ESP32_CAM_PERIMETER"

// ── 📡 TOPICS ─────────────────────────────────────────────────────────────────
#define TOPIC_HEARTBEAT      "mailbox/heartbeat"
#define TOPIC_PHOTO_REQUEST  "mailbox/photo_request"   // Pi → ESP32-CAM
#define TOPIC_PHOTO          "mailbox/photo"            // ESP32-CAM → Pi
#define TOPIC_DECISION       "mailbox/decision"         // Pi → nodes (for LED)
#define TOPIC_NONCE_CHALLENGE "perimeter/nonce_challenge"
#define TOPIC_NONCE_RESPONSE  "perimeter/nonce_response"

// ── 📌 PINS (AI Thinker ESP32-CAM) ───────────────────────────────────────────
#define CAM_PIN_PWDN         32
#define CAM_PIN_RESET        -1
#define CAM_PIN_XCLK         0
#define CAM_PIN_SIOD         26
#define CAM_PIN_SIOC         27
#define CAM_PIN_D7           35
#define CAM_PIN_D6           34
#define CAM_PIN_D5           39
#define CAM_PIN_D4           36
#define CAM_PIN_D3           21
#define CAM_PIN_D2           19
#define CAM_PIN_D1           18
#define CAM_PIN_D0           5
#define CAM_PIN_VSYNC        25
#define CAM_PIN_HREF         23
#define CAM_PIN_PCLK         22

// Onboard flash LED — GPIO 4 (safe to use now, no RFID on this device)
#define PIN_FLASH            4

// ── ⏱️ TIMING ─────────────────────────────────────────────────────────────────
#define HEARTBEAT_MS         500
#define BURST_COUNT          5     // number of photos taken on each DENY
#define BURST_DELAY_MS       600   // ms between each shot in burst

// ── 💾 STATE ──────────────────────────────────────────────────────────────────
WiFiClient    wifiClient;
PubSubClient  mqtt(wifiClient);
String        HMAC_KEY         = "";
unsigned long lastHeartbeat    = 0;
unsigned long lastMqttRetry    = 0;
uint32_t      lastPacketTime   = 0;
bool          cameraReady      = false;

// ═══════════════════════════════════════════════════════════════════════════
// 📸 CAMERA INIT
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
    config.frame_size   = FRAMESIZE_QVGA;   // 320x240 — fast over MQTT
    config.jpeg_quality = 12;
    config.fb_count     = 1;
    return esp_camera_init(&config) == ESP_OK;
}

// ═══════════════════════════════════════════════════════════════════════════
// 📷 BURST CAPTURE + PUBLISH  (5 photos, 600 ms apart)
// ═══════════════════════════════════════════════════════════════════════════
void captureAndPublish(const String& uid, const String& reason) {
    Serial.printf(" [ 📷 ] Burst capture for UID: %s (%s) — %d shots\n",
        uid.c_str(), reason.c_str(), BURST_COUNT);

    if (!cameraReady) {
        Serial.println(F(" [ ⚠️ CAM ] Camera not ready — sending NOCAMERA"));
        String topic = String(TOPIC_PHOTO) + "/" + uid + "/0";
        mqtt.publish(topic.c_str(), "NOCAMERA");
        return;
    }

    for (int shot = 0; shot < BURST_COUNT; shot++) {
        // Flash LED once per shot
        digitalWrite(PIN_FLASH, HIGH); delay(150); digitalWrite(PIN_FLASH, LOW);

        // Small settle time so camera AE adjusts between shots
        delay(50);

        camera_fb_t* fb = esp_camera_fb_get();
        if (!fb) {
            Serial.printf(" [ ❌ CAM ] Shot %d failed.\n", shot + 1);
            delay(BURST_DELAY_MS);
            continue;
        }

        // Topic: mailbox/photo/<uid>/<shot_index>
        // Pi subscribes to mailbox/photo/+/+ and saves each one separately
        String topic = String(TOPIC_PHOTO) + "/" + uid + "/" + String(shot);
        bool ok = mqtt.beginPublish(topic.c_str(), fb->len, false);
        if (ok) {
            size_t sent = 0;
            while (sent < fb->len) {
                size_t chunk = min((size_t)512, fb->len - sent);
                mqtt.write(fb->buf + sent, chunk);
                sent += chunk;
            }
            mqtt.endPublish();
            Serial.printf(" [ 📷 ] Shot %d/%d: %u bytes → %s\n",
                shot + 1, BURST_COUNT, fb->len, topic.c_str());
        } else {
            Serial.printf(" [ ❌ CAM ] Shot %d publish failed.\n", shot + 1);
        }
        esp_camera_fb_return(fb);

        if (shot < BURST_COUNT - 1) delay(BURST_DELAY_MS);
    }
    Serial.println(F(" [ 📷 ] Burst complete."));
}

// ═══════════════════════════════════════════════════════════════════════════
// 🔐 HMAC
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
// 📥 MQTT CALLBACK
// ═══════════════════════════════════════════════════════════════════════════
void onMessage(char* topic, byte* payload, unsigned int len) {
    String msg((char*)payload, len);
    String t(topic);

    StaticJsonDocument<256> doc;
    if (deserializeJson(doc, msg)) return;

    // Pi requests a photo capture
    if (t == TOPIC_PHOTO_REQUEST) {
        String uid    = doc["uid"]    | "UNKNOWN";
        String reason = doc["reason"] | "DENY";
        captureAndPublish(uid, reason);
        return;
    }

    // Flash LED to reflect decision from RFID node
    if (t == TOPIC_DECISION) {
        const char* d = doc["decision"] | "";
        if (strcmp(d, "GRANT") == 0) {
            // Brief green flash on the flash LED
            digitalWrite(PIN_FLASH, HIGH); delay(500); digitalWrite(PIN_FLASH, LOW);
        }
        return;
    }

    // Nonce puzzle
    if (t == TOPIC_NONCE_CHALLENGE) {
        const char* devId = doc["device_id"] | "";
        if (strlen(devId) > 0 && String(devId) != DEVICE_ID) return;
        uint32_t nonce = doc["nonce"] | 0;
        uint32_t rem   = nonce % 1000;
        uint32_t x     = rem ? (1000 - rem) : 0;
        StaticJsonDocument<256> r;
        r["device_id"] = DEVICE_ID; r["nonce"] = nonce;
        r["solution"]  = x; r["solve_time_us"] = 1;
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
    Serial.println(F("  ║  ZERO-TRUST SURVEILLANCE NODE   ║"));
    Serial.println(F("  ║  ESP32-CAM  v1                  ║"));
    Serial.println(F("  ╚══════════════════════════════════╝\n"));

    pinMode(PIN_FLASH, OUTPUT);
    digitalWrite(PIN_FLASH, LOW);

    loadKey();

    // Init camera
    cameraReady = initCamera();
    if (cameraReady) {
        Serial.println(F(" [ 📷 CAM ] Camera ready ✅"));
    } else {
        Serial.println(F(" [ ⚠️ CAM ] Camera init failed — running without lens."));
    }

    Serial.print(F(" [ 🌐 ] Connecting WiFi"));
    WiFi.mode(WIFI_STA);
    WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
    while (WiFi.status() != WL_CONNECTED) { delay(400); Serial.print("."); }
    Serial.printf("\n [ 🌐 ] IP: %s\n", WiFi.localIP().toString().c_str());

    mqtt.setServer(MQTT_BROKER, MQTT_PORT);
    mqtt.setCallback(onMessage);
    mqtt.setBufferSize(65536);   // large buffer for JPEG frames

    // Startup flash
    digitalWrite(PIN_FLASH, HIGH); delay(100); digitalWrite(PIN_FLASH, LOW);
    Serial.println(F("\n  >>> SURVEILLANCE ACTIVE <<<\n"));
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
            mqtt.subscribe(TOPIC_PHOTO_REQUEST);
            mqtt.subscribe(TOPIC_DECISION);
            mqtt.subscribe(TOPIC_NONCE_CHALLENGE);
        } else {
            Serial.println(F("FAILED"));
        }
    }
    if (mqtt.connected()) mqtt.loop();

    // Heartbeat
    if (now - lastHeartbeat >= HEARTBEAT_MS) {
        lastHeartbeat = now;
        if (mqtt.connected()) sendHeartbeat();
    }
}
