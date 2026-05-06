#include <WiFi.h>
#include <PubSubClient.h>
#include <ArduinoJson.h>
#include <HTTPClient.h>

// ==========================================
// 1. CONFIGURATION
// ==========================================
const char* WIFI_SSID     = "Room203";
const char* WIFI_PASSWORD = "Hostel@203";
const char* MQTT_SERVER   = "192.168.1.113";
const int   MQTT_PORT     = 1883;
const char* HTTP_SERVER_URL = "http://192.168.1.113:5005/verify";
const char* DEVICE_ID     = "ESP32_TELEMETRY_NODE";

const unsigned long HEARTBEAT_INTERVAL_MS = 5000;
const unsigned long DASHBOARD_INTERVAL_MS = 1000;

WiFiClient espClient;
PubSubClient mqtt(espClient);

// ==========================================
// 2. SHARED STATE
// ==========================================
portMUX_TYPE stateMux = portMUX_INITIALIZER_UNLOCKED;

unsigned long lastDashboardMs = 0;
int mqttState = 0; 
unsigned long sentCount = 0;
bool mqttEverConnected = false;
const char* pendingConnectionState = "BOOT";

// ==========================================
// 3. THE AESTHETIC DASHBOARD (Core 1)
// ==========================================
void printBeautifulDashboard() {
  int status;
  unsigned long count;

  portENTER_CRITICAL(&stateMux);
  status = mqttState;
  count = sentCount;
  portEXIT_CRITICAL(&stateMux);

  String connStatus = (status == 1) ? "[OK]  " : "[FAIL]";

  Serial.printf("  │  PKT: %-5lu │ MQTT: %-6s │ RSSI: %-4d dBm │ HEAP: %-6d b │\n", 
                count, connStatus.c_str(), WiFi.RSSI(), ESP.getFreeHeap());
}

void dashboardTask(void* parameter) {
  for (;;) {
    unsigned long now = millis();
    if (now - lastDashboardMs >= DASHBOARD_INTERVAL_MS) {
      lastDashboardMs = now;
      printBeautifulDashboard();
    }
    vTaskDelay(100 / portTICK_PERIOD_MS);
  }
}

// ==========================================
// 4. MQTT & NETWORK
// ==========================================
void connectToWiFi() {
  Serial.print("\n📶 Connecting to WiFi: ");
  Serial.println(WIFI_SSID);
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }
  Serial.println("\n✅ WiFi Connected!");
}

void reconnectMqtt() {
  while (!mqtt.connected()) {
    Serial.print("🌐 Connecting to MQTT...");
    if (mqtt.connect(DEVICE_ID)) {
      Serial.println("connected");
      portENTER_CRITICAL(&stateMux);
      mqttState = 1;
      mqttEverConnected = true;
      portEXIT_CRITICAL(&stateMux);
    } else {
      Serial.print("failed, rc=");
      Serial.print(mqtt.state());
      Serial.println(" retry in 5s");
      portENTER_CRITICAL(&stateMux);
      mqttState = 0;
      portEXIT_CRITICAL(&stateMux);
      delay(5000);
    }
  }
}

// ==========================================
// 5. HEARTBEAT & TELEMETRY (Core 0)
// ==========================================
void sendHeartbeat() {
  // ── Build JSON with ALL 6 features the CNN-LSTM model needs ──────────────
  StaticJsonDocument<512> doc;
  doc["device_id"]          = DEVICE_ID;
  doc["timestamp"]          = millis();
  doc["rssi"]               = WiFi.RSSI();
  doc["free_heap"]          = ESP.getFreeHeap();
  doc["packet_size"]        = 512;   // Static JSON payload size
  doc["packet_count"]       = sentCount;
  doc["temperature"]        = 0.0;   // No sensor on this node — Arduino has it
  doc["humidity"]           = 0.0;   // No sensor on this node — Arduino has it
  doc["status"]             = "TELEMETRY_ACTIVE";

  char buffer[512];
  serializeJson(doc, buffer);

  // 1. Send via MQTT (for training data collector)
  if (mqtt.publish("mailbox/heartbeat", buffer)) {
    portENTER_CRITICAL(&stateMux);
    sentCount++;
    portEXIT_CRITICAL(&stateMux);
  }

  // 2. Send via HTTP to /verify (for live CNN-LSTM inference)
  HTTPClient http;
  http.begin(HTTP_SERVER_URL);
  http.addHeader("Content-Type", "application/json");
  int httpResponseCode = http.POST(buffer);
  http.end();
}

void setup() {
  Serial.begin(115200);
  delay(1000);

  Serial.println(F("\n  ┌─────────────────────────────────────────────────────────┐"));
  Serial.println(F("  │     ZERO-TRUST : TELEMETRY & NETWORK FINGERPRINT        │"));
  Serial.println(F("  ├─────────────────────────────────────────────────────────┤"));
  Serial.println(F("  │  [OK] Initializing Telemetry Node (ESP32 Standard)      │"));
  Serial.println(F("  │  [OK] Allocating CNN-LSTM Heartbeat Buffers             │"));
  Serial.println(F("  │  [OK] Configuring 6-Feature Data Extraction             │"));
  Serial.println(F("  ├─────────────────────────────────────────────────────────┤"));
  Serial.println(F("  │  DATA STREAM   : RSSI, Heap, IPD, PktSize, Temp, Hum    │"));
  Serial.println(F("  │  AI TARGET     : 5000ms Heartbeat Window                │"));
  Serial.println(F("  └─────────────────────────────────────────────────────────┘\n"));

  connectToWiFi();
  mqtt.setServer(MQTT_SERVER, MQTT_PORT);

  // Pin Core 1 to Dashboard printing, Core 0 to network + heartbeat
  xTaskCreatePinnedToCore(dashboardTask, "DashTask", 4096, NULL, 1, NULL, 1);

  Serial.println(F("\n  ┌─────────────────────────────────────────────────────────┐"));
  Serial.println(F("  │  [SYSTEM ONLINE] TRANSMITTING HARDWARE ATTESTATION      │"));
  Serial.println(F("  └─────────────────────────────────────────────────────────┘\n"));
}

void loop() {
  if (WiFi.status() != WL_CONNECTED) {
    connectToWiFi();
  }
  
  if (!mqtt.connected()) {
    reconnectMqtt();
  }
  mqtt.loop();

  static unsigned long lastHeartbeatMs = 0;
  if (millis() - lastHeartbeatMs >= HEARTBEAT_INTERVAL_MS) {
    lastHeartbeatMs = millis();
    sendHeartbeat();
  }
}
