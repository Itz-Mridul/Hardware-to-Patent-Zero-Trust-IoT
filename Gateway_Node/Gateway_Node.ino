#include <WiFi.h>
#include <PubSubClient.h>
#include <ArduinoJson.h>
#include <DHT.h>

// ==========================================
// 1. CONFIGURATION
// ==========================================
const char* WIFI_SSID = "Room203";
const char* WIFI_PASSWORD = "YOUR_WIFI_PASSWORD"; // GitHub Safe!
const char* MQTT_SERVER = "192.168.1.105"; 
const int MQTT_PORT = 1883;
const char* DEVICE_ID = "ESP32_GATEWAY_001";

const unsigned long HEARTBEAT_INTERVAL_MS = 5000;
const unsigned long DASHBOARD_INTERVAL_MS = 1000; // 1 Hz is fast enough for a live dashboard 
const unsigned long DHT_READ_INTERVAL_MS = 2000; 
const unsigned long VIB_HOLD_MS = 400;           
const unsigned long TAMPER_DEBOUNCE_MS = 1000;   

#define DHTPIN 4
#define DHTTYPE DHT22
DHT dht(DHTPIN, DHTTYPE);

#ifndef D5
#define D5 5
#endif
#define VIB_PIN D5

WiFiClient espClient;
PubSubClient mqtt(espClient);

// ==========================================
// 2. SHARED STATE (Thread Safe)
// ==========================================
portMUX_TYPE stateMux = portMUX_INITIALIZER_UNLOCKED;

unsigned long lastDashboardMs = 0;
unsigned long lastDhtReadMs = 0;
unsigned long vibTriggerTime = 0;

float lastHumidity = 0.0;
float lastTemperature = 0.0;
int mqttState = 0; 
unsigned long sentCount = 0;

volatile bool vibrationLatched = false;
bool pendingTamperAlert = false; 
int visualVibLevel = 0;

// ==========================================
// 3. HARDWARE HELPERS
// ==========================================
void IRAM_ATTR vibrationISR() {
  vibrationLatched = true;
}

void updateDhtCache(bool forceRead = false) {
  unsigned long now = millis();
  if (!forceRead && now - lastDhtReadMs < DHT_READ_INTERVAL_MS) return;
  
  lastDhtReadMs = now;
  float humidity = dht.readHumidity();
  float temperature = dht.readTemperature();

  if (!isnan(humidity) && !isnan(temperature)) {
    portENTER_CRITICAL(&stateMux);
    lastHumidity = humidity;
    lastTemperature = temperature;
    portEXIT_CRITICAL(&stateMux);
  }
}

// ==========================================
// 4. THE AESTHETIC DASHBOARD (Core 1)
// ==========================================
void printBeautifulDashboard() {
  float temp, hum;
  int status, vib;
  unsigned long count;

  portENTER_CRITICAL(&stateMux);
  temp = lastTemperature;
  hum = lastHumidity;
  status = mqttState;
  vib = visualVibLevel;
  count = sentCount;
  portEXIT_CRITICAL(&stateMux);

  String connStatus = (status == 1) ? "[ OK ]" : "[FAIL]";
  String vibStatus = (vib > 0) ? "🚨 ALERT " : "✅ SAFE  ";

  Serial.printf("📡 PKT: %-5lu | 🌐 MQTT: %-6s | 🌡️ TEMP: %5.2f C | 💧 HUM: %5.2f %% | 📳 VIB: %-9s | 📶 RSSI: %-4d dBm\n", 
                count, connStatus.c_str(), temp, hum, vibStatus.c_str(), WiFi.RSSI());
}

// ==========================================
// 5. MQTT NETWORK TASK (Core 0 Background)
// ==========================================
void networkTask(void* pvParameters) {
  unsigned long lastHeartbeatMs = 0;
  unsigned long lastTamperPublishMs = 0;

  mqtt.setServer(MQTT_SERVER, MQTT_PORT);

  for (;;) {
    unsigned long now = millis();

    // 1. Maintain WiFi Connection
    if (WiFi.status() != WL_CONNECTED) {
      portENTER_CRITICAL(&stateMux);
      mqttState = 0;
      portEXIT_CRITICAL(&stateMux);
      
      WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
      
      while (WiFi.status() != WL_CONNECTED) {
        vTaskDelay(500 / portTICK_PERIOD_MS);
      }
      continue; 
    }

    // 2. Maintain MQTT Connection
    if (!mqtt.connected()) {
      portENTER_CRITICAL(&stateMux);
      mqttState = 0;
      portEXIT_CRITICAL(&stateMux);
      
      if (!mqtt.connect(DEVICE_ID)) {
         vTaskDelay(2000 / portTICK_PERIOD_MS);
         continue; 
      }
    } else {
      portENTER_CRITICAL(&stateMux);
      mqttState = 1;
      portEXIT_CRITICAL(&stateMux);
    }

    mqtt.loop(); 

    // 3. Check for Tamper Triggers
    bool localTamper = false;
    portENTER_CRITICAL(&stateMux);
    if (pendingTamperAlert) {
        localTamper = true;
        pendingTamperAlert = false;
    }
    portEXIT_CRITICAL(&stateMux);

    if (localTamper && (now - lastTamperPublishMs >= TAMPER_DEBOUNCE_MS)) {
      lastTamperPublishMs = now;
      
      StaticJsonDocument<160> doc;
      doc["device_id"] = DEVICE_ID;
      doc["event"] = "TAMPER_ALERT";
      doc["sensor"] = "SW-420";
      doc["rssi"] = WiFi.RSSI();
      doc["uptime_ms"] = now;

      char buffer[160];
      serializeJson(doc, buffer);
      mqtt.publish("mailbox/tamper", buffer);
      
      portENTER_CRITICAL(&stateMux);
      sentCount++;
      portEXIT_CRITICAL(&stateMux);
    }

    // 4. Send 5-Second Heartbeat
    if (now - lastHeartbeatMs >= HEARTBEAT_INTERVAL_MS) {
      lastHeartbeatMs = now;

      float t, h;
      portENTER_CRITICAL(&stateMux);
      t = lastTemperature;
      h = lastHumidity;
      portEXIT_CRITICAL(&stateMux);

      StaticJsonDocument<256> doc;
      doc["device_id"] = DEVICE_ID;
      doc["temperature"] = t;
      doc["humidity"] = h;
      doc["rssi"] = WiFi.RSSI();
      doc["uptime_ms"] = now;

      char buffer[256];
      serializeJson(doc, buffer);
      mqtt.publish("mailbox/heartbeat", buffer);

      portENTER_CRITICAL(&stateMux);
      sentCount++;
      portEXIT_CRITICAL(&stateMux);
    }

    vTaskDelay(10 / portTICK_PERIOD_MS);
  }
}

// ==========================================
// 6. MAIN SETUP & LOOP
// ==========================================
void setup() {
  Serial.begin(115200);
  delay(1000);

  Serial.println("\n=========================================================================================");
  Serial.println("                   🚀 ESP32 TELEMETRY NODE : SYSTEM BOOTING 🚀                        ");
  Serial.println("=========================================================================================\n");

  dht.begin();
  // INPUT_PULLUP keeps the line HIGH when the sensor is idle, preventing
  // floating-pin noise from triggering spurious RISING-edge interrupts.
  pinMode(VIB_PIN, INPUT_PULLUP);
  attachInterrupt(digitalPinToInterrupt(VIB_PIN), vibrationISR, RISING);

  updateDhtCache(true);

  xTaskCreatePinnedToCore(networkTask, "NetworkTask", 8192, NULL, 1, NULL, 0);
}

void loop() {
  unsigned long now = millis();
  updateDhtCache();

  if (vibrationLatched) {
    vibrationLatched = false;
    vibTriggerTime = now;
    
    portENTER_CRITICAL(&stateMux);
    visualVibLevel = 1;
    pendingTamperAlert = true; 
    portEXIT_CRITICAL(&stateMux);
  } else if (now - vibTriggerTime > VIB_HOLD_MS) {
    portENTER_CRITICAL(&stateMux);
    visualVibLevel = 0;
    portEXIT_CRITICAL(&stateMux);
  }

  if (now - lastDashboardMs >= DASHBOARD_INTERVAL_MS) {
    lastDashboardMs = now;
    printBeautifulDashboard();
  }
}
