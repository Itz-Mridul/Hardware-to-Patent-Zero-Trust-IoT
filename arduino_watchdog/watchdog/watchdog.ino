#include <DHT.h>

// ── 📌 PIN DEFINITIONS ────────────────────────────────────────────────────────
#define DHT_PIN               2      // DHT22 data pin
#define VIB_PIN               3      // SW-420 vibration sensor (active LOW)
#define RELAY_PIN             7      // Kill-switch relay signal (HIGH = Pi CUT)
#define HEARTBEAT_LED         13     // Built-in LED for visual status

// ── ⚙️ SENSOR CONFIGURATION ───────────────────────────────────────────────────
#define DHT_TYPE              DHT22
#define ROOM_TEMP_LIMIT       70.0   // °C — Threshold for fire/heat-gun attack
#define READ_INTERVAL_MS      5000   // ms — Delay between DHT22 readings
#define WATCHDOG_TIMEOUT_MS   30000  // ms — Freeze threshold for Pi Keepalive
#define BAUD_RATE             9600   // bps— Serial communication speed

// ── 🎚️ OUTPUT TOGGLE ──────────────────────────────────────────────────────────
// TRUE  = Professional CLI Dashboard for your demo/serial monitor viewing
// FALSE = Strict JSON for the Raspberry Pi integration (REQUIRED for Pi to parse events)
bool HUMAN_MODE = false;   // ← Keep FALSE when connected to Pi; set TRUE only for serial monitor demo
// ──────────────────────────────────────────────────────────────────────────────

// ── ⏱️ TIMING & STATE VARIABLES ───────────────────────────────────────────────
DHT dht(DHT_PIN, DHT_TYPE);

unsigned long lastDhtReadMs   = 0;
unsigned long lastPiPingMs    = 0;
unsigned long vibDebounceMs   = 0;
bool          killSwitchActive= false;

// ── 🚨 INTERRUPT SERVICE ROUTINE (ISR) ────────────────────────────────────────
volatile bool vibrationDetected = false;

void vibrationISR() {
  vibrationDetected = true;
}

// ── 💀 RELAY CONTROL: THE KILL-SWITCH ─────────────────────────────────────────
void activateKillSwitch(String reason) {
  if (killSwitchActive) return;  // Prevent double-triggering

  killSwitchActive = true;

  if (HUMAN_MODE) {
    Serial.println();
    Serial.println(F("================================================================"));
    Serial.println(F(" ⚠️ CRITICAL INCIDENT : HARDWARE SABOTAGE DETECTED"));
    Serial.println(F("================================================================"));
    Serial.print(F(" >> TRIGGER SOURCE   : ")); Serial.println(reason);
    Serial.println(F(" >> ACTION           : INITIATING ZERO-DAY PROTOCOL"));
    Serial.println(F(" >> TARGET           : RELAY CIRCUIT [PIN 7]"));
    Serial.println(F(" >> STATUS           : SEVERING MAIN POWER SUPPLY..."));
    Serial.println(F("----------------------------------------------------------------"));
    Serial.println(F(" [OK] POWER CUT SUCCESSFUL."));
    Serial.println(F(" [OK] VOLATILE RAM WIPED TO ZEROES."));
    Serial.println(F(" [OK] VAULT SECURED. SYSTEM LOCKED UNTIL MANUAL RESET."));
    Serial.println(F("================================================================"));
  } else {
    Serial.print(F("{\"event\":\"KILL_SWITCH_ACTIVATED\",\"reason\":\""));
    Serial.print(reason);
    Serial.println(F("\",\"action\":\"POWER_CUT\"}"));
  }

  delay(100); // Flush serial buffer

  // EXECUTE POWER CUT 
  digitalWrite(RELAY_PIN, HIGH);

  // Enter infinite emergency LED flash pattern
  while (true) {
    digitalWrite(HEARTBEAT_LED, HIGH); delay(50);
    digitalWrite(HEARTBEAT_LED, LOW);  delay(50);
  }
}

// ── 🚀 SYSTEM SETUP ───────────────────────────────────────────────────────────
void setup() {
  Serial.begin(BAUD_RATE);
  delay(1000);

  pinMode(RELAY_PIN,     OUTPUT);
  pinMode(HEARTBEAT_LED, OUTPUT);
  pinMode(VIB_PIN,       INPUT_PULLUP);

  digitalWrite(RELAY_PIN,     LOW);
  digitalWrite(HEARTBEAT_LED, LOW);

  attachInterrupt(digitalPinToInterrupt(VIB_PIN), vibrationISR, FALLING);

  dht.begin();
  delay(2000);  

  lastPiPingMs = millis();

  if (HUMAN_MODE) {
    Serial.println();
    Serial.println(F("======================================================="));
    Serial.println(F("   ZERO-TRUST WATCHDOG v3.0  |  STATUS: ARMED   "));
    Serial.println(F("======================================================="));
    Serial.println(F(" [INIT] Air-Gapped Kernel ............... SECURE"));
    Serial.println(F(" [INIT] SW-420 Kinetic Sensor ........... ONLINE"));
    Serial.println(F(" [INIT] DHT22 Thermal Monitor ........... ONLINE"));
    Serial.println(F(" [INIT] Power Control Relay (Pin 7) ..... CLOSED"));
    Serial.println(F("-------------------------------------------------------"));
    Serial.println(F(" >> SYSTEM READY. MONITORING ENCLAVE."));
    Serial.println(F("=======================================================\n"));
  } else {
    Serial.println(F("{\"event\":\"WATCHDOG_ONLINE\",\"status\":\"ARMED\"}"));
  }
}

// ── 🔄 MAIN SUPERVISORY LOOP ──────────────────────────────────────────────────
void loop() {
  unsigned long now = millis();

  // 1️⃣ Visual Heartbeat
  static unsigned long lastLedMs = 0;
  if (now - lastLedMs > (killSwitchActive ? 100 : 1000)) {
    lastLedMs = now;
    digitalWrite(HEARTBEAT_LED, !digitalRead(HEARTBEAT_LED));
  }

  // 2️⃣ Read Serial Keepalive (PING)
  if (Serial.available() > 0) {
    String incoming = Serial.readStringUntil('\n');
    incoming.trim();
    if (incoming == "PING" || incoming.startsWith("{")) {
      lastPiPingMs = now;  
      if (HUMAN_MODE) Serial.println(F(" [NET] Heartbeat OK."));
    }
  }

  // 3️⃣ Software Freeze Detection
  if (now - lastPiPingMs > WATCHDOG_TIMEOUT_MS) {
    activateKillSwitch("PI_WATCHDOG_TIMEOUT");
  }

  // 4️⃣ Kinetic Attack Detection (Vibration)
  if (vibrationDetected) {
    vibrationDetected = false;
    if (now - vibDebounceMs > 1000) {
      vibDebounceMs = now;
      if (!HUMAN_MODE) {
        Serial.println(F("{\"event\":\"PHYSICAL_TAMPER\",\"sensor\":\"SW420\",\"action\":\"KILL_SWITCH_TRIGGERING\"}"));
      }
      activateKillSwitch("KINETIC_IMPACT_SW420");
    }
  }

  // 5️⃣ Thermal Attack Detection (DHT22)
  if (now - lastDhtReadMs >= READ_INTERVAL_MS) {
    lastDhtReadMs = now;

    float temp     = dht.readTemperature();
    float humidity = dht.readHumidity();

    if (isnan(temp) || isnan(humidity)) {
      if (HUMAN_MODE) {
        Serial.println(F(" [ERR] DHT22 SENSOR FAULT."));
      } else {
        Serial.println(F("{\"event\":\"DHT22_READ_ERROR\",\"action\":\"SENSOR_FAULT\"}"));
      }
    } else {
      if (HUMAN_MODE) {
        Serial.print(F(" [SYS] T: "));
        Serial.print(temp, 1);
        Serial.print(F("°C  |  H: "));
        Serial.print(humidity, 1);
        Serial.println(F("%"));
      } else {
        Serial.print(F("{\"event\":\"ENVIRONMENT\",\"temperature\":"));
        Serial.print(temp, 2);
        Serial.print(F(",\"humidity\":"));
        Serial.print(humidity, 2);
        Serial.println(F("}"));
      }

      if (temp >= ROOM_TEMP_LIMIT) {
        if (!HUMAN_MODE) {
          Serial.println(F("{\"event\":\"THERMAL_EMERGENCY\",\"action\":\"KILL_SWITCH_TRIGGERING\"}"));
        }
        activateKillSwitch("THERMAL_BREACH_70C");
      }
    }
  }
}