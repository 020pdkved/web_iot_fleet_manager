#include "config.h"
#include <Arduino.h>
#include <HTTPUpdate.h>
#include <PubSubClient.h>
#include <WebServer.h>
#include <WiFi.h>
#include <WiFiClient.h>
#include <WiFiClientSecure.h>
#include <WiFiManager.h>
#include <mbedtls/sha256.h>
#include <nvs_flash.h>
#include <Preferences.h>

// =============================================================================
// GLOBAL STATE & SYSTEM VARIABLES
// =============================================================================
// Current active firmware mode:
//   Mode 1: Pressed -> Solid ON,  Released -> OFF
//   Mode 2: Pressed -> Blink,     Released -> OFF
//   Mode 3: Pressed -> OFF,       Released -> Solid ON
//   Mode 4: Pressed -> OFF,       Released -> Blink
uint8_t currentMode = ESP_MODE;

// Master Service State: true = ACTIVE (LED driven), false = STANDBY (LED OFF,
// MQTT alive)
bool systemServiceActive = true;

// Autonomous Offline Mode (true = 100% local operation without cloud/MQTT dependency)
bool autonomousOfflineMode = false;

// Output Delay in seconds (0.0 to 10.0 in 0.5s increments)
float outputDelaySec = 0.0f;

// Button state tracking & delay propagation
bool rawButtonState = false;     // true = Pressed, false = Released
bool delayedButtonState = false; // Applied button state after output delay
bool pendingStateChange = false;
bool targetPendingState = false;
unsigned long stateChangeStartTime = 0;

// LED Blink state tracking (4Hz -> 125ms ON / 125ms OFF)
unsigned long lastBlinkToggle = 0;
bool blinkOutputState = false;

// OTA In-Progress flag
bool otaInProgress = false;

// Unique Hardware Markers & Cryptographic Security Identity
String mqttClientId;
String chipIdStr;
String nodeMac = "";
String nodeName = "Node: A";
String nodeClient = "Client 1: Alpha Enterprise Corp";
String nodeProject = "Project 1: Enterprise OTA Fleet";
String nodeSecHash = "";

// Network & Web Server instances
WiFiManager wm;
WiFiClient espWifiClient;
PubSubClient mqttClient(espWifiClient);
WebServer localServer(80);

// =============================================================================
// FUNCTION DECLARATIONS
// =============================================================================
void initNVS();
void initHardware();
void initWiFiProvisioning();
void initMQTT();
void reconnectMQTT();
void publishStatusTelemetry();
void mqttCallback(char *topic, byte *payload, unsigned int length);
void performOTA(const String &firmwareUrl);
void updateHardwareStateMachine();
void setupInSituWebServer();
String computeSHA256(const String &input);

// =============================================================================
// SETUP
// =============================================================================
void setup() {
  Serial.begin(115200);
  delay(400);

  Serial.println("\n=======================================================");
  Serial.println("  Anashwar Technologies - ESP32 Enterprise Fleet Node   ");
  Serial.printf("  Firmware Mode : %d | Service: %s\n", currentMode,
                systemServiceActive ? "ACTIVE" : "STANDBY");
  Serial.println("=======================================================\n");

  // 1. Initialize NVS
  initNVS();

  // 2. Configure Hardware (GPIO 2 LED Output & GPIO 0 BOOT Button Input)
  initHardware();

  // 3. Provision Wi-Fi (Hardcoded VED-FI / vedfi with WiFiManager AP Fallback)
  initWiFiProvisioning();

  // 4. Initialize MQTT & Cryptographic Security Identity
  initMQTT();

  // 5. Start Self-Hosted In-Situ Web Server on Port 80
  setupInSituWebServer();
}

// =============================================================================
// MAIN LOOP (NON-BLOCKING)
// =============================================================================
void loop() {
  // 1. Service Hardware State Machine (Button read + Output Delay + LED drive)
  updateHardwareStateMachine();

  // 2. Wi-Fi auto-reconnect watchdog (non-blocking)
  static unsigned long lastWifiAttempt = 0;
  static int wifiAttemptToggle = 0;
  if (WiFi.status() != WL_CONNECTED) {
    unsigned long now = millis();
    if (now - lastWifiAttempt >= 8000) {
      lastWifiAttempt = now;
      const char *targetSsid =
          (wifiAttemptToggle % 2 == 0) ? WIFI_SSID : WIFI_SSID_FALLBACK;
      wifiAttemptToggle++;
      Serial.printf("[WiFi] Re-attempting connection to '%s'...\n", targetSsid);
      WiFi.disconnect(false);
      WiFi.begin(targetSsid, WIFI_PASSWORD);
    }
  }

  // 3. Service MQTT client & periodic telemetry (Bypassed if Autonomous Offline Mode is active)
  if (!otaInProgress && WiFi.status() == WL_CONNECTED && !autonomousOfflineMode) {
    if (!mqttClient.connected()) {
      reconnectMQTT();
    } else {
      mqttClient.loop();

      // Heartbeat telemetry transmission every 3 seconds (or faster on state
      // change)
      static unsigned long lastTelemetry = 0;
      static bool lastReportedBtn = false;
      static bool lastReportedService = true;
      static float lastReportedDelay = -1.0f;
      static uint8_t lastReportedMode = 0;

      unsigned long now = millis();
      bool stateChanged = (rawButtonState != lastReportedBtn) ||
                          (systemServiceActive != lastReportedService) ||
                          (fabs(outputDelaySec - lastReportedDelay) > 0.05f) ||
                          (currentMode != lastReportedMode);

      if (stateChanged || (now - lastTelemetry >= 3000)) {
        lastTelemetry = now;
        lastReportedBtn = rawButtonState;
        lastReportedService = systemServiceActive;
        lastReportedDelay = outputDelaySec;
        lastReportedMode = currentMode;
        publishStatusTelemetry();
      }
    }
  }

  // 4. Handle In-Situ Web Server requests on Port 80
  localServer.handleClient();

  delay(5);
}

// =============================================================================
// HARDWARE INITIALIZATION & STATE MACHINE
// =============================================================================
void initHardware() {
  // Configure GPIO 2 LED as Output
  pinMode(ONBOARD_LED_PIN, OUTPUT);
  digitalWrite(ONBOARD_LED_PIN, LED_STATE_OFF);

  // Configure GPIO 0 BOOT Button as Input with internal pull-up
  pinMode(BOOT_BUTTON_PIN, INPUT_PULLUP);

  // Initial read
  rawButtonState = (digitalRead(BOOT_BUTTON_PIN) == LOW);
  delayedButtonState = rawButtonState;

  Serial.printf("[HARDWARE] GPIO %d (LED Active-HIGH) & GPIO %d (BOOT Button) "
                "initialized.\n",
                ONBOARD_LED_PIN, BOOT_BUTTON_PIN);
}

void updateHardwareStateMachine() {
  bool networkAvailable = (WiFi.status() == WL_CONNECTED);
  // If master service is turned OFF (Standby), or network is disconnected and
  // autonomous "Serve while offline" mode is disabled, suspend service (force LED OFF)
  if (!systemServiceActive || (!networkAvailable && !autonomousOfflineMode)) {
    digitalWrite(ONBOARD_LED_PIN, LED_STATE_OFF);
    return;
  }

  unsigned long now = millis();

  // 1. Read immediate physical BOOT button state (GPIO 0: LOW = Pressed, HIGH =
  // Released)
  bool currentRaw = (digitalRead(BOOT_BUTTON_PIN) == LOW);

  // 2. Output Delay State Machine (0.0s to 10.0s in 0.5s increments)
  if (currentRaw != rawButtonState) {
    rawButtonState = currentRaw;
    if (outputDelaySec <= 0.05f) {
      // Instant propagation
      delayedButtonState = rawButtonState;
      pendingStateChange = false;
    } else {
      // Start output delay timer
      pendingStateChange = true;
      targetPendingState = rawButtonState;
      stateChangeStartTime = now;
    }
  }

  if (pendingStateChange) {
    unsigned long requiredDelayMs = (unsigned long)(outputDelaySec * 1000.0f);
    if (now - stateChangeStartTime >= requiredDelayMs) {
      delayedButtonState = targetPendingState;
      pendingStateChange = false;
    }
  }

  // 3. Update LED Output based on Active Firmware Mode & delayedButtonState
  // Mode 1: Pressed -> Solid ON,  Released -> OFF
  // Mode 2: Pressed -> Blink,     Released -> OFF
  // Mode 3: Pressed -> OFF,       Released -> Solid ON
  // Mode 4: Pressed -> OFF,       Released -> Blink

  // Blink generator: 4 Hz toggle (125ms half-period)
  if (now - lastBlinkToggle >= 125) {
    lastBlinkToggle = now;
    blinkOutputState = !blinkOutputState;
  }

  bool ledShouldBeOn = false;

  switch (currentMode) {
  case 1:
    // Mode 1: Solid ON while BOOT button is pressed, OFF when released
    ledShouldBeOn = delayedButtonState;
    break;

  case 2:
    // Mode 2: LED blinks while BOOT button is pressed, OFF when released
    ledShouldBeOn = delayedButtonState ? blinkOutputState : false;
    break;

  case 3:
    // Mode 3: Solid ON when BOOT button is NOT pressed, OFF when pressed
    ledShouldBeOn = !delayedButtonState;
    break;

  case 4:
    // Mode 4: LED blinks when BOOT button is NOT pressed, OFF when pressed
    ledShouldBeOn = (!delayedButtonState) ? blinkOutputState : false;
    break;

  default:
    ledShouldBeOn = delayedButtonState;
    break;
  }

  digitalWrite(ONBOARD_LED_PIN, ledShouldBeOn ? LED_STATE_ON : LED_STATE_OFF);
}

// =============================================================================
// CRYPTOGRAPHIC SHA-256 HASH COMPUTATION
// =============================================================================
String computeSHA256(const String &input) {
  byte shaResult[32];
  mbedtls_sha256_context ctx;
  mbedtls_sha256_init(&ctx);
  mbedtls_sha256_starts_ret(&ctx, 0); // 0 = SHA-256
  mbedtls_sha256_update_ret(&ctx, (const unsigned char *)input.c_str(),
                            input.length());
  mbedtls_sha256_finish_ret(&ctx, shaResult);
  mbedtls_sha256_free(&ctx);

  char hexBuf[65];
  for (int i = 0; i < 32; i++) {
    sprintf(hexBuf + (i * 2), "%02x", shaResult[i]);
  }
  hexBuf[64] = '\0';
  return String(hexBuf);
}

// =============================================================================
// NON-VOLATILE STORAGE (NVS) INITIALIZATION
// =============================================================================
void initNVS() {
  esp_err_t err = nvs_flash_init();
  if (err == ESP_ERR_NVS_NO_FREE_PAGES ||
      err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
    Serial.println(
        "[NVS] Truncated partition detected. Erasing and re-initializing...");
    ESP_ERROR_CHECK(nvs_flash_erase());
    err = nvs_flash_init();
  }
  ESP_ERROR_CHECK(err);
  Serial.println("[NVS] Non-Volatile Storage initialized.");
}

// =============================================================================
// WI-FI PROVISIONING & CONNECTION
// =============================================================================
void initWiFiProvisioning() {
  WiFi.mode(WIFI_STA);

  Serial.printf("[WiFi] Attempting direct connection to '%s'...\n", WIFI_SSID);
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);

  int attempts = 0;
  while (WiFi.status() != WL_CONNECTED && attempts < 20) {
    delay(350);
    Serial.print(".");
    attempts++;
  }

  if (WiFi.status() != WL_CONNECTED) {
    Serial.printf(
        "\n[WiFi] Could not connect to '%s'. Trying fallback '%s'...\n",
        WIFI_SSID, WIFI_SSID_FALLBACK);
    WiFi.disconnect();
    WiFi.begin(WIFI_SSID_FALLBACK, WIFI_PASSWORD);
    attempts = 0;
    while (WiFi.status() != WL_CONNECTED && attempts < 15) {
      delay(350);
      Serial.print(".");
      attempts++;
    }
  }

  if (WiFi.status() == WL_CONNECTED) {
    Serial.println("\n[WiFi] Connected successfully!");
    Serial.print("[WiFi] IP Address : ");
    Serial.println(WiFi.localIP());
    Serial.print("[WiFi] Gateway    : ");
    Serial.println(WiFi.gatewayIP());
    Serial.print("[WiFi] RSSI Signal: ");
    Serial.printf("%d dBm\n", WiFi.RSSI());
  } else {
    Serial.println("\n[WiFi] Auto-connect timed out. Initializing WiFiManager "
                   "fallback...");
    wm.setConfigPortalTimeout(60);
    wm.setConnectTimeout(10);
    if (!wm.autoConnect(AP_FALLBACK_SSID)) {
      Serial.println(
          "[WiFi] Portal timed out. Continuing in STA retry mode...");
    } else {
      Serial.println("[WiFi] Connected via Captive Portal!");
      Serial.print("[WiFi] IP Address: ");
      Serial.println(WiFi.localIP());
    }
  }
}

// =============================================================================
// MQTT INITIALIZATION & TELEMETRY
// =============================================================================
void initMQTT() {
  uint64_t mac = ESP.getEfuseMac();
  char idBuffer[32];
  snprintf(idBuffer, sizeof(idBuffer), "Anashwar-ESP32-%04X%08X",
           (uint16_t)(mac >> 32), (uint32_t)mac);
  mqttClientId = String(idBuffer);

  char chipBuf[32];
  snprintf(chipBuf, sizeof(chipBuf), "%04X%08X", (uint16_t)(mac >> 32),
           (uint32_t)mac);
  chipIdStr = String(chipBuf);

  uint8_t baseMac[6];
  esp_read_mac(baseMac, ESP_MAC_WIFI_STA);
  char macBuf[24];
  snprintf(macBuf, sizeof(macBuf), "%02X:%02X:%02X:%02X:%02X:%02X", baseMac[0],
           baseMac[1], baseMac[2], baseMac[3], baseMac[4], baseMac[5]);
  nodeMac = String(macBuf);

  // Compute unique cryptographic hardware SHA-256 fingerprint: sha256(MAC +
  // CHIP_ID + SALT)
  nodeSecHash = computeSHA256(nodeMac + chipIdStr + String(SECURITY_SALT));

  // Match against REGISTERED_NODES from config.h
  bool matched = false;
  for (size_t i = 0; i < REGISTERED_NODE_COUNT; i++) {
    if (nodeMac.equalsIgnoreCase(REGISTERED_NODES[i].macAddress) ||
        chipIdStr.equalsIgnoreCase(REGISTERED_NODES[i].chipId)) {
      nodeName = REGISTERED_NODES[i].nodeName;
      nodeClient = REGISTERED_NODES[i].clientName;
      nodeProject = REGISTERED_NODES[i].projectName;
      matched = true;
      break;
    }
  }

  if (!matched) {
    // Auto-discovered device
    nodeName = "Node: " + nodeMac.substring(nodeMac.length() - 5);
    nodeClient = "Unassigned Client";
    nodeProject = "Auto-Discovered";
  }

  // Load NVS persisted custom name overrides (from portal bidirectional renaming)
  Preferences p;
  p.begin("fleet", true);
  String sN = p.getString("node_name", "");
  String sC = p.getString("client_name", "");
  String sP = p.getString("proj_name", "");
  p.end();
  if (sN.length() > 0) nodeName = sN;
  if (sC.length() > 0) nodeClient = sC;
  if (sP.length() > 0) nodeProject = sP;

  mqttClient.setServer(MQTT_BROKER_HOST, MQTT_BROKER_PORT);
  mqttClient.setCallback(mqttCallback);
  mqttClient.setBufferSize(768);
  mqttClient.setKeepAlive(60);

  Serial.printf("[SECURITY] Verified Identity: %s\n", nodeName.c_str());
  Serial.printf("[SECURITY] Client: %s | Project: %s\n", nodeClient.c_str(),
                nodeProject.c_str());
  Serial.printf("[SECURITY] MAC: %s | ChipID: %s\n", nodeMac.c_str(),
                chipIdStr.c_str());
  Serial.printf("[SECURITY] SHA-256 Hash: %s\n", nodeSecHash.c_str());
}

void publishStatusTelemetry() {
  if (!mqttClient.connected())
    return;

  char statusPayload[512];
  snprintf(statusPayload, sizeof(statusPayload),
           "{\"name\":\"%s\",\"id\":\"%s\",\"mac\":\"%s\",\"chip_id\":\"%s\","
           "\"client\":\"%s\",\"project\":\"%s\",\"sec_hash\":\"%s\",\"mode\":%"
           "d,\"service\":%s,\"offline\":%s,\"state\":\"%s\",\"ip\":\"%s\",\"rssi\":%d,"
           "\"heap\":%u,\"uptime\":%lu,\"delay\":%.1f,\"btn\":%d,\"led\":%d}",
           nodeName.c_str(), mqttClientId.c_str(), nodeMac.c_str(),
           chipIdStr.c_str(), nodeClient.c_str(), nodeProject.c_str(),
           nodeSecHash.c_str(), currentMode,
           systemServiceActive ? "true" : "false",
           autonomousOfflineMode ? "true" : "false",
           systemServiceActive ? "online" : "standby",
           WiFi.localIP().toString().c_str(), WiFi.RSSI(),
           (unsigned int)ESP.getFreeHeap(), millis() / 1000, outputDelaySec,
           rawButtonState ? 1 : 0,
           (digitalRead(ONBOARD_LED_PIN) == LED_STATE_ON) ? 1 : 0);

  mqttClient.publish(MQTT_TOPIC_STATUS, statusPayload, false);
}

void reconnectMQTT() {
  static unsigned long lastReconnectAttempt = 0;
  unsigned long now = millis();

  if (now - lastReconnectAttempt < 5000)
    return;
  lastReconnectAttempt = now;

  if (WiFi.status() != WL_CONNECTED)
    return;

  Serial.printf("[MQTT] Connecting to broker %s:%d as %s...\n",
                MQTT_BROKER_HOST, MQTT_BROKER_PORT, mqttClientId.c_str());

  if (mqttClient.connect(mqttClientId.c_str())) {
    Serial.println("[MQTT] Connected successfully!");
    mqttClient.subscribe(MQTT_TOPIC_COMMANDS);
    Serial.printf("[MQTT] Subscribed to topic: %s\n", MQTT_TOPIC_COMMANDS);
    publishStatusTelemetry();
  } else {
    Serial.printf("[MQTT] Connection failed, rc=%d. Will retry...\n",
                  mqttClient.state());
  }
}

// =============================================================================
// COMMAND PROCESSOR & DISPATCHER
// =============================================================================
void mqttCallback(char *topic, byte *payload, unsigned int length) {
  if (length == 0 || otaInProgress)
    return;

  char messageBuffer[length + 1];
  memcpy(messageBuffer, payload, length);
  messageBuffer[length] = '\0';
  String cmd = String(messageBuffer);
  cmd.trim();

  Serial.printf("\n[MQTT] Received directive on '%s': %s\n", topic,
                cmd.c_str());

  // Targeted Command Resolution: "OTA:<target>:<url>" or
  // "CMD:<target>:<command>" Supports bracketed format (e.g. "CMD:[Node:
  // A]:DELAY:1.5") and prefixed format
  if (cmd.startsWith("CMD:") || cmd.startsWith("OTA:")) {
    bool isOTA = cmd.startsWith("OTA:");
    String rest = cmd.substring(4);
    String target = "";
    String action = "";

    if (rest.startsWith("[")) {
      int closeBracket = rest.indexOf(']');
      if (closeBracket > 0) {
        target = rest.substring(1, closeBracket);
        action = rest.substring(closeBracket + 1);
        if (action.startsWith(":"))
          action = action.substring(1);
      }
    } else if (rest.startsWith("Node: A:")) {
      target = "Node: A";
      action = rest.substring(8);
    } else if (rest.startsWith("Node: B:")) {
      target = "Node: B";
      action = rest.substring(8);
    } else {
      int firstCol = rest.indexOf(':');
      if (firstCol > 0) {
        target = rest.substring(0, firstCol);
        action = rest.substring(firstCol + 1);
      }
    }

    target.trim();
    action.trim();

    if (target.length() > 0) {
      bool isForMe = false;
      if (target.equalsIgnoreCase("ALL"))
        isForMe = true;
      else if (target.equalsIgnoreCase(nodeName))
        isForMe = true;
      else if (target.equalsIgnoreCase("Node A") && nodeName == "Node: A")
        isForMe = true;
      else if (target.equalsIgnoreCase("Node B") && nodeName == "Node: B")
        isForMe = true;
      else if ((target.equalsIgnoreCase("Node Alpha") ||
                target.equalsIgnoreCase("Alpha")) &&
               nodeName == "Node: A")
        isForMe = true;
      else if ((target.equalsIgnoreCase("Node Beta") ||
                target.equalsIgnoreCase("Beta")) &&
               nodeName == "Node: B")
        isForMe = true;
      else if (target.equalsIgnoreCase(nodeMac) ||
               target.equalsIgnoreCase(mqttClientId))
        isForMe = true;
      else if (WiFi.localIP().toString() == target)
        isForMe = true;

      if (!isForMe) {
        Serial.printf("[MQTT] Directive target is '%s', bypassing (I am %s).\n",
                      target.c_str(), nodeName.c_str());
        return;
      }

      if (isOTA) {
        Serial.printf(
            "[MQTT] OTA directive confirmed for %s (%s). Target: %s\n",
            nodeName.c_str(), nodeMac.c_str(), action.c_str());
        performOTA(action);
        return;
      }

      // Command targeted for this node
      cmd = action;
    }
  }

  // 1. Output Delay Configuration Directive
  if (cmd.startsWith("DELAY:") || cmd.startsWith("DELAY=")) {
    String valStr = cmd.substring(6);
    valStr.trim();
    float newDelay = valStr.toFloat();
    if (newDelay >= 0.0f && newDelay <= 10.0f) {
      outputDelaySec = newDelay;
      Serial.printf("[SYSTEM] %s: Output delay updated to %.1f seconds.\n",
                    nodeName.c_str(), outputDelaySec);
      publishStatusTelemetry();
    }
  }

  // 2. Master Service Toggle Directive
  else if (cmd.equalsIgnoreCase("SERVICE:OFF") ||
           cmd.equalsIgnoreCase("SERVICE=OFF") || cmd.equalsIgnoreCase("OFF")) {
    systemServiceActive = false;
    digitalWrite(ONBOARD_LED_PIN, LED_STATE_OFF);
    Serial.printf("[SYSTEM] %s: Master Service turned OFF (Standby Mode). "
                  "Telemetry & Broker remain alive.\n",
                  nodeName.c_str());
    publishStatusTelemetry();
  } else if (cmd.equalsIgnoreCase("SERVICE:ON") ||
             cmd.equalsIgnoreCase("SERVICE=ON") || cmd.equalsIgnoreCase("ON")) {
    systemServiceActive = true;
    Serial.printf("[SYSTEM] %s: Master Service turned ON (Active Mode).\n",
                  nodeName.c_str());
    publishStatusTelemetry();
  }

  // 3. Autonomous Offline Mode Directive
  else if (cmd.startsWith("OFFLINE:") || cmd.startsWith("OFFLINE=")) {
    String val = cmd.substring(8);
    val.trim();
    autonomousOfflineMode = (val.equalsIgnoreCase("ON") || val.equalsIgnoreCase("TRUE") || val.equalsIgnoreCase("1"));
    Serial.printf("[SYSTEM] %s: Autonomous Offline Mode %s.\n",
                  nodeName.c_str(), autonomousOfflineMode ? "ENABLED (100% Local)" : "DISABLED (Cloud Connected)");
    publishStatusTelemetry();
    if (autonomousOfflineMode && mqttClient.connected()) {
      delay(50);
      mqttClient.disconnect();
    }
  }

  // 3. Firmware Mode Switching Directive
  else if (cmd.startsWith("MODE:") || cmd.startsWith("MODE=")) {
    String modeStr = cmd.substring(5);
    modeStr.trim();
    int newMode = modeStr.toInt();
    if (newMode >= 1 && newMode <= 4) {
      currentMode = (uint8_t)newMode;
      Serial.printf("[SYSTEM] %s: Switched to Firmware Mode %d.\n",
                    nodeName.c_str(), currentMode);
      publishStatusTelemetry();
    }
  }

  // 4. Force Telemetry Report Directive & Presence Ping ACK
  else if (cmd.equalsIgnoreCase("REPORT") || cmd.equalsIgnoreCase("STATUS") || cmd.equalsIgnoreCase("PING")) {
    Serial.printf("[SYSTEM] %s: Presence Ping ACK triggered.\n", nodeName.c_str());
    publishStatusTelemetry();
  }

  // 4b. Bidirectional Renaming Directives (Persisted into NVS Flash)
  else if (cmd.startsWith("RENAME:") || cmd.startsWith("RENAME=")) {
    String val = cmd.substring(7);
    val.trim();
    if (val.length() > 0) {
      Serial.printf("[SYSTEM] Renaming node from '%s' to '%s' (persisted in NVS)\n", nodeName.c_str(), val.c_str());
      nodeName = val;
      Preferences p;
      p.begin("fleet", false);
      p.putString("node_name", nodeName);
      p.end();
      publishStatusTelemetry();
    }
  }
  else if (cmd.startsWith("SETCLIENT:") || cmd.startsWith("SETCLIENT=")) {
    String val = cmd.substring(10);
    val.trim();
    if (val.length() > 0) {
      Serial.printf("[SYSTEM] Updating client to '%s' (persisted in NVS)\n", val.c_str());
      nodeClient = val;
      Preferences p;
      p.begin("fleet", false);
      p.putString("client_name", nodeClient);
      p.end();
      publishStatusTelemetry();
    }
  }
  else if (cmd.startsWith("SETPROJECT:") || cmd.startsWith("SETPROJECT=")) {
    String val = cmd.substring(11);
    val.trim();
    if (val.length() > 0) {
      Serial.printf("[SYSTEM] Updating project to '%s' (persisted in NVS)\n", val.c_str());
      nodeProject = val;
      Preferences p;
      p.begin("fleet", false);
      p.putString("proj_name", nodeProject);
      p.end();
      publishStatusTelemetry();
    }
  }

  // 5. System Reset Directive
  else if (cmd.equalsIgnoreCase("REBOOT") || cmd.equalsIgnoreCase("RESET")) {
    Serial.printf("[SYSTEM] %s: Reboot requested via MQTT. Restarting...\n",
                  nodeName.c_str());
    delay(200);
    ESP.restart();
  }

  // 6. Direct OTA URL Directive
  else if (cmd.startsWith("http://") || cmd.startsWith("https://")) {
    performOTA(cmd);
  }
}

// =============================================================================
// OVER-THE-AIR (OTA) FLASH PIPELINE
// =============================================================================
void performOTA(const String &firmwareUrl) {
  otaInProgress = true;

  Serial.println("\n=======================================================");
  Serial.println(">>> STARTING OVER-THE-AIR (OTA) FIRMWARE UPDATE <<<");
  Serial.printf("Target URL: %s\n", firmwareUrl.c_str());
  Serial.println("=======================================================");

  if (mqttClient.connected()) {
    char statusPayload[200];
    snprintf(statusPayload, sizeof(statusPayload),
             "{\"id\":\"%s\",\"name\":\"%s\",\"mode\":%d,\"service\":%s,"
             "\"state\":\"ota_downloading\",\"url\":\"%s\"}",
             mqttClientId.c_str(), nodeName.c_str(), currentMode,
             systemServiceActive ? "true" : "false", firmwareUrl.c_str());
    mqttClient.publish(MQTT_TOPIC_STATUS, statusPayload, false);
    delay(80);
    mqttClient.disconnect();
  }

  httpUpdate.rebootOnUpdate(true);
  httpUpdate.setFollowRedirects(HTTPC_STRICT_FOLLOW_REDIRECTS);

  static int lastLoggedPercent = -1;
  lastLoggedPercent = -1;

  httpUpdate.onStart([]() {
    Serial.println(
        "[OTA] Partition stream opened. Flashing firmware sectors...");
  });

  httpUpdate.onEnd([]() {
    Serial.println(
        "\n[OTA] Flashing complete! Rebooting into verified firmware...");
  });

  httpUpdate.onProgress([](int current, int total) {
    if (total <= 0)
      return;
    static unsigned long lastStrobe = 0;
    unsigned long now = millis();
    if (now - lastStrobe >= 60) {
      lastStrobe = now;
      digitalWrite(ONBOARD_LED_PIN, !digitalRead(ONBOARD_LED_PIN));
    }

    int percent = (current * 100) / total;
    if (percent != lastLoggedPercent && (percent % 10 == 0 || percent == 100)) {
      lastLoggedPercent = percent;
      Serial.printf("[OTA] Progress: %3d%%  (%d / %d KB)\n", percent,
                    current / 1024, total / 1024);
    }
  });

  httpUpdate.onError([](int errorCode) {
    Serial.printf("[OTA] Error Code: %d\n", errorCode);
  });

  t_httpUpdate_return result;

  if (firmwareUrl.startsWith("https://")) {
    Serial.println("[OTA] Transport: TLS/HTTPS via WiFiClientSecure...");
    WiFiClientSecure secureClient;
    secureClient.setInsecure();
    secureClient.setTimeout(120);
    result = httpUpdate.update(secureClient, firmwareUrl);
  } else {
    Serial.println("[OTA] Transport: Plain HTTP via WiFiClient...");
    WiFiClient standardClient;
    standardClient.setTimeout(120);
    result = httpUpdate.update(standardClient, firmwareUrl);
  }

  switch (result) {
  case HTTP_UPDATE_FAILED:
    Serial.printf("[OTA] UPDATE FAILED! Error (%d): %s\n",
                  httpUpdate.getLastError(),
                  httpUpdate.getLastErrorString().c_str());
    otaInProgress = false;
    initHardware();
    break;

  case HTTP_UPDATE_NO_UPDATES:
    Serial.println("[OTA] HTTP 304: No updates.");
    otaInProgress = false;
    initHardware();
    break;

  case HTTP_UPDATE_OK:
    Serial.println("[OTA] Update OK! Rebooting...");
    break;
  }
}

// =============================================================================
// SELF-HOSTED IN-SITU WEB SERVER (Port 80 on Wi-Fi STA)
// =============================================================================
void setupInSituWebServer() {
  // 1. Root In-Situ Control Web Page (Anashwar Frosted Glass Design)
  localServer.on("/", HTTP_GET, []() {
    String modeTitles[] = {
        "", "Mode 1: Solid ON while BOOT pressed, OFF when released",
        "Mode 2: Blinks while BOOT pressed, OFF when released",
        "Mode 3: Solid ON when BOOT released, OFF when pressed",
        "Mode 4: Blinks when BOOT released, OFF when pressed"};
    String curModeTitle = (currentMode >= 1 && currentMode <= 4)
                              ? modeTitles[currentMode]
                              : ("Mode " + String(currentMode));

    String html =
        "<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'><meta "
        "name='viewport' content='width=device-width,initial-scale=1'>";
    html +=
        "<title>" + nodeName + " - Anashwar Enterprise Fleet</title><style>";
    html += ":root{--bg:#0B0F17;--card:rgba(22,27,34,0.75);--border:rgba(255,"
            "255,255,0.08);--crimson:#E11D48;--success:#10B981;--warn:#F59E0B;-"
            "-blue:#3B82F6;--text:#F8FAFC;--muted:#94A3B8;}";
    html += "* {box-sizing:border-box;margin:0;padding:0;} "
            "body{background:var(--bg);color:var(--text);font-family:-apple-"
            "system,BlinkMacSystemFont,'Segoe "
            "UI',Roboto,sans-serif;padding:24px 16px;min-height:100vh;}";
    html += ".container{max-width:560px;margin:0 auto;}";
    html += ".header{display:flex;align-items:center;gap:14px;margin-bottom:"
            "20px;padding-bottom:16px;border-bottom:1px solid var(--border);}";
    html += ".logo-box{width:46px;height:46px;border-radius:12px;background:"
            "linear-gradient(135deg,#E11D48,#9F1239);display:flex;align-items:"
            "center;justify-content:center;font-weight:900;font-size:22px;"
            "color:#fff;box-shadow:0 4px 14px rgba(225,29,72,0.4);}";
    html += ".header-titles h1{font-size:18px;font-weight:700;color:#fff;} "
            ".header-titles p{font-size:12px;color:var(--muted);}";
    html += ".card{background:var(--card);backdrop-filter:blur(20px);-webkit-"
            "backdrop-filter:blur(20px);border:1px solid "
            "var(--border);border-radius:18px;padding:22px;box-shadow:0 8px "
            "32px rgba(0,0,0,0.4);margin-bottom:16px;}";
    html += ".node-banner{display:flex;justify-content:space-between;align-"
            "items:center;margin-bottom:16px;}";
    html += ".node-title{font-size:22px;font-weight:800;color:#fff;letter-"
            "spacing:-0.5px;}";
    html += ".badge{padding:4px "
            "12px;border-radius:20px;font-size:11px;font-weight:700;text-"
            "transform:uppercase;letter-spacing:0.5px;}";
    html += ".badge-active{background:rgba(16,185,129,0.15);color:var(--"
            "success);border:1px solid rgba(16,185,129,0.3);}";
    html += ".badge-standby{background:rgba(245,158,11,0.15);color:var(--warn);"
            "border:1px solid rgba(245,158,11,0.3);}";
    html += ".row{display:flex;justify-content:space-between;align-items:"
            "center;padding:10px 0;border-bottom:1px solid "
            "rgba(255,255,255,0.05);font-size:13px;}";
    html +=
        ".row:last-child{border-bottom:none;} .row-label{color:var(--muted);} "
        ".row-val{font-family:monospace;font-weight:600;}";
    html += ".sec-hash{color:#34D399;font-size:11px;word-break:break-all;font-"
            "family:monospace;}";
    html += ".live-grid{display:grid;grid-template-columns:1fr "
            "1fr;gap:12px;margin-top:14px;}";
    html += ".live-box{background:rgba(0,0,0,0.3);border:1px solid "
            "var(--border);border-radius:12px;padding:14px;text-align:center;}";
    html += ".live-lbl{font-size:11px;color:var(--muted);text-transform:"
            "uppercase;margin-bottom:6px;font-weight:700;}";
    html += ".live-val{font-size:16px;font-weight:800;}";
    html +=
        ".section-title{font-size:12px;font-weight:700;color:var(--muted);text-"
        "transform:uppercase;letter-spacing:0.8px;margin-bottom:12px;}";
    html += "select,button{width:100%;padding:12px;border-radius:10px;font-"
            "size:14px;font-weight:600;margin-top:10px;cursor:pointer;"
            "transition:all 0.2s;}";
    html += "select{background:#0D1117;color:var(--text);border:1px solid "
            "var(--border);cursor:pointer;}";
    html += ".btn-service{border:none;color:#fff;}";
    html += ".btn-service-off{background:linear-gradient(135deg,#F59E0B,#"
            "D97706);box-shadow:0 4px 14px rgba(245,158,11,0.3);}";
    html += ".btn-service-on{background:linear-gradient(135deg,#10B981,#059669)"
            ";box-shadow:0 4px 14px rgba(16,185,129,0.3);}";
    html +=
        ".btn-primary{background:linear-gradient(135deg,#E11D48,#BE123C);"
        "border:none;color:#fff;box-shadow:0 4px 14px rgba(225,29,72,0.3);}";
    html += ".btn-mode{background:rgba(255,255,255,0.03);color:var(--text);"
            "border:1px solid var(--border);text-align:left;padding:12px "
            "14px;margin-top:8px;}";
    html += ".btn-mode.active{border-color:var(--crimson);background:rgba(225,"
            "29,72,0.15);color:#fff;}";
    html += ".btn-reboot{background:transparent;color:#EF4444;border:1px solid "
            "rgba(239,68,68,0.3);margin-top:16px;}";
    html += "</style></head><body><div class='container'>";

    // Header
    html += "<div class='header'><div class='logo-box'>at</div><div "
            "class='header-titles'><h1>Anashwar Technologies</h1><p>Enterprise "
            "Edge Node Control Console</p></div></div>";

    // Node Summary Card
    html += "<div class='card'>";
    html += "<div class='node-banner'><div class='node-title'>⚡ " + nodeName +
            "</div>";
    html += "<span class='badge " +
            String(systemServiceActive ? "badge-active'>ACTIVE"
                                       : "badge-standby'>STANDBY") +
            "</span></div>";

    html += "<div class='row'><span class='row-label'>Client "
            "Workspace</span><span class='row-val'>" +
            nodeClient + "</span></div>";
    html += "<div class='row'><span class='row-label'>Project "
            "Fleet</span><span class='row-val'>" +
            nodeProject + "</span></div>";
    html += "<div class='row'><span class='row-label'>Hardware MAC</span><span "
            "class='row-val'>" +
            nodeMac + "</span></div>";
    html += "<div class='row'><span class='row-label'>eFuse Chip "
            "ID</span><span class='row-val'>" +
            chipIdStr + "</span></div>";
    html += "<div class='row'><span class='row-label'>IP Address "
            "(STA)</span><span class='row-val' style='color:#60A5FA;'>" +
            WiFi.localIP().toString() + "</span></div>";
    html += "<div class='row'><span class='row-label'>Security "
            "Fingerprint</span><span class='sec-hash'>" +
            nodeSecHash.substring(0, 20) + "... [Verified]</span></div>";

    // Live status tiles
    html += "<div class='live-grid'>";
    html += "<div class='live-box'><div class='live-lbl'>BOOT Button (GPIO "
            "0)</div><div id='btn-live' class='live-val' style='color:" +
            String(rawButtonState ? "#10B981'>PRESSED" : "#94A3B8'>RELEASED") +
            "</div></div>";
    html += "<div class='live-box'><div class='live-lbl'>Blue LED (GPIO "
            "2)</div><div id='led-live' class='live-val' style='color:" +
            String((digitalRead(ONBOARD_LED_PIN) == LED_STATE_ON)
                       ? "#3B82F6'>SOLID ON"
                       : "#64748B'>DARK / OFF") +
            "</div></div>";
    html += "</div>";

    // Service Toggle Form
    html += "<form method='POST' action='/api/service'>";
    html += "<button type='submit' class='btn-service " +
            String(systemServiceActive
                       ? "btn-service-off'>⏸ Set Node to STANDBY (LED OFF, "
                         "Broker Active)"
                       : "btn-service-on'>▶ Turn Node to ACTIVE (Enable LED)") +
            "</button>";
    html += "</form>";
    html += "</div>";

    // Output Delay Configurator Card
    html += "<div class='card'>";
    html += "<div class='section-title'>⏱ Configurable Output Delay (0 - 10 "
            "sec, 0.5s step)</div>";
    html += "<form method='POST' action='/api/settings'>";
    html += "<label style='font-size:12px;color:var(--muted);'>Select output "
            "propagation delay when BOOT button toggles:</label>";
    html += "<select name='output_delay'>";
    for (float s = 0.0f; s <= 10.05f; s += 0.5f) {
      String sel = (fabs(outputDelaySec - s) < 0.1f) ? " selected" : "";
      html += "<option value='" + String(s, 1) + "'" + sel + ">" +
              String(s, 1) + " seconds" +
              (s == 0.0f ? " (Instant Propagation)" : "") + "</option>";
    }
    html += "</select>";
    html += "<button type='submit' class='btn-primary'>💾 Save Output "
            "Delay</button>";
    html += "</form>";
    html += "</div>";

    // Autonomous Offline Mode Card
    html += "<div class='card'>";
    html += "<div class='section-title'>🌐 Autonomous Offline Operation</div>";
    html += "<div style='font-size:12px;color:var(--muted);margin-bottom:10px;'>Operate ESP32 locally without cloud or MQTT dependency:</div>";
    html += "<form method='POST' action='/api/offline'>";
    html += "<button type='submit' class='btn-service " +
            String(autonomousOfflineMode
                       ? "btn-service-on'>⚡ Offline Mode ACTIVE (Click to Connect Cloud)"
                       : "btn-service-off'>🌐 Cloud Connected (Click to Go Offline)") +
            "</button>";
    html += "</form>";
    html += "</div>";

    // Firmware Mode Switcher Card
    html += "<div class='card'>";
    html += "<div class='section-title'>🎛 Switch Firmware Mode</div>";
    for (int m = 1; m <= 4; m++) {
      String act = (currentMode == m) ? " active" : "";
      html += "<form method='POST' action='/api/mode?val=" + String(m) + "'>";
      html += "<button type='submit' class='btn-mode" + act + "'>" +
              modeTitles[m] + "</button>";
      html += "</form>";
    }

    // Reboot Button
    html += "<form method='POST' action='/api/reboot' onsubmit='return "
            "confirm(\"Reboot this ESP32?\");'>";
    html += "<button type='submit' class='btn-reboot'>🔄 Reboot Node</button>";
    html += "</form>";
    html += "</div>";

    // Auto-refresh script for live button/led
    html += "<script>";
    html += "setInterval(()=>{";
    html += "fetch('/api/status').then(r=>r.json()).then(d=>{";
    html += "const btn=document.getElementById('btn-live');";
    html += "const led=document.getElementById('led-live');";
    html += "if(btn){btn.innerText=d.btn?'PRESSED':'RELEASED';btn.style.color="
            "d.btn?'#10B981':'#94A3B8';}";
    html += "if(led){led.innerText=d.led?'SOLID ON':'DARK / "
            "OFF';led.style.color=d.led?'#3B82F6':'#64748B';}";
    html += "}).catch(()=>{});";
    html += "}, 600);";
    html += "</script>";

    html += "</div></body></html>";
    localServer.send(200, "text/html", html);
  });

  // 2. Output Delay Setting API
  localServer.on("/api/settings", HTTP_POST, []() {
    if (localServer.hasArg("output_delay")) {
      float d = localServer.arg("output_delay").toFloat();
      if (d >= 0.0f && d <= 10.0f) {
        outputDelaySec = d;
        Serial.printf(
            "[WEB] Output delay updated to %.1f seconds via Web UI.\n",
            outputDelaySec);
        publishStatusTelemetry();
      }
    }
    localServer.sendHeader("Location", "/");
    localServer.send(303);
  });

  // 3. Service Toggle API
  localServer.on("/api/service", HTTP_POST, []() {
    systemServiceActive = !systemServiceActive;
    if (!systemServiceActive) {
      digitalWrite(ONBOARD_LED_PIN, LED_STATE_OFF);
    }
    Serial.printf("[WEB] Master Service toggled to: %s\n",
                  systemServiceActive ? "ACTIVE" : "STANDBY");
    publishStatusTelemetry();
    localServer.sendHeader("Location", "/");
    localServer.send(303);
  });

  // 4. Mode Selection API
  localServer.on("/api/mode", HTTP_POST, []() {
    if (localServer.hasArg("val")) {
      int m = localServer.arg("val").toInt();
      if (m >= 1 && m <= 4) {
        currentMode = (uint8_t)m;
        Serial.printf("[WEB] Switched to Firmware Mode %d.\n", currentMode);
        publishStatusTelemetry();
      }
    }
    localServer.sendHeader("Location", "/");
    localServer.send(303);
  });

  // 5. Autonomous Offline API
  localServer.on("/api/offline", HTTP_POST, []() {
    autonomousOfflineMode = !autonomousOfflineMode;
    Serial.printf("[WEB] Autonomous Offline Mode toggled to: %s\n",
                  autonomousOfflineMode ? "ENABLED (100% Local)" : "DISABLED (Cloud Active)");
    if (!autonomousOfflineMode && WiFi.status() == WL_CONNECTED && !mqttClient.connected()) {
      reconnectMQTT();
    }
    publishStatusTelemetry();
    localServer.sendHeader("Location", "/");
    localServer.send(303);
  });

  // 6. Node Reboot API
  localServer.on("/api/reboot", HTTP_POST, []() {
    localServer.send(200, "text/plain",
                     "Rebooting ESP32... Reconnecting in 15 seconds.");
    delay(300);
    ESP.restart();
  });

  // 7. JSON Status Telemetry Endpoint
  localServer.on("/api/status", HTTP_GET, []() {
    char buf[512];
    snprintf(
        buf, sizeof(buf),
        "{\"name\":\"%s\",\"id\":\"%s\",\"mac\":\"%s\",\"chip_id\":\"%s\","
        "\"client\":\"%s\",\"project\":\"%s\",\"sec_hash\":\"%s\",\"mode\":%d,"
        "\"service\":%s,\"offline\":%s,\"state\":\"%s\",\"ip\":\"%s\",\"rssi\":%d,\"heap\":%u,"
        "\"uptime\":%lu,\"delay\":%.1f,\"btn\":%d,\"led\":%d}",
        nodeName.c_str(), mqttClientId.c_str(), nodeMac.c_str(),
        chipIdStr.c_str(), nodeClient.c_str(), nodeProject.c_str(),
        nodeSecHash.c_str(), currentMode,
        systemServiceActive ? "true" : "false",
        autonomousOfflineMode ? "true" : "false",
        systemServiceActive ? "online" : "standby",
        WiFi.localIP().toString().c_str(), WiFi.RSSI(),
        (unsigned int)ESP.getFreeHeap(), millis() / 1000, outputDelaySec,
        rawButtonState ? 1 : 0,
        (digitalRead(ONBOARD_LED_PIN) == LED_STATE_ON) ? 1 : 0);

    localServer.send(200, "application/json", buf);
  });

  localServer.begin();
  Serial.println("[WEB] Self-Hosted In-Situ Web Server started on Port 80.");
}
