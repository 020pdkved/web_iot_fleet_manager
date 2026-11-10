// =============================================================================
// Minimal ESP32 Fleet Node Firmware with Embedded In-Situ Web Server (Port 80)
// Wi-Fi: "AnashwarTech2" | Password: "At@12345"
// Portal: https://manage.anashwartech.com
// =============================================================================

#include <WiFi.h>
#include <PubSubClient.h>
#include <WebServer.h>
#include <HTTPUpdate.h>
#include <mbedtls/sha256.h>

// 1. NETWORK & CLOUD BROKER CONFIGURATION
const char* WIFI_SSID     = "AnashwarTech2";
const char* WIFI_PASSWORD = "At@12345";

const char* MQTT_BROKER    = "broker.hivemq.com";
const int   MQTT_PORT      = 1883;
const char* TOPIC_STATUS   = "anashwar/poc/status";
const char* TOPIC_COMMANDS = "anashwar/poc/commands";
const char* SECURITY_SALT  = "AnashwarEnterprise2026SecureSalt";

// 2. FLEET & NODE IDENTITY (Rename as needed)
String nodeName    = "Tree 1";
String nodeClient  = "Hamley’s x Cadbury";
String nodeProject = "Connected Edge Fleet";

String nodeMac      = "";
String chipIdStr    = "";
String secHash      = "";
bool   masterActive = true;

WiFiClient   espClient;
PubSubClient mqtt(espClient);
WebServer    localServer(80);

unsigned long lastTelemetry = 0;

// =============================================================================
// CRYPTOGRAPHIC SHA-256 HARDWARE FINGERPRINT
// =============================================================================
String computeSecHash(String input) {
  byte hash[32];
  mbedtls_sha256_context ctx;
  mbedtls_sha256_init(&ctx);
  mbedtls_sha256_starts(&ctx, 0);
  mbedtls_sha256_update(&ctx, (const unsigned char*)input.c_str(), input.length());
  mbedtls_sha256_finish(&ctx, hash);
  mbedtls_sha256_free(&ctx);

  char hex[65];
  for (int i = 0; i < 32; i++) sprintf(&hex[i * 2], "%02x", hash[i]);
  hex[64] = 0;
  return String(hex);
}

// =============================================================================
// TELEMETRY HEARTBEAT (Zero-Touch Portal Schema)
// =============================================================================
void publishTelemetry() {
  if (!mqtt.connected()) return;

  char buf[768];
  snprintf(buf, sizeof(buf),
    "{\"name\":\"%s\",\"id\":\"Anashwar-%s\",\"mac\":\"%s\",\"chip_id\":\"%s\","
    "\"client\":\"%s\",\"project\":\"%s\",\"sec_hash\":\"%s\",\"mode\":1,"
    "\"service\":%s,\"offline\":false,\"state\":\"%s\",\"ip\":\"%s\","
    "\"rssi\":%d,\"heap\":%u,\"uptime\":%lu,\"delay\":0.0,\"btn\":0,\"led\":%d,"
    "\"mcu\":\"ESP32\",\"arch\":\"Xtensa LX6 Dual-Core\",\"flash\":4.0,\"ram\":320,\"antenna\":\"2.4 GHz 802.11 b/g/n\"}",
    nodeName.c_str(), chipIdStr.c_str(), nodeMac.c_str(), chipIdStr.c_str(),
    nodeClient.c_str(), nodeProject.c_str(), secHash.c_str(),
    masterActive ? "true" : "false",
    masterActive ? "online" : "standby",
    WiFi.localIP().toString().c_str(), WiFi.RSSI(),
    (unsigned int)ESP.getFreeHeap(), millis() / 1000,
    masterActive ? 1 : 0);

  mqtt.publish(TOPIC_STATUS, buf, false);
}

// =============================================================================
// REMOTE COMMAND HANDLER (PING, REBOOT, SERVICE, OTA)
// =============================================================================
void onMqttCommand(char* topic, byte* payload, unsigned int length) {
  char msg[length + 1];
  memcpy(msg, payload, length);
  msg[length] = '\0';
  String cmd = String(msg);
  cmd.trim();

  // Target Check: Wildcard [*] or this node name
  if (cmd.indexOf("[*]") < 0 && cmd.indexOf("[" + nodeName + "]") < 0) return;

  Serial.printf("[CMD] Received: %s\n", cmd.c_str());

  // 1. Presence Ping Response (<100ms ACK)
  if (cmd.indexOf("PING") >= 0) {
    publishTelemetry();
  }
  // 2. Hardware Reboot
  else if (cmd.indexOf("REBOOT") >= 0) {
    delay(200);
    ESP.restart();
  }
  // 3. Master Service Toggle
  else if (cmd.indexOf("SERVICE:OFF") >= 0) {
    masterActive = false;
    publishTelemetry();
  } else if (cmd.indexOf("SERVICE:ON") >= 0) {
    masterActive = true;
    publishTelemetry();
  }
  // 4. Over-The-Air Update
  else if (cmd.startsWith("OTA:")) {
    int lastCol = cmd.lastIndexOf(':');
    if (lastCol > 0) {
      String url = cmd.substring(lastCol + 1);
      Serial.printf("[OTA] Updating from %s...\n", url.c_str());
      WiFiClient otaClient;
      httpUpdate.update(otaClient, url);
    }
  }
}

// =============================================================================
// IN-SITU ON-BOARD WEB SERVER (Port 80)
// =============================================================================
void setupWebServer() {
  // Root Dashboard Page
  localServer.on("/", HTTP_GET, []() {
    String html = "<!DOCTYPE html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>";
    html += "<title>" + nodeName + " - Node Console</title><style>";
    html += "body{background:#0B0F17;color:#F8FAFC;font-family:-apple-system,sans-serif;padding:20px;text-align:center;}";
    html += ".card{max-width:440px;margin:20px auto;background:#161B22;border:1px solid rgba(255,255,255,0.1);border-radius:16px;padding:22px;text-align:left;}";
    html += "h1{font-size:20px;color:#E11D48;margin-bottom:14px;text-align:center;}";
    html += ".row{display:flex;justify-content:space-between;padding:8px 0;border-bottom:1px solid rgba(255,255,255,0.06);font-size:13px;}";
    html += ".btn{width:100%;padding:12px;border:none;border-radius:10px;font-weight:700;margin-top:14px;cursor:pointer;}";
    html += ".btn-on{background:#10B981;color:#fff;} .btn-off{background:#F59E0B;color:#fff;}";
    html += "</style></head><body><div class='card'>";
    html += "<h1>⚡ " + nodeName + "</h1>";
    html += "<div class='row'><span>Client</span><b>" + nodeClient + "</b></div>";
    html += "<div class='row'><span>Project</span><b>" + nodeProject + "</b></div>";
    html += "<div class='row'><span>IP Address</span><b style='color:#38BDF8;'>" + WiFi.localIP().toString() + "</b></div>";
    html += "<div class='row'><span>MAC</span><b>" + nodeMac + "</b></div>";
    html += "<div class='row'><span>Wi-Fi Signal</span><b>" + String(WiFi.RSSI()) + " dBm</b></div>";
    html += "<div class='row'><span>Service State</span><b style='color:" + String(masterActive ? "#10B981'>ACTIVE" : "#F59E0B'>STANDBY") + "</b></div>";
    html += "<form method='POST' action='/toggle'><button class='btn " + String(masterActive ? "btn-off'>Set STANDBY" : "btn-on'>Set ACTIVE") + "</button></form>";
    html += "</div></body></html>";
    localServer.send(200, "text/html", html);
  });

  localServer.on("/toggle", HTTP_POST, []() {
    masterActive = !masterActive;
    publishTelemetry();
    localServer.sendHeader("Location", "/");
    localServer.send(303);
  });

  localServer.begin();
  Serial.println("[HTTP] In-Situ Web UI listening on Port 80");
}

// =============================================================================
// MQTT RECONNECT
// =============================================================================
void reconnectMQTT() {
  static unsigned long lastTry = 0;
  if (millis() - lastTry < 4000) return;
  lastTry = millis();

  if (WiFi.status() != WL_CONNECTED) return;

  String clientId = "Anashwar-" + chipIdStr;
  Serial.printf("[MQTT] Connecting to %s as %s...\n", MQTT_BROKER, clientId.c_str());

  if (mqtt.connect(clientId.c_str())) {
    Serial.println("[MQTT] Connected! Subscribed to directives.");
    mqtt.subscribe(TOPIC_COMMANDS);
    publishTelemetry();
  }
}

// =============================================================================
// ARDUINO SETUP
// =============================================================================
void setup() {
  Serial.begin(115200);
  delay(300);

  // 1. Hardware Identifiers & SHA-256 Attestation
  uint64_t mac = ESP.getEfuseMac();
  char cBuf[32];
  snprintf(cBuf, sizeof(cBuf), "%04X%08X", (uint16_t)(mac >> 32), (uint32_t)mac);
  chipIdStr = String(cBuf);

  // 2. Wi-Fi Connection
  WiFi.mode(WIFI_STA);
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
  Serial.printf("\n[WiFi] Connecting to %s", WIFI_SSID);
  while (WiFi.status() != WL_CONNECTED) {
    delay(400);
    Serial.print(".");
  }

  nodeMac = WiFi.macAddress();
  secHash = computeSecHash(nodeMac + chipIdStr + String(SECURITY_SALT));

  Serial.println("\n[WiFi] Connected!");
  Serial.printf("[WiFi] Local IP: %s\n", WiFi.localIP().toString().c_str());
  Serial.printf("[SECURITY] SHA-256 Fingerprint: %s\n", secHash.c_str());

  // 3. MQTT Client
  mqtt.setServer(MQTT_BROKER, MQTT_PORT);
  mqtt.setCallback(onMqttCommand);
  mqtt.setBufferSize(768);

  // 4. Start Embedded Web UI on Port 80
  setupWebServer();
}

// =============================================================================
// ARDUINO LOOP
// =============================================================================
void loop() {
  // 1. Wi-Fi Watchdog
  if (WiFi.status() != WL_CONNECTED) {
    static unsigned long lastRetry = 0;
    if (millis() - lastRetry >= 6000) {
      lastRetry = millis();
      WiFi.reconnect();
    }
    return;
  }

  // 2. MQTT Client & Telemetry (Heartbeat every 5s)
  if (!mqtt.connected()) {
    reconnectMQTT();
  } else {
    mqtt.loop();
    if (millis() - lastTelemetry >= 5000) {
      lastTelemetry = millis();
      publishTelemetry();
    }
  }

  // 3. Serve Embedded In-Situ Web UI
  localServer.handleClient();

  delay(5);
}
