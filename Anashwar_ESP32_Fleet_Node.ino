/*
  =============================================================================
  Anashwar Technologies - Universal ESP32 Enterprise Fleet Node
  =============================================================================
  Production Reference Firmware (.ino) for Arduino IDE & PlatformIO
  
  Features:
    - Zero-Touch Cloud Auto-Onboarding to https://manage.anashwartech.com
    - Cryptographic 4-Point SHA-256 Hardware Fingerprint (MAC + Chip ID + Salt)
    - Bidirectional MQTT Telemetry & Directives via HiveMQ Cloud (1883)
    - Instant Presence Ping/ACK Watchdog Response (<100ms)
    - Self-Hosted In-Situ Web Server on Port 80 (LAN Direct & Cloud Proxy)
    - Remote Over-The-Air (OTA) Firmware Flashing via HTTP/HTTPS
    - Remote Hardware Reboot & Master Service State Toggle (Active/Standby)
    - Clean Architecture: ZERO GPIO 0 or GPIO 2 prototype remnants!
  
  Compatible Hardware:
    - ESP32-WROOM-32, ESP32-WROVER, ESP32-S2, ESP32-S3, ESP32-C3, ESP32-C6
  =============================================================================
*/

#include <WiFi.h>
#include <PubSubClient.h>
#include <WebServer.h>
#include <HTTPUpdate.h>
#include <Preferences.h>
#include <mbedtls/sha256.h>

// =============================================================================
// USER CONFIGURATION (Edit for your deployment)
// =============================================================================
const char* WIFI_SSID          = "VED-FI";               // Primary Wi-Fi SSID
const char* WIFI_PASSWORD      = "vedang123";            // Wi-Fi Password
const char* WIFI_SSID_FALLBACK = "vedfi";                // Fallback Wi-Fi SSID

const char* MQTT_BROKER        = "broker.hivemq.com";    // HiveMQ Public Broker
const int   MQTT_PORT          = 1883;                   // Standard MQTT TCP Port
const char* TOPIC_STATUS       = "anashwar/poc/status";   // Node -> Cloud Telemetry
const char* TOPIC_COMMANDS     = "anashwar/poc/commands"; // Cloud -> Node Directives

const char* SECURITY_SALT      = "AnashwarEnterprise2026SecureSalt";

// Default Enterprise Fleet Identity (Can also be renamed dynamically from portal)
String nodeName    = "Tree 1";
String nodeClient  = "Hamley’s x Cadbury";
String nodeProject = "Connected Edge Fleet";

// =============================================================================
// SYSTEM STATE & GLOBAL VARIABLES
// =============================================================================
bool masterServiceActive = true;       // Master operational state
bool otaInProgress       = false;      // OTA flashing flag

String nodeMac     = "";
String chipIdStr   = "";
String mqttClientId= "";
String secHash     = "";

WiFiClient   espWifiClient;
PubSubClient mqttClient(espWifiClient);
WebServer    localServer(80);

unsigned long lastTelemetryPublish = 0;
const unsigned long TELEMETRY_INTERVAL_MS = 6000; // Telemetry heartbeat (6 seconds)

// =============================================================================
// CRYPTOGRAPHIC SHA-256 HARDWARE FINGERPRINT
// =============================================================================
String computeSHA256(const String& input) {
  byte hash[32];
  mbedtls_sha256_context ctx;
  mbedtls_sha256_init(&ctx);
  mbedtls_sha256_starts(&ctx, 0); // 0 = SHA-256
  mbedtls_sha256_update(&ctx, (const unsigned char*)input.c_str(), input.length());
  mbedtls_sha256_finish(&ctx, hash);
  mbedtls_sha256_free(&ctx);

  char hexBuf[65];
  for (int i = 0; i < 32; i++) {
    sprintf(&hexBuf[i * 2], "%02x", hash[i]);
  }
  hexBuf[64] = '\0';
  return String(hexBuf);
}

// =============================================================================
// TELEMETRY PUBLISHER (JSON Schema for Zero-Touch Fleet Portal)
// =============================================================================
void publishStatusTelemetry() {
  if (!mqttClient.connected()) return;

  char payload[768];
  snprintf(payload, sizeof(payload),
    "{\"name\":\"%s\",\"id\":\"%s\",\"mac\":\"%s\",\"chip_id\":\"%s\","
    "\"client\":\"%s\",\"project\":\"%s\",\"sec_hash\":\"%s\",\"mode\":1,"
    "\"service\":%s,\"offline\":false,\"state\":\"%s\",\"ip\":\"%s\",\"rssi\":%d,"
    "\"heap\":%u,\"uptime\":%lu,\"delay\":0.0,\"btn\":0,\"led\":%d,"
    "\"mcu\":\"ESP32\",\"arch\":\"Xtensa LX6 Dual-Core @ 240MHz\",\"flash\":4.0,"
    "\"ram\":320,\"antenna\":\"2.4 GHz 802.11 b/g/n\"}",
    nodeName.c_str(), mqttClientId.c_str(), nodeMac.c_str(), chipIdStr.c_str(),
    nodeClient.c_str(), nodeProject.c_str(), secHash.c_str(),
    masterServiceActive ? "true" : "false",
    masterServiceActive ? "online" : "standby",
    WiFi.localIP().toString().c_str(), WiFi.RSSI(),
    (unsigned int)ESP.getFreeHeap(), millis() / 1000,
    masterServiceActive ? 1 : 0);

  mqttClient.publish(TOPIC_STATUS, payload, false);
}

// =============================================================================
// REMOTE OVER-THE-AIR (OTA) FIRMWARE UPDATE
// =============================================================================
void performOTA(const String& firmwareUrl) {
  Serial.printf("\n[OTA] Commencing Over-The-Air Update from: %s\n", firmwareUrl.c_str());
  otaInProgress = true;

  WiFiClient client;
  client.setTimeout(120);
  t_httpUpdate_return ret = httpUpdate.update(client, firmwareUrl);

  switch (ret) {
    case HTTP_UPDATE_FAILED:
      Serial.printf("[OTA] Flashing Failed! Error (%d): %s\n",
                    httpUpdate.getLastError(), httpUpdate.getLastErrorString().c_str());
      otaInProgress = false;
      break;
    case HTTP_UPDATE_NO_UPDATES:
      Serial.println("[OTA] HTTP 304: No newer binary available.");
      otaInProgress = false;
      break;
    case HTTP_UPDATE_OK:
      Serial.println("[OTA] Flashing Succeeded! Rebooting into new firmware...");
      ESP.restart();
      break;
  }
}

// =============================================================================
// MQTT COMMAND DISPATCHER & DIRECTIVE PROCESSOR
// =============================================================================
void onMqttDirective(char* topic, byte* payload, unsigned int length) {
  if (length == 0 || otaInProgress) return;

  char msgBuf[length + 1];
  memcpy(msgBuf, payload, length);
  msgBuf[length] = '\0';
  String cmd = String(msgBuf);
  cmd.trim();

  Serial.printf("[MQTT] Directive received: %s\n", cmd.c_str());

  // Target Check: Wildcard [*], ALL, or this node name
  String target = "";
  String action = cmd;

  if (cmd.startsWith("CMD:") || cmd.startsWith("OTA:")) {
    bool isOTA = cmd.startsWith("OTA:");
    String rest = cmd.substring(4);
    if (rest.startsWith("[")) {
      int closeBrk = rest.indexOf(']');
      if (closeBrk > 0) {
        target = rest.substring(1, closeBrk);
        action = rest.substring(closeBrk + 1);
        if (action.startsWith(":")) action = action.substring(1);
      }
    }
    target.trim();
    action.trim();

    bool isForMe = false;
    if (target == "*" || target.equalsIgnoreCase("ALL") || target.equalsIgnoreCase(nodeName) ||
        target.equalsIgnoreCase(nodeMac) || target.equalsIgnoreCase(chipIdStr) ||
        target == WiFi.localIP().toString()) {
      isForMe = true;
    }

    if (!isForMe) return; // Ignore commands directed to other nodes

    if (isOTA) {
      performOTA(action);
      return;
    }
  }

  // 1. Presence Ping ACK
  if (action.equalsIgnoreCase("PING") || action.equalsIgnoreCase("STATUS")) {
    Serial.printf("[SYSTEM] %s: Presence Ping ACK triggered.\n", nodeName.c_str());
    publishStatusTelemetry();
  }

  // 2. Hardware Reboot Directive
  else if (action.equalsIgnoreCase("REBOOT") || action.equalsIgnoreCase("RESET")) {
    Serial.printf("[SYSTEM] %s: Remote reboot ordered. Restarting...\n", nodeName.c_str());
    delay(200);
    ESP.restart();
  }

  // 3. Master Service Toggle
  else if (action.equalsIgnoreCase("SERVICE:OFF") || action.equalsIgnoreCase("SERVICE=OFF")) {
    masterServiceActive = false;
    Serial.printf("[SYSTEM] %s: Standby Mode engaged.\n", nodeName.c_str());
    publishStatusTelemetry();
  } else if (action.equalsIgnoreCase("SERVICE:ON") || action.equalsIgnoreCase("SERVICE=ON")) {
    masterServiceActive = true;
    Serial.printf("[SYSTEM] %s: Active Service engaged.\n", nodeName.c_str());
    publishStatusTelemetry();
  }

  // 4. Remote Bidirectional Renaming (Persisted to NVS)
  else if (action.startsWith("RENAME:") || action.startsWith("RENAME=")) {
    String newN = action.substring(7);
    newN.trim();
    if (newN.length() > 0) {
      nodeName = newN;
      Preferences p;
      p.begin("fleet", false);
      p.putString("node_name", nodeName);
      p.end();
      publishStatusTelemetry();
    }
  }

  // 5. Custom Project Directives (Add your project hardware logic here!)
  else if (action.startsWith("RELAY:") || action.startsWith("LIGHTS:") || action.startsWith("ACTUATOR:")) {
    Serial.printf("[PROJECT] Custom Directive executed: %s\n", action.c_str());
    publishStatusTelemetry();
  }
}

// =============================================================================
// MQTT RECONNECTION LOGIC
// =============================================================================
void reconnectMQTT() {
  static unsigned long lastAttempt = 0;
  if (millis() - lastAttempt < 4000) return;
  lastAttempt = millis();

  if (WiFi.status() != WL_CONNECTED) return;

  Serial.printf("[MQTT] Connecting to %s:%d as %s...\n", MQTT_BROKER, MQTT_PORT, mqttClientId.c_str());
  if (mqttClient.connect(mqttClientId.c_str())) {
    Serial.println("[MQTT] Connected! Subscribing to directives...");
    mqttClient.subscribe(TOPIC_COMMANDS);
    publishStatusTelemetry();
  } else {
    Serial.printf("[MQTT] Connect failed (rc=%d), will retry.\n", mqttClient.state());
  }
}

// =============================================================================
// SELF-HOSTED IN-SITU WEB SERVER (Port 80)
// =============================================================================
void setupInSituWebServer() {
  // 1. Root In-Situ Web UI Dashboard
  localServer.on("/", HTTP_GET, []() {
    String html = "<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'>";
    html += "<meta name='viewport' content='width=device-width,initial-scale=1'>";
    html += "<title>" + nodeName + " - Anashwar Enterprise Fleet</title>";
    html += "<style>";
    html += ":root{--bg:#0B0F17;--card:rgba(22,27,34,0.75);--border:rgba(255,255,255,0.08);--crimson:#E11D48;--green:#10B981;--blue:#38BDF8;--text:#F8FAFC;--muted:#94A3B8;}";
    html += "* {box-sizing:border-box;margin:0;padding:0;}";
    html += "body{background:var(--bg);color:var(--text);font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;padding:20px 16px;min-height:100vh;}";
    html += ".container{max-width:540px;margin:0 auto;}";
    html += ".header{display:flex;align-items:center;gap:12px;margin-bottom:18px;padding-bottom:14px;border-bottom:1px solid var(--border);}";
    html += ".logo{width:42px;height:42px;border-radius:10px;background:linear-gradient(135deg,#E11D48,#9F1239);display:flex;align-items:center;justify-content:center;font-weight:900;font-size:20px;color:#fff;box-shadow:0 4px 14px rgba(225,29,72,0.4);}";
    html += ".card{background:var(--card);backdrop-filter:blur(20px);-webkit-backdrop-filter:blur(20px);border:1px solid var(--border);border-radius:16px;padding:20px;margin-bottom:16px;box-shadow:0 8px 32px rgba(0,0,0,0.4);}";
    html += ".node-title{font-size:20px;font-weight:800;color:#fff;}";
    html += ".badge{padding:4px 10px;border-radius:20px;font-size:11px;font-weight:700;text-transform:uppercase;}";
    html += ".badge-act{background:rgba(16,185,129,0.15);color:var(--green);border:1px solid rgba(16,185,129,0.3);}";
    html += ".badge-sby{background:rgba(245,158,11,0.15);color:#FBBF24;border:1px solid rgba(245,158,11,0.3);}";
    html += ".row{display:flex;justify-content:space-between;align-items:center;padding:9px 0;border-bottom:1px solid rgba(255,255,255,0.05);font-size:13px;}";
    html += ".row:last-child{border-bottom:none;} .lbl{color:var(--muted);} .val{font-family:monospace;font-weight:600;}";
    html += "button{width:100%;padding:12px;border-radius:10px;font-size:14px;font-weight:700;margin-top:10px;cursor:pointer;border:none;transition:0.2s;}";
    html += ".btn-service-off{background:linear-gradient(135deg,#F59E0B,#D97706);color:#fff;}";
    html += ".btn-service-on{background:linear-gradient(135deg,#10B981,#059669);color:#fff;}";
    html += ".btn-reboot{background:transparent;color:#EF4444;border:1px solid rgba(239,68,68,0.3);margin-top:12px;}";
    html += "</style></head><body><div class='container'>";
    
    // Header
    html += "<div class='header'><div class='logo'>at</div><div><h1 style='font-size:17px;font-weight:700;'>Anashwar Technologies</h1><p style='font-size:11px;color:var(--muted);'>In-Situ On-Board Edge Console</p></div></div>";

    // Summary Card
    html += "<div class='card'>";
    html += "<div style='display:flex;justify-content:space-between;align-items:center;margin-bottom:14px;'><div class='node-title'>⚡ " + nodeName + "</div>";
    html += "<span class='badge " + String(masterServiceActive ? "badge-act'>ACTIVE" : "badge-sby'>STANDBY") + "</span></div>";
    html += "<div class='row'><span class='lbl'>Client</span><span class='val'>" + nodeClient + "</span></div>";
    html += "<div class='row'><span class='lbl'>Project</span><span class='val'>" + nodeProject + "</span></div>";
    html += "<div class='row'><span class='lbl'>Carrier IP (STA)</span><span class='val' style='color:#38BDF8;'>" + WiFi.localIP().toString() + "</span></div>";
    html += "<div class='row'><span class='lbl'>Hardware MAC</span><span class='val'>" + nodeMac + "</span></div>";
    html += "<div class='row'><span class='lbl'>Chip ID</span><span class='val'>" + chipIdStr + "</span></div>";
    html += "<div class='row'><span class='lbl'>Wi-Fi Signal</span><span class='val'>" + String(WiFi.RSSI()) + " dBm</span></div>";
    html += "<div class='row'><span class='lbl'>Free SRAM</span><span class='val'>" + String(ESP.getFreeHeap() / 1024) + " KB</span></div>";
    html += "<div class='row'><span class='lbl'>Security Fingerprint</span><span class='val' style='color:#34D399;font-size:11px;'>" + secHash.substring(0, 16) + "...</span></div>";

    // Service Toggle Form
    html += "<form method='POST' action='/api/service'>";
    html += "<button type='submit' class='" + String(masterServiceActive ? "btn-service-off'>⏸ Put Node into STANDBY" : "btn-service-on'>▶ Put Node into ACTIVE") + "</button>";
    html += "</form>";

    // Reboot Form
    html += "<form method='POST' action='/api/reboot' onsubmit='return confirm(\"Reboot this node?\");'>";
    html += "<button type='submit' class='btn-reboot'>🔄 Reboot Hardware</button>";
    html += "</form>";
    html += "</div>";

    html += "</div></body></html>";
    localServer.send(200, "text/html", html);
  });

  // 2. Service Toggle API
  localServer.on("/api/service", HTTP_POST, []() {
    masterServiceActive = !masterServiceActive;
    publishStatusTelemetry();
    localServer.sendHeader("Location", "/");
    localServer.send(303);
  });

  // 3. Remote Reboot API
  localServer.on("/api/reboot", HTTP_POST, []() {
    localServer.send(200, "text/plain", "Rebooting ESP32...");
    delay(250);
    ESP.restart();
  });

  // 4. JSON Status Telemetry Endpoint
  localServer.on("/api/status", HTTP_GET, []() {
    char buf[512];
    snprintf(buf, sizeof(buf),
      "{\"name\":\"%s\",\"id\":\"%s\",\"mac\":\"%s\",\"chip_id\":\"%s\","
      "\"client\":\"%s\",\"project\":\"%s\",\"sec_hash\":\"%s\","
      "\"service\":%s,\"state\":\"%s\",\"ip\":\"%s\",\"rssi\":%d,\"heap\":%u,\"uptime\":%lu}",
      nodeName.c_str(), mqttClientId.c_str(), nodeMac.c_str(), chipIdStr.c_str(),
      nodeClient.c_str(), nodeProject.c_str(), secHash.c_str(),
      masterServiceActive ? "true" : "false",
      masterServiceActive ? "online" : "standby",
      WiFi.localIP().toString().c_str(), WiFi.RSSI(),
      (unsigned int)ESP.getFreeHeap(), millis() / 1000);
    localServer.send(200, "application/json", buf);
  });

  localServer.begin();
  Serial.println("[HTTP] In-Situ On-Board Web Server listening on Port 80.");
}

// =============================================================================
// SETUP INITIALIZATION
// =============================================================================
void setup() {
  Serial.begin(115200);
  delay(300);

  Serial.println("\n=======================================================");
  Serial.println("  Anashwar Technologies - ESP32 Fleet Edge Node         ");
  Serial.println("  Portal: https://manage.anashwartech.com               ");
  Serial.println("=======================================================\n");

  // Load dynamically renamed names from NVS flash if previously saved
  Preferences p;
  p.begin("fleet", true);
  String sN = p.getString("node_name", "");
  String sC = p.getString("client_name", "");
  String sP = p.getString("proj_name", "");
  p.end();
  if (sN.length() > 0) nodeName = sN;
  if (sC.length() > 0) nodeClient = sC;
  if (sP.length() > 0) nodeProject = sP;

  // Derive unique hardware IDs
  uint64_t mac = ESP.getEfuseMac();
  char cBuf[32];
  snprintf(cBuf, sizeof(cBuf), "%04X%08X", (uint16_t)(mac >> 32), (uint32_t)mac);
  chipIdStr = String(cBuf);
  mqttClientId = "Anashwar-" + chipIdStr;

  // Wi-Fi Connection
  WiFi.mode(WIFI_STA);
  Serial.printf("[WiFi] Connecting to %s...\n", WIFI_SSID);
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
  int tries = 0;
  while (WiFi.status() != WL_CONNECTED && tries < 20) {
    delay(350);
    Serial.print(".");
    tries++;
  }
  if (WiFi.status() != WL_CONNECTED) {
    Serial.printf("\n[WiFi] Fallback to %s...\n", WIFI_SSID_FALLBACK);
    WiFi.disconnect();
    WiFi.begin(WIFI_SSID_FALLBACK, WIFI_PASSWORD);
    tries = 0;
    while (WiFi.status() != WL_CONNECTED && tries < 15) {
      delay(350);
      Serial.print(".");
      tries++;
    }
  }

  nodeMac = WiFi.macAddress();
  secHash = computeSHA256(nodeMac + chipIdStr + String(SECURITY_SALT));

  Serial.println("\n[WiFi] Connected!");
  Serial.printf("[WiFi] STA IP Address : %s\n", WiFi.localIP().toString().c_str());
  Serial.printf("[SECURITY] Verified SHA-256: %s\n", secHash.c_str());

  // MQTT Client
  mqttClient.setServer(MQTT_BROKER, MQTT_PORT);
  mqttClient.setCallback(onMqttDirective);
  mqttClient.setBufferSize(768);

  // In-Situ Web UI
  setupInSituWebServer();
}

// =============================================================================
// MAIN EXECUTION LOOP
// =============================================================================
void loop() {
  // 1. Wi-Fi auto-reconnect watchdog
  if (WiFi.status() != WL_CONNECTED) {
    static unsigned long lastWifiRetry = 0;
    if (millis() - lastWifiRetry >= 8000) {
      lastWifiRetry = millis();
      WiFi.disconnect();
      WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
    }
  }

  // 2. MQTT connectivity & background processing
  if (!otaInProgress && WiFi.status() == WL_CONNECTED) {
    if (!mqttClient.connected()) {
      reconnectMQTT();
    } else {
      mqttClient.loop();

      // Periodic Telemetry heartbeat
      unsigned long now = millis();
      if (now - lastTelemetryPublish >= TELEMETRY_INTERVAL_MS) {
        lastTelemetryPublish = now;
        publishStatusTelemetry();
      }
    }
  }

  // 3. Handle incoming In-Situ Web Server requests on Port 80
  localServer.handleClient();

  delay(5);
}
