// =============================================================================
// Anashwar Technologies - Universal Plug & Play ESP32 Fleet Node
// Wi-Fi Profiles:
//   1. "VED-FI"        / "11111111"
//   2. "AnashwarTech2" / "At@12345"
// Global Fleet Portal: https://manage.anashwartech.com
// =============================================================================

#include <WiFi.h>
#include <WiFiMulti.h>
#include <PubSubClient.h>
#include <WebServer.h>
#include <HTTPUpdate.h>
#include <mbedtls/sha256.h>

// 1. CLOUD BROKER & PROTOCOL CONFIGURATION
const char* MQTT_BROKER    = "broker.hivemq.com";
const int   MQTT_PORT      = 1883;
const char* TOPIC_STATUS   = "anashwar/poc/status";
const char* TOPIC_COMMANDS = "anashwar/poc/commands";
const char* SECURITY_SALT  = "AnashwarEnterprise2026SecureSalt";

// 2. FLEET & NODE IDENTITY (Change as needed)
String nodeName    = "Tree 1";
String nodeClient  = "Hamley’s x Cadbury";
String nodeProject = "Connected Edge Fleet";

String nodeMac      = "";
String chipIdStr    = "";
String secHash      = "";
bool   masterActive = true;

WiFiMulti    wifiMulti;
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

  Serial.printf("[CMD] Directive received: %s\n", cmd.c_str());

  // 1. Presence Ping Response (<100ms ACK)
  if (cmd.indexOf("PING") >= 0) {
    publishTelemetry();
  }
  // 2. Remote Reboot
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
      Serial.printf("[OTA] Commencing update from %s...\n", url.c_str());
      WiFiClient otaClient;
      httpUpdate.update(otaClient, url);
    }
  }
}

// =============================================================================
// IN-SITU ON-BOARD WEB SERVER (Port 80)
// =============================================================================
void setupWebServer() {
  // 1. Root In-Situ Web UI (Exact frosted-glass styling)
  localServer.on("/", HTTP_GET, []() {
    String html = "<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'>";
    html += "<meta name='viewport' content='width=device-width,initial-scale=1'>";
    html += "<title>" + nodeName + " - On-Board Console</title><style>";
    html += ":root{--bg:#0B0F17;--card:rgba(22,27,34,0.85);--border:rgba(255,255,255,0.08);--crimson:#E11D48;--green:#10B981;--blue:#38BDF8;--text:#F8FAFC;--muted:#94A3B8;}";
    html += "* {box-sizing:border-box;margin:0;padding:0;}";
    html += "body{background:var(--bg);color:var(--text);font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;padding:18px 16px;min-height:100vh;}";
    html += ".container{max-width:520px;margin:0 auto;}";
    html += ".header{display:flex;align-items:center;gap:12px;margin-bottom:16px;padding-bottom:12px;border-bottom:1px solid var(--border);}";
    html += ".logo{width:40px;height:40px;border-radius:10px;background:linear-gradient(135deg,#E11D48,#9F1239);display:flex;align-items:center;justify-content:center;font-weight:900;font-size:19px;color:#fff;box-shadow:0 4px 14px rgba(225,29,72,0.4);}";
    html += ".card{background:var(--card);backdrop-filter:blur(20px);-webkit-backdrop-filter:blur(20px);border:1px solid var(--border);border-radius:16px;padding:20px;margin-bottom:14px;box-shadow:0 8px 32px rgba(0,0,0,0.4);}";
    html += ".node-title{font-size:20px;font-weight:800;color:#fff;}";
    html += ".badge{padding:4px 10px;border-radius:20px;font-size:11px;font-weight:700;text-transform:uppercase;}";
    html += ".badge-act{background:rgba(16,185,129,0.15);color:var(--green);border:1px solid rgba(16,185,129,0.3);}";
    html += ".badge-sby{background:rgba(245,158,11,0.15);color:#FBBF24;border:1px solid rgba(245,158,11,0.3);}";
    html += ".row{display:flex;justify-content:space-between;align-items:center;padding:9px 0;border-bottom:1px solid rgba(255,255,255,0.05);font-size:13px;}";
    html += ".row:last-child{border-bottom:none;} .lbl{color:var(--muted);} .val{font-family:monospace;font-weight:600;}";
    html += "button{width:100%;padding:12px;border-radius:10px;font-size:14px;font-weight:700;margin-top:10px;cursor:pointer;border:none;transition:0.2s;}";
    html += ".btn-on{background:linear-gradient(135deg,#10B981,#059669);color:#fff;}";
    html += ".btn-off{background:linear-gradient(135deg,#F59E0B,#D97706);color:#fff;}";
    html += ".btn-reboot{background:transparent;color:#EF4444;border:1px solid rgba(239,68,68,0.3);margin-top:10px;}";
    html += ".hw-pill{background:rgba(56,189,248,0.12);color:#38BDF8;border:1px solid rgba(56,189,248,0.3);padding:3px 8px;border-radius:12px;font-size:10px;font-weight:700;}";
    html += "</style></head><body><div class='container'>";
    
    // Header
    html += "<div class='header'><div class='logo'>at</div><div style='flex:1;'>";
    html += "<div style='display:flex;justify-content:space-between;align-items:center;'><h1 style='font-size:16px;font-weight:700;'>Anashwar Technologies</h1><span class='hw-pill'>● On-Board Server (Port 80)</span></div>";
    html += "<p style='font-size:11px;color:var(--muted);margin-top:2px;'>Edge Node Hardware Console &bull; Connected to " + WiFi.SSID() + "</p></div></div>";

    // Summary Card
    html += "<div class='card'>";
    html += "<div style='display:flex;justify-content:space-between;align-items:center;margin-bottom:14px;'><div class='node-title'>⚡ " + nodeName + "</div>";
    html += "<span class='badge " + String(masterActive ? "badge-act' id='badge-state'>ACTIVE" : "badge-sby' id='badge-state'>STANDBY") + "</span></div>";
    html += "<div class='row'><span class='lbl'>Client</span><span class='val'>" + nodeClient + "</span></div>";
    html += "<div class='row'><span class='lbl'>Project</span><span class='val'>" + nodeProject + "</span></div>";
    html += "<div class='row'><span class='lbl'>Local IP (STA)</span><span class='val' style='color:#38BDF8;'>" + WiFi.localIP().toString() + "</span></div>";
    html += "<div class='row'><span class='lbl'>Connected Wi-Fi</span><span class='val' style='color:#34D399;'>" + WiFi.SSID() + "</span></div>";
    html += "<div class='row'><span class='lbl'>Hardware MAC</span><span class='val'>" + nodeMac + "</span></div>";
    html += "<div class='row'><span class='lbl'>Chip ID</span><span class='val'>" + chipIdStr + "</span></div>";
    html += "<div class='row'><span class='lbl'>Wi-Fi Signal</span><span class='val'>" + String(WiFi.RSSI()) + " dBm</span></div>";
    html += "<div class='row'><span class='lbl'>Free Heap RAM</span><span class='val'>" + String(ESP.getFreeHeap() / 1024) + " KB</span></div>";
    html += "<div class='row'><span class='lbl'>Security Attestation</span><span class='val' style='color:#34D399;font-size:11px;'>" + secHash.substring(0, 16) + "...</span></div>";

    // Service Toggle Form
    html += "<form method='POST' action='/api/service'>";
    html += "<button type='submit' class='" + String(masterActive ? "btn-off'>⏸ Put Node into STANDBY" : "btn-on'>▶ Put Node into ACTIVE") + "</button>";
    html += "</form>";

    // Reboot Form
    html += "<form method='POST' action='/api/reboot' onsubmit='return confirm(\"Reboot this node?\");'>";
    html += "<button type='submit' class='btn-reboot'>🔄 Reboot Hardware</button>";
    html += "</form>";
    html += "</div></div>";

    // Auto-refresh script
    html += "<script>setInterval(()=>{fetch('/api/status').then(r=>r.json()).then(d=>{";
    html += "const b=document.getElementById('badge-state');if(b){b.className='badge '+(d.service?'badge-act':'badge-sby');b.innerText=d.service?'ACTIVE':'STANDBY';}";
    html += "}).catch(()=>{});},1500);</script></body></html>";

    localServer.send(200, "text/html", html);
  });

  // 2. Service Toggle API
  localServer.on("/api/service", HTTP_POST, []() {
    masterActive = !masterActive;
    publishTelemetry();
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
      nodeName.c_str(), ("Anashwar-" + chipIdStr).c_str(), nodeMac.c_str(), chipIdStr.c_str(),
      nodeClient.c_str(), nodeProject.c_str(), secHash.c_str(),
      masterActive ? "true" : "false",
      masterActive ? "online" : "standby",
      WiFi.localIP().toString().c_str(), WiFi.RSSI(),
      (unsigned int)ESP.getFreeHeap(), millis() / 1000);
    localServer.send(200, "application/json", buf);
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

  // 1. Silicon Hardware Identifiers & SHA-256 Attestation
  uint64_t mac = ESP.getEfuseMac();
  char cBuf[32];
  snprintf(cBuf, sizeof(cBuf), "%04X%08X", (uint16_t)(mac >> 32), (uint32_t)mac);
  chipIdStr = String(cBuf);

  // 2. Plug & Play Multi-AP Wi-Fi Configuration (VED-FI and AnashwarTech2)
  WiFi.mode(WIFI_STA);
  wifiMulti.addAP("VED-FI", "11111111");
  wifiMulti.addAP("AnashwarTech2", "At@12345");

  Serial.println("\n[WiFi] Scanning for known networks (VED-FI, AnashwarTech2)...");
  while (wifiMulti.run() != WL_CONNECTED) {
    delay(400);
    Serial.print(".");
  }

  nodeMac = WiFi.macAddress();
  secHash = computeSecHash(nodeMac + chipIdStr + String(SECURITY_SALT));

  Serial.println("\n[WiFi] Connected to SSID: " + WiFi.SSID());
  Serial.printf("[WiFi] Local Assigned IP : %s\n", WiFi.localIP().toString().c_str());
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
  // 1. Plug & Play Wi-Fi Roaming Watchdog
  if (wifiMulti.run() != WL_CONNECTED) {
    delay(400);
    return;
  }

  // 2. MQTT Client & Telemetry Heartbeat (every 5 seconds)
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
