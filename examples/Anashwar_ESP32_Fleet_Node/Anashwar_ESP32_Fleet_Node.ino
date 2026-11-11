/*
  =============================================================================
  Anashwar Technologies - Universal Fleet Integration Adapter
  =============================================================================
  INTEGRATION REFERENCE FOR EXISTING ESP32 CODEBASES
  (Stepper Motors, DFPlayer Mini, Relays, Multi-Page Web UIs, Gestures & Haptics)
  
  HOW TO USE THIS REFERENCE IN YOUR EXISTING PROJECT:
  -----------------------------------------------------------------------------
  You do NOT need to rewrite your code! Your existing hardware drivers, 
  stepper loops, DFPlayer sound triggers, and complex multi-page web UIs 
  (with sliders, swipe gestures, phone vibration, dials, and custom CSS/JS) 
  remain 100% UNTOUCHED.
  
  You only need to add 3 lightweight integration hooks:
    1. INCLUDES & FLEET IDENTITY (At the top of your file)
    2. initFleetManager()        (Call once at the bottom of your setup())
    3. serviceFleetManager()     (Call once in your loop())
    4. onFleetDirective()        (Hook your motor/audio/relay calls here!)
  
  Portal URL: https://manage.anashwartech.com
  =============================================================================
*/

#include <WiFi.h>
#include <WiFiMulti.h>       // Built-in ESP32 Multi-AP roaming
#include <PubSubClient.h>    // Standard MQTT library
#include <WebServer.h>       // Or use ESPAsyncWebServer if your project uses it
#include <HTTPUpdate.h>      // Built-in ESP32 remote OTA updater
#include <Preferences.h>     // Built-in ESP32 NVS persistent storage
#include <mbedtls/sha256.h>  // Built-in cryptographic SHA-256

// =============================================================================
// STEP 1: FLEET IDENTITY & NETWORK CONFIGURATION
// (Paste this near the top of your existing sketch)
// =============================================================================

// Wi-Fi Profiles (The ESP32 will auto-scan and connect to whichever is in range)
const char* WIFI_SSID_1 = "VED-FI";
const char* WIFI_PASS_1 = "11111111";

const char* WIFI_SSID_2 = "AnashwarTech2";
const char* WIFI_PASS_2 = "At@12345";

// HiveMQ Public Cloud MQTT Mesh
const char* FLEET_MQTT_BROKER    = "broker.hivemq.com";
const int   FLEET_MQTT_PORT      = 1883;
const char* FLEET_TOPIC_STATUS   = "anashwar/poc/status";    // Node -> Portal Telemetry
const char* FLEET_TOPIC_COMMANDS = "anashwar/poc/commands";  // Portal -> Node Directives
const char* FLEET_SECURITY_SALT  = "AnashwarEnterprise2026SecureSalt";

// Original coded defaults for this project (persisted into NVS on first boot
// or whenever firmware defaults change; ESP32 UI Reset reverts to these values)
const char* DEFAULT_NODE_NAME    = "Tree 1";
const char* DEFAULT_CLIENT_NAME  = "Hamley's x Cadbury";
const char* DEFAULT_PROJECT_NAME = "Connected Edge Fleet";
const char* FLEET_NVS_NS         = "anashwar_id";

// Active fleet identity (loaded from NVS at boot; updated when renamed from Portal)
String fleetNodeName    = DEFAULT_NODE_NAME;
String fleetClientName  = DEFAULT_CLIENT_NAME;
String fleetProjectName = DEFAULT_PROJECT_NAME;

// System State Tracking
String fleetMac            = "";
String fleetChipId         = "";
String fleetSecHash        = "";
bool   fleetServiceOn      = true;   // Master enable/disable flag
bool   fleetIdentityCustom = false;  // True if renamed from Web Portal
uint32_t fleetResetSeq     = 0;      // Incremented each time ESP32 resets names to defaults

WiFiMulti    fleetWiFiMulti;
WiFiClient   fleetMqttNetClient;
PubSubClient fleetMqtt(fleetMqttNetClient);
unsigned long lastFleetTelemetry = 0;

// =============================================================================
// STEP 2: CRYPTOGRAPHIC 4-POINT ATTESTATION (Zero-Touch Security)
// =============================================================================
String computeFleetSecHash(const String& input) {
  byte hash[32];
  mbedtls_sha256_context ctx;
  mbedtls_sha256_init(&ctx);
  mbedtls_sha256_starts(&ctx, 0); // 0 = SHA-256
  mbedtls_sha256_update(&ctx, (const unsigned char*)input.c_str(), input.length());
  mbedtls_sha256_finish(&ctx, hash);
  mbedtls_sha256_free(&ctx);

  char hexBuf[65];
  for (int i = 0; i < 32; i++) sprintf(&hexBuf[i * 2], "%02x", hash[i]);
  hexBuf[64] = '\0';
  return String(hexBuf);
}

void publishFleetTelemetry() {
  if (!fleetMqtt.connected()) return;

  char buf[1024];
  snprintf(buf, sizeof(buf),
    "{\"name\":\"%s\",\"id\":\"Anashwar-%s\",\"mac\":\"%s\",\"chip_id\":\"%s\","
    "\"client\":\"%s\",\"project\":\"%s\",\"sec_hash\":\"%s\",\"mode\":1,"
    "\"service\":%s,\"offline\":false,\"state\":\"%s\",\"ip\":\"%s\","
    "\"rssi\":%d,\"heap\":%u,\"uptime\":%lu,\"delay\":0.0,\"btn\":0,\"led\":%d,"
    "\"identity_custom\":%s,\"reset_seq\":%lu,"
    "\"mcu\":\"ESP32\",\"arch\":\"Xtensa LX6 Dual-Core @ 240MHz\",\"flash\":4.0,"
    "\"ram\":320,\"antenna\":\"2.4 GHz 802.11 b/g/n\"}",
    fleetNodeName.c_str(), fleetChipId.c_str(), fleetMac.c_str(), fleetChipId.c_str(),
    fleetClientName.c_str(), fleetProjectName.c_str(), fleetSecHash.c_str(),
    fleetServiceOn ? "true" : "false",
    fleetServiceOn ? "online" : "standby",
    WiFi.localIP().toString().c_str(), WiFi.RSSI(),
    (unsigned int)ESP.getFreeHeap(), millis() / 1000,
    fleetServiceOn ? 1 : 0,
    fleetIdentityCustom ? "true" : "false",
    (unsigned long)fleetResetSeq);

  fleetMqtt.publish(FLEET_TOPIC_STATUS, buf, false);
}

// =============================================================================
// STEP 2B: NVS IDENTITY PERSISTENCE & FACTORY RESET HELPERS
// Keeps original coded names in NVS alongside active portal-renamed names.
// =============================================================================
void loadFleetIdentityFromNVS() {
  Preferences prefs;
  prefs.begin(FLEET_NVS_NS, false);

  // Detect if firmware was freshly coded with new hardcoded defaults
  String codeSig = String(DEFAULT_NODE_NAME) + "|" + String(DEFAULT_CLIENT_NAME) + "|" + String(DEFAULT_PROJECT_NAME);
  String savedSig = prefs.getString("def_sig", "");

  if (savedSig != codeSig || !prefs.isKey("def_node")) {
    prefs.putString("def_node",   DEFAULT_NODE_NAME);
    prefs.putString("def_client", DEFAULT_CLIENT_NAME);
    prefs.putString("def_proj",   DEFAULT_PROJECT_NAME);
    prefs.putString("def_sig",    codeSig);
    if (!prefs.getBool("custom_set", false)) {
      prefs.putString("act_node",   DEFAULT_NODE_NAME);
      prefs.putString("act_client", DEFAULT_CLIENT_NAME);
      prefs.putString("act_proj",   DEFAULT_PROJECT_NAME);
    }
  }

  fleetNodeName       = prefs.getString("act_node",   DEFAULT_NODE_NAME);
  fleetClientName     = prefs.getString("act_client", DEFAULT_CLIENT_NAME);
  fleetProjectName    = prefs.getString("act_proj",   DEFAULT_PROJECT_NAME);
  fleetIdentityCustom = prefs.getBool("custom_set",   false);
  fleetResetSeq       = prefs.getUInt("rst_seq",      0);
  prefs.end();

  Serial.printf("[NVS] Identity loaded (custom=%d, rst_seq=%lu) -> Client: %s | Project: %s | Node: %s\n",
                fleetIdentityCustom ? 1 : 0, (unsigned long)fleetResetSeq,
                fleetClientName.c_str(), fleetProjectName.c_str(), fleetNodeName.c_str());
}

void saveFleetActiveIdentity(bool customFlag) {
  Preferences prefs;
  prefs.begin(FLEET_NVS_NS, false);
  prefs.putString("act_node",   fleetNodeName);
  prefs.putString("act_client", fleetClientName);
  prefs.putString("act_proj",   fleetProjectName);
  prefs.putBool("custom_set",   customFlag);
  prefs.end();
  fleetIdentityCustom = customFlag;
}

void resetFleetIdentityToDefaults() {
  Preferences prefs;
  prefs.begin(FLEET_NVS_NS, false);
  String defN = prefs.getString("def_node",   DEFAULT_NODE_NAME);
  String defC = prefs.getString("def_client", DEFAULT_CLIENT_NAME);
  String defP = prefs.getString("def_proj",   DEFAULT_PROJECT_NAME);
  uint32_t nextSeq = prefs.getUInt("rst_seq", 0) + 1;
  prefs.putString("act_node",   defN);
  prefs.putString("act_client", defC);
  prefs.putString("act_proj",   defP);
  prefs.putBool("custom_set",   false);
  prefs.putUInt("rst_seq",      nextSeq);
  prefs.end();

  fleetNodeName       = defN;
  fleetClientName     = defC;
  fleetProjectName    = defP;
  fleetIdentityCustom = false;
  fleetResetSeq       = nextSeq;

  Serial.printf("[NVS RESET #%lu] Reverted to coded defaults -> Client: %s | Project: %s | Node: %s\n",
                (unsigned long)fleetResetSeq, fleetClientName.c_str(), fleetProjectName.c_str(), fleetNodeName.c_str());

  // Immediately publish reverted names so the Web Portal syncs right away
  publishFleetTelemetry();
}

// =============================================================================
// STEP 3: DIRECTIVE HANDLER (Hook your Steppers, DFPlayer, Relays here!)
// =============================================================================
void onFleetDirective(char* topic, byte* payload, unsigned int length) {
  char msgBuf[length + 1];
  memcpy(msgBuf, payload, length);
  msgBuf[length] = '\0';
  String cmd = String(msgBuf);
  cmd.trim();

  // Verify target: broadcast [*], specific [fleetNodeName], [fleetChipId], or [fleetMac]
  bool targeted = (cmd.indexOf("[*]") >= 0)
               || (cmd.indexOf("[" + fleetNodeName + "]") >= 0)
               || (cmd.indexOf("[" + fleetChipId + "]") >= 0)
               || (cmd.indexOf("[" + fleetMac + "]") >= 0);
  if (!targeted) return;

  // Extract directive body after "]:" (e.g. CMD:[Tree 1]:RENAME:NewName -> RENAME:NewName)
  int sep = cmd.indexOf("]:");
  String body = (sep >= 0) ? cmd.substring(sep + 2) : cmd;
  body.trim();

  if (body.indexOf("PING") >= 0) {
    publishFleetTelemetry(); // Silent instant presence ACK to portal
    return;
  }

  Serial.printf("[FLEET DIRECTIVE] Received: %s\n", body.c_str());

  // ---------------------------------------------------------------------------
  // 1. PORTAL <-> ESP32 BIDIRECTIONAL IDENTITY SYNC (Persisted to NVS)
  // ---------------------------------------------------------------------------
  if (body.startsWith("RENAME:")) {
    String newName = body.substring(7);
    newName.trim();
    if (newName.length() > 0) {
      fleetNodeName = newName;
      saveFleetActiveIdentity(true);
      Serial.printf("[NVS] Node renamed via Portal -> %s\n", fleetNodeName.c_str());
      publishFleetTelemetry();
    }
    return;
  }

  if (body.startsWith("SETCLIENT:")) {
    String newClient = body.substring(10);
    newClient.trim();
    if (newClient.length() > 0) {
      fleetClientName = newClient;
      saveFleetActiveIdentity(true);
      Serial.printf("[NVS] Client renamed via Portal -> %s\n", fleetClientName.c_str());
      publishFleetTelemetry();
    }
    return;
  }

  if (body.startsWith("SETPROJECT:")) {
    String newProj = body.substring(11);
    newProj.trim();
    if (newProj.length() > 0) {
      fleetProjectName = newProj;
      saveFleetActiveIdentity(true);
      Serial.printf("[NVS] Project renamed via Portal -> %s\n", fleetProjectName.c_str());
      publishFleetTelemetry();
    }
    return;
  }

  if (body.equals("RESET_NAMES") || body.equals("RESET_IDENTITY")) {
    resetFleetIdentityToDefaults();
    return;
  }

  // ---------------------------------------------------------------------------
  // 2. STANDARD FLEET DIRECTIVES (Do not remove)
  // ---------------------------------------------------------------------------
  if (body.indexOf("REBOOT") >= 0) {
    delay(200);
    ESP.restart(); // Remote software restart
    return;
  }

  if (body.indexOf("SERVICE:OFF") >= 0) {
    fleetServiceOn = false;
    // >>> HOOK: Pause your steppers or silence audio here if desired <<<
    publishFleetTelemetry();
    return;
  }

  if (body.indexOf("SERVICE:ON") >= 0) {
    fleetServiceOn = true;
    // >>> HOOK: Resume normal hardware operations here <<<
    publishFleetTelemetry();
    return;
  }

  if (body.startsWith("OTA:")) {
    int firstCol = body.indexOf(':');
    if (firstCol > 0) {
      String url = body.substring(firstCol + 1);
      url.trim();
      WiFiClient otaClient;
      httpUpdate.update(otaClient, url); // Flash new .bin over HTTP
    }
    return;
  }

  // ---------------------------------------------------------------------------
  // 3. PROJECT-SPECIFIC HARDWARE HOOKS (Trigger your custom peripherals!)
  // ---------------------------------------------------------------------------
  // EXAMPLE A: STEPPER MOTOR CONTROL
  // From the portal console, type: STEPPER:MOVE:500 or STEPPER:HOME
  if (body.indexOf("STEPPER:MOVE:") >= 0) {
    int steps = body.substring(body.lastIndexOf(':') + 1).toInt();
    Serial.printf("[STEPPER] Moving %d steps...\n", steps);
    // myStepper.step(steps); // <-- Call your existing stepper function!
    publishFleetTelemetry();
  }
  
  // EXAMPLE B: DFPLAYER MINI MP3 AUDIO TRIGGER
  // From the portal console, type: AUDIO:PLAY:1 or AUDIO:VOLUME:25
  else if (body.indexOf("AUDIO:PLAY:") >= 0) {
    int trackNum = body.substring(body.lastIndexOf(':') + 1).toInt();
    Serial.printf("[DFPLAYER] Playing track #%d...\n", trackNum);
    // myDFPlayer.play(trackNum); // <-- Call your existing audio function!
    publishFleetTelemetry();
  }

  // EXAMPLE C: RELAY OR SOLENOID TRIGGER
  // From the portal console, type: RELAY:1:ON or RELAY:1:OFF
  else if (body.indexOf("RELAY:") >= 0) {
    bool state = (body.indexOf(":ON") >= 0);
    Serial.printf("[RELAY] Switched %s\n", state ? "ON" : "OFF");
    // digitalWrite(MY_RELAY_PIN, state ? HIGH : LOW);
    publishFleetTelemetry();
  }
}

// =============================================================================
// STEP 4: MQTT CONNECTION MANAGEMENT
// =============================================================================
void reconnectFleetMQTT() {
  static unsigned long lastMqttRetry = 0;
  if (millis() - lastMqttRetry < 4000) return;
  lastMqttRetry = millis();

  if (WiFi.status() != WL_CONNECTED) return;

  String clientId = "Anashwar-" + fleetChipId;
  Serial.printf("[MQTT] Connecting to HiveMQ as %s...\n", clientId.c_str());

  if (fleetMqtt.connect(clientId.c_str())) {
    Serial.println("[MQTT] Connected to Fleet Mesh! Subscribed to directives.");
    fleetMqtt.subscribe(FLEET_TOPIC_COMMANDS);
    publishFleetTelemetry();
  }
}

// =============================================================================
// STEP 5: INITIALIZATION FUNCTION (Call this once in your setup())
// =============================================================================
void initFleetManager() {
  // 1. Load coded defaults & portal-synced active identity from NVS
  loadFleetIdentityFromNVS();

  // 2. Read silicon MAC & eFuse chip ID
  uint64_t mac = ESP.getEfuseMac();
  char cBuf[32];
  snprintf(cBuf, sizeof(cBuf), "%04X%08X", (uint16_t)(mac >> 32), (uint32_t)mac);
  fleetChipId = String(cBuf);

  // 3. Configure Multi-AP Plug & Play Wi-Fi Roaming
  WiFi.mode(WIFI_STA);
  fleetWiFiMulti.addAP(WIFI_SSID_1, WIFI_PASS_1);
  fleetWiFiMulti.addAP(WIFI_SSID_2, WIFI_PASS_2);

  Serial.println("\n[WiFi] Scanning for known networks (VED-FI, AnashwarTech2)...");
  while (fleetWiFiMulti.run() != WL_CONNECTED) {
    delay(300);
    Serial.print(".");
  }

  fleetMac = WiFi.macAddress();
  fleetSecHash = computeFleetSecHash(fleetMac + fleetChipId + String(FLEET_SECURITY_SALT));

  Serial.println("\n[WiFi] Connected to SSID: " + WiFi.SSID());
  Serial.printf("[WiFi] Assigned STA IP : %s\n", WiFi.localIP().toString().c_str());
  Serial.printf("[SECURITY] SHA-256 Fingerprint: %s\n", fleetSecHash.c_str());

  // 4. Configure HiveMQ MQTT Mesh Client
  fleetMqtt.setServer(FLEET_MQTT_BROKER, FLEET_MQTT_PORT);
  fleetMqtt.setCallback(onFleetDirective);
  fleetMqtt.setBufferSize(1024);
}

// =============================================================================
// STEP 6: SERVICE LOOP FUNCTION (Call this once in your loop())
// =============================================================================
void serviceFleetManager() {
  // 1. Maintain Wi-Fi Roaming
  if (fleetWiFiMulti.run() != WL_CONNECTED) {
    return;
  }

  // 2. Maintain MQTT & Heartbeat Telemetry (every 6 seconds)
  if (!fleetMqtt.connected()) {
    reconnectFleetMQTT();
  } else {
    fleetMqtt.loop();
    if (millis() - lastFleetTelemetry >= 6000) {
      lastFleetTelemetry = millis();
      publishFleetTelemetry();
    }
  }
}

// =============================================================================
// YOUR EXISTING PROJECT CODEBASE (EXAMPLES: WEBSERVER, STEPPERS, AUDIO)
// This is your actual project code. Keep your complex UI completely as is!
// =============================================================================

WebServer myExistingWebServer(80); // Your existing WebServer (or AsyncWebServer)

void setupMyExistingProjectUI() {
  // ---------------------------------------------------------------------------
  // YOUR EXISTING COMPLEX WEB PAGES (MULTI-PAGE, GESTURES, VIBRATION, DIALS)
  // The Portal's reverse proxy will seamlessly stream ALL your sub-pages!
  // ---------------------------------------------------------------------------
  
  // PAGE 1: Root Dashboard (Dials, Sliders, Buttons)
  myExistingWebServer.on("/", HTTP_GET, []() {
    String html = "<!DOCTYPE html><html><head><meta charset='utf-8'>";
    html += "<meta name='viewport' content='width=device-width,initial-scale=1'>";
    html += "<title>Complex Machine Controller</title>";
    html += "<style>";
    html += "body { background:#0F172A; color:#F8FAFC; font-family:sans-serif; text-align:center; padding:20px; }";
    html += ".card { background:#1E293B; border-radius:18px; padding:24px; max-width:480px; margin:0 auto; box-shadow:0 10px 25px rgba(0,0,0,0.5); }";
    html += ".dial { width:120px; height:120px; border-radius:50%; border:8px solid #38BDF8; margin:16px auto; display:flex; align-items:center; justify-content:center; font-size:24px; font-weight:800; }";
    html += ".btn { background:#E11D48; color:#fff; border:none; padding:14px 20px; border-radius:12px; font-weight:700; width:100%; margin:8px 0; cursor:pointer; }";
    html += ".nav-links a { color:#38BDF8; margin:0 8px; font-size:13px; text-decoration:none; }";
    html += "</style></head><body>";
    html += "<div class='card'>";
    html += "<h2>Stepper & Audio Rig</h2>";
    html += "<div style='font-size:11px;color:#94A3B8;margin-bottom:8px;'>";
    html += "Active: <b>" + fleetClientName + "</b> / <b>" + fleetProjectName + "</b> / <b>" + fleetNodeName + "</b>";
    html += "</div>";
    html += "<div class='dial' id='pos-dial'>500</div>";
    html += "<p style='color:#94A3B8; font-size:12px;'>Swipe, dial & touch enabled interface</p>";
    html += "<button class='btn' onclick='vibratePhone(); sendStep(50)'>Step Motor Forward (+50)</button>";
    html += "<button class='btn' style='background:#10B981;' onclick='vibratePhone(); playSound(1)'>Play Audio Track 1</button>";
    html += "<button class='btn' style='background:#475569;' onclick='vibratePhone(); resetIdentity()'>Reset Names to Coded Defaults (NVS)</button>";
    html += "<div class='nav-links' style='margin-top:16px;'>";
    html += "<a href='/motors'>Motor Config &rarr;</a>";
    html += "<a href='/audio'>Audio Playlist &rarr;</a>";
    html += "<a href='/settings'>Identity & Calibration &rarr;</a>";
    html += "</div></div>";
    
    // Client-side phone haptic feedback and API calls
    html += "<script>";
    html += "function vibratePhone() { if(navigator.vibrate) navigator.vibrate(40); }";
    html += "function sendStep(n) { fetch('/api/step?n='+n); }";
    html += "function playSound(t) { fetch('/api/sound?track='+t); }";
    html += "function resetIdentity() { if(confirm('Revert Client/Project/Node names back to NVS coded defaults and sync with Portal?')) { fetch('/api/reset_identity', {method:'POST'}).then(r=>r.json()).then(()=>{ location.reload(); }); } }";
    html += "</script>";
    html += "</body></html>";
    myExistingWebServer.send(200, "text/html", html);
  });

  // PAGE 2: Stepper Calibration Page (/motors)
  myExistingWebServer.on("/motors", HTTP_GET, []() {
    myExistingWebServer.send(200, "text/html", "<h1>Stepper Motors Page</h1><p><a href='/'>&larr; Back to Main</a></p>");
  });

  // PAGE 3: Audio Playlist Page (/audio)
  myExistingWebServer.on("/audio", HTTP_GET, []() {
    myExistingWebServer.send(200, "text/html", "<h1>DFPlayer Audio Page</h1><p><a href='/'>&larr; Back to Main</a></p>");
  });

  // PAGE 4: Identity & Calibration Page (/settings) showing active vs NVS defaults
  myExistingWebServer.on("/settings", HTTP_GET, []() {
    Preferences prefs;
    prefs.begin(FLEET_NVS_NS, true);
    String defC = prefs.getString("def_client", DEFAULT_CLIENT_NAME);
    String defP = prefs.getString("def_proj",   DEFAULT_PROJECT_NAME);
    String defN = prefs.getString("def_node",   DEFAULT_NODE_NAME);
    prefs.end();

    String page = "<!DOCTYPE html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>";
    page += "<title>Node Identity & Calibration</title>";
    page += "<style>body{background:#0F172A;color:#F8FAFC;font-family:sans-serif;padding:24px;}.box{background:#1E293B;padding:20px;border-radius:14px;max-width:480px;margin:0 auto;}";
    page += "button{background:#E11D48;color:#fff;border:none;padding:12px 18px;border-radius:10px;font-weight:700;cursor:pointer;width:100%;margin-top:12px;}a{color:#38BDF8;}</style></head><body>";
    page += "<div class='box'><h2>Device Identity (NVS)</h2>";
    page += "<p><b>Active (Portal Synced):</b><br>" + fleetClientName + " / " + fleetProjectName + " / " + fleetNodeName + "</p>";
    page += "<p><b>Stored Coded Defaults (NVS):</b><br>" + defC + " / " + defP + " / " + defN + "</p>";
    page += "<button onclick=\"fetch('/api/reset_identity',{method:'POST'}).then(()=>location.reload())\">Reset to Coded Defaults & Sync Portal</button>";
    page += "<p style='margin-top:16px;'><a href='/'>&larr; Back to Dashboard</a></p></div></body></html>";
    myExistingWebServer.send(200, "text/html", page);
  });

  // ACTION API: Reset active NVS identity back to coded defaults and notify Portal
  myExistingWebServer.on("/api/reset_identity", HTTP_POST, []() {
    resetFleetIdentityToDefaults();
    myExistingWebServer.send(200, "application/json",
      "{\"status\":\"reset\",\"node\":\"" + fleetNodeName + "\",\"client\":\"" + fleetClientName + "\",\"project\":\"" + fleetProjectName + "\"}");
  });
  myExistingWebServer.on("/api/reset_identity", HTTP_GET, []() {
    resetFleetIdentityToDefaults();
    myExistingWebServer.send(200, "application/json",
      "{\"status\":\"reset\",\"node\":\"" + fleetNodeName + "\",\"client\":\"" + fleetClientName + "\",\"project\":\"" + fleetProjectName + "\"}");
  });

  // ACTION API: Step motor
  myExistingWebServer.on("/api/step", HTTP_GET, []() {
    int n = myExistingWebServer.arg("n").toInt();
    Serial.printf("[STEPPER] Stepping %d from web UI...\n", n);
    myExistingWebServer.send(200, "application/json", "{\"status\":\"ok\"}");
  });

  // ACTION API: Play sound
  myExistingWebServer.on("/api/sound", HTTP_GET, []() {
    int t = myExistingWebServer.arg("track").toInt();
    Serial.printf("[AUDIO] Triggering track %d from web UI...\n", t);
    myExistingWebServer.send(200, "application/json", "{\"status\":\"ok\"}");
  });

  myExistingWebServer.begin();
  Serial.println("[HTTP] Your existing multi-page web server is live on Port 80.");
}

// =============================================================================
// MAIN ARDUINO SETUP & LOOP (Just see how simple it is to attach!)
// =============================================================================

void setup() {
  Serial.begin(115200);

  // 1. Initialize your existing hardware (steppers, audio, relays, pins)
  // myStepper.init();
  // myDFPlayer.begin(Serial2);
  // pinMode(RELAY_PIN, OUTPUT);

  // 2. ATTACH TO FLEET MANAGEMENT (Single call!)
  initFleetManager();

  // 3. Start your existing complex web server (or leave as you already have it)
  setupMyExistingProjectUI();
}

void loop() {
  // 1. KEEP FLEET TELEMETRY & DIRECTIVES RUNNING IN BACKGROUND (Single call!)
  serviceFleetManager();

  // 2. Handle your existing web server requests
  myExistingWebServer.handleClient();

  // 3. Run your existing non-blocking hardware tasks
  // myStepper.run();
  // updateSensors();

  delay(2);
}
