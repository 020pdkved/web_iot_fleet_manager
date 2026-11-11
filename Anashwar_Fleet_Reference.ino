/*
  =============================================================================
  ANASHWAR TECHNOLOGIES - UNIVERSAL MULTI-PLATFORM FLEET REFERENCE (v4.2)
  Portal URL : https://manage.anashwartech.com
  MQTT Broker: broker.hivemq.com | Port: 1883
  =============================================================================

  ONE SINGLE AUTHORITATIVE REFERENCE FOR ALL PROJECT WORKSPACES & PLATFORMS:
    1. ESP32 Family          (ESP32-WROOM-32, ESP32-S3, ESP32-C3, ESP32-C6)
    2. ESP8266 Family        (NodeMCU, Wemos D1 Mini, ESP-12F)
    3. Raspberry Pi Pico W   (RP2040 / Pico 2 W RP2350 - Arduino & MicroPython)
    4. Realtek Ameba BW16    (RTL8720DN Dual-Band 2.4GHz / 5GHz)
    5. Raspberry Pi 3 / 4B / Zero 2 W / Linux SBCs (Python 3 Daemon at bottom)

  =============================================================================
  HOW THE "Web UI" BUTTON WORKS GLOBALLY (THROUGH FIREWALLS / HOTSPOT NAT):
  =============================================================================
  When your hardware sits behind a phone hotspot or local Wi-Fi (e.g. 10.73.198.1),
  a cloud server (https://manage.anashwartech.com) CANNOT reach port 80 directly.
  "Direct LAN" works ONLY when your browser is on the same Wi-Fi SSID as the MCU.

  To stream your EXISTING multi-page web UI (steppers, DFPlayer, relays, dials,
  swipes, vibration, /settings, /motors, /audio, etc.) on the Portal "Web UI"
  button from ANYWHERE in the world:
    -> The portal sends HTTP requests over MQTT topic:
         anashwar/proxy/req/<chip_id>
    -> Your firmware forwards that request to localhost:80 (your existing web UI),
       captures the HTML/CSS/JS/JSON response, chunks it as Base64, and publishes
       back on:
         anashwar/proxy/res
    -> The portal rewrites links/fetch/XHR inside an iframe and renders YOUR EXACT
       onboard multi-page web interface globally!

  IF AN EXISTING NODE (e.g. Tree 1) SHOWS ONLY THE FALLBACK STANDBY/REBOOT CARD
  WHEN CLICKING "Web UI":
    Add Step 1B ("FLEET_PROXY_REQ_TOPIC"), Step 2C ("pumpFleetHttpProxy()"),
    and subscribe to "anashwar/proxy/req/" + fleetChipId in reconnectFleetMQTT()!

  =============================================================================
  NVS / PERSISTENT IDENTITY & PORTAL BIDIRECTIONAL RENAME SYNC:
  =============================================================================
  - Your coded defaults (DEFAULT_NODE_NAME, DEFAULT_CLIENT_NAME, DEFAULT_PROJECT_NAME)
    are stored permanently in NVS ("def_node", "def_client", "def_proj").
  - Renaming Client, Project, or Node in https://manage.anashwartech.com pushes
    CMD:[<chip>]:RENAME / SETCLIENT / SETPROJECT and updates NVS ("act_*").
  - Hitting "Reset to Coded Defaults" in your device UI (/settings or POST
    /api/reset_identity) restores "def_*" -> "act_*", increments reset_seq, and
    immediately publishes updated telemetry so the Web Portal reverts automatically!
  =============================================================================
*/

// =============================================================================
// TARGET PLATFORM AUTO-DETECTION & LIBRARIES
// =============================================================================
// Uncomment ONLY if your existing sketch uses ESPAsyncWebServer instead of WebServer:
// #define FLEET_USES_ASYNC_WEBSERVER

#if defined(ESP32)
  #include <WiFi.h>
  #include <WiFiMulti.h>
  #ifndef FLEET_USES_ASYNC_WEBSERVER
    #include <WebServer.h>
  #endif
  #include <HTTPUpdate.h>
  #include <Preferences.h>
  #include <mbedtls/sha256.h>
  #define FLEET_MCU_NAME  "ESP32"
  #define FLEET_MCU_ARCH  "Xtensa/RISC-V Dual-Core"
  #define FLEET_HAS_NVS   1

#elif defined(ESP8266)
  #include <ESP8266WiFi.h>
  #include <ESP8266WiFiMulti.h>
  #ifndef FLEET_USES_ASYNC_WEBSERVER
    #include <ESP8266WebServer.h>
    using WebServer = ESP8266WebServer;
  #endif
  #include <ESP8266httpUpdate.h>
  #include <EEPROM.h>
  #define FLEET_MCU_NAME  "ESP8266"
  #define FLEET_MCU_ARCH  "Tensilica L106 80/160MHz"
  #define FLEET_HAS_EEPROM 1

#elif defined(ARDUINO_ARCH_RP2040)
  // Covers Raspberry Pi Pico W (RP2040) & Raspberry Pi Pico 2 W (RP2350)
  #include <WiFi.h>
  #include <WiFiMulti.h>
  #include <WebServer.h>
  #include <HTTPUpdate.h>
  #include <EEPROM.h>
  #if defined(PICO_RP2350)
    #define FLEET_MCU_NAME "Pico 2 W"
    #define FLEET_MCU_ARCH "Dual Cortex-M33 @ 150MHz"
  #else
    #define FLEET_MCU_NAME "Pico W"
    #define FLEET_MCU_ARCH "Dual Cortex-M0+ @ 133MHz"
  #endif
  #define FLEET_HAS_EEPROM 1

#elif defined(BOARD_RTL8720DN_BW16) || defined(ARDUINO_AMEBA) || defined(CONFIG_PLATFORM_8721D)
  // Covers Realtek Ameba BW16 / RTL8720DN (Dual-Band 2.4GHz + 5GHz)
  #include <WiFi.h>
  #include <WiFiClient.h>
  #include <WiFiServer.h>
  #include <FlashMemory.h>
  #define FLEET_MCU_NAME  "BW16"
  #define FLEET_MCU_ARCH  "ARM Cortex-M33 KM4 @ 200MHz"
  #define FLEET_IS_BW16   1

#else
  #error "Unsupported board selected! Select ESP32, ESP8266, Pico W/2W, or BW16 (or see RPi Python / Pico MicroPython sections below)."
#endif

#include <PubSubClient.h>
#include <vector>

// =============================================================================
// STEP 1: WIFI CREDENTIALS, MQTT CREDENTIALS & CODED IDENTITY DEFAULTS
// =============================================================================
const char* WIFI_SSID_1 = "VED-FI";
const char* WIFI_PASS_1 = "11111111";

const char* WIFI_SSID_2 = "AnashwarTech2";
const char* WIFI_PASS_2 = "At@12345";

const char* FLEET_MQTT_BROKER     = "broker.hivemq.com";
const int   FLEET_MQTT_PORT       = 1883;
const char* FLEET_TOPIC_STATUS    = "anashwar/poc/status";     // Telemetry -> Portal
const char* FLEET_TOPIC_COMMANDS  = "anashwar/poc/commands";   // Commands  <- Portal
const char* FLEET_PROXY_REQ_PREF  = "anashwar/proxy/req/";     // HTTP Req  <- Portal (+ chip_id)
const char* FLEET_PROXY_RES_TOPIC = "anashwar/proxy/res";      // HTTP Res  -> Portal
const char* FLEET_SECURITY_SALT   = "AnashwarEnterprise2026SecureSalt";

// Hardcoded defaults for THIS project firmware (preserved in NVS/Flash for UI Reset)
const char* DEFAULT_NODE_NAME     = "Tree 1";
const char* DEFAULT_CLIENT_NAME   = "Cadbury & Hamley's";
const char* DEFAULT_PROJECT_NAME  = "X'mas Trees";
const char* FLEET_NVS_NS          = "anashwar_id";

// Active runtime identity (loaded from NVS/EEPROM; overwritten by Portal rename)
String fleetNodeName     = DEFAULT_NODE_NAME;
String fleetClientName   = DEFAULT_CLIENT_NAME;
String fleetProjectName  = DEFAULT_PROJECT_NAME;

String   fleetMac            = "";
String   fleetChipId         = "";
String   fleetSecHash        = "";
String   fleetProxyReqTopic  = "";
String   fleetPublicIp       = "";
String   fleetGeoLoc         = "";
String   fleetIsp            = "";
bool     fleetServiceOn      = true;
bool     fleetIdentityCustom = false;
uint32_t fleetResetSeq       = 0;

#if defined(ESP32) || defined(ARDUINO_ARCH_RP2040)
  WiFiMulti fleetWiFiMulti;
#elif defined(ESP8266)
  ESP8266WiFiMulti fleetWiFiMulti;
#endif

WiFiClient   fleetMqttNetClient;
PubSubClient fleetMqtt(fleetMqttNetClient);
unsigned long lastFleetTelemetry = 0;

// Hook to pump synchronous Arduino WebServer during internal loopback proxy calls
// (No-op if you use ESPAsyncWebServer or a custom async loop)
#ifndef FLEET_IS_BW16
  #ifndef FLEET_USES_ASYNC_WEBSERVER
    extern WebServer myExistingWebServer; // Point this to your sketch's WebServer object
    inline void fleetPumpWebServer() { myExistingWebServer.handleClient(); }
  #else
    inline void fleetPumpWebServer() {}
  #endif
#else
  inline void fleetPumpWebServer() {}
#endif

// =============================================================================
// STEP 1B: PORTABLE CRYPTO (SHA-256) & RFC-4648 BASE64 + JSON MINI-PARSER
// Zero external dependencies (works identically on ESP32, ESP8266, Pico, BW16)
// =============================================================================
#if !defined(ESP32)
// Compact standalone SHA-256 for non-ESP32 targets
static void portableSha256(const uint8_t* data, size_t len, uint8_t hash[32]) {
  static const uint32_t k[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
  };
  uint32_t s[8] = {0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
  auto rotr = [](uint32_t x, uint32_t n) { return (x >> n) | (x << (32 - n)); };
  size_t total = ((len + 9 + 63) / 64) * 64;
  std::vector<uint8_t> msg(total, 0);
  if (len) memcpy(msg.data(), data, len);
  msg[len] = 0x80;
  uint64_t bitlen = (uint64_t)len * 8;
  for (int i = 0; i < 8; i++) msg[total - 1 - i] = (bitlen >> (i * 8)) & 0xFF;
  for (size_t off = 0; off < total; off += 64) {
    uint32_t w[64];
    for (int i = 0; i < 16; i++)
      w[i] = ((uint32_t)msg[off+i*4]<<24)|((uint32_t)msg[off+i*4+1]<<16)|((uint32_t)msg[off+i*4+2]<<8)|msg[off+i*4+3];
    for (int i = 16; i < 64; i++) {
      uint32_t s0 = rotr(w[i-15],7) ^ rotr(w[i-15],18) ^ (w[i-15] >> 3);
      uint32_t s1 = rotr(w[i-2],17) ^ rotr(w[i-2],19) ^ (w[i-2] >> 10);
      w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    uint32_t a=s[0],b=s[1],c=s[2],d=s[3],e=s[4],f=s[5],g=s[6],h=s[7];
    for (int i = 0; i < 64; i++) {
      uint32_t S1 = rotr(e,6)^rotr(e,11)^rotr(e,25), ch = (e&f)^((~e)&g), t1 = h+S1+ch+k[i]+w[i];
      uint32_t S0 = rotr(a,2)^rotr(a,13)^rotr(a,22), maj = (a&b)^(a&c)^(b&c), t2 = S0+maj;
      h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    s[0]+=a; s[1]+=b; s[2]+=c; s[3]+=d; s[4]+=e; s[5]+=f; s[6]+=g; s[7]+=h;
  }
  for (int i = 0; i < 8; i++) {
    hash[i*4]=(s[i]>>24)&0xFF; hash[i*4+1]=(s[i]>>16)&0xFF; hash[i*4+2]=(s[i]>>8)&0xFF; hash[i*4+3]=s[i]&0xFF;
  }
}
#endif

String computeFleetSecHash(const String& input) {
  uint8_t hash[32];
#if defined(ESP32)
  mbedtls_sha256_context ctx;
  mbedtls_sha256_init(&ctx);
  mbedtls_sha256_starts(&ctx, 0);
  mbedtls_sha256_update(&ctx, (const unsigned char*)input.c_str(), input.length());
  mbedtls_sha256_finish(&ctx, hash);
  mbedtls_sha256_free(&ctx);
#else
  portableSha256((const uint8_t*)input.c_str(), input.length(), hash);
#endif
  char hexBuf[65];
  for (int i = 0; i < 32; i++) sprintf(&hexBuf[i * 2], "%02x", hash[i]);
  hexBuf[64] = '\0';
  return String(hexBuf);
}

static const char FLEET_B64_TBL[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

String fleetBase64Encode(const uint8_t* data, size_t len) {
  String out;
  out.reserve(((len + 2) / 3) * 4 + 2);
  for (size_t i = 0; i < len; i += 3) {
    uint32_t v = ((uint32_t)data[i]) << 16;
    if (i + 1 < len) v |= ((uint32_t)data[i + 1]) << 8;
    if (i + 2 < len) v |= ((uint32_t)data[i + 2]);
    out += FLEET_B64_TBL[(v >> 18) & 0x3F];
    out += FLEET_B64_TBL[(v >> 12) & 0x3F];
    out += (i + 1 < len) ? FLEET_B64_TBL[(v >> 6) & 0x3F] : '=';
    out += (i + 2 < len) ? FLEET_B64_TBL[v & 0x3F] : '=';
  }
  return out;
}

std::vector<uint8_t> fleetBase64Decode(const String& in) {
  std::vector<uint8_t> out;
  uint32_t val = 0;
  int valb = -8;
  for (unsigned int i = 0; i < in.length(); i++) {
    char c = in[i];
    if (c == '=') break;
    const char* p = strchr(FLEET_B64_TBL, c);
    if (!p) continue;
    val = (val << 6) + (uint32_t)(p - FLEET_B64_TBL);
    valb += 6;
    if (valb >= 0) {
      out.push_back((uint8_t)((val >> valb) & 0xFF));
      valb -= 8;
    }
  }
  return out;
}

String fleetJsonGetStr(const String& json, const char* key) {
  String pat = String("\"") + key + "\":\"";
  int idx = json.indexOf(pat);
  if (idx < 0) return "";
  idx += pat.length();
  String res;
  for (unsigned int i = (unsigned int)idx; i < json.length(); i++) {
    char c = json[i];
    if (c == '\\' && i + 1 < json.length()) {
      res += json[++i];
      continue;
    }
    if (c == '"') break;
    res += c;
  }
  return res;
}

static String jsonEscapeMin(const String& s) {
  String out;
  for (unsigned int i = 0; i < s.length(); i++) {
    char c = s[i];
    if (c == '"' || c == '\\') out += '\\';
    out += c;
  }
  return out;
}

// One-time lightweight WAN geolocation fetch after Wi-Fi connect so the cloud
// portal resolves the node's real ISP/city rather than Render's Oregon server IP.
void fetchFleetPublicGeo() {
  if (WiFi.status() != WL_CONNECTED) return;
  WiFiClient geoClient;
  if (!geoClient.connect("ip-api.com", 80)) return;
  geoClient.print(
    "GET /json/?fields=status,country,regionName,city,isp,query HTTP/1.0\r\n"
    "Host: ip-api.com\r\n"
    "User-Agent: AnashwarFleetNode/4.3\r\n"
    "Connection: close\r\n\r\n"
  );
  unsigned long dl = millis() + 1800;
  String resp;
  while ((long)(dl - millis()) > 0 && (geoClient.connected() || geoClient.available())) {
    while (geoClient.available()) {
      resp += (char)geoClient.read();
    }
    fleetPumpWebServer();
    delay(2);
  }
  geoClient.stop();

  int bodyIdx = resp.indexOf("\r\n\r\n");
  if (bodyIdx < 0) return;
  String j = resp.substring(bodyIdx + 4);
  if (fleetJsonGetStr(j, "status") != "success") return;

  fleetPublicIp = fleetJsonGetStr(j, "query");
  fleetIsp      = fleetJsonGetStr(j, "isp");
  String city   = fleetJsonGetStr(j, "city");
  String reg    = fleetJsonGetStr(j, "regionName");
  String ctry   = fleetJsonGetStr(j, "country");

  fleetGeoLoc = "";
  if (city.length()) fleetGeoLoc += city;
  if (reg.length() && reg != city) {
    if (fleetGeoLoc.length()) fleetGeoLoc += ", ";
    fleetGeoLoc += reg;
  }
  if (ctry.length()) {
    if (fleetGeoLoc.length()) fleetGeoLoc += ", ";
    fleetGeoLoc += ctry;
  }
  Serial.printf("[GEO] Hardware WAN: %s | %s (%s)\n",
                fleetPublicIp.c_str(), fleetGeoLoc.c_str(), fleetIsp.c_str());
}

// =============================================================================
// STEP 2: FLEET TELEMETRY PUBLISHER
// =============================================================================
void publishFleetTelemetry() {
  if (!fleetMqtt.connected()) return;

  char buf[1280];
#if defined(ESP32)
  unsigned int freeHeap = (unsigned int)ESP.getFreeHeap();
  float flashMb = (float)ESP.getFlashChipSize() / (1024.0f * 1024.0f);
  int ramKb = 320;
#elif defined(ESP8266)
  unsigned int freeHeap = (unsigned int)ESP.getFreeHeap();
  float flashMb = (float)ESP.getFlashChipSize() / (1024.0f * 1024.0f);
  int ramKb = 80;
#elif defined(ARDUINO_ARCH_RP2040)
  unsigned int freeHeap = (unsigned int)rp2040.getFreeHeap();
  float flashMb = 2.0f;
  int ramKb = 264;
#else
  unsigned int freeHeap = 200000;
  float flashMb = 4.0f;
  int ramKb = 512;
#endif

  snprintf(buf, sizeof(buf),
    "{\"name\":\"%s\",\"id\":\"Anashwar-%s\",\"mac\":\"%s\",\"chip_id\":\"%s\","
    "\"client\":\"%s\",\"project\":\"%s\",\"sec_hash\":\"%s\",\"mode\":1,"
    "\"service\":%s,\"offline\":false,\"state\":\"%s\",\"ip\":\"%s\","
    "\"pub_ip\":\"%s\",\"geo\":\"%s\",\"isp\":\"%s\","
    "\"rssi\":%d,\"heap\":%u,\"uptime\":%lu,\"delay\":0.0,\"btn\":0,\"led\":%d,"
    "\"identity_custom\":%s,\"reset_seq\":%lu,"
    "\"mcu\":\"%s\",\"arch\":\"%s\",\"flash\":%.1f,"
    "\"ram\":%d,\"antenna\":\"2.4 GHz WiFi\"}",
    jsonEscapeMin(fleetNodeName).c_str(), fleetChipId.c_str(), fleetMac.c_str(), fleetChipId.c_str(),
    jsonEscapeMin(fleetClientName).c_str(), jsonEscapeMin(fleetProjectName).c_str(), fleetSecHash.c_str(),
    fleetServiceOn ? "true" : "false",
    fleetServiceOn ? "online" : "standby",
    WiFi.localIP().toString().c_str(),
    fleetPublicIp.c_str(), jsonEscapeMin(fleetGeoLoc).c_str(), jsonEscapeMin(fleetIsp).c_str(),
    (int)WiFi.RSSI(), freeHeap, (unsigned long)(millis() / 1000),
    fleetServiceOn ? 1 : 0,
    fleetIdentityCustom ? "true" : "false",
    (unsigned long)fleetResetSeq,
    FLEET_MCU_NAME, FLEET_MCU_ARCH, flashMb, ramKb);

  fleetMqtt.publish(FLEET_TOPIC_STATUS, buf, false);
}

// =============================================================================
// STEP 2B: NVS / FLASH IDENTITY PERSISTENCE & FACTORY DEFAULT RESET
// Stores BOTH coded defaults ("def_*") AND portal-renamed active names ("act_*").
// Calling resetFleetIdentityToDefaults() reverts act_* -> def_* and notifies Portal.
// =============================================================================
#if defined(FLEET_HAS_EEPROM)
struct FleetEepromId {
  uint32_t magic;
  uint8_t  custom;
  uint32_t resetSeq;
  char     defSig[96];
  char     defNode[48];
  char     defClient[64];
  char     defProj[64];
  char     actNode[48];
  char     actClient[64];
  char     actProj[64];
};
static const uint32_t FLEET_EEPROM_MAGIC = 0x414E5357UL;
#endif

void loadFleetIdentityFromNVS() {
#if defined(FLEET_HAS_NVS)
  Preferences prefs;
  prefs.begin(FLEET_NVS_NS, false);
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
#elif defined(FLEET_HAS_EEPROM)
  EEPROM.begin(sizeof(FleetEepromId) + 16);
  FleetEepromId data;
  EEPROM.get(0, data);
  String codeSig = String(DEFAULT_NODE_NAME) + "|" + String(DEFAULT_CLIENT_NAME) + "|" + String(DEFAULT_PROJECT_NAME);
  if (data.magic != FLEET_EEPROM_MAGIC) {
    memset(&data, 0, sizeof(data));
    data.magic = FLEET_EEPROM_MAGIC;
    data.custom = 0;
    data.resetSeq = 0;
  }
  if (String(data.defSig) != codeSig) {
    strncpy(data.defSig,    codeSig.c_str(),      sizeof(data.defSig) - 1);
    strncpy(data.defNode,   DEFAULT_NODE_NAME,    sizeof(data.defNode) - 1);
    strncpy(data.defClient, DEFAULT_CLIENT_NAME,  sizeof(data.defClient) - 1);
    strncpy(data.defProj,   DEFAULT_PROJECT_NAME, sizeof(data.defProj) - 1);
    if (!data.custom) {
      strncpy(data.actNode,   DEFAULT_NODE_NAME,    sizeof(data.actNode) - 1);
      strncpy(data.actClient, DEFAULT_CLIENT_NAME,  sizeof(data.actClient) - 1);
      strncpy(data.actProj,   DEFAULT_PROJECT_NAME, sizeof(data.actProj) - 1);
    }
    EEPROM.put(0, data);
    EEPROM.commit();
  }
  fleetNodeName       = String(data.actNode);
  fleetClientName     = String(data.actClient);
  fleetProjectName    = String(data.actProj);
  fleetIdentityCustom = (data.custom != 0);
  fleetResetSeq       = data.resetSeq;
#endif
  Serial.printf("[NVS] Loaded (custom=%d, rst=%lu) -> Client: %s | Project: %s | Node: %s\n",
                fleetIdentityCustom ? 1 : 0, (unsigned long)fleetResetSeq,
                fleetClientName.c_str(), fleetProjectName.c_str(), fleetNodeName.c_str());
}

void saveFleetActiveIdentity(bool customFlag) {
#if defined(FLEET_HAS_NVS)
  Preferences prefs;
  prefs.begin(FLEET_NVS_NS, false);
  prefs.putString("act_node",   fleetNodeName);
  prefs.putString("act_client", fleetClientName);
  prefs.putString("act_proj",   fleetProjectName);
  prefs.putBool("custom_set",   customFlag);
  prefs.end();
#elif defined(FLEET_HAS_EEPROM)
  FleetEepromId data;
  EEPROM.get(0, data);
  data.magic = FLEET_EEPROM_MAGIC;
  data.custom = customFlag ? 1 : 0;
  memset(data.actNode, 0, sizeof(data.actNode));
  memset(data.actClient, 0, sizeof(data.actClient));
  memset(data.actProj, 0, sizeof(data.actProj));
  strncpy(data.actNode,   fleetNodeName.c_str(),    sizeof(data.actNode) - 1);
  strncpy(data.actClient, fleetClientName.c_str(),  sizeof(data.actClient) - 1);
  strncpy(data.actProj,   fleetProjectName.c_str(), sizeof(data.actProj) - 1);
  EEPROM.put(0, data);
  EEPROM.commit();
#endif
  fleetIdentityCustom = customFlag;
}

void resetFleetIdentityToDefaults() {
#if defined(FLEET_HAS_NVS)
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
  fleetNodeName = defN; fleetClientName = defC; fleetProjectName = defP;
  fleetResetSeq = nextSeq;
#elif defined(FLEET_HAS_EEPROM)
  FleetEepromId data;
  EEPROM.get(0, data);
  strncpy(data.actNode,   data.defNode,   sizeof(data.actNode) - 1);
  strncpy(data.actClient, data.defClient, sizeof(data.actClient) - 1);
  strncpy(data.actProj,   data.defProj,   sizeof(data.actProj) - 1);
  data.custom = 0;
  data.resetSeq += 1;
  EEPROM.put(0, data);
  EEPROM.commit();
  fleetNodeName = String(data.actNode);
  fleetClientName = String(data.actClient);
  fleetProjectName = String(data.actProj);
  fleetResetSeq = data.resetSeq;
#else
  fleetNodeName = DEFAULT_NODE_NAME;
  fleetClientName = DEFAULT_CLIENT_NAME;
  fleetProjectName = DEFAULT_PROJECT_NAME;
  fleetResetSeq += 1;
#endif
  fleetIdentityCustom = false;
  Serial.printf("[NVS RESET #%lu] Reverted -> Client: %s | Project: %s | Node: %s\n",
                (unsigned long)fleetResetSeq, fleetClientName.c_str(),
                fleetProjectName.c_str(), fleetNodeName.c_str());
  publishFleetTelemetry();
}

// =============================================================================
// STEP 2C: GLOBAL MQTT HTTP-PROXY RELAY (Non-Blocking Loopback Port 80 Tunnel)
// Lets the Web Portal "Web UI" button display YOUR REAL onboard HTML/CSS/JS
// from anywhere on Earth without port forwarding or VPN!
// =============================================================================
struct FleetHttpProxyJob {
  bool   pending;
  String rid;
  String method;
  String path;
  String ct;
  String b64Body;
} fleetProxyJob = {false, "", "GET", "/", "", ""};

void pumpFleetHttpProxy() {
  if (!fleetProxyJob.pending) return;

  FleetHttpProxyJob job = fleetProxyJob;
  fleetProxyJob.pending = false;

  WiFiClient localHttp;
  if (!localHttp.connect("127.0.0.1", 80)) {
    if (!localHttp.connect(WiFi.localIP(), 80)) {
      String errJson = "{\"rid\":\"" + job.rid + "\",\"i\":0,\"n\":1,\"st\":502,\"err\":\"Local port 80 connect failed\",\"d\":\"\"}";
      fleetMqtt.publish(FLEET_PROXY_RES_TOPIC, errJson.c_str(), false);
      return;
    }
  }

  std::vector<uint8_t> reqBody = job.b64Body.length() ? fleetBase64Decode(job.b64Body) : std::vector<uint8_t>();

  // Send HTTP/1.0 so local WebServer closes connection at end (avoids chunked encoding)
  localHttp.print(job.method);
  localHttp.print(" ");
  localHttp.print(job.path.length() ? job.path : "/");
  localHttp.print(" HTTP/1.0\r\nHost: 127.0.0.1\r\nConnection: close\r\n");
  if (reqBody.size() > 0) {
    localHttp.print("Content-Type: ");
    localHttp.print(job.ct.length() ? job.ct : "application/x-www-form-urlencoded");
    localHttp.print("\r\nContent-Length: ");
    localHttp.print((unsigned int)reqBody.size());
    localHttp.print("\r\n");
  }
  localHttp.print("\r\n");
  if (reqBody.size() > 0) {
    localHttp.write(reqBody.data(), reqBody.size());
  }

  std::vector<uint8_t> rawResp;
  rawResp.reserve(8192);
  uint8_t chunkBuf[512];
  unsigned long deadline = millis() + 3500;

  while ((long)(deadline - millis()) > 0) {
    fleetPumpWebServer(); // CRITICAL: lets synchronous Arduino WebServer serve loopback request!
    fleetMqtt.loop();
    while (localHttp.available()) {
      int r = localHttp.read(chunkBuf, sizeof(chunkBuf));
      if (r > 0) {
        rawResp.insert(rawResp.end(), chunkBuf, chunkBuf + r);
        deadline = millis() + 1200;
      }
    }
    if (!localHttp.connected() && !localHttp.available() && rawResp.size() > 0) {
      break;
    }
    delay(1);
  }
  localHttp.stop();

  if (rawResp.size() == 0) {
    String errJson = "{\"rid\":\"" + job.rid + "\",\"i\":0,\"n\":1,\"st\":504,\"err\":\"Local port 80 timeout\",\"d\":\"\"}";
    fleetMqtt.publish(FLEET_PROXY_RES_TOPIC, errJson.c_str(), false);
    return;
  }

  // Locate "\r\n\r\n" header/body boundary
  size_t hdrEnd = rawResp.size();
  size_t sepLen = 4;
  for (size_t i = 0; i + 3 < rawResp.size(); i++) {
    if (rawResp[i] == '\r' && rawResp[i+1] == '\n' && rawResp[i+2] == '\r' && rawResp[i+3] == '\n') {
      hdrEnd = i; sepLen = 4; break;
    }
    if (rawResp[i] == '\n' && rawResp[i+1] == '\n') {
      hdrEnd = i; sepLen = 2; break;
    }
  }

  String hdrStr;
  hdrStr.reserve(hdrEnd + 1);
  for (size_t i = 0; i < hdrEnd; i++) hdrStr += (char)rawResp[i];

  int statusCode = 200;
  int sp1 = hdrStr.indexOf(' ');
  if (sp1 > 0) {
    int sp2 = hdrStr.indexOf(' ', sp1 + 1);
    statusCode = (sp2 > sp1) ? hdrStr.substring(sp1 + 1, sp2).toInt() : hdrStr.substring(sp1 + 1).toInt();
    if (statusCode <= 0) statusCode = 200;
  }

  String ctype = "text/html; charset=utf-8";
  String locHdr = "";
  int lineStart = hdrStr.indexOf('\n');
  while (lineStart >= 0 && (unsigned int)(lineStart + 1) < hdrStr.length()) {
    int lineEnd = hdrStr.indexOf('\n', lineStart + 1);
    String line = (lineEnd >= 0) ? hdrStr.substring(lineStart + 1, lineEnd) : hdrStr.substring(lineStart + 1);
    line.trim();
    String lower = line;
    lower.toLowerCase();
    if (lower.startsWith("content-type:")) {
      ctype = line.substring(13); ctype.trim();
    } else if (lower.startsWith("location:")) {
      locHdr = line.substring(9); locHdr.trim();
    }
    lineStart = lineEnd;
  }

  size_t bodyStart = (hdrEnd < rawResp.size()) ? (hdrEnd + sepLen) : rawResp.size();
  size_t bodyLen = (bodyStart < rawResp.size()) ? (rawResp.size() - bodyStart) : 0;
  String b64 = bodyLen > 0 ? fleetBase64Encode(rawResp.data() + bodyStart, bodyLen) : "";

  const size_t CHUNK_CHARS = 1800; // Fits well inside PubSubClient 4096-byte buffer
  int totalChunks = (b64.length() == 0) ? 1 : (int)((b64.length() + CHUNK_CHARS - 1) / CHUNK_CHARS);

  for (int i = 0; i < totalChunks; i++) {
    size_t start = (size_t)i * CHUNK_CHARS;
    size_t end = start + CHUNK_CHARS;
    if (end > b64.length()) end = b64.length();
    String slice = (start < b64.length()) ? b64.substring(start, end) : "";

    String msg = "{\"rid\":\"" + job.rid + "\",\"i\":" + String(i) + ",\"n\":" + String(totalChunks);
    if (i == 0) {
      msg += ",\"st\":" + String(statusCode) + ",\"ct\":\"" + jsonEscapeMin(ctype) + "\"";
      if (locHdr.length() > 0) msg += ",\"loc\":\"" + jsonEscapeMin(locHdr) + "\"";
    }
    msg += ",\"d\":\"" + slice + "\"}";
    fleetMqtt.publish(FLEET_PROXY_RES_TOPIC, msg.c_str(), false);
    fleetMqtt.loop();
    delay(2);
  }
}

// =============================================================================
// STEP 3: MQTT DIRECTIVE & PROXY REQUEST HANDLER
// =============================================================================
void onFleetDirective(char* topic, byte* payload, unsigned int length) {
  String topicStr = String(topic);
  String msg;
  msg.reserve(length + 1);
  for (unsigned int i = 0; i < length; i++) msg += (char)payload[i];

  // A. Global Web UI Proxy Tunnel Request (enqueue only; execute cleanly in loop)
  if (topicStr == fleetProxyReqTopic) {
    fleetProxyJob.rid     = fleetJsonGetStr(msg, "rid");
    fleetProxyJob.method  = fleetJsonGetStr(msg, "m");
    fleetProxyJob.path    = fleetJsonGetStr(msg, "p");
    fleetProxyJob.ct      = fleetJsonGetStr(msg, "ct");
    fleetProxyJob.b64Body = fleetJsonGetStr(msg, "b");
    if (fleetProxyJob.rid.length() > 0) {
      fleetProxyJob.pending = true;
    }
    return;
  }

  // B. Standard Fleet Directives
  msg.trim();
  bool targeted = (msg.indexOf("[*]") >= 0)
               || (msg.indexOf("[" + fleetNodeName + "]") >= 0)
               || (msg.indexOf("[" + fleetChipId + "]") >= 0)
               || (msg.indexOf("[" + fleetMac + "]") >= 0);
  if (!targeted) return;

  int sep = msg.indexOf("]:");
  String body = (sep >= 0) ? msg.substring(sep + 2) : msg;
  body.trim();

  if (body.indexOf("PING") >= 0) {
    publishFleetTelemetry();
    return;
  }

  Serial.printf("[FLEET DIRECTIVE] Received: %s\n", body.c_str());

  // Portal <-> Device Identity Sync
  if (body.startsWith("RENAME:")) {
    String v = body.substring(7); v.trim();
    if (v.length() > 0) { fleetNodeName = v; saveFleetActiveIdentity(true); publishFleetTelemetry(); }
    return;
  }
  if (body.startsWith("SETCLIENT:")) {
    String v = body.substring(10); v.trim();
    if (v.length() > 0) { fleetClientName = v; saveFleetActiveIdentity(true); publishFleetTelemetry(); }
    return;
  }
  if (body.startsWith("SETPROJECT:")) {
    String v = body.substring(11); v.trim();
    if (v.length() > 0) { fleetProjectName = v; saveFleetActiveIdentity(true); publishFleetTelemetry(); }
    return;
  }
  if (body.equals("RESET_NAMES") || body.equals("RESET_IDENTITY")) {
    resetFleetIdentityToDefaults();
    return;
  }

  if (body.indexOf("REBOOT") >= 0) {
    delay(200);
#if defined(ESP32) || defined(ESP8266)
    ESP.restart();
#elif defined(ARDUINO_ARCH_RP2040)
    rp2040.reboot();
#endif
    return;
  }
  if (body.indexOf("SERVICE:OFF") >= 0) {
    fleetServiceOn = false;
    // HOOK: Pause steppers / silence DFPlayer / open safety relay here
    publishFleetTelemetry();
    return;
  }
  if (body.indexOf("SERVICE:ON") >= 0) {
    fleetServiceOn = true;
    // HOOK: Resume normal project hardware operation here
    publishFleetTelemetry();
    return;
  }

#if defined(ESP32) || defined(ESP8266) || defined(ARDUINO_ARCH_RP2040)
  if (body.startsWith("OTA:")) {
    int firstCol = body.indexOf(':');
    if (firstCol > 0) {
      String url = body.substring(firstCol + 1); url.trim();
      WiFiClient otaClient;
  #if defined(ESP8266)
      ESPhttpUpdate.update(otaClient, url);
  #else
      httpUpdate.update(otaClient, url);
  #endif
    }
    return;
  }
#endif

  // Custom hardware directives (dispatch from Portal Registry / Terminal)
  if (body.indexOf("STEPPER:MOVE:") >= 0) {
    int steps = body.substring(body.lastIndexOf(':') + 1).toInt();
    Serial.printf("[STEPPER] Moving %d steps...\n", steps);
    publishFleetTelemetry();
  } else if (body.indexOf("AUDIO:PLAY:") >= 0) {
    int track = body.substring(body.lastIndexOf(':') + 1).toInt();
    Serial.printf("[DFPLAYER] Playing track %d...\n", track);
    publishFleetTelemetry();
  } else if (body.indexOf("RELAY:") >= 0) {
    bool on = (body.indexOf(":ON") >= 0);
    Serial.printf("[RELAY] State -> %s\n", on ? "ON" : "OFF");
    publishFleetTelemetry();
  }
}

// =============================================================================
// STEP 4: MQTT CONNECTION & LIFECYCLE
// =============================================================================
void reconnectFleetMQTT() {
  static unsigned long lastMqttRetry = 0;
  if (millis() - lastMqttRetry < 4000) return;
  lastMqttRetry = millis();
  if (WiFi.status() != WL_CONNECTED) return;

  String clientId = "Anashwar-" + fleetChipId;
  if (fleetMqtt.connect(clientId.c_str())) {
    fleetMqtt.subscribe(FLEET_TOPIC_COMMANDS);
    fleetMqtt.subscribe(fleetProxyReqTopic.c_str()); // Subscribe to global HTTP Proxy tunnel!
    Serial.printf("[MQTT] Connected (%s). Subscribed to commands & %s\n",
                  clientId.c_str(), fleetProxyReqTopic.c_str());
    publishFleetTelemetry();
  }
}

void initFleetManager() {
  loadFleetIdentityFromNVS();

#if defined(ESP32)
  uint64_t mac = ESP.getEfuseMac();
  char cBuf[16];
  snprintf(cBuf, sizeof(cBuf), "%04X%08X", (uint16_t)(mac >> 32), (uint32_t)mac);
  fleetChipId = String(cBuf);
#elif defined(ESP8266)
  char cBuf[16];
  snprintf(cBuf, sizeof(cBuf), "%08X", (uint32_t)ESP.getChipId());
  fleetChipId = String(cBuf);
#elif defined(ARDUINO_ARCH_RP2040)
  fleetChipId = String(rp2040.getChipID());
#else
  byte macRaw[6]; WiFi.macAddress(macRaw);
  char cBuf[16];
  snprintf(cBuf, sizeof(cBuf), "%02X%02X%02X%02X%02X%02X",
           macRaw[0], macRaw[1], macRaw[2], macRaw[3], macRaw[4], macRaw[5]);
  fleetChipId = String(cBuf);
#endif

  fleetProxyReqTopic = String(FLEET_PROXY_REQ_PREF) + fleetChipId;

#if defined(FLEET_IS_BW16)
  Serial.println("[WiFi] BW16 trying VED-FI then AnashwarTech2...");
  if (WiFi.begin((char*)WIFI_SSID_1, (char*)WIFI_PASS_1) != WL_CONNECTED) {
    delay(1500);
    WiFi.begin((char*)WIFI_SSID_2, (char*)WIFI_PASS_2);
  }
  while (WiFi.status() != WL_CONNECTED) { delay(300); Serial.print("."); }
#else
  WiFi.mode(WIFI_STA);
  fleetWiFiMulti.addAP(WIFI_SSID_1, WIFI_PASS_1);
  fleetWiFiMulti.addAP(WIFI_SSID_2, WIFI_PASS_2);
  Serial.println("[WiFi] Scanning (VED-FI / AnashwarTech2)...");
  while (fleetWiFiMulti.run() != WL_CONNECTED) { delay(300); Serial.print("."); }
#endif

  fleetMac = WiFi.macAddress();
  fleetSecHash = computeFleetSecHash(fleetMac + fleetChipId + String(FLEET_SECURITY_SALT));
  Serial.printf("\n[WiFi] Connected! IP: %s | Chip ID: %s\n",
                WiFi.localIP().toString().c_str(), fleetChipId.c_str());

  fetchFleetPublicGeo(); // Resolve hardware WAN IP + city/ISP once at boot for cloud portal
  fleetMqtt.setServer(FLEET_MQTT_BROKER, FLEET_MQTT_PORT);
  fleetMqtt.setCallback(onFleetDirective);
  fleetMqtt.setBufferSize(4096); // Required for chunked Web UI HTTP-Proxy payloads!
}

void serviceFleetManager() {
#if !defined(FLEET_IS_BW16)
  if (fleetWiFiMulti.run() != WL_CONNECTED) return;
#else
  if (WiFi.status() != WL_CONNECTED) return;
#endif

  if (!fleetMqtt.connected()) {
    reconnectFleetMQTT();
  } else {
    fleetMqtt.loop();
    pumpFleetHttpProxy(); // Streams local Port-80 Web UI back to Cloud Portal when requested!
    if (millis() - lastFleetTelemetry >= 6000) {
      lastFleetTelemetry = millis();
      publishFleetTelemetry();
    }
  }
}

// =============================================================================
// EXAMPLE EMBEDDED PROJECT WEB UI (MULTI-PAGE, HAPTICS, NVS IDENTITY RESET)
// Your real project web UI (steppers, DFPlayer, WLED, multi-tab controls, etc.)
// lives untouched on Port 80 and is tunneled globally via pumpFleetHttpProxy().
// =============================================================================
#if !defined(FLEET_IS_BW16) && !defined(FLEET_USES_ASYNC_WEBSERVER)
WebServer myExistingWebServer(80);

void setupMyExistingProjectUI() {
  myExistingWebServer.on("/", HTTP_GET, []() {
    String html = "<!DOCTYPE html><html><head><meta charset='utf-8'>";
    html += "<meta name='viewport' content='width=device-width,initial-scale=1'>";
    html += "<title>" + fleetNodeName + " Controller</title>";
    html += "<style>body{background:#0F172A;color:#F8FAFC;font-family:sans-serif;text-align:center;padding:20px;}";
    html += ".card{background:#1E293B;border-radius:16px;padding:22px;max-width:480px;margin:0 auto;}";
    html += ".btn{background:#E11D48;color:#fff;border:none;padding:12px 18px;border-radius:10px;font-weight:700;width:100%;margin:6px 0;cursor:pointer;}";
    html += "a{color:#38BDF8;margin:0 8px;font-size:13px;}</style></head><body>";
    html += "<div class='card'><h2>" + fleetNodeName + " Edge UI</h2>";
    html += "<p style='color:#94A3B8;font-size:12px;'>" + fleetClientName + " / " + fleetProjectName + "</p>";
    html += "<button class='btn' onclick='vibrate();fetch(\"/api/step?n=50\")'>Step Motor (+50)</button>";
    html += "<button class='btn' style='background:#10B981;' onclick='vibrate();fetch(\"/api/sound?track=1\")'>Play Track 1</button>";
    html += "<div style='margin-top:14px;'><a href='/settings'>Identity &amp; NVS Reset &rarr;</a></div>";
    html += "</div><script>function vibrate(){if(navigator.vibrate)navigator.vibrate(35);}</script></body></html>";
    myExistingWebServer.send(200, "text/html", html);
  });

  myExistingWebServer.on("/settings", HTTP_GET, []() {
    String page = "<!DOCTYPE html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>";
    page += "<title>Identity Settings</title><style>body{background:#0F172A;color:#F8FAFC;font-family:sans-serif;padding:24px;}";
    page += ".box{background:#1E293B;padding:20px;border-radius:14px;max-width:480px;margin:0 auto;}";
    page += "button{background:#E11D48;color:#fff;border:none;padding:12px;border-radius:10px;font-weight:700;width:100%;cursor:pointer;}a{color:#38BDF8;}</style></head><body>";
    page += "<div class='box'><h2>Device Identity (NVS)</h2>";
    page += "<p>Active: <b>" + fleetClientName + " / " + fleetProjectName + " / " + fleetNodeName + "</b></p>";
    page += "<p>Defaults: <b>" + String(DEFAULT_CLIENT_NAME) + " / " + String(DEFAULT_PROJECT_NAME) + " / " + String(DEFAULT_NODE_NAME) + "</b></p>";
    page += "<button onclick=\"fetch('/api/reset_identity',{method:'POST'}).then(()=>location.reload())\">Reset to Coded Defaults &amp; Sync Portal</button>";
    page += "<p style='margin-top:14px;'><a href='/'>&larr; Dashboard</a></p></div></body></html>";
    myExistingWebServer.send(200, "text/html", page);
  });

  myExistingWebServer.on("/api/reset_identity", HTTP_POST, []() {
    resetFleetIdentityToDefaults();
    myExistingWebServer.send(200, "application/json",
      "{\"status\":\"reset\",\"node\":\"" + fleetNodeName + "\",\"client\":\"" + fleetClientName + "\",\"project\":\"" + fleetProjectName + "\"}");
  });

  myExistingWebServer.on("/api/step", HTTP_GET, []() {
    myExistingWebServer.send(200, "application/json", "{\"status\":\"ok\",\"step\":" + myExistingWebServer.arg("n") + "}");
  });

  myExistingWebServer.on("/api/sound", HTTP_GET, []() {
    myExistingWebServer.send(200, "application/json", "{\"status\":\"ok\",\"track\":" + myExistingWebServer.arg("track") + "}");
  });

  myExistingWebServer.begin();
}
#endif

void setup() {
  Serial.begin(115200);
  initFleetManager();
#if !defined(FLEET_IS_BW16) && !defined(FLEET_USES_ASYNC_WEBSERVER)
  setupMyExistingProjectUI();
#endif
}

void loop() {
  serviceFleetManager();
#if !defined(FLEET_IS_BW16) && !defined(FLEET_USES_ASYNC_WEBSERVER)
  myExistingWebServer.handleClient();
#endif
  delay(2);
}

/*
===============================================================================
RASPBERRY PI 3 / PI 4B / ZERO 2 W / LINUX SBC AGENT (Python 3 Standalone)
===============================================================================
Run alongside any local web app on the Raspberry Pi (Flask/FastAPI/Node-RED/Nginx
listening on LOCAL_WEB_PORT e.g. 80 or 8080):
  pip3 install paho-mqtt requests
  python3 anashwar_rpi_agent.py

#if 0
import base64, hashlib, json, math, os, socket, subprocess, threading, time, uuid
import paho.mqtt.client as mqtt
import requests

BROKER         = "broker.hivemq.com"
PORT           = 1883
TOPIC_STATUS   = "anashwar/poc/status"
TOPIC_COMMANDS = "anashwar/poc/commands"
PROXY_RES      = "anashwar/proxy/res"
SALT           = "AnashwarEnterprise2026SecureSalt"

STATE_FILE     = os.path.expanduser("~/.anashwar_rpi_identity.json")
LOCAL_WEB_PORT = int(os.environ.get("ANASHWAR_LOCAL_WEB_PORT", "80"))

DEFAULT_NODE    = os.environ.get("ANASHWAR_NODE",    socket.gethostname())
DEFAULT_CLIENT  = os.environ.get("ANASHWAR_CLIENT",  "Cadbury & Hamley's")
DEFAULT_PROJECT = os.environ.get("ANASHWAR_PROJECT", "Connected Edge Fleet")

def get_mac():
    n = uuid.getnode()
    return ":".join(f"{(n >> (8*i)) & 0xff:02X}" for i in range(5, -1, -1))

MAC = get_mac()
CHIP_ID = MAC.replace(":", "")
SEC_HASH = hashlib.sha256((MAC + CHIP_ID + SALT).encode()).hexdigest()
PROXY_REQ = f"anashwar/proxy/req/{CHIP_ID}"

def load_id():
    if os.path.isfile(STATE_FILE):
        with open(STATE_FILE) as f:
            return json.load(f)
    st = {"node": DEFAULT_NODE, "client": DEFAULT_CLIENT, "project": DEFAULT_PROJECT, "custom": False, "rst": 0}
    with open(STATE_FILE, "w") as f:
        json.dump(st, f)
    return st

identity = load_id()
service_on = True

def resolve_wan_geo():
    try:
        r = requests.get("http://ip-api.com/json/?fields=status,country,regionName,city,isp,query", timeout=3).json()
        if r.get("status") == "success":
            parts = [p for p in [r.get("city", ""), r.get("regionName", ""), r.get("country", "")] if p]
            return {"pub_ip": r.get("query", ""), "geo": ", ".join(parts), "isp": r.get("isp", "")}
    except Exception:
        pass
    return {"pub_ip": "", "geo": "", "isp": ""}

WAN_GEO = resolve_wan_geo()

def save_id():
    with open(STATE_FILE, "w") as f:
        json.dump(identity, f)

def publish_telemetry(client):
    ip = socket.gethostbyname(socket.gethostname())
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80)); ip = s.getsockname()[0]; s.close()
    except Exception:
        pass
    payload = {
        "name": identity["node"], "id": f"Anashwar-{CHIP_ID}", "mac": MAC, "chip_id": CHIP_ID,
        "client": identity["client"], "project": identity["project"], "sec_hash": SEC_HASH,
        "mode": 1, "service": service_on, "offline": False,
        "state": "online" if service_on else "standby", "ip": ip,
        "pub_ip": WAN_GEO["pub_ip"], "geo": WAN_GEO["geo"], "isp": WAN_GEO["isp"],
        "rssi": -42, "heap": 512000, "uptime": int(time.monotonic()), "mcu": "RaspberryPi",
        "arch": "ARMv8 Cortex-A72 Linux", "flash": 32.0, "ram": 4096,
        "identity_custom": identity["custom"], "reset_seq": identity["rst"]
    }
    client.publish(TOPIC_STATUS, json.dumps(payload))

def handle_proxy(client, req):
    rid = req.get("rid", "")
    method = req.get("m", "GET")
    path = req.get("p", "/")
    body = base64.b64decode(req["b"]) if req.get("b") else None
    hdrs = {"Content-Type": req["ct"]} if req.get("ct") else {}
    try:
        r = requests.request(method, f"http://127.0.0.1:{LOCAL_WEB_PORT}{path}", data=body, headers=hdrs, timeout=4, allow_redirects=False)
        b64 = base64.b64encode(r.content).decode("ascii")
        n = max(1, math.ceil(len(b64) / 2400))
        for i in range(n):
            pkt = {"rid": rid, "i": i, "n": n, "d": b64[i*2400:(i+1)*2400]}
            if i == 0:
                pkt["st"] = r.status_code
                pkt["ct"] = r.headers.get("Content-Type", "text/html")
                if "Location" in r.headers:
                    pkt["loc"] = r.headers["Location"]
            client.publish(PROXY_RES, json.dumps(pkt))
    except Exception as e:
        client.publish(PROXY_RES, json.dumps({"rid": rid, "i": 0, "n": 1, "st": 502, "err": str(e), "d": ""}))

def on_connect(c, u, fl, rc):
    c.subscribe(TOPIC_COMMANDS)
    c.subscribe(PROXY_REQ)
    publish_telemetry(c)

def on_message(c, u, msg):
    if msg.topic == PROXY_REQ:
        threading.Thread(target=handle_proxy, args=(c, json.loads(msg.payload)), daemon=True).start()
        return
    txt = msg.payload.decode(errors="ignore").strip()
    if not any(t in txt for t in ("[*]", f"[{identity['node']}]", f"[{CHIP_ID}]", f"[{MAC}]")):
        return
    body = txt.split("]:", 1)[1].strip() if "]:" in txt else txt
    if "PING" in body:
        publish_telemetry(c)
    elif body.startswith("RENAME:"):
        identity["node"] = body[7:].strip(); identity["custom"] = True; save_id(); publish_telemetry(c)
    elif body.startswith("SETCLIENT:"):
        identity["client"] = body[10:].strip(); identity["custom"] = True; save_id(); publish_telemetry(c)
    elif body.startswith("SETPROJECT:"):
        identity["project"] = body[11:].strip(); identity["custom"] = True; save_id(); publish_telemetry(c)
    elif body in ("RESET_NAMES", "RESET_IDENTITY"):
        identity.update({"node": DEFAULT_NODE, "client": DEFAULT_CLIENT, "project": DEFAULT_PROJECT, "custom": False, "rst": identity["rst"] + 1})
        save_id(); publish_telemetry(c)
    elif "REBOOT" in body:
        subprocess.Popen(["sudo", "reboot"])

cli = mqtt.Client(client_id=f"Anashwar-{CHIP_ID}")
cli.on_connect = on_connect
cli.on_message = on_message
cli.connect(BROKER, PORT, 60)
cli.loop_start()
while True:
    publish_telemetry(cli)
    time.sleep(6)
#endif
===============================================================================
*/

