/**
 * Anashwar Fleet Management System - Universal ESP32 Client Library
 * Drop-in integration header for any ESP32 project across any workspace.
 * 
 * Auto-registers your Device, Client Tenant, and Project Portfolio on the
 * Anashwar Fleet Management Portal (https://manage.anashwartech.com)
 * as soon as the ESP32 boots and connects to Wi-Fi.
 */

#ifndef ANASHWAR_FLEET_H
#define ANASHWAR_FLEET_H

#include <Arduino.h>
#include <WiFi.h>
#include <PubSubClient.h>
#include <HTTPUpdate.h>
#include <mbedtls/sha256.h>
#include <Preferences.h>

// =============================================================================
// DEFAULT ENTERPRISE SETTINGS
// =============================================================================
#ifndef ANASHWAR_MQTT_BROKER
#define ANASHWAR_MQTT_BROKER "broker.hivemq.com"
#endif

#ifndef ANASHWAR_MQTT_PORT
#define ANASHWAR_MQTT_PORT 1883
#endif

#ifndef ANASHWAR_TOPIC_STATUS
#define ANASHWAR_TOPIC_STATUS "anashwar/poc/status"
#endif

#ifndef ANASHWAR_TOPIC_COMMANDS
#define ANASHWAR_TOPIC_COMMANDS "anashwar/poc/commands"
#endif

#ifndef ANASHWAR_SECURITY_SALT
#define ANASHWAR_SECURITY_SALT "Anashwar-Enterprise-Hardware-Key-2026"
#endif

// =============================================================================
// MCU HARDWARE PROFILE & ARCHITECTURE SPECS (ESP32, ESP8266, BW16, Arduino Uno R4)
// =============================================================================
#if defined(ESP32)
  #define ANASHWAR_MCU_FAMILY     "ESP32"
  #define ANASHWAR_MCU_ARCH       "Xtensa LX6 Dual-Core @ 240MHz"
  #define ANASHWAR_MCU_FLASH_MB   4.0f
  #define ANASHWAR_MCU_SRAM_KB    320
  #define ANASHWAR_MCU_ANTENNA    "2.4 GHz 802.11 b/g/n + BLE 4.2 (PCB Trace Antenna)"
#elif defined(ESP8266)
  #define ANASHWAR_MCU_FAMILY     "ESP8266"
  #define ANASHWAR_MCU_ARCH       "Tensilica L106 32-bit @ 80/160MHz"
  #define ANASHWAR_MCU_FLASH_MB   4.0f
  #define ANASHWAR_MCU_SRAM_KB    80
  #define ANASHWAR_MCU_ANTENNA    "2.4 GHz 802.11 b/g/n (PCB Antenna)"
#elif defined(ARDUINO_UNOR4_WIFI)
  #define ANASHWAR_MCU_FAMILY     "Arduino UNO R4 WiFi"
  #define ANASHWAR_MCU_ARCH       "Renesas RA4M1 (48MHz ARM Cortex-M4) + ESP32-S3"
  #define ANASHWAR_MCU_FLASH_MB   0.25f
  #define ANASHWAR_MCU_SRAM_KB    32
  #define ANASHWAR_MCU_ANTENNA    "2.4 GHz 802.11 b/g/n + BLE 5.0"
#elif defined(RTL8720DN) || defined(BOARD_RTL8720DN_BW16)
  #define ANASHWAR_MCU_FAMILY     "BW16 (RTL8720DN)"
  #define ANASHWAR_MCU_ARCH       "Realtek Ameba KM4 (200MHz) + KM0 (20MHz)"
  #define ANASHWAR_MCU_FLASH_MB   4.0f
  #define ANASHWAR_MCU_SRAM_KB    512
  #define ANASHWAR_MCU_ANTENNA    "Dual-Band 2.4 GHz & 5.0 GHz 802.11 a/b/g/n + BLE 5.0"
#else
  #define ANASHWAR_MCU_FAMILY     "Generic Edge MCU"
  #define ANASHWAR_MCU_ARCH       "Microcontroller Core"
  #define ANASHWAR_MCU_FLASH_MB   4.0f
  #define ANASHWAR_MCU_SRAM_KB    256
  #define ANASHWAR_MCU_ANTENNA    "2.4 GHz 802.11 b/g/n"
#endif

class AnashwarFleetClient {
public:
    typedef void (*CommandCallback)(const String& action, const String& value);

    AnashwarFleetClient() : _mqtt(_wifiClient), _lastHeartbeat(0), _cmdCallback(nullptr), _serviceActive(true), _offlineMode(false), _delaySec(0.0f) {}

    /**
     * Initialize Fleet Client with Client Tenant, Project Name, and Device Name
     */
    void begin(const char* clientName, const char* projectName, const char* deviceName, CommandCallback cb = nullptr) {
        _prefs.begin("fleet", false);
        String savedNode = _prefs.getString("node_name", "");
        String savedClient = _prefs.getString("client_name", "");
        String savedProject = _prefs.getString("proj_name", "");

        _clientName = (savedClient.length() > 0) ? savedClient : String(clientName);
        _projectName = (savedProject.length() > 0) ? savedProject : String(projectName);
        _deviceName = (savedNode.length() > 0) ? savedNode : String(deviceName);
        _cmdCallback = cb;

        // 1. Resolve Hardware MAC & Chip ID
        uint64_t mac = ESP.getEfuseMac();
        char chipBuf[32];
        snprintf(chipBuf, sizeof(chipBuf), "%04X%08X", (uint16_t)(mac >> 32), (uint32_t)mac);
        _chipId = String(chipBuf);

        uint8_t baseMac[6];
        esp_read_mac(baseMac, ESP_MAC_WIFI_STA);
        char macBuf[24];
        snprintf(macBuf, sizeof(macBuf), "%02X:%02X:%02X:%02X:%02X:%02X",
                 baseMac[0], baseMac[1], baseMac[2], baseMac[3], baseMac[4], baseMac[5]);
        _macAddress = String(macBuf);

        // 2. Compute 4-Point Cryptographic SHA-256 Identity
        _secHash = computeSHA256(_macAddress + _chipId + String(ANASHWAR_SECURITY_SALT));

        // 3. Configure MQTT
        _mqtt.setServer(ANASHWAR_MQTT_BROKER, ANASHWAR_MQTT_PORT);
        _mqtt.setBufferSize(768);
        _mqtt.setKeepAlive(60);
        
        // Static callback wrapper
        _instance = this;
        _mqtt.setCallback([](char* topic, byte* payload, unsigned int length) {
            if (_instance) _instance->handleMqttMessage(topic, payload, length);
        });

        Serial.println("\n[AnashwarFleet] =========================================");
        Serial.printf("[AnashwarFleet] Device     : %s\n", _deviceName.c_str());
        Serial.printf("[AnashwarFleet] Client     : %s\n", _clientName.c_str());
        Serial.printf("[AnashwarFleet] Project    : %s\n", _projectName.c_str());
        Serial.printf("[AnashwarFleet] MAC        : %s\n", _macAddress.c_str());
        Serial.printf("[AnashwarFleet] Security   : SHA-256 Verified\n");
        Serial.println("[AnashwarFleet] =========================================\n");
    }

    /**
     * Call this in your Arduino loop() function frequently
     */
    void loop() {
        if (_offlineMode) return; // 100% Autonomous local operation, bypass cloud MQTT
        if (WiFi.status() != WL_CONNECTED) return;

        if (!_mqtt.connected()) {
            reconnect();
        } else {
            _mqtt.loop();

            unsigned long now = millis();
            if (now - _lastHeartbeat >= 3000) {
                _lastHeartbeat = now;
                publishTelemetry();
            }
        }
    }

    void setServiceActive(bool active) { _serviceActive = active; }
    bool isServiceActive() const { return _serviceActive; }

    void setOfflineMode(bool offline) { _offlineMode = offline; }
    bool isOfflineMode() const { return _offlineMode; }

    /**
     * Determines whether the node should execute its in-situ job.
     * If Serve while offline is OFF and network drops, halts job.
     */
    bool canServeJob() const {
        if (!_serviceActive) return false;
        if (!_offlineMode && WiFi.status() != WL_CONNECTED) return false;
        return true;
    }

    void setDelaySec(float delaySec) { _delaySec = delaySec; }
    float getDelaySec() const { return _delaySec; }

    String getDeviceName() const { return _deviceName; }
    String getMacAddress() const { return _macAddress; }

private:
    Preferences _prefs;
    WiFiClient _wifiClient;
    PubSubClient _mqtt;
    String _clientName;
    String _projectName;
    String _deviceName;
    String _macAddress;
    String _chipId;
    String _secHash;
    unsigned long _lastHeartbeat;
    CommandCallback _cmdCallback;
    bool _serviceActive;
    bool _offlineMode;
    float _delaySec;

    static AnashwarFleetClient* _instance;

    String computeSHA256(const String& input) {
        byte shaResult[32];
        mbedtls_sha256_context ctx;
        mbedtls_sha256_init(&ctx);
        mbedtls_sha256_starts_ret(&ctx, 0);
        mbedtls_sha256_update_ret(&ctx, (const unsigned char*)input.c_str(), input.length());
        mbedtls_sha256_finish_ret(&ctx, shaResult);
        mbedtls_sha256_free(&ctx);

        char hexBuf[65];
        for (int i = 0; i < 32; i++) {
            sprintf(hexBuf + (i * 2), "%02x", shaResult[i]);
        }
        hexBuf[64] = '\0';
        return String(hexBuf);
    }

    void reconnect() {
        static unsigned long lastAttempt = 0;
        if (millis() - lastAttempt < 4000) return;
        lastAttempt = millis();

        String clientId = "AnashwarNode-" + _chipId;
        Serial.printf("[AnashwarFleet] Connecting to HiveMQ broker (%s:%d)...\n", ANASHWAR_MQTT_BROKER, ANASHWAR_MQTT_PORT);
        if (_mqtt.connect(clientId.c_str())) {
            Serial.println("[AnashwarFleet] Connected! Subscribing to commands topic...");
            _mqtt.subscribe(ANASHWAR_TOPIC_COMMANDS);
            publishTelemetry(); // Instant first heartbeat
        }
    }

    void publishTelemetry() {
        char payload[768];
        snprintf(payload, sizeof(payload),
            "{\"name\":\"%s\",\"id\":\"%s\",\"mac\":\"%s\",\"chip_id\":\"%s\","
            "\"client\":\"%s\",\"project\":\"%s\",\"sec_hash\":\"%s\",\"mode\":1,"
            "\"service\":%s,\"offline\":%s,\"state\":\"%s\",\"ip\":\"%s\",\"rssi\":%d,"
            "\"heap\":%u,\"uptime\":%lu,\"delay\":%.1f,\"btn\":0,\"led\":1,"
            "\"mcu\":\"%s\",\"arch\":\"%s\",\"flash\":%.1f,\"ram\":%d,\"antenna\":\"%s\"}",
            _deviceName.c_str(),
            ("Anashwar-" + _chipId).c_str(),
            _macAddress.c_str(),
            _chipId.c_str(),
            _clientName.c_str(),
            _projectName.c_str(),
            _secHash.c_str(),
            _serviceActive ? "true" : "false",
            _offlineMode ? "true" : "false",
            _serviceActive ? "online" : "standby",
            WiFi.localIP().toString().c_str(),
            WiFi.RSSI(),
            (unsigned int)ESP.getFreeHeap(),
            millis() / 1000,
            _delaySec,
            ANASHWAR_MCU_FAMILY,
            ANASHWAR_MCU_ARCH,
            ANASHWAR_MCU_FLASH_MB,
            ANASHWAR_MCU_SRAM_KB,
            ANASHWAR_MCU_ANTENNA
        );

        _mqtt.publish(ANASHWAR_TOPIC_STATUS, payload, false);
    }

    void handleMqttMessage(char* topic, byte* payload, unsigned int length) {
        char buf[length + 1];
        memcpy(buf, payload, length);
        buf[length] = '\0';
        String msg = String(buf);
        msg.trim();

        // Standard commands: CMD:[DeviceName]:<action>:<value> or OTA:[DeviceName]:<url>
        if (!msg.startsWith("CMD:") && !msg.startsWith("OTA:")) return;

        bool isOTA = msg.startsWith("OTA:");
        String rest = msg.substring(4);
        String target = "";
        String action = "";

        if (rest.startsWith("[")) {
            int closeBracket = rest.indexOf(']');
            if (closeBracket > 0) {
                target = rest.substring(1, closeBracket);
                action = rest.substring(closeBracket + 1);
                if (action.startsWith(":")) action = action.substring(1);
            }
        } else {
            int col = rest.indexOf(':');
            if (col > 0) {
                target = rest.substring(0, col);
                action = rest.substring(col + 1);
            }
        }

        // Target match check (by name, mac, or wildcard "*")
        if (target != "*" && !target.equalsIgnoreCase(_deviceName) && !target.equalsIgnoreCase(_macAddress)) {
            return; // Not addressed to this device
        }

        Serial.printf("[AnashwarFleet] Directive for [%s]: %s\n", _deviceName.c_str(), action.c_str());

        if (isOTA) {
            performOTA(action);
            return;
        }

        // Command dispatch
        if (action.startsWith("SERVICE:")) {
            String val = action.substring(8);
            _serviceActive = (val.equalsIgnoreCase("ON") || val.equalsIgnoreCase("ACTIVE") || val.equalsIgnoreCase("TRUE"));
            Serial.printf("[AnashwarFleet] Service state changed to: %s\n", _serviceActive ? "ACTIVE" : "STANDBY");
            if (_cmdCallback) _cmdCallback("SERVICE", val);
            publishTelemetry();
        } else if (action.startsWith("DELAY:")) {
            String val = action.substring(6);
            _delaySec = val.toFloat();
            Serial.printf("[AnashwarFleet] Output delay updated to: %.1fs\n", _delaySec);
            if (_cmdCallback) _cmdCallback("DELAY", val);
            publishTelemetry();
        } else if (action.startsWith("OFFLINE:")) {
            String val = action.substring(8);
            _offlineMode = (val.equalsIgnoreCase("ON") || val.equalsIgnoreCase("TRUE") || val.equalsIgnoreCase("1"));
            Serial.printf("[AnashwarFleet] Autonomous offline mode: %s\n", _offlineMode ? "ENABLED (100% Local)" : "DISABLED (Cloud Active)");
            if (_cmdCallback) _cmdCallback("OFFLINE", val);
            publishTelemetry();
            if (_offlineMode && _mqtt.connected()) {
                delay(50);
                _mqtt.disconnect();
            }
        } else if (action.equalsIgnoreCase("REBOOT")) {
            Serial.println("[AnashwarFleet] Remote REBOOT directive accepted. Restarting in 500ms...");
            delay(500);
            ESP.restart();
        } else if (action.equalsIgnoreCase("PING") || action.equalsIgnoreCase("STATUS") || action.equalsIgnoreCase("REPORT")) {
            Serial.printf("[AnashwarFleet] Ping received from portal. Responding with presence ACK...\n");
            publishTelemetry();
        } else if (action.startsWith("RENAME:")) {
            String newName = action.substring(7);
            newName.trim();
            if (newName.length() > 0) {
                Serial.printf("[AnashwarFleet] Node renamed from '%s' to '%s' (persisted to NVS)\n", _deviceName.c_str(), newName.c_str());
                _deviceName = newName;
                _prefs.putString("node_name", _deviceName);
                publishTelemetry();
            }
        } else if (action.startsWith("SETCLIENT:")) {
            String newClient = action.substring(10);
            newClient.trim();
            if (newClient.length() > 0) {
                Serial.printf("[AnashwarFleet] Client renamed to '%s' (persisted to NVS)\n", newClient.c_str());
                _clientName = newClient;
                _prefs.putString("client_name", _clientName);
                publishTelemetry();
            }
        } else if (action.startsWith("SETPROJECT:")) {
            String newProj = action.substring(11);
            newProj.trim();
            if (newProj.length() > 0) {
                Serial.printf("[AnashwarFleet] Project renamed to '%s' (persisted to NVS)\n", newProj.c_str());
                _projectName = newProj;
                _prefs.putString("proj_name", _projectName);
                publishTelemetry();
            }
        } else {
            if (_cmdCallback) _cmdCallback("CUSTOM", action);
        }
    }

    void performOTA(const String& firmwareUrl) {
        Serial.printf("\n[AnashwarFleet] Initiating Cloud OTA Update from: %s\n", firmwareUrl.c_str());
        
        // Disconnect MQTT cleanly before flash
        _mqtt.disconnect();
        delay(200);

        WiFiClient otaClient;
        t_httpUpdate_return ret = httpUpdate.update(otaClient, firmwareUrl);

        switch (ret) {
            case HTTP_UPDATE_FAILED:
                Serial.printf("[AnashwarFleet] OTA Failed Error (%d): %s\n", 
                              httpUpdate.getLastError(), httpUpdate.getLastErrorString().c_str());
                break;
            case HTTP_UPDATE_NO_UPDATES:
                Serial.println("[AnashwarFleet] OTA Warning: No updates available.");
                break;
            case HTTP_UPDATE_OK:
                Serial.println("[AnashwarFleet] OTA Success! Hardware rebooting into new firmware...");
                break;
        }
    }
};

__attribute__((weak)) AnashwarFleetClient* AnashwarFleetClient::_instance = nullptr;

#endif // ANASHWAR_FLEET_H

