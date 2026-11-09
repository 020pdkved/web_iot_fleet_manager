#pragma once
#include <Arduino.h>

// =============================================================================
//  ANASHWAR TECHNOLOGIES - ESP32 ENTERPRISE FIRMWARE CONFIGURATION
//  File: include/config.h
// =============================================================================
//
//  >>> WHERE TO CONFIGURE WI-FI NETWORK CREDENTIALS <<<
//  Edit WIFI_SSID and WIFI_PASSWORD below to connect your ESP32 boards
//  to your phone hotspot or local Wi-Fi router.
//
// =============================================================================

#define WIFI_SSID           "VED-FI"        // <-- Primary Wi-Fi SSID (Phone Hotspot / Router)
#define WIFI_SSID_FALLBACK  "vedfi"         // <-- Alternative Wi-Fi SSID (Auto-switch fallback)
#define WIFI_PASSWORD       "11111111"      // <-- Wi-Fi Password (Minimum 8 characters)

// Fallback Captive Portal Access Point Name (if Wi-Fi fails to connect)
#define AP_FALLBACK_SSID    "Anashwar-ESP32-Setup"

// =============================================================================
//  ENTERPRISE SECURITY & CRYPTOGRAPHIC REGISTRY
// =============================================================================
// Cryptographic salt used to compute unique SHA-256 device authentication hashes
#define SECURITY_SALT       "AnashwarEnterprise2026SecureSalt"

// Structure defining a registered hardware node in the fleet
struct FleetNodeDefinition {
    const char* nodeName;      // e.g. "Node: A"
    const char* macAddress;    // e.g. "EC:C9:FF:FF:08:94"
    const char* chipId;        // e.g. "9408FFFFC9EC"
    const char* clientId;      // e.g. "client_1"
    const char* clientName;    // e.g. "Client 1: Alpha Enterprise Corp"
    const char* projectId;     // e.g. "proj_1"
    const char* projectName;   // e.g. "Project 1: Enterprise OTA Fleet"
    const char* securityHash;  // SHA-256 fingerprint: sha256(MAC + CHIP_ID + SALT)
    const char* preferredPort; // e.g. "/dev/cu.usbserial-0001"
};

// Registered Fleet Nodes (Extensible: simply append new nodes here)
static const FleetNodeDefinition REGISTERED_NODES[] = {
    {
        "Node: A",
        "EC:C9:FF:FF:08:94",
        "9408FFFFC9EC",
        "client_1",
        "Client 1: Alpha Enterprise Corp",
        "proj_1",
        "Project 1: Enterprise OTA Fleet",
        "0647df22dceea927a2fe279cdb6fe999fc873a2d1d8f0cfca79934833eb5ed7d",
        "/dev/cu.usbserial-0001"
    },
    {
        "Node: B",
        "70:4B:CA:48:E6:BC",
        "BCE648CA4B70",
        "client_1",
        "Client 1: Alpha Enterprise Corp",
        "proj_1",
        "Project 1: Enterprise OTA Fleet",
        "d56ab3dfed28a8a361a0b323be53b3abbd43dbfc16a1eb040a23c940cefbe703",
        "/dev/cu.usbserial-3"
    }
};

static const size_t REGISTERED_NODE_COUNT = sizeof(REGISTERED_NODES) / sizeof(REGISTERED_NODES[0]);

// =============================================================================
//  MQTT TELEMETRY & COMMAND BROKER CONFIGURATION
// =============================================================================
#define MQTT_BROKER_HOST    "broker.hivemq.com"
#define MQTT_BROKER_PORT    1883
#define MQTT_TOPIC_COMMANDS "anashwar/poc/commands"
#define MQTT_TOPIC_STATUS   "anashwar/poc/status"

// =============================================================================
//  HARDWARE GPIO PIN DEFINITIONS
// =============================================================================
// Active-HIGH: HIGH = LED ON (Solid lit blue), LOW = LED OFF
#define ONBOARD_LED_PIN     2
#define LED_IS_ACTIVE_LOW   false

#define LED_STATE_ON        (LED_IS_ACTIVE_LOW ? LOW : HIGH)
#define LED_STATE_OFF       (LED_IS_ACTIVE_LOW ? HIGH : LOW)

// BOOT Pushbutton Pin (GPIO 0)
// Configured as INPUT_PULLUP:
//   Pressed  = LOW (0)
//   Released = HIGH (1)
#define BOOT_BUTTON_PIN     0

// =============================================================================
//  DEFAULT FIRMWARE MODE
//  Mode 1: Pressed -> Solid ON,  Released -> OFF
//  Mode 2: Pressed -> Blink,     Released -> OFF
//  Mode 3: Pressed -> OFF,       Released -> Solid ON
//  Mode 4: Pressed -> OFF,       Released -> Blink
// =============================================================================
#ifndef ESP_MODE
#define ESP_MODE 1
#endif
