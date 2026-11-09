# Anashwar Technologies - ESP32 Cross-Network OTA POC

This repository contains the complete firmware and automation toolchain for remote, cross-network Over-The-Air (OTA) firmware updates on the ESP32 triggered asynchronously via MQTT.

---

## Architecture Overview

```
                      +-----------------------------+
                      |     broker.hivemq.com       |
                      |        (Port 1883)          |
                      +--------------+--------------+
                                     |
                 MQTT Publish        | MQTT Subscribe
         ("http://.../firmware.bin") | (anashwar/poc/commands)
                                     v
+------------------+         +-------+-------+
|   OTA Trigger    |         |  ESP32 Board  |
|  (ota_manager.py |         |  (Mode 1,2,3) |
|   or Web UI)     |         +-------+-------+
+------------------+                 |
                                     | HTTP/HTTPS GET (.bin)
                                     v
                      +-----------------------------+
                      |   HTTP Server / Ngrok       |
                      |   (firmware_modeX.bin)      |
                      +-----------------------------+
```

---

## Hardware LED Indicator Modes

GPIO 2 (onboard blue LED) reflects the active firmware version using a non-blocking `millis()` state machine:

| Firmware Mode | LED Behavior | Frequency / Cycle | Description |
| :--- | :--- | :--- | :--- |
| **Mode 1** | **Solid ON** | Constant HIGH | Baseline Initial Firmware |
| **Mode 2** | **Fast Blink** | 4.0 Hz (125ms ON / 125ms OFF) | Target Update 1 |
| **Mode 3** | **Slow Blink** | 0.5 Hz (1000ms ON / 1000ms OFF) | Target Update 2 |

---

## Directory Structure

```text
ESP32_WEB_OTA/
├── platformio.ini       # PlatformIO configuration & multi-environment targets
├── ota_manager.py       # Turnkey Python automation CLI (Zero dependencies)
├── src/
│   └── main.cpp         # Complete unified firmware
├── binaries/            # Pre-compiled binaries for each mode
│   ├── firmware_mode1.bin
│   ├── firmware_mode2.bin
│   └── firmware_mode3.bin
└── README.md            # This documentation
```

---

## Quick Start (Automated Tooling)

An interactive automation tool `ota_manager.py` is provided. It handles builds, USB flashing, HTTP hosting, MQTT triggers, and serial monitoring.

### Launch Interactive CLI
```bash
python3 ota_manager.py
```

### Or Use Direct Commands:

1. **Rebuild all binaries**:
   ```bash
   python3 ota_manager.py build
   ```

2. **Flash Mode 1 over USB (Initial Device Provisioning)**:
   ```bash
   python3 ota_manager.py flash mode1
   ```

3. **Start the local OTA HTTP server**:
   ```bash
   python3 ota_manager.py serve
   ```

4. **Trigger OTA via MQTT** (in another terminal):
   ```bash
   # Trigger update to Mode 2 (Fast Blink)
   python3 ota_manager.py trigger 2

   # Trigger update to Mode 3 (Slow Blink)
   python3 ota_manager.py trigger 3

   # Trigger using a custom public URL (e.g. Ngrok / Cloud storage)
   python3 ota_manager.py trigger https://your-ngrok-subdomain.ngrok-free.app/firmware_mode2.bin
   ```

5. **Open Serial Monitor**:
   ```bash
   python3 ota_manager.py monitor
   ```

---

## Network Provisioning Flow (WiFiManager)

1. On initial boot, the ESP32 attempts connection to stored credentials in NVS flash.
2. If credentials are missing or connection fails, the device boots an Access Point named **`Anashwar-ESP32-Setup`** (IP: `192.168.4.1`).
3. Connect your smartphone or computer to the AP and use the captive portal to input your local Wi-Fi SSID and password.
4. The ESP32 saves credentials to flash and reboots into station (STA) mode automatically.

