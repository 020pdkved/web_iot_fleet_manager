# Anashwar Technologies - Universal ESP32 Enterprise Fleet Manager & Edge OS

[![Enterprise SLA](https://img.shields.io/badge/Fleet_OS-v4.2_Enterprise-crimson.svg)](https://manage.anashwartech.com)
[![Portal Live](https://img.shields.io/badge/Portal-manage.anashwartech.com-10B981.svg)](https://manage.anashwartech.com)
[![MQTT Mesh](https://img.shields.io/badge/Mesh-broker.hivemq.com:1883-38BDF8.svg)](https://www.hivemq.com)
[![Security](https://img.shields.io/badge/Security-SHA--256_FIDO2_Passkey-A78BFA.svg)](https://manage.anashwartech.com)

Production edge microcontroller fleet management, zero-touch auto-onboarding, cryptographic security identity, and cross-network Over-The-Air (OTA) firmware deployment platform.

**Live Enterprise Portal:** [https://manage.anashwartech.com](https://manage.anashwartech.com)

---

## 1. System Architecture

```text
                                 +--------------------------------------------+
                                 |         https://manage.anashwartech.com     |
                                 |         (Cloud Render Web Service)         |
                                 |  - FIDO2 / Knox Biometric Passkey Auth     |
                                 |  - Zero-Touch Auto-Onboarding Engine       |
                                 |  - Reverse Proxy for In-Situ Node Web UIs  |
                                 +---------------------+----------------------+
                                                       |
                                      REST / WebSockets | HTTPS Directives
                                                       v
                                 +--------------------------------------------+
                                 |             broker.hivemq.com              |
                                 |              (TCP Port 1883)               |
                                 +---------------------+----------------------+
                                      ^                               ^
                        MQTT Telemetry |                 MQTT Directives |
                  (anashwar/poc/status) |          (anashwar/poc/commands)
                                      |                               |
                     +----------------+-------------------------------+
                     |
                     v
   +------------------------------------+          +------------------------------------+
   |         Node: Tree 1               |          |         Node: Node A / Generic     |
   |   (Hamley's x Cadbury Fleet)       |          |      (Alpha Enterprise Fleet)      |
   |------------------------------------|          |------------------------------------|
   | - Hardware SHA-256 Fingerprint     |          | - Hardware SHA-256 Fingerprint     |
   | - Autonomous Offline Operation     |          | - Autonomous Offline Operation     |
   | - In-Situ Web Server (Port 80)     |          | - In-Situ Web Server (Port 80)     |
   | - HTTP/HTTPS OTA Flash Engine      |          | - HTTP/HTTPS OTA Flash Engine      |
   | - Custom Relays / Lights / Sensors |          | - Project Specific Peripherals     |
   +------------------------------------+          +------------------------------------+
```

---

## 2. Hardware Independence (Zero Prototype Remnants)

The production fleet architecture is **100% pin-independent**. 

Earlier prototypes utilized GPIO 0 (boot button) and GPIO 2 (blue LED) for testing state machines and blink modes. **Production project nodes do NOT need these pins.**

- **No hardcoded button debounce or blink timers**: Your node runs whatever code, sensors, relays, displays, or actuators your project requires.
- **Universal telemetry**: The node reports core system metrics (`name`, `mac`, `chip_id`, `client`, `project`, `sec_hash`, `service`, `state`, `ip`, `rssi`, `heap`, `uptime`, `mcu`, `arch`, `flash`, `ram`, `antenna`).
- **Dynamic Portal UI**: The web portal automatically detects whether a node is a custom project node and hides legacy test visualizers, presenting clean, enterprise-grade controls.

---

## 3. Viewing the In-Situ Embedded Web UI

Every connected ESP32 hosts its own self-contained, frosted-glass configuration console on **Port 80**. You can view this embedded interface in two ways:

### Method A: Directly on Local Wi-Fi (Phone or Laptop)
1. Ensure your phone or laptop is connected to the **same Wi-Fi network** or hotspot as the ESP32.
2. In the portal under the node's control center, note the node's **Carrier IP (STA)** (e.g. `http://10.73.198.1/` or `http://192.168.1.105/`).
3. Click the **`↗ Direct LAN Link`** button or type the IP directly into your browser.
4. You will see the live, on-device Anashwar In-Situ Console directly from the ESP32!

### Method B: In-Portal Reverse Proxy Viewer
1. Open the portal at [https://manage.anashwartech.com](https://manage.anashwartech.com).
2. Click **`⚡ Open Node Controls`** on the node card, or tap **`🌐 On-Board Web UI`** in the top action bar.
3. A modal opens with an embedded viewer routed through `/proxy/node/<NodeName>/`.
4. When the portal host shares local network routing with the node, the portal securely proxies all HTML, styling, and action toggles right inside the cloud dashboard.

---

## 4. Zero-Touch Fleet Auto-Onboarding

When an ESP32 edge node boots and connects to Wi-Fi, it automatically registers itself with the portal:

1. **Calculates Cryptographic Hardware Fingerprint**:
   $$\text{sec\_hash} = \text{SHA256}(\text{MAC} + \text{ChipID} + \text{"AnashwarEnterprise2026SecureSalt"})$$
2. **Publishes Telemetry Heartbeat** to `anashwar/poc/status`:
   ```json
   {
     "name": "Tree 1",
     "id": "Anashwar-ECC9FFFD034C",
     "mac": "EC:C9:FF:FD:03:4C",
     "chip_id": "ECC9FFFD034C",
     "client": "Hamley’s x Cadbury",
     "project": "Connected Edge Fleet",
     "sec_hash": "4e23249026a8ba9038c890a8530b8fa93967da912d9afa331640e6ab4d78da68",
     "service": true,
     "offline": false,
     "state": "online",
     "ip": "10.73.198.1",
     "rssi": -48,
     "heap": 144492,
     "uptime": 588,
     "mcu": "ESP32",
     "arch": "Xtensa LX6 Dual-Core @ 240MHz",
     "flash": 4.0,
     "ram": 320,
     "antenna": "2.4 GHz 802.11 b/g/n"
   }
   ```
3. **Portal Auto-Discovery**:
   - Automatically registers the Client and Project in `fleet_registry.json`.
   - Assigns the node and flags it with an **`ONLINE` (Green)** status pill.
   - Evaluates 4-point majority security trust index (100% Verified).

---

## 5. Bidirectional Command Protocol

The portal dispatches directives to the fleet on topic `anashwar/poc/commands`:

| Command String | Target | Node Action |
| :--- | :--- | :--- |
| `CMD:[*]:PING` or `CMD:[<Node>]:PING` | All or Specific | Node publishes fresh telemetry payload within 100ms (Presence ACK). |
| `CMD:[<Node>]:REBOOT` | Specific Node | Delays 200ms and executes software reset (`ESP.restart()`). |
| `CMD:[<Node>]:SERVICE:ON` | Specific Node | Sets master operational service state to ACTIVE. |
| `CMD:[<Node>]:SERVICE:OFF` | Specific Node | Sets master operational service state to STANDBY. |
| `OTA:[<Node>]:<http_binary_url>` | Specific Node | Downloads `.bin` via HTTP and executes OTA flash, then reboots. |
| `CMD:[<Node>]:RENAME:<NewName>` | Specific Node | Stores updated node name in NVS Flash (`Preferences`). |
| `CMD:[*]:SETCLIENT:<NewClient>` | All Nodes | Updates default client workspace name across all devices. |
| `CMD:[*]:SETPROJECT:<NewProject>` | All Nodes | Updates default fleet project name across all devices. |
| `CMD:[<Node>]:<CUSTOM_DIRECTIVE>` | Specific Node | Any custom project string (e.g. `RELAY:ON`, `LIGHTS:1`, `BRIGHTNESS:80`). |

---

## 6. Project Files & Directory Structure

```text
ESP32_WEB_OTA/
├── Anashwar_ESP32_Fleet_Node.ino   # Standalone Arduino reference firmware (Clean production)
├── examples/
│   └── Anashwar_ESP32_Fleet_Node/
│       └── Anashwar_ESP32_Fleet_Node.ino # Arduino IDE ready sketch
├── web_portal.py                   # Complete Python Enterprise Fleet Server
├── src/
│   └── main.cpp                    # PlatformIO C++ firmware implementation
├── include/
│   ├── config.h                    # Global credentials, salt, & topic constants
│   └── README                      # Header documentation
├── platformio.ini                  # Multi-environment PlatformIO build configuration
├── users.json                      # Enterprise credentials & WebAuthn biometrics database
├── fleet_registry.json             # Clients, projects, and registered nodes database
└── README.md                       # This documentation
```

---

## 7. How to Deploy to an ESP32

### Option 1: Arduino IDE (Easiest)
1. Open Arduino IDE.
2. Open [`Anashwar_ESP32_Fleet_Node.ino`](Anashwar_ESP32_Fleet_Node.ino) or `examples/Anashwar_ESP32_Fleet_Node/Anashwar_ESP32_Fleet_Node.ino`.
3. In Library Manager, install **PubSubClient** by Nick O'Leary.
4. Update `WIFI_SSID`, `WIFI_PASSWORD`, `nodeName`, `nodeClient`, and `nodeProject` at the top of the file.
5. Select your ESP32 board (e.g., `ESP32 Dev Module`) and USB port.
6. Click **Upload**.
7. Open Serial Monitor at `115200` baud. Within 5 seconds, your node will connect, publish telemetry, and appear live on [https://manage.anashwartech.com](https://manage.anashwartech.com)!

### Option 2: PlatformIO
```bash
# Build firmware
pio run -e esp32_nodeA

# Flash over USB
pio run -e esp32_nodeA --target upload

# Launch serial monitor
pio device monitor -b 115200
```

---

## 8. Enterprise Portal Cloud Deployment

The portal server (`web_portal.py`) is designed with **zero heavy dependencies** (runs on Python 3 standard library with native sockets for MQTT):

```bash
# Run portal locally
python3 web_portal.py

# Live Production Service
# Hosted on Render Web Service, bound to custom domain:
# https://manage.anashwartech.com
```

### Security & Authentication
- **FIDO2 / WebAuthn Biometric Passkeys**: Hardware-backed biometric authentication (Samsung Knox, Android Biometrics, Apple FaceID / TouchID).
- **Session Tokens**: Cryptographically secure 48-character hex tokens with `SameSite=None; Secure; Max-Age=604800`.
- **4-Point Hardware Attestation**: Guarantees node authenticity using MAC address, silicon eFuse chip ID, SHA-256 fingerprint, and carrier IP validation.

---

## License & Support

Developed by **Anashwar Technologies**. Proprietary and confidential enterprise fleet management architecture.
For technical support and operations: `ops@anashwartech.com`.
