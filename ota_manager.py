#!/usr/bin/env python3
"""
Anashwar Technologies - ESP32 Cross-Network OTA Automation Suite
Senior Embedded Engineering Toolkit

This script provides end-to-end automation for:
  1. Multi-target compilation (Mode 1: Solid, Mode 2: 4Hz Blink, Mode 3: 0.5Hz Blink)
  2. Automatic binary distribution into the 'binaries/' directory
  3. Automatic serial port detection and USB flashing
  4. Embedded zero-dependency HTTP server for hosting firmware .bin files
  5. Built-in zero-dependency MQTT 3.1.1 publisher targeting broker.hivemq.com
  6. Real-time serial monitor integration
"""

import sys
import os
import time
import socket
import threading
import glob
import subprocess
from http.server import SimpleHTTPRequestHandler, HTTPServer

DEFAULT_MQTT_BROKER = "broker.hivemq.com"
DEFAULT_MQTT_PORT = 1883
DEFAULT_MQTT_TOPIC = "anashwar/poc/commands"
DEFAULT_HTTP_PORT = 8080

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
BINARIES_DIR = os.path.join(PROJECT_ROOT, "binaries")


def find_pio_binary():
    """Locates the PlatformIO executable."""
    home_pio = os.path.expanduser("~/.platformio/penv/bin/pio")
    if os.path.isfile(home_pio) and os.access(home_pio, os.X_OK):
        return home_pio
    
    # Check system PATH
    for path in os.environ.get("PATH", "").split(os.pathsep):
        candidate = os.path.join(path, "pio")
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return "pio"


def get_local_ip():
    """Detects the primary local LAN IP address."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Does not actually transmit packets; resolves local outbound interface
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip


def find_esp32_port():
    """Scans for active serial ports commonly used by ESP32 USB-UART bridges."""
    patterns = [
        "/dev/cu.usbserial*",
        "/dev/cu.wchusbserial*",
        "/dev/cu.SLAB_USBtoUART*",
        "/dev/cu.usbmodem*",
        "/dev/ttyUSB*",
        "/dev/ttyACM*"
    ]
    matches = []
    for p in patterns:
        matches.extend(glob.glob(p))
    return matches[0] if matches else None


def build_all_modes():
    """Compiles all three firmware environments and organizes the outputs."""
    pio = find_pio_binary()
    print("\n[BUILD] Compiling all 4 firmware environments (mode1, mode2, mode3, mode4)...")
    cmd = [pio, "run", "-e", "mode1", "-e", "mode2", "-e", "mode3", "-e", "mode4"]
    
    result = subprocess.run(cmd, cwd=PROJECT_ROOT)
    if result.returncode != 0:
        print("[BUILD] Compilation failed! Review the error messages above.")
        return False

    os.makedirs(BINARIES_DIR, exist_ok=True)
    src = os.path.join(PROJECT_ROOT, ".pio", "build", "esp32dev", "firmware.bin")
    dest = os.path.join(BINARIES_DIR, "Base_firmware.bin")
    if os.path.exists(src):
        with open(src, "rb") as f_in, open(dest, "wb") as f_out:
            f_out.write(f_in.read())
        size_kb = os.path.getsize(dest) / 1024.0
        print(f"  ✓ Base_firmware.bin    ({size_kb:7.1f} KB) -> {dest}")
    else:
        for env in ("mode1", "esp32dev"):
            alt_src = os.path.join(PROJECT_ROOT, ".pio", "build", env, "firmware.bin")
            if os.path.exists(alt_src):
                with open(alt_src, "rb") as f_in, open(dest, "wb") as f_out:
                    f_out.write(f_in.read())
                size_kb = os.path.getsize(dest) / 1024.0
                print(f"  ✓ Base_firmware.bin    ({size_kb:7.1f} KB) -> {dest}")
                break

    print("\n[BUILD] Base_firmware.bin is ready in 'binaries/'.")
    return True


def flash_device(mode="mode1"):
    """Flashes a chosen mode firmware to the attached ESP32."""
    pio = find_pio_binary()
    port = find_esp32_port()

    print(f"\n[FLASH] Initiating USB upload for {mode}...")
    if port:
        print(f"[FLASH] Detected ESP32 device on port: {port}")
    else:
        print("[FLASH] No port explicitly matched; letting PlatformIO auto-detect...")

    cmd = [pio, "run", "-e", mode, "-t", "upload"]
    if port:
        cmd.extend(["--upload-port", port])

    result = subprocess.run(cmd, cwd=PROJECT_ROOT)
    if result.returncode == 0:
        print(f"[FLASH] Successfully flashed {mode} to ESP32!")
        return True
    else:
        print(f"[FLASH] Upload failed. Please ensure your ESP32 is plugged in via a data-capable USB cable.")
        return False


def start_http_server(port=DEFAULT_HTTP_PORT):
    """Starts a local HTTP server serving the binaries directory."""
    os.makedirs(BINARIES_DIR, exist_ok=True)

    class CustomHandler(SimpleHTTPRequestHandler):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, directory=BINARIES_DIR, **kwargs)

        def log_message(self, format, *args):
            print(f"[HTTP] {self.address_string()} - {args[0]}")

    server = HTTPServer(("0.0.0.0", port), CustomHandler)
    local_ip = get_local_ip()
    print(f"\n[HTTP] Local OTA Server running on port {port}")
    print(f"[HTTP] Root Directory : {BINARIES_DIR}")
    print(f"[HTTP] Local Base URL : http://{local_ip}:{port}/")
    print(f"[HTTP] Available files:")
    for f in os.listdir(BINARIES_DIR):
        if f.endswith(".bin"):
            print(f"   -> http://{local_ip}:{port}/{f}")
    print("[HTTP] Press Ctrl+C in this terminal to stop the server.\n")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[HTTP] Server stopped.")


def publish_mqtt(topic, payload, broker=DEFAULT_MQTT_BROKER, port=DEFAULT_MQTT_PORT):
    """Pure-Python MQTT 3.1.1 Publisher (zero external dependencies)."""
    print(f"\n[MQTT] Connecting to broker: {broker}:{port}...")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(8)

    try:
        s.connect((broker, port))

        # MQTT CONNECT packet
        client_id = f"Anashwar-Trigger-{int(time.time())}".encode('ascii')
        proto_name = b"MQTT"
        var_header = (
            len(proto_name).to_bytes(2, 'big') + proto_name +
            b'\x04' + # Protocol Level (3.1.1)
            b'\x02' + # Flags: Clean Session
            (60).to_bytes(2, 'big') # Keep Alive
        )
        connect_payload = len(client_id).to_bytes(2, 'big') + client_id
        rem_len = len(var_header) + len(connect_payload)
        connect_packet = b'\x10' + bytes([rem_len]) + var_header + connect_payload
        s.sendall(connect_packet)

        # Receive CONNACK
        ack = s.recv(4)
        if len(ack) < 4 or ack[0] != 0x20 or ack[3] != 0:
            print(f"[MQTT] Connection refused by broker (code: {ack[3] if len(ack) >= 4 else 'unknown'})")
            return False

        print("[MQTT] Broker connection established (CONNACK OK)!")

        # MQTT PUBLISH packet (QoS 0)
        topic_bytes = topic.encode('utf-8')
        payload_bytes = payload.encode('utf-8')
        pub_var_header = len(topic_bytes).to_bytes(2, 'big') + topic_bytes
        pub_payload = payload_bytes
        pub_rem_len = len(pub_var_header) + len(pub_payload)

        # Encode remaining length
        if pub_rem_len < 128:
            rem_len_bytes = bytes([pub_rem_len])
        else:
            rem_len_bytes = bytes([(pub_rem_len & 0x7F) | 0x80, (pub_rem_len >> 7) & 0x7F])

        pub_packet = b'\x30' + rem_len_bytes + pub_var_header + pub_payload
        s.sendall(pub_packet)

        print(f"[MQTT] Successfully published message!")
        print(f"  Topic  : {topic}")
        print(f"  Payload: {payload}")
        return True

    except Exception as e:
        print(f"[MQTT] Transmission error: {e}")
        return False
    finally:
        s.close()


def open_serial_monitor():
    """Opens PlatformIO serial monitor at 115200 baud."""
    pio = find_pio_binary()
    port = find_esp32_port()
    cmd = [pio, "device", "monitor", "-b", "115200"]
    if port:
        cmd.extend(["-p", port])
    print(f"\n[MONITOR] Starting Serial Monitor at 115200 baud...")
    print("[MONITOR] To exit monitor, press Ctrl+C or Ctrl+]")
    subprocess.run(cmd, cwd=PROJECT_ROOT)


def interactive_menu():
    """Main interactive terminal CLI."""
    while True:
        local_ip = get_local_ip()
        print("\n" + "=" * 62)
        print("   ANASHWAR TECHNOLOGIES - ESP32 OTA AUTOMATION SUITE   ")
        print("=" * 62)
        print(f" Detected Local IP : {local_ip}")
        print(f" Detected USB Port : {find_esp32_port() or 'None (Not plugged in)'}")
        print("-" * 62)
        print(" [1] Build All Firmware Modes (Mode 1, Mode 2, Mode 3)")
        print(" [2] Flash Mode 1 to ESP32 via USB (Initial Setup)")
        print(" [3] Flash Mode 2 or 3 to ESP32 via USB")
        print(" [4] Start Local OTA HTTP Server (Port 8080)")
        print(" [5] Trigger OTA via Local Network URL")
        print(" [6] Trigger OTA via Custom URL (e.g. Ngrok / Cloud)")
        print(" [7] Launch Serial Monitor (115200 baud)")
        print(" [0] Exit")
        print("=" * 62)

        choice = input("Select an option [0-7]: ").strip()

        if choice == "1":
            build_all_modes()
        elif choice == "2":
            flash_device("mode1")
        elif choice == "3":
            sub = input("Select environment (mode2 or mode3) [default: mode2]: ").strip() or "mode2"
            flash_device(sub)
        elif choice == "4":
            start_http_server()
        elif choice == "5":
            url = f"http://{local_ip}:{DEFAULT_HTTP_PORT}/Base_firmware.bin"
            publish_mqtt(DEFAULT_MQTT_TOPIC, url)
        elif choice == "6":
            custom_url = input("Enter the public HTTP/HTTPS URL: ").strip()
            if custom_url.startswith("http"):
                publish_mqtt(DEFAULT_MQTT_TOPIC, custom_url)
            else:
                print("[ERROR] URL must start with 'http://' or 'https://'")
        elif choice == "7":
            open_serial_monitor()
        elif choice == "0":
            print("\nExiting. Good luck with your POC testing!")
            sys.exit(0)
        else:
            print("[ERROR] Invalid selection.")


if __name__ == "__main__":
    if len(sys.argv) > 1:
        action = sys.argv[1].lower()
        if action == "build":
            build_all_modes()
        elif action == "flash":
            target = sys.argv[2] if len(sys.argv) > 2 else "mode1"
            flash_device(target)
        elif action == "serve":
            port = int(sys.argv[2]) if len(sys.argv) > 2 else DEFAULT_HTTP_PORT
            start_http_server(port)
        elif action == "trigger":
            if len(sys.argv) > 2:
                arg = sys.argv[2]
                if arg in ("1", "2", "3", "base"):
                    ip = get_local_ip()
                    url = f"http://{ip}:{DEFAULT_HTTP_PORT}/Base_firmware.bin"
                else:
                    url = arg
            else:
                ip = get_local_ip()
                url = f"http://{ip}:{DEFAULT_HTTP_PORT}/Base_firmware.bin"
            publish_mqtt(DEFAULT_MQTT_TOPIC, url)
        elif action == "monitor":
            open_serial_monitor()
        else:
            print(f"Unknown action: {action}")
            print("Usage: python3 ota_manager.py [build | flash <mode> | serve | trigger <mode|url> | monitor]")
    else:
        interactive_menu()

