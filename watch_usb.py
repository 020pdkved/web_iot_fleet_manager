#!/usr/bin/env python3
"""
Real-time USB Device & Serial Port Sniffer for macOS
Runs in terminal to immediately notify you the second an ESP32 is recognized.
"""

import sys
import glob
import time
import subprocess

def get_current_ports():
    return set(glob.glob("/dev/cu.*"))

def main():
    print("==================================================")
    print("  ESP32 USB CONNECTION MONITOR - LISTENING...     ")
    print("==================================================")
    print("Trying to detect any incoming USB-UART device.")
    print("Try the following:")
    print("  1. Flip the USB-C cable 180 degrees.")
    print("  2. If using USB-C to USB-C, try USB-A cable + adapter.")
    print("  3. Hold BOOT, tap EN/RST, then release BOOT.")
    print("--------------------------------------------------")

    baseline = get_current_ports()
    print(f"Current base ports: {[p for p in baseline if 'Bluetooth' not in p and 'debug' not in p]}")
    print("Waiting for new port to appear...")

    while True:
        current = get_current_ports()
        new_ports = current - baseline
        if new_ports:
            print("\n" + "*" * 50)
            print(f" [SUCCESS] NEW PORT DETECTED: {list(new_ports)}")
            print("*" * 50)
            for p in new_ports:
                if "Bluetooth" not in p and "debug" not in p:
                    print(f"\nAttempting to identify device on {p}...")
                    subprocess.run(["~/.platformio/penv/bin/pio", "device", "list"])
                    sys.exit(0)
        time.sleep(0.5)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nMonitor stopped.")

