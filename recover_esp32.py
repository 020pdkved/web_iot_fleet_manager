#!/usr/bin/env python3
"""
Anashwar Technologies - ESP32 Hardware Recovery & Flash Tool
Forces flash erase and re-installs clean bootloader, partition table, and Mode 1 firmware.
"""

import sys
import os
import glob
import time
import subprocess

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
ESPTOOL = os.path.expanduser("~/.platformio/packages/tool-esptoolpy/esptool.py")
PYTHON = os.path.expanduser("~/.platformio/penv/bin/python")

CANDIDATE_PATTERNS = [
    "/dev/cu.usbserial*",
    "/dev/cu.wchusbserial*",
    "/dev/cu.SLAB_USBtoUART*",
    "/dev/cu.usbmodem*",
    "/dev/cu.CP210*",
    "/dev/cu.CH34*",
    "/dev/ttyUSB*",
    "/dev/ttyACM*"
]

def scan_ports():
    ports = []
    for pat in CANDIDATE_PATTERNS:
        ports.extend(glob.glob(pat))
    # Also check any /dev/cu.* that isn't Bluetooth or debug-console
    for p in glob.glob("/dev/cu.*"):
        if "Bluetooth" not in p and "debug-console" not in p:
            if p not in ports:
                ports.append(p)
    return ports

def wait_for_port(timeout=60):
    print("\n=======================================================")
    print("  ESP32 HARDWARE RECOVERY INSTRUCTIONS                 ")
    print("=======================================================")
    print(" 1. Unplug the ESP32 from USB.")
    print(" 2. Press and HOLD the [BOOT] button (IO0 / 0 / PRG).")
    print(" 3. While STILL HOLDING [BOOT], plug the USB into your Mac.")
    print(" 4. Keep holding for 2 seconds, then release [BOOT].")
    print("-------------------------------------------------------")
    print(" Waiting for ESP32 serial port to appear on Mac...")

    start = time.time()
    while time.time() - start < timeout:
        ports = scan_ports()
        if ports:
            print(f"\n[FOUND] Detected ESP32 on port: {ports[0]}")
            return ports[0]
        time.sleep(0.5)
        print(".", end="", flush=True)

    print("\n[TIMEOUT] No serial device appeared. Please check cable or USB-C hub.")
    return None

def recover_and_flash(port, target_mode="mode1"):
    print(f"\n[1/3] Interrogating ESP32 on {port}...")
    chip_cmd = [PYTHON, ESPTOOL, "--port", port, "--baud", "115200", "chip_id"]
    res = subprocess.run(chip_cmd)
    if res.returncode != 0:
        print("[WARNING] Could not read chip_id automatically. Board may need manual BOOT press.")

    print(f"\n[2/3] Performing FULL FLASH ERASE to wipe corrupt NVS & partition tables...")
    erase_cmd = [PYTHON, ESPTOOL, "--port", port, "--baud", "460800", "erase_flash"]
    res = subprocess.run(erase_cmd)
    if res.returncode != 0:
        print("[ERROR] Flash erase failed! Try holding BOOT again while running.")
        return False

    print(f"\n[3/3] Uploading clean bootloader, partitions, and {target_mode} firmware...")
    pio = os.path.expanduser("~/.platformio/penv/bin/pio")
    upload_cmd = [pio, "run", "-e", target_mode, "-t", "upload", "--upload-port", port]
    res = subprocess.run(upload_cmd, cwd=PROJECT_ROOT)
    if res.returncode == 0:
        print("\n=======================================================")
        print(" [SUCCESS] ESP32 has been completely recovered & flashed!")
        print(" Press the [EN] / [RST] button on your board to boot.")
        print(" LED will be solid ON (Mode 1), and AP will appear.")
        print("=======================================================\n")
        return True
    else:
        print("[ERROR] Firmware upload failed.")
        return False

if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "mode1"
    existing = scan_ports()
    if existing:
        print(f"Detected port immediately: {existing[0]}")
        recover_and_flash(existing[0], mode)
    else:
        port = wait_for_port()
        if port:
            recover_and_flash(port, mode)
        else:
            sys.exit(1)

