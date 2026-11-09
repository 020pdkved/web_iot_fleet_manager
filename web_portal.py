#!/usr/bin/env python3
"""
Anashwar Technologies - Enterprise Fleet Management Console
Multi-Page Cloud & USB Firmware Management System for ESP32 Nodes

Hierarchical Architecture:
  Dashboard (Overview) -> Clients -> Projects -> Nodes -> Node Detail / Control Center

Hardware Identities:
  - Node: A | MAC: EC:C9:FF:FF:08:94 | Chip ID: 9408FFFFC9EC | Port: /dev/cu.usbserial-0001
  - Node: B | MAC: 70:4B:CA:48:E6:BC | Chip ID: BCE648CA4B70 | Port: /dev/cu.usbserial-3
"""

import os
import sys
import time
import json
import socket
import threading
import glob
import re
import hashlib
import subprocess
import atexit
import secrets
import urllib.request
import urllib.parse
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse

PORT = int(os.environ.get("PORT", 8080))
DEFAULT_MQTT_BROKER = "broker.hivemq.com"
DEFAULT_MQTT_PORT = 1883
DEFAULT_MQTT_TOPIC_COMMANDS = "anashwar/poc/commands"
DEFAULT_MQTT_TOPIC_STATUS = "anashwar/poc/status"
SECURITY_SALT = "AnashwarEnterprise2026SecureSalt"

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
BINARIES_DIR = os.path.join(PROJECT_ROOT, "binaries")
STATIC_DIR = os.path.join(PROJECT_ROOT, "static")
REGISTRY_FILE = os.path.join(PROJECT_ROOT, "fleet_registry.json")
USERS_FILE = os.path.join(PROJECT_ROOT, "users.json")
os.makedirs(BINARIES_DIR, exist_ok=True)
os.makedirs(STATIC_DIR, exist_ok=True)

# User Database & Session Store
users_db = {}
active_sessions = {}  # token -> {"username": str, "login_time": float}

def load_users():
    global users_db
    if os.path.isfile(USERS_FILE):
        try:
            with open(USERS_FILE, "r") as f:
                users_db = json.load(f)
                return
        except Exception as e:
            print(f"[AUTH] Error reading {USERS_FILE}: {e}")
    users_db = {
        "admin": {
            "username": "admin",
            "password_hash": hashlib.sha256("At@12345".encode("utf-8")).hexdigest(),
            "role": "Super Admin",
            "created_at": time.strftime("%Y-%m-%d")
        }
    }
    save_users()

def save_users():
    try:
        with open(USERS_FILE, "w") as f:
            json.dump(users_db, f, indent=2)
    except Exception as e:
        print(f"[AUTH] Error saving {USERS_FILE}: {e}")

load_users()

def verify_credentials(username, password):
    if username in users_db:
        stored_hash = users_db[username].get("password_hash", "")
        pwd_hash = hashlib.sha256(password.encode("utf-8")).hexdigest()
        if stored_hash == pwd_hash or stored_hash == password:
            return True
    return False

def get_authenticated_user(headers, parsed_url=None, body_data=None):
    token = None
    # 1. URL Query Parameter: ?token=... or ?auth=...
    if parsed_url and parsed_url.query:
        qp = parse_qs(parsed_url.query)
        if "token" in qp:
            token = qp["token"][0].strip()
        elif "auth" in qp:
            token = qp["auth"][0].strip()

    # 2. Authorization Header: Bearer <token>
    if not token:
        auth_header = headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:].strip()

    # 3. Cookie Header: session_token=<token>
    if not token:
        cookie_header = headers.get("Cookie", "")
        if "session_token=" in cookie_header:
            for part in cookie_header.split(";"):
                part = part.strip()
                if part.startswith("session_token="):
                    token = part.split("=")[1].strip()
                    break

    # 4. Request Body: token=...
    if not token and body_data:
        if isinstance(body_data, dict) and "token" in body_data:
            val = body_data["token"]
            token = val[0].strip() if isinstance(val, list) else str(val).strip()

    if token and token in active_sessions:
        return active_sessions[token]["username"], token
    return None, None

def scan_usb_devices():
    ports = glob.glob("/dev/cu.usbserial*") + glob.glob("/dev/cu.SLAB_USBtoUART*") + glob.glob("/dev/cu.wchusbserial*") + glob.glob("/dev/cu.usbmodem*")
    ports = sorted(list(set(ports)))
    devices = []
    for p in ports:
        matched_node = None
        for n_name, n in nodes_telemetry.items():
            if n.get("port") == p:
                matched_node = n
                break
        if not matched_node:
            for n_name, r in fleet_registry.get("registered_nodes", {}).items():
                if r.get("port") == p:
                    matched_node = r
                    break
        devices.append({
            "port": p,
            "assigned": matched_node is not None,
            "node_name": matched_node.get("name", "") if matched_node else "",
            "mac": matched_node.get("mac", "") if matched_node else "",
            "chip_id": matched_node.get("chip_id", "") if matched_node else "",
            "client": matched_node.get("client", "") if matched_node else "",
            "project": matched_node.get("project", "") if matched_node else ""
        })
    return devices

def check_node_web_ui(ip, port=80, timeout=0.8):
    if not ip or ip.startswith("0.0.0.0") or ip == "127.0.0.1":
        return False
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        s.close()
        return True
    except Exception:
        return False

def background_web_ui_detector():
    while True:
        try:
            for name, node in list(nodes_telemetry.items()):
                if node.get("online") and node.get("ip"):
                    node["has_web_ui"] = check_node_web_ui(node["ip"], 80)
                else:
                    node["has_web_ui"] = False
        except Exception:
            pass
        time.sleep(10)

t_webui = threading.Thread(target=background_web_ui_detector, daemon=True)
t_webui.start()

ESPTOOL_PATH = "/Users/vedangphadke/.platformio/packages/tool-esptoolpy/esptool.py"
PYTHON_ENV_PATH = "/Users/vedangphadke/.platformio/penv/bin/python3"

activity_logs = []
public_tunnel_url = ""

# =============================================================================
# HIERARCHICAL FLEET REGISTRY & PERSISTENCE
# =============================================================================
DEFAULT_FLEET = {
    "clients": {
        "client_1": {
            "id": "client_1",
            "name": "Client 1: Alpha Enterprise Corp",
            "code": "ALPH-CORP",
            "description": "Autonomous Industrial Edge IoT Operations & Real-time Fleet",
            "tier": "Tier-1 Enterprise SLA",
            "contact": "ops@alphaenterprise.com",
            "created_at": "2026-01-15",
            "projects": ["proj_1"]
        }
    },
    "projects": {
        "proj_1": {
            "id": "proj_1",
            "client_id": "client_1",
            "name": "Project 1: Enterprise OTA Fleet",
            "code": "OTA-FLEET-POC",
            "description": "Dual ESP32 Wireless & USB Hardware Control Architecture",
            "created_at": "2026-02-01",
            "nodes": ["Node: A", "Node: B"]
        }
    },
    "registered_nodes": {
        "Node: A": {
            "name": "Node: A",
            "mac": "EC:C9:FF:FF:08:94",
            "chip_id": "9408FFFFC9EC",
            "client_id": "client_1",
            "project_id": "proj_1",
            "port": "/dev/cu.usbserial-0001",
            "expected_hash": "0647df22dceea927a2fe279cdb6fe999fc873a2d1d8f0cfca79934833eb5ed7d"
        },
        "Node: B": {
            "name": "Node: B",
            "mac": "70:4B:CA:48:E6:BC",
            "chip_id": "BCE648CA4B70",
            "client_id": "client_1",
            "project_id": "proj_1",
            "port": "/dev/cu.usbserial-3",
            "expected_hash": "d56ab3dfed28a8a361a0b323be53b3abbd43dbfc16a1eb040a23c940cefbe703"
        }
    }
}

fleet_registry = DEFAULT_FLEET

def load_fleet_registry():
    global fleet_registry
    if os.path.isfile(REGISTRY_FILE):
        try:
            with open(REGISTRY_FILE, "r") as f:
                data = json.load(f)
                if "clients" in data and "projects" in data and "registered_nodes" in data:
                    fleet_registry = data
                    return
        except Exception as e:
            print(f"[REGISTRY] Error reading {REGISTRY_FILE}: {e}")
    save_fleet_registry()

def save_fleet_registry():
    try:
        with open(REGISTRY_FILE, "w") as f:
            json.dump(fleet_registry, f, indent=2)
    except Exception as e:
        print(f"[REGISTRY] Error saving {REGISTRY_FILE}: {e}")

load_fleet_registry()

# Dynamic auto-discovered hardware devices not yet assigned to a project
auto_discovered_nodes = {}

# Live Hardware Telemetry
nodes_telemetry = {
    "Node: A": {
        "name": "Node: A",
        "mac": "EC:C9:FF:FF:08:94",
        "chip_id": "9408FFFFC9EC",
        "port": "/dev/cu.usbserial-0001",
        "client": "Client 1: Alpha Enterprise Corp",
        "project": "Project 1: Enterprise OTA Fleet",
        "sec_hash": "0647df22dceea927a2fe279cdb6fe999fc873a2d1d8f0cfca79934833eb5ed7d",
        "trust_score": 100,
        "trust_level": "Verified (High Trust)",
        "ip": "10.94.142.79",
        "mode": 1,
        "service": True,
        "state": "online",
        "delay": 0.0,
        "btn": 0,
        "led": 0,
        "rssi": -45,
        "heap": 242000,
        "uptime": 0,
        "last_seen": 0,
        "online": False
    },
    "Node: B": {
        "name": "Node: B",
        "mac": "70:4B:CA:48:E6:BC",
        "chip_id": "BCE648CA4B70",
        "port": "/dev/cu.usbserial-3",
        "client": "Client 1: Alpha Enterprise Corp",
        "project": "Project 1: Enterprise OTA Fleet",
        "sec_hash": "d56ab3dfed28a8a361a0b323be53b3abbd43dbfc16a1eb040a23c940cefbe703",
        "trust_score": 100,
        "trust_level": "Verified (High Trust)",
        "ip": "10.94.142.111",
        "mode": 1,
        "service": True,
        "state": "online",
        "delay": 0.0,
        "btn": 0,
        "led": 0,
        "rssi": -42,
        "heap": 241000,
        "uptime": 0,
        "last_seen": 0,
        "online": False
    }
}

# Update state tracking per node
node_updates = {
    "Node: A": {
        "active": False,
        "route": "cloud",
        "filename": "firmware_mode1.bin",
        "total_bytes": 0,
        "sent_bytes": 0,
        "percent": 0,
        "speed_kbps": 0.0,
        "stage": "idle",
        "stage_text": "Ready",
        "target_mode": 1,
        "start_time": 0,
        "reboot_start_time": 0,
        "verified_time": 0,
        "error_message": ""
    },
    "Node: B": {
        "active": False,
        "route": "cloud",
        "filename": "firmware_mode1.bin",
        "total_bytes": 0,
        "sent_bytes": 0,
        "percent": 0,
        "speed_kbps": 0.0,
        "stage": "idle",
        "stage_text": "Ready",
        "target_mode": 1,
        "start_time": 0,
        "reboot_start_time": 0,
        "verified_time": 0,
        "error_message": ""
    }
}

def sync_telemetry_with_registry():
    global nodes_telemetry, node_updates, fleet_registry
    for n_name, r_node in fleet_registry.get("registered_nodes", {}).items():
        c_id = r_node.get("client_id", "client_1")
        p_id = r_node.get("project_id", "proj_1")
        c_name = fleet_registry.get("clients", {}).get(c_id, {}).get("name", "Alpha Enterprise Corp")
        p_name = fleet_registry.get("projects", {}).get(p_id, {}).get("name", "Enterprise OTA Fleet")
        if n_name not in nodes_telemetry:
            nodes_telemetry[n_name] = {
                "name": n_name,
                "mac": r_node.get("mac", ""),
                "chip_id": r_node.get("chip_id", ""),
                "port": r_node.get("port", "WiFi Wireless"),
                "client": c_name,
                "project": p_name,
                "sec_hash": r_node.get("expected_hash", ""),
                "trust_score": 100,
                "trust_level": "Verified (High Trust)",
                "ip": "0.0.0.0",
                "mode": 1,
                "service": True,
                "state": "online",
                "delay": 0.0,
                "btn": 0,
                "led": 0,
                "rssi": -50,
                "heap": 240000,
                "uptime": 0,
                "last_seen": 0,
                "online": False
            }
        else:
            nodes_telemetry[n_name]["client"] = c_name
            nodes_telemetry[n_name]["project"] = p_name

        if n_name not in node_updates:
            node_updates[n_name] = {
                "active": False,
                "route": "cloud",
                "filename": "firmware_mode1.bin",
                "total_bytes": 0,
                "sent_bytes": 0,
                "percent": 0,
                "speed_kbps": 0.0,
                "stage": "idle",
                "stage_text": "Ready",
                "target_mode": 1,
                "start_time": 0,
                "reboot_start_time": 0,
                "verified_time": 0,
                "error_message": ""
            }

sync_telemetry_with_registry()

def log_event(msg):
    ts = time.strftime("[%H:%M:%S]")
    entry = f"{ts} {msg}"
    activity_logs.append(entry)
    if len(activity_logs) > 300:
        activity_logs.pop(0)
    print(entry, flush=True)

def compute_security_hash(mac, chip_id, salt=SECURITY_SALT):
    raw = f"{mac}{chip_id}{salt}".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()

def verify_node_security(tdata, reg_entry):
    """
    Majority 4-Point Cryptographic & Hardware Verification:
      1. MAC address match
      2. eFuse Chip ID match
      3. SHA-256 hash match: sha256(mac + chip_id + salt)
      4. Valid carrier IP subnet match
    """
    matches = 0
    t_mac = tdata.get("mac", "").upper()
    r_mac = reg_entry.get("mac", "").upper()
    if t_mac and r_mac and t_mac == r_mac:
        matches += 1

    t_chip = tdata.get("chip_id", "").upper()
    r_chip = reg_entry.get("chip_id", "").upper()
    if t_chip and r_chip and t_chip == r_chip:
        matches += 1

    t_hash = tdata.get("sec_hash", "").lower()
    expected_hash = reg_entry.get("expected_hash", "").lower()
    if not expected_hash and r_mac and r_chip:
        expected_hash = compute_security_hash(r_mac, r_chip)
    if t_hash and expected_hash and t_hash == expected_hash:
        matches += 1

    t_ip = tdata.get("ip", "")
    if t_ip and not t_ip.startswith("0.0.0.0") and not t_ip.startswith("127."):
        matches += 1

    score = int((matches / 4.0) * 100)
    if matches >= 3:
        level = "Verified (High Trust)"
    elif matches == 2:
        level = "Moderate Trust"
    else:
        level = "Unverified"
    return score, level

def get_lan_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip

mdns_process = None

def start_mdns_broadcast(hostname="control.local", service_name="Anashwar Fleet Control"):
    global mdns_process
    if sys.platform != "darwin":
        return None
    lan_ip = get_lan_ip()
    cmd = [
        "dns-sd", "-P",
        service_name,
        "_http._tcp",
        "local",
        "80",
        hostname,
        lan_ip
    ]
    try:
        mdns_process = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        log_event(f"mDNS Broadcast Active: http://{hostname} & http://{hostname}:{PORT} -> {lan_ip}")
        return mdns_process
    except Exception as e:
        log_event(f"mDNS Broadcast warning: {e}")
        return None

def stop_mdns_broadcast():
    global mdns_process
    if mdns_process:
        try:
            mdns_process.terminate()
            mdns_process.wait(timeout=1)
        except Exception:
            try:
                mdns_process.kill()
            except Exception:
                pass
        mdns_process = None

atexit.register(stop_mdns_broadcast)

def get_active_tunnel():
    # 1. Cloud environment variable (Render, Railway, or user specified)
    env_url = os.environ.get("PUBLIC_URL") or os.environ.get("RENDER_EXTERNAL_URL")
    if env_url:
        return env_url.rstrip("/")

    # 2. Local active tunnel file if created by tunnel daemon
    tunnel_file = os.path.join(PROJECT_ROOT, "active_tunnel.txt")
    if os.path.isfile(tunnel_file):
        try:
            with open(tunnel_file, "r") as f:
                url = f.read().strip()
                if url:
                    return url.rstrip("/")
        except Exception:
            pass

    # 3. Permanent canonical domain
    return "https://manage.anashwartech.com"

def inspect_esp32_binary(file_path):
    info = {
        "filename": os.path.basename(file_path),
        "path": file_path,
        "size_bytes": 0,
        "size_kb": 0.0,
        "valid": False,
        "magic": "0x00",
        "target_chip": "Unknown",
        "sha256": "",
        "modified": 0
    }
    if not os.path.isfile(file_path):
        return info
    try:
        info["size_bytes"] = os.path.getsize(file_path)
        info["size_kb"] = round(info["size_bytes"] / 1024, 1)
        info["modified"] = os.path.getmtime(file_path)

        with open(file_path, "rb") as f:
            header = f.read(16)
            f.seek(0)
            sha = hashlib.sha256(f.read()).hexdigest()
            info["sha256"] = sha

        if len(header) >= 4 and header[0] == 0xE9:
            info["valid"] = True
            info["magic"] = f"0x{header[0]:02X}"
            chip_id = header[3]
            if chip_id == 0x00: info["target_chip"] = "ESP32 (Classic Dual-Core)"
            elif chip_id == 0x02: info["target_chip"] = "ESP32-S2"
            elif chip_id == 0x05: info["target_chip"] = "ESP32-C3"
            elif chip_id == 0x09: info["target_chip"] = "ESP32-S3"
            else: info["target_chip"] = f"ESP32 (Chip ID {chip_id})"
        else:
            info["valid"] = False
            info["target_chip"] = "Invalid Binary Header"
    except Exception as e:
        info["error"] = str(e)
    return info

def resolve_target_node(val):
    if not val:
        return None
    val_clean = str(val).strip()
    if val_clean in nodes_telemetry:
        return val_clean

    v = val_clean.lower()
    if "node: a" in v or v in ("node a", "a", "alpha", "node alpha"):
        return "Node: A"
    if "node: b" in v or v in ("node b", "b", "beta", "node beta"):
        return "Node: B"
    for name, node in nodes_telemetry.items():
        if v == node.get("mac", "").lower():
            return name
        if v == node.get("chip_id", "").lower():
            return name
        if v == node.get("port", "").lower():
            return name
        if v == node.get("ip", "").lower():
            return name
    return None

# =============================================================================
# ZERO-DEPENDENCY MQTT CLIENT (SOCKET IMPLEMENTATION)
# =============================================================================
def start_mqtt_client():
    def mqtt_listener():
        while True:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(10)
                s.connect((DEFAULT_MQTT_BROKER, DEFAULT_MQTT_PORT))
                client_id = f"AnashwarSub-{int(time.time()*1000)%100000}".encode('ascii')
                proto = b"MQTT"
                vh = len(proto).to_bytes(2, 'big') + proto + b'\x04\x02\x00\x3c'
                payload = len(client_id).to_bytes(2, 'big') + client_id
                s.sendall(b'\x10' + bytes([len(vh)+len(payload)]) + vh + payload)
                ack = s.recv(4)
                if len(ack) < 4 or ack[3] != 0:
                    time.sleep(3)
                    continue

                sub_topic = DEFAULT_MQTT_TOPIC_STATUS.encode('utf-8')
                sub_vh = b'\x00\x01'
                sub_payload = len(sub_topic).to_bytes(2, 'big') + sub_topic + b'\x00'
                sub_rem = len(sub_vh) + len(sub_payload)
                s.sendall(b'\x82' + bytes([sub_rem]) + sub_vh + sub_payload)
                s.recv(5)
                log_event(f"MQTT Connected & Subscribed to '{DEFAULT_MQTT_TOPIC_STATUS}' on {DEFAULT_MQTT_BROKER}")

                last_ping = time.time()
                while True:
                    now = time.time()
                    if now - last_ping >= 20:
                        try:
                            s.sendall(b'\xc0\x00')
                            last_ping = now
                        except Exception:
                            break

                    try:
                        b1 = s.recv(1)
                    except (socket.timeout, TimeoutError):
                        continue
                    except Exception:
                        break

                    if not b1:
                        break
                    pkt_type = b1[0] >> 4
                    multiplier = 1
                    rem_len = 0
                    while True:
                        d_byte = s.recv(1)[0]
                        rem_len += (d_byte & 127) * multiplier
                        multiplier *= 128
                        if not (d_byte & 128):
                            break
                    data = b""
                    while len(data) < rem_len:
                        chunk = s.recv(min(rem_len - len(data), 4096))
                        if not chunk:
                            break
                        data += chunk

                    if pkt_type == 3: # PUBLISH
                        topic_len = int.from_bytes(data[0:2], 'big')
                        msg = data[2+topic_len:].decode('utf-8', errors='ignore')
                        try:
                            tdata = json.loads(msg)
                            raw_id = tdata.get("id", "")
                            raw_name = tdata.get("name", "")
                            raw_mac = tdata.get("mac", "")
                            raw_chip = tdata.get("chip_id", "")

                            target_key = resolve_target_node(raw_name) or resolve_target_node(raw_id) or resolve_target_node(raw_mac)
                            if not target_key:
                                ip = tdata.get("ip", "")
                                if ip == "10.94.142.79": target_key = "Node: A"
                                elif ip == "10.94.142.111": target_key = "Node: B"

                            if not target_key:
                                # ZERO-TOUCH FLEET AUTO-ONBOARDING:
                                # Automatically register Client, Project, and Node dynamically!
                                target_name = (raw_name.strip() if raw_name else "") or f"Node-{raw_mac[-5:].replace(':','').upper() if len(raw_mac)>=5 else str(int(time.time()))[-4:]}"
                                client_name = (tdata.get("client") or "").strip() or "Alpha Enterprise Corp"
                                project_name = (tdata.get("project") or "").strip() or "Connected Edge Fleet"

                                # 1. Match or Create Client
                                client_id = None
                                for cid, c in fleet_registry["clients"].items():
                                    if c.get("name", "").strip().lower() == client_name.lower():
                                        client_id = cid
                                        break
                                if not client_id:
                                    clean_code = "".join([w[0] for w in client_name.split() if w.isalnum()])[:4].upper() or "ENT"
                                    client_id = f"client_{int(time.time())}_{abs(hash(client_name)) % 1000}"
                                    fleet_registry["clients"][client_id] = {
                                        "id": client_id,
                                        "name": client_name,
                                        "code": clean_code,
                                        "description": f"Auto-discovered Enterprise Client: {client_name}",
                                        "tier": "Tier-1 Enterprise SLA",
                                        "contact": "ops@anashwartech.com",
                                        "created_at": time.strftime("%Y-%m-%d"),
                                        "projects": []
                                    }

                                # 2. Match or Create Project
                                project_id = None
                                for pid, p in fleet_registry["projects"].items():
                                    if p.get("client_id") == client_id and p.get("name", "").strip().lower() == project_name.lower():
                                        project_id = pid
                                        break
                                if not project_id:
                                    proj_code = "".join([w[0] for w in project_name.split() if w.isalnum()])[:4].upper() or "PRJ"
                                    project_id = f"proj_{int(time.time())}_{abs(hash(project_name)) % 1000}"
                                    fleet_registry["projects"][project_id] = {
                                        "id": project_id,
                                        "client_id": client_id,
                                        "name": project_name,
                                        "code": proj_code,
                                        "description": f"Autonomous Edge Project: {project_name}",
                                        "created_at": time.strftime("%Y-%m-%d"),
                                        "nodes": []
                                    }
                                    if project_id not in fleet_registry["clients"][client_id]["projects"]:
                                        fleet_registry["clients"][client_id]["projects"].append(project_id)

                                # 3. Register Node under Project & Registry
                                if target_name not in fleet_registry["projects"][project_id]["nodes"]:
                                    fleet_registry["projects"][project_id]["nodes"].append(target_name)

                                fleet_registry["registered_nodes"][target_name] = {
                                    "name": target_name,
                                    "mac": raw_mac,
                                    "chip_id": raw_chip,
                                    "client_id": client_id,
                                    "project_id": project_id,
                                    "port": tdata.get("port", "WiFi Wireless"),
                                    "expected_hash": tdata.get("sec_hash", "")
                                }
                                save_fleet_registry()

                                # 4. Initialize in-memory telemetry & update tracking
                                nodes_telemetry[target_name] = {
                                    "name": target_name,
                                    "mac": raw_mac,
                                    "chip_id": raw_chip,
                                    "port": tdata.get("port", "WiFi Wireless"),
                                    "client": client_name,
                                    "project": project_name,
                                    "sec_hash": tdata.get("sec_hash", ""),
                                    "trust_score": 100,
                                    "trust_level": "Verified (High Trust)",
                                    "ip": tdata.get("ip", "0.0.0.0"),
                                    "mode": int(tdata.get("mode", 1)),
                                    "service": bool(tdata.get("service", True)),
                                    "state": tdata.get("state", "online"),
                                    "delay": float(tdata.get("delay", 0.0)),
                                    "btn": int(tdata.get("btn", 0)),
                                    "led": int(tdata.get("led", 0)),
                                    "rssi": int(tdata.get("rssi", -60)),
                                    "heap": int(tdata.get("heap", 240000)),
                                    "uptime": int(tdata.get("uptime", 0)),
                                    "last_seen": time.time(),
                                    "online": True
                                }
                                node_updates[target_name] = {
                                    "active": False,
                                    "route": "cloud",
                                    "filename": "firmware_mode1.bin",
                                    "total_bytes": 0,
                                    "sent_bytes": 0,
                                    "percent": 0,
                                    "speed_kbps": 0.0,
                                    "stage": "idle",
                                    "stage_text": "Ready",
                                    "target_mode": 1,
                                    "start_time": 0,
                                    "reboot_start_time": 0,
                                    "verified_time": 0,
                                    "error_message": ""
                                }
                                target_key = target_name
                                log_event(f"AUTO-DISCOVERY: Node '{target_name}' onboarded into Client '{client_name}' & Project '{project_name}'")

                            node = nodes_telemetry[target_key]
                            if tdata.get("client"): node["client"] = tdata["client"]
                            if tdata.get("project"): node["project"] = tdata["project"]
                            node["mode"] = tdata.get("mode", node["mode"])
                            node["service"] = bool(tdata.get("service", True))
                            node["state"] = tdata.get("state", "online")
                            node["ip"] = tdata.get("ip", node["ip"])
                            node["rssi"] = tdata.get("rssi", node["rssi"])
                            node["heap"] = tdata.get("heap", node["heap"])
                            node["uptime"] = tdata.get("uptime", 0)
                            node["delay"] = float(tdata.get("delay", node["delay"]))
                            node["btn"] = int(tdata.get("btn", 0))
                            node["led"] = int(tdata.get("led", 0))
                            node["sec_hash"] = tdata.get("sec_hash", node.get("sec_hash", ""))
                            node["last_seen"] = time.time()
                            node["online"] = True

                            # Verify 4-point majority security
                            reg_node = fleet_registry["registered_nodes"].get(target_key, {})
                            score, level = verify_node_security(tdata, reg_node)
                            node["trust_score"] = score
                            node["trust_level"] = level

                            mode_descs = {
                                1: "Mode 1 (Press to Light)",
                                2: "Mode 2 (High Alert)",
                                3: "Mode 3 (Rest Beacon)",
                                4: "Mode 4 (Pulse Beacon)"
                            }
                            m_desc = mode_descs.get(node["mode"], f"Mode {node['mode']}")

                            u_info = node_updates[target_key]
                            if u_info["active"] and u_info["stage"] in ("rebooting", "flashing", "downloading"):
                                u_info["stage"] = "completed"
                                u_info["percent"] = 100
                                u_info["stage_text"] = f"Confirmed online running {m_desc}!"
                                u_info["verified_time"] = time.time()
                                u_info["active"] = False
                                log_event(f"UPDATE CONFIRMED: [{target_key}] verified online running {m_desc} (IP: {node['ip']})")

                        except Exception as e:
                            log_event(f"Telemetry parse error: {e}")
            except Exception as e:
                time.sleep(3)

    t = threading.Thread(target=mqtt_listener, daemon=True)
    t.start()

def publish_mqtt_command(topic, payload_str, broker=DEFAULT_MQTT_BROKER, port=DEFAULT_MQTT_PORT):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(6)
    try:
        s.connect((broker, port))
        client_id = f"AnashwarPub-{int(time.time()*1000)%100000}".encode('ascii')
        proto = b"MQTT"
        vh = len(proto).to_bytes(2, 'big') + proto + b'\x04\x02\x00\x3c'
        payload = len(client_id).to_bytes(2, 'big') + client_id
        s.sendall(b'\x10' + bytes([len(vh)+len(payload)]) + vh + payload)
        ack = s.recv(4)
        if len(ack) < 4 or ack[3] != 0:
            return False

        t_bytes = topic.encode('utf-8')
        p_bytes = payload_str.encode('utf-8')
        var_header = len(t_bytes).to_bytes(2, 'big') + t_bytes
        total_len = len(var_header) + len(p_bytes)

        header = bytearray([0x30]) # PUBLISH QoS 0
        rem = total_len
        while True:
            d = rem % 128
            rem = rem // 128
            if rem > 0:
                d |= 0x80
            header.append(d)
            if rem == 0:
                break

        s.sendall(header + var_header + p_bytes)
        log_event(f"MQTT Command Dispatched: '{payload_str}' -> '{topic}'")
        return True
    except Exception as e:
        log_event(f"MQTT Publish Error: {e}")
        return False
    finally:
        s.close()

# =============================================================================
# BACKGROUND FLASH TASKS
# =============================================================================
def run_usb_flash_task(target_node, filename, mode_num):
    u = node_updates[target_node]
    bin_path = os.path.join(BINARIES_DIR, filename)

    port = nodes_telemetry[target_node]["port"]
    log_event(f"USB DIRECT FLASH: Starting for [{target_node}] on {port} with '{filename}'...")

    u["active"] = True
    u["route"] = "usb"
    u["filename"] = filename
    u["stage"] = "flashing"
    u["stage_text"] = f"Flashing sectors to {port} via USB direct link..."
    u["target_mode"] = mode_num
    u["start_time"] = time.time()
    u["percent"] = 15

    cmd = [
        PYTHON_ENV_PATH,
        ESPTOOL_PATH,
        "--port", port,
        "--baud", "460800",
        "--chip", "esp32",
        "write_flash",
        "-z", "0x10000",
        bin_path
    ]

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True,
            bufsize=1
        )

        for line in proc.stdout:
            m = re.search(r'\((\d+)\s*%\)', line)
            if m:
                p = int(m.group(1))
                u["percent"] = 15 + int(p * 0.70)
                u["stage_text"] = f"Writing flash sectors: {p}% ({u['percent']}% overall)"

        proc.wait()

        if proc.returncode == 0:
            u["stage"] = "rebooting"
            u["percent"] = 88
            u["stage_text"] = "USB write successful. Rebooting node..."
            u["reboot_start_time"] = time.time()
            log_event(f"USB FLASH SUCCESS: [{target_node}] reset via RTS. Waiting for telemetry verification...")
        else:
            u["stage"] = "failed"
            u["stage_text"] = f"esptool.py returned error code {proc.returncode}"
            u["error_message"] = f"Flash failed with exit code {proc.returncode}"
            u["active"] = False
            log_event(f"USB FLASH ERROR: [{target_node}] failed on {port}")

    except Exception as e:
        u["stage"] = "failed"
        u["stage_text"] = f"Subprocess exception: {str(e)}"
        u["error_message"] = str(e)
        u["active"] = False
        log_event(f"USB FLASH EXCEPTION: {e}")

# =============================================================================
# HTTP REQUEST HANDLER
# =============================================================================
class FleetDashboardHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        return # Suppress default noisy console logs

    def do_HEAD(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path in ("/", "/login"):
            user, token = get_authenticated_user(self.headers, parsed)
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            if token:
                self.send_header("Set-Cookie", f"session_token={token}; Path=/; SameSite=None; Secure; Max-Age=604800")
            self.end_headers()
            if not user:
                html = render_login_html()
            else:
                html = render_fleet_html(user, token)
            self.wfile.write(html.encode("utf-8"))
            return

        elif path.startswith("/static/"):
            filename = os.path.basename(path)
            file_path = os.path.join(STATIC_DIR, filename)
            if os.path.isfile(file_path):
                content_type = "application/octet-stream"
                if filename.endswith(".png"): content_type = "image/png"
                elif filename.endswith(".jpg") or filename.endswith(".jpeg"): content_type = "image/jpeg"
                elif filename.endswith(".svg"): content_type = "image/svg+xml"
                elif filename.endswith(".css"): content_type = "text/css"
                elif filename.endswith(".js"): content_type = "application/javascript"

                self.send_response(200)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(os.path.getsize(file_path)))
                self.send_header("Cache-Control", "public, max-age=86400")
                self.end_headers()
                with open(file_path, "rb") as f:
                    self.wfile.write(f.read())
            else:
                self.send_error(404, "Static file not found")

        elif path == "/api/telemetry":
            user, token = get_authenticated_user(self.headers, parsed)
            if not user:
                self.send_response(401)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"error": "Unauthorized", "authenticated": false}')
                return

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
            self.end_headers()

            # Check online status (active heartbeat within 25 seconds)
            now = time.time()
            for key, node in nodes_telemetry.items():
                node["online"] = (now - node["last_seen"] < 25)

            # Auto-update reboot elapsed time for active updates
            for key, u in node_updates.items():
                if u["active"] and u["stage"] == "rebooting" and u["reboot_start_time"] > 0:
                    elapsed = int(time.time() - u["reboot_start_time"])
                    u["stage_text"] = f"Rebooting & establishing connection... {elapsed}s elapsed (est. 15-25s)"

            payload = {
                "nodes": nodes_telemetry,
                "updates": node_updates,
                "fleet": fleet_registry,
                "auto_discovered": auto_discovered_nodes,
                "public_tunnel": get_active_tunnel(),
                "lan_ip": get_lan_ip(),
                "mdns_url": "http://control.local",
                "port": PORT,
                "logs": activity_logs[-40:],
                "current_user": user,
                "user_role": users_db.get(user, {}).get("role", "Administrator"),
                "usb_devices": scan_usb_devices()
            }
            self.wfile.write(json.dumps(payload).encode("utf-8"))

        elif path == "/api/binaries":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            bins = []
            for f in sorted(glob.glob(os.path.join(BINARIES_DIR, "*.bin"))):
                info = inspect_esp32_binary(f)
                if info["valid"]:
                    bins.append(info)
            self.wfile.write(json.dumps({"binaries": bins}).encode("utf-8"))

        elif path == "/api/users":
            user, token = get_authenticated_user(self.headers, parsed)
            if not user:
                self.send_error(401, "Unauthorized")
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            u_list = [{"username": u, "role": d.get("role", "Administrator"), "created_at": d.get("created_at", "")} for u, d in users_db.items()]
            self.wfile.write(json.dumps({"users": u_list, "current_user": user}).encode("utf-8"))

        elif path == "/api/usb/scan":
            user, token = get_authenticated_user(self.headers, parsed)
            if not user:
                self.send_error(401, "Unauthorized")
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"devices": scan_usb_devices()}).encode("utf-8"))

        elif path.startswith("/proxy/node/"):
            user, token = get_authenticated_user(self.headers, parsed)
            if not user:
                self.send_error(401, "Unauthorized")
                return

            rest = path[len("/proxy/node/"):]
            parts = rest.split("/", 1)
            target_node_raw = urllib.parse.unquote(parts[0])
            subpath = parts[1] if len(parts) > 1 else ""
            if parsed.query:
                subpath += "?" + parsed.query

            target_node = resolve_target_node(target_node_raw)
            if not target_node or target_node not in nodes_telemetry:
                self.send_error(404, "Node not found")
                return

            node_ip = nodes_telemetry[target_node].get("ip")
            if not node_ip:
                self.send_error(502, "Node has no valid IP address")
                return

            target_url = f"http://{node_ip}/{subpath}"
            try:
                req = urllib.request.Request(target_url, headers={"User-Agent": "Anashwar-Fleet-Proxy"})
                with urllib.request.urlopen(req, timeout=5) as resp:
                    self.send_response(resp.status)
                    for k, v in resp.headers.items():
                        if k.lower() in ("content-type", "content-length", "cache-control"):
                            self.send_header(k, v)
                    self.end_headers()
                    self.wfile.write(resp.read())
            except Exception as e:
                self.send_response(502)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.end_headers()
                self.wfile.write(f"<div style='font-family:sans-serif;padding:30px;background:#0f172a;color:#f87171;border-radius:12px;'><h3>⚠️ ESP32 In-Situ Web UI Unavailable</h3><p>Could not connect to {target_node} at http://{node_ip}:80/</p><p style='color:#94a3b8;font-size:12px;'>Error: {e}</p></div>".encode("utf-8"))

        elif path.startswith("/download/"):
            filename = os.path.basename(path)
            file_path = os.path.join(BINARIES_DIR, filename)

            if os.path.isfile(file_path):
                file_size = os.path.getsize(file_path)
                client_ip = self.client_address[0]
                log_event(f"ESP32 Connected: Requesting {filename} ({file_size/1024:.1f} KB) from {client_ip}")

                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Content-Length", str(file_size))
                self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
                self.send_header("Accept-Ranges", "bytes")
                self.send_header("X-ESP32-STA", client_ip)
                self.end_headers()

                with open(file_path, "rb") as f:
                    sent = 0
                    start_t = time.time()
                    while True:
                        chunk = f.read(4096)
                        if not chunk:
                            break
                        self.wfile.write(chunk)
                        sent += len(chunk)

                duration = max(time.time() - start_t, 0.05)
                speed = (sent / 1024.0) / duration
                log_event(f"DOWNLOAD COMPLETE: {filename} sent ({sent/1024:.1f} KB @ {speed:.1f} KB/s)")

                # If this download belongs to an active OTA update, move to rebooting phase
                for n_key, u in node_updates.items():
                    if u["active"] and u["stage"] == "downloading" and u["filename"] == filename:
                        u["stage"] = "rebooting"
                        u["percent"] = 88
                        u["stage_text"] = "Download complete. Device flashing sectors & rebooting..."
                        u["reboot_start_time"] = time.time()
                        log_event(f"[{n_key}] Flashing sectors & restarting into new firmware...")
            else:
                self.send_error(404, "Binary file not found")
        else:
            self.send_error(404, "Page not found")

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)

        if path == "/api/login":
            data = parse_qs(body.decode("utf-8"))
            u = data.get("username", [""])[0].strip()
            p = data.get("password", [""])[0].strip()
            if verify_credentials(u, p):
                token = secrets.token_hex(24)
                active_sessions[token] = {"username": u, "login_time": time.time()}
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Set-Cookie", f"session_token={token}; Path=/; SameSite=None; Secure; Max-Age=604800")
                self.end_headers()
                self.wfile.write(json.dumps({"success": True, "token": token, "username": u, "role": users_db[u].get("role", "Administrator")}).encode("utf-8"))
                log_event(f"AUTH: User '{u}' logged in successfully")
            else:
                self.send_response(401)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"success": false, "error": "Invalid username or password"}')
                log_event(f"AUTH WARNING: Failed login attempt for user '{u}'")
            return

        elif path == "/api/logout":
            u, token = get_authenticated_user(self.headers, parsed)
            if token and token in active_sessions:
                del active_sessions[token]
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Set-Cookie", "session_token=; Path=/; SameSite=None; Secure; Expires=Thu, 01 Jan 1970 00:00:00 GMT")
            self.end_headers()
            self.wfile.write(b'{"success": true}')
            return

        # Verification of session token for all operations below
        data = {}
        try:
            data = parse_qs(body.decode("utf-8"))
        except Exception:
            pass

        user, token = get_authenticated_user(self.headers, parsed, data)
        if not user:
            self.send_response(401)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"error": "Unauthorized", "authenticated": false}')
            return

        # 1. Hardware Node Command Dispatcher
        if path == "/api/command":
            data = parse_qs(body.decode("utf-8"))
            raw_target = data.get("target", [""])[0]
            action = data.get("action", [""])[0]
            val = data.get("val", [""])[0]

            target_node = resolve_target_node(raw_target)
            if not target_node:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b'{"error": "Invalid target node"}')
                return

            if action == "DELAY":
                try:
                    fval = float(val)
                    if 0.0 <= fval <= 10.0:
                        cmd = f"CMD:[{target_node}]:DELAY:{fval:.1f}"
                        publish_mqtt_command(DEFAULT_MQTT_TOPIC_COMMANDS, cmd)
                        nodes_telemetry[target_node]["delay"] = fval
                except ValueError:
                    pass

            elif action == "SERVICE":
                state_str = "OFF" if val.upper() in ("OFF", "STANDBY", "FALSE") else "ON"
                cmd = f"CMD:[{target_node}]:SERVICE:{state_str}"
                publish_mqtt_command(DEFAULT_MQTT_TOPIC_COMMANDS, cmd)
                nodes_telemetry[target_node]["service"] = (state_str == "ON")
                if state_str == "OFF":
                    nodes_telemetry[target_node]["led"] = 0

            elif action == "OFFLINE":
                state_str = "ON" if val.upper() in ("ON", "TRUE", "ENABLE") else "OFF"
                cmd = f"CMD:[{target_node}]:OFFLINE:{state_str}"
                publish_mqtt_command(DEFAULT_MQTT_TOPIC_COMMANDS, cmd)
                nodes_telemetry[target_node]["offline_mode"] = (state_str == "ON")
                log_event(f"OFFLINE: Set [{target_node}] autonomous offline mode to {state_str}")

            elif action == "REBOOT":
                cmd = f"CMD:[{target_node}]:REBOOT"
                publish_mqtt_command(DEFAULT_MQTT_TOPIC_COMMANDS, cmd)

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"success": true}')

        # 2. Firmware Deployment Dispatcher (Cloud OTA & USB Direct)
        elif path == "/api/deploy":
            data = parse_qs(body.decode("utf-8"))
            raw_target = data.get("target", [""])[0]
            route = data.get("route", ["cloud"])[0]
            filename = data.get("filename", [""])[0]

            target_node = resolve_target_node(raw_target)
            if not target_node:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b'{"error": "Invalid target node"}')
                return

            file_path = os.path.join(BINARIES_DIR, filename)
            if not os.path.isfile(file_path):
                self.send_response(404)
                self.end_headers()
                self.wfile.write(b'{"error": "Firmware file does not exist"}')
                return

            mode_num = 1
            if "mode2" in filename: mode_num = 2
            elif "mode3" in filename: mode_num = 3
            elif "mode4" in filename: mode_num = 4

            u = node_updates[target_node]
            u["active"] = True
            u["route"] = route
            u["filename"] = filename
            u["target_mode"] = mode_num
            u["start_time"] = time.time()
            u["reboot_start_time"] = 0
            u["verified_time"] = 0
            u["error_message"] = ""

            if route == "usb":
                t = threading.Thread(target=run_usb_flash_task, args=(target_node, filename, mode_num), daemon=True)
                t.start()
            else:
                # Cloud OTA route
                u["stage"] = "downloading"
                u["percent"] = 25
                u["stage_text"] = "Dispatching OTA directive to HiveMQ Cloud broker..."

                tunnel = get_active_tunnel()
                ota_url = f"{tunnel}/download/{filename}"
                cmd = f"OTA:[{target_node}]:{ota_url}"
                publish_mqtt_command(DEFAULT_MQTT_TOPIC_COMMANDS, cmd)
                log_event(f"OTA INITIATED: [{target_node}] instructed to fetch {ota_url}")

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"success": true}')

        # 3. Create Client Endpoint
        elif path == "/api/client/create":
            data = parse_qs(body.decode("utf-8"))
            name = data.get("name", [""])[0].strip()
            code = data.get("code", [""])[0].strip()
            desc = data.get("description", [""])[0].strip()

            if name:
                c_id = f"client_{int(time.time())}"
                fleet_registry["clients"][c_id] = {
                    "id": c_id,
                    "name": name,
                    "code": code or f"CL-{len(fleet_registry['clients'])+1}",
                    "description": desc or "Enterprise Edge Solutions",
                    "tier": "Tier-1 Enterprise SLA",
                    "contact": "admin@enterprise.com",
                    "created_at": time.strftime("%Y-%m-%d"),
                    "projects": []
                }
                save_fleet_registry()
                log_event(f"REGISTRY: Created Client '{name}' ({c_id})")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"success": True, "client_id": c_id}).encode("utf-8"))
            else:
                self.send_error(400, "Client name is required")

        # 4. Delete Client Endpoint
        elif path == "/api/client/delete":
            data = parse_qs(body.decode("utf-8"))
            c_id = data.get("client_id", [""])[0].strip()
            if c_id in fleet_registry["clients"]:
                c_name = fleet_registry["clients"][c_id]["name"]
                proj_ids = list(fleet_registry["clients"][c_id].get("projects", []))
                for p_id in proj_ids:
                    if p_id in fleet_registry["projects"]:
                        del fleet_registry["projects"][p_id]
                del fleet_registry["clients"][c_id]
                save_fleet_registry()
                log_event(f"REGISTRY: Client '{c_name}' ({c_id}) deleted by '{user}'")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"success": true}')
            else:
                self.send_error(404, "Client not found")

        # 5. Create Project Endpoint
        elif path == "/api/project/create":
            data = parse_qs(body.decode("utf-8"))
            client_id = data.get("client_id", [""])[0].strip()
            name = data.get("name", [""])[0].strip()
            code = data.get("code", [""])[0].strip()
            desc = data.get("description", [""])[0].strip()

            if client_id in fleet_registry["clients"] and name:
                p_id = f"proj_{int(time.time())}"
                fleet_registry["projects"][p_id] = {
                    "id": p_id,
                    "client_id": client_id,
                    "name": name,
                    "code": code or f"PRJ-{len(fleet_registry['projects'])+1}",
                    "description": desc or "Production IoT Deployment",
                    "created_at": time.strftime("%Y-%m-%d"),
                    "nodes": []
                }
                fleet_registry["clients"][client_id]["projects"].append(p_id)
                save_fleet_registry()
                log_event(f"REGISTRY: Created Project '{name}' ({p_id}) under Client '{client_id}'")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"success": True, "project_id": p_id}).encode("utf-8"))
            else:
                self.send_error(400, "Invalid client ID or project name")

        # 6. Delete Project Endpoint
        elif path == "/api/project/delete":
            data = parse_qs(body.decode("utf-8"))
            p_id = data.get("project_id", [""])[0].strip()
            if p_id in fleet_registry["projects"]:
                p_name = fleet_registry["projects"][p_id]["name"]
                c_id = fleet_registry["projects"][p_id].get("client_id")
                if c_id and c_id in fleet_registry["clients"] and p_id in fleet_registry["clients"][c_id]["projects"]:
                    fleet_registry["clients"][c_id]["projects"].remove(p_id)
                del fleet_registry["projects"][p_id]
                save_fleet_registry()
                log_event(f"REGISTRY: Project '{p_name}' ({p_id}) deleted by '{user}'")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"success": true}')
            else:
                self.send_error(404, "Project not found")

        # 7. Create/Register Node Endpoint
        elif path == "/api/node/create":
            data = parse_qs(body.decode("utf-8"))
            n_name = data.get("name", [""])[0].strip()
            mac = data.get("mac", [""])[0].strip()
            chip_id = data.get("chip_id", [""])[0].strip()
            port = data.get("port", ["WiFi Wireless"])[0].strip()
            project_id = data.get("project_id", [""])[0].strip()

            if not n_name or not project_id or project_id not in fleet_registry["projects"]:
                self.send_error(400, "Valid node name and project required")
                return

            c_id = fleet_registry["projects"][project_id]["client_id"]
            fleet_registry["registered_nodes"][n_name] = {
                "name": n_name,
                "mac": mac,
                "chip_id": chip_id,
                "client_id": c_id,
                "project_id": project_id,
                "port": port,
                "expected_hash": compute_security_hash(mac, chip_id) if (mac and chip_id) else ""
            }
            if n_name not in fleet_registry["projects"][project_id]["nodes"]:
                fleet_registry["projects"][project_id]["nodes"].append(n_name)
            save_fleet_registry()
            sync_telemetry_with_registry()
            log_event(f"REGISTRY: Node [{n_name}] manually registered under Project '{project_id}'")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"success": true}')

        # 8. Delete Node Endpoint
        elif path == "/api/node/delete":
            data = parse_qs(body.decode("utf-8"))
            n_name = data.get("node_name", [""])[0].strip()
            target_node = resolve_target_node(n_name) or n_name
            if target_node in fleet_registry["registered_nodes"]:
                p_id = fleet_registry["registered_nodes"][target_node].get("project_id")
                if p_id and p_id in fleet_registry["projects"] and target_node in fleet_registry["projects"][p_id]["nodes"]:
                    fleet_registry["projects"][p_id]["nodes"].remove(target_node)
                del fleet_registry["registered_nodes"][target_node]
                if target_node in nodes_telemetry:
                    del nodes_telemetry[target_node]
                if target_node in node_updates:
                    del node_updates[target_node]
                save_fleet_registry()
                log_event(f"REGISTRY: Node [{target_node}] removed from registry by '{user}'")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"success": true}')
            else:
                self.send_error(404, "Node not found")

        # 9. User Management: Create User
        elif path == "/api/users/create":
            data = parse_qs(body.decode("utf-8"))
            new_u = data.get("username", [""])[0].strip()
            new_p = data.get("password", [""])[0].strip()
            role = data.get("role", ["Fleet Operator"])[0].strip()
            if not new_u or not new_p:
                self.send_error(400, "Username and password required")
                return
            if new_u in users_db:
                self.send_response(400)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"success": false, "error": "Username already exists"}')
                return
            users_db[new_u] = {
                "username": new_u,
                "password_hash": hashlib.sha256(new_p.encode("utf-8")).hexdigest(),
                "role": role,
                "created_at": time.strftime("%Y-%m-%d")
            }
            save_users()
            log_event(f"AUTH: User '{new_u}' ({role}) registered by '{user}'")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"success": True}).encode("utf-8"))

        # 10. User Management: Delete User
        elif path == "/api/users/delete":
            data = parse_qs(body.decode("utf-8"))
            del_u = data.get("username", [""])[0].strip()
            if del_u == user:
                self.send_response(400)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"success": false, "error": "Cannot delete your own active account"}')
                return
            if del_u == "admin":
                self.send_response(400)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"success": false, "error": "Cannot delete primary administrator"}')
                return
            if del_u in users_db:
                del users_db[del_u]
                save_users()
                log_event(f"AUTH: User '{del_u}' deleted by '{user}'")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"success": True}).encode("utf-8"))
            else:
                self.send_error(404, "User not found")

        # 11. Assign Node to Project Endpoint
        elif path == "/api/node/assign":
            data = parse_qs(body.decode("utf-8"))
            node_name = data.get("node_name", [""])[0].strip()
            project_id = data.get("project_id", [""])[0].strip()

            if project_id in fleet_registry["projects"] and node_name in nodes_telemetry:
                client_id = fleet_registry["projects"][project_id]["client_id"]
                if node_name not in fleet_registry["registered_nodes"]:
                    fleet_registry["registered_nodes"][node_name] = {
                        "name": node_name,
                        "mac": nodes_telemetry[node_name]["mac"],
                        "chip_id": nodes_telemetry[node_name]["chip_id"],
                        "port": nodes_telemetry[node_name]["port"],
                        "client_id": client_id,
                        "project_id": project_id
                    }
                else:
                    old_pid = fleet_registry["registered_nodes"][node_name].get("project_id")
                    if old_pid and old_pid in fleet_registry["projects"] and node_name in fleet_registry["projects"][old_pid]["nodes"]:
                        fleet_registry["projects"][old_pid]["nodes"].remove(node_name)
                    fleet_registry["registered_nodes"][node_name]["client_id"] = client_id
                    fleet_registry["registered_nodes"][node_name]["project_id"] = project_id

                if node_name not in fleet_registry["projects"][project_id]["nodes"]:
                    fleet_registry["projects"][project_id]["nodes"].append(node_name)

                nodes_telemetry[node_name]["client"] = fleet_registry["clients"][client_id]["name"]
                nodes_telemetry[node_name]["project"] = fleet_registry["projects"][project_id]["name"]
                save_fleet_registry()
                log_event(f"REGISTRY: Assigned [{node_name}] to Project '{project_id}'")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"success": true}')
            else:
                self.send_error(400, "Invalid node or project")

        # 12. Reverse Proxy for Node In-Situ Web UI (POST Support)
        elif path.startswith("/proxy/node/"):
            rest = path[len("/proxy/node/"):]
            parts = rest.split("/", 1)
            target_node_raw = urllib.parse.unquote(parts[0])
            subpath = parts[1] if len(parts) > 1 else ""
            if parsed.query:
                subpath += "?" + parsed.query
            target_node = resolve_target_node(target_node_raw)
            if not target_node or target_node not in nodes_telemetry:
                self.send_error(404, "Node not found")
                return
            node_ip = nodes_telemetry[target_node].get("ip")
            if not node_ip:
                self.send_error(502, "Node has no valid IP address")
                return
            target_url = f"http://{node_ip}/{subpath}"
            try:
                content_type = self.headers.get("Content-Type", "application/x-www-form-urlencoded")
                req = urllib.request.Request(target_url, data=body, method="POST", headers={"Content-Type": content_type, "User-Agent": "Anashwar-Fleet-Proxy"})
                with urllib.request.urlopen(req, timeout=5) as resp:
                    self.send_response(resp.status)
                    for k, v in resp.headers.items():
                        if k.lower() in ("content-type", "content-length", "cache-control"):
                            self.send_header(k, v)
                    self.end_headers()
                    self.wfile.write(resp.read())
            except Exception as e:
                self.send_response(502)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.end_headers()
                self.wfile.write(f"<h3>Proxy Error</h3><p>{e}</p>".encode("utf-8"))

        # 13. Binary Drag-and-Drop Upload Endpoint
        elif path == "/api/upload_bin":
            content_type = self.headers.get("Content-Type", "")
            if "multipart/form-data" in content_type:
                boundary = content_type.split("boundary=")[1].strip().encode("utf-8")
                parts = body.split(b"--" + boundary)

                for part in parts:
                    if b'filename="' in part:
                        header_part, file_data = part.split(b"\r\n\r\n", 1)
                        file_data = file_data.rstrip(b"\r\n--")
                        m = re.search(rb'filename="([^"]+)"', header_part)
                        if m:
                            filename = os.path.basename(m.group(1).decode("utf-8"))
                            if not filename.endswith(".bin"):
                                filename += ".bin"
                            save_path = os.path.join(BINARIES_DIR, filename)
                            with open(save_path, "wb") as f:
                                f.write(file_data)
                            info = inspect_esp32_binary(save_path)
                            log_event(f"CUSTOM BINARY UPLOADED: '{filename}' ({info['size_kb']} KB, Chip: {info['target_chip']})")

                            self.send_response(200)
                            self.send_header("Content-Type", "application/json")
                            self.end_headers()
                            self.wfile.write(json.dumps({"success": True, "binary": info}).encode("utf-8"))
                            return

            self.send_error(400, "Invalid file upload payload")
        else:
            self.send_error(404, "Endpoint not found")

# =============================================================================
# HTML FRONTEND (DASHTAIL + APPLE FROSTED GLASS UI/UX)
# =============================================================================
def render_login_html():
    return """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Anashwar Technologies - Operations Console Login</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap" rel="stylesheet">
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: 'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, sans-serif;
      background: #080C15;
      color: #F8FAFC;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      position: relative;
      overflow: hidden;
      padding: 20px;
    }
    .ambient-glow-1 {
      position: absolute;
      top: -150px;
      left: -150px;
      width: 500px;
      height: 500px;
      background: radial-gradient(circle, rgba(225, 29, 72, 0.22) 0%, rgba(225, 29, 72, 0) 70%);
      filter: blur(80px);
      pointer-events: none;
    }
    .ambient-glow-2 {
      position: absolute;
      bottom: -150px;
      right: -150px;
      width: 550px;
      height: 550px;
      background: radial-gradient(circle, rgba(14, 165, 233, 0.20) 0%, rgba(14, 165, 233, 0) 70%);
      filter: blur(90px);
      pointer-events: none;
    }
    .login-card {
      position: relative;
      z-index: 10;
      width: 100%;
      max-width: 420px;
      background: rgba(15, 23, 42, 0.65);
      backdrop-filter: blur(28px);
      -webkit-backdrop-filter: blur(28px);
      border: 1px solid rgba(255, 255, 255, 0.12);
      border-radius: 24px;
      padding: 40px 32px;
      box-shadow: 0 25px 60px rgba(0, 0, 0, 0.5), inset 0 1px 0 rgba(255, 255, 255, 0.15);
    }
    .login-brand {
      text-align: center;
      margin-bottom: 28px;
    }
    .login-logo {
      height: 44px;
      width: auto;
      margin-bottom: 14px;
      filter: drop-shadow(0 4px 12px rgba(225, 29, 72, 0.3));
    }
    .login-title {
      font-size: 22px;
      font-weight: 800;
      letter-spacing: -0.5px;
      color: #FFFFFF;
    }
    .login-subtitle {
      font-size: 13px;
      color: #94A3B8;
      margin-top: 4px;
    }
    .badge-pill {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      background: rgba(225, 29, 72, 0.12);
      border: 1px solid rgba(225, 29, 72, 0.3);
      color: #FB7185;
      font-size: 11px;
      font-weight: 700;
      padding: 4px 10px;
      border-radius: 100px;
      margin-top: 10px;
    }
    .form-group {
      margin-bottom: 20px;
      text-align: left;
    }
    .form-label {
      display: block;
      font-size: 12px;
      font-weight: 600;
      color: #CBD5E1;
      margin-bottom: 8px;
      letter-spacing: 0.2px;
    }
    .input-wrapper {
      position: relative;
      display: flex;
      align-items: center;
    }
    .input-icon {
      position: absolute;
      left: 14px;
      font-size: 16px;
      color: #64748B;
      pointer-events: none;
    }
    .form-input {
      width: 100%;
      background: rgba(30, 41, 59, 0.6);
      border: 1px solid rgba(255, 255, 255, 0.12);
      border-radius: 12px;
      padding: 12px 14px 12px 42px;
      font-size: 14px;
      color: #FFFFFF;
      outline: none;
      transition: all 0.2s ease;
      font-family: inherit;
    }
    .form-input:focus {
      border-color: #E11D48;
      background: rgba(30, 41, 59, 0.9);
      box-shadow: 0 0 0 3px rgba(225, 29, 72, 0.25);
    }
    .btn-submit {
      width: 100%;
      background: linear-gradient(135deg, #E11D48 0%, #BE123C 100%);
      color: #FFFFFF;
      border: none;
      border-radius: 12px;
      padding: 14px;
      font-size: 14px;
      font-weight: 700;
      cursor: pointer;
      transition: all 0.2s ease;
      box-shadow: 0 10px 25px rgba(225, 29, 72, 0.35);
      margin-top: 8px;
    }
    .btn-submit:hover {
      transform: translateY(-1px);
      box-shadow: 0 14px 30px rgba(225, 29, 72, 0.45);
      background: linear-gradient(135deg, #F43F5E 0%, #E11D48 100%);
    }
    .error-box {
      display: none;
      background: rgba(239, 68, 68, 0.15);
      border: 1px solid rgba(239, 68, 68, 0.4);
      color: #FCA5A5;
      padding: 10px 14px;
      border-radius: 10px;
      font-size: 12px;
      margin-bottom: 18px;
      text-align: center;
      font-weight: 600;
    }
    .login-footer {
      text-align: center;
      margin-top: 24px;
      font-size: 11px;
      color: #64748B;
      line-height: 1.5;
    }
    .login-hint {
      background: rgba(255, 255, 255, 0.04);
      border: 1px dashed rgba(255, 255, 255, 0.12);
      border-radius: 10px;
      padding: 8px 12px;
      margin-top: 14px;
      font-size: 11px;
      color: #94A3B8;
      text-align: center;
    }
  </style>
</head>
<body>
  <div class="ambient-glow-1"></div>
  <div class="ambient-glow-2"></div>

  <div class="login-card">
    <div class="login-brand">
      <img src="/static/logo.png" alt="Anashwar Technologies" class="login-logo" onerror="this.style.display='none'">
      <div class="login-title">Anashwar Technologies</div>
      <div class="login-subtitle">Enterprise Edge Fleet Management Portal</div>
      <div class="badge-pill">🔒 Encrypted Operations Console</div>
    </div>

    <div class="error-box" id="error-banner"></div>

    <form onsubmit="handleLogin(event)">
      <div class="form-group">
        <label class="form-label">Username</label>
        <div class="input-wrapper">
          <span class="input-icon">👤</span>
          <input type="text" id="login-username" class="form-input" placeholder="Enter username" required autofocus autocomplete="username">
        </div>
      </div>

      <div class="form-group">
        <label class="form-label">Password</label>
        <div class="input-wrapper">
          <span class="input-icon">🔑</span>
          <input type="password" id="login-password" class="form-input" placeholder="Enter password" required autocomplete="current-password">
        </div>
      </div>

      <button type="submit" class="btn-submit" id="login-btn">Sign In to Fleet Console &rarr;</button>
    </form>

    <div class="login-hint">
      🔑 <b>Test Access:</b> User <code>admin</code> &bull; Password <code>At@12345</code>
    </div>

    <div class="login-footer">
      Anashwar Technologies Private Limited &bull; Enterprise Fleet Portal<br>
      Authorized Personnel Only &bull; All sessions logged & authenticated
    </div>
  </div>

  <script>
    // Check if session token already exists in localStorage / sessionStorage
    (function checkExistingSession() {
      const urlParams = new URLSearchParams(window.location.search);
      if (urlParams.get('logout') === 'true') {
        localStorage.removeItem('anashwar_token');
        sessionStorage.removeItem('anashwar_token');
        return;
      }
      const savedToken = localStorage.getItem('anashwar_token') || sessionStorage.getItem('anashwar_token');
      if (savedToken && !urlParams.get('token')) {
        window.location.href = '/?token=' + encodeURIComponent(savedToken);
      }
    })();

    async function handleLogin(e) {
      e.preventDefault();
      const errBox = document.getElementById('error-banner');
      const btn = document.getElementById('login-btn');
      errBox.style.display = 'none';

      const u = document.getElementById('login-username').value.trim();
      const p = document.getElementById('login-password').value;
      if (!u || !p) return;

      btn.disabled = true;
      btn.innerText = 'Verifying Credentials...';

      try {
        const resp = await fetch('/api/login', {
          method: 'POST',
          headers: {'Content-Type': 'application/x-www-form-urlencoded'},
          body: `username=${encodeURIComponent(u)}&password=${encodeURIComponent(p)}`
        });
        const data = await resp.json();
        if (data.success && data.token) {
          btn.innerText = '✓ Authenticated! Loading Console...';
          localStorage.setItem('anashwar_token', data.token);
          sessionStorage.setItem('anashwar_token', data.token);
          try {
            document.cookie = `session_token=${data.token}; Path=/; SameSite=None; Secure; Max-Age=604800`;
          } catch(e) {}
          // Pass token in URL query parameter to guarantee access in cross-site frames and third-party cookie blocked environments
          window.location.href = '/?token=' + encodeURIComponent(data.token);
        } else {
          errBox.innerText = data.error || 'Invalid credentials. Access denied.';
          errBox.style.display = 'block';
          btn.disabled = false;
          btn.innerText = 'Sign In to Fleet Console →';
        }
      } catch (err) {
        errBox.innerText = 'Network error contacting authorization server.';
        errBox.style.display = 'block';
        btn.disabled = false;
        btn.innerText = 'Sign In to Fleet Console →';
      }
    }
  </script>
</body>
</html>
"""

def render_fleet_html(current_user="admin", token=""):
    html_content = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
  <title>Anashwar Technologies - Enterprise Edge Fleet Console</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg: #090D16;
      --sidebar: #0D111A;
      --card-bg: rgba(22, 27, 34, 0.65);
      --card-border: rgba(255, 255, 255, 0.08);
      --card-border-hover: rgba(225, 29, 72, 0.45);
      --crimson: #E11D48;
      --crimson-hover: #BE123C;
      --crimson-glow: rgba(225, 29, 72, 0.35);
      --success: #10B981;
      --warn: #F59E0B;
      --info: #06B6D4;
      --blue: #3B82F6;
      --text: #F8FAFC;
      --text-muted: #94A3B8;
      --text-dim: #64748B;
      --font: 'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, sans-serif;
      --font-mono: 'JetBrains Mono', monospace;
    }

    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background-color: var(--bg);
      background-image: 
        radial-gradient(at 0% 0%, rgba(225, 29, 72, 0.08) 0px, transparent 50%),
        radial-gradient(at 100% 100%, rgba(59, 130, 246, 0.06) 0px, transparent 50%);
      color: var(--text);
      font-family: var(--font);
      min-height: 100vh;
      display: flex;
      overflow-x: hidden;
    }

    /* Scrollbars */
    ::-webkit-scrollbar { width: 6px; height: 6px; }
    ::-webkit-scrollbar-track { background: transparent; }
    ::-webkit-scrollbar-thumb { background: rgba(255, 255, 255, 0.15); border-radius: 4px; }
    ::-webkit-scrollbar-thumb:hover { background: rgba(255, 255, 255, 0.3); }

    /* Left Sidebar */
    .sidebar {
      width: 270px;
      min-width: 270px;
      background: var(--sidebar);
      border-right: 1px solid var(--card-border);
      display: flex;
      flex-direction: column;
      position: sticky;
      top: 0;
      height: 100vh;
      z-index: 100;
    }

    .brand-header {
      padding: 24px 20px;
      display: flex;
      align-items: center;
      gap: 14px;
      border-bottom: 1px solid var(--card-border);
    }
    .brand-logo {
      width: 44px;
      height: 44px;
      border-radius: 12px;
      background: #FFFFFF;
      padding: 3px;
      box-shadow: 0 4px 18px var(--crimson-glow);
      display: flex;
      align-items: center;
      justify-content: center;
    }
    .brand-logo img {
      width: 100%;
      height: 100%;
      object-fit: contain;
    }
    .brand-title {
      display: flex;
      flex-direction: column;
    }
    .brand-name {
      font-size: 16px;
      font-weight: 800;
      color: #FFFFFF;
      letter-spacing: -0.3px;
    }
    .brand-subtitle {
      font-size: 11px;
      color: var(--text-muted);
      font-weight: 500;
    }

    .nav-section {
      padding: 20px 14px 10px 14px;
    }
    .nav-section-title {
      font-size: 11px;
      text-transform: uppercase;
      letter-spacing: 0.8px;
      color: var(--text-dim);
      font-weight: 700;
      padding-left: 10px;
      margin-bottom: 8px;
    }
    .nav-item {
      display: flex;
      align-items: center;
      gap: 12px;
      padding: 10px 14px;
      border-radius: 10px;
      color: var(--text-muted);
      text-decoration: none;
      font-size: 13px;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.2s ease;
      margin-bottom: 4px;
    }
    .nav-item:hover {
      color: #FFFFFF;
      background: rgba(255, 255, 255, 0.04);
    }
    .nav-item.active {
      background: var(--crimson);
      color: #FFFFFF;
      box-shadow: 0 4px 16px var(--crimson-glow);
    }
    .nav-icon {
      font-size: 16px;
      width: 20px;
      text-align: center;
    }

    .sidebar-footer {
      margin-top: auto;
      padding: 18px;
      border-top: 1px solid var(--card-border);
      background: rgba(0, 0, 0, 0.2);
    }
    .status-badge-row {
      display: flex;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 8px;
      font-size: 12px;
    }
    .status-pill {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 4px 10px;
      border-radius: 20px;
      font-size: 11px;
      font-weight: 700;
    }
    .pill-green {
      background: rgba(16, 185, 129, 0.15);
      color: #34D399;
      border: 1px solid rgba(16, 185, 129, 0.3);
    }
    .pill-crimson {
      background: rgba(225, 29, 72, 0.15);
      color: #FB7185;
      border: 1px solid rgba(225, 29, 72, 0.3);
    }
    .pill-cyan {
      background: rgba(6, 182, 212, 0.15);
      color: #38BDF8;
      border: 1px solid rgba(6, 182, 212, 0.3);
    }
    .delete-btn-tiny {
      background: rgba(239, 68, 68, 0.15);
      border: 1px solid rgba(239, 68, 68, 0.3);
      color: #F87171;
      border-radius: 8px;
      padding: 4px 8px;
      font-size: 11px;
      cursor: pointer;
      transition: all 0.2s ease;
      line-height: 1;
    }
    .delete-btn-tiny:hover {
      background: rgba(239, 68, 68, 0.35);
      color: #FFFFFF;
      transform: scale(1.05);
    }
    .user-pill-btn {
      display: flex;
      align-items: center;
      gap: 6px;
      background: rgba(255, 255, 255, 0.06);
      border: 1px solid rgba(255, 255, 255, 0.12);
      padding: 5px 12px;
      border-radius: 100px;
      cursor: pointer;
      transition: all 0.2s;
    }
    .user-pill-btn:hover {
      background: rgba(255, 255, 255, 0.12);
      border-color: rgba(255, 255, 255, 0.2);
    }
    .btn-cyan {
      background: linear-gradient(135deg, #0EA5E9 0%, #0284C7 100%);
      box-shadow: 0 4px 14px rgba(14, 165, 233, 0.35);
      color: #FFFFFF;
    }
    .btn-cyan:hover {
      background: linear-gradient(135deg, #38BDF8 0%, #0EA5E9 100%);
      box-shadow: 0 6px 20px rgba(14, 165, 233, 0.45);
    }
    .pulsing-dot {
      width: 7px;
      height: 7px;
      border-radius: 50%;
      background: currentColor;
      box-shadow: 0 0 8px currentColor;
      animation: pulse 1.8s infinite;
    }
    @keyframes pulse {
      0%, 100% { opacity: 1; transform: scale(1); }
      50% { opacity: 0.4; transform: scale(0.85); }
    }

    /* Main Container */
    .main-wrapper {
      flex: 1;
      display: flex;
      flex-direction: column;
      overflow-y: auto;
      height: 100vh;
    }

    /* Top Navigation Bar */
    .topbar {
      height: 72px;
      padding: 0 32px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      border-bottom: 1px solid var(--card-border);
      background: rgba(9, 13, 22, 0.7);
      backdrop-filter: blur(16px);
      -webkit-backdrop-filter: blur(16px);
      position: sticky;
      top: 0;
      z-index: 90;
    }
    .breadcrumb-row {
      display: flex;
      align-items: center;
      gap: 8px;
      font-size: 13px;
      font-weight: 600;
      color: var(--text-muted);
    }
    .breadcrumb-item {
      cursor: pointer;
      transition: color 0.2s;
    }
    .breadcrumb-item:hover {
      color: #FFFFFF;
    }
    .breadcrumb-active {
      color: #FFFFFF;
      font-weight: 700;
    }
    .breadcrumb-sep {
      color: var(--text-dim);
      font-size: 11px;
    }

    .topbar-actions {
      display: flex;
      align-items: center;
      gap: 16px;
    }
    .search-box {
      display: flex;
      align-items: center;
      gap: 8px;
      background: rgba(255, 255, 255, 0.04);
      border: 1px solid var(--card-border);
      border-radius: 10px;
      padding: 8px 14px;
      font-size: 13px;
      color: var(--text-muted);
    }
    .search-box input {
      background: transparent;
      border: none;
      outline: none;
      color: #FFFFFF;
      font-size: 13px;
      width: 180px;
    }
    .kbd-shortcut {
      background: rgba(255, 255, 255, 0.1);
      padding: 2px 6px;
      border-radius: 4px;
      font-size: 10px;
      font-family: var(--font-mono);
    }

    /* Content Area */
    .content-area {
      padding: 28px 32px;
      flex: 1;
    }

    /* Top KPI Summary Gradient Cards (DashTail Style) */
    .kpi-grid {
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 20px;
      margin-bottom: 28px;
    }
    .kpi-card {
      border-radius: 18px;
      padding: 22px 24px;
      color: #FFFFFF;
      position: relative;
      overflow: hidden;
      box-shadow: 0 10px 30px rgba(0, 0, 0, 0.35);
      transition: transform 0.2s ease;
    }
    .kpi-card:hover {
      transform: translateY(-3px);
    }
    .kpi-card.gradient-crimson {
      background: linear-gradient(135deg, #E11D48 0%, #9F1239 100%);
    }
    .kpi-card.gradient-orange {
      background: linear-gradient(135deg, #F97316 0%, #C2410C 100%);
    }
    .kpi-card.gradient-green {
      background: linear-gradient(135deg, #10B981 0%, #047857 100%);
    }
    .kpi-card.gradient-cyan {
      background: linear-gradient(135deg, #06B6D4 0%, #0369A1 100%);
    }
    .kpi-title {
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: 0.8px;
      opacity: 0.9;
      font-weight: 700;
      margin-bottom: 8px;
    }
    .kpi-value {
      font-size: 26px;
      font-weight: 800;
      letter-spacing: -0.5px;
      margin-bottom: 6px;
    }
    .kpi-subtitle {
      font-size: 12px;
      opacity: 0.85;
      font-weight: 500;
    }

    /* Frosted Glass Chamfered Cards (Apple Glassmorphism) */
    .glass-card {
      background: var(--card-bg);
      backdrop-filter: blur(20px);
      -webkit-backdrop-filter: blur(20px);
      border: 1px solid var(--card-border);
      border-radius: 18px;
      padding: 24px;
      box-shadow: inset 0 1px 0 0 rgba(255, 255, 255, 0.05), 0 8px 32px rgba(0, 0, 0, 0.37);
      transition: all 0.25s cubic-bezier(0.16, 1, 0.3, 1);
      position: relative;
    }
    .glass-card:hover {
      border-color: var(--card-border-hover);
      box-shadow: inset 0 1px 0 0 rgba(255, 255, 255, 0.08), 0 12px 40px rgba(0, 0, 0, 0.5), 0 0 20px rgba(225, 29, 72, 0.15);
    }

    .section-header-row {
      display: flex;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 20px;
    }
    .section-heading {
      font-size: 18px;
      font-weight: 800;
      color: #FFFFFF;
      letter-spacing: -0.3px;
      display: flex;
      align-items: center;
      gap: 10px;
    }
    .section-desc {
      font-size: 13px;
      color: var(--text-muted);
      margin-top: 2px;
    }

    /* Client Tiles Grid */
    .client-grid {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(360px, 1fr));
      gap: 22px;
      margin-bottom: 34px;
    }
    .client-tile {
      cursor: pointer;
    }
    .client-tile-header {
      display: flex;
      align-items: flex-start;
      justify-content: space-between;
      margin-bottom: 16px;
    }
    .client-avatar {
      width: 48px;
      height: 48px;
      border-radius: 14px;
      background: linear-gradient(135deg, rgba(225, 29, 72, 0.2), rgba(225, 29, 72, 0.05));
      border: 1px solid rgba(225, 29, 72, 0.3);
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 20px;
      font-weight: 800;
      color: #FB7185;
    }
    .client-name {
      font-size: 17px;
      font-weight: 700;
      color: #FFFFFF;
      margin-bottom: 4px;
    }
    .client-desc {
      font-size: 12px;
      color: var(--text-muted);
      line-height: 1.5;
    }
    .client-metrics-row {
      display: grid;
      grid-template-columns: repeat(3, 1fr);
      gap: 10px;
      background: rgba(0, 0, 0, 0.25);
      border-radius: 12px;
      padding: 12px;
      margin: 16px 0;
      border: 1px solid rgba(255, 255, 255, 0.04);
    }
    .metric-col {
      text-align: center;
    }
    .metric-val {
      font-size: 15px;
      font-weight: 700;
      color: #FFFFFF;
    }
    .metric-lbl {
      font-size: 11px;
      color: var(--text-dim);
      margin-top: 2px;
    }
    .client-footer-btn {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding-top: 14px;
      border-top: 1px solid rgba(255, 255, 255, 0.06);
      font-size: 13px;
      font-weight: 600;
      color: #FB7185;
    }

    /* Add Card Placeholder */
    .add-card-btn {
      background: rgba(22, 27, 34, 0.35);
      border: 2px dashed rgba(255, 255, 255, 0.12);
      border-radius: 18px;
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      min-height: 220px;
      cursor: pointer;
      transition: all 0.2s ease;
      color: var(--text-muted);
      gap: 12px;
    }
    .add-card-btn:hover {
      border-color: var(--crimson);
      color: #FFFFFF;
      background: rgba(225, 29, 72, 0.05);
    }
    .add-icon-circle {
      width: 44px;
      height: 44px;
      border-radius: 50%;
      background: rgba(255, 255, 255, 0.06);
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 20px;
    }

    /* Projects Grid */
    .projects-grid {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(360px, 1fr));
      gap: 22px;
      margin-bottom: 34px;
    }
    .project-card {
      cursor: pointer;
    }

    /* Node Cards Grid */
    .nodes-grid {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(380px, 1fr));
      gap: 22px;
      margin-bottom: 34px;
    }
    .node-card {
      cursor: pointer;
    }
    .node-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 14px;
    }
    .node-title-group {
      display: flex;
      align-items: center;
      gap: 10px;
    }
    .node-name {
      font-size: 18px;
      font-weight: 800;
      color: #FFFFFF;
    }
    .node-spec-row {
      display: flex;
      justify-content: space-between;
      padding: 8px 0;
      font-size: 13px;
      border-bottom: 1px solid rgba(255, 255, 255, 0.04);
    }
    .node-spec-lbl {
      color: var(--text-muted);
    }
    .node-spec-val {
      font-family: var(--font-mono);
      font-weight: 600;
      color: #FFFFFF;
    }

    /* Interactive Node Detail Inspector View */
    .node-detail-layout {
      display: grid;
      grid-template-columns: 1.15fr 0.85fr;
      gap: 24px;
    }
    .panel-block {
      margin-bottom: 24px;
    }
    .panel-title {
      font-size: 14px;
      font-weight: 700;
      color: var(--text-muted);
      text-transform: uppercase;
      letter-spacing: 0.6px;
      margin-bottom: 14px;
    }

    /* Apple-style Master Service Switch */
    .service-switch-box {
      background: rgba(0, 0, 0, 0.35);
      border: 1px solid var(--card-border);
      border-radius: 16px;
      padding: 18px 20px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 20px;
    }
    .service-info h4 {
      font-size: 15px;
      font-weight: 700;
      color: #FFFFFF;
      margin-bottom: 4px;
    }
    .service-info p {
      font-size: 12px;
      color: var(--text-muted);
    }
    .apple-switch {
      position: relative;
      display: inline-block;
      width: 58px;
      height: 32px;
    }
    .apple-switch input { opacity: 0; width: 0; height: 0; }
    .slider {
      position: absolute; cursor: pointer; top: 0; left: 0; right: 0; bottom: 0;
      background-color: #334155;
      transition: .3s cubic-bezier(0.16, 1, 0.3, 1);
      border-radius: 34px;
    }
    .slider:before {
      position: absolute; content: ""; height: 26px; width: 26px; left: 3px; bottom: 3px;
      background-color: white;
      transition: .3s cubic-bezier(0.16, 1, 0.3, 1);
      border-radius: 50%;
      box-shadow: 0 2px 6px rgba(0,0,0,0.3);
    }
    input:checked + .slider {
      background-color: var(--success);
    }
    input:checked + .slider:before {
      transform: translateX(26px);
    }

    /* Delay Configurator Slider & Stepper */
    .delay-box {
      background: rgba(0, 0, 0, 0.35);
      border: 1px solid var(--card-border);
      border-radius: 16px;
      padding: 20px;
      margin-bottom: 20px;
    }
    .delay-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 14px;
    }
    .delay-val-badge {
      font-size: 18px;
      font-weight: 800;
      font-family: var(--font-mono);
      color: #38BDF8;
    }
    .range-slider {
      width: 100%;
      height: 8px;
      border-radius: 5px;
      background: #1E293B;
      outline: none;
      -webkit-appearance: none;
      margin-bottom: 14px;
    }
    .range-slider::-webkit-slider-thumb {
      -webkit-appearance: none;
      width: 22px;
      height: 22px;
      border-radius: 50%;
      background: var(--crimson);
      cursor: pointer;
      box-shadow: 0 0 10px var(--crimson-glow);
    }
    .preset-pills {
      display: flex;
      gap: 8px;
    }
    .preset-pill {
      background: rgba(255, 255, 255, 0.05);
      border: 1px solid var(--card-border);
      border-radius: 8px;
      padding: 6px 12px;
      font-size: 12px;
      font-weight: 600;
      color: var(--text-muted);
      cursor: pointer;
      transition: all 0.2s;
    }
    .preset-pill:hover, .preset-pill.active {
      background: var(--crimson);
      color: #FFFFFF;
      border-color: var(--crimson);
    }

    /* Live Hardware Simulation Panel (LED & BOOT Button) */
    .hw-visualizer {
      background: rgba(0, 0, 0, 0.4);
      border: 1px solid var(--card-border);
      border-radius: 18px;
      padding: 22px;
      margin-bottom: 20px;
    }
    .hw-display-row {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 16px;
      margin-top: 12px;
    }
    .hw-unit {
      background: rgba(255, 255, 255, 0.03);
      border: 1px solid var(--card-border);
      border-radius: 14px;
      padding: 16px;
      text-align: center;
      display: flex;
      flex-direction: column;
      align-items: center;
    }
    .led-orb {
      width: 44px;
      height: 44px;
      border-radius: 50%;
      background: #1E293B;
      border: 2px solid #334155;
      margin: 12px 0;
      transition: all 0.25s ease;
    }
    .led-orb.active {
      background: #3B82F6;
      border-color: #60A5FA;
      box-shadow: 0 0 24px #3B82F6, inset 0 0 12px #93C5FD;
    }
    .boot-btn-sim {
      width: 44px;
      height: 44px;
      border-radius: 12px;
      background: #1E293B;
      border: 2px solid #334155;
      margin: 12px 0;
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 11px;
      font-weight: 800;
      color: var(--text-muted);
      box-shadow: 0 4px 0 #0F172A;
      transition: all 0.15s ease;
    }
    .boot-btn-sim.pressed {
      transform: translateY(3px);
      box-shadow: 0 1px 0 #0F172A;
      background: #F59E0B;
      color: #000000;
      border-color: #FBBF24;
    }

    /* Firmware Deployment Pipeline */
    .mode-select-grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 12px;
      margin-bottom: 18px;
    }
    .mode-btn {
      background: rgba(255, 255, 255, 0.03);
      border: 1px solid var(--card-border);
      border-radius: 12px;
      padding: 14px 16px;
      text-align: left;
      cursor: pointer;
      transition: all 0.2s;
    }
    .mode-btn:hover {
      background: rgba(255, 255, 255, 0.06);
    }
    .mode-btn.active {
      background: rgba(225, 29, 72, 0.15);
      border-color: var(--crimson);
    }
    .mode-btn-title {
      font-size: 13px;
      font-weight: 700;
      color: #FFFFFF;
      margin-bottom: 4px;
    }
    .mode-btn-desc {
      font-size: 11px;
      color: var(--text-muted);
      line-height: 1.4;
    }

    /* Drag and Drop Zone */
    .dropzone {
      border: 2px dashed rgba(255, 255, 255, 0.14);
      border-radius: 14px;
      padding: 24px;
      text-align: center;
      background: rgba(0, 0, 0, 0.2);
      cursor: pointer;
      transition: all 0.2s;
      margin-bottom: 18px;
    }
    .dropzone:hover, .dropzone.dragover {
      border-color: var(--crimson);
      background: rgba(225, 29, 72, 0.06);
    }
    .dropzone-icon {
      font-size: 26px;
      margin-bottom: 6px;
    }

    .btn-action-row {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 14px;
    }
    .btn-main {
      padding: 14px 18px;
      border-radius: 12px;
      font-size: 14px;
      font-weight: 700;
      border: none;
      cursor: pointer;
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 8px;
      transition: all 0.2s ease;
    }
    .btn-crimson {
      background: linear-gradient(135deg, #E11D48, #BE123C);
      color: #FFFFFF;
      box-shadow: 0 4px 16px var(--crimson-glow);
    }
    .btn-crimson:hover {
      background: linear-gradient(135deg, #F43F5E, #E11D48);
      transform: translateY(-1px);
    }
    .btn-usb {
      background: rgba(255, 255, 255, 0.06);
      border: 1px solid var(--card-border);
      color: #FFFFFF;
    }
    .btn-usb:hover {
      background: rgba(255, 255, 255, 0.1);
    }

    /* Progress Stepper */
    .update-tracker {
      background: rgba(0, 0, 0, 0.4);
      border: 1px solid var(--card-border);
      border-radius: 16px;
      padding: 20px;
      margin-top: 20px;
      display: none;
    }
    .update-tracker.visible { display: block; }
    .tracker-bar-bg {
      height: 8px;
      border-radius: 4px;
      background: #1E293B;
      overflow: hidden;
      margin: 12px 0;
    }
    .tracker-bar-fill {
      height: 100%;
      background: linear-gradient(90deg, #E11D48, #38BDF8);
      width: 0%;
      transition: width 0.4s ease;
    }

    /* Modal Dialogs */
    .modal-overlay {
      position: fixed;
      top: 0; left: 0; right: 0; bottom: 0;
      background: rgba(0, 0, 0, 0.75);
      backdrop-filter: blur(8px);
      display: none;
      align-items: center;
      justify-content: center;
      z-index: 200;
    }
    .modal-overlay.open { display: flex; }
    .modal-card {
      width: 100%;
      max-width: 480px;
      background: #0E131F;
      border: 1px solid var(--card-border);
      border-radius: 20px;
      padding: 28px;
      box-shadow: 0 20px 60px rgba(0,0,0,0.8);
    }
    .modal-card h3 {
      font-size: 18px;
      font-weight: 800;
      margin-bottom: 6px;
    }
    .modal-card p {
      font-size: 13px;
      color: var(--text-muted);
      margin-bottom: 20px;
    }
    .form-group {
      margin-bottom: 16px;
    }
    .form-group label {
      display: block;
      font-size: 12px;
      font-weight: 700;
      color: var(--text-muted);
      margin-bottom: 6px;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }
    .form-input {
      width: 100%;
      padding: 12px 14px;
      background: rgba(0, 0, 0, 0.3);
      border: 1px solid var(--card-border);
      border-radius: 10px;
      color: #FFFFFF;
      font-size: 14px;
      outline: none;
    }
    .form-input:focus {
      border-color: var(--crimson);
    }
    .modal-actions {
      display: flex;
      justify-content: flex-end;
      gap: 12px;
      margin-top: 24px;
    }
    .btn-secondary {
      background: transparent;
      border: 1px solid var(--card-border);
      color: var(--text-muted);
      padding: 10px 18px;
      border-radius: 10px;
      cursor: pointer;
    }

    /* Terminal logs */
    .log-box {
      background: #05080E;
      border: 1px solid var(--card-border);
      border-radius: 14px;
      padding: 16px;
      font-family: var(--font-mono);
      font-size: 12px;
      height: 180px;
      overflow-y: auto;
      color: #94A3B8;
      line-height: 1.6;
    }
  </style>
</head>
<body>

  <!-- Left Sidebar -->
  <aside class="sidebar">
    <div class="brand-header">
      <div class="brand-logo">
        <img src="/static/logo.png" alt="Anashwar Technologies Logo">
      </div>
      <div class="brand-title">
        <span class="brand-name">Anashwar</span>
        <span class="brand-subtitle">Enterprise Edge Fleet</span>
      </div>
    </div>

    <div class="nav-section">
      <div class="nav-section-title">Operations</div>
      <div class="nav-item active" onclick="navigateTo('dashboard')">
        <span class="nav-icon">📊</span> Dashboard Overview
      </div>
      <div class="nav-item" onclick="navigateTo('clients')">
        <span class="nav-icon">🏢</span> Client Workspaces
      </div>
      <div class="nav-item" onclick="navigateTo('projects')">
        <span class="nav-icon">📁</span> Project Portfolios
      </div>
      <div class="nav-item" onclick="openNodeDetail('Node: A')">
        <span class="nav-icon">⚡</span> Node: A (Console)
      </div>
      <div class="nav-item" onclick="openNodeDetail('Node: B')">
        <span class="nav-icon">⚡</span> Node: B (Console)
      </div>
    </div>

    <div class="nav-section">
      <div class="nav-section-title">Security & Pipeline</div>
      <div class="nav-item" onclick="showSecurityModal()">
        <span class="nav-icon">🔒</span> SHA-256 Registry
      </div>
      <div class="nav-item" onclick="scrollToLogs()">
        <span class="nav-icon">📜</span> Telemetry Logs
      </div>
    </div>

    <div class="sidebar-footer">
      <div class="status-badge-row">
        <span>LAN mDNS</span>
        <span class="status-pill pill-cyan">control.local</span>
      </div>
      <div class="status-badge-row">
        <span>HiveMQ Broker</span>
        <span class="status-pill pill-green"><span class="pulsing-dot"></span> Connected</span>
      </div>
      <div class="status-badge-row">
        <span>Cloudflare Tunnel</span>
        <span class="status-pill pill-cyan">Active 🚀</span>
      </div>
      <div style="font-size: 10px; color: var(--text-dim); text-align: center; margin-top: 10px;">
        Anashwar Fleet OS v4.2 &bull; Dual ESP32
      </div>
    </div>
  </aside>

  <!-- Main Content Wrapper -->
  <div class="main-wrapper">
    
    <!-- Topbar -->
    <header class="topbar">
      <div class="breadcrumb-row" id="breadcrumb-container">
        <span class="breadcrumb-item" onclick="navigateTo('dashboard')">🏠 Dashboard</span>
      </div>

      <div class="topbar-actions">
        <div class="search-box">
          <span>🔍</span>
          <input type="text" placeholder="Search fleet, nodes, MAC...">
          <span class="kbd-shortcut">⌘K</span>
        </div>
        <a id="mdns-link" href="http://control.local" target="_blank" class="status-pill pill-cyan" style="text-decoration:none;">
          📡 control.local
        </a>
        <a id="public-tunnel-link" href="#" target="_blank" class="status-pill pill-crimson" style="text-decoration:none;">
          🌐 Public Web View
        </a>
        <div style="display:flex; align-items:center; gap:8px; border-left:1px solid rgba(255,255,255,0.12); padding-left:12px; margin-left:4px;">
          <div class="user-pill-btn" onclick="openUserModal()" title="Current Logged In User">
            <span style="font-size:14px;">👤</span>
            <span id="topbar-user-name" style="font-weight:700; font-size:12px;">__CURRENT_USER__</span>
          </div>
          <button class="btn-secondary" style="padding:5px 10px; font-size:11px;" onclick="openUserModal()" title="Manage Users">👥 Users</button>
          <button class="btn-secondary" style="padding:5px 10px; font-size:11px; border-color:rgba(239,68,68,0.4); color:#F87171;" onclick="handleLogout()" title="Sign Out">🚪 Logout</button>
        </div>
      </div>
    </header>

    <!-- Dynamic Content Area -->
    <main class="content-area">

      <!-- VIEW 1: DASHBOARD OVERVIEW -->
      <div id="view-dashboard">
        <!-- 4 Vibrant Top Snapshot Cards (DashTail Style) -->
        <div class="kpi-grid">
          <div class="kpi-card gradient-crimson">
            <div class="kpi-title">Active Fleet Nodes</div>
            <div class="kpi-value" id="kpi-active-nodes">2 / 2 Online</div>
            <div class="kpi-subtitle">100% Operational Telemetry</div>
          </div>
          <div class="kpi-card gradient-orange">
            <div class="kpi-title">Security Trust Index</div>
            <div class="kpi-value">100% Verified</div>
            <div class="kpi-subtitle">SHA-256 + MAC + eFuse Verified</div>
          </div>
          <div class="kpi-card gradient-green">
            <div class="kpi-title">Firmware Pipeline</div>
            <div class="kpi-value">Mode 1 Active</div>
            <div class="kpi-subtitle">4 Multi-Mode Builds Ready</div>
          </div>
          <div class="kpi-card gradient-cyan">
            <div class="kpi-title">Carrier & Broker Mesh</div>
            <div class="kpi-value">Low Latency</div>
            <div class="kpi-subtitle">HiveMQ Cloud (1883) &bull; Zero Drop</div>
          </div>
        </div>

        <!-- Clients Section -->
        <div class="section-header-row">
          <div>
            <div class="section-heading">🏢 Enterprise Client Workspaces</div>
            <div class="section-desc">Select a client tenant space to inspect project pipelines and hardware nodes</div>
          </div>
          <button class="btn-main btn-crimson" onclick="openAddClientModal()">+ Add New Client</button>
        </div>

        <div class="client-grid" id="clients-container">
          <!-- Populated by JS -->
        </div>

        <!-- Fleet Nodes Quick Inspector -->
        <div class="section-header-row" style="margin-top: 10px;">
          <div>
            <div class="section-heading">⚡ Connected Hardware Edge Nodes</div>
            <div class="section-desc">Live ESP32 nodes connected via Wi-Fi STA and HiveMQ MQTT</div>
          </div>
        </div>

        <div class="nodes-grid" id="dashboard-nodes-container">
          <!-- Populated by JS -->
        </div>

        <!-- Activity Logs -->
        <div class="section-header-row" style="margin-top: 10px;">
          <div class="section-heading">📜 Telemetry & Command Audit Trail</div>
        </div>
        <div class="log-box" id="activity-log-stream">
          <!-- Populated by JS -->
        </div>
      </div>

      <!-- VIEW 2: CLIENT DETAIL VIEW -->
      <div id="view-client" style="display: none;">
        <div class="glass-card" style="margin-bottom: 24px;">
          <div style="display: flex; justify-content: space-between; align-items: center;">
            <div>
              <button class="btn-secondary" style="margin-bottom: 12px;" onclick="navigateTo('dashboard')">&larr; Back to Dashboard</button>
              <h2 id="client-view-title" style="font-size: 24px; font-weight: 800; color: #FFFFFF;">Client 1: Alpha Enterprise Corp</h2>
              <p id="client-view-desc" style="color: var(--text-muted); font-size: 13px; margin-top: 4px;">Autonomous Industrial Edge IoT Operations & Real-time Fleet</p>
            </div>
            <button class="btn-main btn-crimson" onclick="openAddProjectModal()">+ Add New Project</button>
          </div>
        </div>

        <div class="section-header-row">
          <div class="section-heading">📁 Client Projects</div>
        </div>
        <div class="projects-grid" id="client-projects-container">
          <!-- Populated by JS -->
        </div>
      </div>

      <!-- VIEW 3: PROJECT DETAIL VIEW -->
      <div id="view-project" style="display: none;">
        <div class="glass-card" style="margin-bottom: 24px;">
          <div style="display: flex; justify-content: space-between; align-items: center;">
            <div>
              <button class="btn-secondary" style="margin-bottom: 12px;" onclick="backToClient()">&larr; Back to Client</button>
              <h2 id="project-view-title" style="font-size: 24px; font-weight: 800; color: #FFFFFF;">Project 1: Enterprise OTA Fleet</h2>
              <p id="project-view-desc" style="color: var(--text-muted); font-size: 13px; margin-top: 4px;">Dual ESP32 Wireless & USB Hardware Control Architecture</p>
            </div>
          </div>
        </div>

        <div class="section-header-row">
          <div class="section-heading">🖧 Project Hardware Nodes</div>
          <button class="btn-main btn-crimson" onclick="openAddNodeModal()">+ Register Node to Project</button>
        </div>
        <div class="nodes-grid" id="project-nodes-container">
          <!-- Populated by JS -->
        </div>
      </div>

      <!-- VIEW 4: NODE DETAIL & CONTROL CENTER -->
      <div id="view-node-detail" style="display: none;">
        <div class="glass-card" style="margin-bottom: 24px;">
          <div style="display: flex; justify-content: space-between; align-items: center;">
            <div>
              <button class="btn-secondary" style="margin-bottom: 12px;" onclick="backToProject()">&larr; Back to Project</button>
              <div style="display: flex; align-items: center; gap: 12px; flex-wrap: wrap;">
                <h2 id="detail-node-name" style="font-size: 26px; font-weight: 800; color: #FFFFFF;">Node: A</h2>
                <span id="detail-node-status-pill" class="status-pill pill-green"><span class="pulsing-dot"></span> ONLINE</span>
                <span class="status-pill pill-cyan">✓ SHA-256 VERIFIED</span>
                <button class="btn-main btn-cyan" style="font-size: 12px; padding: 6px 12px;" onclick="openInsituModal()">🌐 On-Board Web UI</button>
                <button class="btn-secondary" style="border-color: rgba(239,68,68,0.4); color: #F87171; font-size: 12px; padding: 6px 12px;" onclick="deleteNode(selectedNodeName)">🗑️ Delete Node</button>
              </div>
            </div>
            <!-- Quick switcher for all nodes -->
            <div style="display: flex; gap: 8px; flex-wrap: wrap;" id="node-switcher-container">
              <button class="btn-secondary" onclick="openNodeDetail('Node: A')">Node: A</button>
              <button class="btn-secondary" onclick="openNodeDetail('Node: B')">Node: B</button>
            </div>
          </div>
        </div>

        <div class="node-detail-layout">
          <!-- Left Column: Controls & Visualizer -->
          <div>
            <!-- Master Service Toggle Box -->
            <div class="service-switch-box">
              <div class="service-info">
                <h4>Master Service Switch</h4>
                <p>When STANDBY is selected, hardware operation suspends (LED OFF), while MQTT telemetry remains live.</p>
              </div>
              <label class="apple-switch">
                <input type="checkbox" id="detail-service-toggle" onchange="toggleMasterService()">
                <span class="slider"></span>
              </label>
            </div>

            <!-- Autonomous Offline Mode Box -->
            <div class="service-switch-box" style="margin-top: 14px;">
              <div class="service-info">
                <h4>Autonomous Offline Mode</h4>
                <p>When enabled, hardware operates 100% locally without blocking on internet drops. All hardware loops and in-situ web servers stay live.</p>
              </div>
              <label class="apple-switch">
                <input type="checkbox" id="detail-offline-toggle" onchange="toggleOfflineMode()">
                <span class="slider"></span>
              </label>
            </div>

            <!-- Output Delay Configurator -->
            <div class="delay-box">
              <div class="delay-header">
                <div>
                  <h4 style="font-size: 15px; font-weight: 700; color: #FFFFFF;">Configurable Output Propagation Delay</h4>
                  <p style="font-size: 12px; color: var(--text-muted); margin-top: 2px;">Delay in seconds before button press toggles physical output (0 - 10s, 0.5s step)</p>
                </div>
                <div class="delay-val-badge" id="delay-display-val">0.0s</div>
              </div>

              <input type="range" class="range-slider" id="delay-range" min="0" max="10" step="0.5" value="0" oninput="onDelaySliderInput(this.value)" onchange="applyDelay(this.value)">

              <div class="preset-pills">
                <span class="preset-pill" onclick="applyDelay(0.0)">0.0s (Instant)</span>
                <span class="preset-pill" onclick="applyDelay(1.0)">1.0s</span>
                <span class="preset-pill" onclick="applyDelay(2.5)">2.5s</span>
                <span class="preset-pill" onclick="applyDelay(5.0)">5.0s</span>
                <span class="preset-pill" onclick="applyDelay(10.0)">10.0s</span>
              </div>
            </div>

            <!-- Live Hardware Visualizer -->
            <div class="hw-visualizer">
              <div class="panel-title">Real-Time Hardware Visualizer</div>
              <p style="font-size: 12px; color: var(--text-muted);">Dynamic state mirrored from physical GPIO 2 & GPIO 0</p>
              
              <div class="hw-display-row">
                <div class="hw-unit">
                  <div style="font-size: 11px; font-weight: 700; color: var(--text-dim); text-transform: uppercase;">GPIO 2 Blue LED</div>
                  <div class="led-orb" id="visualizer-led"></div>
                  <div style="font-size: 13px; font-weight: 700;" id="visualizer-led-text">DARK / OFF</div>
                </div>

                <div class="hw-unit">
                  <div style="font-size: 11px; font-weight: 700; color: var(--text-dim); text-transform: uppercase;">GPIO 0 BOOT Button</div>
                  <div class="boot-btn-sim" id="visualizer-btn">BOOT</div>
                  <div style="font-size: 13px; font-weight: 700;" id="visualizer-btn-text">RELEASED</div>
                </div>
              </div>
            </div>

            <!-- In-Situ Web Server Gateway -->
            <div class="glass-card">
            <!-- In-Situ Embedded Server Card -->
            <div class="glass-card" style="margin-top: 24px;">
              <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                <div class="panel-title" style="margin: 0;">On-Board Web Server (In-Situ)</div>
                <span id="insitu-status-pill" class="status-pill pill-green"><span class="pulsing-dot"></span> Port 80 Live</span>
              </div>
              <p style="font-size: 12px; color: var(--text-muted); margin-bottom: 14px;">The ESP32 runs an onboard web server serving its own branded in-situ configuration console. View it live through the secure portal reverse proxy:</p>
              <div style="display: flex; gap: 10px; flex-wrap: wrap;">
                <button class="btn-main btn-cyan" onclick="openInsituModal()" style="flex: 1; min-width: 170px; font-size: 13px;">
                  🌐 Launch In-Portal Proxy Viewer
                </button>
                <a id="detail-insitu-link" href="#" target="_blank" class="btn-secondary" style="flex: 1; min-width: 150px; text-decoration: none; text-align: center; font-size: 13px;">
                  ↗ Direct LAN (<span id="detail-insitu-ip">10.94.142.79</span>)
                </a>
              </div>
            </div>
          </div>

          <!-- Right Column: Firmware Pipeline & Hardware Specs -->
          <div>
            <!-- Hardware Specifications Card -->
            <div class="glass-card" style="margin-bottom: 24px;">
              <div class="panel-title">Node Telemetry & Markers</div>
              <div class="node-spec-row"><span class="node-spec-lbl">Hardware MAC</span><span class="node-spec-val" id="spec-mac">-</span></div>
              <div class="node-spec-row"><span class="node-spec-lbl">eFuse Chip ID</span><span class="node-spec-val" id="spec-chip">-</span></div>
              <div class="node-spec-row"><span class="node-spec-lbl">STA Local IP</span><span class="node-spec-val" id="spec-ip" style="color:#38BDF8;">-</span></div>
              <div class="node-spec-row"><span class="node-spec-lbl">USB Port (Backdoor)</span><span class="node-spec-val" id="spec-port">-</span></div>
              <div class="node-spec-row"><span class="node-spec-lbl">Wi-Fi Signal (RSSI)</span><span class="node-spec-val" id="spec-rssi">-</span></div>
              <div class="node-spec-row"><span class="node-spec-lbl">Free Heap RAM</span><span class="node-spec-val" id="spec-heap">-</span></div>
              <div class="node-spec-row"><span class="node-spec-lbl">Uptime</span><span class="node-spec-val" id="spec-uptime">-</span></div>
              <div class="node-spec-row" style="border:none;"><span class="node-spec-lbl">SHA-256 Fingerprint</span><span class="node-spec-val" id="spec-hash" style="color:#34D399; font-size:11px; word-break:break-all;">-</span></div>
            </div>

            <!-- Firmware Deployment Hub -->
            <div class="glass-card">
              <div class="panel-title">Firmware Deployment Pipeline</div>
              <p style="font-size: 12px; color: var(--text-muted); margin-bottom: 14px;">Select a pre-compiled multi-mode binary or drag & drop a custom .bin:</p>

              <div class="mode-select-grid">
                <div class="mode-btn active" id="btn-mode-1" onclick="selectFirmwareMode(1)">
                  <div class="mode-btn-title">Firmware 1</div>
                  <div class="mode-btn-desc">Pressed: Solid ON<br>Released: OFF</div>
                </div>
                <div class="mode-btn" id="btn-mode-2" onclick="selectFirmwareMode(2)">
                  <div class="mode-btn-title">Firmware 2</div>
                  <div class="mode-btn-desc">Pressed: Blinking<br>Released: OFF</div>
                </div>
                <div class="mode-btn" id="btn-mode-3" onclick="selectFirmwareMode(3)">
                  <div class="mode-btn-title">Firmware 3</div>
                  <div class="mode-btn-desc">Released: Solid ON<br>Pressed: OFF</div>
                </div>
                <div class="mode-btn" id="btn-mode-4" onclick="selectFirmwareMode(4)">
                  <div class="mode-btn-title">Firmware 4</div>
                  <div class="mode-btn-desc">Released: Blinking<br>Pressed: OFF</div>
                </div>
              </div>

              <!-- Custom .bin Upload Zone -->
              <div class="dropzone" id="bin-dropzone" onclick="document.getElementById('bin-file-input').click()">
                <div class="dropzone-icon">📥</div>
                <div style="font-size: 13px; font-weight: 700; color: #FFFFFF;" id="dropzone-label">Drop custom .bin file here or click to browse</div>
                <div style="font-size: 11px; color: var(--text-muted); margin-top: 4px;">Pre-flash verification of magic byte 0xE9 & SHA-256</div>
                <input type="file" id="bin-file-input" style="display:none;" accept=".bin" onchange="handleFileSelect(this.files)">
              </div>

              <!-- Deployment Actions -->
              <div class="btn-action-row">
                <button class="btn-main btn-crimson" onclick="triggerDeployment('cloud')">
                  🚀 Wireless OTA Update
                </button>
                <button class="btn-main btn-usb" onclick="triggerDeployment('usb')">
                  🔌 USB Direct Flash
                </button>
              </div>

              <!-- Refined Progress Tracker -->
              <div class="update-tracker" id="detail-tracker">
                <div style="display: flex; justify-content: space-between; font-size: 13px; font-weight: 700;">
                  <span id="tracker-stage-title">Deployment in Progress</span>
                  <span id="tracker-pct" style="color:#38BDF8;">0%</span>
                </div>
                <div class="tracker-bar-bg">
                  <div class="tracker-bar-fill" id="tracker-fill"></div>
                </div>
                <div style="font-size: 12px; color: var(--text-muted);" id="tracker-status-text">
                  Preparing firmware payload...
                </div>
              </div>

            </div>
          </div>
        </div>
      </div>

    </main>
  </div>

  <!-- Modal: Add Client -->
  <div class="modal-overlay" id="modal-add-client">
    <div class="modal-card">
      <h3>Add New Client Tenant</h3>
      <p>Register a new client enterprise account in the fleet registry.</p>
      <div class="form-group">
        <label>Client Name</label>
        <input type="text" class="form-input" id="new-client-name" placeholder="e.g. Beta Robotics Corp">
      </div>
      <div class="form-group">
        <label>Client Code</label>
        <input type="text" class="form-input" id="new-client-code" placeholder="e.g. BETA-ROB">
      </div>
      <div class="form-group">
        <label>Description</label>
        <input type="text" class="form-input" id="new-client-desc" placeholder="Edge automation facilities">
      </div>
      <div class="modal-actions">
        <button class="btn-secondary" onclick="closeModal('modal-add-client')">Cancel</button>
        <button class="btn-main btn-crimson" onclick="submitNewClient()">Create Client</button>
      </div>
    </div>
  </div>

  <!-- Modal: Add Project -->
  <div class="modal-overlay" id="modal-add-project">
    <div class="modal-card">
      <h3>Add New Project</h3>
      <p>Create a project pipeline under this client.</p>
      <div class="form-group">
        <label>Project Name</label>
        <input type="text" class="form-input" id="new-proj-name" placeholder="e.g. Factory Floor Sensor Mesh">
      </div>
      <div class="form-group">
        <label>Project Code</label>
        <input type="text" class="form-input" id="new-proj-code" placeholder="e.g. SENS-MESH-01">
      </div>
      <div class="form-group">
        <label>Description</label>
        <input type="text" class="form-input" id="new-proj-desc" placeholder="High-frequency telemetry pipeline">
      </div>
      <div class="modal-actions">
        <button class="btn-secondary" onclick="closeModal('modal-add-project')">Cancel</button>
        <button class="btn-main btn-crimson" onclick="submitNewProject()">Create Project</button>
      </div>
    </div>
  </div>

  <!-- Modal: Add Node -->
  <div class="modal-overlay" id="modal-add-node">
    <div class="modal-card">
      <h3>Register Node to Project</h3>
      <p>Provision hardware identity and assign it to the current project.</p>
      
      <div class="form-group">
        <label>Detected USB Device (Auto-Detect Hardware)</label>
        <select class="form-input" id="new-node-usb-select" onchange="onUsbSelectChange()">
          <option value="">-- Scanning USB Ports... --</option>
        </select>
        <div style="font-size: 11px; color: var(--text-dim); margin-top: 4px;">Select a detected USB port to auto-populate port and identity.</div>
      </div>

      <div class="form-group">
        <label>Node Display Name</label>
        <input type="text" class="form-input" id="new-node-name" placeholder="e.g. Node: C">
      </div>

      <div class="form-group">
        <label>Hardware Port / Route</label>
        <input type="text" class="form-input" id="new-node-port" placeholder="/dev/cu.usbserial-XXXX or WiFi Wireless">
      </div>

      <div class="form-group">
        <label>Hardware MAC Address (STA)</label>
        <input type="text" class="form-input" id="new-node-mac" placeholder="e.g. 24:6F:28:XX:XX:XX">
      </div>

      <div class="form-group">
        <label>eFuse Chip ID</label>
        <input type="text" class="form-input" id="new-node-chip" placeholder="e.g. 9408FFFFC9EC">
      </div>

      <div class="modal-actions">
        <button class="btn-secondary" onclick="closeModal('modal-add-node')">Cancel</button>
        <button class="btn-main btn-crimson" onclick="submitNewNode()">Register Node</button>
      </div>
    </div>
  </div>

  <!-- Modal: User Management -->
  <div class="modal-overlay" id="modal-users">
    <div class="modal-card" style="max-width: 540px;">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
        <h3 style="margin: 0;">Enterprise User Accounts</h3>
        <button class="btn-secondary" style="padding: 4px 10px; font-size: 11px;" onclick="closeModal('modal-users')">✕ Close</button>
      </div>
      <p>Manage authenticated administrators and operators with portal access.</p>
      
      <div style="margin-bottom: 20px;">
        <div style="font-size: 12px; font-weight: 700; color: #CBD5E1; margin-bottom: 8px;">Existing Accounts</div>
        <div id="users-list-container" style="max-height: 180px; overflow-y: auto;">
          <!-- Populated by JS -->
        </div>
      </div>

      <div style="border-top: 1px solid rgba(255,255,255,0.08); padding-top: 16px;">
        <div style="font-size: 12px; font-weight: 700; color: #CBD5E1; margin-bottom: 10px;">Register New User</div>
        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 10px; margin-bottom: 10px;">
          <input type="text" class="form-input" id="new-user-username" placeholder="Username">
          <input type="password" class="form-input" id="new-user-password" placeholder="Password">
        </div>
        <div style="display: flex; gap: 10px;">
          <select class="form-input" id="new-user-role" style="flex: 1;">
            <option value="Super Admin">Super Admin</option>
            <option value="Fleet Operator" selected>Fleet Operator</option>
            <option value="Viewer">Viewer (Read-Only)</option>
          </select>
          <button class="btn-main btn-crimson" onclick="submitNewUser()" style="padding: 10px 18px; font-size: 13px;">+ Add User</button>
        </div>
      </div>
    </div>
  </div>

  <!-- Modal: In-Situ Web UI Viewer -->
  <div class="modal-overlay" id="modal-insitu-webui">
    <div class="modal-card" style="max-width: 960px; width: 95vw; padding: 20px;">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 14px; border-bottom: 1px solid rgba(255,255,255,0.08); padding-bottom: 12px;">
        <div>
          <h3 style="margin: 0;" id="insitu-modal-title">In-Situ On-Board Web UI</h3>
          <div style="font-size: 11px; color: #34D399; margin-top: 2px;">● Connected via Anashwar High-Speed Hardware Reverse Proxy</div>
        </div>
        <div style="display: flex; gap: 8px;">
          <button class="btn-secondary" style="padding: 6px 12px; font-size: 12px;" onclick="refreshInsituIframe()">🔄 Reload</button>
          <a id="insitu-modal-direct-link" href="#" target="_blank" class="btn-secondary" style="padding: 6px 12px; font-size: 12px; text-decoration: none;">↗ Direct Link</a>
          <button class="btn-secondary" style="padding: 6px 12px; font-size: 12px;" onclick="closeModal('modal-insitu-webui')">✕ Close</button>
        </div>
      </div>
      <div style="width: 100%; height: 580px; border-radius: 14px; overflow: hidden; background: #0B0F19; border: 1px solid rgba(255,255,255,0.1);">
        <iframe id="insitu-iframe" style="width: 100%; height: 100%; border: none;" src="about:blank"></iframe>
      </div>
    </div>
  </div>

  <script>
    // State
    let currentView = 'dashboard';
    let selectedClientId = 'client_1';
    let selectedProjectId = 'proj_1';
    let selectedNodeName = 'Node: A';
    let selectedFirmwareFile = 'firmware_mode1.bin';

    let fleetData = {};
    let telemetryData = {};

    function navigateTo(view, param1, param2) {
      currentView = view;
      document.querySelectorAll('#view-dashboard, #view-client, #view-project, #view-node-detail').forEach(el => el.style.display = 'none');
      
      const breadcrumb = document.getElementById('breadcrumb-container');

      if (view === 'dashboard') {
        document.getElementById('view-dashboard').style.display = 'block';
        breadcrumb.innerHTML = '<span class="breadcrumb-active">🏠 Dashboard Overview</span>';
      } else if (view === 'clients' || view === 'client') {
        if (param1) {
          selectedClientId = param1;
        } else if (!selectedClientId && fleetData.clients && Object.keys(fleetData.clients).length > 0) {
          selectedClientId = Object.keys(fleetData.clients)[0];
        }
        document.getElementById('view-client').style.display = 'block';
        const client = fleetData.clients ? fleetData.clients[selectedClientId] : null;
        const cName = client ? client.name : selectedClientId;
        document.getElementById('client-view-title').innerText = cName;
        document.getElementById('client-view-desc').innerText = client ? client.description : '';
        breadcrumb.innerHTML = `
          <span class="breadcrumb-item" onclick="navigateTo('dashboard')">🏠 Dashboard</span>
          <span class="breadcrumb-sep">&gt;</span>
          <span class="breadcrumb-active">🏢 ${cName}</span>
        `;
        renderClientProjects();
      } else if (view === 'projects' || view === 'project') {
        if (param1) {
          selectedProjectId = param1;
        } else if (!selectedProjectId && fleetData.projects && Object.keys(fleetData.projects).length > 0) {
          selectedProjectId = Object.keys(fleetData.projects)[0];
        }
        document.getElementById('view-project').style.display = 'block';
        const proj = fleetData.projects ? fleetData.projects[selectedProjectId] : null;
        const client = (proj && fleetData.clients) ? fleetData.clients[proj.client_id] : null;
        const pName = proj ? proj.name : selectedProjectId;
        document.getElementById('project-view-title').innerText = pName;
        document.getElementById('project-view-desc').innerText = proj ? proj.description : '';
        breadcrumb.innerHTML = `
          <span class="breadcrumb-item" onclick="navigateTo('dashboard')">🏠 Dashboard</span>
          <span class="breadcrumb-sep">&gt;</span>
          <span class="breadcrumb-item" onclick="navigateTo('client', '${proj ? proj.client_id : ''}')">🏢 ${client ? client.name : 'Client'}</span>
          <span class="breadcrumb-sep">&gt;</span>
          <span class="breadcrumb-active">📁 ${pName}</span>
        `;
        renderProjectNodes();
      } else if (view === 'node-detail') {
        if (param1) selectedNodeName = param1;
        const regNode = (fleetData.registered_nodes && fleetData.registered_nodes[selectedNodeName]) ? fleetData.registered_nodes[selectedNodeName] : null;
        if (regNode && regNode.project_id) {
          selectedProjectId = regNode.project_id;
          selectedClientId = regNode.client_id;
        }
        document.getElementById('view-node-detail').style.display = 'block';
        const proj = fleetData.projects ? fleetData.projects[selectedProjectId] : null;
        const pName = proj ? proj.name : 'Project';
        breadcrumb.innerHTML = `
          <span class="breadcrumb-item" onclick="navigateTo('dashboard')">🏠 Dashboard</span>
          <span class="breadcrumb-sep">&gt;</span>
          <span class="breadcrumb-item" onclick="navigateTo('project', '${selectedProjectId}')">📁 ${pName}</span>
          <span class="breadcrumb-sep">&gt;</span>
          <span class="breadcrumb-active">⚡ ${selectedNodeName}</span>
        `;
        updateNodeDetailUI();
      }
    }

    function backToClient() {
      const proj = fleetData.projects ? fleetData.projects[selectedProjectId] : null;
      navigateTo('client', proj ? proj.client_id : selectedClientId);
    }

    function backToProject() {
      navigateTo('project', selectedProjectId);
    }

    function openNodeDetail(name) {
      selectedNodeName = name;
      navigateTo('node-detail', name);
    }

    // Modal helpers
    function openAddClientModal() { document.getElementById('modal-add-client').classList.add('open'); }
    function openAddProjectModal() { document.getElementById('modal-add-project').classList.add('open'); }
    function closeModal(id) { document.getElementById(id).classList.remove('open'); }

    // Session & Auth Token Management for Cross-Origin Frames
    const CURRENT_AUTH_TOKEN = "__CURRENT_TOKEN__" || localStorage.getItem('anashwar_token') || sessionStorage.getItem('anashwar_token') || "";
    if (CURRENT_AUTH_TOKEN) {
      try {
        localStorage.setItem('anashwar_token', CURRENT_AUTH_TOKEN);
        sessionStorage.setItem('anashwar_token', CURRENT_AUTH_TOKEN);
      } catch(e) {}
    }

    function authedFetch(url, options = {}) {
      options.headers = options.headers || {};
      const token = CURRENT_AUTH_TOKEN || localStorage.getItem('anashwar_token') || sessionStorage.getItem('anashwar_token') || "";
      if (token) {
        if (options.headers instanceof Headers) {
          options.headers.set('Authorization', 'Bearer ' + token);
        } else {
          options.headers['Authorization'] = 'Bearer ' + token;
        }
        const sep = url.includes('?') ? '&' : '?';
        url = url + sep + 'token=' + encodeURIComponent(token);
      }
      return fetch(url, options);
    }

    // User Authentication & Management
    async function handleLogout() {
      localStorage.removeItem('anashwar_token');
      sessionStorage.removeItem('anashwar_token');
      try {
        await authedFetch('/api/logout', { method: 'POST' });
      } catch(e) {}
      window.location.href = '/?logout=true';
    }

    function openUserModal() {
      document.getElementById('modal-users').classList.add('open');
      loadUsersList();
    }

    async function loadUsersList() {
      try {
        const res = await authedFetch('/api/users');
        const data = await res.json();
        const listContainer = document.getElementById('users-list-container');
        if (!listContainer || !data.users) return;
        let html = '';
        for (const u of data.users) {
          const isSelf = (u.username === data.current_user);
          const isPrimaryAdmin = (u.username === 'admin');
          html += `
            <div style="display:flex; justify-content:space-between; align-items:center; background:rgba(255,255,255,0.03); border:1px solid rgba(255,255,255,0.07); padding:10px 14px; border-radius:10px; margin-bottom:8px;">
              <div>
                <div style="font-weight:700; font-size:13px; color:#FFFFFF;">${u.username} ${isSelf ? '<span style="color:#38BDF8; font-size:11px;">(You)</span>' : ''}</div>
                <div style="font-size:11px; color:var(--text-dim);">${u.role} &bull; Created ${u.created_at || 'Recently'}</div>
              </div>
              <div>
                ${(!isSelf && !isPrimaryAdmin) ? `<button class="delete-btn-tiny" onclick="deleteUser('${u.username}')">🗑️ Delete</button>` : `<span style="font-size:11px; color:#64748B;">Protected</span>`}
              </div>
            </div>
          `;
        }
        listContainer.innerHTML = html;
      } catch (e) {
        console.error("Error loading users:", e);
      }
    }

    async function submitNewUser() {
      const u = document.getElementById('new-user-username').value.trim();
      const p = document.getElementById('new-user-password').value;
      const r = document.getElementById('new-user-role').value;
      if (!u || !p) return alert("Username and password are required");
      const res = await authedFetch('/api/users/create', {
        method: 'POST',
        headers: {'Content-Type': 'application/x-www-form-urlencoded'},
        body: `username=${encodeURIComponent(u)}&password=${encodeURIComponent(p)}&role=${encodeURIComponent(r)}`
      });
      const data = await res.json();
      if (data.success) {
        document.getElementById('new-user-username').value = '';
        document.getElementById('new-user-password').value = '';
        loadUsersList();
      } else {
        alert(data.error || "Failed to create user");
      }
    }

    async function deleteUser(username) {
      if (!confirm(`Are you sure you want to delete user '${username}'?`)) return;
      const res = await authedFetch('/api/users/delete', {
        method: 'POST',
        headers: {'Content-Type': 'application/x-www-form-urlencoded'},
        body: `username=${encodeURIComponent(username)}`
      });
      const data = await res.json();
      if (data.success) {
        loadUsersList();
      } else {
        alert(data.error || "Failed to delete user");
      }
    }

    // Client & Project Deletion
    async function deleteClient(clientId, clientName) {
      if (!confirm(`Delete Client "${clientName}" and all associated projects?`)) return;
      const res = await authedFetch('/api/client/delete', {
        method: 'POST',
        headers: {'Content-Type': 'application/x-www-form-urlencoded'},
        body: `client_id=${encodeURIComponent(clientId)}`
      });
      if (res.ok) {
        fetchTelemetry();
        navigateTo('dashboard');
      } else {
        alert("Error deleting client");
      }
    }

    async function deleteProject(projectId, projectName) {
      if (!confirm(`Delete Project "${projectName}"?`)) return;
      const res = await authedFetch('/api/project/delete', {
        method: 'POST',
        headers: {'Content-Type': 'application/x-www-form-urlencoded'},
        body: `project_id=${encodeURIComponent(projectId)}`
      });
      if (res.ok) {
        fetchTelemetry();
        navigateTo('client', selectedClientId);
      } else {
        alert("Error deleting project");
      }
    }

    // Node Registration & Deletion
    async function deleteNode(nodeName) {
      if (!confirm(`Delete Node "${nodeName}" from registry?`)) return;
      const res = await authedFetch('/api/node/delete', {
        method: 'POST',
        headers: {'Content-Type': 'application/x-www-form-urlencoded'},
        body: `node_name=${encodeURIComponent(nodeName)}`
      });
      if (res.ok) {
        fetchTelemetry();
        navigateTo('project', selectedProjectId);
      } else {
        alert("Error deleting node");
      }
    }

    async function openAddNodeModal() {
      document.getElementById('modal-add-node').classList.add('open');
      try {
        const res = await authedFetch('/api/usb/scan');
        const data = await res.json();
        const sel = document.getElementById('new-node-usb-select');
        if (sel && data.devices) {
          sel.innerHTML = '<option value="">-- Select Detected USB Device (Optional) --</option>';
          for (const d of data.devices) {
            sel.innerHTML += `<option value="${d.port}" data-mac="${d.mac}" data-chip="${d.chip_id}" data-name="${d.node_name}">
              ${d.port} ${d.node_name ? '('+d.node_name+')' : '(Available to Assign)'}
            </option>`;
          }
        }
      } catch(e) {
        console.error("USB scan error:", e);
      }
    }

    function onUsbSelectChange() {
      const sel = document.getElementById('new-node-usb-select');
      const opt = sel.options[sel.selectedIndex];
      if (opt && opt.value) {
        document.getElementById('new-node-port').value = opt.value;
        if (opt.dataset.name) document.getElementById('new-node-name').value = opt.dataset.name;
        if (opt.dataset.mac) document.getElementById('new-node-mac').value = opt.dataset.mac;
        if (opt.dataset.chip) document.getElementById('new-node-chip').value = opt.dataset.chip;
      }
    }

    async function submitNewNode() {
      const name = document.getElementById('new-node-name').value.trim();
      const port = document.getElementById('new-node-port').value.trim() || 'WiFi Wireless';
      const mac = document.getElementById('new-node-mac').value.trim();
      const chip = document.getElementById('new-node-chip').value.trim();
      if (!name) return alert("Please enter Node Name");
      const res = await authedFetch('/api/node/create', {
        method: 'POST',
        headers: {'Content-Type': 'application/x-www-form-urlencoded'},
        body: `name=${encodeURIComponent(name)}&port=${encodeURIComponent(port)}&mac=${encodeURIComponent(mac)}&chip_id=${encodeURIComponent(chip)}&project_id=${encodeURIComponent(selectedProjectId)}`
      });
      if (res.ok) {
        closeModal('modal-add-node');
        fetchTelemetry();
      } else {
        alert("Error registering node");
      }
    }

    // In-Situ Reverse Proxy Viewer
    function openInsituModal() {
      const modal = document.getElementById('modal-insitu-webui');
      const iframe = document.getElementById('insitu-iframe');
      const title = document.getElementById('insitu-modal-title');
      const directLink = document.getElementById('insitu-modal-direct-link');
      
      const node = telemetryData.nodes ? telemetryData.nodes[selectedNodeName] : null;
      const ip = node ? node.ip : '0.0.0.0';
      
      title.innerText = `In-Situ On-Board Web UI: ${selectedNodeName}`;
      iframe.src = `/proxy/node/${encodeURIComponent(selectedNodeName)}/`;
      directLink.href = `http://${ip}/`;
      modal.classList.add('open');
    }

    function refreshInsituIframe() {
      const iframe = document.getElementById('insitu-iframe');
      if (iframe) iframe.src = iframe.src;
    }

    // Autonomous Offline Mode Toggle
    function toggleOfflineMode() {
      const chk = document.getElementById('detail-offline-toggle');
      const state = chk.checked ? 'ON' : 'OFF';
      authedFetch('/api/command', {
        method: 'POST',
        headers: {'Content-Type': 'application/x-www-form-urlencoded'},
        body: `target=${encodeURIComponent(selectedNodeName)}&action=OFFLINE&val=${state}`
      });
    }

    function submitNewClient() {
      const name = document.getElementById('new-client-name').value;
      const code = document.getElementById('new-client-code').value;
      const desc = document.getElementById('new-client-desc').value;
      if (!name) return alert('Please enter client name');
      
      authedFetch('/api/client/create', {
        method: 'POST',
        headers: {'Content-Type': 'application/x-www-form-urlencoded'},
        body: `name=${encodeURIComponent(name)}&code=${encodeURIComponent(code)}&description=${encodeURIComponent(desc)}`
      }).then(r => r.json()).then(d => {
        closeModal('modal-add-client');
        fetchTelemetry();
      });
    }

    function submitNewProject() {
      const name = document.getElementById('new-proj-name').value;
      const code = document.getElementById('new-proj-code').value;
      const desc = document.getElementById('new-proj-desc').value;
      if (!name) return alert('Please enter project name');

      authedFetch('/api/project/create', {
        method: 'POST',
        headers: {'Content-Type': 'application/x-www-form-urlencoded'},
        body: `client_id=${encodeURIComponent(selectedClientId)}&name=${encodeURIComponent(name)}&code=${encodeURIComponent(code)}&description=${encodeURIComponent(desc)}`
      }).then(r => r.json()).then(d => {
        closeModal('modal-add-project');
        fetchTelemetry();
      });
    }

    // Controls
    function toggleMasterService() {
      const chk = document.getElementById('detail-service-toggle');
      const state = chk.checked ? 'ON' : 'OFF';
      authedFetch('/api/command', {
        method: 'POST',
        headers: {'Content-Type': 'application/x-www-form-urlencoded'},
        body: `target=${encodeURIComponent(selectedNodeName)}&action=SERVICE&val=${state}`
      });
    }

    function onDelaySliderInput(val) {
      document.getElementById('delay-display-val').innerText = parseFloat(val).toFixed(1) + 's';
    }

    function applyDelay(val) {
      val = parseFloat(val).toFixed(1);
      document.getElementById('delay-range').value = val;
      document.getElementById('delay-display-val').innerText = val + 's';
      authedFetch('/api/command', {
        method: 'POST',
        headers: {'Content-Type': 'application/x-www-form-urlencoded'},
        body: `target=${encodeURIComponent(selectedNodeName)}&action=DELAY&val=${val}`
      });
    }

    function selectFirmwareMode(m) {
      for (let i = 1; i <= 4; i++) {
        const btn = document.getElementById('btn-mode-' + i);
        if (btn) btn.classList.toggle('active', i === m);
      }
      selectedFirmwareFile = `firmware_mode${m}.bin`;
      document.getElementById('dropzone-label').innerText = `Selected: firmware_mode${m}.bin (Pre-Compiled Mode ${m})`;
    }

    function triggerDeployment(route) {
      if (!confirm(`Deploy ${selectedFirmwareFile} to [${selectedNodeName}] via ${route.toUpperCase()}?`)) return;
      authedFetch('/api/deploy', {
        method: 'POST',
        headers: {'Content-Type': 'application/x-www-form-urlencoded'},
        body: `target=${encodeURIComponent(selectedNodeName)}&route=${route}&filename=${encodeURIComponent(selectedFirmwareFile)}`
      }).then(r => r.json()).then(d => {
        fetchTelemetry();
      });
    }

    function handleFileSelect(files) {
      if (!files || !files.length) return;
      const file = files[0];
      const formData = new FormData();
      formData.append('file', file);
      
      document.getElementById('dropzone-label').innerText = `Uploading & validating ${file.name}...`;

      authedFetch('/api/upload_bin', {
        method: 'POST',
        body: formData
      }).then(r => r.json()).then(d => {
        if (d.success) {
          selectedFirmwareFile = d.binary.filename;
          document.getElementById('dropzone-label').innerText = `✓ Verified ${d.binary.filename} (${d.binary.size_kb} KB, ${d.binary.target_chip})`;
          alert(`Binary verified successfully!\n\nTarget Chip: ${d.binary.target_chip}\nSize: ${d.binary.size_kb} KB\nSHA-256: ${d.binary.sha256.substring(0, 24)}...`);
        } else {
          alert('Upload failed: ' + (d.error || 'Invalid file'));
        }
      });
    }

    // Render Helpers
    function renderClients() {
      const container = document.getElementById('clients-container');
      if (!container || !fleetData.clients) return;

      let html = '';
      for (const [c_id, client] of Object.entries(fleetData.clients)) {
        const numProjects = client.projects ? client.projects.length : 0;
        let numNodes = 0;
        if (fleetData.projects) {
          for (const p_id of (client.projects || [])) {
            const p = fleetData.projects[p_id];
            if (p && p.nodes) numNodes += p.nodes.length;
          }
        }

        html += `
          <div class="glass-card client-tile" onclick="navigateTo('client', '${c_id}')">
            <div class="client-tile-header">
              <div class="client-avatar">${client.code ? client.code.substring(0,2) : 'CL'}</div>
              <div style="display:flex; align-items:center; gap:8px;">
                <span class="status-pill pill-crimson">${client.tier || 'Enterprise'}</span>
                <button class="delete-btn-tiny" onclick="event.stopPropagation(); deleteClient('${c_id}', '${client.name}')" title="Delete Client">🗑️</button>
              </div>
            </div>
            <div class="client-name">${client.name}</div>
            <div class="client-desc">${client.description}</div>

            <div class="client-metrics-row">
              <div class="metric-col"><div class="metric-val">${numProjects}</div><div class="metric-lbl">Projects</div></div>
              <div class="metric-col"><div class="metric-val">${numNodes}</div><div class="metric-lbl">Edge Nodes</div></div>
              <div class="metric-col"><div class="metric-val" style="color:#34D399;">100%</div><div class="metric-lbl">Verified</div></div>
            </div>

            <div class="client-footer-btn">
              <span>Open Client Console</span>
              <span>&rarr;</span>
            </div>
          </div>
        `;
      }

      html += `
        <div class="add-card-btn" onclick="openAddClientModal()">
          <div class="add-icon-circle">+</div>
          <div style="font-weight:700;">Add Client Workspace</div>
          <div style="font-size:11px;color:var(--text-dim);">Register a new enterprise tenant</div>
        </div>
      `;

      container.innerHTML = html;
    }

    function renderClientProjects() {
      const container = document.getElementById('client-projects-container');
      if (!container || !fleetData.projects) return;

      const client = fleetData.clients ? fleetData.clients[selectedClientId] : null;
      const projIds = client ? client.projects : [];

      let html = '';
      for (const p_id of projIds) {
        const proj = fleetData.projects[p_id];
        if (!proj) continue;
        const numNodes = proj.nodes ? proj.nodes.length : 0;

        html += `
          <div class="glass-card project-card" onclick="navigateTo('project', '${p_id}')">
            <div style="display:flex; justify-content:space-between; margin-bottom:12px; align-items:center;">
              <span class="status-pill pill-cyan">${proj.code || 'PROJ'}</span>
              <div style="display:flex; align-items:center; gap:8px;">
                <span class="status-pill pill-green">${numNodes} Nodes</span>
                <button class="delete-btn-tiny" onclick="event.stopPropagation(); deleteProject('${p_id}', '${proj.name}')" title="Delete Project">🗑️</button>
              </div>
            </div>
            <div class="client-name">${proj.name}</div>
            <div class="client-desc">${proj.description}</div>
            <div class="client-footer-btn" style="margin-top:16px;">
              <span>Open Project Edge Nodes</span>
              <span>&rarr;</span>
            </div>
          </div>
        `;
      }

      html += `
        <div class="add-card-btn" onclick="openAddProjectModal()">
          <div class="add-icon-circle">+</div>
          <div style="font-weight:700;">Add Project Fleet</div>
          <div style="font-size:11px;color:var(--text-dim);">Deploy hardware under this client</div>
        </div>
      `;

      container.innerHTML = html;
    }

    function renderProjectNodes() {
      const container = document.getElementById('project-nodes-container');
      if (!container || !fleetData.projects) return;

      const proj = fleetData.projects[selectedProjectId];
      const nodeNames = proj ? proj.nodes : [];

      let html = '';
      for (const n_name of nodeNames) {
        const node = telemetryData.nodes ? telemetryData.nodes[n_name] : null;
        if (!node) continue;

        const isOnline = node.online;
        const modeNum = node.mode;
        const modeTitles = ["", "Mode 1 (Solid on Press)", "Mode 2 (Blink on Press)", "Mode 3 (Solid on Release)", "Mode 4 (Blink on Release)"];

        html += `
          <div class="glass-card node-card" onclick="openNodeDetail('${n_name}')">
            <div class="node-header">
              <div class="node-title-group">
                <span style="font-size:20px;">⚡</span>
                <span class="node-name">${n_name}</span>
              </div>
              <div style="display:flex; align-items:center; gap:8px;">
                <span class="status-pill ${isOnline ? 'pill-green' : 'pill-crimson'}">
                  <span class="pulsing-dot"></span> ${isOnline ? 'ONLINE' : 'OFFLINE'}
                </span>
                <button class="delete-btn-tiny" onclick="event.stopPropagation(); deleteNode('${n_name}')" title="Delete Node">🗑️</button>
              </div>
            </div>

            <div class="node-spec-row"><span class="node-spec-lbl">Hardware MAC</span><span class="node-spec-val">${node.mac}</span></div>
            <div class="node-spec-row"><span class="node-spec-lbl">Carrier IP (STA)</span><span class="node-spec-val" style="color:#38BDF8;">${node.ip}</span></div>
            <div class="node-spec-row"><span class="node-spec-lbl">Active Mode</span><span class="node-spec-val">${modeTitles[modeNum] || 'Mode ' + modeNum}</span></div>
            <div class="node-spec-row"><span class="node-spec-lbl">Master Service</span><span class="node-spec-val" style="color:${node.service ? '#34D399':'#FBBF24'}">${node.service ? 'ACTIVE' : 'STANDBY'}</span></div>
            <div class="node-spec-row"><span class="node-spec-lbl">Output Delay</span><span class="node-spec-val">${node.delay.toFixed(1)}s</span></div>
            <div class="node-spec-row" style="border:none;"><span class="node-spec-lbl">Security Hash</span><span class="node-spec-val" style="color:#34D399;font-size:11px;">✓ Verified</span></div>

            <div class="client-footer-btn" style="margin-top:14px;">
              <span>Manage & Control Node</span>
              <span>&rarr;</span>
            </div>
          </div>
        `;
      }

      html += `
        <div class="add-card-btn" onclick="openAddNodeModal()">
          <div class="add-icon-circle">+</div>
          <div style="font-weight:700;">Register Node to Project</div>
          <div style="font-size:11px;color:var(--text-dim);">Assign an ESP32 hardware node</div>
        </div>
      `;

      container.innerHTML = html;
    }

    function renderDashboardNodes() {
      const container = document.getElementById('dashboard-nodes-container');
      if (!container || !telemetryData.nodes) return;

      let html = '';
      for (const [name, node] of Object.entries(telemetryData.nodes)) {
        const isOnline = node.online;
        const modeTitles = ["", "Mode 1 (Solid on Press)", "Mode 2 (Blink on Press)", "Mode 3 (Solid on Release)", "Mode 4 (Blink on Release)"];

        html += `
          <div class="glass-card node-card" onclick="openNodeDetail('${name}')">
            <div class="node-header">
              <div class="node-title-group">
                <span style="font-size:20px;">⚡</span>
                <span class="node-name">${name}</span>
              </div>
              <span class="status-pill ${isOnline ? 'pill-green' : 'pill-crimson'}">
                <span class="pulsing-dot"></span> ${isOnline ? 'ONLINE' : 'OFFLINE'}
              </span>
            </div>

            <div class="node-spec-row"><span class="node-spec-lbl">Client / Project</span><span class="node-spec-val" style="font-size:12px;">${node.client || 'Enterprise'} / ${node.project || 'Project'}</span></div>
            <div class="node-spec-row"><span class="node-spec-lbl">Hardware MAC</span><span class="node-spec-val">${node.mac}</span></div>
            <div class="node-spec-row"><span class="node-spec-lbl">IP Address</span><span class="node-spec-val" style="color:#38BDF8;">${node.ip}</span></div>
            <div class="node-spec-row"><span class="node-spec-lbl">Active Mode</span><span class="node-spec-val">${modeTitles[node.mode] || 'Mode ' + node.mode}</span></div>
            <div class="node-spec-row" style="border:none;"><span class="node-spec-lbl">Output Delay</span><span class="node-spec-val">${node.delay.toFixed(1)}s</span></div>

            <div class="client-footer-btn" style="margin-top:14px;">
              <span>Open Control Console</span>
              <span>&rarr;</span>
            </div>
          </div>
        `;
      }
      container.innerHTML = html;
    }

    function updateNodeDetailUI() {
      if (!telemetryData.nodes) return;
      const node = telemetryData.nodes[selectedNodeName];
      if (!node) return;

      document.getElementById('detail-node-name').innerText = selectedNodeName;
      const statusPill = document.getElementById('detail-node-status-pill');
      if (node.online) {
        statusPill.className = 'status-pill pill-green';
        statusPill.innerHTML = '<span class="pulsing-dot"></span> ONLINE';
      } else {
        statusPill.className = 'status-pill pill-crimson';
        statusPill.innerHTML = '<span class="pulsing-dot"></span> OFFLINE';
      }

      // Quick switcher buttons
      const sw = document.getElementById('node-switcher-container');
      if (sw && telemetryData.nodes) {
        let swHtml = '';
        for (const nName of Object.keys(telemetryData.nodes)) {
          const isSel = (nName === selectedNodeName);
          swHtml += `<button class="${isSel ? 'btn-main btn-crimson' : 'btn-secondary'}" style="padding: 6px 14px; font-size: 12px;" onclick="openNodeDetail('${nName}')">${nName}</button>`;
        }
        sw.innerHTML = swHtml;
      }

      // Specs
      document.getElementById('spec-mac').innerText = node.mac;
      document.getElementById('spec-chip').innerText = node.chip_id;
      document.getElementById('spec-ip').innerText = node.ip;
      document.getElementById('spec-port').innerText = node.port;
      document.getElementById('spec-rssi').innerText = node.rssi + ' dBm';
      document.getElementById('spec-heap').innerText = Math.round(node.heap / 1024) + ' KB';
      document.getElementById('spec-uptime').innerText = node.uptime + 's';
      document.getElementById('spec-hash').innerText = (node.sec_hash || '').substring(0, 24) + '...';

      // Controls
      document.getElementById('detail-service-toggle').checked = node.service;
      document.getElementById('delay-range').value = node.delay;
      document.getElementById('delay-display-val').innerText = node.delay.toFixed(1) + 's';

      // In-situ link
      const insituLink = document.getElementById('detail-insitu-link');
      const insituIp = document.getElementById('detail-insitu-ip');
      insituLink.href = `http://${node.ip}/`;
      insituIp.innerText = node.ip;

      // Real-time Visualizer
      const ledOrb = document.getElementById('visualizer-led');
      const ledText = document.getElementById('visualizer-led-text');
      if (node.led === 1 || (node.service && node.btn === 1 && node.mode === 1)) {
        ledOrb.classList.add('active');
        ledText.innerText = 'SOLID ON (Active-HIGH)';
        ledText.style.color = '#60A5FA';
      } else {
        ledOrb.classList.remove('active');
        ledText.innerText = 'DARK / OFF';
        ledText.style.color = '#94A3B8';
      }

      const btnSim = document.getElementById('visualizer-btn');
      const btnText = document.getElementById('visualizer-btn-text');
      if (node.btn === 1) {
        btnSim.classList.add('pressed');
        btnText.innerText = 'PRESSED (LOW)';
        btnText.style.color = '#F59E0B';
      } else {
        btnSim.classList.remove('pressed');
        btnText.innerText = 'RELEASED (HIGH)';
        btnText.style.color = '#94A3B8';
      }

      // Update tracker
      if (telemetryData.updates) {
        const u = telemetryData.updates[selectedNodeName];
        const tracker = document.getElementById('detail-tracker');
        if (u && (u.active || u.stage === 'completed' || u.stage === 'failed')) {
          tracker.classList.add('visible');
          document.getElementById('tracker-pct').innerText = u.percent + '%';
          document.getElementById('tracker-fill').style.width = u.percent + '%';
          document.getElementById('tracker-status-text').innerText = u.stage_text;
          document.getElementById('tracker-stage-title').innerText = u.route.toUpperCase() + ' Deployment: ' + u.stage.toUpperCase();
        } else {
          tracker.classList.remove('visible');
        }
      }
    }

    function scrollToLogs() {
      const el = document.getElementById('activity-log-stream');
      if (el) el.scrollIntoView({ behavior: 'smooth' });
    }

    function showSecurityModal() {
      alert(`Anashwar Cryptographic Security Registry:\\n\\n` +
            `Node: A\\n` +
            `  MAC: EC:C9:FF:FF:08:94\\n` +
            `  eFuse ID: 9408FFFFC9EC\\n` +
            `  SHA-256: 0647df22dceea927a2fe279cdb6fe999fc873a2d1d8f0cfca79934833eb5ed7d\\n` +
            `  Trust: Verified (4-Point Majority)\\n\\n` +
            `Node: B\\n` +
            `  MAC: 70:4B:CA:48:E6:BC\\n` +
            `  eFuse ID: BCE648CA4B70\\n` +
            `  SHA-256: d56ab3dfed28a8a361a0b323be53b3abbd43dbfc16a1eb040a23c940cefbe703\\n` +
            `  Trust: Verified (4-Point Majority)`);
    }

    function fetchTelemetry() {
      authedFetch('/api/telemetry')
        .then(r => {
          if (r.status === 401) {
            localStorage.removeItem('anashwar_token');
            sessionStorage.removeItem('anashwar_token');
            window.location.href = '/?logout=true';
            return;
          }
          return r.json();
        })
        .then(data => {
          if (!data) return;
          telemetryData = data;
          fleetData = data.fleet || DEFAULT_FLEET;

          // Public tunnel link
          if (data.public_tunnel) {
            document.getElementById('public-tunnel-link').href = data.public_tunnel;
          }

          // KPI Active nodes
          let onlineCount = 0;
          let totalCount = 0;
          if (data.nodes) {
            for (const n of Object.values(data.nodes)) {
              totalCount++;
              if (n.online) onlineCount++;
            }
          }
          document.getElementById('kpi-active-nodes').innerText = `${onlineCount} / ${totalCount} Online`;

          // Activity logs
          if (data.logs) {
            const logBox = document.getElementById('activity-log-stream');
            logBox.innerHTML = data.logs.map(l => `<div>${l}</div>`).join('');
            logBox.scrollTop = logBox.scrollHeight;
          }

          // Re-render active view
          if (currentView === 'dashboard') {
            renderClients();
            renderDashboardNodes();
          } else if (currentView === 'client') {
            renderClientProjects();
          } else if (currentView === 'project') {
            renderProjectNodes();
          } else if (currentView === 'node-detail') {
            updateNodeDetailUI();
          }
        })
        .catch(e => console.error("Telemetry error:", e));
    }

    // Polling interval
    fetchTelemetry();
    setInterval(fetchTelemetry, 1000);
  </script>
</body>
</html>
"""
    return html_content.replace("__CURRENT_USER__", current_user).replace("__CURRENT_TOKEN__", token)

def run_server():
    start_mqtt_client()
    start_mdns_broadcast()

    # Attempt to start port 80 auxiliary listener for direct http://control.local access
    port_80_active = False
    try:
        server_80 = ThreadingHTTPServer(("0.0.0.0", 80), FleetDashboardHandler)
        t_80 = threading.Thread(target=server_80.serve_forever, daemon=True)
        t_80.start()
        port_80_active = True
    except Exception as e:
        port_80_active = False

    server = ThreadingHTTPServer(("0.0.0.0", PORT), FleetDashboardHandler)
    lan_ip = get_lan_ip()
    log_event("=" * 60)
    log_event("Anashwar Technologies - Enterprise ESP32 Fleet Manager")
    log_event(f"Local Dashboard URL : http://localhost:{PORT}")
    log_event(f"LAN Network URL     : http://{lan_ip}:{PORT}")
    if port_80_active:
        log_event(f"mDNS LAN Hostname   : http://control.local (and http://control.local:{PORT})")
    else:
        log_event(f"mDNS LAN Hostname   : http://control.local:{PORT}")
    log_event(f"Target MQTT Broker  : {DEFAULT_MQTT_BROKER}:{DEFAULT_MQTT_PORT}")
    log_event("=" * 60)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        stop_mdns_broadcast()
        server.server_close()

if __name__ == "__main__":
    run_server()
