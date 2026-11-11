#!/usr/bin/env python3
"""
Anashwar Technologies - Enterprise Fleet Management Console
Multi-Page Cloud & USB Firmware Management System for Multi-MCU Edge Nodes
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
import uuid
import base64
import ipaddress
import urllib.request
import urllib.parse
import urllib.error
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse

PORT = int(os.environ.get("PORT", 8080))
DEFAULT_MQTT_BROKER = "broker.hivemq.com"
DEFAULT_MQTT_PORT = 1883
DEFAULT_MQTT_TOPIC_COMMANDS = "anashwar/poc/commands"
DEFAULT_MQTT_TOPIC_STATUS = "anashwar/poc/status"
PROXY_TOPIC_REQ_PREFIX = "anashwar/proxy/req/"
PROXY_TOPIC_RES = "anashwar/proxy/res"
SECURITY_SALT = "AnashwarEnterprise2026SecureSalt"

_mqtt_pub_lock = threading.Lock()
_mqtt_pub_sock = None
_proxy_lock = threading.Lock()
pending_proxy_requests = {}

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
BINARIES_DIR = os.path.join(PROJECT_ROOT, "binaries")
STATIC_DIR = os.path.join(PROJECT_ROOT, "static")
REGISTRY_FILE = os.path.join(PROJECT_ROOT, "fleet_registry.json")
USERS_FILE = os.path.join(PROJECT_ROOT, "users.json")
REGISTRY_DIR = os.path.join(PROJECT_ROOT, "registry_logs")
WEBAUTHN_FILE = os.path.join(PROJECT_ROOT, "webauthn_credentials.json")
os.makedirs(BINARIES_DIR, exist_ok=True)
os.makedirs(STATIC_DIR, exist_ok=True)
os.makedirs(REGISTRY_DIR, exist_ok=True)

# User Database & Session Store
users_db = {}
active_sessions = {}  # token -> device_info dict with username, os, device_model, ip, location, etc.
ACTIVE_SESSIONS_FILE = os.path.join(PROJECT_ROOT, "active_sessions.json")
session_history = []  # list of past login device telemetry records
SESSION_HISTORY_FILE = os.path.join(PROJECT_ROOT, "session_history.json")
webauthn_credentials = {} # username -> list of credentials
webauthn_challenges = {} # username / _login_ -> {"challenge": str, "ts": float}
last_presence_ping_time = 0.0
geo_cache = {}

def load_active_sessions():
    global active_sessions
    if os.path.isfile(ACTIVE_SESSIONS_FILE):
        try:
            with open(ACTIVE_SESSIONS_FILE, "r") as f:
                active_sessions = json.load(f)
                return
        except Exception as e:
            print(f"[AUTH] Error reading {ACTIVE_SESSIONS_FILE}: {e}")
    active_sessions = {}

def save_active_sessions():
    try:
        with open(ACTIVE_SESSIONS_FILE, "w") as f:
            json.dump(active_sessions, f, indent=2)
    except Exception as e:
        print(f"[AUTH] Error saving {ACTIVE_SESSIONS_FILE}: {e}")

load_active_sessions()

def load_session_history():
    global session_history
    if os.path.isfile(SESSION_HISTORY_FILE):
        try:
            with open(SESSION_HISTORY_FILE, "r") as f:
                session_history = json.load(f)
                return
        except Exception:
            pass
    session_history = []

def save_session_history():
    try:
        with open(SESSION_HISTORY_FILE, "w") as f:
            json.dump(session_history[-60:], f, indent=2)
    except Exception:
        pass

load_session_history()

def add_session_history(info):
    global session_history
    session_history.append(info)
    if len(session_history) > 60:
        session_history = session_history[-60:]
    save_session_history()

def load_webauthn():
    global webauthn_credentials
    if os.path.isfile(WEBAUTHN_FILE):
        try:
            with open(WEBAUTHN_FILE, "r") as f:
                webauthn_credentials = json.load(f)
                return
        except Exception as e:
            print(f"[AUTH] Error reading {WEBAUTHN_FILE}: {e}")
    webauthn_credentials = {}

def save_webauthn():
    try:
        with open(WEBAUTHN_FILE, "w") as f:
            json.dump(webauthn_credentials, f, indent=2)
    except Exception as e:
        print(f"[AUTH] Error saving {WEBAUTHN_FILE}: {e}")

load_webauthn()

def get_ip_geolocation(ip_str=""):
    if not ip_str or ip_str.startswith("192.168.") or ip_str.startswith("10.") or ip_str.startswith("172.") or ip_str == "127.0.0.1":
        cache_key = "wan_self"
        url = "http://ip-api.com/json/"
    else:
        cache_key = ip_str
        url = f"http://ip-api.com/json/{ip_str}"

    if cache_key in geo_cache and (time.time() - geo_cache[cache_key]["ts"] < 3600):
        return geo_cache[cache_key]["data"]

    res = {
        "location": "Pune, Maharashtra, India",
        "city": "Pune",
        "region": "Maharashtra",
        "country": "India",
        "isp": "Reliance Jio Infocomm Limited",
        "public_ip": ""
    }
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "AnashwarFleet/1.0"})
        with urllib.request.urlopen(req, timeout=3) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            if data.get("status") == "success":
                city = data.get("city", "")
                region = data.get("regionName", "")
                country = data.get("country", "")
                isp = data.get("isp", "")
                query_ip = data.get("query", "")
                loc_parts = [p for p in [city, region, country] if p]
                loc_str = ", ".join(loc_parts) if loc_parts else (country or "Global")
                res = {
                    "location": loc_str,
                    "city": city,
                    "region": region,
                    "country": country,
                    "isp": isp,
                    "public_ip": query_ip
                }
                geo_cache[cache_key] = {"ts": time.time(), "data": res}
                return res
    except Exception as e:
        pass
    geo_cache[cache_key] = {"ts": time.time(), "data": res}
    return res

def parse_client_device(user_agent_str, headers=None, client_ip="127.0.0.1", extra_payload=None):
    ua = user_agent_str or ""
    headers = headers or {}
    extra_payload = extra_payload or {}

    # 1. Operating System Detection
    os_name = "Unknown OS"
    if "iPhone" in ua or "iPad" in ua or "iPod" in ua:
        os_name = "Apple iOS" if "iPhone" in ua else "Apple iPadOS"
        m = re.search(r"OS (\d+[_\d]*)", ua)
        if m:
            os_name += " " + m.group(1).replace("_", ".")
    elif "Android" in ua:
        os_name = "Android"
        m = re.search(r"Android (\d+(\.\d+)?)", ua)
        if m:
            os_name += " " + m.group(1)
    elif "Macintosh" in ua or "Mac OS X" in ua:
        os_name = "macOS (Apple Mac)"
        m = re.search(r"Mac OS X (\d+[_\d]*)", ua)
        if m:
            os_name += " " + m.group(1).replace("_", ".")
    elif "Windows NT 10.0" in ua:
        os_name = "Windows 11 / 10"
    elif "Windows NT" in ua:
        os_name = "Windows"
    elif "Linux" in ua:
        os_name = "Linux"

    # 2. Device Name & Model
    device_model = extra_payload.get("device_model", "")
    if isinstance(device_model, list):
        device_model = device_model[0] if device_model else ""
    device_model = device_model.strip() if device_model else ""

    if not device_model:
        if "iPhone" in ua:
            device_model = "Apple iPhone"
        elif "iPad" in ua:
            device_model = "Apple iPad"
        elif "SM-" in ua or "Samsung" in ua:
            m = re.search(r"(SM-[A-Za-z0-9]+)", ua)
            device_model = f"Samsung Galaxy ({m.group(1)})" if m else "Samsung Galaxy"
        elif "Pixel" in ua:
            m = re.search(r"(Pixel [A-Za-z0-9 ]+)", ua)
            device_model = f"Google {m.group(1)}" if m else "Google Pixel"
        elif "Macintosh" in ua:
            device_model = "Apple MacBook / Mac"
        elif "Windows" in ua:
            device_model = "PC Desktop / Laptop"
        else:
            device_model = "Edge Terminal"

    # 3. Touch Screen & Form Factor
    is_touch = extra_payload.get("is_touch")
    if isinstance(is_touch, list):
        is_touch = is_touch[0] if is_touch else False
    if isinstance(is_touch, str):
        is_touch = (is_touch.lower() in ("true", "1", "yes"))
    if is_touch is None:
        is_touch = ("Mobile" in ua or "Android" in ua or "iPhone" in ua or "iPad" in ua)

    device_type = "Touch Screen Phone" if ("iPhone" in ua or ("Android" in ua and "Mobile" in ua)) else \
                  "Touch Screen Tablet" if ("iPad" in ua or ("Android" in ua and "Mobile" not in ua)) else \
                  "Touch Device" if is_touch else "Desktop / PC (Non-Touch)"

    # Screen resolution
    screen_res = extra_payload.get("screen", "")
    if isinstance(screen_res, list):
        screen_res = screen_res[0] if screen_res else ""
    screen_res = screen_res or ("Retina Mobile" if is_touch else "Desktop FHD")

    # 4. Geolocation & IP
    geo = get_ip_geolocation(client_ip)

    now = time.localtime()
    return {
        "os": os_name,
        "device_model": device_model,
        "device_type": device_type,
        "is_touch": bool(is_touch),
        "screen": screen_res,
        "ip": client_ip,
        "location": geo.get("location", "Pune, Maharashtra, India"),
        "carrier": geo.get("isp", "Reliance Jio"),
        "login_time": time.time(),
        "login_time_str": time.strftime("%Y-%m-%d %H:%M:%S", now),
        "last_active": time.time()
    }

def can_user_view_log(line, caller_username, caller_role):
    # If no actor tag, default to system event (visible to everyone)
    if "[ACTOR:" not in line:
        return True
    try:
        tag_start = line.find("[ACTOR:")
        tag_end = line.find("]", tag_start)
        if tag_start < 0 or tag_end < 0:
            return True
        tag = line[tag_start+7:tag_end]
        parts = tag.split(":")
        if len(parts) < 2:
            return True
        actor = parts[0]
        role = parts[1]

        # 1. System hardware telemetry is visible to all users
        if role == "SYSTEM" or actor == "SYSTEM":
            return True

        # 2. Super Admin sees ALL actions
        if caller_role == "Super Admin":
            return True

        # 3. Fleet Operator:
        # - sees his own actions
        # - sees standard Users' actions
        # - CANNOT see Super Admin actions
        # - CANNOT see other Fleet Operators' actions
        if caller_role == "Fleet Operator":
            if role == "Super Admin":
                return False
            if role == "Fleet Operator":
                return (actor == caller_username)
            if role == "User":
                return True
            return False

        # 4. Standard User:
        # - sees ONLY his own actions
        if caller_role == "User":
            return (actor == caller_username)

        return False
    except Exception:
        return True

def format_log_display(line, caller_role):
    if "[ACTOR:" not in line:
        return line
    try:
        tag_start = line.find("[ACTOR:")
        tag_end = line.find("]", tag_start)
        tag = line[tag_start+7:tag_end]
        parts = tag.split(":")
        actor = parts[0]
        role = parts[1]
        clean_text = (line[:tag_start] + line[tag_end+1:]).strip()
        if actor == "SYSTEM":
            return clean_text
        if caller_role == "Super Admin":
            return f"{clean_text} [{actor} • {role}]"
        return f"{clean_text} (by {actor})"
    except Exception:
        return line

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

    # 2. Authorization Header: Bearer <token> or X-Session-Token
    if not token:
        auth_header = headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:].strip()
        elif headers.get("X-Session-Token"):
            token = headers.get("X-Session-Token", "").strip()
        elif headers.get("X-Auth-Token"):
            token = headers.get("X-Auth-Token", "").strip()

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
    "clients": {},
    "projects": {},
    "registered_nodes": {},
    "history": {
        "clients": {},
        "projects": {},
        "nodes": {}
    }
}

fleet_registry = {
    "clients": {},
    "projects": {},
    "registered_nodes": {},
    "history": {
        "clients": {},
        "projects": {},
        "nodes": {}
    }
}

_last_history_save_ts = 0.0

def norm_name(s):
    if not s:
        return ""
    s = str(s).replace("\u2018", "'").replace("\u2019", "'").replace("\u201c", '"').replace("\u201d", '"')
    return re.sub(r"\s+", " ", s).strip()

def norm_key(s):
    return norm_name(s).lower()

def ensure_history_schema():
    if "history" not in fleet_registry or not isinstance(fleet_registry["history"], dict):
        fleet_registry["history"] = {"clients": {}, "projects": {}, "nodes": {}}
    for k in ("clients", "projects", "nodes"):
        if k not in fleet_registry["history"] or not isinstance(fleet_registry["history"][k], dict):
            fleet_registry["history"][k] = {}

def load_fleet_registry():
    global fleet_registry
    dirty = False
    if os.path.isfile(REGISTRY_FILE):
        try:
            with open(REGISTRY_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                if "clients" in data and "projects" in data and "registered_nodes" in data:
                    fleet_registry = data
        except Exception as e:
            print(f"[REGISTRY] Error reading {REGISTRY_FILE}: {e}")
            dirty = True
    else:
        dirty = True

    ensure_history_schema()

    # Remove legacy hardcoded POC dummy clients/nodes if lingering from old files
    stale_client_ids = [
        cid for cid, c in list(fleet_registry.get("clients", {}).items())
        if cid in ("client_1", "client_1793973495")
        or norm_key(c.get("name", "")) in ("client 1: alpha enterprise corp", "hamley's x cadbury milkinis")
    ]
    for cid in stale_client_ids:
        c_obj = fleet_registry["clients"].pop(cid, None)
        if c_obj:
            for pid in list(c_obj.get("projects", [])):
                fleet_registry["projects"].pop(pid, None)
        dirty = True

    for pid, p_obj in list(fleet_registry.get("projects", {}).items()):
        if p_obj.get("client_id") in stale_client_ids or pid == "proj_1":
            fleet_registry["projects"].pop(pid, None)
            dirty = True

    for n_name, n_obj in list(fleet_registry.get("registered_nodes", {}).items()):
        if n_obj.get("client_id") in stale_client_ids or n_name in ("Node: A", "Node: B"):
            fleet_registry["registered_nodes"].pop(n_name, None)
            dirty = True

    if dirty:
        save_fleet_registry()

def save_fleet_registry():
    try:
        ensure_history_schema()
        with open(REGISTRY_FILE, "w", encoding="utf-8") as f:
            json.dump(fleet_registry, f, indent=2)
    except Exception as e:
        print(f"[REGISTRY] Error saving {REGISTRY_FILE}: {e}")

def record_history_online(node_name, client_name, project_name, tdata):
    """Upsert deduplicated client/project/node records whenever a hardware node is online."""
    global _last_history_save_ts
    ensure_history_schema()
    h = fleet_registry["history"]
    c_clean = norm_name(client_name) or "Unassigned Client"
    p_clean = norm_name(project_name) or "Connected Edge Fleet"
    n_clean = norm_name(node_name) or "ESP32-Node"
    c_k = norm_key(c_clean)
    p_k = f"{c_k}::{norm_key(p_clean)}"
    mac_raw = (tdata.get("mac") or "").strip().upper()
    chip_raw = (tdata.get("chip_id") or "").strip().upper()
    n_k = mac_raw or chip_raw or norm_key(n_clean)

    now_ts = time.time()
    now_str = time.strftime("%Y-%m-%d %H:%M:%S")
    is_new = False

    if c_k not in h["clients"]:
        is_new = True
        code = "".join([w[0] for w in c_clean.split() if w and w[0].isalnum()])[:4].upper() or "ENT"
        h["clients"][c_k] = {
            "key": c_k,
            "name": c_clean,
            "code": code,
            "first_seen": now_str,
            "last_seen": now_str,
            "last_seen_ts": now_ts
        }
    else:
        h["clients"][c_k]["name"] = c_clean
        h["clients"][c_k]["last_seen"] = now_str
        h["clients"][c_k]["last_seen_ts"] = now_ts

    if p_k not in h["projects"]:
        is_new = True
        p_code = "".join([w[0] for w in p_clean.split() if w and w[0].isalnum()])[:4].upper() or "PRJ"
        h["projects"][p_k] = {
            "key": p_k,
            "client_key": c_k,
            "client_name": c_clean,
            "name": p_clean,
            "code": p_code,
            "first_seen": now_str,
            "last_seen": now_str,
            "last_seen_ts": now_ts
        }
    else:
        h["projects"][p_k]["name"] = p_clean
        h["projects"][p_k]["client_key"] = c_k
        h["projects"][p_k]["client_name"] = c_clean
        h["projects"][p_k]["last_seen"] = now_str
        h["projects"][p_k]["last_seen_ts"] = now_ts

    if n_k not in h["nodes"]:
        is_new = True
        h["nodes"][n_k] = {
            "key": n_k,
            "project_key": p_k,
            "client_key": c_k,
            "client_name": c_clean,
            "project_name": p_clean,
            "name": n_clean,
            "mac": mac_raw,
            "chip_id": chip_raw,
            "ip": tdata.get("ip", "0.0.0.0"),
            "mcu_family": tdata.get("mcu") or tdata.get("mcu_family") or "ESP32",
            "first_seen": now_str,
            "last_seen": now_str,
            "last_seen_ts": now_ts
        }
    else:
        node_h = h["nodes"][n_k]
        node_h["name"] = n_clean
        node_h["project_key"] = p_k
        node_h["client_key"] = c_k
        node_h["client_name"] = c_clean
        node_h["project_name"] = p_clean
        if mac_raw: node_h["mac"] = mac_raw
        if chip_raw: node_h["chip_id"] = chip_raw
        if tdata.get("ip"): node_h["ip"] = tdata.get("ip")
        if tdata.get("mcu") or tdata.get("mcu_family"):
            node_h["mcu_family"] = tdata.get("mcu") or tdata.get("mcu_family")
        node_h["last_seen"] = now_str
        node_h["last_seen_ts"] = now_ts

    if is_new or (now_ts - _last_history_save_ts >= 60.0):
        _last_history_save_ts = now_ts
        save_fleet_registry()

load_fleet_registry()

# Dynamic auto-discovered hardware devices not yet assigned to a project
auto_discovered_nodes = {}

# Live Hardware Telemetry (starts clean; populated from registered/live MQTT hardware)
nodes_telemetry = {}
node_updates = {}

def sync_telemetry_with_registry():
    global nodes_telemetry, node_updates, fleet_registry
    for n_name, r_node in fleet_registry.get("registered_nodes", {}).items():
        c_id = r_node.get("client_id", "")
        p_id = r_node.get("project_id", "")
        c_name = fleet_registry.get("clients", {}).get(c_id, {}).get("name", "Unassigned Client")
        p_name = fleet_registry.get("projects", {}).get(p_id, {}).get("name", "Connected Edge Fleet")
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
                "offline": False,
                "state": "offline",
                "delay": 0.0,
                "btn": 0,
                "led": 0,
                "rssi": -60,
                "heap": 240000,
                "uptime": 0,
                "mcu_family": "ESP32",
                "mcu_arch": "Xtensa LX6 Dual-Core @ 240MHz",
                "flash_mb": 4.0,
                "ram_total_kb": 320,
                "wireless_bands": "2.4 GHz 802.11 b/g/n + BLE 4.2 (PCB Trace Antenna)",
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
                "filename": "Base_firmware.bin",
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

def _is_ping_noise(text):
    u = str(text or "").upper()
    return (":PING" in u) or ("MANUAL PRESENCE PING" in u)

def log_event(msg, actor="SYSTEM", actor_role="SYSTEM"):
    if _is_ping_noise(msg):
        return
    now = time.localtime()
    day_str = time.strftime("%Y-%m-%d", now)
    ts = time.strftime("[%H:%M:%S]", now)
    meta_tag = f"[ACTOR:{actor}:{actor_role}]"
    entry = f"{meta_tag} {ts} {msg}"
    activity_logs.append(entry)
    if len(activity_logs) > 400:
        activity_logs.pop(0)
    print(f"{ts} [{actor}:{actor_role}] {msg}", flush=True)
    try:
        log_file = os.path.join(REGISTRY_DIR, f"{day_str}.log")
        with open(log_file, "a", encoding="utf-8") as f:
            f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S', now)}] {meta_tag} {msg}\n")
    except Exception as e:
        print(f"[REGISTRY] Error writing daily log: {e}", flush=True)

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
        "size_mb": 0.0,
        "valid": False,
        "magic": "0x00",
        "target_chip": "Unknown",
        "sha256": "",
        "modified": 0,
        "app_desc": {
            "project_name": "",
            "app_version": "",
            "compile_date": "",
            "compile_time": "",
            "idf_version": ""
        },
        "ota_partition": {
            "supported": True,
            "status": "Compatible",
            "required_partition": "default dual-OTA (1.25 MB)",
            "occupancy_pct": 0.0,
            "max_partition_bytes": 1310720,
            "details": ""
        },
        "internet_endpoints": {
            "mqtt_brokers": [],
            "http_endpoints": [],
            "topics": [],
            "wifi_ssids": []
        },
        "telemetry_markers": {
            "mac_reporting": False,
            "chip_id_reporting": False,
            "security_hash": False,
            "client_reporting": False,
            "project_reporting": False,
            "node_name_reporting": False,
            "ip_reporting": False,
            "service_toggle": False,
            "offline_mode": False
        },
        "adherence_score": 0,
        "compliance_status": "Non-Compliant"
    }
    if not os.path.isfile(file_path):
        return info
    try:
        size = os.path.getsize(file_path)
        info["size_bytes"] = size
        info["size_kb"] = round(size / 1024.0, 1)
        info["size_mb"] = round(size / (1024.0 * 1024.0), 2)
        info["modified"] = os.path.getmtime(file_path)

        with open(file_path, "rb") as f:
            data = f.read()

        info["sha256"] = hashlib.sha256(data).hexdigest()

        # Check ESP32 image magic header 0xE9
        if len(data) >= 4 and data[0] == 0xE9:
            info["valid"] = True
            info["magic"] = f"0x{data[0]:02X}"
            chip_id = data[3]
            if chip_id == 0x00: info["target_chip"] = "ESP32 (Classic Dual-Core)"
            elif chip_id == 0x02: info["target_chip"] = "ESP32-S2"
            elif chip_id == 0x05: info["target_chip"] = "ESP32-C3"
            elif chip_id == 0x09: info["target_chip"] = "ESP32-S3"
            else: info["target_chip"] = f"ESP32 (Chip ID {chip_id})"
        else:
            info["valid"] = False
            info["target_chip"] = "Invalid Binary Header"

        # 1. OTA Partition Compatibility Check
        DEFAULT_OTA_BYTES = 1310720    # 1280 KB / 1.25 MB
        MIN_SPIFFS_OTA_BYTES = 1966080 # 1920 KB / 1.875 MB
        if size <= DEFAULT_OTA_BYTES:
            pct = round((size / float(DEFAULT_OTA_BYTES)) * 100.0, 1)
            info["ota_partition"] = {
                "supported": True,
                "status": f"100% Compatible ({pct}% of Default 1.25MB Partition)",
                "required_partition": "default dual-OTA (1.25 MB / 1280 KB)",
                "occupancy_pct": pct,
                "max_partition_bytes": DEFAULT_OTA_BYTES,
                "details": f"Fits standard dual OTA slot ({info['size_kb']} KB / 1280 KB)."
            }
        elif size <= MIN_SPIFFS_OTA_BYTES:
            pct = round((size / float(MIN_SPIFFS_OTA_BYTES)) * 100.0, 1)
            info["ota_partition"] = {
                "supported": True,
                "status": f"Compatible with Min-SPIFFS ({pct}% of 1.87MB Partition)",
                "required_partition": "min_spiffs dual-OTA (1.87 MB / 1920 KB)",
                "occupancy_pct": pct,
                "max_partition_bytes": MIN_SPIFFS_OTA_BYTES,
                "details": f"Fits Min-SPIFFS OTA partition table (up to 1920 KB)."
            }
        else:
            info["ota_partition"] = {
                "supported": False,
                "status": "Partition Warning: Exceeds standard 1.9MB dual-OTA partition",
                "required_partition": "huge_app (3.0 MB) or custom partition table",
                "occupancy_pct": 100.0,
                "max_partition_bytes": MIN_SPIFFS_OTA_BYTES,
                "details": "Binary exceeds standard dual OTA partitions; requires huge_app partition configuration."
            }

        # 2. Extract esp_app_desc struct (magic 0xABCD5432)
        idx_desc = data.find(b'\x32\x54\xcd\xab')
        if idx_desc != -1:
            desc_block = data[idx_desc:idx_desc+256]
            if len(desc_block) >= 144:
                info["app_desc"]["app_version"] = desc_block[16:48].split(b'\x00')[0].decode('utf-8', errors='ignore')
                info["app_desc"]["project_name"] = desc_block[48:80].split(b'\x00')[0].decode('utf-8', errors='ignore')
                info["app_desc"]["compile_time"] = desc_block[80:96].split(b'\x00')[0].decode('utf-8', errors='ignore')
                info["app_desc"]["compile_date"] = desc_block[96:112].split(b'\x00')[0].decode('utf-8', errors='ignore')
                info["app_desc"]["idf_version"] = desc_block[112:144].split(b'\x00')[0].decode('utf-8', errors='ignore')

        # 3. Scan Internet & Cloud Endpoints
        brokers = set()
        topics = set()
        urls = set()
        ssids = set()

        if b"broker.hivemq.com" in data: brokers.add("broker.hivemq.com:1883 (HiveMQ MQTT Mesh)")
        if b"anashwar/poc/commands" in data: topics.add("anashwar/poc/commands (Directives)")
        if b"anashwar/poc/status" in data: topics.add("anashwar/poc/status (Telemetry)")
        if b"manage.anashwartech.com" in data: urls.add("https://manage.anashwartech.com")
        if b"VED-FI" in data: ssids.add("VED-FI (Enterprise Primary)")
        if b"vedfi" in data: ssids.add("vedfi (Fallback SSID)")

        info["internet_endpoints"]["mqtt_brokers"] = list(brokers) or ["broker.hivemq.com:1883"]
        info["internet_endpoints"]["topics"] = list(topics) or ["anashwar/poc/status", "anashwar/poc/commands"]
        info["internet_endpoints"]["http_endpoints"] = list(urls) or ["https://manage.anashwartech.com"]
        info["internet_endpoints"]["wifi_ssids"] = list(ssids) or ["VED-FI", "vedfi"]

        # 4. Scan Telemetry & Identity Adherence Markers
        tm = info["telemetry_markers"]
        tm["mac_reporting"] = (b"esp_efuse_mac_get_default" in data or b"getEfuseMac" in data or b"\"mac\"" in data)
        tm["chip_id_reporting"] = (b"getEfuseMac" in data or b"\"chip_id\"" in data or b"chipId" in data)
        tm["security_hash"] = (b"sec_hash" in data or b"mbedtls_sha256" in data or b"AnashwarEnterprise2026SecureSalt" in data or b"SECURITY_SALT" in data)
        tm["client_reporting"] = (b"\"client\"" in data or b"client_1" in data or b"clientName" in data or b"Alpha Enterprise" in data)
        tm["project_reporting"] = (b"\"project\"" in data or b"proj_1" in data or b"projectName" in data or b"OTA Fleet" in data)
        tm["node_name_reporting"] = (b"\"name\"" in data or b"nodeName" in data or b"Node: A" in data or b"Node: B" in data)
        tm["ip_reporting"] = (b"\"ip\"" in data or b"localIP" in data)
        tm["service_toggle"] = (b"SERVICE:ON" in data or b"systemServiceActive" in data or b"\"service\"" in data)
        tm["offline_mode"] = (b"OFFLINE:ON" in data or b"autonomousOfflineMode" in data or b"\"offline\"" in data)

        passed_count = sum(1 for v in tm.values() if v)
        info["adherence_score"] = int((passed_count / float(len(tm))) * 100)
        if passed_count >= 7:
            info["compliance_status"] = f"Fully Compliant ({passed_count}/{len(tm)} Markers Verified)"
        else:
            info["compliance_status"] = f"Partial Adherence ({passed_count}/{len(tm)} Markers Verified)"

    except Exception as e:
        info["error"] = str(e)
    return info

def resolve_target_node(val):
    if not val:
        return None
    val_clean = norm_name(val)
    if val_clean in nodes_telemetry:
        return val_clean

    v = val_clean.lower()
    for name, node in nodes_telemetry.items():
        if v == norm_key(name):
            return name
        if node.get("mac") and v == node.get("mac", "").lower():
            return name
        if node.get("chip_id") and v == node.get("chip_id", "").lower():
            return name
        if node.get("port") and v == node.get("port", "").lower() and "usb" in v:
            return name
        if node.get("ip") and node.get("ip") not in ("", "0.0.0.0") and v == node.get("ip", "").lower():
            return name
    if ("node: a" in v or v in ("node a", "a", "alpha", "node alpha")) and "Node: A" in nodes_telemetry:
        return "Node: A"
    if ("node: b" in v or v in ("node b", "b", "beta", "node beta")) and "Node: B" in nodes_telemetry:
        return "Node: B"
    return None

def match_or_create_client_project(client_name, project_name):
    c_clean = norm_name(client_name) or "Enterprise Client"
    p_clean = norm_name(project_name) or "Connected Edge Fleet"

    client_id = None
    for cid, c in fleet_registry["clients"].items():
        if norm_key(c.get("name", "")) == norm_key(c_clean):
            client_id = cid
            break
    if not client_id:
        clean_code = "".join([w[0] for w in c_clean.split() if w and w[0].isalnum()])[:4].upper() or "ENT"
        client_id = f"client_{int(time.time())}_{abs(hash(c_clean)) % 1000}"
        fleet_registry["clients"][client_id] = {
            "id": client_id,
            "name": c_clean,
            "code": clean_code,
            "description": f"Auto-discovered Enterprise Client: {c_clean}",
            "tier": "Tier-1 Enterprise SLA",
            "contact": "ops@anashwartech.com",
            "created_at": time.strftime("%Y-%m-%d"),
            "projects": []
        }

    project_id = None
    for pid, p in fleet_registry["projects"].items():
        if p.get("client_id") == client_id and norm_key(p.get("name", "")) == norm_key(p_clean):
            project_id = pid
            break
    if not project_id:
        proj_code = "".join([w[0] for w in p_clean.split() if w and w[0].isalnum()])[:4].upper() or "PRJ"
        project_id = f"proj_{int(time.time())}_{abs(hash(p_clean)) % 1000}"
        fleet_registry["projects"][project_id] = {
            "id": project_id,
            "client_id": client_id,
            "name": p_clean,
            "code": proj_code,
            "description": f"Autonomous Edge Project: {p_clean}",
            "created_at": time.strftime("%Y-%m-%d"),
            "nodes": []
        }
    if project_id not in fleet_registry["clients"][client_id]["projects"]:
        fleet_registry["clients"][client_id]["projects"].append(project_id)

    return client_id, c_clean, project_id, p_clean

def sync_node_identity_from_device(old_key, new_node_name, new_client_name, new_project_name, tdata):
    """Apply node-initiated identity revert (e.g. NVS reset on ESP32 UI) back onto Portal registry."""
    new_node_clean = norm_name(new_node_name) or old_key
    cid, c_clean, pid, p_clean = match_or_create_client_project(new_client_name, new_project_name)

    reg_node = fleet_registry["registered_nodes"].pop(old_key, None) or {
        "mac": tdata.get("mac", ""),
        "chip_id": tdata.get("chip_id", ""),
        "port": tdata.get("port", "WiFi Wireless"),
        "expected_hash": tdata.get("sec_hash", "")
    }
    old_pid = reg_node.get("project_id")
    if old_pid and old_pid in fleet_registry["projects"]:
        old_nodes = fleet_registry["projects"][old_pid].get("nodes", [])
        fleet_registry["projects"][old_pid]["nodes"] = [n for n in old_nodes if n != old_key]

    reg_node["name"] = new_node_clean
    reg_node["client_id"] = cid
    reg_node["project_id"] = pid
    if "reset_seq" in tdata:
        reg_node["last_reset_seq"] = int(tdata.get("reset_seq", 0))
    fleet_registry["registered_nodes"][new_node_clean] = reg_node

    if new_node_clean not in fleet_registry["projects"][pid]["nodes"]:
        fleet_registry["projects"][pid]["nodes"].append(new_node_clean)

    if old_key != new_node_clean:
        t_val = nodes_telemetry.pop(old_key, {})
        t_val["name"] = new_node_clean
        nodes_telemetry[new_node_clean] = t_val
        if old_key in node_updates:
            node_updates[new_node_clean] = node_updates.pop(old_key)

    nodes_telemetry[new_node_clean]["client"] = c_clean
    nodes_telemetry[new_node_clean]["project"] = p_clean
    nodes_telemetry[new_node_clean]["pending_portal_sync"] = False
    nodes_telemetry[new_node_clean]["portal_rename_ts"] = 0

    save_fleet_registry()
    log_event(f"NVS RESET SYNC: Hardware [{new_node_clean}] reverted identity to Client '{c_clean}' / Project '{p_clean}'")
    return new_node_clean

# =============================================================================
# ZERO-DEPENDENCY MQTT CLIENT & HTTP-PROXY RELAY (SOCKET IMPLEMENTATION)
# =============================================================================
def _mqtt_encode_rem_len(n):
    out = bytearray()
    while True:
        d = n % 128
        n //= 128
        if n > 0:
            d |= 0x80
        out.append(d)
        if n == 0:
            return bytes(out)

def _mqtt_recv_exact(sock, n):
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("MQTT socket closed")
        buf.extend(chunk)
    return bytes(buf)

def _handle_proxy_res_chunk(msg_str):
    try:
        pdata = json.loads(msg_str)
    except Exception:
        return
    if not isinstance(pdata, dict):
        return
    rid = str(pdata.get("rid", "")).strip()
    if not rid:
        return
    with _proxy_lock:
        entry = pending_proxy_requests.get(rid)
        if entry is None:
            return
        idx = int(pdata.get("i", 0))
        total = max(1, int(pdata.get("n", 1)))
        entry["total"] = total
        if "st" in pdata:
            entry["status"] = int(pdata["st"])
        if pdata.get("ct"):
            entry["ct"] = str(pdata["ct"])
        if pdata.get("loc"):
            entry["loc"] = str(pdata["loc"])
        if pdata.get("err"):
            entry["err"] = str(pdata["err"])
        entry["chunks"][idx] = str(pdata.get("d", ""))
        if len(entry["chunks"]) >= total and all(k in entry["chunks"] for k in range(total)):
            entry["event"].set()

def start_mqtt_client():
    def mqtt_listener():
        global _mqtt_pub_sock
        while True:
            s = None
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(10)
                s.connect((DEFAULT_MQTT_BROKER, DEFAULT_MQTT_PORT))
                client_id = f"AnashwarSub-{int(time.time()*1000)%100000}".encode('ascii')
                proto = b"MQTT"
                vh = len(proto).to_bytes(2, 'big') + proto + b'\x04\x02\x00\x3c'
                payload = len(client_id).to_bytes(2, 'big') + client_id
                s.sendall(b'\x10' + _mqtt_encode_rem_len(len(vh) + len(payload)) + vh + payload)
                ack = _mqtt_recv_exact(s, 4)
                if len(ack) < 4 or ack[3] != 0:
                    time.sleep(3)
                    continue

                t1 = DEFAULT_MQTT_TOPIC_STATUS.encode('utf-8')
                t2 = PROXY_TOPIC_RES.encode('utf-8')
                sub_vh = b'\x00\x01'
                sub_payload = (
                    len(t1).to_bytes(2, 'big') + t1 + b'\x00' +
                    len(t2).to_bytes(2, 'big') + t2 + b'\x00'
                )
                s.sendall(b'\x82' + _mqtt_encode_rem_len(len(sub_vh) + len(sub_payload)) + sub_vh + sub_payload)

                # Read exact SUBACK frame
                _mqtt_recv_exact(s, 1)
                sub_rem = 0
                sub_mult = 1
                while True:
                    db = _mqtt_recv_exact(s, 1)[0]
                    sub_rem += (db & 127) * sub_mult
                    sub_mult *= 128
                    if not (db & 128):
                        break
                if sub_rem > 0:
                    _mqtt_recv_exact(s, sub_rem)

                with _mqtt_pub_lock:
                    _mqtt_pub_sock = s
                log_event(f"MQTT Connected & Subscribed to '{DEFAULT_MQTT_TOPIC_STATUS}' + '{PROXY_TOPIC_RES}' on {DEFAULT_MQTT_BROKER}")

                last_ping = time.time()
                while True:
                    now = time.time()
                    if now - last_ping >= 20:
                        try:
                            with _mqtt_pub_lock:
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
                    qos = (b1[0] >> 1) & 0x03
                    multiplier = 1
                    rem_len = 0
                    while True:
                        d_byte = _mqtt_recv_exact(s, 1)[0]
                        rem_len += (d_byte & 127) * multiplier
                        multiplier *= 128
                        if not (d_byte & 128):
                            break
                    data = _mqtt_recv_exact(s, rem_len) if rem_len > 0 else b""

                    if pkt_type == 3: # PUBLISH
                        if len(data) < 2:
                            continue
                        topic_len = int.from_bytes(data[0:2], 'big')
                        topic_name = data[2:2+topic_len].decode('utf-8', errors='ignore')
                        payload_offset = 2 + topic_len + (2 if qos > 0 else 0)
                        if qos == 1 and len(data) >= 4 + topic_len:
                            try:
                                with _mqtt_pub_lock:
                                    s.sendall(b'\x40\x02' + data[2+topic_len:4+topic_len])
                            except Exception:
                                pass
                        msg = data[payload_offset:].decode('utf-8', errors='ignore')
                        if topic_name == PROXY_TOPIC_RES:
                            _handle_proxy_res_chunk(msg)
                            continue
                        try:
                            tdata = json.loads(msg)
                            raw_id = tdata.get("id", "")
                            raw_name = norm_name(tdata.get("name", ""))
                            raw_mac = tdata.get("mac", "").strip()
                            raw_chip = tdata.get("chip_id", "").strip()
                            raw_client = norm_name(tdata.get("client", ""))
                            raw_project = norm_name(tdata.get("project", ""))

                            # Prioritize immutable silicon MAC / Chip ID first so renames/resets resolve accurately
                            target_key = (
                                resolve_target_node(raw_mac)
                                or resolve_target_node(raw_chip)
                                or resolve_target_node(raw_name)
                                or resolve_target_node(raw_id)
                            )

                            if not target_key:
                                # ZERO-TOUCH FLEET AUTO-ONBOARDING (Deduplicated & Normalized)
                                target_name = raw_name or f"Node-{raw_mac[-5:].replace(':','').upper() if len(raw_mac)>=5 else str(int(time.time()))[-4:]}"
                                c_in = raw_client or "Enterprise Client"
                                p_in = raw_project or "Connected Edge Fleet"
                                client_id, client_name, project_id, project_name = match_or_create_client_project(c_in, p_in)

                                if target_name not in fleet_registry["projects"][project_id]["nodes"]:
                                    fleet_registry["projects"][project_id]["nodes"].append(target_name)

                                fleet_registry["registered_nodes"][target_name] = {
                                    "name": target_name,
                                    "mac": raw_mac,
                                    "chip_id": raw_chip,
                                    "client_id": client_id,
                                    "project_id": project_id,
                                    "port": tdata.get("port", "WiFi Wireless"),
                                    "expected_hash": tdata.get("sec_hash", ""),
                                    "last_reset_seq": int(tdata.get("reset_seq", 0))
                                }
                                save_fleet_registry()

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
                                    "mcu_family": tdata.get("mcu", "ESP32"),
                                    "mcu_arch": tdata.get("arch", "Xtensa LX6 Dual-Core @ 240MHz"),
                                    "flash_mb": float(tdata.get("flash", 4.0)),
                                    "ram_total_kb": int(tdata.get("ram", 320)),
                                    "wireless_bands": tdata.get("antenna", "2.4 GHz 802.11 b/g/n + BLE 4.2"),
                                    "offline": bool(tdata.get("offline", False)),
                                    "last_seen": time.time(),
                                    "online": True
                                }
                                node_updates[target_name] = {
                                    "active": False,
                                    "route": "cloud",
                                    "filename": "Base_firmware.bin",
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
                            else:
                                # Detect if the ESP32 executed a local NVS Reset to coded defaults
                                cur_node = nodes_telemetry[target_key]
                                reg_entry = fleet_registry["registered_nodes"].get(target_key, {})
                                rep_rst_seq = int(tdata.get("reset_seq", 0)) if "reset_seq" in tdata else 0
                                prev_rst_seq = int(reg_entry.get("last_reset_seq", 0))
                                id_custom = tdata.get("identity_custom", None)

                                names_differ = (
                                    (raw_name and norm_key(raw_name) != norm_key(target_key))
                                    or (raw_client and norm_key(raw_client) != norm_key(cur_node.get("client", "")))
                                    or (raw_project and norm_key(raw_project) != norm_key(cur_node.get("project", "")))
                                )

                                if rep_rst_seq > prev_rst_seq:
                                    target_key = sync_node_identity_from_device(
                                        target_key, raw_name or target_key,
                                        raw_client or cur_node.get("client", ""),
                                        raw_project or cur_node.get("project", ""),
                                        tdata
                                    )
                                elif cur_node.get("pending_portal_sync"):
                                    # Wait for ESP32 echo matching new portal names or 8s grace period
                                    if not names_differ:
                                        cur_node["pending_portal_sync"] = False
                                    elif time.time() - cur_node.get("portal_rename_ts", 0) > 8.0 and id_custom is False and names_differ:
                                        target_key = sync_node_identity_from_device(
                                            target_key, raw_name or target_key,
                                            raw_client or cur_node.get("client", ""),
                                            raw_project or cur_node.get("project", ""),
                                            tdata
                                        )
                                elif id_custom is False and names_differ:
                                    target_key = sync_node_identity_from_device(
                                        target_key, raw_name or target_key,
                                        raw_client or cur_node.get("client", ""),
                                        raw_project or cur_node.get("project", ""),
                                        tdata
                                    )

                            node = nodes_telemetry[target_key]
                            if not node.get("pending_portal_sync"):
                                if raw_client: node["client"] = raw_client
                                if raw_project: node["project"] = raw_project
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
                            if tdata.get("mcu"): node["mcu_family"] = tdata["mcu"]
                            if tdata.get("arch"): node["mcu_arch"] = tdata["arch"]
                            if tdata.get("flash"): node["flash_mb"] = float(tdata["flash"])
                            if tdata.get("ram"): node["ram_total_kb"] = int(tdata["ram"])
                            if tdata.get("antenna"): node["wireless_bands"] = tdata["antenna"]
                            if "offline" in tdata: node["offline"] = bool(tdata["offline"])
                            node["last_seen"] = time.time()
                            node["online"] = True

                            # Record unique seen-online entity into persistent History
                            record_history_online(target_key, node.get("client", ""), node.get("project", ""), node)

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
            except Exception:
                pass
            finally:
                with _mqtt_pub_lock:
                    if _mqtt_pub_sock is s:
                        _mqtt_pub_sock = None
                if s is not None:
                    try:
                        s.close()
                    except Exception:
                        pass
                time.sleep(2)

    t = threading.Thread(target=mqtt_listener, daemon=True)
    t.start()

def publish_fast_mqtt(topic, payload_str, broker=DEFAULT_MQTT_BROKER, port=DEFAULT_MQTT_PORT):
    """Low-latency PUBLISH over persistent MQTT socket, falling back cleanly to one-shot TCP."""
    global _mqtt_pub_sock
    t_bytes = topic.encode('utf-8')
    p_bytes = payload_str.encode('utf-8')
    var_header = len(t_bytes).to_bytes(2, 'big') + t_bytes
    pkt = b'\x30' + _mqtt_encode_rem_len(len(var_header) + len(p_bytes)) + var_header + p_bytes
    with _mqtt_pub_lock:
        sock = _mqtt_pub_sock
        if sock is not None and broker == DEFAULT_MQTT_BROKER and port == DEFAULT_MQTT_PORT:
            try:
                sock.sendall(pkt)
                return True
            except Exception:
                _mqtt_pub_sock = None
    return publish_mqtt_command(topic, payload_str, broker=broker, port=port, silent=True)

def publish_mqtt_command(topic, payload_str, broker=DEFAULT_MQTT_BROKER, port=DEFAULT_MQTT_PORT, silent=False):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(6)
    try:
        s.connect((broker, port))
        client_id = f"AnashwarPub-{int(time.time()*1000)%100000}".encode('ascii')
        proto = b"MQTT"
        vh = len(proto).to_bytes(2, 'big') + proto + b'\x04\x02\x00\x3c'
        payload = len(client_id).to_bytes(2, 'big') + client_id
        s.sendall(b'\x10' + _mqtt_encode_rem_len(len(vh) + len(payload)) + vh + payload)
        ack = s.recv(4)
        if len(ack) < 4 or ack[3] != 0:
            return False

        t_bytes = topic.encode('utf-8')
        p_bytes = payload_str.encode('utf-8')
        var_header = len(t_bytes).to_bytes(2, 'big') + t_bytes
        header = b'\x30' + _mqtt_encode_rem_len(len(var_header) + len(p_bytes))

        s.sendall(header + var_header + p_bytes)
        if not silent and not _is_ping_noise(payload_str):
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
# GLOBAL CLOUD IN-SITU LIVE CONSOLE & MQTT HTTP-PROXY RELAY
# =============================================================================
_PROXY_SHIM_TEMPLATE = r"""<script data-anashwar-proxy="1">
(function(){
  if (window.__anashwarProxyHooked) return;
  window.__anashwarProxyHooked = true;
  var BASE = __BASE_JSON__;
  var TOK = __TOK_JSON__;
  var NODE_IP = __IP_JSON__;
  function addTok(u){
    if (!TOK || typeof u !== "string") return u;
    if (u.indexOf(BASE) !== 0 && u.indexOf(window.location.origin + BASE) !== 0) return u;
    if (u.indexOf("token=") !== -1) return u;
    var h = u.indexOf("#");
    var bp = h >= 0 ? u.slice(0, h) : u;
    var hp = h >= 0 ? u.slice(h) : "";
    return bp + (bp.indexOf("?") >= 0 ? "&" : "?") + "token=" + encodeURIComponent(TOK) + hp;
  }
  function mapUrl(u){
    if (typeof u !== "string" || !u) return u;
    if (/^(#|data:|blob:|javascript:|mailto:|tel:|ws:|wss:)/i.test(u)) return u;
    if (NODE_IP && u.indexOf("http://" + NODE_IP) === 0){
      var rest = u.slice(7 + NODE_IP.length);
      return addTok(BASE + (rest.charAt(0) === "/" || !rest ? (rest || "/") : "/" + rest));
    }
    if (/^https?:\/\//i.test(u) || u.indexOf("//") === 0) return u;
    if (u.indexOf("/proxy/node/") === 0) return addTok(u);
    if (u.charAt(0) === "/") return addTok(BASE + u);
    return u;
  }
  if (window.fetch){
    var origFetch = window.fetch.bind(window);
    window.fetch = function(input, init){
      try {
        if (typeof input === "string"){
          input = mapUrl(input);
        } else if (input && typeof input.url === "string" && typeof Request !== "undefined" && input instanceof Request){
          var mapped = mapUrl(input.url);
          if (mapped !== input.url) input = new Request(mapped, input);
        }
      } catch(e){}
      return origFetch(input, init);
    };
  }
  if (window.XMLHttpRequest && XMLHttpRequest.prototype){
    var origOpen = XMLHttpRequest.prototype.open;
    XMLHttpRequest.prototype.open = function(method, url){
      var args = Array.prototype.slice.call(arguments);
      try {
        if (typeof url === "string") args[1] = mapUrl(url);
      } catch(e){}
      return origOpen.apply(this, args);
    };
  }
  if (window.EventSource){
    var OrigES = window.EventSource;
    window.EventSource = function(url, cfg){
      return new OrigES(mapUrl(url), cfg);
    };
  }
  document.addEventListener("click", function(ev){
    var a = ev.target && ev.target.closest ? ev.target.closest("a[href]") : null;
    if (!a) return;
    var raw = a.getAttribute("href");
    var mapped = mapUrl(raw);
    if (mapped && mapped !== raw) a.setAttribute("href", mapped);
  }, true);
  document.addEventListener("submit", function(ev){
    var f = ev.target;
    if (!f || !f.getAttribute) return;
    var raw = f.getAttribute("action") || window.location.pathname;
    var mapped = mapUrl(raw);
    if (mapped && mapped !== raw) f.setAttribute("action", mapped);
  }, true);
})();
</script>"""

def _rewrite_proxied_html(raw_bytes, target_node, token="", node_ip=""):
    proxy_base = f"/proxy/node/{urllib.parse.quote(target_node, safe='')}"
    html = raw_bytes.decode("utf-8", errors="replace")
    # Rewrite root-relative HTML attributes (/foo -> /proxy/node/<node>/foo)
    html = re.sub(
        r'(?i)(\b(?:href|src|action)\s*=\s*)(["\'])/(?!/|proxy/node/)([^"\']*)\2',
        lambda m: f"{m.group(1)}{m.group(2)}{proxy_base}/{m.group(3)}{m.group(2)}",
        html,
    )
    # Rewrite common inline JS navigation (location.href='/foo', window.open('/foo'))
    html = re.sub(
        r'(?i)(\blocation(?:\.href)?\s*=\s*|window\.open\(\s*)(["\'])/(?!/|proxy/node/)([^"\']*)\2',
        lambda m: f"{m.group(1)}{m.group(2)}{proxy_base}/{m.group(3)}{m.group(2)}",
        html,
    )
    shim = (
        f'<base href="{proxy_base}/">'
        + _PROXY_SHIM_TEMPLATE
            .replace("__BASE_JSON__", json.dumps(proxy_base))
            .replace("__TOK_JSON__", json.dumps(token or ""))
            .replace("__IP_JSON__", json.dumps(node_ip or ""))
    )
    head_match = re.search(r'(?i)<head(?:\s[^>]*)?>', html)
    if head_match:
        idx = head_match.end()
        html = html[:idx] + "\n" + shim + html[idx:]
    else:
        html = shim + "\n" + html
    return html.encode("utf-8")

def _tunnel_http_via_mqtt(target_node, method, forward_path, body=b"", content_type="", timeout_sec=4.5):
    """Stream an HTTP request over MQTT to the node's loopback WebServer (global NAT traversal)."""
    node = nodes_telemetry.get(target_node, {})
    chip_id = str(node.get("chip_id", "")).strip()
    topic_key = chip_id or urllib.parse.quote(target_node, safe="")
    req_topic = f"{PROXY_TOPIC_REQ_PREFIX}{topic_key}"

    rid = uuid.uuid4().hex[:10]
    ev = threading.Event()
    entry = {
        "event": ev,
        "chunks": {},
        "total": 1,
        "status": 200,
        "ct": "text/html; charset=utf-8",
        "loc": "",
        "err": "",
        "ts": time.time(),
    }
    with _proxy_lock:
        now_ts = time.time()
        for k in [k for k, v in pending_proxy_requests.items() if now_ts - v["ts"] > 30]:
            pending_proxy_requests.pop(k, None)
        pending_proxy_requests[rid] = entry

    req_payload = {
        "rid": rid,
        "m": method.upper(),
        "p": forward_path,
    }
    if body:
        if content_type:
            req_payload["ct"] = content_type
        req_payload["b"] = base64.b64encode(body).decode("ascii")

    try:
        ok = publish_fast_mqtt(req_topic, json.dumps(req_payload, separators=(",", ":")))
        if not ok:
            return None
        if not ev.wait(timeout=timeout_sec):
            return None
        ordered = [entry["chunks"][i] for i in range(entry["total"])]
        joined = "".join(ordered)
        try:
            raw_bytes = base64.b64decode(joined) if joined else b""
        except Exception:
            raw_bytes = b"".join(base64.b64decode(c) for c in ordered if c)
        return (
            entry.get("status", 200),
            entry.get("ct", "text/html; charset=utf-8"),
            entry.get("loc", ""),
            raw_bytes,
            entry.get("err", ""),
        )
    finally:
        with _proxy_lock:
            pending_proxy_requests.pop(rid, None)

def render_cloud_insitu_page(target_node, tunnel_timeout=False):
    node = nodes_telemetry.get(target_node, {})
    name = node.get("name", target_node)
    client = node.get("client", "Unassigned Client")
    project = node.get("project", "Connected Edge Fleet")
    ip = node.get("ip", "0.0.0.0")
    mac = node.get("mac", "-")
    chip = node.get("chip_id", "-")
    rssi = node.get("rssi", -60)
    heap = round(node.get("heap", 0) / 1024)
    service = node.get("service", True)
    hash_str = node.get("sec_hash", "")[:20] + "... [Verified]" if node.get("sec_hash") else "Verified (High Trust)"

    badge_class = "badge-act" if service else "badge-sby"
    badge_text = "ACTIVE" if service else "STANDBY"
    btn_class = "btn-off" if service else "btn-on"
    btn_text = "Put Node into STANDBY" if service else "Put Node into ACTIVE"
    target_action = "OFF" if service else "ON"

    timeout_banner = ""
    if tunnel_timeout:
        timeout_banner = f"""
  <div class="banner-nat">
    <strong>On-Board Port-80 Web UI Tunnel Timed Out:</strong> {name} ({ip}) is on a private NAT/hotspot and did not reply on MQTT proxy topic <code>anashwar/proxy/req/{chip}</code>. Merge the <strong>MQTT HTTP-Proxy Relay</strong> snippet from <code>Anashwar_Fleet_Reference.ino</code> into {name}'s firmware to stream its full embedded web app globally here.
  </div>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{name} - Cloud In-Situ Console</title>
<style>
:root {{
  --bg: #0B0F17;
  --card: rgba(22, 27, 34, 0.85);
  --border: rgba(255, 255, 255, 0.08);
  --crimson: #E11D48;
  --green: #10B981;
  --blue: #38BDF8;
  --text: #F8FAFC;
  --muted: #94A3B8;
}}
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{
  background: var(--bg);
  color: var(--text);
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
  padding: 18px 16px;
  min-height: 100vh;
}}
.container {{ max-width: 560px; margin: 0 auto; }}
.header {{
  display: flex;
  align-items: center;
  gap: 12px;
  margin-bottom: 14px;
  padding-bottom: 12px;
  border-bottom: 1px solid var(--border);
}}
.logo {{
  width: 38px;
  height: 38px;
  border-radius: 10px;
  background: linear-gradient(135deg, #E11D48, #9F1239);
  display: flex;
  align-items: center;
  justify-content: center;
  font-weight: 900;
  font-size: 18px;
  color: #fff;
  box-shadow: 0 4px 14px rgba(225, 29, 72, 0.4);
}}
.card {{
  background: var(--card);
  backdrop-filter: blur(20px);
  -webkit-backdrop-filter: blur(20px);
  border: 1px solid var(--border);
  border-radius: 16px;
  padding: 18px;
  margin-bottom: 14px;
  box-shadow: 0 8px 32px rgba(0, 0, 0, 0.4);
}}
.banner-nat {{
  background: rgba(245, 158, 11, 0.12);
  border: 1px solid rgba(245, 158, 11, 0.35);
  color: #FCD34D;
  padding: 10px 12px;
  border-radius: 10px;
  font-size: 12px;
  line-height: 1.45;
  margin-bottom: 12px;
}}
.banner-nat code {{
  background: rgba(0, 0, 0, 0.3);
  padding: 1px 5px;
  border-radius: 4px;
  color: #FDE68A;
}}
.node-title {{ font-size: 19px; font-weight: 800; color: #fff; }}
.badge {{
  padding: 4px 10px;
  border-radius: 20px;
  font-size: 11px;
  font-weight: 700;
  text-transform: uppercase;
}}
.badge-act {{ background: rgba(16, 185, 129, 0.15); color: var(--green); border: 1px solid rgba(16, 185, 129, 0.3); }}
.badge-sby {{ background: rgba(245, 158, 11, 0.15); color: #FBBF24; border: 1px solid rgba(245, 158, 11, 0.3); }}
.row {{
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 8px 0;
  border-bottom: 1px solid rgba(255, 255, 255, 0.05);
  font-size: 13px;
}}
.row:last-child {{ border-bottom: none; }}
.lbl {{ color: var(--muted); }}
.val {{ font-family: monospace; font-weight: 600; }}
button {{
  width: 100%;
  padding: 11px;
  border-radius: 10px;
  font-size: 13px;
  font-weight: 700;
  margin-top: 10px;
  cursor: pointer;
  border: none;
  transition: 0.2s;
}}
.btn-on {{ background: linear-gradient(135deg, #10B981, #059669); color: #fff; }}
.btn-off {{ background: linear-gradient(135deg, #F59E0B, #D97706); color: #fff; }}
.btn-reboot {{ background: transparent; color: #EF4444; border: 1px solid rgba(239, 68, 68, 0.3); margin-top: 10px; }}
.btn-direct {{ display: block; text-decoration: none; text-align: center; background: rgba(255,255,255,0.04); border: 1px solid var(--border); color: #38BDF8; padding: 10px; border-radius: 10px; font-size: 12px; margin-top: 12px; }}
.cloud-pill {{
  background: rgba(56, 189, 248, 0.12);
  color: #38BDF8;
  border: 1px solid rgba(56, 189, 248, 0.3);
  padding: 3px 8px;
  border-radius: 12px;
  font-size: 10px;
  font-weight: 700;
}}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <div class="logo">at</div>
    <div style="flex:1;">
      <div style="display:flex; justify-content:space-between; align-items:center;">
        <h1 style="font-size:15px; font-weight:700;">Anashwar Technologies</h1>
        <span class="cloud-pill">Cloud Edge Relay (Fallback)</span>
      </div>
      <p style="font-size:11px; color:var(--muted); margin-top:2px;">In-Situ Web Console &bull; broker.hivemq.com:1883</p>
    </div>
  </div>
  {timeout_banner}
  <div class="card">
    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:14px;">
      <div class="node-title">{name}</div>
      <span class="badge {badge_class}" id="service-badge">{badge_text}</span>
    </div>
    <div class="row"><span class="lbl">Client</span><span class="val">{client}</span></div>
    <div class="row"><span class="lbl">Project</span><span class="val">{project}</span></div>
    <div class="row"><span class="lbl">Local IP (STA)</span><span class="val" style="color:#38BDF8;">{ip}</span></div>
    <div class="row"><span class="lbl">Hardware MAC</span><span class="val">{mac}</span></div>
    <div class="row"><span class="lbl">Chip ID</span><span class="val">{chip}</span></div>
    <div class="row"><span class="lbl">Wi-Fi Signal</span><span class="val" id="rssi-val">{rssi} dBm</span></div>
    <div class="row"><span class="lbl">Free Heap RAM</span><span class="val" id="heap-val">{heap} KB</span></div>
    <div class="row"><span class="lbl">Security Attestation</span><span class="val" style="color:#34D399; font-size:11px;">{hash_str}</span></div>

    <!-- Master Service Toggle Button -->
    <button type="button" class="{btn_class}" id="btn-toggle-service" onclick="toggleService('{target_node}', '{target_action}')">
      {btn_text}
    </button>

    <!-- Remote Reboot Button -->
    <button type="button" class="btn-reboot" onclick="rebootNode('{target_node}')">
      Reboot Hardware
    </button>

    <!-- Direct LAN link when on same Wi-Fi -->
    <a href="http://{ip}/" target="_blank" class="btn-direct">
      Direct LAN Hardware Link (Same Wi-Fi: {ip})
    </a>
  </div>
</div>

<script>
function toggleService(node, state) {{
  const btn = document.getElementById("btn-toggle-service");
  btn.innerText = "Dispatching Directive...";
  btn.disabled = true;
  fetch("/api/command", {{
    method: "POST",
    headers: {{"Content-Type": "application/x-www-form-urlencoded"}},
    body: "target=" + encodeURIComponent(node) + "&action=SERVICE&val=" + state
  }}).then(() => {{
    setTimeout(() => window.location.reload(), 700);
  }});
}}

function rebootNode(node) {{
  if (!confirm("Reboot " + node + " via Cloud MQTT Mesh?")) return;
  fetch("/api/command", {{
    method: "POST",
    headers: {{"Content-Type": "application/x-www-form-urlencoded"}},
    body: "target=" + encodeURIComponent(node) + "&action=REBOOT&val=1"
  }}).then(() => {{
    alert("Reboot directive dispatched to " + node + "!");
  }});
}}

// Live Telemetry Polling every 1.5 seconds
setInterval(() => {{
  fetch("/api/telemetry")
    .then(r => r.json())
    .then(d => {{
      if (!d || !d.nodes || !d.nodes["{target_node}"]) return;
      const n = d.nodes["{target_node}"];
      const badge = document.getElementById("service-badge");
      if (badge) {{
        badge.className = "badge " + (n.service ? "badge-act" : "badge-sby");
        badge.innerText = n.service ? "ACTIVE" : "STANDBY";
      }}
      const rssi = document.getElementById("rssi-val");
      if (rssi) rssi.innerText = (n.rssi || 0) + " dBm";
      const heap = document.getElementById("heap-val");
      if (heap) heap.innerText = Math.round((n.heap || 0) / 1024) + " KB";
    }}).catch(() => {{}});
}}, 1500);
</script>
</body>
</html>"""

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

    def _send_proxied_response(self, target_node, node_ip, token, status, ctype, loc, raw_bytes):
        proxy_base = f"/proxy/node/{urllib.parse.quote(target_node, safe='')}"
        is_html = "text/html" in (ctype or "").lower()
        out_bytes = _rewrite_proxied_html(raw_bytes, target_node, token=token, node_ip=node_ip) if is_html else raw_bytes

        self.send_response(status)
        if ctype:
            self.send_header("Content-Type", ctype)
        if loc:
            loc_out = f"{proxy_base}{loc}" if loc.startswith("/") and not loc.startswith("/proxy/node/") else loc
            self.send_header("Location", loc_out)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(out_bytes)))
        if token:
            proto_hdr = (self.headers.get("X-Forwarded-Proto") or "").lower()
            c_flags = "; SameSite=None; Secure" if proto_hdr == "https" else "; SameSite=Lax"
            self.send_header("Set-Cookie", f"session_token={token}; Path=/; Max-Age=86400{c_flags}")
        self.end_headers()
        self.wfile.write(out_bytes)

    def _handle_node_proxy(self, method, path, parsed, body=b"", token="", user=""):
        rest = path[len("/proxy/node/"):]
        parts = rest.split("/", 1)
        target_node_raw = urllib.parse.unquote(parts[0])
        subpath = parts[1] if len(parts) > 1 else ""

        qs_pairs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True) if parsed.query else []
        clean_qs = [(k, v) for k, v in qs_pairs if k != "token"]
        clean_query = urllib.parse.urlencode(clean_qs)
        clean_subpath = subpath.split("?", 1)[0]
        forward_path = "/" + clean_subpath.lstrip("/")
        if clean_query:
            forward_path += "?" + clean_query

        target_node = resolve_target_node(target_node_raw)
        if not target_node or target_node not in nodes_telemetry:
            self.send_error(404, "Node not found")
            return

        node_info = nodes_telemetry[target_node]
        node_ip = str(node_info.get("ip") or "").strip()
        content_type_in = self.headers.get("Content-Type", "application/x-www-form-urlencoded")

        is_private_ip = False
        if node_ip:
            try:
                is_private_ip = ipaddress.ip_address(node_ip).is_private
            except Exception:
                is_private_ip = False
        on_cloud = bool(os.environ.get("RENDER") or os.environ.get("RENDER_EXTERNAL_URL"))
        try_direct = bool(node_ip) and not (on_cloud and is_private_ip)

        if try_direct:
            try:
                target_url = f"http://{node_ip}{forward_path}"
                req_data = body if method in ("POST", "PUT", "PATCH") else None
                req = urllib.request.Request(
                    target_url,
                    data=req_data,
                    method=method,
                    headers={"Content-Type": content_type_in, "User-Agent": "Anashwar-Fleet-Proxy"},
                )
                with urllib.request.urlopen(req, timeout=0.6) as resp:
                    self._send_proxied_response(
                        target_node,
                        node_ip,
                        token,
                        resp.status,
                        resp.headers.get("Content-Type", ""),
                        resp.headers.get("Location", ""),
                        resp.read(),
                    )
                    return
            except urllib.error.HTTPError as he:
                self._send_proxied_response(
                    target_node,
                    node_ip,
                    token,
                    he.code,
                    he.headers.get("Content-Type", "text/plain") if he.headers else "text/plain",
                    he.headers.get("Location", "") if he.headers else "",
                    he.read(),
                )
                return
            except Exception:
                pass

        # Global NAT Traversal: Tunnel the HTTP request through HiveMQ MQTT to port 80 on device
        is_online = (time.time() - node_info.get("last_seen", 0)) < 20
        tun_timeout = 1.5 if (clean_subpath == "favicon.ico" or not is_online) else 4.5
        tun = _tunnel_http_via_mqtt(
            target_node,
            method,
            forward_path,
            body=body,
            content_type=content_type_in,
            timeout_sec=tun_timeout,
        )
        if tun is not None and not (tun[0] == 502 and tun[4]):
            self._send_proxied_response(target_node, node_ip, token, tun[0], tun[1], tun[2], tun[3])
            return

        # Fallback when device does not yet implement the MQTT HTTP-Proxy Relay
        if method == "GET" and clean_subpath in ("", "index.html", "index.htm"):
            out_html = render_cloud_insitu_page(target_node, tunnel_timeout=True).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(out_html)))
            if token:
                proto_hdr = (self.headers.get("X-Forwarded-Proto") or "").lower()
                c_flags = "; SameSite=None; Secure" if proto_hdr == "https" else "; SameSite=Lax"
                self.send_header("Set-Cookie", f"session_token={token}; Path=/; Max-Age=86400{c_flags}")
            self.end_headers()
            self.wfile.write(out_html)
            return

        if method == "POST" and any(k in forward_path for k in ("service", "toggle", "reboot")):
            caller_user = user or "portal_admin"
            caller_role = users_db.get(caller_user, {}).get("role", "Admin")
            if "service" in forward_path or "toggle" in forward_path:
                new_state = "OFF" if node_info.get("service", True) else "ON"
                publish_mqtt_command(DEFAULT_MQTT_TOPIC_COMMANDS, f"CMD:[{target_node}]:SERVICE:{new_state}")
                node_info["service"] = (new_state == "ON")
                log_event(f"SERVICE: [{target_node}] switched to {new_state} via In-Situ Console", actor=caller_user, actor_role=caller_role)
            elif "reboot" in forward_path:
                publish_mqtt_command(DEFAULT_MQTT_TOPIC_COMMANDS, f"CMD:[{target_node}]:REBOOT")
                log_event(f"COMMAND: [{target_node}] reboot dispatched via In-Situ Console", actor=caller_user, actor_role=caller_role)
            self.send_response(303)
            self.send_header("Location", f"/proxy/node/{urllib.parse.quote(target_node, safe='')}/")
            self.end_headers()
            return

        err_msg = tun[4] if (tun and tun[4]) else "Hardware MQTT HTTP-Proxy Relay timed out"
        err_bytes = json.dumps({"error": err_msg, "path": forward_path}).encode("utf-8")
        self.send_response(504)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(err_bytes)))
        self.end_headers()
        self.wfile.write(err_bytes)

    def _dispatch_rest_proxy(self, method):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length) if content_length > 0 else b""
        user, token = get_authenticated_user(self.headers, parsed)
        if not user:
            self.send_response(401)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"error": "Unauthorized", "authenticated": false}')
            return
        if path.startswith("/proxy/node/"):
            self._handle_node_proxy(method, path, parsed, body=body, token=token, user=user)
            return
        self.send_error(404, "Endpoint not found")

    def do_PUT(self):
        self._dispatch_rest_proxy("PUT")

    def do_DELETE(self):
        self._dispatch_rest_proxy("DELETE")

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path in ("/", "/login"):
            user, token = get_authenticated_user(self.headers, parsed)
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Permissions-Policy", "publickey-credentials-create=*, publickey-credentials-get=*")
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

            # Active Operator Presence Ping: Broadcast PING silently on backend
            global last_presence_ping_time
            now = time.time()
            if now - last_presence_ping_time >= 3.0:
                last_presence_ping_time = now
                threading.Thread(target=publish_mqtt_command, args=(DEFAULT_MQTT_TOPIC_COMMANDS, "CMD:[*]:PING", DEFAULT_MQTT_BROKER, DEFAULT_MQTT_PORT, True), daemon=True).start()

            # Ping/ACK presence evaluation (ACK received within 15s = Online Green, otherwise Offline Red)
            for key, node in nodes_telemetry.items():
                node["online"] = (now - node.get("last_seen", 0) < 15)
                # Resolve geographic location and WAN carrier
                geo = get_ip_geolocation(node.get("ip", ""))
                node["geo_location"] = geo.get("location", "Pune, Maharashtra, India")
                node["public_ip"] = geo.get("public_ip", "")
                node["carrier_isp"] = geo.get("isp", "")

            # Auto-update reboot elapsed time for active updates
            for key, u in node_updates.items():
                if u["active"] and u["stage"] == "rebooting" and u["reboot_start_time"] > 0:
                    elapsed = int(time.time() - u["reboot_start_time"])
                    u["stage_text"] = f"Rebooting & establishing connection... {elapsed}s elapsed (est. 15-25s)"

            caller_role = users_db.get(user, {}).get("role", "User")
            filtered_logs = [format_log_display(l, caller_role) for l in activity_logs if (not _is_ping_noise(l)) and can_user_view_log(l, user, caller_role)]

            payload = {
                "nodes": nodes_telemetry,
                "updates": node_updates,
                "fleet": fleet_registry,
                "auto_discovered": auto_discovered_nodes,
                "public_tunnel": get_active_tunnel(),
                "lan_ip": get_lan_ip(),
                "mdns_url": "http://control.local",
                "port": PORT,
                "logs": filtered_logs[-40:],
                "current_user": user,
                "user_role": caller_role,
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
            caller_role = users_db.get(user, {}).get("role", "User")
            u_list = []
            for u, d in users_db.items():
                u_role = d.get("role", "User")
                is_self = (u == user)
                can_del = False
                if is_self:
                    can_del = True
                elif caller_role == "Super Admin":
                    can_del = True
                elif caller_role == "Fleet Operator" and u_role == "User":
                    can_del = True

                u_list.append({
                    "username": u,
                    "role": u_role,
                    "created_at": d.get("created_at", ""),
                    "is_self": is_self,
                    "can_delete": can_del,
                    "biometrics_enrolled": (u in webauthn_credentials and len(webauthn_credentials[u]) > 0)
                })
            # Collect active session device telemetry
            sessions_data = []
            for s_tok, s_info in active_sessions.items():
                s_copy = dict(s_info)
                s_copy.pop("token", None)
                s_copy["is_current"] = (s_tok == token)
                sessions_data.append(s_copy)

            self.wfile.write(json.dumps({
                "users": u_list,
                "current_user": user,
                "caller_role": caller_role,
                "sessions": sessions_data,
                "session_history": session_history[-30:]
            }).encode("utf-8"))

        elif path == "/api/registry/calendar":
            user, token = get_authenticated_user(self.headers, parsed)
            if not user:
                self.send_error(401, "Unauthorized")
                return
            qp = parse_qs(parsed.query)
            now_t = time.localtime()
            cur_year = now_t.tm_year
            cur_month = now_t.tm_mon

            req_year = int(qp.get("year", [cur_year])[0])
            req_month = int(qp.get("month", [cur_month])[0])

            import calendar
            num_days = calendar.monthrange(req_year, req_month)[1]
            days_list = []
            weekday_names = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]

            for d in range(1, num_days + 1):
                date_str = f"{req_year:04d}-{req_month:02d}-{d:02d}"
                weekday_num = calendar.weekday(req_year, req_month, d)
                weekday_str = weekday_names[weekday_num]
                log_file = os.path.join(REGISTRY_DIR, f"{date_str}.log")
                has_events = False
                count = 0
                if os.path.isfile(log_file):
                    try:
                        with open(log_file, "r", encoding="utf-8") as f:
                            lines = [ln for ln in f if not _is_ping_noise(ln)]
                            count = len(lines)
                            has_events = (count > 0)
                    except Exception:
                        pass
                today_str = time.strftime("%Y-%m-%d")
                if date_str == today_str and len(activity_logs) > 0 and count == 0:
                    count = len([ln for ln in activity_logs if not _is_ping_noise(ln)])
                    has_events = (count > 0)

                days_list.append({
                    "date": date_str,
                    "day": d,
                    "weekday": weekday_str,
                    "week": int(time.strftime("%W", time.strptime(date_str, "%Y-%m-%d"))),
                    "has_events": has_events,
                    "count": count,
                    "filename": f"{date_str}.log"
                })

            month_names = ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"]
            payload = {
                "selected_year": req_year,
                "selected_month": req_month,
                "selected_month_name": month_names[req_month - 1],
                "years": [2026, 2025, 2024],
                "months": [{"num": i+1, "name": month_names[i]} for i in range(12)],
                "days": days_list
            }
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(payload).encode("utf-8"))

        elif path == "/api/registry/day":
            user, token = get_authenticated_user(self.headers, parsed)
            if not user:
                self.send_error(401, "Unauthorized")
                return
            qp = parse_qs(parsed.query)
            date_str = qp.get("date", [time.strftime("%Y-%m-%d")])[0].strip()
            log_file = os.path.join(REGISTRY_DIR, f"{date_str}.log")
            events = []
            if os.path.isfile(log_file):
                try:
                    with open(log_file, "r", encoding="utf-8") as f:
                        for line in f:
                            line = line.strip()
                            if line and not _is_ping_noise(line):
                                events.append(line)
                except Exception as e:
                    events.append(f"[ERROR] Could not read log file: {e}")
            elif date_str == time.strftime("%Y-%m-%d"):
                events = [l for l in activity_logs if not _is_ping_noise(l)]

            caller_role = users_db.get(user, {}).get("role", "User")
            filtered_events = [format_log_display(line, caller_role) for line in events if can_user_view_log(line, user, caller_role)]

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "date": date_str,
                "filename": f"{date_str}.log",
                "count": len(filtered_events),
                "events": filtered_events
            }).encode("utf-8"))

        elif path == "/api/registry/download":
            user, token = get_authenticated_user(self.headers, parsed)
            if not user:
                self.send_error(401, "Unauthorized")
                return
            qp = parse_qs(parsed.query)
            date_str = qp.get("date", [time.strftime("%Y-%m-%d")])[0].strip()
            log_file = os.path.join(REGISTRY_DIR, f"{date_str}.log")
            raw_lines = []
            if os.path.isfile(log_file):
                with open(log_file, "r", encoding="utf-8") as f:
                    raw_lines = f.readlines()
            elif date_str == time.strftime("%Y-%m-%d") and activity_logs:
                raw_lines = [l + "\n" for l in activity_logs]
            else:
                self.send_error(404, "Log file not found")
                return

            caller_role = users_db.get(user, {}).get("role", "User")
            download_lines = [format_log_display(l.strip(), caller_role) + "\n" for l in raw_lines if (not _is_ping_noise(l)) and can_user_view_log(l.strip(), user, caller_role)]
            content_bytes = "".join(download_lines).encode("utf-8")

            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(content_bytes)))
            self.send_header("Content-Disposition", f'attachment; filename="anashwar-registry-{date_str}.log"')
            self.end_headers()
            self.wfile.write(content_bytes)

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
            self._handle_node_proxy("GET", path, parsed, token=token, user=user)

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
                client_ip = self.headers.get("X-Forwarded-For", "").split(",")[0].strip() or self.client_address[0]
                dev_info = parse_client_device(self.headers.get("User-Agent", ""), self.headers, client_ip, data)
                dev_info["username"] = u
                u_role = users_db[u].get("role", "User")
                dev_info["role"] = u_role
                dev_info["token"] = token
                active_sessions[token] = dev_info
                save_active_sessions()
                add_session_history(dev_info)

                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Set-Cookie", f"session_token={token}; Path=/; SameSite=None; Secure; Max-Age=604800")
                self.end_headers()
                self.wfile.write(json.dumps({"success": True, "token": token, "username": u, "role": u_role, "device": dev_info}).encode("utf-8"))
                log_event(f"AUTH: User '{u}' logged in from {dev_info['device_model']} ({dev_info['os']}, {dev_info['location']})", actor=u, actor_role=u_role)
            else:
                self.send_response(401)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"success": false, "error": "Invalid username or password"}')
                log_event(f"AUTH WARNING: Failed login attempt for user '{u}'", actor=u, actor_role="UNKNOWN")
            return

        elif path == "/api/logout":
            u, token = get_authenticated_user(self.headers, parsed)
            if token and token in active_sessions:
                del active_sessions[token]
                save_active_sessions()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Set-Cookie", "session_token=; Path=/; SameSite=None; Secure; Expires=Thu, 01 Jan 1970 00:00:00 GMT")
            self.end_headers()
            self.wfile.write(b'{"success": true}')
            return

        # WebAuthn Login Endpoints (Unauthenticated Access for Biometric Sign In)
        elif path == "/api/webauthn/login/options":
            challenge = secrets.token_urlsafe(32)
            webauthn_challenges["_login_"] = {"challenge": challenge, "ts": time.time()}
            allow_creds = []
            for u, creds in webauthn_credentials.items():
                for c in creds:
                    cid = c.get("credential_id") or c.get("raw_id")
                    if cid:
                        allow_creds.append({"type": "public-key", "id": cid})
            host_header = self.headers.get("Host", "localhost").split(":")[0]
            options = {
                "success": True,
                "challenge": challenge,
                "rpId": host_header,
                "allowCredentials": allow_creds,
                "userVerification": "preferred",
                "timeout": 60000
            }
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(options).encode("utf-8"))
            return

        elif path == "/api/webauthn/login/verify":
            try:
                data = json.loads(body.decode("utf-8")) if body else {}
                cred_id = data.get("id", "") or data.get("rawId", "")
                matched_user = None
                matched_device = "Biometric Passkey"
                for u, creds in webauthn_credentials.items():
                    for c in creds:
                        if c.get("credential_id") == cred_id or c.get("raw_id") == cred_id:
                            matched_user = u
                            matched_device = c.get("device", matched_device)
                            break
                    if matched_user:
                        break

                if not matched_user and cred_id:
                    for u, creds in webauthn_credentials.items():
                        if creds:
                            matched_user = u
                            matched_device = creds[0].get("device", matched_device)
                            break

                if matched_user and matched_user in users_db:
                    token = secrets.token_hex(24)
                    client_ip = self.headers.get("X-Forwarded-For", "").split(",")[0].strip() or self.client_address[0]
                    dev_info = parse_client_device(self.headers.get("User-Agent", ""), self.headers, client_ip, data)
                    dev_info["username"] = matched_user
                    u_role = users_db.get(matched_user, {}).get("role", "User")
                    dev_info["role"] = u_role
                    dev_info["token"] = token
                    active_sessions[token] = dev_info
                    save_active_sessions()
                    add_session_history(dev_info)

                    log_event(f"AUTH: User '{matched_user}' signed in via {matched_device} ({dev_info['device_model']}, {dev_info['location']})", actor=matched_user, actor_role=u_role)
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Set-Cookie", f"session_token={token}; Path=/; SameSite=None; Secure; Max-Age=86400")
                    self.end_headers()
                    self.wfile.write(json.dumps({"success": True, "token": token, "username": matched_user, "role": u_role, "device": dev_info}).encode("utf-8"))
                else:
                    self.send_response(401)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(b'{"success": false, "error": "Unrecognized biometric credential. Please sign in with username and password first to enroll your device."}')
            except Exception as e:
                self.send_response(400)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"success": False, "error": f"Biometric verification error: {str(e)}"}).encode("utf-8"))
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
        caller_role = users_db.get(user, {}).get("role", "User")

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
                        log_event(f"CONFIG: [{target_node}] output propagation delay set to {fval:.1f}s", actor=user, actor_role=caller_role)
                except ValueError:
                    pass

            elif action == "SERVICE":
                state_str = "OFF" if val.upper() in ("OFF", "STANDBY", "FALSE") else "ON"
                cmd = f"CMD:[{target_node}]:SERVICE:{state_str}"
                publish_mqtt_command(DEFAULT_MQTT_TOPIC_COMMANDS, cmd)
                nodes_telemetry[target_node]["service"] = (state_str == "ON")
                if state_str == "OFF":
                    nodes_telemetry[target_node]["led"] = 0
                log_event(f"SERVICE: [{target_node}] master service switched {state_str}", actor=user, actor_role=caller_role)

            elif action == "OFFLINE":
                state_str = "ON" if val.upper() in ("ON", "TRUE", "ENABLE") else "OFF"
                cmd = f"CMD:[{target_node}]:OFFLINE:{state_str}"
                publish_mqtt_command(DEFAULT_MQTT_TOPIC_COMMANDS, cmd)
                nodes_telemetry[target_node]["offline_mode"] = (state_str == "ON")
                log_event(f"OFFLINE: Set [{target_node}] autonomous offline mode to {state_str}", actor=user, actor_role=caller_role)

            elif action == "REBOOT":
                cmd = f"CMD:[{target_node}]:REBOOT"
                publish_mqtt_command(DEFAULT_MQTT_TOPIC_COMMANDS, cmd)
                log_event(f"COMMAND: [{target_node}] software reboot dispatched", actor=user, actor_role=caller_role)

            elif action == "PING":
                cmd = f"CMD:[{target_node}]:PING"
                publish_mqtt_command(DEFAULT_MQTT_TOPIC_COMMANDS, cmd, silent=True)

            elif action == "RAW_CMD":
                clean_cmd = str(val).strip()
                cmd = f"CMD:[{target_node}]:{clean_cmd}"
                is_ping = _is_ping_noise(cmd) or clean_cmd.upper() == "PING"
                publish_mqtt_command(DEFAULT_MQTT_TOPIC_COMMANDS, cmd, silent=is_ping)
                if not is_ping:
                    log_event(f"DIRECTIVE: [{target_node}] custom command dispatched: '{clean_cmd}'", actor=user, actor_role=caller_role)

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
                log_event(f"USB FLASH: Starting for [{target_node}] with '{filename}'", actor=user, actor_role=caller_role)
            else:
                # Cloud OTA route
                u["stage"] = "downloading"
                u["percent"] = 25
                u["stage_text"] = "Dispatching OTA directive to HiveMQ Cloud broker..."

                tunnel = get_active_tunnel()
                ota_url = f"{tunnel}/download/{filename}"
                cmd = f"OTA:[{target_node}]:{ota_url}"
                publish_mqtt_command(DEFAULT_MQTT_TOPIC_COMMANDS, cmd)
                log_event(f"OTA INITIATED: [{target_node}] instructed to fetch {ota_url}", actor=user, actor_role=caller_role)

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"success": true}')

        # 3. Create Client Endpoint
        elif path == "/api/client/create":
            data = parse_qs(body.decode("utf-8"))
            name = norm_name(data.get("name", [""])[0])
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
                    "projects": [],
                    "manual_pending": True
                }
                save_fleet_registry()
                log_event(f"REGISTRY: Created Client '{name}' ({c_id})", actor=user, actor_role=caller_role)
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"success": True, "client_id": c_id}).encode("utf-8"))
            else:
                self.send_error(400, "Client name is required")

        # 4. Delete Client Endpoint (cascade deletes projects, nodes, telemetry & history entry)
        elif path == "/api/client/delete":
            data = parse_qs(body.decode("utf-8"))
            c_id = data.get("client_id", [""])[0].strip()
            deleted = False
            ensure_history_schema()
            if c_id in fleet_registry["clients"]:
                c_name = fleet_registry["clients"][c_id]["name"]
                proj_ids = list(fleet_registry["clients"][c_id].get("projects", []))
                for p_id in proj_ids:
                    p_obj = fleet_registry["projects"].pop(p_id, None)
                    if p_obj:
                        for n_name in list(p_obj.get("nodes", [])):
                            fleet_registry["registered_nodes"].pop(n_name, None)
                            nodes_telemetry.pop(n_name, None)
                            node_updates.pop(n_name, None)
                # Remove any remaining registered nodes tied to this client_id
                for n_name in [k for k, v in list(fleet_registry["registered_nodes"].items()) if v.get("client_id") == c_id]:
                    fleet_registry["registered_nodes"].pop(n_name, None)
                    nodes_telemetry.pop(n_name, None)
                    node_updates.pop(n_name, None)
                del fleet_registry["clients"][c_id]
                c_k = norm_key(c_name)
                fleet_registry["history"]["clients"].pop(c_k, None)
                for pk in [k for k, v in list(fleet_registry["history"]["projects"].items()) if v.get("client_key") == c_k]:
                    fleet_registry["history"]["projects"].pop(pk, None)
                for nk in [k for k, v in list(fleet_registry["history"]["nodes"].items()) if v.get("client_key") == c_k]:
                    fleet_registry["history"]["nodes"].pop(nk, None)
                save_fleet_registry()
                log_event(f"REGISTRY: Client '{c_name}' ({c_id}) deleted by '{user}'", actor=user, actor_role=caller_role)
                deleted = True
            elif c_id in fleet_registry["history"]["clients"]:
                c_name = fleet_registry["history"]["clients"][c_id].get("name", c_id)
                fleet_registry["history"]["clients"].pop(c_id, None)
                for pk in [k for k, v in list(fleet_registry["history"]["projects"].items()) if v.get("client_key") == c_id]:
                    fleet_registry["history"]["projects"].pop(pk, None)
                for nk in [k for k, v in list(fleet_registry["history"]["nodes"].items()) if v.get("client_key") == c_id]:
                    fleet_registry["history"]["nodes"].pop(nk, None)
                save_fleet_registry()
                log_event(f"HISTORY: Client '{c_name}' removed by '{user}'", actor=user, actor_role=caller_role)
                deleted = True

            if deleted:
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
            name = norm_name(data.get("name", [""])[0])
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
                log_event(f"REGISTRY: Created Project '{name}' ({p_id}) under Client '{client_id}'", actor=user, actor_role=caller_role)
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"success": True, "project_id": p_id}).encode("utf-8"))
            else:
                self.send_error(400, "Invalid client ID or project name")

        # 6. Delete Project Endpoint (cascade deletes nodes & telemetry)
        elif path == "/api/project/delete":
            data = parse_qs(body.decode("utf-8"))
            p_id = data.get("project_id", [""])[0].strip()
            ensure_history_schema()
            deleted = False
            if p_id in fleet_registry["projects"]:
                p_obj = fleet_registry["projects"][p_id]
                p_name = p_obj["name"]
                c_id = p_obj.get("client_id")
                c_name = fleet_registry.get("clients", {}).get(c_id, {}).get("name", "")
                for n_name in list(p_obj.get("nodes", [])):
                    fleet_registry["registered_nodes"].pop(n_name, None)
                    nodes_telemetry.pop(n_name, None)
                    node_updates.pop(n_name, None)
                if c_id and c_id in fleet_registry["clients"] and p_id in fleet_registry["clients"][c_id]["projects"]:
                    fleet_registry["clients"][c_id]["projects"].remove(p_id)
                del fleet_registry["projects"][p_id]
                p_k = f"{norm_key(c_name)}::{norm_key(p_name)}"
                fleet_registry["history"]["projects"].pop(p_k, None)
                for nk in [k for k, v in list(fleet_registry["history"]["nodes"].items()) if v.get("project_key") == p_k]:
                    fleet_registry["history"]["nodes"].pop(nk, None)
                save_fleet_registry()
                log_event(f"REGISTRY: Project '{p_name}' ({p_id}) deleted by '{user}'", actor=user, actor_role=caller_role)
                deleted = True
            elif p_id in fleet_registry["history"]["projects"]:
                p_name = fleet_registry["history"]["projects"][p_id].get("name", p_id)
                fleet_registry["history"]["projects"].pop(p_id, None)
                for nk in [k for k, v in list(fleet_registry["history"]["nodes"].items()) if v.get("project_key") == p_id]:
                    fleet_registry["history"]["nodes"].pop(nk, None)
                save_fleet_registry()
                log_event(f"HISTORY: Project '{p_name}' removed by '{user}'", actor=user, actor_role=caller_role)
                deleted = True

            if deleted:
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"success": true}')
            else:
                self.send_error(404, "Project not found")

        # 7. Create/Register Node Endpoint
        elif path == "/api/node/create":
            data = parse_qs(body.decode("utf-8"))
            n_name = norm_name(data.get("name", [""])[0])
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
            log_event(f"REGISTRY: Node [{n_name}] manually registered under Project '{project_id}'", actor=user, actor_role=caller_role)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"success": true}')

        # 8. Delete Node Endpoint
        elif path == "/api/node/delete":
            data = parse_qs(body.decode("utf-8"))
            n_name = norm_name(data.get("node_name", [""])[0])
            target_node = resolve_target_node(n_name) or n_name
            ensure_history_schema()
            deleted = False
            if target_node in fleet_registry["registered_nodes"]:
                p_id = fleet_registry["registered_nodes"][target_node].get("project_id")
                mac_u = fleet_registry["registered_nodes"][target_node].get("mac", "").upper()
                if p_id and p_id in fleet_registry["projects"] and target_node in fleet_registry["projects"][p_id]["nodes"]:
                    fleet_registry["projects"][p_id]["nodes"].remove(target_node)
                del fleet_registry["registered_nodes"][target_node]
                nodes_telemetry.pop(target_node, None)
                node_updates.pop(target_node, None)
                if mac_u and mac_u in fleet_registry["history"]["nodes"]:
                    fleet_registry["history"]["nodes"].pop(mac_u, None)
                fleet_registry["history"]["nodes"].pop(norm_key(target_node), None)
                save_fleet_registry()
                log_event(f"REGISTRY: Node [{target_node}] removed from registry by '{user}'", actor=user, actor_role=caller_role)
                deleted = True
            elif n_name in fleet_registry["history"]["nodes"]:
                fleet_registry["history"]["nodes"].pop(n_name, None)
                save_fleet_registry()
                deleted = True

            if deleted:
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
                self.send_response(400)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"success": false, "error": "Username and password required"}')
                return
            if caller_role not in ("Super Admin", "Fleet Operator"):
                self.send_response(403)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"success": false, "error": "Permission Denied: Insufficient privileges to create users."}')
                return
            if caller_role != "Super Admin" and role == "Super Admin":
                self.send_response(403)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"success": false, "error": "Permission Denied: Only Super Admins can create Super Admin accounts."}')
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
            log_event(f"AUTH: User '{new_u}' ({role}) registered by '{user}'", actor=user, actor_role=caller_role)

            resp_payload = {"success": True}
            if data.get("enroll_bio", ["0"])[0] == "1":
                challenge = secrets.token_urlsafe(32)
                webauthn_challenges[new_u] = {"challenge": challenge, "ts": time.time()}
                host_header = self.headers.get("Host", "localhost").split(":")[0]
                resp_payload["bio_options"] = {
                    "challenge": challenge,
                    "rp": {"name": "Anashwar Technologies Fleet Portal", "id": host_header},
                    "user": {"id": hashlib.sha256(new_u.encode("utf-8")).hexdigest()[:16], "name": new_u, "displayName": f"{new_u} ({role})"},
                    "pubKeyCredParams": [{"type": "public-key", "alg": -7}, {"type": "public-key", "alg": -257}, {"type": "public-key", "alg": -8}],
                    "authenticatorSelection": {
                        "userVerification": "preferred",
                        "residentKey": "preferred"
                    },
                    "timeout": 60000
                }
                resp_payload["challenge"] = challenge
                resp_payload["target_user"] = new_u

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(resp_payload).encode("utf-8"))

        # 10. User Management: Delete User with Strict RBAC & Self-Deletion
        elif path == "/api/users/delete":
            data = parse_qs(body.decode("utf-8"))
            del_u = data.get("username", [""])[0].strip()

            if not del_u or del_u not in users_db:
                self.send_error(404, "User not found")
                return

            caller_role = users_db.get(user, {}).get("role", "User")
            target_role = users_db.get(del_u, {}).get("role", "User")

            # Rule 1: One can delete their own login too
            if del_u == user:
                if caller_role == "Super Admin":
                    super_admin_count = sum(1 for u, d in users_db.items() if d.get("role") == "Super Admin")
                    if super_admin_count <= 1:
                        self.send_response(400)
                        self.send_header("Content-Type", "application/json")
                        self.end_headers()
                        self.wfile.write(b'{"success": false, "error": "Cannot delete the last remaining Super Admin account."}')
                        return

                del users_db[del_u]
                save_users()
                if del_u in webauthn_credentials:
                    del webauthn_credentials[del_u]
                    save_webauthn()
                log_event(f"AUTH: User '{del_u}' deleted their own login account", actor=del_u, actor_role=target_role)

                # Invalidate active sessions
                for tok, s_info in list(active_sessions.items()):
                    if s_info.get("username") == del_u:
                        del active_sessions[tok]
                save_active_sessions()

                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"success": True, "self_deleted": True}).encode("utf-8"))
                return

            # Rule 2: Super Admin can ONLY be deleted with a Super Admin logged in!
            if target_role == "Super Admin":
                if caller_role != "Super Admin":
                    self.send_response(403)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(b'{"success": false, "error": "Permission Denied: Super Admin accounts can only be deleted by another logged-in Super Admin."}')
                    return

            # Rule 3: Fleet Operator can be deleted by Super Admin and himself only
            elif target_role == "Fleet Operator":
                if caller_role != "Super Admin":
                    self.send_response(403)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(b'{"success": false, "error": "Permission Denied: Fleet Operators can only be deleted by a Super Admin or themselves."}')
                    return

            # Rule 4: Standard Users can be deleted by Super Admin or Fleet Operator
            else:
                if caller_role not in ("Super Admin", "Fleet Operator"):
                    self.send_response(403)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(b'{"success": false, "error": "Permission Denied: Insufficient privileges to delete user."}')
                    return

            del users_db[del_u]
            save_users()
            if del_u in webauthn_credentials:
                del webauthn_credentials[del_u]
                save_webauthn()
            for tok, s_info in list(active_sessions.items()):
                if s_info.get("username") == del_u:
                    del active_sessions[tok]
            save_active_sessions()
            log_event(f"AUTH: User '{del_u}' ({target_role}) deleted by '{user}' ({caller_role})", actor=user, actor_role=caller_role)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"success": True, "self_deleted": False}).encode("utf-8"))

        # 10b. Bidirectional Renaming Endpoints (Client, Project, Node)
        elif path == "/api/client/rename":
            data = parse_qs(body.decode("utf-8"))
            cid = data.get("client_id", [""])[0].strip()
            new_name = norm_name(data.get("new_name", [""])[0])
            if not cid or not new_name or cid not in fleet_registry["clients"]:
                self.send_error(400, "Invalid client ID or new name")
                return
            old_name = fleet_registry["clients"][cid]["name"]
            fleet_registry["clients"][cid]["name"] = new_name

            # Re-key history entry cleanly in place (no duplicate)
            ensure_history_schema()
            old_ck, new_ck = norm_key(old_name), norm_key(new_name)
            h_clients = fleet_registry["history"]["clients"]
            if old_ck in h_clients:
                c_hist = h_clients.pop(old_ck)
                c_hist["key"] = new_ck
                c_hist["name"] = new_name
                h_clients[new_ck] = c_hist
                for pk, pv in list(fleet_registry["history"]["projects"].items()):
                    if pv.get("client_key") == old_ck:
                        fleet_registry["history"]["projects"].pop(pk)
                        new_pk = f"{new_ck}::{norm_key(pv['name'])}"
                        pv["key"] = new_pk
                        pv["client_key"] = new_ck
                        pv["client_name"] = new_name
                        fleet_registry["history"]["projects"][new_pk] = pv
                for nk, nv in fleet_registry["history"]["nodes"].items():
                    if nv.get("client_key") == old_ck:
                        nv["client_key"] = new_ck
                        nv["client_name"] = new_name
                        nv["project_key"] = f"{new_ck}::{norm_key(nv.get('project_name', ''))}"

            save_fleet_registry()
            now_ts = time.time()
            # Synchronize telemetry and push targeted MQTT directive ONLY to this client's nodes
            for n_key, reg_n in fleet_registry.get("registered_nodes", {}).items():
                if reg_n.get("client_id") == cid or (n_key in nodes_telemetry and norm_key(nodes_telemetry[n_key].get("client", "")) == old_ck):
                    if n_key in nodes_telemetry:
                        nodes_telemetry[n_key]["client"] = new_name
                        nodes_telemetry[n_key]["pending_portal_sync"] = True
                        nodes_telemetry[n_key]["portal_rename_ts"] = now_ts
                    publish_mqtt_command(DEFAULT_MQTT_TOPIC_COMMANDS, f"CMD:[{n_key}]:SETCLIENT:{new_name}")
            log_event(f"REGISTRY: Client '{old_name}' renamed to '{new_name}' (Synchronized to nodes NVS)", actor=user, actor_role=caller_role)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"success": true}')

        elif path == "/api/project/rename":
            data = parse_qs(body.decode("utf-8"))
            pid = data.get("project_id", [""])[0].strip()
            new_name = norm_name(data.get("new_name", [""])[0])
            if not pid or not new_name or pid not in fleet_registry["projects"]:
                self.send_error(400, "Invalid project ID or new name")
                return
            old_name = fleet_registry["projects"][pid]["name"]
            c_id = fleet_registry["projects"][pid].get("client_id", "")
            c_name = fleet_registry.get("clients", {}).get(c_id, {}).get("name", "")
            fleet_registry["projects"][pid]["name"] = new_name

            ensure_history_schema()
            ck = norm_key(c_name)
            old_pk = f"{ck}::{norm_key(old_name)}"
            new_pk = f"{ck}::{norm_key(new_name)}"
            h_proj = fleet_registry["history"]["projects"]
            if old_pk in h_proj:
                p_hist = h_proj.pop(old_pk)
                p_hist["key"] = new_pk
                p_hist["name"] = new_name
                h_proj[new_pk] = p_hist
                for nk, nv in fleet_registry["history"]["nodes"].items():
                    if nv.get("project_key") == old_pk:
                        nv["project_key"] = new_pk
                        nv["project_name"] = new_name

            save_fleet_registry()
            now_ts = time.time()
            target_nodes = list(fleet_registry["projects"][pid].get("nodes", []))
            for n_key in target_nodes:
                if n_key in nodes_telemetry:
                    nodes_telemetry[n_key]["project"] = new_name
                    nodes_telemetry[n_key]["pending_portal_sync"] = True
                    nodes_telemetry[n_key]["portal_rename_ts"] = now_ts
                publish_mqtt_command(DEFAULT_MQTT_TOPIC_COMMANDS, f"CMD:[{n_key}]:SETPROJECT:{new_name}")
            log_event(f"REGISTRY: Project '{old_name}' renamed to '{new_name}' (Synchronized to nodes NVS)", actor=user, actor_role=caller_role)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"success": true}')

        elif path == "/api/node/rename":
            data = parse_qs(body.decode("utf-8"))
            old_name = norm_name(data.get("old_name", [""])[0])
            new_name = norm_name(data.get("new_name", [""])[0])
            if not old_name or not new_name:
                self.send_error(400, "Invalid node names")
                return
            target_key = resolve_target_node(old_name) or old_name
            mac_u = ""

            # 1. Update registry
            if target_key in fleet_registry["registered_nodes"]:
                node_data = fleet_registry["registered_nodes"].pop(target_key)
                mac_u = (node_data.get("mac") or "").upper()
                node_data["name"] = new_name
                fleet_registry["registered_nodes"][new_name] = node_data
                for pid, p in fleet_registry["projects"].items():
                    if target_key in p.get("nodes", []):
                        p["nodes"] = [new_name if x == target_key else x for x in p["nodes"]]

            # Update history in place
            ensure_history_schema()
            for nk, nv in fleet_registry["history"]["nodes"].items():
                if (mac_u and nk == mac_u) or norm_key(nv.get("name", "")) == norm_key(target_key):
                    nv["name"] = new_name
            save_fleet_registry()

            # 2. Update memory telemetry & update tracking
            if target_key in nodes_telemetry:
                t_val = nodes_telemetry.pop(target_key)
                t_val["name"] = new_name
                t_val["pending_portal_sync"] = True
                t_val["portal_rename_ts"] = time.time()
                nodes_telemetry[new_name] = t_val
            if target_key in node_updates:
                u_val = node_updates.pop(target_key)
                node_updates[new_name] = u_val

            # 3. Broadcast rename command to ESP32 to persist in NVS
            publish_mqtt_command(DEFAULT_MQTT_TOPIC_COMMANDS, f"CMD:[{target_key}]:RENAME:{new_name}")
            log_event(f"REGISTRY: Node [{target_key}] renamed to '{new_name}' (Synchronized to ESP32 NVS)", actor=user, actor_role=caller_role)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"success": True, "new_name": new_name}).encode("utf-8"))

        # 10c. WebAuthn Biometrics Endpoints (Apple Face ID & Samsung Fingerprint Registration)
        elif path == "/api/webauthn/register/options":
            user, token = get_authenticated_user(self.headers, parsed)
            if not user:
                self.send_response(401)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"success": false, "error": "Unauthorized"}')
                return
            target_user = user
            if body:
                try:
                    b_data = json.loads(body.decode("utf-8"))
                    req_u = b_data.get("username", "").strip()
                    if req_u and req_u in users_db:
                        target_user = req_u
                except Exception:
                    pass
            challenge = secrets.token_urlsafe(32)
            webauthn_challenges[target_user] = {"challenge": challenge, "ts": time.time()}
            user_id = hashlib.sha256(target_user.encode("utf-8")).hexdigest()[:16]
            host_header = self.headers.get("Host", "localhost").split(":")[0]
            options = {
                "challenge": challenge,
                "rp": {"name": "Anashwar Technologies Fleet Portal", "id": host_header},
                "user": {"id": user_id, "name": target_user, "displayName": f"{target_user} ({users_db.get(target_user, {}).get('role', 'User')})"},
                "pubKeyCredParams": [{"type": "public-key", "alg": -7}, {"type": "public-key", "alg": -257}],
                "authenticatorSelection": {
                    "authenticatorAttachment": "platform",
                    "userVerification": "preferred",
                    "residentKey": "preferred"
                },
                "timeout": 60000
            }
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"success": True, "options": options, "challenge": challenge, "target_user": target_user}).encode("utf-8"))

        elif path == "/api/webauthn/register/verify":
            user, token = get_authenticated_user(self.headers, parsed)
            if not user:
                self.send_response(401)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"success": false, "error": "Unauthorized"}')
                return
            try:
                data = json.loads(body.decode("utf-8")) if body else {}
                cred_id = data.get("id", "") or data.get("rawId", "")
                target_user = data.get("username", user).strip() or user
                device_label = data.get("device_label", "Biometric Sensor (Fingerprint / Face ID)")
                if not cred_id:
                    self.send_response(400)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(b'{"success": false, "error": "Missing biometric credential ID"}')
                    return
                if target_user not in webauthn_credentials:
                    webauthn_credentials[target_user] = []
                webauthn_credentials[target_user].append({
                    "credential_id": cred_id,
                    "raw_id": cred_id,
                    "device": device_label,
                    "enrolled_at": time.strftime("%Y-%m-%d %H:%M:%S")
                })
                save_webauthn()
                caller_role = users_db.get(user, {}).get("role", "User")
                log_event(f"AUTH: Biometric device enrolled for user '{target_user}' ({device_label})", actor=user, actor_role=caller_role)
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"success": True, "message": f"Biometric passkey successfully linked to '{target_user}'"}).encode("utf-8"))
            except Exception as e:
                self.send_response(400)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"success": False, "error": f"Registration error: {str(e)}"}).encode("utf-8"))

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
                log_event(f"REGISTRY: Assigned [{node_name}] to Project '{project_id}'", actor=user, actor_role=caller_role)
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"success": true}')
            else:
                self.send_error(400, "Invalid node or project")

        # 12. Reverse Proxy for Node In-Situ Web UI (POST Support)
        elif path.startswith("/proxy/node/"):
            self._handle_node_proxy("POST", path, parsed, body=body, token=token, user=user)

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
                            log_event(f"CUSTOM BINARY UPLOADED: '{filename}' ({info['size_kb']} KB, Chip: {info['target_chip']})", actor=user, actor_role=caller_role)

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
<html lang="en" data-theme="dark">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Anashwar Technologies - Operations Console Login</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&family=JetBrains+Mono:wght@500;600&display=swap" rel="stylesheet">
  <script>
    (function(){
      try {
        var t = localStorage.getItem('anashwar_theme') || 'dark';
        document.documentElement.setAttribute('data-theme', t);
      } catch(e){}
    })();
  </script>
  <style>
    :root {
      --l-bg: #070B14;
      --l-card: rgba(15, 23, 42, 0.72);
      --l-border: rgba(255, 255, 255, 0.12);
      --l-text: #F8FAFC;
      --l-muted: #94A3B8;
      --l-dim: #64748B;
      --l-input-bg: rgba(30, 41, 59, 0.65);
      --l-bio-bg: rgba(255, 255, 255, 0.05);
      --l-divider: rgba(255, 255, 255, 0.1);
      --l-shadow: 0 25px 60px rgba(0, 0, 0, 0.55), inset 0 1px 0 rgba(255, 255, 255, 0.12);
    }
    html[data-theme="light"] {
      --l-bg: #EEF2F7;
      --l-card: rgba(255, 255, 255, 0.86);
      --l-border: rgba(15, 23, 42, 0.10);
      --l-text: #0F172A;
      --l-muted: #475569;
      --l-dim: #64748B;
      --l-input-bg: #FFFFFF;
      --l-bio-bg: rgba(15, 23, 42, 0.04);
      --l-divider: rgba(15, 23, 42, 0.1);
      --l-shadow: 0 24px 54px rgba(15, 23, 42, 0.10), inset 0 1px 0 rgba(255, 255, 255, 0.9);
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: 'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, sans-serif;
      background: var(--l-bg);
      color: var(--l-text);
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      position: relative;
      overflow: hidden;
      padding: 20px;
      transition: background-color 0.35s ease, color 0.35s ease;
    }
    #login-mesh-bg {
      position: fixed;
      inset: 0;
      width: 100%;
      height: 100%;
      z-index: 0;
      pointer-events: none;
    }
    .ambient-glow-1 {
      position: fixed;
      top: -160px;
      left: -140px;
      width: 520px;
      height: 520px;
      background: radial-gradient(circle, rgba(225, 29, 72, 0.22) 0%, rgba(225, 29, 72, 0) 70%);
      filter: blur(80px);
      pointer-events: none;
      animation: driftGlowA 14s ease-in-out infinite alternate;
      z-index: 1;
    }
    .ambient-glow-2 {
      position: fixed;
      bottom: -160px;
      right: -140px;
      width: 560px;
      height: 560px;
      background: radial-gradient(circle, rgba(14, 165, 233, 0.20) 0%, rgba(14, 165, 233, 0) 70%);
      filter: blur(90px);
      pointer-events: none;
      animation: driftGlowB 16s ease-in-out infinite alternate;
      z-index: 1;
    }
    @keyframes driftGlowA {
      0% { transform: translate(0, 0) scale(1); }
      100% { transform: translate(60px, 45px) scale(1.12); }
    }
    @keyframes driftGlowB {
      0% { transform: translate(0, 0) scale(1); }
      100% { transform: translate(-55px, -40px) scale(1.15); }
    }
    @keyframes cardFloatIn {
      from { opacity: 0; transform: translateY(18px) scale(0.985); }
      to { opacity: 1; transform: translateY(0) scale(1); }
    }
    .theme-fab {
      position: fixed;
      top: 18px;
      right: 18px;
      z-index: 20;
      display: inline-flex;
      align-items: center;
      gap: 7px;
      padding: 8px 14px;
      border-radius: 100px;
      background: var(--l-card);
      backdrop-filter: blur(18px);
      border: 1px solid var(--l-border);
      color: var(--l-text);
      font-size: 12px;
      font-weight: 700;
      cursor: pointer;
      transition: all 0.22s ease;
      font-family: inherit;
    }
    .theme-fab:hover {
      border-color: #E11D48;
      transform: translateY(-1px);
    }
    .login-card {
      position: relative;
      z-index: 10;
      width: 100%;
      max-width: 420px;
      background: var(--l-card);
      backdrop-filter: blur(28px);
      -webkit-backdrop-filter: blur(28px);
      border: 1px solid var(--l-border);
      border-radius: 24px;
      padding: 40px 32px;
      box-shadow: var(--l-shadow);
      animation: cardFloatIn 0.45s cubic-bezier(0.22, 1, 0.36, 1) forwards;
    }
    .login-brand { text-align: center; margin-bottom: 28px; }
    .login-logo { height: 44px; width: auto; margin-bottom: 14px; filter: drop-shadow(0 4px 12px rgba(225, 29, 72, 0.28)); }
    .login-title { font-size: 22px; font-weight: 800; letter-spacing: -0.5px; color: var(--l-text); }
    .login-subtitle { font-size: 13px; color: var(--l-muted); margin-top: 4px; }
    .badge-pill {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      background: rgba(225, 29, 72, 0.12);
      border: 1px solid rgba(225, 29, 72, 0.3);
      color: #E11D48;
      font-size: 11px;
      font-weight: 700;
      padding: 5px 12px;
      border-radius: 100px;
      margin-top: 12px;
    }
    html[data-theme="dark"] .badge-pill { color: #FB7185; }
    .form-group { margin-bottom: 20px; text-align: left; }
    .form-label { display: block; font-size: 12px; font-weight: 600; color: var(--l-muted); margin-bottom: 8px; letter-spacing: 0.2px; }
    .input-wrapper { position: relative; display: flex; align-items: center; }
    .input-icon {
      position: absolute;
      left: 14px;
      display: flex;
      align-items: center;
      color: var(--l-dim);
      pointer-events: none;
    }
    .form-input {
      width: 100%;
      background: var(--l-input-bg);
      border: 1px solid var(--l-border);
      border-radius: 12px;
      padding: 12px 14px 12px 42px;
      font-size: 14px;
      color: var(--l-text);
      outline: none;
      transition: all 0.2s ease;
      font-family: inherit;
    }
    .form-input:focus {
      border-color: #E11D48;
      box-shadow: 0 0 0 3px rgba(225, 29, 72, 0.22);
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
    .btn-submit:hover { transform: translateY(-1px); box-shadow: 0 14px 30px rgba(225, 29, 72, 0.45); background: linear-gradient(135deg, #F43F5E 0%, #E11D48 100%); }
    .btn-submit:active, .btn-biometric:active { transform: scale(0.985); }
    .error-box {
      display: none;
      background: rgba(239, 68, 68, 0.14);
      border: 1px solid rgba(239, 68, 68, 0.4);
      color: #EF4444;
      padding: 10px 14px;
      border-radius: 10px;
      font-size: 12px;
      margin-bottom: 18px;
      text-align: center;
      font-weight: 600;
    }
    .login-footer { text-align: center; margin-top: 24px; font-size: 11px; color: var(--l-dim); line-height: 1.5; }
    .btn-biometric {
      width: 100%;
      background: var(--l-bio-bg);
      border: 1px solid var(--l-border);
      border-radius: 12px;
      padding: 12px;
      color: var(--l-text);
      font-size: 13px;
      font-weight: 700;
      cursor: pointer;
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 10px;
      transition: all 0.25s ease;
      font-family: inherit;
    }
    .btn-biometric:hover {
      background: rgba(225, 29, 72, 0.14);
      border-color: rgba(225, 29, 72, 0.45);
      transform: translateY(-1px);
    }
  </style>
</head>
<body>
  <canvas id="login-mesh-bg"></canvas>
  <button type="button" class="theme-fab" id="theme-toggle-login" onclick="toggleLoginTheme()">
    <svg id="login-theme-svg" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="5"/><path d="M12 1v2M12 21v2M4.22 4.22l1.42 1.42M18.36 18.36l1.42 1.42M1 12h2M21 12h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"/></svg>
    <span id="login-theme-lbl">Light Mode</span>
  </button>
  <div id="iframe-breakout-banner" style="display: none; background: #B91C1C; color: #FFF; padding: 12px 16px; font-size: 13px; text-align: center; justify-content: space-between; align-items: center; width: 100%; box-sizing: border-box; z-index: 99999; position: fixed; top: 0; left: 0;">
    <span>Notice: Viewing inside an embedded frame. For Biometric login, open directly in browser:</span>
    <button type="button" onclick="window.top.location.href = window.location.href;" style="background: #FFF; color: #000; border: none; padding: 6px 14px; border-radius: 8px; font-weight: 700; cursor: pointer; margin-left: 10px;">Open in Chrome &nearr;</button>
  </div>
  <div class="ambient-glow-1"></div>
  <div class="ambient-glow-2"></div>

  <div class="login-card">
    <div class="login-brand">
      <img src="/static/logo.png" alt="Anashwar Technologies" class="login-logo" onerror="this.style.display='none'">
      <div class="login-title">Anashwar Technologies</div>
      <div class="login-subtitle">Enterprise Edge Fleet Management Portal</div>
      <div class="badge-pill">
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
        <span>Encrypted Operations Console</span>
      </div>
    </div>

    <div class="error-box" id="error-banner"></div>

    <form onsubmit="handleLogin(event)">
      <div class="form-group">
        <label class="form-label">Username</label>
        <div class="input-wrapper">
          <span class="input-icon"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg></span>
          <input type="text" id="login-username" class="form-input" placeholder="Enter username" required autofocus autocomplete="username">
        </div>
      </div>

      <div class="form-group">
        <label class="form-label">Password</label>
        <div class="input-wrapper">
          <span class="input-icon"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"/></svg></span>
          <input type="password" id="login-password" class="form-input" placeholder="Enter password" required autocomplete="current-password">
        </div>
      </div>

      <button type="submit" class="btn-submit" id="login-btn">Sign In to Fleet Console &rarr;</button>

      <div style="margin: 18px 0 14px 0; display: flex; align-items: center; gap: 10px;">
        <div style="flex: 1; height: 1px; background: var(--l-divider);"></div>
        <span style="font-size: 11px; color: var(--l-dim); font-weight: 600; text-transform: uppercase;">Or Authenticate With</span>
        <div style="flex: 1; height: 1px; background: var(--l-divider);"></div>
      </div>

      <button type="button" class="btn-biometric" id="btn-biometric-login" onclick="handleBiometricLogin()">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
        <span>Biometric Login</span>
      </button>
    </form>

    <div class="login-footer">
      Anashwar Technologies Private Limited &bull; Enterprise Fleet Portal<br>
      Authorized Personnel Only &bull; All sessions logged & authenticated
    </div>
  </div>

  <script>
    const BIO_ICON_SVG = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>';
    function updateLoginThemeBtn() {
      const t = document.documentElement.getAttribute('data-theme') || 'dark';
      const lbl = document.getElementById('login-theme-lbl');
      const svg = document.getElementById('login-theme-svg');
      if (lbl) lbl.innerText = (t === 'dark') ? 'Light Mode' : 'Dark Mode';
      if (svg) svg.innerHTML = (t === 'dark')
        ? '<circle cx="12" cy="12" r="5"/><path d="M12 1v2M12 21v2M4.22 4.22l1.42 1.42M18.36 18.36l1.42 1.42M1 12h2M21 12h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"/>'
        : '<path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/>';
    }
    function toggleLoginTheme() {
      const cur = document.documentElement.getAttribute('data-theme') || 'dark';
      const nxt = (cur === 'dark') ? 'light' : 'dark';
      document.documentElement.setAttribute('data-theme', nxt);
      try { localStorage.setItem('anashwar_theme', nxt); } catch(e) {}
      updateLoginThemeBtn();
    }
    updateLoginThemeBtn();

    (function initLoginCanvas(){
      const cv = document.getElementById('login-mesh-bg');
      if (!cv) return;
      const ctx = cv.getContext('2d');
      let w = 0, h = 0, pts = [];
      function resize(){
        w = cv.width = window.innerWidth;
        h = cv.height = window.innerHeight;
        const cnt = Math.min(48, Math.max(20, Math.floor((w * h) / 30000)));
        pts = Array.from({length: cnt}, () => ({
          x: Math.random() * w, y: Math.random() * h,
          vx: (Math.random() - 0.5) * 0.45, vy: (Math.random() - 0.5) * 0.45,
          r: 1.5 + Math.random() * 1.8
        }));
      }
      resize();
      window.addEventListener('resize', resize);
      function tick(){
        if (!document.hidden) {
          ctx.clearRect(0, 0, w, h);
          const isLight = document.documentElement.getAttribute('data-theme') === 'light';
          const dotCol = isLight ? 'rgba(15, 23, 42, 0.25)' : 'rgba(56, 189, 248, 0.35)';
          const lineRgb = isLight ? '225, 29, 72' : '56, 189, 248';
          for (let i = 0; i < pts.length; i++) {
            const p = pts[i];
            p.x += p.vx; p.y += p.vy;
            if (p.x < 0 || p.x > w) p.vx *= -1;
            if (p.y < 0 || p.y > h) p.vy *= -1;
            ctx.beginPath(); ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
            ctx.fillStyle = dotCol; ctx.fill();
            for (let j = i + 1; j < pts.length; j++) {
              const q = pts[j], dx = p.x - q.x, dy = p.y - q.y, d = Math.hypot(dx, dy);
              if (d < 135) {
                ctx.beginPath(); ctx.moveTo(p.x, p.y); ctx.lineTo(q.x, q.y);
                ctx.strokeStyle = `rgba(${lineRgb}, ${(1 - d / 135) * (isLight ? 0.14 : 0.16)})`;
                ctx.lineWidth = 1; ctx.stroke();
              }
            }
          }
        }
        requestAnimationFrame(tick);
      }
      tick();
    })();

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

      const isTouch = ('ontouchstart' in window) || (navigator.maxTouchPoints > 0) || window.matchMedia('(pointer: coarse)').matches;
      const screenRes = `${window.screen.width}x${window.screen.height}`;
      const devModel = (navigator.userAgentData && navigator.userAgentData.model) ? navigator.userAgentData.model : "";

      try {
        const resp = await fetch('/api/login', {
          method: 'POST',
          headers: {'Content-Type': 'application/x-www-form-urlencoded'},
          body: `username=${encodeURIComponent(u)}&password=${encodeURIComponent(p)}&screen=${encodeURIComponent(screenRes)}&is_touch=${isTouch}&device_model=${encodeURIComponent(devModel)}`
        });
        const data = await resp.json();
        if (data.success && data.token) {
          btn.innerText = 'Authenticated! Loading Console...';
          localStorage.setItem('anashwar_token', data.token);
          sessionStorage.setItem('anashwar_token', data.token);
          try {
            document.cookie = `session_token=${data.token}; Path=/; SameSite=None; Secure; Max-Age=604800`;
          } catch(e) {}
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

    function base64UrlToUint8Array(base64Url) {
      if (!base64Url) return new Uint8Array(0);
      let base64 = base64Url.split("-").join("+").split("_").join("/");
      while (base64.length % 4 !== 0) {
        base64 += "=";
      }
      const bin = atob(base64);
      const bytes = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) {
        bytes[i] = bin.charCodeAt(i);
      }
      return bytes;
    }

    function bufferToBase64Url(buffer) {
      const bytes = new Uint8Array(buffer);
      let binary = "";
      for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
      }
      return btoa(binary).split("+").join("-").split("/").join("_").replace(/=+$/, "");
    }

    async function handleBiometricLogin() {
      const errBox = document.getElementById("error-banner");
      const bioBtn = document.getElementById("btn-biometric-login");
      errBox.style.display = "none";

      if (!window.isSecureContext && window.location.hostname !== "localhost" && window.location.hostname !== "127.0.0.1") {
        errBox.innerText = "Biometric authentication requires a secure HTTPS connection (or localhost). Please ensure you are connected via HTTPS.";
        errBox.style.display = "block";
        return;
      }

      if (!window.PublicKeyCredential) {
        errBox.innerText = "Biometric WebAuthn is not supported on this browser or platform.";
        errBox.style.display = "block";
        return;
      }

      bioBtn.disabled = true;
      bioBtn.innerHTML = BIO_ICON_SVG + "<span>Prompting Fingerprint / Face ID...</span>";

      try {
        const optRes = await fetch("/api/webauthn/login/options", { method: "POST" });
        const options = await optRes.json();

        if (!options || !options.challenge) {
          throw new Error(options.error || "Failed to initialize biometric challenge from server.");
        }

        if (!options.allowCredentials || options.allowCredentials.length === 0) {
          throw new Error("No biometric passkeys have been enrolled yet. Please sign in with username and password first, then enroll your device under Users & Access.");
        }

        const challengeBytes = base64UrlToUint8Array(options.challenge);

        const getCredentialOptions = {
          publicKey: {
            challenge: challengeBytes,
            timeout: options.timeout || 60000,
            userVerification: "preferred"
          }
        };

        const isIp = /^([0-9]{1,3}[.]){3}[0-9]{1,3}$/.test(window.location.hostname);
        if (!isIp) {
          getCredentialOptions.publicKey.rpId = window.location.hostname;
        }

        if (options.allowCredentials && options.allowCredentials.length > 0) {
          getCredentialOptions.publicKey.allowCredentials = options.allowCredentials.map(c => ({
            type: "public-key",
            id: base64UrlToUint8Array(c.id)
          }));
        }

        const assertion = await navigator.credentials.get(getCredentialOptions);
        if (!assertion) throw new Error("Biometric verification cancelled.");

        const credId = bufferToBase64Url(assertion.rawId);

        const isTouch = ("ontouchstart" in window) || (navigator.maxTouchPoints > 0) || (window.matchMedia && window.matchMedia("(pointer: coarse)").matches);
        const screenRes = `${window.screen.width}x${window.screen.height}`;
        const devModel = (navigator.userAgentData && navigator.userAgentData.model) ? navigator.userAgentData.model : "";

        const verifyRes = await fetch("/api/webauthn/login/verify", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ id: assertion.id || credId, rawId: credId, screen: screenRes, is_touch: isTouch, device_model: devModel })
        });
        const vData = await verifyRes.json();

        if (vData.success && vData.token) {
          bioBtn.innerHTML = "<span>Verified! Loading Console...</span>";
          localStorage.setItem("anashwar_token", vData.token);
          sessionStorage.setItem("anashwar_token", vData.token);
          try {
            document.cookie = `session_token=${vData.token}; Path=/; SameSite=None; Secure; Max-Age=604800`;
          } catch(e) {}
          window.location.href = "/?token=" + encodeURIComponent(vData.token);
        } else {
          errBox.innerText = vData.error || "Biometric authentication was not recognized. Please sign in with password first to enroll your device.";
          errBox.style.display = "block";
          bioBtn.disabled = false;
          bioBtn.innerHTML = BIO_ICON_SVG + "<span>Biometric Login</span>";
        }
      } catch (err) {
        if (window.self !== window.top) {
          errBox.innerText = "Embedded in-app frame restriction: WebAuthn biometrics cannot run inside an embedded webview or iframe. Please tap the top button to open directly in Google Chrome / Safari.";
        } else if (err.name === "NotAllowedError") {
          errBox.innerText = "Biometric prompt was dismissed or timed out.";
        } else {
          errBox.innerText = err.message || "Biometric scan was cancelled or timed out.";
        }
        errBox.style.display = "block";
        bioBtn.disabled = false;
        bioBtn.innerHTML = BIO_ICON_SVG + "<span>Biometric Login</span>";
      }
    }

    if (window.self !== window.top) {
      const banner = document.getElementById("iframe-breakout-banner");
      if (banner) banner.style.display = "flex";
    }
  </script>
</body>
</html>
"""

def render_fleet_html(current_user="admin", token=""):
    html_content = """<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
  <title>Anashwar Technologies - Enterprise Edge Fleet Console</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
  <script>
    (function(){
      try {
        var t = localStorage.getItem('anashwar_theme') || 'dark';
        document.documentElement.setAttribute('data-theme', t);
      } catch(e){}
    })();
  </script>
  <style>
    :root {
      --bg: #070B14;
      --sidebar: rgba(11, 16, 28, 0.88);
      --topbar-bg: rgba(9, 13, 22, 0.78);
      --card-bg: rgba(18, 25, 38, 0.74);
      --surface-2: rgba(0, 0, 0, 0.28);
      --surface-3: rgba(255, 255, 255, 0.04);
      --card-border: rgba(148, 163, 184, 0.14);
      --card-border-hover: rgba(225, 29, 72, 0.50);
      --crimson: #E11D48;
      --crimson-hover: #BE123C;
      --crimson-glow: rgba(225, 29, 72, 0.35);
      --success: #10B981;
      --warn: #F59E0B;
      --info: #06B6D4;
      --blue: #3B82F6;
      --text: #F8FAFC;
      --text-strong: #FFFFFF;
      --text-muted: #94A3B8;
      --text-dim: #64748B;
      --modal-bg: #0E131F;
      --input-bg: rgba(0, 0, 0, 0.32);
      --log-bg: #05080E;
      --log-text: #94A3B8;
      --bnav-bg: rgba(13, 17, 26, 0.94);
      --shadow-card: 0 10px 32px rgba(0, 0, 0, 0.38);
      --font: 'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, sans-serif;
      --font-mono: 'JetBrains Mono', monospace;
    }

    html[data-theme="light"] {
      --bg: #EEF2F7;
      --sidebar: rgba(255, 255, 255, 0.90);
      --topbar-bg: rgba(255, 255, 255, 0.84);
      --card-bg: rgba(255, 255, 255, 0.86);
      --surface-2: rgba(241, 245, 249, 0.90);
      --surface-3: rgba(15, 23, 42, 0.04);
      --card-border: rgba(15, 23, 42, 0.10);
      --card-border-hover: rgba(225, 29, 72, 0.45);
      --text: #0F172A;
      --text-strong: #020617;
      --text-muted: #475569;
      --text-dim: #64748B;
      --modal-bg: #FFFFFF;
      --input-bg: #FFFFFF;
      --log-bg: #F8FAFC;
      --log-text: #334155;
      --bnav-bg: rgba(255, 255, 255, 0.94);
      --shadow-card: 0 10px 28px rgba(15, 23, 42, 0.08);
    }

    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background-color: var(--bg);
      color: var(--text);
      font-family: var(--font);
      min-height: 100vh;
      display: flex;
      overflow-x: hidden;
      transition: background-color 0.35s ease, color 0.35s ease;
    }

    /* Live Animated Background Canvas & Orbs */
    #live-mesh-bg {
      position: fixed;
      inset: 0;
      width: 100%;
      height: 100%;
      z-index: 0;
      pointer-events: none;
    }
    .bg-orb-1, .bg-orb-2 {
      position: fixed;
      border-radius: 50%;
      filter: blur(110px);
      pointer-events: none;
      z-index: 0;
      opacity: 0.55;
    }
    .bg-orb-1 {
      top: -180px;
      left: 120px;
      width: 520px;
      height: 520px;
      background: radial-gradient(circle, rgba(225, 29, 72, 0.16) 0%, transparent 70%);
      animation: orbDrift1 18s ease-in-out infinite alternate;
    }
    .bg-orb-2 {
      bottom: -200px;
      right: -120px;
      width: 580px;
      height: 580px;
      background: radial-gradient(circle, rgba(6, 182, 212, 0.15) 0%, transparent 70%);
      animation: orbDrift2 22s ease-in-out infinite alternate;
    }
    @keyframes orbDrift1 {
      0% { transform: translate(0, 0) scale(1); }
      100% { transform: translate(65px, 45px) scale(1.12); }
    }
    @keyframes orbDrift2 {
      0% { transform: translate(0, 0) scale(1); }
      100% { transform: translate(-70px, -50px) scale(1.14); }
    }
    @keyframes viewFadeSlide {
      from { opacity: 0; transform: translateY(10px); }
      to { opacity: 1; transform: translateY(0); }
    }
    .view-animate-in {
      animation: viewFadeSlide 0.32s cubic-bezier(0.22, 1, 0.36, 1) forwards;
    }
    .svg-icon {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      flex-shrink: 0;
      vertical-align: middle;
    }
    .esp32-hw-frame {
      width: 44px;
      height: 44px;
      border-radius: 10px;
      background: #FFFFFF;
      padding: 3px;
      border: 1px solid var(--card-border);
      box-shadow: 0 3px 10px rgba(0, 0, 0, 0.14);
      display: flex;
      align-items: center;
      justify-content: center;
      overflow: hidden;
      flex-shrink: 0;
      transition: transform 0.25s cubic-bezier(0.22, 1, 0.36, 1);
    }
    .esp32-hw-frame img {
      width: 100%;
      height: 100%;
      object-fit: contain;
    }
    .esp32-hero-frame {
      width: 60px;
      height: 60px;
      border-radius: 14px;
      background: #FFFFFF;
      padding: 5px;
      border: 1px solid var(--card-border);
      box-shadow: 0 5px 16px rgba(0, 0, 0, 0.18);
      display: flex;
      align-items: center;
      justify-content: center;
      overflow: hidden;
      flex-shrink: 0;
      transition: transform 0.3s ease;
    }
    .esp32-hero-frame:hover { transform: scale(1.05); }
    .esp32-hero-frame img {
      width: 100%;
      height: 100%;
      object-fit: contain;
    }
    .active-node-row {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 10px;
      padding: 10px 12px;
      border-radius: 12px;
      background: var(--surface-2);
      border: 1px solid var(--card-border);
      margin-bottom: 8px;
      transition: all 0.22s cubic-bezier(0.22, 1, 0.36, 1);
    }
    .active-node-row:hover {
      border-color: rgba(16, 185, 129, 0.45);
      transform: translateY(-2px);
      box-shadow: 0 6px 18px rgba(0, 0, 0, 0.18);
    }
    .active-node-row:hover .esp32-hw-frame, .node-card:hover .esp32-hw-frame {
      transform: scale(1.06) rotate(-1.5deg);
    }
    .btn-main:active, .btn-secondary:active, .preset-pill:active, .theme-toggle-btn:active {
      transform: scale(0.975);
    }

    /* Scrollbars */
    ::-webkit-scrollbar { width: 6px; height: 6px; }
    ::-webkit-scrollbar-track { background: transparent; }
    ::-webkit-scrollbar-thumb { background: rgba(148, 163, 184, 0.25); border-radius: 4px; }
    ::-webkit-scrollbar-thumb:hover { background: rgba(148, 163, 184, 0.45); }

    /* Left Sidebar */
    .sidebar {
      width: 204px;
      min-width: 204px;
      background: var(--sidebar);
      backdrop-filter: blur(22px);
      -webkit-backdrop-filter: blur(22px);
      border-right: 1px solid var(--card-border);
      display: flex;
      flex-direction: column;
      position: sticky;
      top: 0;
      height: 100vh;
      z-index: 100;
      transition: background-color 0.3s ease, border-color 0.3s ease;
    }

    .brand-header {
      padding: 14px 12px;
      display: flex;
      align-items: center;
      gap: 10px;
      border-bottom: 1px solid var(--card-border);
    }
    .brand-logo {
      width: 34px;
      height: 34px;
      border-radius: 9px;
      background: #FFFFFF;
      padding: 3px;
      box-shadow: 0 3px 12px var(--crimson-glow);
      display: flex;
      align-items: center;
      justify-content: center;
      flex-shrink: 0;
    }
    .brand-logo img {
      width: 100%;
      height: 100%;
      object-fit: contain;
    }
    .brand-title {
      display: flex;
      flex-direction: column;
      min-width: 0;
    }
    .brand-name {
      font-size: 14px;
      font-weight: 800;
      color: var(--text-strong);
      letter-spacing: -0.2px;
      line-height: 1.2;
    }
    .brand-subtitle {
      font-size: 10px;
      color: var(--text-muted);
      font-weight: 500;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }

    .nav-section {
      padding: 10px 10px 4px 10px;
    }
    .nav-section-title {
      font-size: 10px;
      text-transform: uppercase;
      letter-spacing: 0.7px;
      color: var(--text-dim);
      font-weight: 700;
      padding-left: 8px;
      margin-bottom: 5px;
    }
    .nav-item {
      display: flex;
      align-items: center;
      gap: 8px;
      padding: 7px 9px;
      border-radius: 8px;
      color: var(--text-muted);
      text-decoration: none;
      font-size: 12px;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.2s ease;
      margin-bottom: 2px;
      white-space: nowrap;
      overflow: hidden;
    }
    .nav-item:hover {
      color: var(--text-strong);
      background: var(--surface-3);
    }
    .nav-item.active {
      background: var(--crimson);
      color: #FFFFFF;
      box-shadow: 0 4px 14px var(--crimson-glow);
    }
    .nav-icon {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      width: 16px;
      height: 16px;
      flex-shrink: 0;
    }

    .sidebar-footer {
      margin-top: auto;
      padding: 10px 12px;
      border-top: 1px solid var(--card-border);
      background: var(--surface-2);
    }
    .status-badge-row {
      display: flex;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 5px;
      font-size: 11px;
      gap: 6px;
    }
    .status-pill {
      display: inline-flex;
      align-items: center;
      gap: 4px;
      padding: 2px 7px;
      border-radius: 20px;
      font-size: 10px;
      font-weight: 700;
    }
    .pill-green {
      background: rgba(16, 185, 129, 0.14);
      color: #10B981;
      border: 1px solid rgba(16, 185, 129, 0.35);
    }
    .pill-crimson {
      background: rgba(225, 29, 72, 0.14);
      color: #FB7185;
      border: 1px solid rgba(225, 29, 72, 0.35);
    }
    .pill-cyan {
      background: rgba(6, 182, 212, 0.14);
      color: #38BDF8;
      border: 1px solid rgba(6, 182, 212, 0.35);
    }
    html[data-theme="light"] .pill-green { color: #047857; background: rgba(16, 185, 129, 0.12); }
    html[data-theme="light"] .pill-crimson { color: #BE123C; background: rgba(225, 29, 72, 0.10); }
    html[data-theme="light"] .pill-cyan { color: #0369A1; background: rgba(14, 165, 233, 0.12); }
    .delete-btn-tiny {
      background: rgba(239, 68, 68, 0.12);
      border: 1px solid rgba(239, 68, 68, 0.3);
      color: #EF4444;
      border-radius: 8px;
      padding: 5px 8px;
      font-size: 11px;
      cursor: pointer;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 4px;
      transition: all 0.2s ease;
      line-height: 1;
    }
    .delete-btn-tiny:hover {
      background: rgba(239, 68, 68, 0.28);
      color: var(--text-strong);
      transform: scale(1.05);
    }
    .user-pill-btn {
      display: flex;
      align-items: center;
      gap: 6px;
      background: var(--surface-3);
      border: 1px solid var(--card-border);
      color: var(--text);
      padding: 5px 12px;
      border-radius: 100px;
      cursor: pointer;
      transition: all 0.2s;
    }
    .user-pill-btn:hover {
      border-color: var(--crimson);
    }
    .theme-toggle-btn {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      background: var(--surface-3);
      border: 1px solid var(--card-border);
      color: var(--text);
      padding: 6px 12px;
      border-radius: 100px;
      font-size: 12px;
      font-weight: 700;
      cursor: pointer;
      font-family: inherit;
      transition: all 0.22s ease;
    }
    .theme-toggle-btn:hover {
      border-color: var(--info);
      color: var(--text-strong);
      transform: translateY(-1px);
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
      position: relative;
      z-index: 10;
    }

    /* Top Navigation Bar */
    .topbar {
      height: 56px;
      padding: 0 22px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      border-bottom: 1px solid var(--card-border);
      background: var(--topbar-bg);
      backdrop-filter: blur(18px);
      -webkit-backdrop-filter: blur(18px);
      position: sticky;
      top: 0;
      z-index: 90;
      transition: background-color 0.3s ease, border-color 0.3s ease;
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
      display: inline-flex;
      align-items: center;
      gap: 6px;
      transition: color 0.2s;
    }
    .breadcrumb-item:hover {
      color: var(--text-strong);
    }
    .breadcrumb-active {
      color: var(--text-strong);
      font-weight: 700;
      display: inline-flex;
      align-items: center;
      gap: 6px;
    }
    .breadcrumb-sep {
      color: var(--text-dim);
      font-size: 11px;
    }

    .topbar-actions {
      display: flex;
      align-items: center;
      gap: 12px;
    }
    .search-box {
      display: flex;
      align-items: center;
      gap: 8px;
      background: var(--surface-3);
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
      color: var(--text-strong);
      font-size: 13px;
      width: 180px;
    }
    .kbd-shortcut {
      background: var(--surface-3);
      border: 1px solid var(--card-border);
      padding: 2px 6px;
      border-radius: 4px;
      font-size: 10px;
      font-family: var(--font-mono);
    }

    /* Content Area */
    .content-area {
      padding: 20px 22px;
      flex: 1;
    }

    /* Top KPI Summary Gradient Cards (3 Cards) */
    .kpi-grid {
      display: grid;
      grid-template-columns: repeat(3, 1fr);
      gap: 14px;
      margin-bottom: 20px;
    }
    .kpi-card {
      border-radius: 14px;
      padding: 15px 18px;
      color: #FFFFFF;
      position: relative;
      overflow: hidden;
      box-shadow: 0 10px 30px rgba(0, 0, 0, 0.25);
      transition: transform 0.25s cubic-bezier(0.22, 1, 0.36, 1), box-shadow 0.25s ease;
    }
    .kpi-card:hover {
      transform: translateY(-3px);
      box-shadow: 0 16px 36px rgba(0, 0, 0, 0.32);
    }
    .kpi-card.gradient-crimson {
      background: linear-gradient(135deg, #E11D48 0%, #9F1239 100%);
    }
    .kpi-card.gradient-orange {
      background: linear-gradient(135deg, #F97316 0%, #C2410C 100%);
    }
    .kpi-card.gradient-cyan {
      background: linear-gradient(135deg, #06B6D4 0%, #0369A1 100%);
    }
    .kpi-title {
      font-size: 11px;
      text-transform: uppercase;
      letter-spacing: 0.7px;
      opacity: 0.9;
      font-weight: 700;
      margin-bottom: 5px;
    }
    .kpi-value {
      font-size: 20px;
      font-weight: 800;
      letter-spacing: -0.4px;
      margin-bottom: 4px;
    }
    .kpi-subtitle {
      font-size: 11px;
      opacity: 0.9;
      font-weight: 500;
    }

    /* Frosted Glass Chamfered Cards */
    .glass-card {
      background: var(--card-bg);
      backdrop-filter: blur(20px);
      -webkit-backdrop-filter: blur(20px);
      border: 1px solid var(--card-border);
      border-radius: 15px;
      padding: 18px;
      box-shadow: var(--shadow-card);
      transition: all 0.25s cubic-bezier(0.16, 1, 0.3, 1);
      position: relative;
    }
    .glass-card:hover {
      border-color: var(--card-border-hover);
      transform: translateY(-2px);
    }

    .section-header-row {
      display: flex;
      align-items: center;
      justify-content: space-between;
      flex-wrap: wrap;
      gap: 10px;
      margin-bottom: 14px;
    }
    .section-heading {
      font-size: 16px;
      font-weight: 800;
      color: var(--text-strong);
      letter-spacing: -0.3px;
      display: flex;
      align-items: center;
      gap: 8px;
    }
    .section-desc {
      font-size: 12px;
      color: var(--text-muted);
      margin-top: 2px;
    }

    /* Client Tiles Grid */
    .client-grid {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(330px, 1fr));
      gap: 16px;
      margin-bottom: 24px;
    }
    .client-tile {
      cursor: pointer;
    }
    .client-tile-header {
      display: flex;
      align-items: flex-start;
      justify-content: space-between;
      margin-bottom: 12px;
    }
    .client-avatar {
      width: 40px;
      height: 40px;
      border-radius: 11px;
      background: linear-gradient(135deg, rgba(225, 29, 72, 0.2), rgba(225, 29, 72, 0.05));
      border: 1px solid rgba(225, 29, 72, 0.3);
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 15px;
      font-weight: 800;
      color: #FB7185;
    }
    html[data-theme="light"] .client-avatar { color: #E11D48; }
    .client-name {
      font-size: 17px;
      font-weight: 700;
      color: var(--text-strong);
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
      background: var(--surface-2);
      border-radius: 12px;
      padding: 12px;
      margin: 14px 0;
      border: 1px solid var(--card-border);
    }
    .metric-col {
      text-align: center;
    }
    .metric-val {
      font-size: 15px;
      font-weight: 700;
      color: var(--text-strong);
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
      border-top: 1px solid var(--card-border);
      font-size: 13px;
      font-weight: 600;
      color: var(--crimson);
    }

    /* Add Card Placeholder */
    .add-card-btn {
      background: var(--surface-3);
      border: 2px dashed var(--card-border);
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
      color: var(--text-strong);
      background: rgba(225, 29, 72, 0.05);
    }
    .add-icon-circle {
      width: 44px;
      height: 44px;
      border-radius: 50%;
      background: var(--surface-3);
      border: 1px solid var(--card-border);
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 20px;
    }

    /* Projects Grid */
    .projects-grid {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(320px, 1fr));
      gap: 16px;
      margin-bottom: 24px;
    }
    .project-card {
      cursor: pointer;
    }

    /* Node Cards Grid */
    .nodes-grid {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(330px, 1fr));
      gap: 16px;
      margin-bottom: 24px;
    }
    .node-card {
      cursor: pointer;
    }
    .node-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 12px;
    }
    .node-title-group {
      display: flex;
      align-items: center;
      gap: 10px;
    }
    .node-name {
      font-size: 16px;
      font-weight: 800;
      color: var(--text-strong);
    }
    .node-spec-row {
      display: flex;
      justify-content: space-between;
      padding: 8px 0;
      font-size: 13px;
      border-bottom: 1px solid var(--card-border);
    }
    .node-spec-lbl {
      color: var(--text-muted);
    }
    .node-spec-val {
      font-family: var(--font-mono);
      font-weight: 600;
      color: var(--text-strong);
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
      background: var(--surface-2);
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
      color: var(--text-strong);
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
      background: var(--surface-2);
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
      flex-wrap: wrap;
    }
    .preset-pill {
      background: var(--surface-3);
      border: 1px solid var(--card-border);
      border-radius: 8px;
      padding: 6px 12px;
      font-size: 12px;
      font-weight: 600;
      color: var(--text-muted);
      cursor: pointer;
      display: inline-flex;
      align-items: center;
      gap: 6px;
      transition: all 0.2s;
    }
    .preset-pill:hover, .preset-pill.active {
      background: var(--crimson);
      color: #FFFFFF;
      border-color: var(--crimson);
    }

    /* Live Hardware Simulation Panel (LED & BOOT Button) */
    .hw-visualizer {
      background: var(--surface-2);
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
      background: var(--surface-3);
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
      background: var(--surface-3);
      border: 1px solid var(--card-border);
      border-radius: 12px;
      padding: 14px 16px;
      text-align: left;
      cursor: pointer;
      transition: all 0.2s;
    }
    .mode-btn:hover {
      border-color: var(--card-border-hover);
    }
    .mode-btn.active {
      background: rgba(225, 29, 72, 0.15);
      border-color: var(--crimson);
    }
    .mode-btn-title {
      font-size: 13px;
      font-weight: 700;
      color: var(--text-strong);
      margin-bottom: 4px;
    }
    .mode-btn-desc {
      font-size: 11px;
      color: var(--text-muted);
      line-height: 1.4;
    }

    /* Drag and Drop Zone */
    .dropzone {
      border: 2px dashed var(--card-border);
      border-radius: 14px;
      padding: 24px;
      text-align: center;
      background: var(--surface-2);
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
      background: var(--surface-3);
      border: 1px solid var(--card-border);
      color: var(--text-strong);
    }
    .btn-usb:hover {
      border-color: var(--crimson);
    }

    /* Progress Stepper */
    .update-tracker {
      background: var(--surface-2);
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
      background: rgba(0, 0, 0, 0.72);
      backdrop-filter: blur(8px);
      -webkit-backdrop-filter: blur(8px);
      display: none;
      align-items: center;
      justify-content: center;
      z-index: 200;
      transform: translateZ(0);
      will-change: opacity;
    }
    .modal-overlay.open { display: flex; }
    .modal-card {
      width: 100%;
      max-width: 580px;
      background: var(--modal-bg);
      color: var(--text);
      border: 1px solid var(--card-border);
      border-radius: 20px;
      padding: 28px;
      box-shadow: 0 20px 60px rgba(0,0,0,0.45);
      max-height: 90vh;
      overflow-y: auto;
      transform: translateZ(0);
      animation: viewFadeSlide 0.22s ease;
    }
    .modal-card h3 {
      font-size: 18px;
      font-weight: 800;
      color: var(--text-strong);
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
      background: var(--input-bg);
      border: 1px solid var(--card-border);
      border-radius: 10px;
      color: var(--text-strong);
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
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 6px;
      transition: all 0.2s ease;
    }
    .btn-secondary:hover {
      color: var(--text-strong);
      border-color: var(--card-border-hover);
      background: var(--surface-3);
    }

    /* Terminal logs */
    .log-box {
      background: var(--log-bg);
      border: 1px solid var(--card-border);
      border-radius: 14px;
      padding: 16px;
      font-family: var(--font-mono);
      font-size: 12px;
      height: 180px;
      overflow-y: auto;
      color: var(--log-text);
      line-height: 1.6;
    }

    /* Two-Form Display System: Touch Screen Phone vs Non-Touch PC/Mac Desktop */
    .form-mode-pill {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 6px 14px;
      border-radius: 100px;
      background: rgba(225, 29, 72, 0.12);
      border: 1px solid rgba(225, 29, 72, 0.35);
      color: #FB7185;
      font-size: 12px;
      font-weight: 700;
      cursor: pointer;
      transition: all 0.2s ease;
      font-family: var(--font);
    }
    .form-mode-pill:hover {
      background: rgba(225, 29, 72, 0.25);
      border-color: var(--crimson);
      color: #FFFFFF;
      transform: translateY(-1px);
    }

    /* Base Firmware Golden Reference Card */
    .base-firmware-card {
      background: var(--surface-3);
      border: 1px solid var(--card-border);
      border-radius: 14px;
      padding: 16px 18px;
      cursor: pointer;
      transition: all 0.2s ease;
      margin-bottom: 18px;
    }
    .base-firmware-card:hover {
      border-color: var(--card-border-hover);
    }
    .base-firmware-card.active {
      background: rgba(225, 29, 72, 0.12);
      border-color: var(--crimson);
      box-shadow: 0 4px 20px rgba(225, 29, 72, 0.22);
    }

    /* Mobile Bottom Navigation Bar */
    .mobile-bottom-nav {
      display: none;
      position: fixed;
      bottom: 0;
      left: 0;
      right: 0;
      height: 64px;
      background: var(--bnav-bg);
      backdrop-filter: blur(20px);
      -webkit-backdrop-filter: blur(20px);
      border-top: 1px solid var(--card-border);
      z-index: 150;
      grid-template-columns: repeat(4, 1fr);
      align-items: center;
      padding: 0 8px;
      box-shadow: 0 -4px 24px rgba(0, 0, 0, 0.25);
    }
    .bottom-nav-item {
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      background: transparent;
      border: none;
      color: var(--text-muted);
      cursor: pointer;
      padding: 8px 4px;
      border-radius: 10px;
      transition: all 0.2s;
      text-decoration: none;
      min-height: 48px;
    }
    .bottom-nav-item .bnav-icon {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      line-height: 1.2;
    }
    .bottom-nav-item .bnav-label {
      font-size: 11px;
      font-weight: 600;
      margin-top: 2px;
    }
    .bottom-nav-item.active, .bottom-nav-item:active {
      color: #0EA5E9;
    }
    .bottom-nav-item.active .bnav-icon {
      transform: scale(1.15);
    }

    /* Responsive Phone Touch Mode (Default <= 860px or overridden by class) */
    @media (max-width: 860px) {
      .sidebar { display: none !important; }
      .mobile-bottom-nav { display: grid !important; }
      .content-area { padding: 14px 16px 84px 16px !important; }
      .topbar { padding: 0 16px !important; height: 60px !important; }
      .search-box { display: none !important; }
      #mdns-link, #public-tunnel-link { display: none !important; }
      .kpi-grid { grid-template-columns: 1fr !important; gap: 12px !important; margin-bottom: 18px !important; }
      .kpi-card { padding: 16px !important; border-radius: 14px !important; }
      .kpi-title { font-size: 12px !important; }
      .kpi-value { font-size: 20px !important; }
      .node-detail-layout { grid-template-columns: 1fr !important; gap: 18px !important; }
      .client-grid, .projects-grid, .nodes-grid { grid-template-columns: 1fr !important; gap: 12px !important; }
      .btn-action-row { grid-template-columns: 1fr !important; gap: 10px !important; }
      .modal-overlay { align-items: flex-end !important; }
      .modal-card { width: 100% !important; max-width: 100% !important; border-radius: 20px 20px 0 0 !important; max-height: 85vh !important; overflow-y: auto !important; padding: 22px 18px 32px 18px !important; }
      .apple-switch { width: 56px !important; height: 32px !important; }
      .apple-switch .slider:before { height: 26px !important; width: 26px !important; left: 3px !important; bottom: 3px !important; }
      .apple-switch input:checked + .slider:before { transform: translateX(24px) !important; }
      .btn-main, .btn-secondary { min-height: 44px !important; font-size: 13px !important; }
      .form-input { min-height: 46px !important; font-size: 15px !important; }
    }

    body.mode-phone-touch .sidebar { display: none !important; }
    body.mode-phone-touch .mobile-bottom-nav { display: grid !important; }
    body.mode-phone-touch .content-area { padding: 14px 16px 84px 16px !important; }
    body.mode-phone-touch .topbar { padding: 0 16px !important; height: 60px !important; }
    body.mode-phone-touch .search-box { display: none !important; }
    body.mode-phone-touch #mdns-link, body.mode-phone-touch #public-tunnel-link { display: none !important; }
    body.mode-phone-touch .kpi-grid { grid-template-columns: 1fr !important; gap: 12px !important; margin-bottom: 18px !important; }
    body.mode-phone-touch .node-detail-layout { grid-template-columns: 1fr !important; gap: 18px !important; }
    body.mode-phone-touch .client-grid, body.mode-phone-touch .projects-grid, body.mode-phone-touch .nodes-grid { grid-template-columns: 1fr !important; gap: 12px !important; }
    body.mode-phone-touch .btn-action-row { grid-template-columns: 1fr !important; gap: 10px !important; }
    body.mode-phone-touch .modal-overlay { align-items: flex-end !important; }
    body.mode-phone-touch .modal-card { width: 100% !important; max-width: 100% !important; border-radius: 20px 20px 0 0 !important; max-height: 85vh !important; overflow-y: auto !important; padding: 22px 18px 32px 18px !important; }
    body.mode-phone-touch .apple-switch { width: 56px !important; height: 32px !important; }
    body.mode-phone-touch .apple-switch .slider:before { height: 26px !important; width: 26px !important; left: 3px !important; bottom: 3px !important; }
    body.mode-phone-touch .apple-switch input:checked + .slider:before { transform: translateX(24px) !important; }
    body.mode-phone-touch .btn-main, body.mode-phone-touch .btn-secondary { min-height: 44px !important; font-size: 13px !important; }
    body.mode-phone-touch .form-input { min-height: 46px !important; font-size: 15px !important; }

    body.mode-desktop-pc .sidebar { display: flex !important; }
    body.mode-desktop-pc .mobile-bottom-nav { display: none !important; }
    body.mode-desktop-pc .content-area { padding: 20px 22px !important; }
    body.mode-desktop-pc .kpi-grid { display: grid !important; grid-template-columns: repeat(3, 1fr) !important; }
    body.mode-desktop-pc .node-detail-layout { display: grid !important; grid-template-columns: 1.1fr 0.9fr !important; }
    body.mode-desktop-pc .modal-overlay { align-items: center !important; }
    body.mode-desktop-pc .modal-card { border-radius: 20px !important; max-height: 88vh !important; overflow-y: auto !important; }
  </style>
</head>
<body>
  <canvas id="live-mesh-bg"></canvas>
  <div class="bg-orb-1"></div>
  <div class="bg-orb-2"></div>

  <div id="iframe-breakout-banner" style="display: none; background: #B91C1C; color: #FFF; padding: 12px 16px; font-size: 13px; text-align: center; justify-content: space-between; align-items: center; width: 100%; box-sizing: border-box; z-index: 99999; position: relative;">
    <span>Embedded frame detected. For hardware biometrics (Fingerprint / Face ID), open directly in browser:</span>
    <button type="button" onclick="window.top.location.href = window.location.href;" style="background: #FFF; color: #000; border: none; padding: 6px 14px; border-radius: 8px; font-weight: 700; cursor: pointer; margin-left: 10px;">Open in Chrome &rarr;</button>
  </div>

  <!-- Left Sidebar -->
  <aside class="sidebar">
    <div class="brand-header" onclick="navigateTo('dashboard')" style="cursor: pointer;">
      <div class="brand-logo">
        <img src="/static/logo.png" alt="Anashwar Technologies Logo">
      </div>
      <div class="brand-title">
        <span class="brand-name">Anashwar</span>
        <span class="brand-subtitle">Edge Fleet OS</span>
      </div>
    </div>

    <div class="nav-section">
      <div class="nav-section-title">Ops</div>
      <div class="nav-item active" id="nav-dashboard" onclick="navigateTo('dashboard')">
        <span class="nav-icon"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="7" height="9" rx="1.5"/><rect x="14" y="3" width="7" height="5" rx="1.5"/><rect x="14" y="12" width="7" height="9" rx="1.5"/><rect x="3" y="16" width="7" height="5" rx="1.5"/></svg></span>
        <span>Live Fleet</span>
      </div>
      <div class="nav-item" id="nav-history" onclick="navigateTo('history-clients')" style="justify-content: space-between;">
        <span style="display:flex; align-items:center; gap:8px;">
          <span class="nav-icon"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><polyline points="12 7 12 12 15.5 14"/></svg></span>
          <span>History</span>
        </span>
        <span class="status-pill pill-cyan" id="sidebar-history-count" style="font-size: 9px; padding: 1px 5px;">0</span>
      </div>
      <div class="nav-item" id="nav-registry" onclick="navigateTo('registry')">
        <span class="nav-icon"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/></svg></span>
        <span>Registry</span>
      </div>
    </div>

    <div class="nav-section">
      <div class="nav-section-title" style="display: flex; justify-content: space-between; align-items: center;">
        <span>Nodes</span>
        <span class="status-pill pill-cyan" id="sidebar-node-count" style="font-size: 9px; padding: 1px 5px;">0 On</span>
      </div>
      <div id="sidebar-nodes-list" style="display: flex; flex-direction: column; gap: 2px; max-height: 220px; overflow-y: auto;">
        <!-- Populated live by fetchTelemetry() -->
      </div>
    </div>

    <div class="nav-section">
      <div class="nav-section-title">Admin</div>
      <div class="nav-item" onclick="openUserModal()">
        <span class="nav-icon"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg></span>
        <span>Users</span>
      </div>
      <div class="nav-item" onclick="toggleTheme()">
        <span class="nav-icon"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="4"/><path d="M12 2v2"/><path d="M12 20v2"/><path d="m4.93 4.93 1.41 1.41"/><path d="m17.66 17.66 1.41 1.41"/><path d="M2 12h2"/><path d="M20 12h2"/><path d="m6.34 17.66-1.41 1.41"/><path d="m19.07 4.93-1.41 1.41"/></svg></span>
        <span>Theme</span>
      </div>
    </div>

    <div class="sidebar-footer">
      <div class="status-badge-row">
        <span>MQTT</span>
        <span class="status-pill pill-green"><span class="pulsing-dot"></span> Live</span>
      </div>
      <div class="status-badge-row">
        <span style="font-family:var(--font-mono); font-size:10px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">broker.hivemq.com</span>
        <span class="status-pill pill-cyan">1883</span>
      </div>
      <div style="font-size: 9px; color: var(--text-dim); text-align: center; margin-top: 6px;">
        Anashwar Fleet OS v4.2
      </div>
    </div>
  </aside>

  <!-- Main Content Wrapper -->
  <div class="main-wrapper">
    
    <!-- Topbar -->
    <header class="topbar">
      <div class="breadcrumb-row" id="breadcrumb-container">
        <span class="breadcrumb-active">Live Fleet</span>
      </div>

      <div class="topbar-actions">
        <div class="search-box">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="color:var(--text-muted); flex-shrink:0;"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
          <input type="text" id="global-search-input" placeholder="Search clients, projects, nodes, MAC..." oninput="onGlobalSearch(this.value)">
          <span class="kbd-shortcut">Ctrl+K</span>
        </div>
        <button class="theme-toggle-btn" id="theme-toggle-btn" onclick="toggleTheme()" title="Switch Light / Dark Theme">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3a6 6 0 0 0 9 9 9 9 0 1 1-9-9Z"/></svg>
          <span>Dark</span>
        </button>
        <div style="display:flex; align-items:center; gap:8px; border-left:1px solid var(--card-border); padding-left:10px; margin-left:2px;">
          <div class="user-pill-btn" onclick="openUserModal()" title="Current Logged In User">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
            <span id="topbar-user-name" style="font-weight:700; font-size:12px;">__CURRENT_USER__</span>
          </div>
          <button class="btn-secondary" style="padding:5px 10px; font-size:11px;" onclick="openUserModal()" title="Manage Users">
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/></svg>
            <span>Users</span>
          </button>
          <button class="btn-secondary" style="padding:5px 10px; font-size:11px; border-color:rgba(239,68,68,0.4); color:#F87171;" onclick="handleLogout()" title="Sign Out">
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>
            <span>Logout</span>
          </button>
        </div>
      </div>
    </header>

    <!-- Dynamic Content Area -->
    <main class="content-area">

      <!-- VIEW 1: DASHBOARD OVERVIEW (ACTIVE LIVE FLEET) -->
      <div id="view-dashboard" class="view-animate-in">
        <!-- 3 Focused Telemetry & Broker Cards -->
        <div class="kpi-grid">
          <div class="kpi-card gradient-crimson">
            <div class="kpi-title">Active Live Nodes</div>
            <div class="kpi-value" id="kpi-active-nodes">0 Online</div>
            <div class="kpi-subtitle" id="kpi-active-sub">0 Active Clients &bull; 0 Live Projects</div>
          </div>
          <div class="kpi-card gradient-orange">
            <div class="kpi-title">Security Trust Index</div>
            <div class="kpi-value">100% Verified</div>
            <div class="kpi-subtitle">SHA-256 + MAC + eFuse Verified</div>
          </div>
          <div class="kpi-card gradient-cyan">
            <div class="kpi-title">MQTT Broker Credentials</div>
            <div class="kpi-value" style="font-size: 20px; font-family: var(--font-mono); letter-spacing: -0.3px;">broker.hivemq.com</div>
            <div class="kpi-subtitle">Port: 1883 &bull; Topics: anashwar/poc/*</div>
          </div>
        </div>

        <!-- Active Live Clients, Projects & Online Nodes (Upfront In-Your-Face View) -->
        <div class="section-header-row">
          <div>
            <div class="section-heading">Active Live Clients, Projects & Online Nodes</div>
            <div class="section-desc">Only clients currently online are surfaced here for immediate control & Web UI access. Offline & past nodes are organized in Fleet History.</div>
          </div>
          <div style="display:flex; gap:10px; flex-wrap:wrap;">
            <button class="btn-secondary" onclick="navigateTo('history-clients')">View Fleet History &rarr;</button>
            <button class="btn-main btn-crimson" onclick="openAddClientModal()">+ Add New Client</button>
          </div>
        </div>

        <div class="client-grid" id="clients-container">
          <!-- Populated by JS -->
        </div>

        <!-- Registry & Operations Log Card -->
        <div class="section-header-row" style="margin-top: 24px;">
          <div>
            <div class="section-heading">Operations Event Stream</div>
            <div class="section-desc">Command dispatches, hardware acknowledgements, OTA deployments, and identity sync events</div>
          </div>
          <button class="btn-main btn-cyan" onclick="navigateTo('registry')">Open Full Registry Archive &rarr;</button>
        </div>
        <div class="log-box" id="activity-log-stream">
          <!-- Populated by JS -->
        </div>
      </div>

      <!-- VIEW: HISTORY PAGE 1 - CLIENTS -->
      <div id="view-history-clients" style="display: none;">
        <div class="glass-card" style="margin-bottom: 24px;">
          <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 14px;">
            <div>
              <button class="btn-secondary" style="margin-bottom: 10px;" onclick="navigateTo('dashboard')">&larr; Back to Live Fleet</button>
              <h2 style="font-size: 24px; font-weight: 800; color: var(--text-strong); display: flex; align-items: center; gap: 10px;">
                <span>Fleet History: Clients</span>
                <span class="status-pill pill-cyan">Deduplicated</span>
              </h2>
              <p style="color: var(--text-muted); font-size: 13px; margin-top: 4px;">Every unique client ever seen online. Select a client to browse its historical projects on a separate page.</p>
            </div>
          </div>
        </div>
        <div class="client-grid" id="history-clients-container">
          <!-- Populated by JS -->
        </div>
      </div>

      <!-- VIEW: HISTORY PAGE 2 - PROJECTS FOR CLIENT -->
      <div id="view-history-projects" style="display: none;">
        <div class="glass-card" style="margin-bottom: 24px;">
          <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 14px;">
            <div>
              <button class="btn-secondary" style="margin-bottom: 10px;" onclick="navigateTo('history-clients')">&larr; Back to History Clients</button>
              <h2 id="history-client-title" style="font-size: 24px; font-weight: 800; color: var(--text-strong);">Historical Client Projects</h2>
              <p id="history-client-meta" style="color: var(--text-muted); font-size: 13px; margin-top: 4px;">Unique projects seen online under this client. Select a project to view its hardware nodes.</p>
            </div>
          </div>
        </div>
        <div class="projects-grid" id="history-projects-container">
          <!-- Populated by JS -->
        </div>
      </div>

      <!-- VIEW: HISTORY PAGE 3 - NODES FOR PROJECT -->
      <div id="view-history-nodes" style="display: none;">
        <div class="glass-card" style="margin-bottom: 24px;">
          <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 14px;">
            <div>
              <button class="btn-secondary" style="margin-bottom: 10px;" onclick="navigateTo('history-projects', selectedHistoryClientKey)">&larr; Back to Client Projects</button>
              <h2 id="history-project-title" style="font-size: 24px; font-weight: 800; color: var(--text-strong);">Historical Project Nodes</h2>
              <p id="history-project-meta" style="color: var(--text-muted); font-size: 13px; margin-top: 4px;">Unique hardware nodes seen online under this project.</p>
            </div>
          </div>
        </div>
        <div class="nodes-grid" id="history-nodes-container">
          <!-- Populated by JS -->
        </div>
      </div>

      <!-- VIEW: OPERATIONS REGISTRY (DAILY FILES & CALENDAR) -->
      <div id="view-registry" style="display: none;">
        <div class="glass-card" style="margin-bottom: 24px;">
          <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 14px;">
            <div>
              <button class="btn-secondary" style="margin-bottom: 10px;" onclick="navigateTo('dashboard')">&larr; Back to Live Fleet</button>
              <h2 style="font-size: 24px; font-weight: 800; color: var(--text-strong); display: flex; align-items: center; gap: 10px;">
                <span>Enterprise Operations Registry</span>
                <span class="status-pill pill-cyan">Daily Event Partitions</span>
              </h2>
              <p style="color: var(--text-muted); font-size: 13px; margin-top: 4px;">Partitioned daily log files for audit compliance, hardware events, and command trails.</p>
            </div>
            <div style="display: flex; gap: 8px;">
              <button class="btn-secondary" onclick="loadRegistryCalendar()">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/></svg>
                <span>Refresh Registry</span>
              </button>
            </div>
          </div>
        </div>

        <!-- Registry Filters: Yearly, Monthly, Weekly -->
        <div class="glass-card" style="margin-bottom: 24px;">
          <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 12px; flex-wrap: wrap;">
            <span style="font-size: 12px; font-weight: 700; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.5px; width: 60px;">Year:</span>
            <div class="preset-pills" id="registry-year-pills" style="margin: 0;">
              <!-- Populated by JS -->
            </div>
          </div>

          <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 12px; flex-wrap: wrap;">
            <span style="font-size: 12px; font-weight: 700; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.5px; width: 60px;">Month:</span>
            <div class="preset-pills" id="registry-month-pills" style="margin: 0; flex-wrap: wrap;">
              <!-- Populated by JS -->
            </div>
          </div>

          <div style="display: flex; align-items: center; gap: 12px; flex-wrap: wrap;">
            <span style="font-size: 12px; font-weight: 700; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.5px; width: 60px;">Week:</span>
            <div class="preset-pills" id="registry-week-pills" style="margin: 0;">
              <span class="preset-pill active" onclick="filterRegistryWeek('all')">All Weeks</span>
              <span class="preset-pill" onclick="filterRegistryWeek(44)">Week 44</span>
              <span class="preset-pill" onclick="filterRegistryWeek(45)">Week 45 (Current)</span>
            </div>
          </div>
        </div>

        <!-- Daily File Buttons Grid -->
        <div class="section-header-row">
          <div>
            <div class="section-heading">Daily Event Log Files</div>
            <div class="section-desc">Select any active daily file to inspect its audit trail. Inactive days are dimmed.</div>
          </div>
        </div>

        <div class="client-grid" id="registry-days-container">
          <!-- Populated by JS -->
        </div>
      </div>

      <!-- VIEW: DAILY REGISTRY INSPECTOR -->
      <div id="view-registry-day" style="display: none;">
        <div class="glass-card" style="margin-bottom: 24px;">
          <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 14px;">
            <div>
              <button class="btn-secondary" style="margin-bottom: 10px;" onclick="navigateTo('registry')">&larr; Back to Registry Calendar</button>
              <h2 id="reg-day-title" style="font-size: 24px; font-weight: 800; color: var(--text-strong);">Registry File: 2026-11-10.log</h2>
              <div style="display: flex; gap: 8px; align-items: center; margin-top: 6px;">
                <span id="reg-day-count-badge" class="status-pill pill-green">0 Events Recorded</span>
                <span class="status-pill pill-cyan">SHA-256 Hashed Log</span>
              </div>
            </div>
            <div style="display: flex; gap: 10px;">
              <button class="btn-main btn-crimson" id="btn-download-log" onclick="downloadCurrentDayLog()">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
                <span>Download .log File</span>
              </button>
              <button class="btn-secondary" onclick="refreshCurrentDayLog()">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/></svg>
                <span>Refresh Log</span>
              </button>
            </div>
          </div>
        </div>

        <!-- Search and Filter Bar -->
        <div class="glass-card" style="margin-bottom: 18px; padding: 14px 20px;">
          <div style="display: flex; gap: 12px; align-items: center; flex-wrap: wrap;">
            <div class="search-box" style="flex: 1; min-width: 260px;">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="color:var(--text-muted); flex-shrink:0;"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
              <input type="text" id="reg-search-input" placeholder="Search events by Node, IP, Command, MAC, or keyword..." oninput="onRegistrySearchInput(this.value)">
            </div>
            <div class="preset-pills" id="reg-category-pills" style="margin: 0;">
              <span class="preset-pill active" onclick="filterRegistryCategory('ALL')">All Events</span>
              <span class="preset-pill" onclick="filterRegistryCategory('CMD')">Commands</span>
              <span class="preset-pill" onclick="filterRegistryCategory('ACK')">Hardware ACKs</span>
              <span class="preset-pill" onclick="filterRegistryCategory('SEC')">Security & Auth</span>
              <span class="preset-pill" onclick="filterRegistryCategory('OTA')">Firmware OTA</span>
            </div>
          </div>
        </div>

        <!-- Event List -->
        <div class="log-box" id="reg-events-container" style="max-height: 550px;">
          <!-- Populated by JS -->
        </div>
      </div>

      <!-- VIEW 2: CLIENT DETAIL VIEW -->
      <div id="view-client" style="display: none;">
        <div class="glass-card" style="margin-bottom: 24px;">
          <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 12px;">
            <div>
              <button class="btn-secondary" style="margin-bottom: 12px;" onclick="navigateTo('dashboard')">&larr; Back to Live Fleet</button>
              <h2 id="client-view-title" style="font-size: 24px; font-weight: 800; color: var(--text-strong);">Client</h2>
              <p id="client-view-desc" style="color: var(--text-muted); font-size: 13px; margin-top: 4px;">Enterprise Edge IoT Operations & Real-time Fleet</p>
            </div>
            <button class="btn-main btn-crimson" onclick="openAddProjectModal()">+ Add New Project</button>
          </div>
        </div>

        <div class="section-header-row">
          <div class="section-heading">Client Projects</div>
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
              <h2 id="project-view-title" style="font-size: 24px; font-weight: 800; color: var(--text-strong);">Project</h2>
              <p id="project-view-desc" style="color: var(--text-muted); font-size: 13px; margin-top: 4px;">Edge Hardware Control & OTA Architecture</p>
            </div>
          </div>
        </div>

        <div class="section-header-row">
          <div class="section-heading">Project Hardware Nodes</div>
          <button class="btn-main btn-crimson" onclick="openAddNodeModal()">+ Register Node to Project</button>
        </div>
        <div class="nodes-grid" id="project-nodes-container">
          <!-- Populated by JS -->
        </div>
      </div>

      <!-- VIEW 4: NODE DETAIL & CONTROL CENTER -->
      <div id="view-node-detail" style="display: none;">
        <div class="glass-card" style="margin-bottom: 24px;">
          <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 12px;">
            <div>
              <button class="btn-secondary" style="margin-bottom: 12px;" onclick="backToProject()">&larr; Back to Project</button>
              <div style="display: flex; align-items: center; gap: 12px; flex-wrap: wrap;">
                <h2 id="detail-node-name" style="font-size: 26px; font-weight: 800; color: var(--text-strong);">Node Console</h2>
                <span id="detail-node-status-pill" class="status-pill pill-green"><span class="pulsing-dot"></span> ONLINE</span>
                <span class="status-pill pill-cyan">SHA-256 VERIFIED</span>
                <button class="btn-main btn-cyan" style="font-size: 12px; padding: 6px 12px;" onclick="openInsituModal()">
                  <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>
                  <span>On-Board Web UI</span>
                </button>
                <button class="btn-main btn-crimson" style="font-size: 12px; padding: 6px 12px;" onclick="triggerNodeReboot(selectedNodeName)" title="Reboot MCU via MQTT">
                  <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/></svg>
                  <span>Reboot</span>
                </button>
                <button class="btn-secondary" style="font-size: 12px; padding: 6px 12px;" onclick="triggerNodePing(selectedNodeName)" title="Ping node for immediate ACK">
                  <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M5 12.55a11 11 0 0 1 14.08 0"/><path d="M1.42 9a16 16 0 0 1 21.16 0"/><path d="M8.53 16.11a6 6 0 0 1 6.95 0"/><line x1="12" y1="20" x2="12.01" y2="20"/></svg>
                  <span>Ping</span>
                </button>
                <button class="btn-secondary" style="font-size: 12px; padding: 6px 12px;" onclick="openRenameModal('node', selectedNodeName, selectedNodeName)">
                  <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 20h9"/><path d="M16.5 3.5a2.12 2.12 0 0 1 3 3L7 19l-4 1 1-4L16.5 3.5z"/></svg>
                  <span>Rename</span>
                </button>
                <button class="btn-secondary" style="border-color: rgba(239,68,68,0.4); color: #F87171; font-size: 12px; padding: 6px 12px;" onclick="deleteNode(selectedNodeName)">
                  <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/><path d="M10 11v6"/><path d="M14 11v6"/></svg>
                  <span>Delete Node</span>
                </button>
              </div>
            </div>
            <!-- Quick switcher for all nodes -->
            <div style="display: flex; gap: 8px; flex-wrap: wrap;" id="node-switcher-container">
              <!-- Dynamically populated with all registered nodes -->
            </div>
          </div>
        </div>

        <div class="node-detail-layout">
          <!-- Left Column: Controls & Visualizer -->
          <div>
            <!-- Side-by-Side Dual Feature Toggles (Master Service & Serve While Offline) -->
            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 14px; margin-bottom: 18px;">
              <!-- Master Service Toggle Box -->
              <div class="service-switch-box" style="margin: 0;">
                <div class="service-info">
                  <h4>Master Service Switch</h4>
                  <p>ACTIVE: Operation driven. STANDBY: Hardware suspended.</p>
                </div>
                <label class="apple-switch">
                  <input type="checkbox" id="detail-service-toggle" onchange="toggleMasterService()">
                  <span class="slider"></span>
                </label>
              </div>

              <!-- Serve While Offline Toggle Box -->
              <div class="service-switch-box" style="margin: 0;">
                <div class="service-info">
                  <h4>Serve While Offline</h4>
                  <p>ON: Serves in-situ job even when network drops. OFF: Suspends if offline.</p>
                </div>
                <label class="apple-switch">
                  <input type="checkbox" id="detail-offline-toggle" onchange="toggleOfflineMode()">
                  <span class="slider"></span>
                </label>
              </div>
            </div>

            <!-- Universal Custom Command & Directive Console -->
            <div class="glass-card" style="margin-bottom: 18px;">
              <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                <div class="panel-title" style="margin: 0;">Project Action & Directive Console</div>
                <span class="status-pill pill-cyan">Real-Time MQTT</span>
              </div>
              <p style="font-size: 12px; color: var(--text-muted); margin-bottom: 12px;">Dispatch custom action directives to this node (e.g. RELAY:ON, MOTOR:HOME, SPEED:80, or your project's custom commands):</p>
              
              <div style="display: flex; gap: 8px; margin-bottom: 10px;">
                <input type="text" id="custom-directive-input" class="form-input" style="flex: 1;" placeholder="Enter directive, e.g. SERVICE:ON or RELAY:1" onkeydown="if(event.key==='Enter') sendCustomDirective(selectedNodeName)">
                <button class="btn-main btn-crimson" style="padding: 0 16px; font-size: 13px; font-weight: 700;" onclick="sendCustomDirective(selectedNodeName)">Dispatch &rarr;</button>
              </div>

              <div style="display: flex; gap: 6px; flex-wrap: wrap;">
                <span style="font-size: 11px; color: var(--text-dim); align-self: center; margin-right: 4px;">Quick Actions:</span>
                <span class="preset-pill" onclick="sendQuickDirective(selectedNodeName, 'PING')">PING</span>
                <span class="preset-pill" onclick="sendQuickDirective(selectedNodeName, 'SERVICE:ON')">Service ON</span>
                <span class="preset-pill" onclick="sendQuickDirective(selectedNodeName, 'SERVICE:OFF')">Service OFF</span>
                <span class="preset-pill" onclick="sendQuickDirective(selectedNodeName, 'REBOOT')">REBOOT</span>
              </div>
            </div>

            <!-- Output Delay Configurator (Legacy POC Only, Hidden by Default) -->
            <div class="delay-box" id="delay-box-container" style="display: none;">
              <div class="delay-header">
                <div>
                  <h4 style="font-size: 15px; font-weight: 700; color: var(--text-strong);">Configurable Output Propagation Delay</h4>
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

            <!-- Live Hardware Visualizer (Legacy POC Only, Hidden by Default) -->
            <div class="hw-visualizer" id="poc-visualizer-container" style="display: none;">
              <div style="display: flex; justify-content: space-between; align-items: center;">
                <div class="panel-title" style="margin: 0;">Legacy Hardware State Mirror</div>
                <span style="font-size: 10px; color: var(--text-dim);">Optional Telemetry</span>
              </div>
              <p style="font-size: 12px; color: var(--text-muted); margin: 6px 0 12px 0;">Optional status mirror if firmware publishes pin telemetry.</p>
              
              <div class="hw-display-row">
                <div class="hw-unit">
                  <div style="font-size: 11px; font-weight: 700; color: var(--text-dim); text-transform: uppercase;">Output State</div>
                  <div class="led-orb" id="visualizer-led"></div>
                  <div style="font-size: 13px; font-weight: 700;" id="visualizer-led-text">OFF</div>
                </div>

                <div class="hw-unit">
                  <div style="font-size: 11px; font-weight: 700; color: var(--text-dim); text-transform: uppercase;">Input State</div>
                  <div class="boot-btn-sim" id="visualizer-btn">INPUT</div>
                  <div style="font-size: 13px; font-weight: 700;" id="visualizer-btn-text">RELEASED</div>
                </div>
              </div>
            </div>

            <!-- In-Situ Embedded Server Card -->
            <div class="glass-card" style="margin-top: 24px;">
              <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                <div class="panel-title" style="margin: 0;">On-Board Web Server (In-Situ)</div>
                <span id="insitu-status-pill" class="status-pill pill-green"><span class="pulsing-dot"></span> Port 80 Live</span>
              </div>
              <p style="font-size: 12px; color: var(--text-muted); margin-bottom: 14px;">This hardware node hosts an onboard web application. Access its full multi-page touch/desktop UI globally via the secure portal proxy:</p>
              <div style="display: flex; gap: 10px; flex-wrap: wrap;">
                <button class="btn-main btn-cyan" onclick="openInsituModal()" style="flex: 1; min-width: 170px; font-size: 13px;">
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>
                  <span>Launch Global Web UI Viewer</span>
                </button>
                <a id="detail-insitu-link" href="#" target="_blank" class="btn-secondary" style="flex: 1; min-width: 150px; text-decoration: none; text-align: center; font-size: 13px;">
                  <span>Direct LAN (<span id="detail-insitu-ip">0.0.0.0</span>) &rarr;</span>
                </a>
              </div>
            </div>
          </div>

          <!-- Right Column: Hardware Profile & Firmware Pipeline -->
          <div>
            <!-- Microcontroller Hardware Profile & Wireless Capabilities -->
            <div class="glass-card" style="margin-bottom: 24px;">
              <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 14px;">
                <div class="panel-title" style="margin: 0;">Microcontroller Hardware Profile</div>
                <span id="spec-mcu-family-pill" class="status-pill pill-cyan" style="font-size: 11px;">ESP32-WROOM-32</span>
              </div>
              <div id="detail-esp32-photo-wrap" style="display: none; align-items: center; gap: 14px; padding: 12px; margin-bottom: 14px; border-radius: 14px; background: var(--surface-2); border: 1px solid var(--card-border);">
                <div class="esp32-hero-frame">
                  <img src="/static/esp32_wroom32.jpg" alt="ESP32-WROOM-32 Module">
                </div>
                <div>
                  <div style="font-size: 14px; font-weight: 800; color: var(--text-strong);">ESP32-WROOM-32 Hardware Node</div>
                  <div style="font-size: 12px; color: var(--text-muted); margin-top: 2px;">Dual-Core Wi-Fi / BLE SoC Module &bull; NVS Identity Sync</div>
                </div>
              </div>
              <div class="node-spec-row"><span class="node-spec-lbl">MCU Architecture</span><span class="node-spec-val" id="spec-mcu-arch" style="color:#8B5CF6;">Tensilica Xtensa Dual-Core 240MHz</span></div>
              <div class="node-spec-row"><span class="node-spec-lbl">Flash Memory</span><span class="node-spec-val" id="spec-mcu-flash" style="color:#0EA5E9;">4 MB SPI Flash</span></div>
              <div class="node-spec-row"><span class="node-spec-lbl">Total SRAM</span><span class="node-spec-val" id="spec-mcu-ram" style="color:#10B981;">320 KB Total SRAM</span></div>
              <div class="node-spec-row" style="border:none;"><span class="node-spec-lbl">Onboard Antenna Band</span><span class="node-spec-val" id="spec-mcu-antenna" style="color:#D97706;">2.4 GHz 802.11 b/g/n + BLE 4.2</span></div>
            </div>

            <!-- Hardware Specifications Card -->
            <div class="glass-card" style="margin-bottom: 24px;">
              <div class="panel-title">Node Telemetry & Markers</div>
              <div class="node-spec-row"><span class="node-spec-lbl">Hardware MAC</span><span class="node-spec-val" id="spec-mac">-</span></div>
              <div class="node-spec-row"><span class="node-spec-lbl">eFuse Chip ID</span><span class="node-spec-val" id="spec-chip">-</span></div>
              <div class="node-spec-row"><span class="node-spec-lbl">STA Local IP</span><span class="node-spec-val" id="spec-ip" style="color:#0EA5E9;">-</span></div>
              <div class="node-spec-row"><span class="node-spec-lbl">USB Port (Backdoor)</span><span class="node-spec-val" id="spec-port">-</span></div>
              <div class="node-spec-row"><span class="node-spec-lbl">Wi-Fi Signal (RSSI)</span><span class="node-spec-val" id="spec-rssi">-</span></div>
              <div class="node-spec-row"><span class="node-spec-lbl">Free Heap RAM</span><span class="node-spec-val" id="spec-heap">-</span></div>
              <div class="node-spec-row"><span class="node-spec-lbl">Geographic Location</span><span class="node-spec-val" id="spec-geo" style="color:#0EA5E9;">Pune, Maharashtra, India</span></div>
              <div class="node-spec-row"><span class="node-spec-lbl">Public WAN IP & Carrier</span><span class="node-spec-val" id="spec-public-ip">-</span></div>
              <div class="node-spec-row" style="border:none;"><span class="node-spec-lbl">SHA-256 Fingerprint</span><span class="node-spec-val" id="spec-hash" style="color:#10B981; font-size:11px; word-break:break-all;">-</span></div>
            </div>

            <!-- Firmware Deployment Hub -->
            <div class="glass-card">
              <div class="panel-title">Firmware Deployment Pipeline</div>
              <p style="font-size: 12px; color: var(--text-muted); margin-bottom: 14px;">Select the golden reference build or drag &amp; drop a custom verified .bin:</p>

              <!-- Golden Base Firmware Reference Build -->
              <div class="base-firmware-card active" id="card-base-firmware" onclick="selectBaseFirmware()">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                  <div style="font-size: 14px; font-weight: 700; color: var(--text-strong); display: flex; align-items: center; gap: 8px;">
                    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="#F59E0B" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/></svg>
                    <span>Base_firmware.bin</span>
                    <span class="status-pill pill-green" style="font-size: 10px; padding: 2px 8px;">GOLDEN REFERENCE</span>
                  </div>
                  <span class="status-pill pill-cyan" style="font-size: 10px; padding: 2px 8px;">1059.5 KB</span>
                </div>
                <div style="font-size: 12px; color: var(--text-muted); line-height: 1.5;">
                  Standard reference image for multi-MCU fleet integration (ESP32, ESP8266, BW16, Arduino Uno R4). Includes OTA fit checks, HiveMQ broker telemetry, NVS identity sync, and onboard reverse proxy relay.
                </div>
              </div>

              <!-- Custom .bin Upload Zone -->
              <div class="dropzone" id="bin-dropzone" onclick="document.getElementById('bin-file-input').click()">
                <div class="dropzone-icon">
                  <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="var(--crimson)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>
                </div>
                <div style="font-size: 13px; font-weight: 700; color: var(--text-strong);" id="dropzone-label">Drop custom .bin file here or click to browse</div>
                <div style="font-size: 11px; color: var(--text-muted); margin-top: 4px;">Pre-flash verification of OTA partition, endpoints, &amp; markers</div>
                <input type="file" id="bin-file-input" style="display:none;" accept=".bin" onchange="handleFileSelect(this.files)">
              </div>

              <!-- Firmware Pre-Flash Deep Inspection Report Card -->
              <div id="bin-inspect-card" style="display: none; background: var(--surface-2); border: 1px solid var(--card-border); border-radius: 12px; padding: 14px; margin-top: 14px;">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                  <span style="font-size: 12px; font-weight: 700; color: var(--text-strong);">Binary Pre-Flash Inspection</span>
                  <span id="inspect-compliance-pill" class="status-pill pill-green">100% Compliant</span>
                </div>
                <div style="font-size: 11px; color: var(--text-muted); line-height: 1.6;" id="inspect-details">
                  <!-- Populated by JS -->
                </div>
              </div>

              <!-- Deployment Actions -->
              <div class="btn-action-row">
                <button class="btn-main btn-crimson" onclick="triggerDeployment('cloud')">
                  <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4.5 16.5c-1.5 1.26-2 5-2 5s3.74-.5 5-2c.71-.84.7-2.13-.09-2.91a2.18 2.18 0 0 0-2.91-.09z"/><path d="m12 15-3-3a22 22 0 0 1 2-3.95A12.88 12.88 0 0 1 22 2c0 2.72-.78 7.5-6 11a22.35 22.35 0 0 1-4 2z"/></svg>
                  <span>Wireless OTA Update</span>
                </button>
                <button class="btn-main btn-usb" onclick="triggerDeployment('usb')">
                  <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22v-5"/><path d="M9 8V2"/><path d="M15 8V2"/><path d="M18 8v5a4 4 0 0 1-4 4h-4a4 4 0 0 1-4-4V8Z"/></svg>
                  <span>USB Direct Flash</span>
                </button>
              </div>

              <!-- Refined Progress Tracker -->
              <div class="update-tracker" id="detail-tracker">
                <div style="display: flex; justify-content: space-between; font-size: 13px; font-weight: 700;">
                  <span id="tracker-stage-title">Deployment in Progress</span>
                  <span id="tracker-pct" style="color:#0EA5E9;">0%</span>
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
    <div class="modal-card" style="max-width: 580px;">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
        <h3 style="margin: 0;">Enterprise User Accounts & Device Telemetry</h3>
        <button class="btn-secondary" style="padding: 4px 10px; font-size: 11px;" onclick="closeModal('modal-users')">&times; Close</button>
      </div>
      <p>Manage authenticated administrators, operators, and review connected device sessions.</p>
      
      <div style="margin-bottom: 20px;">
        <div style="font-size: 12px; font-weight: 700; color: var(--text-muted); margin-bottom: 8px;">Existing Accounts</div>
        <div id="users-list-container" style="max-height: 180px; overflow-y: auto;">
          <!-- Populated by JS -->
        </div>
      </div>

      <!-- Active Sessions & Connected Device Telemetry -->
      <div style="margin-bottom: 20px; border-top: 1px solid var(--card-border); padding-top: 16px;">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
          <div style="font-size: 12px; font-weight: 700; color: var(--text-muted);">Connected Devices & Active Login Sessions</div>
          <span class="status-pill pill-cyan" id="sessions-count-pill" style="font-size: 10px;">1 Active</span>
        </div>
        <div style="font-size: 11px; color: var(--text-dim); margin-bottom: 10px;">Hardware, OS, device model, form factor, IP, and location captured per login:</div>
        <div id="sessions-list-container" style="max-height: 200px; overflow-y: auto; display: flex; flex-direction: column; gap: 8px;">
          <!-- Populated by JS -->
        </div>
      </div>

      <div style="border-top: 1px solid var(--card-border); padding-top: 16px;">
        <div style="font-size: 12px; font-weight: 700; color: var(--text-muted); margin-bottom: 10px;">Register New User Account</div>
        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 10px; margin-bottom: 10px;">
          <div>
            <label style="font-size: 11px; color: var(--text-dim); display: block; margin-bottom: 4px;">Username</label>
            <input type="text" class="form-input" id="new-user-username" placeholder="e.g. Vedang" autocomplete="off">
          </div>
          <div>
            <label style="font-size: 11px; color: var(--text-dim); display: block; margin-bottom: 4px;">Role</label>
            <select class="form-input" id="new-user-role">
              <option value="Super Admin">Super Admin</option>
              <option value="Fleet Operator" selected>Fleet Operator</option>
              <option value="User">User</option>
            </select>
          </div>
        </div>
        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 10px; margin-bottom: 12px;">
          <div>
            <label style="font-size: 11px; color: var(--text-dim); display: block; margin-bottom: 4px;">Password</label>
            <input type="password" class="form-input" id="new-user-password" placeholder="Enter password" autocomplete="new-password">
          </div>
          <div>
            <label style="font-size: 11px; color: var(--text-dim); display: block; margin-bottom: 4px;">Re-type Password</label>
            <input type="password" class="form-input" id="new-user-confirm-password" placeholder="Confirm password" autocomplete="new-password">
          </div>
        </div>
        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 10px;">
          <button id="btn-add-user" class="btn-main btn-crimson" onclick="submitNewUser(false)" style="padding: 10px 14px; font-size: 12px;">
            Save User Account
          </button>
          <button id="btn-add-user-bio" class="btn-main btn-cyan" onclick="submitNewUser(true)" style="padding: 10px 14px; font-size: 12px;">
            Save &amp; Enroll Biometrics
          </button>
        </div>
      </div>

      <div style="border-top: 1px solid var(--card-border); padding-top: 16px; margin-top: 16px;">
        <div style="font-size: 12px; font-weight: 700; color: var(--text-muted); margin-bottom: 6px;">Device Native Biometrics (Fingerprint / Face ID)</div>
        <div style="font-size: 11px; color: var(--text-dim); margin-bottom: 12px;">Enroll this device's biometric scanner (Fingerprint or Face ID) for your current account to enable fast, passwordless Biometric Login:</div>
        <button id="btn-enroll-curr-device" class="btn-secondary" style="width: 100%; font-size: 12px; padding: 10px; border-color: rgba(56, 189, 248, 0.4); color: #0EA5E9;" onclick="enrollCurrentDeviceBiometrics()">
          Enroll This Device for Currently Logged-in Account
        </button>
      </div>
    </div>
  </div>

  <!-- Modal: Rename Entity (Client, Project, Node) -->
  <div class="modal-overlay" id="modal-rename">
    <div class="modal-card">
      <h3 id="rename-modal-title">Rename Node</h3>
      <p id="rename-modal-desc">Enter the updated name. This change will be synchronized to the ESP32 hardware via NVS memory.</p>
      <input type="hidden" id="rename-target-type">
      <input type="hidden" id="rename-target-id">
      <div class="form-group">
        <label id="rename-input-label">New Name</label>
        <input type="text" class="form-input" id="rename-new-name" placeholder="Enter updated name">
      </div>
      <div class="modal-actions">
        <button class="btn-secondary" onclick="closeModal('modal-rename')">Cancel</button>
        <button class="btn-main btn-crimson" onclick="submitRename()">Save &amp; Synchronize</button>
      </div>
    </div>
  </div>

  <!-- Modal: In-Situ Web UI Viewer -->
  <div class="modal-overlay" id="modal-insitu-webui">
    <div class="modal-card" style="max-width: 1120px; width: 96vw; padding: 14px 16px;">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; border-bottom: 1px solid var(--card-border); padding-bottom: 10px; flex-wrap: wrap; gap: 8px;">
        <div>
          <h3 style="margin: 0; font-size: 16px;" id="insitu-modal-title">In-Situ On-Board Web UI</h3>
          <div style="font-size: 11px; color: #10B981; margin-top: 2px;">Connected via Anashwar Global Hardware Proxy</div>
        </div>
        <div style="display: flex; gap: 6px; flex-wrap: wrap;">
          <button class="btn-secondary" style="padding: 6px 10px; font-size: 12px;" onclick="refreshInsituIframe()">
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/></svg>
            <span>Reload</span>
          </button>
          <a id="insitu-modal-fulltab-link" href="#" target="_blank" class="btn-secondary" style="padding: 6px 10px; font-size: 12px; text-decoration: none; border-color: rgba(16,185,129,0.4); color: #10B981;">Open Full Tab &rarr;</a>
          <a id="insitu-modal-direct-link" href="#" target="_blank" class="btn-secondary" style="padding: 6px 10px; font-size: 12px; text-decoration: none;">Direct LAN &rarr;</a>
          <button class="btn-secondary" style="padding: 6px 10px; font-size: 12px;" onclick="closeModal('modal-insitu-webui')">&times; Close</button>
        </div>
      </div>
      <div style="width: 100%; height: 72vh; min-height: 520px; border-radius: 12px; overflow: hidden; background: var(--log-bg); border: 1px solid var(--card-border);">
        <iframe id="insitu-iframe" style="width: 100%; height: 100%; border: none;" src="about:blank"></iframe>
      </div>
    </div>
  </div>

  <!-- Mobile Bottom Navigation Bar (Touch Screen Phone Form) -->
  <nav class="mobile-bottom-nav" id="mobile-bottom-nav">
    <button class="bottom-nav-item active" id="bnav-dashboard" onclick="navigateTo('dashboard')">
      <span class="bnav-icon"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="7" height="9" rx="1.5"/><rect x="14" y="3" width="7" height="5" rx="1.5"/><rect x="14" y="12" width="7" height="9" rx="1.5"/><rect x="3" y="16" width="7" height="5" rx="1.5"/></svg></span>
      <span class="bnav-label">Live Fleet</span>
    </button>
    <button class="bottom-nav-item" id="bnav-history" onclick="navigateTo('history-clients')">
      <span class="bnav-icon"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><polyline points="12 7 12 12 15.5 14"/></svg></span>
      <span class="bnav-label">History</span>
    </button>
    <button class="bottom-nav-item" id="bnav-node-detail" onclick="openCurrentNodeDetail()">
      <span class="bnav-icon"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="4" width="16" height="16" rx="2"/><rect x="9" y="9" width="6" height="6"/><line x1="9" y1="1" x2="9" y2="4"/><line x1="15" y1="1" x2="15" y2="4"/><line x1="9" y1="20" x2="9" y2="23"/><line x1="15" y1="20" x2="15" y2="23"/></svg></span>
      <span class="bnav-label">Node</span>
    </button>
    <button class="bottom-nav-item" id="bnav-registry" onclick="navigateTo('registry')">
      <span class="bnav-icon"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg></span>
      <span class="bnav-label">Registry</span>
    </button>
  </nav>

  <script>
    // State
    const DEFAULT_FLEET = { clients: {}, projects: {}, registered_nodes: {}, history: { clients: {}, projects: {}, nodes: {} } };
    let currentView = "dashboard";
    let selectedClientId = "";
    let selectedProjectId = "";
    let selectedNodeName = "";
    let selectedHistoryClientKey = "";
    let selectedHistoryProjectKey = "";
    let selectedFirmwareFile = "Base_firmware.bin";
    let globalSearchQuery = "";

    let fleetData = DEFAULT_FLEET;
    let telemetryData = {};

    let currentRegYear = 2026;
    let currentRegMonth = 11;
    let currentRegWeek = "all";
    let currentLoadedDate = "";
    let currentDayEvents = [];
    let currentCategoryFilter = "ALL";

    const ICONS = {
      edit: '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 20h9"/><path d="M16.5 3.5a2.12 2.12 0 0 1 3 3L7 19l-4 1 1-4L16.5 3.5z"/></svg>',
      trash: '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/><path d="M10 11v6"/><path d="M14 11v6"/></svg>',
      globe: '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>',
      sliders: '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="4" y1="21" x2="4" y2="14"/><line x1="4" y1="10" x2="4" y2="3"/><line x1="12" y1="21" x2="12" y2="12"/><line x1="12" y1="8" x2="12" y2="3"/><line x1="20" y1="21" x2="20" y2="16"/><line x1="20" y1="12" x2="20" y2="3"/><line x1="1" y1="14" x2="7" y2="14"/><line x1="9" y1="8" x2="15" y2="8"/><line x1="17" y1="16" x2="23" y2="16"/></svg>',
      ping: '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M5 12.55a11 11 0 0 1 14.08 0"/><path d="M1.42 9a16 16 0 0 1 21.16 0"/><path d="M8.53 16.11a6 6 0 0 1 6.95 0"/><line x1="12" y1="20" x2="12.01" y2="20"/></svg>',
      reboot: '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/></svg>',
      chip: '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="5" y="5" width="14" height="14" rx="2"/><rect x="9" y="9" width="6" height="6"/><line x1="9" y1="2" x2="9" y2="5"/><line x1="15" y1="2" x2="15" y2="5"/><line x1="9" y1="19" x2="9" y2="22"/><line x1="15" y1="19" x2="15" y2="22"/><line x1="2" y1="9" x2="5" y2="9"/><line x1="2" y1="15" x2="5" y2="15"/><line x1="19" y1="9" x2="22" y2="9"/><line x1="19" y1="15" x2="22" y2="15"/></svg>',
      phone: '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="5" y="2" width="14" height="20" rx="2" ry="2"/><line x1="12" y1="18" x2="12.01" y2="18"/></svg>',
      desktop: '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="3" width="20" height="14" rx="2" ry="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg>',
      sun: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="4"/><path d="M12 2v2"/><path d="M12 20v2"/><path d="m4.93 4.93 1.41 1.41"/><path d="m17.66 17.66 1.41 1.41"/><path d="M2 12h2"/><path d="M20 12h2"/><path d="m6.34 17.66-1.41 1.41"/><path d="m19.07 4.93-1.41 1.41"/></svg>',
      moon: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3a6 6 0 0 0 9 9 9 9 0 1 1-9-9Z"/></svg>'
    };

    function escHtml(val) {
      return String(val == null ? "" : val)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#39;");
    }

    function escJs(val) {
      const bs = String.fromCharCode(92);
      const raw = String(val == null ? "" : val)
        .split(bs).join(bs + bs)
        .split("'").join(bs + "'")
        .split(String.fromCharCode(10)).join(" ")
        .split(String.fromCharCode(13)).join("");
      return escHtml(raw);
    }

    function normKey(val) {
      return String(val == null ? "" : val).trim().toLowerCase()
        .split(String.fromCharCode(0x2018)).join("'")
        .split(String.fromCharCode(0x2019)).join("'")
        .split("`").join("'");
    }

    function isEsp32Node(node) {
      if (!node) return false;
      const meta = ((node.mcu || "") + " " + (node.mcu_family || "") + " " + (node.mcu_type || "") + " " + (node.mcu_arch || "")).toUpperCase();
      return meta.includes("ESP32") || meta.includes("WROOM") || meta.includes("XTENSA");
    }

    function updateThemeButton() {
      const btn = document.getElementById("theme-toggle-btn");
      if (!btn) return;
      const cur = document.documentElement.getAttribute("data-theme") || "dark";
      if (cur === "light") {
        btn.innerHTML = ICONS.moon + "<span>Dark</span>";
      } else {
        btn.innerHTML = ICONS.sun + "<span>Light</span>";
      }
    }

    function toggleTheme() {
      const cur = document.documentElement.getAttribute("data-theme") || "dark";
      const next = (cur === "dark") ? "light" : "dark";
      document.documentElement.setAttribute("data-theme", next);
      try { localStorage.setItem("anashwar_theme", next); } catch(e) {}
      updateThemeButton();
    }

    function onGlobalSearch(val) {
      globalSearchQuery = (val || "").toLowerCase().trim();
      if (currentView === "dashboard") renderClients();
      else if (currentView === "history-clients") renderHistoryClients();
      else if (currentView === "history-projects") renderHistoryProjects();
      else if (currentView === "history-nodes") renderHistoryNodes();
      else if (currentView === "client") renderClientProjects();
      else if (currentView === "project") renderProjectNodes();
    }

    document.addEventListener("keydown", function(e) {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        const inp = document.getElementById("global-search-input");
        if (inp) inp.focus();
      }
    });

    function showAnimatedView(viewElId) {
      const el = document.getElementById(viewElId);
      if (!el) return;
      el.classList.remove("view-animate-in");
      el.style.display = "block";
      void el.offsetWidth;
      el.classList.add("view-animate-in");
    }

    function navigateTo(view, param1, param2) {
      currentView = view;
      document.querySelectorAll("#view-dashboard, #view-history-clients, #view-history-projects, #view-history-nodes, #view-client, #view-project, #view-node-detail, #view-registry, #view-registry-day").forEach(el => {
        el.style.display = "none";
        el.classList.remove("view-animate-in");
      });
      document.querySelectorAll(".nav-item").forEach(el => el.classList.remove("active"));
      document.querySelectorAll(".bottom-nav-item").forEach(el => el.classList.remove("active"));

      if (view === "dashboard" || view === "clients" || view === "client" || view === "projects" || view === "project") {
        const b = document.getElementById("bnav-dashboard");
        if (b) b.classList.add("active");
      } else if (view.startsWith("history")) {
        const b = document.getElementById("bnav-history");
        if (b) b.classList.add("active");
      } else if (view === "registry" || view === "registry-day") {
        const b = document.getElementById("bnav-registry");
        if (b) b.classList.add("active");
      } else if (view === "node-detail") {
        const b = document.getElementById("bnav-node-detail");
        if (b) b.classList.add("active");
      }

      const breadcrumb = document.getElementById("breadcrumb-container");
      const hData = (fleetData && fleetData.history) ? fleetData.history : { clients: {}, projects: {}, nodes: {} };

      if (view === "dashboard") {
        const navD = document.getElementById("nav-dashboard");
        if (navD) navD.classList.add("active");
        showAnimatedView("view-dashboard");
        breadcrumb.innerHTML = `<span class="breadcrumb-active">Live Fleet</span>`;
        renderClients();
      } else if (view === "history-clients") {
        const navH = document.getElementById("nav-history");
        if (navH) navH.classList.add("active");
        showAnimatedView("view-history-clients");
        breadcrumb.innerHTML = `
          <span class="breadcrumb-item" onclick="navigateTo('dashboard')">Live Fleet</span>
          <span class="breadcrumb-sep">&gt;</span>
          <span class="breadcrumb-active">Fleet History: Clients</span>
        `;
        renderHistoryClients();
      } else if (view === "history-projects") {
        const navH = document.getElementById("nav-history");
        if (navH) navH.classList.add("active");
        if (param1) selectedHistoryClientKey = param1;
        else if (!selectedHistoryClientKey && hData.clients && Object.keys(hData.clients).length > 0) {
          selectedHistoryClientKey = Object.keys(hData.clients)[0];
        }
        const hc = hData.clients ? hData.clients[selectedHistoryClientKey] : null;
        const hcName = hc ? hc.name : (selectedHistoryClientKey || "Client");
        showAnimatedView("view-history-projects");
        breadcrumb.innerHTML = `
          <span class="breadcrumb-item" onclick="navigateTo('dashboard')">Live Fleet</span>
          <span class="breadcrumb-sep">&gt;</span>
          <span class="breadcrumb-item" onclick="navigateTo('history-clients')">Fleet History</span>
          <span class="breadcrumb-sep">&gt;</span>
          <span class="breadcrumb-active">${escHtml(hcName)}</span>
        `;
        renderHistoryProjects();
      } else if (view === "history-nodes") {
        const navH = document.getElementById("nav-history");
        if (navH) navH.classList.add("active");
        if (param1) selectedHistoryProjectKey = param1;
        else if (!selectedHistoryProjectKey && hData.projects && Object.keys(hData.projects).length > 0) {
          selectedHistoryProjectKey = Object.keys(hData.projects)[0];
        }
        const hp = hData.projects ? hData.projects[selectedHistoryProjectKey] : null;
        if (hp && hp.client_key) selectedHistoryClientKey = hp.client_key;
        const hc = hData.clients ? hData.clients[selectedHistoryClientKey] : null;
        const hcName = hc ? hc.name : (hp ? hp.client_name : "Client");
        const hpName = hp ? hp.name : (selectedHistoryProjectKey || "Project");
        showAnimatedView("view-history-nodes");
        breadcrumb.innerHTML = `
          <span class="breadcrumb-item" onclick="navigateTo('dashboard')">Live Fleet</span>
          <span class="breadcrumb-sep">&gt;</span>
          <span class="breadcrumb-item" onclick="navigateTo('history-clients')">Fleet History</span>
          <span class="breadcrumb-sep">&gt;</span>
          <span class="breadcrumb-item" onclick="navigateTo('history-projects', '${escJs(selectedHistoryClientKey)}')">${escHtml(hcName)}</span>
          <span class="breadcrumb-sep">&gt;</span>
          <span class="breadcrumb-active">${escHtml(hpName)}</span>
        `;
        renderHistoryNodes();
      } else if (view === "registry") {
        const navR = document.getElementById("nav-registry");
        if (navR) navR.classList.add("active");
        showAnimatedView("view-registry");
        breadcrumb.innerHTML = `
          <span class="breadcrumb-item" onclick="navigateTo('dashboard')">Live Fleet</span>
          <span class="breadcrumb-sep">&gt;</span>
          <span class="breadcrumb-active">Operations Registry</span>
        `;
        loadRegistryCalendar();
      } else if (view === "registry-day") {
        const navR = document.getElementById("nav-registry");
        if (navR) navR.classList.add("active");
        showAnimatedView("view-registry-day");
        const dStr = param1 || (new Date()).toISOString().split("T")[0];
        breadcrumb.innerHTML = `
          <span class="breadcrumb-item" onclick="navigateTo('dashboard')">Live Fleet</span>
          <span class="breadcrumb-sep">&gt;</span>
          <span class="breadcrumb-item" onclick="navigateTo('registry')">Operations Registry</span>
          <span class="breadcrumb-sep">&gt;</span>
          <span class="breadcrumb-active">${escHtml(dStr)}.log</span>
        `;
        openRegistryDay(dStr);
      } else if (view === "clients" || view === "client") {
        if (param1) {
          selectedClientId = param1;
        } else if (!selectedClientId && fleetData.clients && Object.keys(fleetData.clients).length > 0) {
          selectedClientId = Object.keys(fleetData.clients)[0];
        }
        showAnimatedView("view-client");
        const client = fleetData.clients ? fleetData.clients[selectedClientId] : null;
        const cName = client ? client.name : (selectedClientId || "Client");
        document.getElementById("client-view-title").innerText = cName;
        document.getElementById("client-view-desc").innerText = client ? (client.description || "") : "";
        breadcrumb.innerHTML = `
          <span class="breadcrumb-item" onclick="navigateTo('dashboard')">Live Fleet</span>
          <span class="breadcrumb-sep">&gt;</span>
          <span class="breadcrumb-active">${escHtml(cName)}</span>
        `;
        renderClientProjects();
      } else if (view === "projects" || view === "project") {
        if (param1) {
          selectedProjectId = param1;
        } else if (!selectedProjectId && fleetData.projects && Object.keys(fleetData.projects).length > 0) {
          selectedProjectId = Object.keys(fleetData.projects)[0];
        }
        showAnimatedView("view-project");
        const proj = fleetData.projects ? fleetData.projects[selectedProjectId] : null;
        const client = (proj && fleetData.clients) ? fleetData.clients[proj.client_id] : null;
        const pName = proj ? proj.name : (selectedProjectId || "Project");
        document.getElementById("project-view-title").innerText = pName;
        document.getElementById("project-view-desc").innerText = proj ? (proj.description || "") : "";
        breadcrumb.innerHTML = `
          <span class="breadcrumb-item" onclick="navigateTo('dashboard')">Live Fleet</span>
          <span class="breadcrumb-sep">&gt;</span>
          <span class="breadcrumb-item" onclick="navigateTo('client', '${escJs(proj ? proj.client_id : "")}')">${escHtml(client ? client.name : "Client")}</span>
          <span class="breadcrumb-sep">&gt;</span>
          <span class="breadcrumb-active">${escHtml(pName)}</span>
        `;
        renderProjectNodes();
      } else if (view === "node-detail") {
        if (param1) selectedNodeName = param1;
        const regNode = (fleetData.registered_nodes && fleetData.registered_nodes[selectedNodeName]) ? fleetData.registered_nodes[selectedNodeName] : null;
        if (regNode && regNode.project_id) {
          selectedProjectId = regNode.project_id;
          selectedClientId = regNode.client_id;
        }
        showAnimatedView("view-node-detail");
        const proj = fleetData.projects ? fleetData.projects[selectedProjectId] : null;
        const pName = proj ? proj.name : "Project";
        breadcrumb.innerHTML = `
          <span class="breadcrumb-item" onclick="navigateTo('dashboard')">Live Fleet</span>
          <span class="breadcrumb-sep">&gt;</span>
          <span class="breadcrumb-item" onclick="navigateTo('project', '${escJs(selectedProjectId)}')">${escHtml(pName)}</span>
          <span class="breadcrumb-sep">&gt;</span>
          <span class="breadcrumb-active">${escHtml(selectedNodeName || "Node")}</span>
        `;
        updateNodeDetailUI();
      }
    }

    function backToClient() {
      const proj = fleetData.projects ? fleetData.projects[selectedProjectId] : null;
      navigateTo("client", proj ? proj.client_id : selectedClientId);
    }

    function backToProject() {
      navigateTo("project", selectedProjectId);
    }

    function openNodeDetail(name) {
      selectedNodeName = name;
      navigateTo("node-detail", name);
    }

    // Modal helpers
    function openAddClientModal() { document.getElementById("modal-add-client").classList.add("open"); }
    function openAddProjectModal() { document.getElementById("modal-add-project").classList.add("open"); }
    function closeModal(id) {
      const el = document.getElementById(id);
      if (el) el.classList.remove("open");
      fetchTelemetry();
    }

    // Rename Entity Modal & Submission
    function openRenameModal(type, id, currentName) {
      document.getElementById("rename-target-type").value = type;
      document.getElementById("rename-target-id").value = id;
      document.getElementById("rename-new-name").value = currentName;
      
      const title = document.getElementById("rename-modal-title");
      const desc = document.getElementById("rename-modal-desc");
      const label = document.getElementById("rename-input-label");
      
      if (type === "client") {
        title.innerText = "Rename Client";
        desc.innerText = "Update client name. This will synchronize across all associated projects and connected nodes.";
        label.innerText = "New Client Name";
      } else if (type === "project") {
        title.innerText = "Rename Project";
        desc.innerText = "Update project name. This will synchronize across all assigned nodes.";
        label.innerText = "New Project Name";
      } else if (type === "node") {
        title.innerText = "Rename Hardware Node";
        desc.innerText = "Update node name. This is transmitted via MQTT (CMD:RENAME) and saved in the ESP32 NVS memory.";
        label.innerText = "New Node Name";
      }
      document.getElementById("modal-rename").classList.add("open");
      setTimeout(() => document.getElementById("rename-new-name").focus(), 100);
    }

    async function submitRename() {
      const type = document.getElementById("rename-target-type").value;
      const id = document.getElementById("rename-target-id").value;
      const newName = document.getElementById("rename-new-name").value.trim();
      if (!newName) return alert("Please enter a valid name.");
      
      let endpoint = "";
      let body = "";
      if (type === "client") {
        endpoint = "/api/client/rename";
        body = `client_id=${encodeURIComponent(id)}&new_name=${encodeURIComponent(newName)}`;
      } else if (type === "project") {
        endpoint = "/api/project/rename";
        body = `project_id=${encodeURIComponent(id)}&new_name=${encodeURIComponent(newName)}`;
      } else if (type === "node") {
        endpoint = "/api/node/rename";
        body = `old_name=${encodeURIComponent(id)}&new_name=${encodeURIComponent(newName)}`;
      }
      
      try {
        const res = await authedFetch(endpoint, {
          method: "POST",
          headers: {"Content-Type": "application/x-www-form-urlencoded"},
          body: body
        });
        const d = await res.json();
        if (d.success) {
          closeModal("modal-rename");
          if (type === "node" && selectedNodeName === id) {
            selectedNodeName = newName;
          }
          fetchTelemetry();
        } else {
          alert(d.error || "Failed to rename");
        }
      } catch(e) {
        alert("Error communicating with server: " + e);
      }
    }

    // Session & Auth Token Management for Cross-Origin Frames
    const CURRENT_AUTH_TOKEN = "__CURRENT_TOKEN__" || localStorage.getItem("anashwar_token") || sessionStorage.getItem("anashwar_token") || "";
    if (CURRENT_AUTH_TOKEN) {
      try {
        localStorage.setItem("anashwar_token", CURRENT_AUTH_TOKEN);
        sessionStorage.setItem("anashwar_token", CURRENT_AUTH_TOKEN);
      } catch(e) {}
    }

    function authedFetch(url, options = {}) {
      options.headers = options.headers || {};
      const token = CURRENT_AUTH_TOKEN || localStorage.getItem("anashwar_token") || sessionStorage.getItem("anashwar_token") || "";
      if (token) {
        if (options.headers instanceof Headers) {
          options.headers.set("Authorization", "Bearer " + token);
        } else {
          options.headers["Authorization"] = "Bearer " + token;
        }
        const sep = url.includes("?") ? "&" : "?";
        url = url + sep + "token=" + encodeURIComponent(token);
      }
      return fetch(url, options);
    }

    // User Authentication & Management
    async function handleLogout() {
      localStorage.removeItem("anashwar_token");
      sessionStorage.removeItem("anashwar_token");
      try {
        await authedFetch("/api/logout", { method: "POST" });
      } catch(e) {}
      window.location.href = "/?logout=true";
    }

    function openUserModal() {
      document.getElementById("modal-users").classList.add("open");
      const uInput = document.getElementById("new-user-username");
      const pInput = document.getElementById("new-user-password");
      if (uInput) uInput.value = "";
      if (pInput) pInput.value = "";
      loadUsersList();
    }

    async function loadUsersList() {
      const listContainer = document.getElementById("users-list-container");
      const sessContainer = document.getElementById("sessions-list-container");
      try {
        const res = await authedFetch("/api/users");
        if (!res.ok) {
          const errData = await res.json().catch(() => ({}));
          console.error("Error loading users:", res.status, errData);
          if (listContainer) {
            listContainer.innerHTML = `<div style="color:#F87171; padding:10px; font-size:12px;">Failed to load accounts: ${errData.error || res.statusText} (Status ${res.status})</div>`;
          }
          return;
        }
        const data = await res.json();
        if (!listContainer || !data.users) return;
        let html = "";
        for (const u of data.users) {
          const isSelf = u.is_self;
          html += `
            <div style="display:flex; justify-content:space-between; align-items:center; background:var(--surface-2); border:1px solid var(--card-border); padding:10px 14px; border-radius:10px; margin-bottom:8px;">
              <div>
                <div style="font-weight:700; font-size:13px; color:var(--text-strong); display:flex; align-items:center; gap:6px;">
                  <span>${escHtml(u.username)}</span>
                  ${isSelf ? '<span style="color:#0EA5E9; font-size:11px;">(You)</span>' : ""}
                  ${u.biometrics_enrolled ? '<span style="font-size:11px; color:#10B981; background:rgba(16,185,129,0.15); border:1px solid rgba(16,185,129,0.3); border-radius:10px; padding:1px 6px;">Biometrics Enrolled</span>' : ""}
                </div>
                <div style="font-size:11px; color:var(--text-dim);">${escHtml(u.role)} &bull; Created ${escHtml(u.created_at || "Recently")}</div>
              </div>
              <div style="display:flex; align-items:center; gap:8px;">
                <button class="btn-secondary" style="font-size:11px; padding:4px 8px; border-color:rgba(56, 189, 248, 0.4); color:#0EA5E9;" onclick="enrollBiometricsForUser('${escJs(u.username)}')">
                  ${u.biometrics_enrolled ? 'Re-enroll' : 'Enroll Biometrics'}
                </button>
                ${u.can_delete ? `<button class="delete-btn-tiny" onclick="deleteUser('${escJs(u.username)}')" title="Delete Account">${ICONS.trash} ${isSelf ? "Delete Self" : "Delete"}</button>` : `<span style="font-size:11px; color:var(--text-dim);">Protected</span>`}
              </div>
            </div>
          `;
        }
        listContainer.innerHTML = html || '<div style="font-size:12px; color:var(--text-dim); padding:8px;">No accounts found</div>';

        // Populate Active & Recent Connected Device Sessions
        const sessCountPill = document.getElementById("sessions-count-pill");
        if (sessContainer) {
          const sessions = data.sessions || [];
          if (sessCountPill) sessCountPill.innerText = `${sessions.length} Active Session${sessions.length === 1 ? "" : "s"}`;
          let sHtml = "";
          for (const s of sessions) {
            const isTouch = s.is_touch;
            const icon = isTouch ? ICONS.phone : ICONS.desktop;
            const formBadge = isTouch ? '<span class="status-pill pill-crimson" style="font-size:10px; padding:2px 8px;">Touch Mobile</span>' : '<span class="status-pill pill-cyan" style="font-size:10px; padding:2px 8px;">Desktop</span>';
            const currBadge = s.is_current ? '<span class="status-pill pill-green" style="font-size:10px; padding:2px 8px;">This Device</span>' : '';
            sHtml += `
              <div style="background:var(--surface-2); border:1px solid var(--card-border); padding:10px 12px; border-radius:10px;">
                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:5px; flex-wrap:wrap; gap:6px;">
                  <div style="font-weight:700; font-size:13px; color:var(--text-strong); display:flex; align-items:center; gap:6px;">
                    <span class="svg-icon">${icon}</span>
                    <span>${escHtml(s.device_model || "Hardware Device")}</span>
                    ${formBadge}
                    ${currBadge}
                  </div>
                  <span style="font-size:11px; color:#0EA5E9; font-weight:700;">${escHtml(s.username)} (${escHtml(s.role)})</span>
                </div>
                <div style="font-size:11px; color:var(--text-dim); display:flex; flex-wrap:wrap; gap:8px; line-height:1.4;">
                  <span><strong>OS:</strong> ${s.os || "Unknown"}</span>
                  <span>&bull;</span>
                  <span><strong>IP:</strong> ${s.ip || "127.0.0.1"}</span>
                  <span>&bull;</span>
                  <span><strong>Location:</strong> ${s.location || "Pune, Maharashtra, India"}</span>
                  <span>&bull;</span>
                  <span><strong>Carrier:</strong> ${s.carrier || "Network"}</span>
                  ${s.screen_res ? `<span>&bull;</span><span><strong>Display:</strong> ${s.screen_res}</span>` : ""}
                  <span>&bull;</span>
                  <span><strong>Active:</strong> ${s.login_time_str || "Online"}</span>
                </div>
              </div>
            `;
          }
          sessContainer.innerHTML = sHtml || '<div style="font-size:12px; color:var(--text-dim); padding:8px;">No active sessions recorded</div>';
        }
      } catch (e) {
        console.error("Error loading users:", e);
        if (listContainer) {
          listContainer.innerHTML = `<div style="color:#F87171; padding:10px; font-size:12px;">Error connecting to user service: ${e.message}</div>`;
        }
      }
    }

    function base64UrlToUint8Array(base64Url) {
      if (!base64Url) return new Uint8Array(0);
      let base64 = base64Url.split("-").join("+").split("_").join("/");
      while (base64.length % 4 !== 0) {
        base64 += "=";
      }
      const bin = atob(base64);
      const bytes = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) {
        bytes[i] = bin.charCodeAt(i);
      }
      return bytes;
    }

    function bufferToBase64Url(buffer) {
      const bytes = new Uint8Array(buffer);
      let binary = "";
      for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
      }
      return btoa(binary).split("+").join("-").split("/").join("_").replace(/=+$/, "");
    }

    async function submitNewUser(enrollBiometricsAfter = false) {
      const u = document.getElementById("new-user-username").value.trim();
      const p = document.getElementById("new-user-password").value;
      const cp = document.getElementById("new-user-confirm-password").value;
      const r = document.getElementById("new-user-role").value;

      if (!u) return alert("Please enter a username");
      if (!p) return alert("Please enter a password");
      if (!cp) return alert("Please re-type the password in the confirmation field");
      if (p !== cp) {
        return alert("Passwords do not match! Please verify that both password fields are identical.");
      }

      const submitBtn = enrollBiometricsAfter ? document.getElementById("btn-add-user-bio") : document.getElementById("btn-add-user");
      if (submitBtn) {
        submitBtn.disabled = true;
        submitBtn.innerText = enrollBiometricsAfter ? "Saving & Enrolling..." : "Saving...";
      }

      try {
        const enrollBioFlag = enrollBiometricsAfter ? "1" : "0";
        const res = await authedFetch("/api/users/create", {
          method: "POST",
          headers: {"Content-Type": "application/x-www-form-urlencoded"},
          body: `username=${encodeURIComponent(u)}&password=${encodeURIComponent(p)}&role=${encodeURIComponent(r)}&enroll_bio=${enrollBioFlag}`
        });
        const data = await res.json();
        if (!data.success) {
          alert(data.error || "Failed to create user");
          return;
        }

        document.getElementById("new-user-username").value = "";
        document.getElementById("new-user-password").value = "";
        document.getElementById("new-user-confirm-password").value = "";

        if (enrollBiometricsAfter && data.bio_options) {
          // Immediately invoke navigator.credentials.create with fresh user gesture token!
          const bioOk = await enrollBiometricsForUser(u, data.bio_options);
          await loadUsersList();
          if (bioOk) {
            alert(`User '${u}' registered and device biometric authentication linked successfully!\nYou can now use Biometric Login.`);
          }
        } else {
          await loadUsersList();
          alert(`User '${u}' (${r}) registered successfully!`);
        }
      } catch(err) {
        alert("Network error creating user: " + err);
      } finally {
        if (submitBtn) {
          submitBtn.disabled = false;
          submitBtn.innerText = enrollBiometricsAfter ? "Save & Enroll Biometrics" : "Save User Account";
        }
      }
    }

    async function deleteUser(username) {
      if (!confirm(`Are you sure you want to delete user '${username}'?`)) return;
      try {
        const res = await authedFetch("/api/users/delete", {
          method: "POST",
          headers: {"Content-Type": "application/x-www-form-urlencoded"},
          body: `username=${encodeURIComponent(username)}`
        });
        const data = await res.json();
        if (data.success) {
          if (data.self_deleted) {
            alert("Your account was deleted. You will now be signed out.");
            handleLogout();
            return;
          }
          loadUsersList();
        } else {
          alert(data.error || "Failed to delete user");
        }
      } catch(e) {
        alert("Error deleting user: " + e);
      }
    }

    // Biometric Device Enrollment (WebAuthn / Samsung Knox Fingerprint / Apple Face ID)
    async function enrollCurrentDeviceBiometrics() {
      const u = "__CURRENT_USER__" || "admin";
      const ok = await enrollBiometricsForUser(u);
      if (ok) {
        alert(`Biometric authentication (Fingerprint / Face ID) successfully enrolled for user '${u}'!\nYou can now sign in using 'Biometric Login' on the sign-in screen.`);
      }
    }

    async function enrollBiometricsForUser(targetUser, preloadedOpts = null) {
      if (!window.isSecureContext && window.location.hostname !== "localhost" && window.location.hostname !== "127.0.0.1") {
        alert("Biometric enrollment (WebAuthn) requires a secure HTTPS connection (or localhost). Please access the portal using HTTPS.");
        return false;
      }
      if (!window.PublicKeyCredential) {
        alert("WebAuthn / Biometrics is not supported on this browser or platform.");
        return false;
      }
      try {
        let opts = preloadedOpts;
        if (!opts) {
          const res = await authedFetch("/api/webauthn/register/options", {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify({ username: targetUser })
          });
          const data = await res.json();
          opts = data.options || data;
          if (!opts || !opts.challenge) {
            alert("Failed to initialize biometric challenge from server: " + (data.error || "No challenge"));
            return false;
          }
        }

        opts.rp = opts.rp || {};
        const isIp = /^([0-9]{1,3}[.]){3}[0-9]{1,3}$/.test(window.location.hostname);
        if (isIp) {
          delete opts.rp.id;
        } else {
          opts.rp.id = window.location.hostname;
        }

        opts.challenge = base64UrlToUint8Array(opts.challenge);
        opts.user = opts.user || {};
        opts.user.id = new TextEncoder().encode(targetUser);
        opts.user.name = targetUser;
        opts.user.displayName = targetUser;

        opts.pubKeyCredParams = opts.pubKeyCredParams || [
          { type: "public-key", alg: -7 },
          { type: "public-key", alg: -257 },
          { type: "public-key", alg: -8 }
        ];

        opts.authenticatorSelection = opts.authenticatorSelection || {};
        opts.authenticatorSelection.userVerification = "preferred";
        opts.authenticatorSelection.residentKey = "preferred";

        // Prompt native device fingerprint (Samsung S24 Ultra) or Face ID (Apple)
        const credential = await navigator.credentials.create({ publicKey: opts });
        if (!credential) {
          alert("Biometric enrollment cancelled.");
          return false;
        }

        const credId = bufferToBase64Url(credential.rawId);

        const verifyPayload = {
          id: credential.id || credId,
          rawId: credId,
          username: targetUser,
          type: credential.type,
          device_label: (navigator.userAgentData && navigator.userAgentData.model) ? navigator.userAgentData.model : (window.innerWidth <= 860 ? "Samsung / Mobile Device" : "Mac / PC Desktop")
        };

        const vRes = await authedFetch("/api/webauthn/register/verify", {
          method: "POST",
          headers: {"Content-Type": "application/json"},
          body: JSON.stringify(verifyPayload)
        });
        const vData = await vRes.json();
        if (vData.success) {
          await loadUsersList();
          return true;
        } else {
          alert("Biometric verification failed: " + (vData.error || "Unknown error"));
          return false;
        }
      } catch(e) {
        console.error("Biometrics error:", e);
        let detail = e.message || e.name || "Operation failed";
        if (window.self !== window.top) {
          detail = "Embedded in-app frame restriction: WebAuthn biometrics cannot run inside an embedded webview or iframe. Please tap 'Open in Browser' at the top of the screen to open directly in Google Chrome / Safari.";
        } else if (e.name === "NotAllowedError") {
          detail = "Biometric prompt was dismissed, timed out, or cancelled on the device. Please tap 'Enroll Biometrics' and scan your fingerprint when prompted.";
        }
        alert("Biometric scanner notice: " + detail);
        return false;
      }
    }

    // Client & Project Deletion
    async function deleteClient(clientId, clientName) {
      if (!confirm(`Delete Client "${clientName}" and all associated projects?`)) return;
      const res = await authedFetch("/api/client/delete", {
        method: "POST",
        headers: {"Content-Type": "application/x-www-form-urlencoded"},
        body: `client_id=${encodeURIComponent(clientId)}`
      });
      if (res.ok) {
        fetchTelemetry();
        if (currentView === "history-clients") navigateTo("history-clients");
        else navigateTo("dashboard");
      } else {
        alert("Error deleting client");
      }
    }

    async function deleteProject(projectId, projectName) {
      if (!confirm(`Delete Project "${projectName}"?`)) return;
      const res = await authedFetch("/api/project/delete", {
        method: "POST",
        headers: {"Content-Type": "application/x-www-form-urlencoded"},
        body: `project_id=${encodeURIComponent(projectId)}`
      });
      if (res.ok) {
        fetchTelemetry();
        if (currentView === "history-projects") navigateTo("history-projects", selectedHistoryClientKey);
        else navigateTo("client", selectedClientId);
      } else {
        alert("Error deleting project");
      }
    }

    // Node Registration & Deletion
    async function deleteNode(nodeName) {
      if (!confirm(`Delete Node "${nodeName}" from registry?`)) return;
      const res = await authedFetch("/api/node/delete", {
        method: "POST",
        headers: {"Content-Type": "application/x-www-form-urlencoded"},
        body: `node_name=${encodeURIComponent(nodeName)}`
      });
      if (res.ok) {
        if (selectedNodeName === nodeName) selectedNodeName = "";
        fetchTelemetry();
        if (selectedProjectId && fleetData.projects && fleetData.projects[selectedProjectId]) {
          navigateTo("project", selectedProjectId);
        } else {
          navigateTo("dashboard");
        }
      } else {
        alert("Error deleting node");
      }
    }

    async function openAddNodeModal() {
      document.getElementById("modal-add-node").classList.add("open");
      try {
        const res = await authedFetch("/api/usb/scan");
        const data = await res.json();
        const sel = document.getElementById("new-node-usb-select");
        if (sel && data.devices) {
          sel.innerHTML = '<option value="">-- Select Detected USB Device (Optional) --</option>';
          for (const d of data.devices) {
            sel.innerHTML += `<option value="${d.port}" data-mac="${d.mac}" data-chip="${d.chip_id}" data-name="${d.node_name}">
              ${d.port} ${d.node_name ? "("+d.node_name+")" : "(Available to Assign)"}
            </option>`;
          }
        }
      } catch(e) {
        console.error("USB scan error:", e);
      }
    }

    function onUsbSelectChange() {
      const sel = document.getElementById("new-node-usb-select");
      const opt = sel.options[sel.selectedIndex];
      if (opt && opt.value) {
        document.getElementById("new-node-port").value = opt.value;
        if (opt.dataset.name) document.getElementById("new-node-name").value = opt.dataset.name;
        if (opt.dataset.mac) document.getElementById("new-node-mac").value = opt.dataset.mac;
        if (opt.dataset.chip) document.getElementById("new-node-chip").value = opt.dataset.chip;
      }
    }

    async function submitNewNode() {
      const name = document.getElementById("new-node-name").value.trim();
      const port = document.getElementById("new-node-port").value.trim() || "WiFi Wireless";
      const mac = document.getElementById("new-node-mac").value.trim();
      const chip = document.getElementById("new-node-chip").value.trim();
      if (!name) return alert("Please enter Node Name");
      const res = await authedFetch("/api/node/create", {
        method: "POST",
        headers: {"Content-Type": "application/x-www-form-urlencoded"},
        body: `name=${encodeURIComponent(name)}&port=${encodeURIComponent(port)}&mac=${encodeURIComponent(mac)}&chip_id=${encodeURIComponent(chip)}&project_id=${encodeURIComponent(selectedProjectId)}`
      });
      if (res.ok) {
        closeModal("modal-add-node");
        fetchTelemetry();
      } else {
        alert("Error registering node");
      }
    }

    // In-Situ Reverse Proxy Viewer
    function openInsituNode(nodeName) {
      if (nodeName) selectedNodeName = nodeName;
      openInsituModal();
    }

    function openInsituModal() {
      const modal = document.getElementById("modal-insitu-webui");
      const iframe = document.getElementById("insitu-iframe");
      const title = document.getElementById("insitu-modal-title");
      const directLink = document.getElementById("insitu-modal-direct-link");
      const fullTabLink = document.getElementById("insitu-modal-fulltab-link");
      
      const node = telemetryData.nodes ? telemetryData.nodes[selectedNodeName] : null;
      const ip = node ? node.ip : "0.0.0.0";
      const tok = CURRENT_AUTH_TOKEN || localStorage.getItem("anashwar_token") || sessionStorage.getItem("anashwar_token") || "";
      const proxyUrl = `/proxy/node/${encodeURIComponent(selectedNodeName)}/?token=${encodeURIComponent(tok)}`;
      
      title.innerText = `In-Situ On-Board Web UI: ${selectedNodeName}`;
      iframe.src = proxyUrl;
      if (fullTabLink) fullTabLink.href = proxyUrl;
      directLink.href = `http://${ip}/`;
      modal.classList.add("open");
    }

    function refreshInsituIframe() {
      const iframe = document.getElementById("insitu-iframe");
      if (iframe) iframe.src = iframe.src;
    }

    // Master Service Switch & Autonomous Offline Mode Toggles
    function toggleMasterService() {
      const chk = document.getElementById("detail-service-toggle");
      const state = chk.checked ? "ON" : "OFF";
      authedFetch("/api/command", {
        method: "POST",
        headers: {"Content-Type": "application/x-www-form-urlencoded"},
        body: `target=${encodeURIComponent(selectedNodeName)}&action=SERVICE&val=${state}`
      });
    }

    function toggleOfflineMode() {
      const chk = document.getElementById("detail-offline-toggle");
      const state = chk.checked ? "ON" : "OFF";
      authedFetch("/api/command", {
        method: "POST",
        headers: {"Content-Type": "application/x-www-form-urlencoded"},
        body: `target=${encodeURIComponent(selectedNodeName)}&action=OFFLINE&val=${state}`
      });
    }

    function triggerNodeReboot(nodeName) {
      if (!confirm(`Send hardware reboot signal to [${nodeName}]?`)) return;
      authedFetch("/api/command", {
        method: "POST",
        headers: {"Content-Type": "application/x-www-form-urlencoded"},
        body: `target=${encodeURIComponent(nodeName)}&action=REBOOT&val=1`
      }).then(() => fetchTelemetry());
    }

    function triggerNodePing(nodeName) {
      authedFetch("/api/command", {
        method: "POST",
        headers: {"Content-Type": "application/x-www-form-urlencoded"},
        body: `target=${encodeURIComponent(nodeName)}&action=PING&val=1`
      }).then(() => fetchTelemetry());
    }

    function sendCustomDirective(nodeName) {
      const input = document.getElementById("custom-directive-input");
      const cmd = input ? input.value.trim() : "";
      if (!cmd) return alert("Please enter a directive or command string");
      authedFetch("/api/command", {
        method: "POST",
        headers: {"Content-Type": "application/x-www-form-urlencoded"},
        body: `target=${encodeURIComponent(nodeName)}&action=RAW_CMD&val=${encodeURIComponent(cmd)}`
      }).then(r => r.json()).then(d => {
        if (input) input.value = "";
        fetchTelemetry();
      });
    }

    function sendQuickDirective(nodeName, cmd) {
      authedFetch("/api/command", {
        method: "POST",
        headers: {"Content-Type": "application/x-www-form-urlencoded"},
        body: `target=${encodeURIComponent(nodeName)}&action=RAW_CMD&val=${encodeURIComponent(cmd)}`
      }).then(() => fetchTelemetry());
    }

    function openCurrentNodeDetail() {
      const nodesObj = telemetryData.nodes || {};
      let target = selectedNodeName;
      if (!target || !nodesObj[target]) {
        const onlineKeys = Object.keys(nodesObj).filter(k => nodesObj[k] && nodesObj[k].online);
        const allKeys = Object.keys(nodesObj);
        target = onlineKeys[0] || allKeys[0] || "";
      }
      if (!target) {
        alert("No hardware nodes are currently registered. Wait for a node to connect or inspect Fleet History.");
        navigateTo("history-clients");
        return;
      }
      openNodeDetail(target);
    }

    function submitNewClient() {
      const name = document.getElementById("new-client-name").value;
      const code = document.getElementById("new-client-code").value;
      const desc = document.getElementById("new-client-desc").value;
      if (!name) return alert("Please enter client name");
      
      authedFetch("/api/client/create", {
        method: "POST",
        headers: {"Content-Type": "application/x-www-form-urlencoded"},
        body: `name=${encodeURIComponent(name)}&code=${encodeURIComponent(code)}&description=${encodeURIComponent(desc)}`
      }).then(r => r.json()).then(d => {
        closeModal("modal-add-client");
        fetchTelemetry();
      });
    }

    function submitNewProject() {
      const name = document.getElementById("new-proj-name").value;
      const code = document.getElementById("new-proj-code").value;
      const desc = document.getElementById("new-proj-desc").value;
      if (!name) return alert("Please enter project name");

      authedFetch("/api/project/create", {
        method: "POST",
        headers: {"Content-Type": "application/x-www-form-urlencoded"},
        body: `client_id=${encodeURIComponent(selectedClientId)}&name=${encodeURIComponent(name)}&code=${encodeURIComponent(code)}&description=${encodeURIComponent(desc)}`
      }).then(r => r.json()).then(d => {
        closeModal("modal-add-project");
        fetchTelemetry();
      });
    }

    function onDelaySliderInput(val) {
      document.getElementById("delay-display-val").innerText = parseFloat(val).toFixed(1) + "s";
    }

    function applyDelay(val) {
      val = parseFloat(val).toFixed(1);
      document.getElementById("delay-range").value = val;
      document.getElementById("delay-display-val").innerText = val + "s";
      authedFetch("/api/command", {
        method: "POST",
        headers: {"Content-Type": "application/x-www-form-urlencoded"},
        body: `target=${encodeURIComponent(selectedNodeName)}&action=DELAY&val=${val}`
      });
    }

    // Binary Inspection Card Renderer
    function updateBinaryInspectionCard(info) {
      const card = document.getElementById("bin-inspect-card");
      const details = document.getElementById("inspect-details");
      const pill = document.getElementById("inspect-compliance-pill");
      if (!card || !details) return;
      
      card.style.display = "block";
      const sizeKb = info.size_kb || 1059;
      const otaFitPct = ((sizeKb / 1280) * 100).toFixed(1);
      const compliant = (info.compliance_score >= 8);
      
      if (pill) {
        pill.className = compliant ? "status-pill pill-green" : "status-pill pill-crimson";
        pill.innerText = compliant ? `${info.compliance_score || 9}/9 Compliant` : "Non-Compliant";
      }
      
      details.innerHTML = `
        <div><strong>Partition Fit:</strong> ${sizeKb} KB / 1,280 KB (${otaFitPct}% of Dual-OTA Partition - ${info.ota_partition_fit || "OK"})</div>
        <div><strong>Target Chip & Magic:</strong> ${info.target_chip || "ESP32"} (Magic: ${info.magic_byte || "0xE9"}, App Desc: ${info.app_desc_magic || "0xABCD5432"})</div>
        <div><strong>Internet Broker:</strong> <code style="color:#38BDF8;">${info.broker_endpoint || "broker.hivemq.com:1883"}</code></div>
        <div><strong>Integration Markers:</strong> ${info.markers_summary || "9/9 Adherent (MAC, eFuse, Local IP, Delay, Service, SHA-256)"}</div>
      `;
    }

    function selectBaseFirmware() {
      selectedFirmwareFile = "Base_firmware.bin";
      const card = document.getElementById("card-base-firmware");
      if (card) card.classList.add("active");
      const dropLabel = document.getElementById("dropzone-label");
      if (dropLabel) dropLabel.innerText = "Selected: Base_firmware.bin (Golden Reference Build)";
      
      updateBinaryInspectionCard({
        filename: "Base_firmware.bin",
        size_kb: 1059.5,
        ota_partition_fit: "Fits standard 1.25MB / 1.87MB OTA partition (82.8% used)",
        target_chip: "ESP32 (Tensilica Xtensa Dual-Core 240MHz)",
        magic_byte: "0xE9 (ESP32 Standard)",
        app_desc_magic: "0xABCD5432 (ESP-IDF Validated)",
        broker_endpoint: "broker.hivemq.com:1883",
        compliance_score: 9,
        markers_summary: "9/9 Compliant (MAC, eFuse, Local IP, Delay, Service, Offline, SHA-256)"
      });
    }

    function selectFirmwareMode(m) {
      selectBaseFirmware();
    }

    function triggerDeployment(route) {
      if (!confirm(`Deploy ${selectedFirmwareFile} to [${selectedNodeName}] via ${route.toUpperCase()}?`)) return;
      authedFetch("/api/deploy", {
        method: "POST",
        headers: {"Content-Type": "application/x-www-form-urlencoded"},
        body: `target=${encodeURIComponent(selectedNodeName)}&route=${route}&filename=${encodeURIComponent(selectedFirmwareFile)}`
      }).then(r => r.json()).then(d => {
        fetchTelemetry();
      });
    }

    function handleFileSelect(files) {
      if (!files || !files.length) return;
      const file = files[0];
      const formData = new FormData();
      formData.append("file", file);
      
      document.getElementById("dropzone-label").innerText = `Uploading & validating ${file.name}...`;

      authedFetch("/api/upload_bin", {
        method: "POST",
        body: formData
      }).then(r => r.json()).then(d => {
        if (d.success) {
          selectedFirmwareFile = d.binary.filename;
          document.getElementById("dropzone-label").innerText = `Verified ${d.binary.filename} (${d.binary.size_kb} KB, ${d.binary.target_chip})`;
          updateBinaryInspectionCard(d.binary);
        } else {
          alert("Upload failed: " + (d.error || "Invalid file"));
        }
      });
    }

    // Operations Registry: Calendar & Daily Inspector
    async function loadRegistryCalendar(year, month) {
      if (year) currentRegYear = year;
      if (month) currentRegMonth = month;
      
      try {
        const res = await authedFetch(`/api/registry/calendar?year=${currentRegYear}&month=${currentRegMonth}`);
        const data = await res.json();
        
        // Render Year Pills
        const yearContainer = document.getElementById("registry-year-pills");
        if (yearContainer && data.years) {
          yearContainer.innerHTML = data.years.map(y => `
            <span class="preset-pill ${y === data.selected_year ? "active" : ""}" onclick="loadRegistryCalendar(${y}, ${currentRegMonth})">${y}</span>
          `).join("");
        }
        
        // Render Month Pills
        const monthContainer = document.getElementById("registry-month-pills");
        if (monthContainer && data.months) {
          monthContainer.innerHTML = data.months.map(m => `
            <span class="preset-pill ${m.num === data.selected_month ? "active" : ""}" onclick="loadRegistryCalendar(${currentRegYear}, ${m.num})">${m.name}</span>
          `).join("");
        }
        
        // Render Daily File Buttons Grid
        const daysContainer = document.getElementById("registry-days-container");
        if (daysContainer && data.days) {
          let filteredDays = data.days;
          if (currentRegWeek !== "all") {
            filteredDays = filteredDays.filter(d => d.week === currentRegWeek);
          }
          
          let html = "";
          for (const d of filteredDays) {
            if (d.has_events) {
              html += `
                <div class="glass-card" style="padding:16px; cursor:pointer; border-color:rgba(14,165,233,0.3); background:var(--surface-2);" onclick="navigateTo('registry-day', '${escJs(d.date)}')">
                  <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;">
                    <span style="font-weight:700; font-size:14px; color:var(--text-strong);">${escHtml(d.date)}</span>
                    <span class="status-pill pill-cyan">${escHtml(d.weekday)} &bull; Wk ${d.week}</span>
                  </div>
                  <div style="font-size:12px; color:var(--text-muted); margin-bottom:12px;">File: <code style="color:#0EA5E9;">${escHtml(d.filename)}</code></div>
                  <div style="display:flex; justify-content:space-between; align-items:center;">
                    <span class="status-pill pill-green">${d.count} Events Recorded</span>
                    <span style="font-size:12px; color:#0EA5E9; font-weight:700;">Open &rarr;</span>
                  </div>
                </div>
              `;
            } else {
              html += `
                <div class="glass-card" style="padding:16px; opacity:0.42; cursor:not-allowed;">
                  <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;">
                    <span style="font-weight:600; font-size:13px; color:var(--text-muted);">${escHtml(d.date)}</span>
                    <span class="status-pill" style="background:var(--surface-3); color:var(--text-dim);">${escHtml(d.weekday)}</span>
                  </div>
                  <div style="font-size:11px; color:var(--text-dim); margin-bottom:12px;">File: <code>${escHtml(d.filename)}</code></div>
                  <div style="display:flex; justify-content:space-between; align-items:center;">
                    <span style="font-size:11px; color:var(--text-dim);">No events logged</span>
                    <span style="font-size:11px; color:var(--text-dim);">-</span>
                  </div>
                </div>
              `;
            }
          }
          daysContainer.innerHTML = html;
        }
      } catch(e) {
        console.error("Error loading registry calendar:", e);
      }
    }

    function filterRegistryWeek(w) {
      currentRegWeek = w;
      document.querySelectorAll("#registry-week-pills .preset-pill").forEach(el => {
        el.classList.toggle("active", el.innerText.includes(w === "all" ? "All" : `Week ${w}`));
      });
      loadRegistryCalendar(currentRegYear, currentRegMonth);
    }

    async function openRegistryDay(dateStr) {
      currentLoadedDate = dateStr;
      document.getElementById("reg-day-title").innerText = `Registry File: ${dateStr}.log`;
      
      try {
        const res = await authedFetch(`/api/registry/day?date=${encodeURIComponent(dateStr)}`);
        const data = await res.json();
        currentDayEvents = data.events || [];
        document.getElementById("reg-day-count-badge").innerText = `${currentDayEvents.length} Events Recorded`;
        renderRegistryEventsList();
      } catch(e) {
        console.error("Error loading registry day:", e);
      }
    }

    function refreshCurrentDayLog() {
      if (currentLoadedDate) openRegistryDay(currentLoadedDate);
    }

    function downloadCurrentDayLog() {
      if (!currentLoadedDate) return;
      const token = CURRENT_AUTH_TOKEN || localStorage.getItem("anashwar_token") || "";
      window.open(`/api/registry/download?date=${encodeURIComponent(currentLoadedDate)}&token=${encodeURIComponent(token)}`, "_blank");
    }

    function onRegistrySearchInput(val) {
      renderRegistryEventsList(val.toLowerCase().trim());
    }

    function filterRegistryCategory(cat) {
      currentCategoryFilter = cat;
      document.querySelectorAll("#reg-category-pills .preset-pill").forEach(el => {
        el.classList.toggle("active", el.innerText.toUpperCase().includes(cat));
      });
      const searchVal = (document.getElementById("reg-search-input") ? document.getElementById("reg-search-input").value : "").toLowerCase().trim();
      renderRegistryEventsList(searchVal);
    }

    function renderRegistryEventsList(searchQuery = "") {
      const container = document.getElementById("reg-events-container");
      if (!container) return;
      
      let events = currentDayEvents;
      if (currentCategoryFilter !== "ALL") {
        events = events.filter(e => {
          const u = e.toUpperCase();
          if (currentCategoryFilter === "CMD") return u.includes("COMMAND") || u.includes("CMD:");
          if (currentCategoryFilter === "ACK") return u.includes("ACK") || u.includes("PRESENCE") || u.includes("ONLINE");
          if (currentCategoryFilter === "SEC") return u.includes("AUTH") || u.includes("LOGIN") || u.includes("SECURITY") || u.includes("HASH");
          if (currentCategoryFilter === "OTA") return u.includes("OTA") || u.includes("DEPLOY") || u.includes("FLASH") || u.includes("BIN");
          return true;
        });
      }
      
      if (searchQuery) {
        events = events.filter(e => e.toLowerCase().includes(searchQuery));
      }
      
      if (events.length === 0) {
        container.innerHTML = '<div style="color:var(--text-dim); padding:20px; text-align:center;">No matching events found for this filter.</div>';
        return;
      }
      
      container.innerHTML = events.map(line => {
        let color = "var(--log-text)";
        const u = line.toUpperCase();
        if (u.includes("ACK") || u.includes("SUCCESS") || u.includes("VERIFIED")) color = "#10B981";
        else if (u.includes("ERROR") || u.includes("FAIL") || u.includes("OFFLINE")) color = "#EF4444";
        else if (u.includes("CMD:") || u.includes("COMMAND") || u.includes("OTA")) color = "#0EA5E9";
        else if (u.includes("AUTH") || u.includes("USER")) color = "#D97706";
        
        return `<div style="color:${color}; font-family:var(--font-mono); font-size:12px; padding:4px 0; border-bottom:1px solid var(--card-border);">${escHtml(line)}</div>`;
      }).join("");
    }

    // Render Helpers
    function findLiveNodeByNameOrId(name, mac, chipId) {
      const nodesObj = telemetryData.nodes || {};
      if (name && nodesObj[name]) return { key: name, data: nodesObj[name] };
      const mU = (mac || "").toUpperCase();
      const cU = (chipId || "").toUpperCase();
      for (const [k, v] of Object.entries(nodesObj)) {
        if (mU && (v.mac || "").toUpperCase() === mU) return { key: k, data: v };
        if (cU && (v.chip_id || "").toUpperCase() === cU) return { key: k, data: v };
      }
      return null;
    }

    function findActiveClientId(histKey, histName) {
      if (!fleetData.clients) return "";
      const targetK = normKey(histName || histKey);
      for (const [cid, cl] of Object.entries(fleetData.clients)) {
        if (normKey(cl.name) === targetK) return cid;
      }
      return "";
    }

    function findActiveProjectId(histClientKey, histProjName) {
      if (!fleetData.projects) return "";
      const pTarget = normKey(histProjName);
      for (const [pid, pr] of Object.entries(fleetData.projects)) {
        const cl = fleetData.clients ? fleetData.clients[pr.client_id] : null;
        if (normKey(pr.name) === pTarget && (!histClientKey || !cl || normKey(cl.name) === histClientKey)) {
          return pid;
        }
      }
      return "";
    }

    function renderNodeThumb(nodeData) {
      if (isEsp32Node(nodeData)) {
        return `<div class="esp32-hw-frame"><img src="/static/esp32_wroom32.jpg" alt="ESP32-WROOM-32"></div>`;
      }
      return `<div class="esp32-hw-frame" style="background:var(--surface-3); color:var(--info);">${ICONS.chip}</div>`;
    }

    function renderClients() {
      const container = document.getElementById("clients-container");
      if (!container || !fleetData.clients) return;

      const hClients = (fleetData.history && fleetData.history.clients) ? fleetData.history.clients : {};
      const activeList = [];

      for (const [c_id, client] of Object.entries(fleetData.clients)) {
        const clientNodes = [];
        const onlineNodes = [];
        const liveProjSet = new Set();

        if (fleetData.projects) {
          for (const p_id of (client.projects || [])) {
            const p = fleetData.projects[p_id];
            if (p && p.nodes) {
              for (const nName of p.nodes) {
                const nData = telemetryData.nodes ? telemetryData.nodes[nName] : null;
                const entry = {
                  name: nName,
                  projectId: p_id,
                  projectName: p.name || p_id,
                  online: !!(nData && nData.online),
                  ip: nData ? (nData.ip || "0.0.0.0") : "0.0.0.0",
                  rssi: nData ? (nData.rssi || 0) : 0,
                  data: nData || {}
                };
                clientNodes.push(entry);
                if (entry.online) {
                  onlineNodes.push(entry);
                  liveProjSet.add(p_id);
                }
              }
            }
          }
        }

        const isManualEmpty = (clientNodes.length === 0 && (client.manual_pending || !hClients[normKey(client.name)]));
        if (onlineNodes.length === 0 && !isManualEmpty) {
          continue;
        }

        if (globalSearchQuery) {
          const hay = [
            client.name, client.code, client.description,
            ...clientNodes.map(n => `${n.name} ${n.projectName} ${n.ip} ${n.data.mac || ""} ${n.data.chip_id || ""}`)
          ].join(" ").toLowerCase();
          if (!hay.includes(globalSearchQuery)) continue;
        }

        activeList.push({ c_id, client, clientNodes, onlineNodes, liveProjCount: liveProjSet.size });
      }

      activeList.sort((a, b) => b.onlineNodes.length - a.onlineNodes.length);

      let html = "";
      for (const item of activeList) {
        const { c_id, client, clientNodes, onlineNodes } = item;
        const numProjects = client.projects ? client.projects.length : 0;
        const onlineCount = onlineNodes.length;
        const offlineCount = clientNodes.length - onlineCount;

        const liveRowsHtml = onlineNodes.length > 0 ? onlineNodes.map(n => {
          const svcOn = (n.data && n.data.service !== false);
          return `
            <div class="active-node-row" onclick="event.stopPropagation(); openNodeDetail('${escJs(n.name)}')">
              <div style="display:flex; align-items:center; gap:12px; min-width:0; flex:1;">
                ${renderNodeThumb(n.data)}
                <div style="min-width:0; flex:1;">
                  <div style="display:flex; align-items:center; gap:8px; flex-wrap:wrap;">
                    <span style="font-weight:700; font-size:14px; color:var(--text-strong); white-space:nowrap; overflow:hidden; text-overflow:ellipsis;">${escHtml(n.name)}</span>
                    <span class="status-pill pill-green" style="font-size:10px; padding:2px 8px;"><span class="pulsing-dot"></span> ONLINE</span>
                    <span class="status-pill pill-cyan" style="font-size:10px; padding:2px 8px;">${escHtml(n.projectName)}</span>
                  </div>
                  <div style="font-size:11px; color:var(--text-muted); margin-top:4px; font-family:var(--font-mono); white-space:nowrap; overflow:hidden; text-overflow:ellipsis;">
                    IP: ${escHtml(n.ip)} &bull; RSSI: ${n.rssi} dBm &bull; ${svcOn ? "ACTIVE" : "STANDBY"}
                  </div>
                </div>
              </div>
              <div style="display:flex; align-items:center; gap:6px; flex-shrink:0;">
                <button class="btn-main btn-cyan" style="padding:7px 11px; font-size:11px; border-radius:9px;" onclick="event.stopPropagation(); openInsituNode('${escJs(n.name)}')" title="Open On-Board Web UI">
                  ${ICONS.globe}
                  <span>Web UI</span>
                </button>
                <button class="btn-main btn-crimson" style="padding:7px 11px; font-size:11px; border-radius:9px;" onclick="event.stopPropagation(); openNodeDetail('${escJs(n.name)}')" title="Open Node Controls">
                  ${ICONS.sliders}
                  <span>Controls</span>
                </button>
              </div>
            </div>
          `;
        }).join("") : '<div style="font-size:12px; color:var(--text-dim); padding:10px 0;">Ready for project &amp; node onboarding.</div>';

        html += `
          <div class="glass-card client-tile" onclick="navigateTo('client', '${escJs(c_id)}')">
            <div class="client-tile-header">
              <div class="client-avatar">${escHtml(client.code ? client.code.substring(0,2) : "CL")}</div>
              <div style="display:flex; align-items:center; gap:8px;">
                <span class="status-pill ${onlineCount > 0 ? "pill-green" : "pill-cyan"}">${onlineCount > 0 ? `${onlineCount} Live Now` : (client.tier || "Active")}</span>
                <button class="delete-btn-tiny" onclick="event.stopPropagation(); openRenameModal('client', '${escJs(c_id)}', '${escJs(client.name)}')" title="Rename Client">${ICONS.edit}</button>
                <button class="delete-btn-tiny" onclick="event.stopPropagation(); deleteClient('${escJs(c_id)}', '${escJs(client.name)}')" title="Delete Client">${ICONS.trash}</button>
              </div>
            </div>
            <div class="client-name">${escHtml(client.name)}</div>
            <div class="client-desc">${escHtml(client.description || "Connected Edge Operations")}</div>

            <div style="margin: 12px 0 8px 0;">
              <div style="font-size: 11px; font-weight: 700; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 8px;">Live Projects &amp; Online Hardware</div>
              ${liveRowsHtml}
            </div>

            <div class="client-metrics-row">
              <div class="metric-col"><div class="metric-val">${numProjects}</div><div class="metric-lbl">Projects</div></div>
              <div class="metric-col"><div class="metric-val" style="color:#10B981;">${onlineCount}</div><div class="metric-lbl">Online Now</div></div>
              <div class="metric-col"><div class="metric-val" style="color:${offlineCount > 0 ? "#EF4444" : "var(--text-muted)"};">${offlineCount}</div><div class="metric-lbl">Offline</div></div>
            </div>

            <div class="client-footer-btn">
              <span>Manage Client Projects</span>
              <span>&rarr;</span>
            </div>
          </div>
        `;
      }

      if (activeList.length === 0) {
        html += `
          <div class="glass-card" style="grid-column: 1 / -1; text-align:center; padding:32px 24px;">
            <div style="font-size:17px; font-weight:800; color:var(--text-strong); margin-bottom:6px;">No Active Live Clients Online</div>
            <div style="font-size:13px; color:var(--text-muted); max-width:520px; margin:0 auto 18px auto;">
              Power on an edge node connected to HiveMQ (broker.hivemq.com:1883) to see live hardware here automatically, or browse previously seen devices in Fleet History.
            </div>
            <div style="display:flex; gap:10px; justify-content:center; flex-wrap:wrap;">
              <button class="btn-main btn-cyan" style="padding:10px 18px; font-size:13px;" onclick="navigateTo('history-clients')">Browse Fleet History &rarr;</button>
              <button class="btn-main btn-crimson" style="padding:10px 18px; font-size:13px;" onclick="openAddClientModal()">+ Add New Client</button>
            </div>
          </div>
        `;
      }

      html += `
        <div class="add-card-btn" onclick="openAddClientModal()">
          <div class="add-icon-circle">+</div>
          <div style="font-weight:700;">Add Enterprise Client</div>
          <div style="font-size:11px;color:var(--text-dim);">Register a new client tenant</div>
        </div>
      `;

      if (container.dataset.lastHtml !== html) {
        container.dataset.lastHtml = html;
        container.innerHTML = html;
      }
    }

    function renderHistoryClients() {
      const container = document.getElementById("history-clients-container");
      if (!container) return;
      const h = (fleetData && fleetData.history) ? fleetData.history : { clients: {}, projects: {}, nodes: {} };
      const hClients = Object.values(h.clients || {});
      const hProjects = Object.values(h.projects || {});
      const hNodes = Object.values(h.nodes || {});

      const enriched = hClients.map(hc => {
        const projs = hProjects.filter(p => p.client_key === hc.key);
        const nodes = hNodes.filter(n => n.client_key === hc.key);
        let liveOnline = 0;
        for (const hn of nodes) {
          const found = findLiveNodeByNameOrId(hn.name, hn.mac, hn.chip_id);
          if (found && found.data && found.data.online) liveOnline++;
        }
        const activeCid = findActiveClientId(hc.key, hc.name);
        return { hc, projCount: projs.length, nodeCount: nodes.length, liveOnline, activeCid };
      }).filter(item => {
        if (!globalSearchQuery) return true;
        return `${item.hc.name} ${item.hc.code}`.toLowerCase().includes(globalSearchQuery);
      });

      enriched.sort((a, b) => (b.liveOnline - a.liveOnline) || ((b.hc.last_seen_ts || 0) - (a.hc.last_seen_ts || 0)));

      let html = "";
      for (const item of enriched) {
        const { hc, projCount, nodeCount, liveOnline, activeCid } = item;
        html += `
          <div class="glass-card client-tile" onclick="navigateTo('history-projects', '${escJs(hc.key)}')">
            <div class="client-tile-header">
              <div class="client-avatar">${escHtml((hc.code || "CL").substring(0, 2))}</div>
              <div style="display:flex; align-items:center; gap:8px;">
                <span class="status-pill ${liveOnline > 0 ? "pill-green" : "pill-cyan"}">${liveOnline > 0 ? `LIVE (${liveOnline} Online)` : "HISTORICAL"}</span>
                ${activeCid ? `<button class="delete-btn-tiny" onclick="event.stopPropagation(); openRenameModal('client', '${escJs(activeCid)}', '${escJs(hc.name)}')" title="Rename Client">${ICONS.edit}</button>` : ""}
                ${activeCid ? `<button class="delete-btn-tiny" onclick="event.stopPropagation(); deleteClient('${escJs(activeCid)}', '${escJs(hc.name)}')" title="Delete Client & History">${ICONS.trash}</button>` : ""}
              </div>
            </div>
            <div class="client-name">${escHtml(hc.name)}</div>
            <div class="client-desc">First seen: ${escHtml(hc.first_seen || "-")} &bull; Last online: ${escHtml(hc.last_seen || "-")}</div>
            <div class="client-metrics-row">
              <div class="metric-col"><div class="metric-val">${projCount}</div><div class="metric-lbl">Projects Seen</div></div>
              <div class="metric-col"><div class="metric-val">${nodeCount}</div><div class="metric-lbl">Nodes Seen</div></div>
              <div class="metric-col"><div class="metric-val" style="color:${liveOnline > 0 ? "#10B981" : "var(--text-muted)"};">${liveOnline}</div><div class="metric-lbl">Online Now</div></div>
            </div>
            <div class="client-footer-btn">
              <span>View Client Projects Page</span>
              <span>&rarr;</span>
            </div>
          </div>
        `;
      }

      if (!html) {
        html = `
          <div class="glass-card" style="grid-column: 1 / -1; text-align:center; padding:32px 24px;">
            <div style="font-size:16px; font-weight:700; color:var(--text-strong); margin-bottom:6px;">No Historical Clients Recorded Yet</div>
            <div style="font-size:13px; color:var(--text-muted);">Once any hardware node connects online via MQTT, its client, project, and node records are stored uniquely here without duplication.</div>
          </div>
        `;
      }

      if (container.dataset.lastHtml !== html) {
        container.dataset.lastHtml = html;
        container.innerHTML = html;
      }
    }

    function renderHistoryProjects() {
      const container = document.getElementById("history-projects-container");
      if (!container) return;
      const h = (fleetData && fleetData.history) ? fleetData.history : { clients: {}, projects: {}, nodes: {} };
      const hc = h.clients ? h.clients[selectedHistoryClientKey] : null;
      const titleEl = document.getElementById("history-client-title");
      const metaEl = document.getElementById("history-client-meta");
      if (titleEl) titleEl.innerText = hc ? `Projects for ${hc.name}` : "Historical Client Projects";
      if (metaEl) metaEl.innerText = hc ? `First seen ${hc.first_seen || "-"} | Last online ${hc.last_seen || "-"}` : "Unique projects seen online under this client.";

      const hProjects = Object.values(h.projects || {}).filter(p => p.client_key === selectedHistoryClientKey);
      const hNodes = Object.values(h.nodes || {});

      const enriched = hProjects.map(hp => {
        const nodes = hNodes.filter(n => n.project_key === hp.key);
        let liveOnline = 0;
        for (const hn of nodes) {
          const found = findLiveNodeByNameOrId(hn.name, hn.mac, hn.chip_id);
          if (found && found.data && found.data.online) liveOnline++;
        }
        const activePid = findActiveProjectId(selectedHistoryClientKey, hp.name);
        return { hp, nodeCount: nodes.length, liveOnline, activePid };
      }).filter(item => {
        if (!globalSearchQuery) return true;
        return `${item.hp.name} ${item.hp.code}`.toLowerCase().includes(globalSearchQuery);
      });

      enriched.sort((a, b) => (b.liveOnline - a.liveOnline) || ((b.hp.last_seen_ts || 0) - (a.hp.last_seen_ts || 0)));

      let html = "";
      for (const item of enriched) {
        const { hp, nodeCount, liveOnline, activePid } = item;
        html += `
          <div class="glass-card project-card" onclick="navigateTo('history-nodes', '${escJs(hp.key)}')">
            <div style="display:flex; justify-content:space-between; margin-bottom:12px; align-items:center;">
              <span class="status-pill pill-cyan">${escHtml(hp.code || "PROJ")}</span>
              <div style="display:flex; align-items:center; gap:8px;">
                <span class="status-pill ${liveOnline > 0 ? "pill-green" : "pill-crimson"}">${liveOnline} / ${nodeCount} Online</span>
                ${activePid ? `<button class="delete-btn-tiny" onclick="event.stopPropagation(); openRenameModal('project', '${escJs(activePid)}', '${escJs(hp.name)}')" title="Rename Project">${ICONS.edit}</button>` : ""}
                ${activePid ? `<button class="delete-btn-tiny" onclick="event.stopPropagation(); deleteProject('${escJs(activePid)}', '${escJs(hp.name)}')" title="Delete Project">${ICONS.trash}</button>` : ""}
              </div>
            </div>
            <div class="client-name">${escHtml(hp.name)}</div>
            <div class="client-desc">First seen: ${escHtml(hp.first_seen || "-")} &bull; Last seen: ${escHtml(hp.last_seen || "-")}</div>
            <div class="client-footer-btn" style="margin-top:16px;">
              <span>View Project Nodes Page (${nodeCount})</span>
              <span>&rarr;</span>
            </div>
          </div>
        `;
      }

      if (!html) {
        html = `
          <div class="glass-card" style="grid-column: 1 / -1; text-align:center; padding:32px 24px;">
            <div style="font-size:15px; font-weight:700; color:var(--text-strong);">No Projects Recorded for This Client</div>
          </div>
        `;
      }

      if (container.dataset.lastHtml !== html) {
        container.dataset.lastHtml = html;
        container.innerHTML = html;
      }
    }

    function renderHistoryNodes() {
      const container = document.getElementById("history-nodes-container");
      if (!container) return;
      const h = (fleetData && fleetData.history) ? fleetData.history : { clients: {}, projects: {}, nodes: {} };
      const hp = h.projects ? h.projects[selectedHistoryProjectKey] : null;
      const titleEl = document.getElementById("history-project-title");
      const metaEl = document.getElementById("history-project-meta");
      if (titleEl) titleEl.innerText = hp ? `Nodes in ${hp.name}` : "Historical Project Nodes";
      if (metaEl) metaEl.innerText = hp ? `Client: ${hp.client_name || "-"} | Last online ${hp.last_seen || "-"}` : "Unique hardware nodes seen under this project.";

      const hNodes = Object.values(h.nodes || {}).filter(n => n.project_key === selectedHistoryProjectKey);
      const enriched = hNodes.map(hn => {
        const liveMatch = findLiveNodeByNameOrId(hn.name, hn.mac, hn.chip_id);
        const liveKey = liveMatch ? liveMatch.key : hn.name;
        const liveData = liveMatch ? liveMatch.data : null;
        return { hn, liveKey, liveData, isOnline: !!(liveData && liveData.online) };
      }).filter(item => {
        if (!globalSearchQuery) return true;
        return `${item.hn.name} ${item.hn.mac} ${item.hn.chip_id} ${item.hn.ip}`.toLowerCase().includes(globalSearchQuery);
      });

      enriched.sort((a, b) => (Number(b.isOnline) - Number(a.isOnline)) || ((b.hn.last_seen_ts || 0) - (a.hn.last_seen_ts || 0)));

      let html = "";
      for (const item of enriched) {
        const { hn, liveKey, liveData, isOnline } = item;
        const boardData = liveData || hn;
        const canOpenDetail = !!(telemetryData.nodes && telemetryData.nodes[liveKey]);
        html += `
          <div class="glass-card node-card" onclick="${canOpenDetail ? `openNodeDetail('${escJs(liveKey)}')` : ""}">
            <div class="node-header">
              <div class="node-title-group">
                ${renderNodeThumb(boardData)}
                <div>
                  <div class="node-name">${escHtml(liveKey)}</div>
                  <div style="font-size:11px; color:var(--text-dim); margin-top:2px;">${escHtml(boardData.mcu_family || "MCU Node")}</div>
                </div>
              </div>
              <div style="display:flex; align-items:center; gap:8px;">
                <span class="status-pill ${isOnline ? "pill-green" : "pill-crimson"}">
                  <span class="pulsing-dot" style="${isOnline ? "" : "background:#EF4444; box-shadow:none;"}"></span> ${isOnline ? "ONLINE" : "OFFLINE"}
                </span>
                ${canOpenDetail ? `<button class="delete-btn-tiny" onclick="event.stopPropagation(); openRenameModal('node', '${escJs(liveKey)}', '${escJs(liveKey)}')" title="Rename Node">${ICONS.edit}</button>` : ""}
                ${canOpenDetail ? `<button class="delete-btn-tiny" onclick="event.stopPropagation(); deleteNode('${escJs(liveKey)}')" title="Delete Node">${ICONS.trash}</button>` : ""}
              </div>
            </div>

            <div class="node-spec-row"><span class="node-spec-lbl">Hardware MAC</span><span class="node-spec-val">${escHtml(boardData.mac || "-")}</span></div>
            <div class="node-spec-row"><span class="node-spec-lbl">eFuse Chip ID</span><span class="node-spec-val">${escHtml(boardData.chip_id || "-")}</span></div>
            <div class="node-spec-row"><span class="node-spec-lbl">Last Known IP</span><span class="node-spec-val" style="color:#0EA5E9;">${escHtml(boardData.ip || "-")}</span></div>
            <div class="node-spec-row"><span class="node-spec-lbl">First Seen Online</span><span class="node-spec-val">${escHtml(hn.first_seen || "-")}</span></div>
            <div class="node-spec-row" style="border:none;"><span class="node-spec-lbl">Last Seen Online</span><span class="node-spec-val">${escHtml(hn.last_seen || "-")}</span></div>

            ${canOpenDetail ? `
              <div style="display: grid; grid-template-columns: ${isOnline ? "1fr 1fr" : "1fr"}; gap: 8px; margin-top: 14px;">
                <button class="btn-main btn-crimson" style="padding: 9px 14px; font-size: 12px; font-weight: 700;" onclick="event.stopPropagation(); openNodeDetail('${escJs(liveKey)}')">
                  ${ICONS.sliders}
                  <span>Open Controls</span>
                </button>
                ${isOnline ? `
                  <button class="btn-main btn-cyan" style="padding: 9px 14px; font-size: 12px; font-weight: 700;" onclick="event.stopPropagation(); openInsituNode('${escJs(liveKey)}')">
                    ${ICONS.globe}
                    <span>Web UI</span>
                  </button>
                ` : ""}
              </div>
            ` : `<div style="font-size:11px; color:var(--text-dim); margin-top:12px;">Historical snapshot (node removed from active queue).</div>`}
          </div>
        `;
      }

      if (!html) {
        html = `
          <div class="glass-card" style="grid-column: 1 / -1; text-align:center; padding:32px 24px;">
            <div style="font-size:15px; font-weight:700; color:var(--text-strong);">No Nodes Recorded for This Project</div>
          </div>
        `;
      }

      if (container.dataset.lastHtml !== html) {
        container.dataset.lastHtml = html;
        container.innerHTML = html;
      }
    }

    function renderClientProjects() {
      const container = document.getElementById("client-projects-container");
      if (!container || !fleetData.projects) return;

      const client = fleetData.clients ? fleetData.clients[selectedClientId] : null;
      const projIds = client ? (client.projects || []) : [];

      let html = "";
      for (const p_id of projIds) {
        const proj = fleetData.projects[p_id];
        if (!proj) continue;
        if (globalSearchQuery && !`${proj.name} ${proj.code} ${proj.description}`.toLowerCase().includes(globalSearchQuery)) continue;

        const numNodes = proj.nodes ? proj.nodes.length : 0;
        let pOnline = 0;
        if (proj.nodes && telemetryData.nodes) {
          for (const n of proj.nodes) {
            if (telemetryData.nodes[n] && telemetryData.nodes[n].online) pOnline++;
          }
        }

        html += `
          <div class="glass-card project-card" onclick="navigateTo('project', '${escJs(p_id)}')">
            <div style="display:flex; justify-content:space-between; margin-bottom:12px; align-items:center;">
              <span class="status-pill pill-cyan">${escHtml(proj.code || "PROJ")}</span>
              <div style="display:flex; align-items:center; gap:8px;">
                <span class="status-pill ${pOnline > 0 ? "pill-green" : "pill-crimson"}">${pOnline} / ${numNodes} Online</span>
                <button class="delete-btn-tiny" onclick="event.stopPropagation(); openRenameModal('project', '${escJs(p_id)}', '${escJs(proj.name)}')" title="Rename Project">${ICONS.edit}</button>
                <button class="delete-btn-tiny" onclick="event.stopPropagation(); deleteProject('${escJs(p_id)}', '${escJs(proj.name)}')" title="Delete Project">${ICONS.trash}</button>
              </div>
            </div>
            <div class="client-name">${escHtml(proj.name)}</div>
            <div class="client-desc">${escHtml(proj.description || "Connected Hardware Project")}</div>
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

      if (container.dataset.lastHtml !== html) {
        container.dataset.lastHtml = html;
        container.innerHTML = html;
      }
    }

    function renderProjectNodes() {
      const container = document.getElementById("project-nodes-container");
      if (!container || !fleetData.projects) return;

      const proj = fleetData.projects[selectedProjectId];
      const nodeNames = proj ? (proj.nodes || []) : [];

      let html = "";
      for (const n_name of nodeNames) {
        const node = telemetryData.nodes ? telemetryData.nodes[n_name] : null;
        if (!node) continue;
        if (globalSearchQuery && !`${n_name} ${node.mac} ${node.ip} ${node.chip_id}`.toLowerCase().includes(globalSearchQuery)) continue;

        const isOnline = !!node.online;

        html += `
          <div class="glass-card node-card" onclick="openNodeDetail('${escJs(n_name)}')">
            <div class="node-header">
              <div class="node-title-group">
                ${renderNodeThumb(node)}
                <div>
                  <div class="node-name">${escHtml(n_name)}</div>
                  <div style="font-size:11px; color:var(--text-dim); margin-top:2px;">${escHtml(node.mcu_family || "MCU Hardware")}</div>
                </div>
              </div>
              <div style="display:flex; align-items:center; gap:8px;">
                <span class="status-pill ${isOnline ? "pill-green" : "pill-crimson"}">
                  <span class="pulsing-dot" style="${isOnline ? "" : "background:#EF4444; box-shadow:none;"}"></span> ${isOnline ? "ONLINE" : "OFFLINE"}
                </span>
                <button class="delete-btn-tiny" onclick="event.stopPropagation(); openRenameModal('node', '${escJs(n_name)}', '${escJs(n_name)}')" title="Rename Node">${ICONS.edit}</button>
                <button class="delete-btn-tiny" onclick="event.stopPropagation(); deleteNode('${escJs(n_name)}')" title="Delete Node">${ICONS.trash}</button>
              </div>
            </div>

            <div class="node-spec-row"><span class="node-spec-lbl">Hardware MAC</span><span class="node-spec-val">${escHtml(node.mac || "-")}</span></div>
            <div class="node-spec-row"><span class="node-spec-lbl">Carrier IP (STA)</span><span class="node-spec-val" style="color:#0EA5E9;">${escHtml(node.ip || "-")}</span></div>
            <div class="node-spec-row"><span class="node-spec-lbl">Wi-Fi Signal (RSSI)</span><span class="node-spec-val">${node.rssi || 0} dBm</span></div>
            <div class="node-spec-row"><span class="node-spec-lbl">Master Service</span><span class="node-spec-val" style="color:${node.service ? "#10B981" : "#D97706"}">${node.service ? "ACTIVE" : "STANDBY"}</span></div>
            <div class="node-spec-row"><span class="node-spec-lbl">Autonomous Offline</span><span class="node-spec-val" style="color:${node.offline ? "#10B981" : "var(--text-muted)"}">${node.offline ? "ENABLED" : "DISABLED"}</span></div>
            <div class="node-spec-row" style="border:none;"><span class="node-spec-lbl">Security Hash</span><span class="node-spec-val" style="color:#10B981;font-size:11px;">SHA-256 Verified</span></div>

            <div style="display: grid; grid-template-columns: 1fr auto auto auto; gap: 8px; margin-top: 14px;">
              <button class="btn-main btn-crimson" style="padding: 9px 12px; font-size: 12px; font-weight: 700; width: 100%; text-align: center;" onclick="event.stopPropagation(); openNodeDetail('${escJs(n_name)}')">
                ${ICONS.sliders}
                <span>Controls</span>
              </button>
              <button class="btn-main btn-cyan" style="padding: 9px 12px; font-size: 12px;" onclick="event.stopPropagation(); openInsituNode('${escJs(n_name)}')" title="Open On-Board Web UI">
                ${ICONS.globe}
              </button>
              <button class="btn-secondary" style="padding: 9px 12px; font-size: 12px;" onclick="event.stopPropagation(); triggerNodePing('${escJs(n_name)}')" title="Ping Node (ACK)">
                ${ICONS.ping}
              </button>
              <button class="btn-secondary" style="padding: 9px 12px; font-size: 12px;" onclick="event.stopPropagation(); triggerNodeReboot('${escJs(n_name)}')" title="Reboot MCU via MQTT">
                ${ICONS.reboot}
              </button>
            </div>
          </div>
        `;
      }

      html += `
        <div class="add-card-btn" onclick="openAddNodeModal()">
          <div class="add-icon-circle">+</div>
          <div style="font-weight:700;">Register Node to Project</div>
          <div style="font-size:11px;color:var(--text-dim);">Assign an edge hardware node</div>
        </div>
      `;

      if (container.dataset.lastHtml !== html) {
        container.dataset.lastHtml = html;
        container.innerHTML = html;
      }
    }

    function updateNodeDetailUI() {
      if (!telemetryData.nodes) return;
      const node = telemetryData.nodes[selectedNodeName];
      if (!node) return;

      document.getElementById("detail-node-name").innerText = selectedNodeName;
      const statusPill = document.getElementById("detail-node-status-pill");
      if (node.online) {
        statusPill.className = "status-pill pill-green";
        statusPill.innerHTML = '<span class="pulsing-dot"></span> ONLINE';
      } else {
        statusPill.className = "status-pill pill-crimson";
        statusPill.innerHTML = '<span class="pulsing-dot" style="background:#EF4444; box-shadow:none;"></span> OFFLINE';
      }

      // Show ESP32-WROOM-32 image ONLY on ESP32 hardware nodes
      const espPhotoWrap = document.getElementById("detail-esp32-photo-wrap");
      if (espPhotoWrap) {
        espPhotoWrap.style.display = isEsp32Node(node) ? "flex" : "none";
      }

      // Quick switcher buttons
      const sw = document.getElementById("node-switcher-container");
      if (sw && telemetryData.nodes) {
        let swHtml = "";
        for (const nName of Object.keys(telemetryData.nodes)) {
          const isSel = (nName === selectedNodeName);
          swHtml += `<button class="${isSel ? "btn-main btn-crimson" : "btn-secondary"}" style="padding: 6px 14px; font-size: 12px;" onclick="openNodeDetail('${escJs(nName)}')">${escHtml(nName)}</button>`;
        }
        sw.innerHTML = swHtml;
      }

      // Hardware Specs & Telemetry
      if (document.getElementById("spec-mac")) document.getElementById("spec-mac").innerText = node.mac || "-";
      if (document.getElementById("spec-chip")) document.getElementById("spec-chip").innerText = node.chip_id || "-";
      if (document.getElementById("spec-ip")) document.getElementById("spec-ip").innerText = node.ip || "-";
      if (document.getElementById("spec-port")) document.getElementById("spec-port").innerText = node.port || "-";
      if (document.getElementById("spec-rssi")) document.getElementById("spec-rssi").innerText = (node.rssi || 0) + " dBm";
      if (document.getElementById("spec-heap")) document.getElementById("spec-heap").innerText = Math.round((node.heap || 0) / 1024) + " KB";
      if (document.getElementById("spec-geo")) document.getElementById("spec-geo").innerText = node.geo_location || "Pune, Maharashtra, India";
      if (document.getElementById("spec-public-ip")) document.getElementById("spec-public-ip").innerText = `${node.public_ip || "WAN IP"} (${node.carrier_isp || "Carrier"})`;
      if (document.getElementById("spec-hash")) document.getElementById("spec-hash").innerText = (node.sec_hash || "").substring(0, 24) + "...";

      // Microcontroller Hardware Profile & Wireless Bands
      if (document.getElementById("spec-mcu-family-pill")) {
        document.getElementById("spec-mcu-family-pill").innerText = node.mcu_family || "ESP32 (Tensilica)";
      }
      if (document.getElementById("spec-mcu-arch")) {
        document.getElementById("spec-mcu-arch").innerText = node.mcu_arch || "Tensilica Xtensa Dual-Core 240MHz";
      }
      if (document.getElementById("spec-mcu-flash")) {
        document.getElementById("spec-mcu-flash").innerText = (node.flash_mb || 4) + " MB SPI Flash";
      }
      if (document.getElementById("spec-mcu-ram")) {
        document.getElementById("spec-mcu-ram").innerText = (node.ram_total_kb || 320) + " KB Total SRAM";
      }
      if (document.getElementById("spec-mcu-antenna")) {
        document.getElementById("spec-mcu-antenna").innerText = node.wireless_bands || "2.4 GHz 802.11 b/g/n + BLE 4.2";
      }

      // Controls (Side-by-side Dual Toggles)
      if (document.getElementById("detail-service-toggle")) document.getElementById("detail-service-toggle").checked = !!node.service;
      if (document.getElementById("detail-offline-toggle")) document.getElementById("detail-offline-toggle").checked = !!node.offline;
      if (document.getElementById("delay-range")) document.getElementById("delay-range").value = node.delay || 0;
      if (document.getElementById("delay-display-val")) document.getElementById("delay-display-val").innerText = (node.delay || 0).toFixed(1) + "s";

      // Legacy POC Hardware Visualizer & Delay box: kept hidden unless explicit legacy POC name
      const pocVis = document.getElementById("poc-visualizer-container");
      const delayBox = document.getElementById("delay-box-container");
      const isLegacyDemo = (node.name === "Node: A" || node.name === "Node: B");
      if (pocVis) pocVis.style.display = isLegacyDemo ? "block" : "none";
      if (delayBox) delayBox.style.display = isLegacyDemo ? "block" : "none";

      // In-situ link
      const insituLink = document.getElementById("detail-insitu-link");
      const insituIp = document.getElementById("detail-insitu-ip");
      if (insituLink && node.ip) insituLink.href = `http://${node.ip}/`;
      if (insituIp && node.ip) insituIp.innerText = node.ip;

      // Update tracker
      if (telemetryData.updates) {
        const u = telemetryData.updates[selectedNodeName];
        const tracker = document.getElementById("detail-tracker");
        if (tracker && u && (u.active || u.stage === "completed" || u.stage === "failed")) {
          tracker.classList.add("visible");
          document.getElementById("tracker-pct").innerText = u.percent + "%";
          document.getElementById("tracker-fill").style.width = u.percent + "%";
          document.getElementById("tracker-status-text").innerText = u.stage_text;
          document.getElementById("tracker-stage-title").innerText = u.route.toUpperCase() + " Deployment: " + u.stage.toUpperCase();
        } else if (tracker) {
          tracker.classList.remove("visible");
        }
      }
    }

    function fetchTelemetry() {
      authedFetch("/api/telemetry")
        .then(r => {
          if (r.status === 401) {
            localStorage.removeItem("anashwar_token");
            sessionStorage.removeItem("anashwar_token");
            window.location.href = "/?logout=true";
            return;
          }
          return r.json();
        })
        .then(data => {
          if (!data) return;
          telemetryData = data;
          fleetData = data.fleet || DEFAULT_FLEET;

          // If a modal is open, skip DOM updates to avoid flickering
          const isModalOpen = !!document.querySelector(".modal-overlay.open");
          if (isModalOpen) return;

          // Update History Sidebar Count
          const hClientsCount = (fleetData.history && fleetData.history.clients) ? Object.keys(fleetData.history.clients).length : 0;
          const histCountEl = document.getElementById("sidebar-history-count");
          if (histCountEl) histCountEl.innerText = String(hClientsCount);

          // Dynamic Sidebar Nodes List (sorted online first)
          const sidebarList = document.getElementById("sidebar-nodes-list");
          const sidebarCount = document.getElementById("sidebar-node-count");
          if (sidebarList && data.nodes) {
            let sHtml = "";
            let sOnline = 0;
            const entries = Object.entries(data.nodes).sort((a, b) => Number(!!b[1].online) - Number(!!a[1].online));
            for (const [nName, nInfo] of entries) {
              const isOnline = !!nInfo.online;
              if (isOnline) sOnline++;
              const dotClass = isOnline ? "online-dot" : "offline-dot";
              const mcu = nInfo.mcu_family || nInfo.mcu_type || "ESP32";
              const isActive = (currentView === "node-detail" && selectedNodeName === nName) ? "active" : "";
              sHtml += `
                <div class="nav-item ${isActive}" onclick="openNodeDetail('${escJs(nName)}')" style="font-size:11.5px; padding:6px 8px; display:flex; justify-content:space-between; align-items:center; cursor:pointer;">
                  <div style="display:flex; align-items:center; gap:6px; overflow:hidden; min-width:0;">
                    <span class="status-dot ${dotClass}" style="width:6px; height:6px; flex-shrink:0;"></span>
                    <span style="font-weight:600; white-space:nowrap; text-overflow:ellipsis; overflow:hidden;">${escHtml(nName)}</span>
                  </div>
                  <span class="status-pill pill-cyan" style="font-size:8.5px; padding:1px 4px; flex-shrink:0;">${escHtml(mcu)}</span>
                </div>
              `;
            }
            if (!entries.length) {
              sHtml = '<div style="font-size:11px; color:var(--text-dim); padding:6px 8px;">No nodes</div>';
            }
            if (sidebarList.dataset.lastHtml !== sHtml) {
              sidebarList.dataset.lastHtml = sHtml;
              sidebarList.innerHTML = sHtml;
            }
            if (sidebarCount) sidebarCount.innerText = `${sOnline} On`;
          }

          // KPI Active live nodes, clients & projects
          let onlineCount = 0;
          if (data.nodes) {
            for (const n of Object.values(data.nodes)) {
              if (n.online) onlineCount++;
            }
          }
          let activeClientsCount = 0;
          let activeProjectsCount = 0;
          if (fleetData.clients && fleetData.projects) {
            for (const cl of Object.values(fleetData.clients)) {
              let clHasOnline = false;
              for (const pid of (cl.projects || [])) {
                const p = fleetData.projects[pid];
                if (p && (p.nodes || []).some(nn => data.nodes && data.nodes[nn] && data.nodes[nn].online)) {
                  clHasOnline = true;
                  activeProjectsCount++;
                }
              }
              if (clHasOnline) activeClientsCount++;
            }
          }
          const kpiEl = document.getElementById("kpi-active-nodes");
          if (kpiEl) {
            const kpiTxt = `${onlineCount} Online`;
            if (kpiEl.innerText !== kpiTxt) kpiEl.innerText = kpiTxt;
          }
          const kpiSubEl = document.getElementById("kpi-active-sub");
          if (kpiSubEl) {
            const subTxt = `${activeClientsCount} Active Client${activeClientsCount === 1 ? "" : "s"} \u2022 ${activeProjectsCount} Live Project${activeProjectsCount === 1 ? "" : "s"}`;
            if (kpiSubEl.innerText !== subTxt) kpiSubEl.innerText = subTxt;
          }

          // Activity logs
          if (data.logs && document.getElementById("activity-log-stream")) {
            const logBox = document.getElementById("activity-log-stream");
            const newLogsHtml = data.logs.map(l => `<div>${escHtml(l)}</div>`).join("");
            if (logBox.dataset.lastLogs !== newLogsHtml) {
              logBox.dataset.lastLogs = newLogsHtml;
              logBox.innerHTML = newLogsHtml;
              logBox.scrollTop = logBox.scrollHeight;
            }
          }

          // Re-render active view
          if (currentView === "dashboard") {
            renderClients();
          } else if (currentView === "history-clients") {
            renderHistoryClients();
          } else if (currentView === "history-projects") {
            renderHistoryProjects();
          } else if (currentView === "history-nodes") {
            renderHistoryNodes();
          } else if (currentView === "client") {
            renderClientProjects();
          } else if (currentView === "project") {
            renderProjectNodes();
          } else if (currentView === "node-detail") {
            updateNodeDetailUI();
          }
        })
        .catch(e => console.error("Telemetry error:", e));
    }

    // Live Animated Particle Mesh Background (Adapts to Dark & Light Mode)
    function initLiveMeshBg() {
      const canvas = document.getElementById("live-mesh-bg");
      if (!canvas || !canvas.getContext) return;
      if (window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;
      const ctx = canvas.getContext("2d");
      let w = 0, h = 0;
      const particles = [];
      const COUNT = 46;

      function resize() {
        w = canvas.width = window.innerWidth;
        h = canvas.height = window.innerHeight;
      }
      window.addEventListener("resize", resize);
      resize();

      for (let i = 0; i < COUNT; i++) {
        particles.push({
          x: Math.random() * w,
          y: Math.random() * h,
          vx: (Math.random() - 0.5) * 0.42,
          vy: (Math.random() - 0.5) * 0.42,
          r: 1.4 + Math.random() * 1.6
        });
      }

      function tick() {
        ctx.clearRect(0, 0, w, h);
        const isLight = (document.documentElement.getAttribute("data-theme") === "light");
        const dotColor = isLight ? "rgba(225, 29, 72, 0.32)" : "rgba(56, 189, 248, 0.45)";
        const lineRgb = isLight ? "14, 165, 233" : "148, 163, 184";
        const maxAlpha = isLight ? 0.16 : 0.14;

        for (let i = 0; i < COUNT; i++) {
          const p = particles[i];
          p.x += p.vx;
          p.y += p.vy;
          if (p.x < 0 || p.x > w) p.vx *= -1;
          if (p.y < 0 || p.y > h) p.vy *= -1;

          ctx.beginPath();
          ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
          ctx.fillStyle = dotColor;
          ctx.fill();

          for (let j = i + 1; j < COUNT; j++) {
            const q = particles[j];
            const dx = p.x - q.x;
            const dy = p.y - q.y;
            const distSq = dx * dx + dy * dy;
            if (distSq < 19600) {
              const a = (1 - Math.sqrt(distSq) / 140) * maxAlpha;
              ctx.beginPath();
              ctx.moveTo(p.x, p.y);
              ctx.lineTo(q.x, q.y);
              ctx.strokeStyle = `rgba(${lineRgb}, ${a.toFixed(3)})`;
              ctx.lineWidth = 1;
              ctx.stroke();
            }
          }
        }
        requestAnimationFrame(tick);
      }
      requestAnimationFrame(tick);
    }

    // Automatic Responsive Display Engine (Touch Screen Phone vs Non-Touch PC/Mac Desktop)
    function getDisplayFormMode() {
      const isTouch = ('ontouchstart' in window) || (navigator.maxTouchPoints > 0) || (window.matchMedia && window.matchMedia('(pointer: coarse)').matches);
      const isNarrow = window.innerWidth <= 860;
      return (isNarrow || isTouch) ? "phone" : "desktop";
    }

    function applyDisplayFormMode() {
      const mode = getDisplayFormMode();
      const body = document.body;
      if (mode === "phone") {
        body.classList.remove("mode-desktop-pc");
        body.classList.add("mode-phone-touch");
      } else {
        body.classList.remove("mode-phone-touch");
        body.classList.add("mode-desktop-pc");
      }
    }

    window.addEventListener("resize", applyDisplayFormMode);
    window.addEventListener("orientationchange", applyDisplayFormMode);

    // Initialize auto display mode, theme toggle, live background & telemetry polling
    applyDisplayFormMode();
    updateThemeButton();
    initLiveMeshBg();
    selectBaseFirmware();

    fetchTelemetry();
    setInterval(fetchTelemetry, 2000);

    if (window.self !== window.top) {
      const banner = document.getElementById("iframe-breakout-banner");
      if (banner) banner.style.display = "flex";
    }
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
