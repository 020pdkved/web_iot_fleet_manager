#!/usr/bin/env python3
import subprocess
import time
import re
import os

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
TUNNEL_FILE = os.path.join(PROJECT_ROOT, "active_tunnel.txt")

print("[TUNNEL] Starting persistent localhost.run reverse tunnel on 127.0.0.1:8080...")

while True:
    try:
        cmd = [
            "ssh",
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "ServerAliveInterval=15",
            "-o", "ServerAliveCountMax=4",
            "-R", "80:127.0.0.1:8080",
            "nokey@localhost.run"
        ]
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)

        url_found = False
        while True:
            line = proc.stdout.readline()
            if not line:
                break
            line_str = line.strip()
            if not url_found and (".lhr.life" in line_str or ".lhr.rocks" in line_str):
                match = re.search(r"https://[a-zA-Z0-9\.\-]+", line_str)
                if match:
                    url = match.group(0)
                    print(f"[TUNNEL] Active Public HTTPS Tunnel: {url}", flush=True)
                    with open(TUNNEL_FILE, "w") as f:
                        f.write(url)
                    url_found = True

        proc.wait()
        print("[TUNNEL] Connection closed by server. Reconnecting in 3s...", flush=True)
        time.sleep(3)
    except Exception as e:
        print(f"[TUNNEL] Exception: {e}. Retrying in 5s...", flush=True)
        time.sleep(5)
