#!/bin/bash
# ==============================================================================
# Anashwar Technologies - Production Ubuntu Server Setup Script
# Run this on your server (157.173.219.70) as root or with sudo
# ==============================================================================

set -e

echo "=== [1/5] Installing Dependencies ==="
apt update
apt install -y python3 python3-pip nginx certbot python3-certbot-nginx

echo "=== [2/5] Setting up Fleet Directory ==="
mkdir -p /opt/anashwar-fleet
cp -r web_portal.py binaries static fleet_registry.json /opt/anashwar-fleet/ 2>/dev/null || true

echo "=== [3/5] Configuring systemd Service ==="
cp deployment/anashwar-fleet.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now anashwar-fleet

echo "=== [4/5] Configuring Nginx ==="
cp deployment/nginx_manage.anashwartech.com.conf /etc/nginx/sites-available/manage.anashwartech.com
ln -sf /etc/nginx/sites-available/manage.anashwartech.com /etc/nginx/sites-enabled/
nginx -t
systemctl reload nginx

echo "=== [5/5] Provisioning SSL with Let's Encrypt ==="
certbot --nginx -d manage.anashwartech.com -d www.manage.anashwartech.com --non-interactive --agree-tos -m admin@anashwartech.com --redirect || echo "Note: Run certbot manually once GoDaddy DNS propagates."

echo "=== DONE! Anashwar Fleet is live at https://manage.anashwartech.com ==="

