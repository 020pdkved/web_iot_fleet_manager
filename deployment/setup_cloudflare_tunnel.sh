#!/bin/bash
# ==============================================================================
# Anashwar Technologies - Mac Cloudflare Tunnel Setup for manage.anashwartech.com
# ==============================================================================

set -e

echo "=== [1/4] Checking cloudflared ==="
if ! command -v cloudflared &> /dev/null; then
    echo "Installing cloudflared via Homebrew..."
    brew install cloudflared
fi

echo "=== [2/4] Authenticating with Cloudflare ==="
echo "Please log in to your Cloudflare account in the browser window that opens:"
cloudflared tunnel login

echo "=== [3/4] Creating Tunnel 'anashwar-fleet' ==="
TUNNEL_OUTPUT=$(cloudflared tunnel create anashwar-fleet 2>&1 || true)
echo "$TUNNEL_OUTPUT"

TUNNEL_ID=$(echo "$TUNNEL_OUTPUT" | grep -oE '[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}' | head -n 1)

if [ -z "$TUNNEL_ID" ]; then
    echo "Fetching existing tunnel ID..."
    TUNNEL_ID=$(cloudflared tunnel list | grep 'anashwar-fleet' | awk '{print $1}')
fi

echo "Tunnel ID: $TUNNEL_ID"

mkdir -p ~/.cloudflared
cat <<EOF > ~/.cloudflared/config.yml
tunnel: $TUNNEL_ID
credentials-file: /Users/$USER/.cloudflared/$TUNNEL_ID.json

ingress:
  - hostname: manage.anashwartech.com
    service: http://localhost:8080
  - hostname: www.manage.anashwartech.com
    service: http://localhost:8080
  - service: http_status:404
EOF

echo "=== [4/4] Configuration Complete! ==="
echo ""
echo ">> IMPORTANT: Add this CNAME record to GoDaddy DNS for anashwartech.com:"
echo "   Type   : CNAME"
echo "   Name   : manage"
echo "   Value  : $TUNNEL_ID.cfargotunnel.com"
echo "   TTL    : 1 Hour"
echo ""
echo "To run the tunnel now, execute:"
echo "   cloudflared tunnel run anashwar-fleet"

