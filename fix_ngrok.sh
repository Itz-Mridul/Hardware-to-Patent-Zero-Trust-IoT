#!/usr/bin/env bash
# fix_ngrok.sh - Authenticate and launch ngrok in the background

if [ -z "$1" ]; then
    echo "Usage: bash fix_ngrok.sh <YOUR_NGROK_TOKEN>"
    exit 1
fi

TOKEN=$1

echo "[*] Authenticating ngrok..."
ngrok config add-authtoken "$TOKEN"

echo "[*] Killing existing ngrok processes..."
killall ngrok 2>/dev/null || true

echo "[*] Starting ngrok on port 5001 in the background..."
nohup ngrok http 5001 > /dev/null 2>&1 &

echo "[*] Waiting for tunnel to establish..."
sleep 3

URL=$(curl -s http://localhost:4040/api/tunnels | grep -o "https://[a-zA-Z0-9.-]*\.ngrok-free.app" | head -n 1)

if [ -z "$URL" ]; then
    echo "[!] Could not fetch URL. Check ngrok dashboard."
else
    echo "[✅] Tunnel established! Your public link is: $URL"
fi
