#!/usr/bin/env bash
# ============================================================
#  update_network.sh — One-command network switcher
#  Zero-Trust IoT Security Gateway
# ============================================================
#
#  Run this script whenever you switch networks
#  (home WiFi ↔ mobile hotspot ↔ university WiFi etc.)
#
#  Usage:
#    bash update_network.sh <PI_IP> <MAC_IP> <WIFI_SSID> <WIFI_PASSWORD>
#
#  Example (mobile hotspot):
#    bash update_network.sh 192.168.43.105 192.168.43.65 "Mridul_Hotspot" "mypassword"
#
#  Example (home WiFi):
#    bash update_network.sh 192.168.1.113 192.168.1.105 "Mridul" "123456789"
#
#  After running this script:
#    1. bash start_all.sh                   (restart Pi services)
#    2. Reflash all 3 ESP32 boards in Arduino IDE
# ============================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Colours ────────────────────────────────────────────────
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'

# ── Args ───────────────────────────────────────────────────
PI_IP="${1}"
MAC_IP="${2}"
WIFI_SSID="${3}"
WIFI_PASSWORD="${4}"

if [ -z "$PI_IP" ] || [ -z "$MAC_IP" ] || [ -z "$WIFI_SSID" ] || [ -z "$WIFI_PASSWORD" ]; then
    echo ""
    echo -e "${BOLD}Usage:${NC}"
    echo "  bash update_network.sh <PI_IP> <MAC_IP> <WIFI_SSID> <WIFI_PASSWORD>"
    echo ""
    echo -e "${BOLD}Example (mobile hotspot):${NC}"
    echo "  bash update_network.sh 192.168.43.105 192.168.43.65 \"MyHotspot\" \"pass123\""
    echo ""
    echo -e "${BOLD}How to find IPs:${NC}"
    echo "  Pi:  hostname -I           (run on Pi via SSH)"
    echo "  Mac: ipconfig getifaddr en0"
    echo ""
    exit 1
fi

echo ""
echo "============================================================"
echo -e "  ${BOLD}⚡ Zero-Trust Network Switcher${NC}"
echo "============================================================"
echo ""
echo -e "  Pi IP         : ${CYAN}${PI_IP}${NC}"
echo -e "  Mac IP        : ${CYAN}${MAC_IP}${NC}"
echo -e "  WiFi SSID     : ${CYAN}${WIFI_SSID}${NC}"
echo -e "  WiFi Password : ${CYAN}${WIFI_PASSWORD}${NC}"
echo ""

# ── 1. Update .env ─────────────────────────────────────────
echo -e "${CYAN}[1/3] Updating .env ...${NC}"
ENV_FILE="$SCRIPT_DIR/.env"

if [ -f "$ENV_FILE" ]; then
    # Update MQTT_BROKER
    sed -i.bak "s|^MQTT_BROKER=.*|MQTT_BROKER=${PI_IP}|" "$ENV_FILE"
    # Update PI_LOCAL_IP
    sed -i.bak "s|^PI_LOCAL_IP=.*|PI_LOCAL_IP=${PI_IP}|" "$ENV_FILE"
    # Update BLOCKCHAIN_URL
    sed -i.bak "s|^BLOCKCHAIN_URL=.*|BLOCKCHAIN_URL=\"http://${MAC_IP}:7545\"|" "$ENV_FILE"
    # Update MAC_IP
    sed -i.bak "s|^MAC_IP=.*|MAC_IP=${MAC_IP}|" "$ENV_FILE"
    # Update WIFI_SSID
    sed -i.bak "s|^WIFI_SSID=.*|WIFI_SSID=\"${WIFI_SSID}\"|" "$ENV_FILE"
    # Update WIFI_PASSWORD
    sed -i.bak "s|^WIFI_PASSWORD=.*|WIFI_PASSWORD=\"${WIFI_PASSWORD}\"|" "$ENV_FILE"
    rm -f "$ENV_FILE.bak"
    echo -e "  ${GREEN}✅ .env updated${NC}"
else
    echo -e "  ${YELLOW}⚠️  .env not found at $ENV_FILE${NC}"
fi

# ── 2. Update network_config.h (ESP32 firmware) ─────────────
echo -e "${CYAN}[2/3] Updating network_config.h ...${NC}"
NETCFG="$SCRIPT_DIR/network_config.h"

if [ -f "$NETCFG" ]; then
    sed -i.bak "s|#define WIFI_SSID.*|#define WIFI_SSID      \"${WIFI_SSID}\"|" "$NETCFG"
    sed -i.bak "s|#define WIFI_PASSWORD.*|#define WIFI_PASSWORD  \"${WIFI_PASSWORD}\"|" "$NETCFG"
    sed -i.bak "s|#define PI_MQTT_BROKER.*|#define PI_MQTT_BROKER  \"${PI_IP}\"|" "$NETCFG"
    rm -f "$NETCFG.bak"
    echo -e "  ${GREEN}✅ network_config.h updated${NC}"
else
    echo -e "  ${YELLOW}⚠️  network_config.h not found${NC}"
fi

# ── 3. Update truffle-config.js ──────────────────────────────
echo -e "${CYAN}[3/3] Updating truffle-config.js ...${NC}"
TRUFFLE="$SCRIPT_DIR/blockchain/truffle-config.js"

if [ -f "$TRUFFLE" ]; then
    sed -i.bak "s|host: \".*\"|host: \"${MAC_IP}\"|" "$TRUFFLE"
    rm -f "$TRUFFLE.bak"
    echo -e "  ${GREEN}✅ truffle-config.js updated${NC}"
fi

# ── Summary ──────────────────────────────────────────────────
echo ""
echo "============================================================"
echo -e "  ${GREEN}${BOLD}✅ Network config updated!${NC}"
echo ""
echo -e "  ${BOLD}NEXT STEPS:${NC}"
echo ""
echo -e "  ${BOLD}[A] On Raspberry Pi:${NC}"
echo "      1. Connect Pi to WiFi: \"${WIFI_SSID}\""
echo "         sudo nmcli dev wifi connect \"${WIFI_SSID}\" password \"${WIFI_PASSWORD}\""
echo "      2. Verify new IP:"
echo "         hostname -I"
echo "      3. If IP matches ${PI_IP}, restart services:"
echo "         bash start_all.sh"
echo ""
echo -e "  ${BOLD}[B] On Mac (Arduino IDE):${NC}"
echo "      4. Open Arduino IDE"
echo "      5. Reflash ESP32 RFID Gateway:"
echo "         esp32_cam/sentry/esp32_rfid_gateway/esp32_rfid_gateway.ino"
echo "      6. Reflash ESP32-CAM Surveillance:"
echo "         esp32_cam/sentry/esp32_cam_surveillance/esp32_cam_surveillance.ino"
echo "      7. Reflash Rogue Skimmer (optional):"
echo "         esp32_gateway/rogue_skimmer/esp32_rogue_skimmer.ino"
echo ""
echo -e "  ${BOLD}[C] Open Dashboard:${NC}"
echo "      http://${PI_IP}:5001"
echo ""
echo "  Logs: tail -f logs/iot_server.log"
echo "============================================================"
echo ""
