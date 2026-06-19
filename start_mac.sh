#!/usr/bin/env bash
# ============================================================
#  start_mac.sh — Zero-Trust IoT  |  Run on your MAC only
# ============================================================
#  Usage:  bash start_mac.sh
# ============================================================

GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'; BOLD='\033[1m'; NC='\033[0m'

MAC_IP=$(ipconfig getifaddr en0 2>/dev/null || ipconfig getifaddr en1 2>/dev/null || echo "localhost")

echo ""
echo "============================================================"
echo -e "  ${BOLD}⚡ Zero-Trust IoT — MAC STARTUP${NC}"
echo "============================================================"
echo ""

# ── 1. Open Ganache GUI ───────────────────────────────────────
echo -e "${CYAN}[1/2] Starting Ganache blockchain...${NC}"
if [ -d "/Applications/Ganache.app" ]; then
    open /Applications/Ganache.app
    echo -e "${GREEN}✅ Ganache.app launched — RPC: http://${MAC_IP}:7545${NC}"
else
    echo -e "${YELLOW}⚠️  Ganache.app not found — trying npx ganache...${NC}"
    pkill -f "ganache" 2>/dev/null || true
    nohup npx ganache --port 7545 --host 0.0.0.0 --chain.networkId 5777 \
        > /tmp/ganache.log 2>&1 &
    echo -e "${GREEN}✅ Ganache CLI started — RPC: http://${MAC_IP}:7545${NC}"
fi

sleep 3

# ── 2. Update .env with current MAC IP ───────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="$SCRIPT_DIR/.env"

if [ -f "$ENV_FILE" ]; then
    # Replace BLOCKCHAIN_URL with current IP
    sed -i '' "s|BLOCKCHAIN_URL=.*|BLOCKCHAIN_URL=\"http://${MAC_IP}:7545\"|" "$ENV_FILE"
    echo -e "${GREEN}✅ .env updated: BLOCKCHAIN_URL=http://${MAC_IP}:7545${NC}"

    # Copy updated .env to Pi
    PI_IP=$(grep "^PI_LOCAL_IP" "$ENV_FILE" | cut -d= -f2 | tr -d '"')
    PI_USER="${PI_SSH_USER:-mridul}"
    if [ -n "$PI_IP" ]; then
        echo -e "${CYAN}[2/2] Syncing .env to Pi (${PI_USER}@${PI_IP})...${NC}"
        scp -O "$ENV_FILE" "${PI_USER}@${PI_IP}:~/Master_IoT_Project/.env" 2>/dev/null \
            && scp -O "$ENV_FILE" "${PI_USER}@${PI_IP}:~/Master_IoT_Project/pi_backend/.env" 2>/dev/null \
            && echo -e "${GREEN}✅ .env synced to Pi${NC}" \
            || echo -e "${YELLOW}⚠️  Could not sync .env to Pi — do it manually if IP changed${NC}"
    fi
fi

# ── Summary ───────────────────────────────────────────────────
echo ""
echo "============================================================"
echo -e "  ${GREEN}${BOLD}MAC is ready!${NC}"
echo ""
echo -e "  Ganache RPC  → ${BOLD}http://${MAC_IP}:7545${NC}"
echo -e "  Your MAC IP  → ${BOLD}${MAC_IP}${NC}"
echo ""
echo -e "  ${YELLOW}Now run on Raspberry Pi:${NC}"
echo -e "    ${BOLD}bash ~/Master_IoT_Project/start_all.sh${NC}"
echo "============================================================"
echo ""
