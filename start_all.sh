#!/usr/bin/env bash
# ============================================================
#  start_all.sh — Zero-Trust IoT Security Gateway Startup
#  v2 — Phase 2 Full Stack (4 services)
# ============================================================
#  Run on the Raspberry Pi:  bash start_all.sh
#
#  Required env vars (set in ~/.bashrc or export before running):
#    TELEGRAM_BOT_TOKEN   — optional but recommended
#    TELEGRAM_CHAT_ID     — optional
#    REAL_PIN             — admin PIN for Honey-PIN system
#    MQTT_BROKER          — defaults to localhost
#    IOT_DB_PATH          — defaults to pi_backend/security.db
#    ENABLE_BLOCKCHAIN    — "true" to submit to Ganache
# ============================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV="$SCRIPT_DIR/.venv/bin/activate"
LOG_DIR="$SCRIPT_DIR/logs"

GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BOLD='\033[1m'
NC='\033[0m'

mkdir -p "$LOG_DIR"

echo ""
echo "============================================================"
echo -e "  ${BOLD}⚡ Zero-Trust IoT Security Gateway${NC}"
echo    "  Hardware-to-Patent — Full Stack Startup"
echo "============================================================"
echo ""

# ── Virtual environment ────────────────────────────────────────
if [ -f "$VENV" ]; then
    source "$VENV"
    echo -e "${GREEN}✅ Virtual environment activated${NC}"
else
    echo -e "${YELLOW}⚠️  No .venv found — using system Python${NC}"
fi

# ── Hardware attestation check ─────────────────────────────────
echo ""
echo -e "${CYAN}[BOOT] Running hardware attestation...${NC}"
python3 -c "
import sys
sys.path.insert(0, '.')
from pi_backend.hardware_attestation import HardwareAttestor
a = HardwareAttestor()
r = a.verify()
if r['passed']:
    print('  ✅ Hardware signature verified — no Trojan components detected.')
else:
    print('  ⚠️  HARDWARE ATTESTATION ISSUES:')
    for alert in r['alerts']:
        if 'golden record' in alert.lower():
            print('      ℹ️  First boot — enrolling golden record...')
            a.enroll()
        else:
            print(f'      ❌ {alert}')
" || echo -e "${YELLOW}  Attestation skipped (library not available)${NC}"

# ── Kill any stale processes ───────────────────────────────────
echo ""
echo -e "${CYAN}Stopping any existing services...${NC}"
pkill -f "pi_backend/iot_server.py"  2>/dev/null || true
pkill -f "pi_backend/dashboard.py"   2>/dev/null || true
pkill -f "defense_sensors.py"        2>/dev/null || true
pkill -f "telegram_alert.py"         2>/dev/null || true
sleep 1

# ── Honey-PIN initialisation ───────────────────────────────────
if [ -n "$REAL_PIN" ]; then
    echo -e "${GREEN}✅ Honey-PIN system will be initialised from REAL_PIN env var${NC}"
else
    echo -e "${YELLOW}⚠️  REAL_PIN not set — Honey-PIN running in demo mode (PIN=1234)${NC}"
    export REAL_PIN="1234"
fi

# ── Generate MQTTS certs if missing ───────────────────────────
if [ ! -f "$SCRIPT_DIR/certs/ca.crt" ]; then
    echo -e "${CYAN}[CERTS] Generating MQTTS certificates...${NC}"
    python3 "$SCRIPT_DIR/pi_backend/mqtts_config.py" \
        --generate \
        --out "$SCRIPT_DIR/certs" \
        --pi-ip "${PI_IP:-192.168.1.109}" \
        --devices esp32_cam esp32_gateway pi_backend \
    && echo -e "${GREEN}✅ TLS certificates generated in ./certs/${NC}" \
    || echo -e "${YELLOW}⚠️  Cert generation skipped (openssl not found)${NC}"
fi

# ── Launch services ────────────────────────────────────────────
echo ""
echo -e "${CYAN}[1/4] Starting IoT Telemetry + AI Server (port 5005)...${NC}"
nohup python3 "$SCRIPT_DIR/pi_backend/iot_server.py" \
    > "$LOG_DIR/iot_server.log" 2>&1 &
IOT_PID=$!
sleep 1

echo -e "${CYAN}[2/4] Starting Physical Defense Sensors (SW-420 + DHT22)...${NC}"
nohup python3 "$SCRIPT_DIR/pi_backend/defense_sensors.py" \
    > "$LOG_DIR/defense_sensors.log" 2>&1 &
SENSOR_PID=$!

echo -e "${CYAN}[3/4] Starting Security Dashboard (port 5001)...${NC}"
nohup python3 -c "
import sys; sys.path.insert(0,'.')
from pi_backend.dashboard import app
import os
app.run(host='0.0.0.0', port=int(os.environ.get('DASHBOARD_PORT','5001')), debug=False)
" > "$LOG_DIR/dashboard.log" 2>&1 &
DASH_PID=$!

echo -e "${CYAN}[4/4] Starting Telegram Alert Service...${NC}"
if [ -n "$TELEGRAM_BOT_TOKEN" ] && [ -n "$TELEGRAM_CHAT_ID" ]; then
    nohup python3 "$SCRIPT_DIR/pi_backend/telegram_alert.py" \
        > "$LOG_DIR/telegram.log" 2>&1 &
    TG_PID=$!
    echo -e "${GREEN}✅ Telegram alerts active${NC}"
else
    echo -e "${YELLOW}⚠️  Telegram skipped — set TELEGRAM_BOT_TOKEN + TELEGRAM_CHAT_ID${NC}"
    TG_PID="—"
fi

sleep 2

# ── Summary ────────────────────────────────────────────────────
echo ""
echo "============================================================"
echo -e "  ${GREEN}${BOLD}All services running!${NC}"
echo ""
echo -e "  IoT + AI Engine  → ${BOLD}port 5005${NC}   (PID $IOT_PID)"
echo -e "  Defense Sensors  → ${BOLD}background${NC} (PID $SENSOR_PID)"
echo -e "  Dashboard        → ${BOLD}http://$(hostname -I | awk '{print $1}'):5001${NC}  (PID $DASH_PID)"
echo -e "  Telegram Alerts  → (PID $TG_PID)"
echo ""
echo "  Logs → $LOG_DIR/"
echo ""
echo "  ATTACKS:"
echo "    Press button on Rogue ESP32  → watch dashboard Threat Radar turn RED"
echo "    Shake the Pironman case      → watch SW-420 wipe keys instantly"
echo ""
echo "  RUN FULL TEST SUITE:"
echo "    python3 -m pytest tests/ -v"
echo ""
echo "  STOP ALL:"
echo "    pkill -f iot_server.py; pkill -f dashboard.py; pkill -f defense_sensors.py"
echo "============================================================"
echo ""
