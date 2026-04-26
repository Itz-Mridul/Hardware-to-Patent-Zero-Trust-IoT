import html
import logging
import os
import subprocess
import sys
import threading

from flask import Flask
from scapy.all import DNSQR, IP, sniff


# blockchain_bridge.py lives in the same directory as this script (Iot_Project/).
# Ensure that directory is on sys.path so the import works from any cwd.
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

from blockchain_bridge import hash_event, send_to_blockchain


# --- 1. CONFIGURATION ---

INTERFACE = os.environ.get("GATEWAY_IFACE", "wlan0")
GATEWAY_IP = os.environ.get("GATEWAY_IP", "192.168.1.113")
COMMAND_CENTER_IP = os.environ.get("COMMAND_CENTER_IP", "192.168.1.113")
COMMAND_CENTER_PORT = 5000

BANNED_DOMAINS = ["spacejam.com", "tiktok.com", "facebook.com"]
TRUSTED_IPS = {
    GATEWAY_IP,
    COMMAND_CENTER_IP,
    "8.8.8.8",
}
BLOCKED_IPS = set()

# Reuse SCRIPT_DIR — no need for a separate BASE_DIR variable.
LOG_FILE = os.path.join(SCRIPT_DIR, "gateway.log")


# --- 2. SETUP LOGGING ---

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)


# --- 3. THE COMMAND CENTER (FLASK WEB SERVER) ---

app = Flask(__name__)


@app.route("/")
def index():
    try:
        if os.path.exists(LOG_FILE):
            from collections import deque
            with open(LOG_FILE, "r", encoding="utf-8") as log_file:
                logs = list(deque(log_file, maxlen=50))
        else:
            logs = ["No gateway events logged yet.\n"]

        logs.reverse()

        rows = []
        for log in logs[:50]:
            # Strip trailing whitespace/newlines so they don't produce blank <li> items.
            clean_log = log.strip()
            safe_log = html.escape(clean_log)
            if "BLOCKED" in clean_log or "BAN" in clean_log or "ALERT" in clean_log:
                rows.append(
                    "<li style='color:#ff4d6d;font-weight:bold;margin-bottom:5px;'>"
                    f"{safe_log}</li>"
                )
            else:
                rows.append(f"<li style='margin-bottom:5px;'>{safe_log}</li>")

        return f"""
        <body style="background-color:#1e1e1e;color:#00ff00;font-family:monospace;padding:20px;">
            <h1 style="color:#ff4d6d;">Zero-Trust Command Center</h1>
            <h3>Live Deep Packet Inspection Logs</h3>
            <ul style="list-style-type:none;padding:0;">
                {''.join(rows)}
            </ul>
        </body>
        """
    except Exception as error:
        return f"Dashboard Error: {html.escape(str(error))}", 500


def run_dashboard():
    app.run(
        host="0.0.0.0",
        port=COMMAND_CENTER_PORT,
        debug=False,
        use_reloader=False,
    )


# --- 4. CORE GATEWAY LOGIC ---

def record_on_chain(event_text):
    """Write a security event to the blockchain in a background thread.

    Blockchain transactions can take 1-5 seconds.  Calling this directly
    from the Scapy packet callback would block the capture thread for that
    duration, causing packet loss.  Running it in a daemon thread lets the
    capture loop return immediately.
    """
    def _worker():
        fingerprint = hash_event(event_text)
        receipt = send_to_blockchain(event_text[:64], fingerprint)
        if receipt is None:
            logging.warning("[BLOCKCHAIN] Failed to record event: %s", event_text)
        else:
            logging.info("[BLOCKCHAIN] Event recorded: %s", event_text)

    threading.Thread(target=_worker, daemon=True).start()


def add_firewall_rule(direction, ip_address):
    base_rule = ["sudo", "iptables", "-C", "FORWARD", direction, ip_address, "-j", "DROP"]
    add_rule = ["sudo", "iptables", "-A", "FORWARD", direction, ip_address, "-j", "DROP"]

    check = subprocess.run(base_rule, capture_output=True, text=True)
    if check.returncode == 0:
        return True

    result = subprocess.run(add_rule, capture_output=True, text=True)
    if result.returncode != 0:
        logging.error("[FIREWALL ERROR] %s", result.stderr.strip())
        return False

    return True


def ban_ip(ip_address):
    if ip_address in TRUSTED_IPS or ip_address in BLOCKED_IPS:
        return

    print(f"[FIREWALL] Banning untrusted IP: {ip_address}")
    logging.warning("[FIREWALL BAN] %s", ip_address)

    source_blocked = add_firewall_rule("-s", ip_address)
    destination_blocked = add_firewall_rule("-d", ip_address)

    if source_blocked and destination_blocked:
        BLOCKED_IPS.add(ip_address)
        record_on_chain(f"Firewall ban: {ip_address}")


def is_banned_domain(website):
    website = website.lower().strip(".")
    return any(
        website == banned or website.endswith(f".{banned}")
        for banned in BANNED_DOMAINS
    )


def process_packet(packet):
    if not packet.haslayer(IP):
        return

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst

    if packet.haslayer(DNSQR):
        website = packet[DNSQR].qname.decode("utf-8", errors="ignore").strip(".")

        if is_banned_domain(website):
            print(f"[DPI] BLOCKED: {website}")
            logging.critical("[SECURITY ALERT] Banned domain lookup: %s", website)
            record_on_chain(f"Banned domain lookup: {website}")
        else:
            print(f"[DPI] Lookup: {website}")
            logging.info("[DNS] Lookup: %s", website)

        return

    if src_ip == GATEWAY_IP and dst_ip not in TRUSTED_IPS:
        ban_ip(dst_ip)
    elif dst_ip == GATEWAY_IP and src_ip not in TRUSTED_IPS:
        ban_ip(src_ip)


if __name__ == "__main__":
    print("--- ZERO-TRUST ULTIMATE GATEWAY ACTIVE ---")
    print(f"Watching {INTERFACE}...")
    print(f"Command Center: http://{COMMAND_CENTER_IP}:{COMMAND_CENTER_PORT}")

    threading.Thread(target=run_dashboard, daemon=True).start()
    sniff(iface=INTERFACE, prn=process_packet, store=False)
