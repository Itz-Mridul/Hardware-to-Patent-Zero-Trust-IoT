#!/usr/bin/env python3
"""
Zero-Trust IoT Security Dashboard
===================================
"Single Pane of Glass" — Flask web app that displays:
  • Live trust score gauges for every ESP32 node
  • Real-time attack event feed
  • Blockchain / forensic evidence log
  • Thermal alerts panel
  • Live MJPEG stream placeholder

Run:
    python3 pi_backend/dashboard.py

Then open http://localhost:5000 in your browser.
"""

import json
import os
import sqlite3
import time
from pathlib import Path

try:
    from flask import Flask, Response, jsonify, render_template_string, stream_with_context
except ImportError:
    raise SystemExit("Flask is required: pip install flask")

from pi_backend.forensic_logger import get_recent_access_log
from pi_backend.photo_store import load_device_photo
from pi_backend.photo_store import store_device_photo as persist_device_photo
from pi_backend.thermal_monitor import get_thermal_alerts

# Photo storage: latest JPEG per device (populated by MQTT photo handler)
_latest_photos: dict = {}   # {device_id: bytes}

def store_device_photo(device_id: str, jpeg_bytes: bytes) -> None:
    """Called by the MQTT handler when a photo payload arrives."""
    _latest_photos[device_id] = jpeg_bytes
    persist_device_photo(device_id, jpeg_bytes)

_BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("IOT_DB_PATH", os.path.join(_BASE_DIR, "security.db"))

app = Flask(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# HTML Template — Dark Mode Single-Page Dashboard
# ─────────────────────────────────────────────────────────────────────────────

DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Zero-Trust IoT Gateway — Security Dashboard</title>
  <meta name="description" content="Real-time Zero-Trust IoT Security monitoring dashboard with AI hardware fingerprinting and blockchain forensic evidence logging." />
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;700&family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet" />
  <style>
    :root {
      --bg:        #0d0f14;
      --surface:   #161b27;
      --border:    #1f2937;
      --text:      #e2e8f0;
      --muted:     #64748b;
      --green:     #10b981;
      --yellow:    #f59e0b;
      --red:       #ef4444;
      --blue:      #3b82f6;
      --cyan:      #06b6d4;
      --purple:    #8b5cf6;
      --radius:    12px;
      --shadow:    0 4px 24px rgba(0,0,0,.4);
    }

    * { box-sizing: border-box; margin: 0; padding: 0; }

    body {
      background: var(--bg);
      color: var(--text);
      font-family: 'Inter', sans-serif;
      min-height: 100vh;
    }

    /* ── HEADER ── */
    header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 1.25rem 2rem;
      background: var(--surface);
      border-bottom: 1px solid var(--border);
      position: sticky;
      top: 0;
      z-index: 100;
    }
    header h1 {
      font-size: 1.1rem;
      font-weight: 700;
      letter-spacing: -.3px;
      background: linear-gradient(90deg, var(--cyan), var(--blue));
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
    }
    .status-pill {
      display: flex;
      align-items: center;
      gap: .5rem;
      font-size: .8rem;
      color: var(--muted);
    }
    .dot {
      width: 8px; height: 8px;
      border-radius: 50%;
      background: var(--green);
      animation: pulse 2s infinite;
    }
    @keyframes pulse {
      0%,100% { opacity: 1; } 50% { opacity: .4; }
    }

    /* ── LAYOUT ── */
    main {
      display: grid;
      grid-template-columns: 1fr 1fr 1fr;
      gap: 1.25rem;
      padding: 1.5rem 2rem;
      max-width: 1400px;
      margin: 0 auto;
    }
    .card {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      padding: 1.25rem 1.5rem;
      box-shadow: var(--shadow);
    }
    .card-wide { grid-column: span 2; }
    .card-full { grid-column: span 3; }
    .card h2 {
      font-size: .75rem;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 1px;
      color: var(--muted);
      margin-bottom: 1rem;
    }

    /* ── TRUST GAUGES ── */
    .device-list { display: flex; flex-direction: column; gap: .85rem; }
    .device-row { display: flex; flex-direction: column; gap: .3rem; }
    .device-meta {
      display: flex;
      justify-content: space-between;
      font-size: .8rem;
    }
    .device-id { font-family: 'JetBrains Mono', monospace; font-size: .75rem; }
    .trust-bar {
      height: 8px;
      border-radius: 99px;
      background: var(--border);
      overflow: hidden;
    }
    .trust-fill {
      height: 100%;
      border-radius: 99px;
      transition: width .6s ease, background .6s ease;
    }

    /* ── ATTACK COUNTER ── */
    .counter-grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 1rem;
    }
    .counter-item {
      background: rgba(255,255,255,.03);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: .85rem 1rem;
      text-align: center;
    }
    .counter-num {
      font-size: 2.2rem;
      font-weight: 700;
      font-family: 'JetBrains Mono', monospace;
    }
    .counter-label { font-size: .7rem; color: var(--muted); margin-top: .2rem; }

    /* ── EVENT FEED ── */
    .feed { max-height: 280px; overflow-y: auto; display: flex; flex-direction: column; gap: .5rem; }
    .feed::-webkit-scrollbar { width: 4px; }
    .feed::-webkit-scrollbar-track { background: transparent; }
    .feed::-webkit-scrollbar-thumb { background: var(--border); border-radius: 99px; }
    .event-row {
      display: flex;
      align-items: flex-start;
      gap: .75rem;
      padding: .6rem .75rem;
      border-radius: 8px;
      background: rgba(255,255,255,.03);
      font-size: .78rem;
      animation: fadeIn .4s ease;
    }
    @keyframes fadeIn { from { opacity: 0; transform: translateY(-4px); } to { opacity: 1; } }
    .event-badge {
      font-size: .65rem;
      font-weight: 700;
      padding: .2rem .5rem;
      border-radius: 4px;
      white-space: nowrap;
    }
    .badge-auth   { background: rgba(16,185,129,.15); color: var(--green); }
    .badge-reject { background: rgba(239,68,68,.15);  color: var(--red); }
    .badge-warn   { background: rgba(245,158,11,.15); color: var(--yellow); }
    .badge-therm  { background: rgba(239,68,68,.25);  color: #ff6060; }
    .event-device { font-family: 'JetBrains Mono', monospace; color: var(--cyan); }
    .event-reason { color: var(--muted); font-size: .72rem; margin-top: .15rem; }
    .event-time   { font-size: .65rem; color: var(--muted); margin-left: auto; white-space: nowrap; }

    /* ── EVIDENCE TABLE ── */
    .evidence-table { width: 100%; border-collapse: collapse; font-size: .78rem; }
    .evidence-table th {
      text-align: left; padding: .5rem .75rem;
      color: var(--muted); font-size: .68rem; text-transform: uppercase;
      border-bottom: 1px solid var(--border);
    }
    .evidence-table td { padding: .55rem .75rem; border-bottom: 1px solid rgba(255,255,255,.04); }
    .evidence-table tr:hover td { background: rgba(255,255,255,.03); }
    .hash { font-family: 'JetBrains Mono', monospace; font-size: .68rem; color: var(--purple); }

    /* ── SYSTEM STATS ── */
    .stats-row { display: flex; gap: 1rem; flex-wrap: wrap; }
    .stat-chip {
      background: rgba(255,255,255,.04);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: .5rem 1rem;
      font-size: .78rem;
    }
    .stat-chip span { color: var(--cyan); font-weight: 600; }

    /* ── REFRESH NOTE ── */
    footer {
      text-align: center;
      color: var(--muted);
      font-size: .72rem;
      padding: 1.5rem;
    }
  </style>
</head>
<body>
  <header>
    <h1>⚡ Zero-Trust IoT Security Gateway</h1>
    <div class="status-pill">
      <div class="dot"></div>
      <span id="clock">—</span>
    </div>
  </header>

  <main>
    <!-- Attack counters -->
    <div class="card">
      <h2>🛡️ Threat Summary</h2>
      <div class="counter-grid">
        <div class="counter-item">
          <div class="counter-num" id="cnt-total" style="color:var(--blue)">—</div>
          <div class="counter-label">Total Events</div>
        </div>
        <div class="counter-item">
          <div class="counter-num" id="cnt-rejected" style="color:var(--red)">—</div>
          <div class="counter-label">Blocked Today</div>
        </div>
        <div class="counter-item">
          <div class="counter-num" id="cnt-auth" style="color:var(--green)">—</div>
          <div class="counter-label">Authenticated</div>
        </div>
        <div class="counter-item">
          <div class="counter-num" id="cnt-thermal" style="color:var(--yellow)">—</div>
          <div class="counter-label">Thermal Alerts</div>
        </div>
      </div>
    </div>

    <!-- Device trust gauges -->
    <div class="card card-wide">
      <h2>📡 Node Trust Scores</h2>
      <div class="device-list" id="device-list">
        <p style="color:var(--muted);font-size:.8rem">Loading device data…</p>
      </div>
    </div>

    <!-- Live event feed -->
    <div class="card card-full">
      <h2>🔴 Live Security Feed</h2>
      <div class="feed" id="event-feed">
        <p style="color:var(--muted);font-size:.8rem">Waiting for events…</p>
      </div>
    </div>

    <!-- Forensic evidence log -->
    <div class="card card-full">
      <h2>⛓️ Forensic Evidence Log (Blockchain-Ready)</h2>
      <div style="overflow-x:auto">
        <table class="evidence-table">
          <thead>
            <tr>
              <th>Time</th>
              <th>Device</th>
              <th>Result</th>
              <th>Trust Score</th>
              <th>Reason</th>
              <th>SHA-256 Hash</th>
              <th>On-Chain TX</th>
            </tr>
          </thead>
          <tbody id="evidence-tbody">
            <tr><td colspan="7" style="color:var(--muted)">Loading…</td></tr>
          </tbody>
        </table>
      </div>
    </div>
  </main>

  <footer>Auto-refreshes every 3 s &nbsp;|&nbsp; Zero-Trust IoT Security Gateway &nbsp;|&nbsp; Hardware-to-Patent</footer>

  <script>
    // ── Clock ──
    function tick() {
      document.getElementById('clock').textContent = new Date().toLocaleTimeString();
    }
    setInterval(tick, 1000); tick();

    // ── Helpers ──
    function fmt(ts) {
      return new Date(ts * 1000).toLocaleTimeString();
    }
    function trustColor(score) {
      if (score >= 75) return 'var(--green)';
      if (score >= 50) return 'var(--yellow)';
      return 'var(--red)';
    }
    function badgeClass(result) {
      if (result === 'AUTHENTICATED') return 'badge-auth';
      if (result === 'REJECTED')      return 'badge-reject';
      if (result === 'EMERGENCY_THERMAL') return 'badge-therm';
      return 'badge-warn';
    }
    function truncHash(h) {
      return h ? h.substring(0, 14) + '…' : '—';
    }

    // ── Device gauges ──
    async function refreshDevices() {
      try {
        const r = await fetch('/api/devices');
        const devices = await r.json();
        const el = document.getElementById('device-list');
        if (!devices.length) {
          el.innerHTML = '<p style="color:var(--muted);font-size:.8rem">No devices seen yet.</p>';
          return;
        }
        el.innerHTML = devices.map(d => {
          const score = Math.max(0, Math.min(100, d.trust_score));
          const color = trustColor(score);
          const status = d.status || 'UNKNOWN';
          return `
            <div class="device-row">
              <div class="device-meta">
                <span class="device-id">${d.device_id}</span>
                <span style="color:${color};font-weight:600">${score.toFixed(1)} / 100</span>
              </div>
              <div class="trust-bar">
                <div class="trust-fill" style="width:${score}%;background:${color}"></div>
              </div>
              <div style="font-size:.68rem;color:var(--muted)">
                Status: <span style="color:${color}">${status}</span>
                &nbsp;· IPD: ${d.last_ipd ?? '—'}ms
                &nbsp;· RSSI: ${d.last_rssi ?? '—'}dBm
                &nbsp;· Last seen: ${d.last_seen ? fmt(d.last_seen) : '—'}
              </div>
            </div>
          `;
        }).join('');
      } catch(e) { console.error('Device refresh failed', e); }
    }

    // ── Counters + Feed ──
    async function refreshFeed() {
      try {
        const r = await fetch('/api/events?limit=30');
        const data = await r.json();

        document.getElementById('cnt-total').textContent    = data.total;
        document.getElementById('cnt-rejected').textContent = data.rejected;
        document.getElementById('cnt-auth').textContent     = data.authenticated;
        document.getElementById('cnt-thermal').textContent  = data.thermal;

        const feed = document.getElementById('event-feed');
        if (!data.events.length) {
          feed.innerHTML = '<p style="color:var(--muted);font-size:.8rem">No events yet.</p>';
          return;
        }
        feed.innerHTML = data.events.map(e => `
          <div class="event-row">
            <span class="event-badge ${badgeClass(e.result)}">${e.result}</span>
            <div style="flex:1;min-width:0">
              <div class="event-device">${e.device_id}</div>
              <div class="event-reason">${e.reason || '—'}</div>
            </div>
            <span class="event-time">${fmt(e.timestamp)}</span>
          </div>
        `).join('');
      } catch(e) { console.error('Feed refresh failed', e); }
    }

    // ── Evidence table ──
    async function refreshEvidence() {
      try {
        const r = await fetch('/api/evidence?limit=20');
        const rows = await r.json();
        const tbody = document.getElementById('evidence-tbody');
        if (!rows.length) {
          tbody.innerHTML = '<tr><td colspan="7" style="color:var(--muted)">No evidence logged yet.</td></tr>';
          return;
        }
        tbody.innerHTML = rows.map(row => {
          const color = row.result === 'AUTHENTICATED' ? 'var(--green)' :
                        row.result === 'REJECTED'      ? 'var(--red)' : 'var(--yellow)';
          return `
            <tr>
              <td>${fmt(row.timestamp)}</td>
              <td class="device-id">${row.device_id}</td>
              <td style="color:${color};font-weight:600">${row.result}</td>
              <td>${row.trust_score != null ? row.trust_score.toFixed(1) : '—'}</td>
              <td style="color:var(--muted)">${row.reason || '—'}</td>
              <td class="hash" title="${row.event_hash}">${truncHash(row.event_hash)}</td>
              <td class="hash">${row.on_chain_tx ? truncHash(row.on_chain_tx) : '<span style=color:var(--muted)>Pending</span>'}</td>
            </tr>
          `;
        }).join('');
      } catch(e) { console.error('Evidence refresh failed', e); }
    }

    function refreshAll() {
      refreshDevices();
      refreshFeed();
      refreshEvidence();
    }

    refreshAll();
    setInterval(refreshAll, 3000);
  </script>
</body>
</html>
"""


# ─────────────────────────────────────────────────────────────────────────────
# API Endpoints
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template_string(DASHBOARD_HTML)


@app.route("/api/devices")
def api_devices():
    """Returns all known device statuses."""
    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                """
                SELECT device_id, status, trust_score, last_seen,
                       last_rssi, last_ipd, connection_state
                FROM device_status
                ORDER BY last_seen DESC
                """
            ).fetchall()
        return jsonify([dict(r) for r in rows])
    except sqlite3.OperationalError:
        return jsonify([])


@app.route("/api/events")
def api_events():
    """Returns recent access log events + summary counters."""
    from flask import request as req
    limit = int(req.args.get("limit", 50))
    events = get_recent_access_log(limit)
    thermal = get_thermal_alerts(limit)

    # Merge and sort thermal alerts into the event feed
    for t in thermal:
        events.append({
            "device_id": t["device_id"],
            "result": "EMERGENCY_THERMAL",
            "reason": t["details"],
            "trust_score": None,
            "timestamp": t["timestamp"],
        })
    events.sort(key=lambda e: e.get("timestamp", 0), reverse=True)

    # Counters
    all_events = get_recent_access_log(10000)
    today_start = int(time.time()) - 86400
    rejected = sum(1 for e in all_events if e["result"] == "REJECTED" and e["timestamp"] > today_start)
    authenticated = sum(1 for e in all_events if e["result"] == "AUTHENTICATED")

    return jsonify({
        "events": events[:limit],
        "total": len(all_events),
        "rejected": rejected,
        "authenticated": authenticated,
        "thermal": len(thermal),
    })


@app.route("/api/evidence")
def api_evidence():
    """Returns the forensic evidence log for the blockchain table."""
    from flask import request as req
    limit = int(req.args.get("limit", 50))
    return jsonify(get_recent_access_log(limit))


@app.route("/api/stats")
def api_stats():
    """Quick system health stats (compatible with iot_server /stats)."""
    try:
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM heartbeats")
            heartbeats = cursor.fetchone()[0]
            cursor.execute("SELECT COUNT(*) FROM evidence")
            evidence = cursor.fetchone()[0]
            cursor.execute("SELECT COUNT(DISTINCT device_id) FROM heartbeats")
            devices = cursor.fetchone()[0]
        return jsonify({"heartbeats": heartbeats, "evidence": evidence, "devices": devices})
    except sqlite3.OperationalError:
        return jsonify({"heartbeats": 0, "evidence": 0, "devices": 0})


# ─────────────────────────────────────────────────────────────────────────────
# New API Endpoints — Phase 2 Dashboard Expansion
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/api/sensors")
def api_sensors():
    """SW-420 and DHT22 sensor health status."""
    try:
        from pi_backend.defense_sensors import get_sensor_status
        return jsonify(get_sensor_status())
    except Exception as exc:
        return jsonify({"error": str(exc), "gpio_available": False})


@app.route("/api/tamper")
def api_tamper():
    """Recent SW-420 physical tamper events."""
    try:
        from pi_backend.defense_sensors import get_tamper_alerts
        return jsonify(get_tamper_alerts(20))
    except Exception as exc:
        return jsonify([])


@app.route("/api/fault")
def api_fault():
    """Recent laser-glitch / fault injection events."""
    try:
        from pi_backend.fault_detector import get_fault_events
        return jsonify(get_fault_events(20))
    except Exception as exc:
        return jsonify([])


@app.route("/api/threat_level")
def api_threat_level():
    """
    Threat Radar — computes an aggregate threat level (0-100) for the UI.

    Score factors:
      • Devices with trust_score < 50 → +30 each
      • REJECTED events in last 5 min → +5 each (capped at 40)
      • Active thermal alerts         → +20 each (capped at 20)
      • PHYSICAL_TAMPER events        → +50 (immediate RED)
      • CLOCK_TAMPER events           → +30
    """
    threat = 0
    alerts_active = []
    now = int(time.time())

    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row

            # Low-trust devices
            devices = conn.execute(
                "SELECT device_id, trust_score FROM device_status "
                "WHERE trust_score < 50"
            ).fetchall()
            for d in devices:
                threat += 30
                alerts_active.append(f"LOW_TRUST:{d['device_id']}({d['trust_score']:.0f})")

            # Recent rejections (last 5 min)
            rejected_count = conn.execute(
                "SELECT COUNT(*) FROM access_log "
                "WHERE result='REJECTED' AND timestamp > ?",
                (now - 300,)
            ).fetchone()[0]
            threat += min(rejected_count * 5, 40)
            if rejected_count:
                alerts_active.append(f"REJECTED_x{rejected_count}")

            # Thermal alerts
            thermal = conn.execute(
                "SELECT COUNT(*) FROM alerts "
                "WHERE event_type IN ('EMERGENCY_THERMAL','SENSOR_TAMPER') "
                "AND timestamp > ?",
                (now - 300,)
            ).fetchone()[0]
            threat += min(thermal * 20, 20)
            if thermal:
                alerts_active.append(f"THERMAL_x{thermal}")

            # Physical tamper
            tamper = conn.execute(
                "SELECT COUNT(*) FROM alerts "
                "WHERE event_type='PHYSICAL_TAMPER' AND timestamp > ?",
                (now - 300,)
            ).fetchone()[0]
            if tamper:
                threat += 50
                alerts_active.append("PHYSICAL_TAMPER")

            # Clock tamper (NTP drift)
            clock = conn.execute(
                "SELECT COUNT(*) FROM alerts "
                "WHERE event_type='CLOCK_TAMPER' AND timestamp > ?",
                (now - 300,)
            ).fetchone()[0]
            if clock:
                threat += 30
                alerts_active.append("CLOCK_TAMPER")

    except sqlite3.OperationalError:
        pass

    threat = min(threat, 100)

    if threat >= 70:
        color = "RED"
    elif threat >= 35:
        color = "ORANGE"
    elif threat >= 10:
        color = "YELLOW"
    else:
        color = "GREEN"

    return jsonify({
        "threat_score": threat,
        "color":        color,
        "alerts":       alerts_active,
        "timestamp":    now,
    })


@app.route("/api/photo/<device_id>")
def api_photo(device_id: str):
    """
    Returns the latest JPEG photo from the ESP32-CAM for this device.
    The dashboard <img> tag polls this endpoint every 5 seconds.
    """
    jpeg = _latest_photos.get(device_id)
    if jpeg is None:
        jpeg = load_device_photo(device_id)
    if jpeg:
        return Response(jpeg, mimetype="image/jpeg")

    # Return a 1×1 transparent placeholder when no photo exists yet
    # (1×1 grey JPEG — minimal valid JPEG bytes)
    placeholder = (
        b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
        b"\xff\xdb\x00C\x00\x08\x06\x06\x07\x06\x05\x08\x07\x07\x07\t\t\x08\n"
        b"\x0c\x14\r\x0c\x0b\x0b\x0c\x19\x12\x13\x0f\x14\x1d\x1a\x1f\x1e\x1d"
        b"\x1a\x1c\x1c $.' \",#\x1c\x1c(7),01444\x1f'9=82<.342\x1eG\xc0\x00\x0b"
        b"\x08\x00\x01\x00\x01\x01\x01\x11\x00\xff\xc4\x00\x1f\x00\x00\x01\x05"
        b"\x01\x01\x01\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x01\x02\x03"
        b"\x04\x05\x06\x07\x08\t\n\x0b\xff\xda\x00\x08\x01\x01\x00\x00?\x00\xfb"
        b"\xd2\x8a(\x03\xff\xd9"
    )
    return Response(placeholder, mimetype="image/jpeg")


@app.route("/api/environment")
def api_environment():
    """Latest DHT22 temperature and humidity reading."""
    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                "SELECT * FROM heartbeats WHERE device_id='PI_DHT22' "
                "ORDER BY received_at DESC LIMIT 1"
            ).fetchone()
        if row:
            return jsonify(dict(row))
        return jsonify({"temperature": None, "humidity": None})
    except sqlite3.OperationalError:
        return jsonify({"temperature": None, "humidity": None})


@app.route("/api/clock")
def api_clock():
    """Clock drift status from the RTC guard."""
    try:
        from pi_backend.clock_guard import check_clock_drift, is_clock_tampered
        report = check_clock_drift()
        report["tampered"] = is_clock_tampered()
        return jsonify(report)
    except Exception as exc:
        return jsonify({"error": str(exc)})


# ─────────────────────────────────────────────────────────────────────────────
# Entry Point
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    port = int(os.environ.get("DASHBOARD_PORT", "5001"))
    print("\n" + "=" * 60)
    print("  Zero-Trust IoT Security Dashboard")
    print(f"  Open → http://localhost:{port}")
    print("=" * 60 + "\n")
    app.run(host="0.0.0.0", port=port, debug=False)
