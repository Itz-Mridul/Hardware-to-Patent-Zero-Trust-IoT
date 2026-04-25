#!/usr/bin/env python3
"""
Clock Guard — Hardware RTC vs NTP Drift Detection
===================================================
Closes the "Temporal Desync" loophole.

An attacker performing NTP spoofing can slowly drift the Pi's system
clock, causing RGB challenge windows and IPD expectations to desync,
eventually forcing a False-Positive lock-out loop that tricks the admin
into lowering security sensitivity.

Defence:
    • Reads authoritative time from a DS3231 RTC module (/dev/rtc0).
    • Compares it against the OS (NTP-synced) clock every 60 seconds.
    • If drift > DRIFT_ALERT_SECONDS, logs a CLOCK_TAMPER alert and
      forces the system to trust hardware time only.
    • Provides get_secure_time() — a single drop-in replacement for
      time.time() that the rest of the codebase uses.

Hardware setup (Raspberry Pi → DS3231):
    SDA  → GPIO 2  (pin 3)
    SCL  → GPIO 3  (pin 5)
    VCC  → 3.3 V   (pin 1)
    GND  → GND     (pin 6)

Then enable the RTC in /boot/config.txt:
    dtoverlay=i2c-rtc,ds3231

And sync hardware clock on first boot:
    sudo hwclock --systohc
"""

import fcntl
import os
import sqlite3
import struct
import time
from typing import Optional

# ── Configuration ──────────────────────────────────────────────────────────────
RTC_DEVICE           = os.environ.get("RTC_DEVICE", "/dev/rtc0")
DRIFT_ALERT_SECONDS  = float(os.environ.get("DRIFT_ALERT_SECONDS", "5.0"))
DRIFT_CHECK_INTERVAL = float(os.environ.get("DRIFT_CHECK_INTERVAL", "60.0"))

_BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH   = os.environ.get("IOT_DB_PATH", os.path.join(_BASE_DIR, "security.db"))

# ioctl code for reading the Linux RTC (RTC_RD_TIME = 0x80247009)
_RTC_RD_TIME = 0x80247009

# Whether a clock tamper has been detected in this session
_clock_tamper_active: bool = False
_last_rtc_offset: float = 0.0        # seconds: rtc_time − system_time


# ── RTC read ───────────────────────────────────────────────────────────────────

def _read_rtc_time() -> Optional[float]:
    """
    Reads the DS3231 hardware clock via the Linux /dev/rtc0 ioctl interface.

    Returns:
        Unix timestamp from the RTC, or None if the device is unavailable
        (dev/test environment without a physical RTC module).
    """
    if not os.path.exists(RTC_DEVICE):
        return None          # graceful no-op in Mac / CI environments

    try:
        with open(RTC_DEVICE, "rb") as rtc:
            # struct rtc_time = 9 × signed int (tm_sec … tm_isdst)
            buf = bytearray(36)
            fcntl.ioctl(rtc, _RTC_RD_TIME, buf)
            (tm_sec, tm_min, tm_hour, tm_mday, tm_mon,
             tm_year, tm_wday, tm_yday, tm_isdst) = struct.unpack("9i", bytes(buf))

            import calendar
            rtc_struct = time.struct_time((
                tm_year + 1900, tm_mon + 1, tm_mday,
                tm_hour, tm_min, tm_sec,
                tm_wday, tm_yday, 0
            ))
            return float(calendar.timegm(rtc_struct))   # always UTC
    except (OSError, PermissionError) as exc:
        print(f"[CLOCK] RTC read failed: {exc}")
        return None


# ── Public API ─────────────────────────────────────────────────────────────────

def get_secure_time() -> float:
    """
    Returns the most trustworthy timestamp available.

    Priority:
        1. DS3231 hardware clock  (immune to NTP spoofing)
        2. OS system clock        (fallback in dev / no RTC)

    This is the single time source that all challenge windows, IPD
    comparisons, and grace-period calculations should use.
    """
    rtc = _read_rtc_time()
    if rtc is not None:
        return rtc
    return time.time()


def check_clock_drift() -> dict:
    """
    Compares RTC time to NTP system time and returns a drift report.

    Should be called periodically (e.g. every 60 s from a background thread).

    Returns a dict with keys:
        rtc_time, system_time, drift_seconds, tamper_detected
    """
    global _clock_tamper_active, _last_rtc_offset

    rtc_time    = _read_rtc_time()
    system_time = time.time()

    if rtc_time is None:
        # No physical RTC — cannot validate, skip silently
        return {
            "rtc_time": None,
            "system_time": system_time,
            "drift_seconds": 0.0,
            "tamper_detected": False,
            "note": "No RTC device found — running in software-time mode",
        }

    drift = abs(rtc_time - system_time)
    _last_rtc_offset = rtc_time - system_time
    tamper = drift >= DRIFT_ALERT_SECONDS

    if tamper and not _clock_tamper_active:
        _clock_tamper_active = True
        _store_clock_tamper_alert(rtc_time, system_time, drift)
        print(
            f"[CLOCK] ⚠️  NTP DRIFT ATTACK DETECTED! "
            f"RTC={rtc_time:.2f}  SYS={system_time:.2f}  "
            f"Δ={drift:.3f}s  (threshold={DRIFT_ALERT_SECONDS}s)"
        )
    elif not tamper:
        _clock_tamper_active = False   # reset once clocks re-sync

    return {
        "rtc_time": rtc_time,
        "system_time": system_time,
        "drift_seconds": round(drift, 4),
        "tamper_detected": tamper,
    }


def is_clock_tampered() -> bool:
    """True if a sustained NTP drift has been detected since last check."""
    return _clock_tamper_active


def start_drift_monitor(interval: float = DRIFT_CHECK_INTERVAL) -> None:
    """
    Starts a background daemon thread that calls check_clock_drift()
    every `interval` seconds.

    Call once at server startup.
    """
    import threading

    def _loop():
        while True:
            check_clock_drift()
            time.sleep(interval)

    t = threading.Thread(target=_loop, name="ClockDriftMonitor", daemon=True)
    t.start()
    print(f"[CLOCK] Drift monitor started (check every {interval:.0f}s, "
          f"alert threshold={DRIFT_ALERT_SECONDS}s)")


# ── DB helpers ─────────────────────────────────────────────────────────────────

def _store_clock_tamper_alert(rtc_time: float, sys_time: float, drift: float) -> None:
    details = (
        f"NTP DRIFT: RTC={rtc_time:.2f} | SYS={sys_time:.2f} | "
        f"Δ={drift:.4f}s ≥ threshold={DRIFT_ALERT_SECONDS}s. "
        f"Possible NTP spoofing attack. System switching to hardware time."
    )
    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute(
                "INSERT INTO alerts (device_id, event_type, timestamp, details) "
                "VALUES (?, ?, ?, ?)",
                ("PI_CLOCK", "CLOCK_TAMPER", int(sys_time), details),
            )
            conn.commit()
    except sqlite3.OperationalError as exc:
        print(f"[CLOCK] DB write skipped: {exc}")


def get_clock_tamper_alerts(limit: int = 50) -> list:
    """Returns recent CLOCK_TAMPER events for the dashboard."""
    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT * FROM alerts WHERE event_type = 'CLOCK_TAMPER' "
                "ORDER BY timestamp DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(r) for r in rows]
    except sqlite3.OperationalError:
        return []
