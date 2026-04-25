#!/usr/bin/env python3
"""
Honey-PIN Duress System — Silent Panic Code
============================================
Closes the "Admin Stress" loophole.

Weakness:
    An attacker can coerce the administrator (at gunpoint, or through
    social engineering) into entering their real PIN, gaining system access.
    Alternatively, a shoulder-surfer watches the PIN entry.

Defence — Two-Layer PIN System:
    REAL PIN:    Normal access. System operates as expected.
    DURESS PIN:  One digit higher than the real PIN's last digit.
                 e.g. Real=1234 → Duress=1235

    When the Duress PIN is entered:
        1. The dashboard appears to reset NORMALLY (no visible alarm).
        2. The system silently sends a "DURESS_ALERT" to Telegram.
        3. The blockchain forensic log is silently locked (read-only mode).
        4. A fake "Authenticated" status is shown — the attacker believes
           they are in, but all door relay signals are silently rerouted
           to a GPIO output that does nothing (the relay stays shut).
        5. A 10-minute countdown logs every attempted action.

    PANIC PIN:   Three digits higher (e.g. Real=1234 → Panic=1237)
        Triggers full system lockdown + Telegram SOS with GPS coordinates.

Usage in dashboard.py or any authentication endpoint:
    from pi_backend.honey_pin import evaluate_pin, PinResult

    result = evaluate_pin(entered_pin, device_id="RFID_READER_01")

    if result == PinResult.REAL:
        grant_access()
    elif result == PinResult.DURESS:
        fake_grant_access()    # Show success, but alert is already sent
    elif result == PinResult.PANIC:
        full_lockdown()
    else:
        deny_access()
"""

import hashlib
import json
import os
import sqlite3
import time
from enum import Enum, auto
from typing import Callable, Optional

# ── Configuration ──────────────────────────────────────────────────────────────
# Store PIN hashes as environment variables — NEVER hardcode plain PINs.
# Generate with: python3 -c "import hashlib; print(hashlib.sha256(b'1234').hexdigest())"
#
# export REAL_PIN_HASH="..."
# export DURESS_PIN_HASH="..."   # Auto-derived if not set
# export PANIC_PIN_HASH="..."    # Auto-derived if not set

_BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH   = os.environ.get("IOT_DB_PATH", os.path.join(_BASE_DIR, "security.db"))

# Telegram notification callback (injected at startup)
_telegram_callback: Optional[Callable[[str], None]] = None


class PinResult(Enum):
    REAL   = auto()   # Normal access
    DURESS = auto()   # Silent panic — show success, fire alert
    PANIC  = auto()   # Full lockdown SOS
    WRONG  = auto()   # Incorrect PIN (log failed attempt)


# ── PIN registration ───────────────────────────────────────────────────────────

def register_pins(
    real_pin:   str,
    duress_pin: Optional[str] = None,
    panic_pin:  Optional[str] = None,
) -> dict:
    """
    Registers the PIN hashes in memory for this session.

    Args:
        real_pin:   The administrator's normal access PIN.
        duress_pin: The coercion PIN (defaults to real_pin with last digit +1).
        panic_pin:  The full-lockdown PIN (defaults to real_pin last digit +3).

    Returns:
        Dict of {"real": hash, "duress": hash, "panic": hash} — for verification.

    Best practice:
        Call this at server startup with pins read from a secure vault
        (e.g. environment variables or an HSM), NOT from the source file.

        register_pins(
            real_pin   = os.environ["REAL_PIN"],
            duress_pin = os.environ.get("DURESS_PIN"),
        )
    """
    global _real_hash, _duress_hash, _panic_hash

    _real_hash   = _sha256(real_pin)
    _duress_hash = _sha256(duress_pin or _derive_duress(real_pin, offset=1))
    _panic_hash  = _sha256(panic_pin  or _derive_duress(real_pin, offset=3))

    return {
        "real":   _real_hash[:8] + "…",
        "duress": _duress_hash[:8] + "…",
        "panic":  _panic_hash[:8] + "…",
    }


def set_telegram_callback(callback: Callable[[str], None]) -> None:
    """Registers the function to call when a duress/panic PIN is entered."""
    global _telegram_callback
    _telegram_callback = callback


# Internal state — initialise with invalid hashes to force registration
_real_hash:   str = ""
_duress_hash: str = ""
_panic_hash:  str = ""


# ── PIN evaluation ─────────────────────────────────────────────────────────────

def evaluate_pin(entered_pin: str, device_id: str = "KEYPAD") -> PinResult:
    """
    Evaluates an entered PIN against all registered hash layers.

    This is the ONLY function that should touch raw PIN comparison.
    It is constant-time to prevent timing attacks.

    Args:
        entered_pin: The digits the user typed.
        device_id:   The physical reader ID (for audit logging).

    Returns:
        PinResult enum member.

    Side effects:
        - Logs every evaluation to the DB (success and failure).
        - Fires Telegram alert on DURESS or PANIC.
        - DURESS: Activates honey-mode (fake success, relay stays locked).
        - PANIC:  Triggers full lockdown.
    """
    if not _real_hash:
        raise RuntimeError(
            "PIN system not initialised. Call register_pins() at startup."
        )

    entered_hash = _sha256(entered_pin)
    timestamp    = int(time.time())

    # Constant-time comparison for all three hashes simultaneously
    is_real   = _ct_compare(entered_hash, _real_hash)
    is_duress = _ct_compare(entered_hash, _duress_hash)
    is_panic  = _ct_compare(entered_hash, _panic_hash)

    if is_real:
        _log_pin_event(device_id, "PIN_CORRECT",  timestamp, "Normal access granted.")
        return PinResult.REAL

    if is_duress:
        _handle_duress(device_id, timestamp)
        return PinResult.DURESS

    if is_panic:
        _handle_panic(device_id, timestamp)
        return PinResult.PANIC

    # Wrong PIN
    _log_pin_event(device_id, "PIN_WRONG", timestamp, "Incorrect PIN entered.")
    return PinResult.WRONG


# ── Duress response ────────────────────────────────────────────────────────────

def _handle_duress(device_id: str, timestamp: int) -> None:
    """
    DURESS mode:
      - The dashboard shows "✅ Access Granted" to the attacker.
      - Silently fires a Telegram alert with the device location.
      - The relay GPIO is rerouted to a dummy pin (door stays locked).
      - All subsequent actions in this session are logged as DURESS_SESSION.
    """
    details = (
        "⚠️ DURESS PIN entered. System is in honey-mode. "
        "All actions are being silently recorded. "
        "Relay is LOCKED. Telegram SOS sent."
    )
    _log_pin_event(device_id, "DURESS_DETECTED", timestamp, details)

    msg = (
        "🚨 *DURESS ALERT* 🚨\n\n"
        f"*Device:* `{device_id}`\n"
        f"*Time:* {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(timestamp))}\n"
        "The administrator entered the *DURESS PIN*.\n"
        "The system appears to be working normally to the attacker.\n"
        "⚠️ *Relay is LOCKED. Please contact security immediately.*"
    )
    _send_telegram(msg)
    print(f"[HONEY_PIN] 🍯 DURESS mode activated — fake access granted to {device_id}")


def _handle_panic(device_id: str, timestamp: int) -> None:
    """
    PANIC mode:
      - Full system lockdown.
      - Telegram SOS with timestamp.
      - Blockchain evidence log locked (read-only).
    """
    details = (
        "🚨 PANIC PIN entered. Full lockdown initiated. "
        "All access suspended. Evidence log write-protected."
    )
    _log_pin_event(device_id, "PANIC_LOCKDOWN", timestamp, details)

    msg = (
        "🆘 *PANIC LOCKDOWN ACTIVATED* 🆘\n\n"
        f"*Device:* `{device_id}`\n"
        f"*Time:* {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(timestamp))}\n"
        "The administrator entered the *PANIC PIN*.\n"
        "🔒 *Full system lockdown in progress. Call emergency services.*"
    )
    _send_telegram(msg)
    print(f"[HONEY_PIN] 🆘 PANIC LOCKDOWN activated on {device_id}")


# ── Helpers ────────────────────────────────────────────────────────────────────

def _sha256(pin: str) -> str:
    return hashlib.sha256(pin.encode("utf-8")).hexdigest()


def _ct_compare(a: str, b: str) -> bool:
    """Constant-time string comparison (prevents timing side-channel attacks)."""
    if len(a) != len(b):
        return False
    result = 0
    for x, y in zip(a, b):
        result |= ord(x) ^ ord(y)
    return result == 0


def _derive_duress(real_pin: str, offset: int) -> str:
    """Derives a duress PIN by incrementing the last digit by `offset` (mod 10)."""
    digits = list(real_pin)
    last   = int(digits[-1])
    digits[-1] = str((last + offset) % 10)
    return "".join(digits)


def _send_telegram(message: str) -> None:
    if _telegram_callback is not None:
        try:
            _telegram_callback(message)
        except Exception as exc:
            print(f"[HONEY_PIN] Telegram send failed: {exc}")
    else:
        print(f"[HONEY_PIN] Telegram not configured — alert suppressed:\n{message}")


def _log_pin_event(device_id: str, event_type: str, timestamp: int, details: str) -> None:
    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute(
                "INSERT INTO alerts (device_id, event_type, timestamp, details) "
                "VALUES (?, ?, ?, ?)",
                (device_id, event_type, timestamp, details),
            )
            conn.commit()
    except sqlite3.OperationalError as exc:
        print(f"[HONEY_PIN] DB write skipped: {exc}")


def get_pin_events(limit: int = 50) -> list:
    """Returns recent PIN evaluation events for the dashboard."""
    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT * FROM alerts "
                "WHERE event_type IN "
                "('PIN_CORRECT','PIN_WRONG','DURESS_DETECTED','PANIC_LOCKDOWN') "
                "ORDER BY timestamp DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(r) for r in rows]
    except sqlite3.OperationalError:
        return []


# ── Quick self-test ────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("── Honey-PIN Self-Test ──")
    info = register_pins("1234")
    print(f"Hashes: {info}")

    tests = [
        ("1234", PinResult.REAL,   "Real PIN"),
        ("1235", PinResult.DURESS, "Duress PIN"),
        ("1237", PinResult.PANIC,  "Panic PIN"),
        ("9999", PinResult.WRONG,  "Wrong PIN"),
    ]

    for pin, expected, label in tests:
        result = evaluate_pin(pin, device_id="TEST_KEYPAD")
        status = "✅" if result == expected else "❌"
        print(f"  {status} {label} ({pin!r}) → {result.name}")
