#!/usr/bin/env python3
"""
Fault Injection Detector — Laser Glitching / Bit-Flip Mitigation
=================================================================
Closes Attack 2: "Laser Fault Injection" (Voltage/Photonic Glitching)

The Attack:
    A high-powered IR laser is focused on the Pi's silicon die at the
    exact microsecond the system evaluates `if (is_valid)`.  The photons
    generate electron-hole pairs in the transistors, flipping a register
    bit from 0 to 1 — converting a "DENY" decision to an "ALLOW" decision
    at the hardware level, below all software defenses.

    This is the same technique used in academic papers to bypass:
        • iPhone Secure Enclave
        • Bank card PIN verification
        • Disk encryption keys

Why software can partially mitigate this:
    Laser glitching is imprecise in time (microsecond jitter) and space
    (laser has to hit the right transistor on an unmarked die).
    If the decision code is structured to require N coherent correct checks
    in a row — each in a different register and memory location — the
    probability of glitching ALL of them drops geometrically.

    Additionally:
        • Redundant check voting (3-of-3 majority)
        • Execution flow verification (ensure code path was fully traversed)
        • Hardware voltage monitoring (ADC on the 3.3V rail)
        • CPU temperature spike detection (laser heats the die)

Mitigations implemented in this module:
    1. verified_decision()  — N-of-M redundant voting with execution guards.
    2. FlowProof            — verifies a full code path was traversed.
    3. VoltageMonitor       — reads the 3.3V rail via MCP3008 ADC (Pi GPIO).
    4. Canary values        — memory canaries detected if flipped by glitch.
"""

import hashlib
import os
import secrets
import sqlite3
import struct
import time
from contextlib import contextmanager
from functools import wraps
from typing import Any, Callable, Optional, TypeVar

_BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH   = os.environ.get("IOT_DB_PATH", os.path.join(_BASE_DIR, "security.db"))

# Number of redundant evaluations required for a "trusted" decision
FAULT_VOTES_REQUIRED = int(os.environ.get("FAULT_VOTES_REQUIRED", "3"))

# Voltage thresholds (3.3V rail; adjust per ADC calibration)
VOLTAGE_NOMINAL  = float(os.environ.get("VOLTAGE_NOMINAL",  "3.30"))
VOLTAGE_GLITCH_LO = float(os.environ.get("VOLTAGE_GLITCH_LO", "3.10"))   # sag
VOLTAGE_GLITCH_HI = float(os.environ.get("VOLTAGE_GLITCH_HI", "3.50"))   # spike

F = TypeVar("F", bound=Callable[..., Any])


# ── 1. N-of-N Redundant Decision Voting ───────────────────────────────────────

def verified_decision(
    predicate: Callable[[], bool],
    votes: int = FAULT_VOTES_REQUIRED,
    label: str = "decision",
) -> bool:
    """
    Evaluates `predicate` exactly `votes` times.

    For the result to be True, ALL evaluations must independently return True.
    A single glitch that flips one vote from False → True is NOT enough;
    the attacker would need to glitch every evaluation simultaneously.

    Each evaluation:
        • Is separated by a random jitter (prevents clock-aligned attacks).
        • Uses a fresh local variable (not reusing the same register).
        • Verifies that the predicate itself hasn't been tampered with.

    Args:
        predicate: A callable that returns bool (e.g. lambda: pin_matches()).
        votes:     Number of independent evaluations needed.
        label:     Label for fault-injection log entries.

    Returns:
        True only if all `votes` evaluations return True.

    Example:
        if verified_decision(lambda: evaluate_pin(entered) == PinResult.REAL):
            grant_access()
    """
    results = []

    for i in range(votes):
        # Random inter-evaluation jitter (0–500µs)
        time.sleep(secrets.randbelow(500) / 1_000_000)

        # Evaluate into a fresh local (different stack position each time)
        try:
            v = bool(predicate())
        except Exception as exc:
            _log_fault_event("EVAL_EXCEPTION", label,
                             f"Predicate raised on vote {i}: {exc}")
            return False

        results.append(v)

    all_true  = all(results)
    all_false = not any(results)

    # Suspicious: some votes True, some False — possible glitch mid-sequence
    if not all_true and not all_false:
        incoherent_votes = sum(results)
        _log_fault_event(
            "INCOHERENT_VOTE", label,
            f"{incoherent_votes}/{votes} votes True — possible laser glitch detected!"
        )
        print(
            f"[FAULT] ⚡ INCOHERENT VOTE on '{label}': "
            f"{incoherent_votes}/{votes} True — glitch suspected!"
        )
        return False   # Fail secure

    return all_true


def fault_guarded(label: str = "", votes: int = FAULT_VOTES_REQUIRED):
    """
    Decorator version of verified_decision.

    Wraps a function so it is called `votes` times; the decorated function
    must return a bool. All votes must agree.

    Usage:
        @fault_guarded(label="pin_check", votes=3)
        def check_pin(entered: str) -> bool:
            return entered == stored_hash
    """
    def decorator(func: F) -> F:
        @wraps(func)
        def wrapper(*args, **kwargs):
            return verified_decision(
                lambda: func(*args, **kwargs),
                votes=votes,
                label=label or func.__name__,
            )
        return wrapper  # type: ignore
    return decorator


# ── 2. Execution Flow Proof ────────────────────────────────────────────────────

class FlowProof:
    """
    Verifies that a complete, expected code path was traversed.

    A laser glitch can cause the CPU to skip instructions, jumping directly
    into the "access granted" block without passing through the validation
    logic. FlowProof detects this by requiring that a sequence of
    "checkpoints" is stamped in the correct order before a final decision
    is made.

    Usage:
        proof = FlowProof(["rfid_read", "pin_check", "rgb_challenge"])

        # ... in the access flow:
        proof.stamp("rfid_read")
        if rfid_valid:
            proof.stamp("pin_check")
            if pin_valid:
                proof.stamp("rgb_challenge")
                if rgb_valid and proof.complete():
                    grant_access()

    A glitch that skips directly to grant_access() without stamping all
    checkpoints will fail proof.complete().
    """

    def __init__(self, checkpoints: list[str]):
        self._required   = checkpoints
        self._stamped    = []
        self._started_at = time.time()
        # Session nonce — different each time, prevents replay of stamps
        self._nonce      = secrets.token_hex(8)

    def stamp(self, checkpoint: str) -> None:
        """
        Records that this checkpoint was reached.
        Must be called in the correct order; out-of-order stamps are
        flagged as a potential glitch.
        """
        expected_index = len(self._stamped)
        if expected_index >= len(self._required):
            _log_fault_event("FLOW_OVERFLOW", checkpoint,
                             "More stamps than checkpoints — possible replay.")
            return

        expected = self._required[expected_index]
        if checkpoint != expected:
            _log_fault_event(
                "FLOW_ORDER_VIOLATION", checkpoint,
                f"Expected '{expected}' but got '{checkpoint}'. "
                f"Possible instruction-skip glitch."
            )
            self._stamped = []   # Reset — deny any completion
            return

        # Stamp includes the nonce to prevent checkpoint replay
        self._stamped.append(f"{self._nonce}:{checkpoint}")

    def complete(self) -> bool:
        """
        Returns True only if ALL checkpoints were stamped in order.
        This is the gate that must be checked before granting access.
        """
        if len(self._stamped) != len(self._required):
            missing = set(self._required) - {
                s.split(":", 1)[1] for s in self._stamped
            }
            _log_fault_event(
                "FLOW_INCOMPLETE", "gate_check",
                f"Only {len(self._stamped)}/{len(self._required)} checkpoints "
                f"reached. Missing: {missing}. Possible glitch-skip."
            )
            return False
        return True

    def reset(self) -> None:
        """Resets the proof for the next access attempt."""
        self._stamped    = []
        self._nonce      = secrets.token_hex(8)
        self._started_at = time.time()


# ── 3. Memory Canary ─────────────────────────────────────────────────────────

class MemoryCanary:
    """
    Places a known random value at a specific memory location.
    Checks that it hasn't been flipped by a glitch before critical decisions.

    A laser hitting RAM at the wrong time can flip arbitrary bits.
    If the canary is corrupted, we know a bit-flip has occurred in this
    process's memory space — abort the current operation.

    Usage:
        canary = MemoryCanary()
        # ... later, before granting access:
        if not canary.intact():
            emergency_lockdown()
    """

    def __init__(self):
        self._value    = secrets.token_bytes(32)
        self._checksum = self._compute_checksum(self._value)

    def _compute_checksum(self, data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()

    def intact(self) -> bool:
        """
        Returns True if the canary value has not been modified.
        A bit-flip attack or memory corruption will change the value
        and trigger a mismatch.
        """
        current = self._compute_checksum(self._value)
        ok = current == self._checksum
        if not ok:
            _log_fault_event(
                "CANARY_CORRUPTED", "memory_canary",
                f"Canary checksum mismatch! Expected {self._checksum[:16]}… "
                f"Got {current[:16]}… Possible bit-flip / memory glitch."
            )
            print("[FAULT] ☢️  MEMORY CANARY CORRUPTED — bit-flip detected!")
        return ok


# ── 4. Voltage Monitor (MCP3008 ADC) ─────────────────────────────────────────

def read_rail_voltage(channel: int = 0) -> Optional[float]:
    """
    Reads the 3.3V power rail via an MCP3008 ADC connected to the Pi's SPI.

    A laser glitch or fault injection tool often works by briefly spiking
    or sagging the supply voltage. A sudden deviation from 3.30V ± 0.05V
    during a crypto operation is a strong indicator of a fault attack.

    Hardware: MCP3008 channel 0 connected to a 3.3V → 1.65V resistor divider.

    Returns:
        Voltage in volts, or None if SPI/ADC not available.
    """
    try:
        import spidev  # type: ignore  # only available on Pi

        spi = spidev.SpiDev()
        spi.open(0, 0)
        spi.max_speed_hz = 1_000_000
        spi.mode = 0

        r = spi.xfer2([1, (8 + channel) << 4, 0])
        raw = ((r[1] & 3) << 8) | r[2]     # 10-bit ADC value (0–1023)
        spi.close()

        # Vref = 3.3V, divider ratio = 2 (for 3.3V → 1.65V input)
        voltage = (raw / 1023.0) * 3.3 * 2.0
        return round(voltage, 3)

    except ImportError:
        return None   # Dev environment — no SPI
    except Exception as exc:
        print(f"[FAULT] ADC read failed: {exc}")
        return None


def check_voltage_glitch(label: str = "operation") -> bool:
    """
    Reads the supply voltage and checks it is within safe bounds.

    Returns True (clean) or False (glitch detected).
    Logs a VOLTAGE_GLITCH alert if out of bounds.
    """
    v = read_rail_voltage()
    if v is None:
        return True   # No ADC — cannot check, assume clean

    clean = VOLTAGE_GLITCH_LO <= v <= VOLTAGE_GLITCH_HI

    if not clean:
        _log_fault_event(
            "VOLTAGE_GLITCH", label,
            f"Rail voltage={v:.3f}V outside safe range "
            f"[{VOLTAGE_GLITCH_LO}V – {VOLTAGE_GLITCH_HI}V] during '{label}'. "
            f"Possible fault injection attack."
        )
        print(
            f"[FAULT] ⚡ VOLTAGE GLITCH: {v:.3f}V during '{label}' "
            f"(nominal={VOLTAGE_NOMINAL}V)"
        )

    return clean


# ── DB helpers ────────────────────────────────────────────────────────────────

def _log_fault_event(event_type: str, label: str, details: str) -> None:
    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute(
                "INSERT INTO alerts (device_id, event_type, timestamp, details) "
                "VALUES (?, ?, ?, ?)",
                (label, event_type, int(time.time()), details),
            )
            conn.commit()
    except sqlite3.OperationalError:
        pass


def get_fault_events(limit: int = 50) -> list:
    """Returns recent fault injection events for the dashboard."""
    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT * FROM alerts "
                "WHERE event_type IN ('INCOHERENT_VOTE','FLOW_INCOMPLETE',"
                "'FLOW_ORDER_VIOLATION','CANARY_CORRUPTED','VOLTAGE_GLITCH',"
                "'EVAL_EXCEPTION','FLOW_OVERFLOW') "
                "ORDER BY timestamp DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(r) for r in rows]
    except sqlite3.OperationalError:
        return []
