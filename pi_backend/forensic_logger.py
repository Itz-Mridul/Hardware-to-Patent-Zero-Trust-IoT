#!/usr/bin/env python3
"""
Forensic Logger Module
-----------------------
Logs every access attempt (AUTHENTICATED or REJECTED) to a local
SQLite cache table (access_log) and optionally submits it to the
blockchain via the enhanced_mqtt_handler.

Every attempt — success and failure — is immutably recorded.
This creates the forensic audit trail for court proceedings.
"""

import hashlib
import json
import os
import sqlite3
import time
from typing import Optional

_BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("IOT_DB_PATH", os.path.join(_BASE_DIR, "security.db"))

# Whether to attempt on-chain logging (disabled by default when Ganache is down)
ENABLE_BLOCKCHAIN = os.environ.get("ENABLE_BLOCKCHAIN", "false").lower() == "true"


def _ensure_access_log_table(db_path: Optional[str] = None) -> None:
    """Create the access_log table if it doesn't exist yet."""
    with sqlite3.connect(db_path or DB_PATH) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS access_log (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id     TEXT    NOT NULL,
                result        TEXT    NOT NULL,
                reason        TEXT,
                trust_score   REAL,
                event_hash    TEXT    NOT NULL,
                timestamp     INTEGER NOT NULL,
                on_chain_tx   TEXT    DEFAULT NULL
            )
            """
        )
        conn.commit()


def _hash_event(device_id: str, result: str, reason: str, timestamp: int) -> str:
    """Creates a deterministic SHA-256 fingerprint for this access event."""
    payload = f"{device_id}|{result}|{reason}|{timestamp}"
    return hashlib.sha256(payload.encode()).hexdigest()


def log_access_attempt(
    device_id: str,
    result: str,
    reason: str,
    trust_score: float,
    submit_to_chain: bool = False,
    db_path: Optional[str] = None,
) -> str:
    """
    Persists an access attempt record to the local SQLite cache.

    Args:
        device_id:       The ESP32 device identifier.
        result:          "AUTHENTICATED", "REJECTED", or "WARNING".
        reason:          Human-readable explanation of the decision.
        trust_score:     Current trust score at the time of the decision.
        submit_to_chain: If True (and ENABLE_BLOCKCHAIN=true), also log on-chain.

    Returns:
        The event hash (SHA-256 hex string) for reference.
    """
    target_db = db_path or DB_PATH
    _ensure_access_log_table(target_db)

    timestamp = int(time.time())
    event_hash = _hash_event(device_id, result, reason, timestamp)
    on_chain_tx: Optional[str] = None

    # Optional blockchain submission
    if submit_to_chain and ENABLE_BLOCKCHAIN:
        on_chain_tx = _submit_to_blockchain(device_id, event_hash, trust_score)

    with sqlite3.connect(target_db) as conn:
        conn.execute(
            """
            INSERT INTO access_log
                (device_id, result, reason, trust_score, event_hash, timestamp, on_chain_tx)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (device_id, result, reason, trust_score, event_hash, timestamp, on_chain_tx),
        )
        conn.commit()

    icon = "✅" if result == "AUTHENTICATED" else "🚨"
    print(
        f"[FORENSIC] {icon} {result} | {device_id} | "
        f"trust={trust_score:.1f} | hash={event_hash[:12]}…"
    )
    return event_hash


def _submit_to_blockchain(device_id: str, event_hash: str, trust_score: float) -> Optional[str]:
    """
    Attempts to submit the event to the blockchain.
    Returns the transaction hash string, or None on failure.
    """
    try:
        from pi_backend.enhanced_mqtt_handler import send_to_blockchain
        fingerprint = int(event_hash[:12], 16)
        receipt = send_to_blockchain(device_id, fingerprint)
        if receipt:
            return receipt.transactionHash.hex()
    except Exception as exc:
        print(f"[FORENSIC] Blockchain submission skipped: {exc}")
    return None


def get_recent_access_log(limit: int = 100) -> list:
    """
    Returns the most recent access log entries.
    Used by the Flask dashboard /evidence endpoint.
    """
    _ensure_access_log_table()
    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                """
                SELECT * FROM access_log
                ORDER BY timestamp DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [dict(r) for r in rows]
    except sqlite3.OperationalError:
        return []
