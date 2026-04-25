#!/usr/bin/env python3
"""
RGB Challenge-Response Module
------------------------------
Generates a random color challenge when an RFID card is scanned.
The ESP32-CAM must flash the matching RGB LED color.
The AI then verifies the color tint in the captured photo.

This defeats pre-recorded deepfake video injection attacks (Attack 2).
"""

import random
import time
from typing import Optional

# The 5 challenge colors the Pi can issue
CHALLENGE_COLORS = ["RED", "GREEN", "BLUE", "CYAN", "YELLOW"]

# Active challenges: {session_id: (color, expires_at)}
_active_challenges: dict = {}

# Challenge validity window (seconds)
CHALLENGE_TTL_SECONDS = 10


def generate_color_challenge(session_id: Optional[str] = None) -> str:
    """
    Picks a random color and stores it as the active challenge.

    Args:
        session_id: Optional identifier to tie this challenge to a session.
                    Defaults to the current timestamp string.

    Returns:
        The challenge color string (e.g. "CYAN").
    """
    color = random.choice(CHALLENGE_COLORS)
    key = session_id or str(time.time())
    _active_challenges[key] = (color, time.time() + CHALLENGE_TTL_SECONDS)
    return color


def get_active_challenge(session_id: str) -> Optional[str]:
    """
    Returns the active challenge for a session, or None if expired / not found.
    """
    entry = _active_challenges.get(session_id)
    if entry is None:
        return None
    color, expires_at = entry
    if time.time() > expires_at:
        del _active_challenges[session_id]
        return None
    return color


def verify_color_response(
    expected: str,
    received: Optional[str],
    session_id: Optional[str] = None,
) -> bool:
    """
    Validates whether the camera's captured photo matches the challenge color.

    In hardware: OpenCV analyses the dominant color tint in the image.
    In tests: we pass the received color directly.

    Args:
        expected: The color the Pi challenged (e.g. "CYAN").
        received: The color extracted from the photo (or None if no photo).
        session_id: If provided, the challenge is consumed after verification.

    Returns:
        True if colors match (case-insensitive), False otherwise.
    """
    if received is None:
        return False

    match = expected.strip().upper() == received.strip().upper()

    # Consume the challenge so it cannot be replayed
    if session_id and session_id in _active_challenges:
        del _active_challenges[session_id]

    return match


def purge_expired_challenges() -> int:
    """
    Cleans up expired challenge entries. Call periodically.

    Returns:
        Number of entries removed.
    """
    now = time.time()
    expired = [k for k, (_, exp) in _active_challenges.items() if now > exp]
    for k in expired:
        del _active_challenges[k]
    return len(expired)
