#!/usr/bin/env python3
"""Shared latest-photo storage for ESP32-CAM JPEG payloads."""

import os
import re
from pathlib import Path


_BASE_DIR = Path(__file__).resolve().parent
PHOTO_DIR = Path(os.environ.get("IOT_PHOTO_DIR", _BASE_DIR / "photos"))


def _safe_device_id(device_id: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.-]", "_", str(device_id or "unknown"))
    return cleaned[:96] or "unknown"


def photo_path(device_id: str) -> Path:
    return PHOTO_DIR / f"{_safe_device_id(device_id)}.jpg"


def store_device_photo(device_id: str, jpeg_bytes: bytes) -> Path:
    PHOTO_DIR.mkdir(parents=True, exist_ok=True)
    path = photo_path(device_id)
    path.write_bytes(jpeg_bytes)
    return path


def load_device_photo(device_id: str) -> bytes | None:
    path = photo_path(device_id)
    try:
        return path.read_bytes()
    except FileNotFoundError:
        return None
