#!/usr/bin/env python3
"""
RGB Challenge Validator — Anti-Deepfake Image Analysis
=======================================================
Analyses captured JPEG images for the expected RGB challenge color tint.
Defeats pre-recorded deepfake video injection attacks.

Usage:
    from pi_backend.rgb_validator import validate
    is_valid, confidence, detected = validate("/path/to/photo.jpg", "CYAN")
"""

import logging
import os

log = logging.getLogger(__name__)

COLOR_THRESHOLDS = {
    "RED":     lambda r, g, b: r > 150 and r > g * 1.5 and r > b * 1.5,
    "GREEN":   lambda r, g, b: g > 150 and g > r * 1.5 and g > b * 1.5,
    "BLUE":    lambda r, g, b: b > 150 and b > r * 1.5 and b > g * 1.5,
    "YELLOW":  lambda r, g, b: r > 150 and g > 150 and b < 100,
    "CYAN":    lambda r, g, b: g > 150 and b > 150 and r < 100,
    "MAGENTA": lambda r, g, b: r > 150 and b > 150 and g < 100,
    "WHITE":   lambda r, g, b: r > 200 and g > 200 and b > 200,
}


def _detect_color(roi_rgb):
    """Detect the dominant color from an RGB ROI array."""
    import numpy as np
    r = float(roi_rgb[:, :, 0].mean())
    g = float(roi_rgb[:, :, 1].mean())
    b = float(roi_rgb[:, :, 2].mean())

    detected = "NONE"
    for color, check in COLOR_THRESHOLDS.items():
        if check(r, g, b):
            detected = color
            break

    brightness = (r + g + b) / 3.0
    confidence = min(100.0, (brightness / 128.0) * 100.0)
    return detected, confidence, r, g, b


def validate(image_path: str, expected_color: str) -> tuple:
    """
    Validates whether the expected RGB color is present in the image.

    Returns: (is_valid, confidence_pct, detected_color)
    """
    try:
        import cv2
    except ImportError:
        log.warning("OpenCV not installed — RGB validation disabled.")
        if os.environ.get("RGB_FAIL_OPEN", "false").lower() == "true":
            return True, 50.0, "OPENCV_MISSING"
        return False, 0.0, "OPENCV_MISSING"

    img = cv2.imread(image_path)
    if img is None:
        return False, 0.0, "NO_IMAGE"

    rgb = cv2.cvtColor(img, cv2.COLOR_BGR2RGB)
    h, w = rgb.shape[:2]
    roi = rgb[: h // 3, : w // 3]

    detected, confidence, r, g, b = _detect_color(roi)
    is_valid = detected == expected_color.strip().upper()

    if not is_valid:
        log.warning(
            f"RGB MISMATCH — Expected:{expected_color} Got:{detected} "
            f"[R:{r:.0f} G:{g:.0f} B:{b:.0f}]"
        )
    return is_valid, confidence, detected


def validate_from_bytes(jpeg_bytes: bytes, expected_color: str) -> tuple:
    """Same as validate() but accepts raw JPEG bytes from MQTT."""
    try:
        import cv2
        import numpy as np
    except ImportError:
        if os.environ.get("RGB_FAIL_OPEN", "false").lower() == "true":
            return True, 50.0, "OPENCV_MISSING"
        return False, 0.0, "OPENCV_MISSING"

    nparr = np.frombuffer(jpeg_bytes, np.uint8)
    img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
    if img is None:
        return False, 0.0, "DECODE_FAILED"

    rgb = cv2.cvtColor(img, cv2.COLOR_BGR2RGB)
    h, w = rgb.shape[:2]
    roi = rgb[: h // 3, : w // 3]

    detected, confidence, r, g, b = _detect_color(roi)
    is_valid = detected == expected_color.strip().upper()
    if not is_valid:
        log.warning(
            f"RGB MISMATCH — Expected:{expected_color} Got:{detected} "
            f"[R:{r:.0f} G:{g:.0f} B:{b:.0f}]"
        )
    return is_valid, confidence, detected
