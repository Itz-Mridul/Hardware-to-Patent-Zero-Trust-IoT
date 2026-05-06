#!/usr/bin/env python3
"""
train_authentication_model.py  — wrapper that delegates to ml_models/train_model.py
This file kept for backward-compatibility with start_all.sh / test references.
"""
import os, sys

# Add project root to path so ml_models/train_model.py can be imported
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TRAIN_SCRIPT = os.path.join(ROOT, "ml_models", "train_model.py")

if not os.path.exists(TRAIN_SCRIPT):
    raise SystemExit(f"Train script not found: {TRAIN_SCRIPT}")

# Execute the CNN-LSTM trainer
import runpy
runpy.run_path(TRAIN_SCRIPT, run_name="__main__")
