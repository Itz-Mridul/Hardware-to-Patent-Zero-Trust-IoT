#!/usr/bin/env python3
"""
Merge Datasets - Raspberry Pi
Combines legitimate heartbeats (from security.db) and 
attack heartbeats (from attack_data.db) into a single training_data.db
"""

import sqlite3
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(BASE_DIR)

# Prefer fresh training_data.db collected by collect_training_data.py.
# Fall back to security.db only if training_data.db doesn't exist.
_training_db_default = os.path.join(BASE_DIR, "training_data.db")
_security_db_default = os.path.join(BASE_DIR, "security.db")
LEGITIMATE_DB = os.environ.get(
    "TRAINING_DB_PATH",
    _training_db_default if os.path.exists(_training_db_default) else _security_db_default,
)

ATTACK_DB   = os.environ.get(
    "ATTACK_DB_PATH",
    os.path.join(PROJECT_ROOT, "tests", "attack_data.db"),
)
# Output goes to ml_models/ so train_model.py finds it without extra config
ML_MODELS_DIR = os.path.join(PROJECT_ROOT, "ml_models")
TRAINING_DB = os.environ.get(
    "ML_TRAINING_DB_PATH",
    os.path.join(ML_MODELS_DIR, "training_data.db"),
)

def merge():
    print("\n" + "="*60)
    print("🔄 DATABASE MERGE TOOL")
    print("="*60)
    
    if not os.path.exists(LEGITIMATE_DB):
        print(f"❌ Error: No legitimate sample DB found.")
        print(f"   Tried: {LEGITIMATE_DB}")
        print(f"   Run collect_training_data.py first to gather ESP32 samples.")
        return

    print(f"📂 Legitimate samples source: {os.path.basename(LEGITIMATE_DB)}")

    if not os.path.exists(ATTACK_DB):
        print(f"❌ Error: {ATTACK_DB} not found. Did you scp it to the home directory?")
        return

    # 1. Start with a fresh training_data.db by copying the legitimate source
    if os.path.exists(TRAINING_DB):
        os.remove(TRAINING_DB)
    
    print(f"📂 Creating {TRAINING_DB}...")
    os.makedirs(ML_MODELS_DIR, exist_ok=True)
    
    with sqlite3.connect(LEGITIMATE_DB) as src, sqlite3.connect(TRAINING_DB) as dst:
        # Copy schema and legitimate data
        src.backup(dst)
    
    # 2. Append attack data
    print(f"➕ Merging attack samples from {ATTACK_DB}...")
    
    with sqlite3.connect(TRAINING_DB) as train_conn:
        cursor = train_conn.cursor()
        cursor.execute(f"ATTACH DATABASE '{ATTACK_DB}' AS attack")
        
        # Insert attack samples (is_legitimate is already 0 in that DB)
        cursor.execute("""
            INSERT INTO heartbeats 
            (device_id, temperature, humidity, rssi, free_heap, 
             inter_packet_delay, packet_size, received_at, is_legitimate)
            SELECT device_id, temperature, humidity, rssi, free_heap, 
                   inter_packet_delay, packet_size, received_at, is_legitimate
            FROM attack.heartbeats
        """)
        
        train_conn.commit()
        
        cursor.execute("SELECT is_legitimate, COUNT(*) FROM heartbeats GROUP BY is_legitimate")
        stats = cursor.fetchall()
        
        print("\n✅ Merge Complete!")
        for label, count in stats:
            status = "Legitimate (1)" if label == 1 else "Attack (0)"
            print(f"   • {status}: {count} samples")

if __name__ == "__main__":
    merge()
