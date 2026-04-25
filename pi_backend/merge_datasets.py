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
SECURITY_DB = os.path.join(BASE_DIR, "security.db")
ATTACK_DB = os.path.join(PROJECT_ROOT, "tests", "attack_data.db")
TRAINING_DB = os.path.join(BASE_DIR, "training_data.db")

def merge():
    print("\n" + "="*60)
    print("🔄 DATABASE MERGE TOOL")
    print("="*60)
    
    if not os.path.exists(SECURITY_DB):
        print(f"❌ Error: {SECURITY_DB} not found. Run the telemetry server first.")
        return

    if not os.path.exists(ATTACK_DB):
        print(f"❌ Error: {ATTACK_DB} not found. Did you scp it to the home directory?")
        return

    # 1. Start with a fresh training_data.db by copying the schema from security.db
    if os.path.exists(TRAINING_DB):
        os.remove(TRAINING_DB)
    
    print(f"📂 Creating {TRAINING_DB}...")
    
    with sqlite3.connect(SECURITY_DB) as src, sqlite3.connect(TRAINING_DB) as dst:
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
            (device_id, timestamp, temperature, humidity, rssi, free_heap, 
             inter_packet_delay, packet_size, received_at, is_legitimate)
            SELECT device_id, timestamp, temperature, humidity, rssi, free_heap, 
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
