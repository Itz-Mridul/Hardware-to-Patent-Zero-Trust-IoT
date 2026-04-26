#!/usr/bin/env python3
"""
Software Attacker - Simulates device spoofing
Creates fake ESP32 heartbeats with different timing signature
"""

import os
import json
import time
import sqlite3
import random

# ---------------- CONFIGURATION ----------------
# Set PI_IP in your environment or .env file — do NOT hardcode real IPs here.
PI_IP = os.environ.get("PI_LOCAL_IP", "192.168.X.X")

# Dynamic DB path (saves in the same directory as this script)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "attack_data.db")

# Attacker device ID
DEVICE_ID = "ESP32_SOFTWARE_ATTACKER"

# Number of fake samples to generate
NUM_SAMPLES = 200

def create_attack_database():
    """Create local database for attack samples"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS heartbeats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id TEXT,
            timestamp INTEGER,
            temperature REAL,
            humidity REAL,
            rssi INTEGER,
            free_heap INTEGER,
            inter_packet_delay INTEGER,
            packet_size INTEGER,
            received_at REAL,
            is_legitimate INTEGER
        )
    ''')
    conn.commit()
    return conn

print("\n" + "="*60)
print("⚠️  SOFTWARE ATTACK SIMULATOR")
print("="*60)
print(f"Attacker ID: {DEVICE_ID}")
print(f"Samples to generate: {NUM_SAMPLES}\n")

# Connect to the dynamic DB path
conn = create_attack_database()
cursor = conn.cursor()

# Initialize timing
last_timestamp = int(time.time() * 1000)
sent_count = 0

for i in range(1, NUM_SAMPLES + 1):
    # Software attacker has DIFFERENT timing characteristics:
    # - More erratic inter-packet delay
    # - Different jitter pattern
    # - Simulates network stack delays differently than hardware
    
    # Random delay between packets (0.15-0.25s instead of hardware's 5s)
    delay_ms = random.randint(150, 250)
    time.sleep(delay_ms / 1000)
    
    # Calculate IPD AFTER the sleep so the first iteration is correct
    current_time = int(time.time() * 1000)
    inter_packet_delay = current_time - last_timestamp
    last_timestamp = current_time
    
    # Create payload (mimicking ESP32 format)
    payload = {
        "device_id": DEVICE_ID,
        "timestamp": current_time,
        "temperature": round(random.uniform(20, 30), 2),
        "humidity": round(random.uniform(40, 60), 2),
        "rssi": random.randint(-75, -55),
        "free_heap": random.randint(200000, 250000),
        "inter_packet_delay": inter_packet_delay,
        "packet_size": random.randint(400, 500)
    }
    
    # BUG FIX: If we send this to the Flask server, the server will log it as 
    # is_legitimate=1 (since it's in baseline mode), contaminating your training data!
    # Therefore, we ONLY store it locally as is_legitimate=0 so you can merge it safely.
    status = "✅ Saved Locally"
    
    # Store locally (primary goal)
    cursor.execute('''
        INSERT INTO heartbeats 
        (device_id, timestamp, temperature, humidity, rssi, free_heap, 
         inter_packet_delay, packet_size, received_at, is_legitimate)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        payload['device_id'],
        payload['timestamp'],
        payload['temperature'],
        payload['humidity'],
        payload['rssi'],
        payload['free_heap'],
        payload['inter_packet_delay'],
        payload['packet_size'],
        time.time(),
        0  # is_legitimate = 0 (attack data)
    ))
    
    if i % 20 == 0:
        conn.commit()
        print(f"📡 Progress: {i}/{NUM_SAMPLES} | IPD: {inter_packet_delay}ms | {status}")
    
    sent_count += 1

conn.commit()
conn.close()

print(f"\n✅ Attack simulation complete!")
print(f"   Generated: {sent_count} fake heartbeats")
print(f"   Database: {DB_PATH}")
print(f"\nNext step: Transfer this data to Raspberry Pi and merge it.")
print(f"\nCommand to transfer:")
print(f"scp '{DB_PATH}' pi@{PI_IP}:~/attack_data.db")
