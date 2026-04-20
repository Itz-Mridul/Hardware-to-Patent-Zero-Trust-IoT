import sqlite3
from pathlib import Path

import pandas as pd


# 1. PATH DIAGNOSTICS
PI_DB_PATH = Path(
    "/home/mridul/Hardware-to-Patent-Zero-Trust-IoT/iot_data.db"
)
DB_PATH = PI_DB_PATH if PI_DB_PATH.exists() else Path(__file__).with_name("iot_data.db")


def table_exists(conn, table_name):
    result = conn.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?",
        (table_name,),
    ).fetchone()
    return result is not None


def main():
    print(f"Checking database at: {DB_PATH.absolute()}")

    if not DB_PATH.exists():
        print("CRITICAL: Database file not found.")
        return

    conn = sqlite3.connect(DB_PATH)
    try:
        if not table_exists(conn, "heartbeats"):
            print("Table 'heartbeats' does not exist yet.")
            print("Start iot_server.py so it can initialize the database.")
            return

        df = pd.read_sql_query("SELECT * FROM heartbeats", conn)
    finally:
        conn.close()

    # 2. DATA VOLUME CHECK
    total_rows = len(df)
    if total_rows == 0:
        print("Database is empty. Is the server running?")
        return

    # 3. TYPE CONVERSION & ERROR TRACKING
    df["timestamp"] = pd.to_numeric(df["timestamp"], errors="coerce")
    bad_ts = df["timestamp"].isna().sum()

    if bad_ts:
        print(f"WARNING: {bad_ts} rows had invalid timestamps and were ignored.")

    df["rssi"] = pd.to_numeric(df["rssi"], errors="coerce")
    df = df.dropna(subset=["device_id", "timestamp"])

    # 4. LOGIC VALIDATION
    unique_devices = df["device_id"].nunique()
    if total_rows < 2 or unique_devices == total_rows:
        print(f"DATA INSUFFICIENT: Found {total_rows} rows but {unique_devices} unique IDs.")
        print("Need multiple packets from the SAME device_id to calculate IPD.")
        print(f"Sample IDs: {df['device_id'].unique()[:3]}")
        return

    # 5. THE ANALYSIS
    df = df.sort_values(["device_id", "timestamp"])
    df["ipd"] = df.groupby("device_id")["timestamp"].diff()
    ipd_df = df.dropna(subset=["ipd"])

    if ipd_df.empty:
        print(f"Found {len(df)} rows, but couldn't calculate IPD.")
        print("Need 2+ rows with the same device_id.")
        print("Current Device IDs in DB:", df["device_id"].unique())
        return

    print(f"\nAnalysis Successful ({len(ipd_df)} IPD samples calculated)")
    print("-" * 40)
    summary = ipd_df.groupby("device_id")["ipd"].agg(["count", "mean", "std", "min", "max"])
    print(summary.to_string(float_format=lambda value: f"{value:.6f}"))


if __name__ == "__main__":
    main()
