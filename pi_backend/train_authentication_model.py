import os
import pickle
import sqlite3

import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score
from sklearn.model_selection import train_test_split


# 1. Connect to your collected data.
# Override with: TRAINING_DB_PATH=/path/to/training_data.db python3 train_ai.py
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get(
    "TRAINING_DB_PATH",
    os.path.join(BASE_DIR, "training_data.db"),
)
MODEL_PATH = os.environ.get(
    "FINGERPRINT_MODEL_PATH",
    os.path.join(BASE_DIR, "fingerprint_model.pkl"),
)


def load_training_data():
    if not os.path.exists(DB_PATH):
        raise FileNotFoundError(
            f"Could not find {DB_PATH}. Make sure your data collection script ran first."
        )

    query = """
        SELECT inter_packet_delay, rssi, free_heap, packet_size, is_legitimate
        FROM heartbeats
        WHERE inter_packet_delay IS NOT NULL
          AND rssi IS NOT NULL
          AND free_heap IS NOT NULL
          AND packet_size IS NOT NULL
          AND is_legitimate IS NOT NULL
    """

    with sqlite3.connect(DB_PATH) as conn:
        return pd.read_sql_query(query, conn)


try:
    df = load_training_data()
except Exception as error:
    print(f"Error: {error}")
    raise SystemExit(1)

if len(df) < 10:
    print("Not enough data to train. Collect more samples first!")
    raise SystemExit(1)

if df["is_legitimate"].nunique() < 2:
    print("Not enough label variety to train. Add both legitimate and attack samples first!")
    raise SystemExit(1)

print(f"Loaded {len(df)} samples for training...")

# 2. Prepare features (X) and labels (y).
X = df[["inter_packet_delay", "rssi", "free_heap", "packet_size"]]
y = df["is_legitimate"].astype(int)

# 3. Split data for testing.
stratify = y if y.value_counts().min() >= 2 else None
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42,
    stratify=stratify,
)

# 4. Train the Random Forest model.
print("Training Behavioral Fingerprinting Model...")
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# 5. Verify accuracy.
predictions = model.predict(X_test)
acc = accuracy_score(y_test, predictions)
print(f"Model Training Complete. Accuracy: {acc * 100:.2f}%")

# 6. Save the fingerprint model.
with open(MODEL_PATH, "wb") as model_file:
    pickle.dump(model, model_file)

print(f"Fingerprint saved as '{MODEL_PATH}'")
