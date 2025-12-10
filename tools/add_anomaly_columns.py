# tools/add_anomaly_columns.py
import sqlite3
import os

db = os.path.abspath(r"C:\Users\Nikhil\OneDrive\Desktop\Desktop\AI-SOC-Project\events.db")
conn = sqlite3.connect(db)
cur = conn.cursor()

cols = [c[1] for c in cur.execute("PRAGMA table_info(alerts)").fetchall()]

if 'anomaly_score' not in cols:
    cur.execute("ALTER TABLE alerts ADD COLUMN anomaly_score REAL")
    print("Added anomaly_score")
else:
    print("anomaly_score already exists")

if 'anomaly_label' not in cols:
    cur.execute("ALTER TABLE alerts ADD COLUMN anomaly_label TEXT")
    print("Added anomaly_label")
else:
    print("anomaly_label already exists")

conn.commit()
conn.close()
