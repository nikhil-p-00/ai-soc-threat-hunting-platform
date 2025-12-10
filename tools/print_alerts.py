# tools/print_alerts.py
import sqlite3, os

db = os.path.abspath(r"C:\Users\Nikhil\OneDrive\Desktop\Desktop\AI-SOC-Project\events.db")

conn = sqlite3.connect(db)
cur = conn.cursor()

rows = cur.execute("""
SELECT 
    id,
    ts,
    severity,
    rule,
    substr(message,1,120),
    vt_permalink,
    anomaly_label,
    anomaly_score
FROM alerts
ORDER BY id DESC
LIMIT 10
""").fetchall()

for r in rows:
    print(r)

conn.close()
