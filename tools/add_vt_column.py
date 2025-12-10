# tools/add_vt_column.py
import sqlite3, os

db = os.path.abspath(r"C:\Users\Nikhil\OneDrive\Desktop\Desktop\AI-SOC-Project\events.db")
conn = sqlite3.connect(db)
cur = conn.cursor()
cols = [c[1] for c in cur.execute("PRAGMA table_info(alerts)").fetchall()]

if 'vt_permalink' not in cols:
    cur.execute("ALTER TABLE alerts ADD COLUMN vt_permalink TEXT")
    print("Added vt_permalink")
else:
    print("vt_permalink already exists")

conn.commit()
conn.close()
