import time
import sqlite3

DB = "../events.db"

def init_db():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT,
            event TEXT
        )
    """)
    conn.commit()
    return conn

def main():
    conn = init_db()
    cursor = conn.cursor()
    print("Log Collector Started...")

    while True:
        # TEMPORARY SAMPLE LOG (we replace with real Sysmon logs later)
        log_text = "Sample log generated at " + str(time.time())

        cursor.execute(
            "INSERT INTO logs (ts, event) VALUES (datetime('now'), ?)",
            (log_text,)
        )
        conn.commit()

        print("Saved log:", log_text)
        time.sleep(2)

if __name__ == "__main__":
    main()
