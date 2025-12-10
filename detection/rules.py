import sqlite3
import time

DB = "../events.db"

def check_logs():
    conn = sqlite3.connect(DB)
    cursor = conn.cursor()

    # get last 5 logs
    rows = cursor.execute("SELECT id, ts, event FROM logs ORDER BY id DESC LIMIT 5").fetchall()

    alerts = []

    for row in rows:
        log_text = row[2].lower()

        # Example rule 1 — detect the word 'error'
        if "error" in log_text:
            alerts.append(f"ERROR DETECTED: {row[2]}")

        # Example rule 2 — detect the word 'failed'
        if "failed" in log_text:
            alerts.append(f"FAILED ACTIVITY: {row[2]}")

    return alerts

def main():
    print("Detection Engine Started...")
    while True:
        alerts = check_logs()
        for alert in alerts:
            print("ALERT:", alert)
        time.sleep(3)

if __name__ == "__main__":
    main()
