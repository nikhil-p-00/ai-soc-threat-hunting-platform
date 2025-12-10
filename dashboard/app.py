# dashboard/app.py
from flask import Flask, render_template, jsonify
import sqlite3
import os

app = Flask(__name__, static_folder="static", template_folder="templates")

DB = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "events.db"))

def fetch_alerts(limit=200):
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    rows = cur.execute(
        "SELECT id, ts, severity, rule, message FROM alerts ORDER BY id DESC LIMIT ?",
        (limit,)
    ).fetchall()
    conn.close()
    alerts = []
    for r in rows:
        alerts.append({
            "id": r[0],
            "ts": r[1],
            "severity": r[2],
            "rule": r[3],
            "message": r[4] or ""
        })
    return alerts

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/alerts")
def api_alerts():
    alerts = fetch_alerts(200)
    return jsonify({"alerts": alerts})

if __name__ == "__main__":
    # debug mode OK for local portfolio demo
    app.run(debug=True, port=5000)
