# detection/sysmon_rules.py
# Improved sysmon rules with VirusTotal enrichment and AI anomaly scoring

import sys, os
# ensure project root on path (safe)
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import sqlite3
import time
import re
from datetime import datetime, timedelta

# vt helper
from tools.vt_lookup import vt_lookup_ip

# ai scorer
from ai.score import score_parsed

DB = r"C:\Users\Nikhil\OneDrive\Desktop\Desktop\AI-SOC-Project\events.db"

# small process whitelist
WHITELIST = {
    "svchost.exe","explorer.exe","chrome.exe","python.exe","cmd.exe","powershell.exe",
    "splunkd.exe","splunk-optimize.exe","btool.exe","python3.9.exe",
    "sysmon64.exe","sysmon.exe"
}

# keep recently seen alert keys for dedupe (in-memory, resets if you restart)
SEEN = {}
SEEN_TTL = 300  # seconds

def ensure_alerts_table():
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT,
            severity TEXT,
            rule TEXT,
            message TEXT,
            source_id INTEGER,
            vt_permalink TEXT,
            anomaly_score REAL,
            anomaly_label TEXT
        )
    """)
    conn.commit()
    conn.close()

def extract_tag(xml, tag):
    if not xml:
        return ""
    m = re.search(rf"<{tag}>(.*?)</{tag}>", xml, flags=re.IGNORECASE | re.DOTALL)
    if m:
        return m.group(1).strip()
    m = re.search(rf"<Data\s+Name=['\"]{tag}['\"]\s*>(.*?)</Data>", xml, flags=re.IGNORECASE | re.DOTALL)
    if m:
        return m.group(1).strip()
    m = re.search(rf"<(.*?)Name=['\"]{tag}['\"].*?>(.*?)</", xml, flags=re.IGNORECASE | re.DOTALL)
    if m:
        return m.group(2).strip()
    return ""

def parse_row(row):
    _id, ts, eid, img, cmd, data = row
    raw = data or ""
    event_id = eid or extract_tag(raw, "EventID")
    image = (img or "").strip() or extract_tag(raw, "Image") or extract_tag(raw, "ImageName") or ""
    command_line = (cmd or "").strip() or extract_tag(raw, "CommandLine") or extract_tag(raw, "Command") or ""
    src_ip = extract_tag(raw, "SourceIp") or extract_tag(raw, "DestinationIp") or ""
    return {"id": _id, "ts": ts, "event_id": event_id, "image": image, "cmd": command_line, "src_ip": src_ip, "raw": raw}

def is_recently_seen(key):
    now = time.time()
    for k in list(SEEN.keys()):
        if SEEN[k] < now - SEEN_TTL:
            del SEEN[k]
    return key in SEEN

def mark_seen(key):
    SEEN[key] = time.time()

def detect_rules_for_row(parsed):
    alerts = []
    txt = (parsed["cmd"] + " " + parsed["image"] + " " + parsed["raw"]).lower()

    # 1) Powershell detection (require strong signal)
    if ("powershell" in txt and ("-enc" in txt or "invoke-webrequest" in txt or "downloadstring" in txt or "iex " in txt)) or re.search(r"-enc\s+[A-Za-z0-9+/=]{8,}", txt):
        msg = f"PowerShell suspicious command: id={parsed['id']} cmd={parsed['cmd']}"
        alerts.append(("HIGH", "powershell_command", msg))

    # 2) New executable created / process create
    if parsed["image"]:
        proc = parsed["image"].split("\\")[-1].lower()
        if proc and proc not in WHITELIST:
            msg = f"Unusual process created: id={parsed['id']} proc={proc} image={parsed['image']}"
            alerts.append(("SUSPICIOUS", "process_create", msg))

    # 3) Network connection with external IP
    ip = parsed.get("src_ip", "")
    if ip and not ip.startswith("10.") and not ip.startswith("192.168.") and not ip.startswith("172.16.") and ip != "127.0.0.1":
        msg = f"Network connection to external IP: id={parsed['id']} ip={ip}"
        alerts.append(("SUSPICIOUS", "network_connection", msg))

    return alerts

def fetch_recent(limit=500):
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    rows = cur.execute("SELECT id, ts, event_id, image, command_line, data FROM sysmon_logs ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    conn.close()
    return rows

def main():
    print("Sysmon XML-based detection (improved + VT + AI) started...")
    ensure_alerts_table()
    while True:
        rows = fetch_recent(500)
        for r in rows:
            parsed = parse_row(r)
            for sev, rule, msg in detect_rules_for_row(parsed):
                key = f"{rule}:{parsed['id']}:{msg[:120]}"
                if is_recently_seen(key):
                    continue
                if "powershell" in msg.lower() or "unusual process" in msg.lower() or "network connection" in msg.lower():
                    # VT enrichment
                    vt_info = ""
                    vtres = {}
                    if parsed.get("src_ip"):
                        ip = parsed["src_ip"]
                        try:
                            vtres = vt_lookup_ip(ip)
                            if vtres.get("success"):
                                vt_info = " | " + vtres.get("message", "")
                                if vtres.get("permalink"):
                                    vt_info += f" | {vtres.get('permalink')}"
                            else:
                                if vtres.get("error") == "no_api_key":
                                    vt_info = " | VT: no_api_key"
                                elif vtres.get("error") == "not_found":
                                    vt_info = " | VT: not_found"
                                else:
                                    vt_info = " | VT: lookup_error"
                        except Exception:
                            vt_info = " | VT: exception"

                    full_message = msg + vt_info

                    # AI scoring (safe)
                    try:
                        aires = score_parsed(parsed)
                        anomaly_score = aires.get("anomaly_score")
                        anomaly_label = aires.get("anomaly_label")
                    except Exception:
                        anomaly_score = None
                        anomaly_label = None

                    # print enriched alert
                    print(f"ALERT [{sev}] {full_message} ANOMALY={anomaly_label} score={anomaly_score}")

                    # insert enriched alert into DB
                    vt_permalink = vtres.get('permalink') if isinstance(vtres, dict) else None
                    try:
                        conn = sqlite3.connect(DB)
                        cur = conn.cursor()
                        cur.execute(
                            "INSERT INTO alerts (ts, severity, rule, message, source_id, vt_permalink, anomaly_score, anomaly_label) VALUES (datetime('now'), ?, ?, ?, ?, ?, ?, ?)",
                            (sev, rule, full_message, parsed['id'], vt_permalink, anomaly_score, anomaly_label)
                        )
                        conn.commit()
                        conn.close()
                    except Exception as e:
                        print("DB insert error:", e)

                    mark_seen(key)
        time.sleep(3)

if __name__ == "__main__":
    main()
