# collector/sysmon_collector.py (fixed)
from Evtx.Evtx import Evtx
import sqlite3
import os
import re

DB = r"C:\Users\Nikhil\OneDrive\Desktop\Desktop\AI-SOC-Project\events.db"
# default Sysmon EVTX path (change if different)
SYSLOG = r"C:\Windows\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx"

def init_db():
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS sysmon_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT,
            event_id TEXT,
            image TEXT,
            command_line TEXT,
            data TEXT
        )
    """)
    conn.commit()
    return conn

def extract_tag(xml, tag):
    """Extract simple element text <tag>value</tag> (returns '' if not found)."""
    start = xml.find(f"<{tag}>")
    if start == -1:
        return ""
    end = xml.find(f"</{tag}>", start)
    if end == -1:
        return ""
    return xml[start+len(tag)+2:end].strip()

def extract_time(xml):
    """Extract TimeCreated SystemTime attribute if present, fallback to empty."""
    m = re.search(r'<TimeCreated\s+SystemTime="([^"]+)"', xml)
    if m:
        return m.group(1)
    # fallback: search for <TimeCreated>value</TimeCreated>
    t = extract_tag(xml, "TimeCreated")
    return t

def extract_eventid(xml):
    # try EventID element
    val = extract_tag(xml, "EventID")
    if val:
        return val
    # sometimes EventID appears as <System><EventID>...</EventID></System>
    m = re.search(r"<EventID>(\d+)</EventID>", xml)
    return m.group(1) if m else ""

def main():
    if not os.path.exists(SYSLOG):
        print("Sysmon log not found:", SYSLOG)
        return

    conn = init_db()
    cur = conn.cursor()

    print("Reading Sysmon logs... please wait")

    with Evtx(SYSLOG) as log:
        for record in log.records():
            xml = record.xml()
            ts = extract_time(xml)
            event_id = extract_eventid(xml)
            image = extract_tag(xml, "Image")
            cmd = extract_tag(xml, "CommandLine")

            cur.execute("""
                INSERT INTO sysmon_logs (ts, event_id, image, command_line, data)
                VALUES (?, ?, ?, ?, ?)
            """, (ts, event_id, image, cmd, xml))

    conn.commit()
    conn.close()
    print("Sysmon logs imported successfully.")

if __name__ == "__main__":
    main()
