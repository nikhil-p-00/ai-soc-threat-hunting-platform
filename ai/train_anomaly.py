# ai/train_anomaly.py
"""
Train an IsolationForest on recent sysmon_logs.
Produces ai/model.joblib
"""
import sqlite3
import pandas as pd
import os
from sklearn.ensemble import IsolationForest
import joblib

DB = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "events.db"))
OUT = os.path.abspath(os.path.join(os.path.dirname(__file__), "model.joblib"))

def extract_features(df):
    def has_powershell(cmd, img):
        s = (cmd or "") + " " + (img or "")
        return 1 if "powershell" in s.lower() else 0
    def cmd_len(cmd):
        return len(cmd or "")
    def proc_whitelist(img):
        proc = (img or "").split("\\")[-1].lower()
        wl = {"svchost.exe","explorer.exe","chrome.exe","python.exe","cmd.exe","powershell.exe",
              "splunkd.exe","splunk-optimize.exe","btool.exe","python3.9.exe","sysmon64.exe","sysmon.exe"}
        return 0 if proc in wl else 1
    def hour_of_day(ts):
        try:
            return pd.to_datetime(ts).hour
        except Exception:
            return 0

    df['cmd_len'] = df['command_line'].apply(cmd_len)
    df['has_powershell'] = df.apply(lambda r: has_powershell(r['command_line'], r['image']), axis=1)
    df['proc_unusual'] = df['image'].apply(proc_whitelist)
    df['hour'] = df['ts'].apply(hour_of_day)
    features = df[['cmd_len','has_powershell','proc_unusual','hour']].fillna(0)
    return features

def load_data(limit=10000):
    conn = sqlite3.connect(DB)
    q = "SELECT id, ts, event_id, image, command_line, data FROM sysmon_logs ORDER BY id DESC LIMIT ?"
    df = pd.read_sql_query(q, conn, params=(limit,))
    conn.close()
    return df

def main():
    print("Loading data...")
    df = load_data(10000)
    if df.empty:
        print("No sysmon_logs rows found. Run collector or insert test data first.")
        return
    print("Extracting features...")
    X = extract_features(df)
    print("Training IsolationForest...")
    model = IsolationForest(n_estimators=200, contamination=0.02, random_state=42)
    model.fit(X)
    joblib.dump((model, X.columns.tolist()), OUT)
    print("Saved model to", OUT)

if __name__ == "__main__":
    main()
