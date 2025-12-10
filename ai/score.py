# ai/score.py
import os, joblib
import numpy as np
import pandas as pd

MODEL_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "model.joblib"))
model_tuple = None

def load_model():
    global model_tuple
    if model_tuple is None:
        model_tuple = joblib.load(MODEL_PATH)
    return model_tuple

def make_features_from_parsed(parsed):
    cmd = parsed.get("cmd","") or ""
    img = parsed.get("image","") or ""
    ts = parsed.get("ts","") or ""
    cmd_len = len(cmd)
    has_powershell = 1 if ("powershell" in (cmd + " " + img).lower()) else 0
    proc = img.split("\\")[-1].lower() if img else ""
    whitelist = {"svchost.exe","explorer.exe","chrome.exe","python.exe","cmd.exe","powershell.exe",
                 "splunkd.exe","splunk-optimize.exe","btool.exe","python3.9.exe","sysmon64.exe","sysmon.exe"}
    proc_unusual = 0 if proc in whitelist else 1
    try:
        hour = int(pd.to_datetime(ts).hour)
    except Exception:
        hour = 0
    return [cmd_len, has_powershell, proc_unusual, hour]

def score_parsed(parsed):
    try:
        mt = load_model()
    except Exception as e:
        return {"anomaly_score": None, "anomaly_label": None}
    model, columns = mt
    X = make_features_from_parsed(parsed)
    # create a DataFrame with the original column names so sklearn sees valid feature names
    import pandas as pd
    df = pd.DataFrame([X], columns=columns)
    try:
        # decision_function returns larger -> more normal; invert to make higher => more anomalous
        score = float(model.decision_function(df)[0])
        anomaly_score = -score
        is_anomaly = "ANOMALY" if model.predict(df)[0] == -1 else "NORMAL"
    except Exception:
        anomaly_score = None
        is_anomaly = None
    return {"anomaly_score": float(round(anomaly_score,6)) if anomaly_score is not None else None, "anomaly_label": is_anomaly}
