🌐 AI-Powered Threat Hunting & SOC Automation Platform
A Mini-SIEM + SOAR + Threat Intelligence + AI Anomaly Detection System
🚀 Overview

This project is a fully functional AI-Powered Threat Hunting & SOC Automation Platform, combining:

Sysmon Log Collection

Rule-based Detection Engine

Machine Learning (Isolation Forest)

Threat Intelligence (VirusTotal Integration)

SOC Dashboard (Flask + Tailwind)

Automated Alerting & Enrichment

It simulates how modern SOC platforms (like Splunk, Sentinel, Elastic & CrowdStrike) work internally — but built entirely using Python, Sysmon, SQLite, and AI models.

This project is designed to showcase skills in:

✔ Threat Hunting
✔ Detection Engineering
✔ SOC Automation
✔ Python for Security
✔ Log Parsing
✔ AI/ML for Cybersecurity
✔ Threat Intelligence Integration
✔ Dashboard Design

🧩 Architecture Diagram
        ┌──────────────────┐
        │   Windows Host    │
        │  (Sysmon Events)  │
        └───────┬──────────┘
                │
                ▼
      ┌──────────────────────┐
      │ Log Collector (EVTX) │
      └───────────┬──────────┘
                  │ Normalized Logs
                  ▼
        ┌────────────────────┐
        │   SQLite Database  │
        └──────────┬─────────┘
                   │
     ┌─────────────┴────────────────┐
     │                               │
     ▼                               ▼
┌──────────────┐        ┌─────────────────────┐
│ Rules Engine │        │ AI Anomaly Detector │
│ (YARA-style) │        │ (Isolation Forest)  │
└──────┬───────┘        └────────────┬────────┘
       │                              │
       ▼                              ▼
    Alerts                    Anomaly Scores
       └──────────────┬──────────────┘
                      ▼
        ┌─────────────────────────────┐
        │ Threat Intelligence (VT API)│
        └──────────────┬──────────────┘
                       ▼
           ┌──────────────────────┐
           │  SOC Dashboard (UI)  │
           │  Flask + Tailwind    │
           └──────────────────────┘

✨ Features
🔍 1. Sysmon Log Collection

Reads Sysmon EVTX logs directly from
C:\Windows\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx

Automatically extracts:

Event ID

Image

CommandLine

Source/Destination IP

Raw XML

🛡️ 2. Detection Engine

Includes multiple types of detections:

✔ Suspicious PowerShell
✔ Encoded commands (-enc)
✔ Unknown/rare process execution
✔ External IP connections
✔ Behavior-based alerts

Built to mimic EDR-style detection logic.

🤖 3. AI Anomaly Detection

Uses an Isolation Forest model to detect:

Unusual process behavior

Abnormal command-line patterns

Rare system events

Each alert is tagged:

NORMAL
ANOMALY


With a numerical score.

🌍 4. Threat Intelligence (VirusTotal)

For any event containing an IP:

Automatically queries VirusTotal

Adds malicious/suspicious count

Adds direct VT permalink

Example enriched alert:

PowerShell suspicious command  
ANOMALY score=0.053  
VT: malicious=5 suspicious=2 | https://www.virustotal.com/gui/ip-address/xxx

📊 5. SOC Dashboard

A modern Flask dashboard that shows:

Live alerts

Severity levels

Rule hits

Anomaly scores

VT enrichment tags

📁 Project Structure
AI-SOC-Project/
│
├── collector/
│   └── sysmon_collector.py
│
├── detection/
│   ├── rules.py
│   └── sysmon_rules.py
│
├── ai/
│   ├── train_anomaly.py
│   └── model.joblib
│
├── dashboard/
│   ├── app.py
│   ├── templates/
│   └── static/
│
├── tools/
│   ├── vt_lookup.py
│   ├── add_vt_column.py
│   └── insert_test.py
│
├── Sysmon/
│   └── sysmonconfig-export.xml
│
├── events.db
└── README.md

🧪 How to Run
1️⃣ Start Sysmon Collector
python collector/sysmon_collector.py

2️⃣ Run Detection Engine
python detection/sysmon_rules.py

3️⃣ Train AI Model (optional)
python ai/train_anomaly.py

4️⃣ Start Dashboard
python dashboard/app.py


Then open:

👉 http://127.0.0.1:5000

🔥 Example Alerts
ALERT [HIGH] PowerShell suspicious command: 
  id=42 
  cmd=powershell -enc Y2FsYy5leGU=
  ANOMALY=NORMAL score=-0.011
  VT: malicious=4 suspicious=1
  https://virustotal.com/...

🧰 Technologies Used

Python 3

Flask

SQLite

Sysmon

scikit-learn

TailwindCSS

VirusTotal API

Regular Expressions

Windows Event Log Parsing

🏆 Why This Project Is Valuable

This project demonstrates real-world skills required for:

SOC Analyst

Detection Engineer

Threat Hunter

Security Automation Engineer

MDR Analyst

Recruiters love seeing:

Real detection logic

AI anomaly detection

Threat intel enrichment

Dashboard + backend

This is not a basic project — it is portfolio-grade.

📌 Disclaimer

This platform is for educational and defensive research purposes only.
Do not use it to monitor systems without authorization.

🎉 Final Note

This project reflects modern cybersecurity engineering practices and shows strong capability in:

Writing production-grade security code

Building defensive tools

Understanding attacker behavior

Designing SOC automation logic
