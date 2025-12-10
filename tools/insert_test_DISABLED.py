# tools/insert_test.py
import sqlite3

DB = r"C:\Users\Nikhil\OneDrive\Desktop\Desktop\AI-SOC-Project\events.db"

conn = sqlite3.connect(DB)
c = conn.cursor()

xml = ("<Event><System><EventID>1</EventID></System>"
       "<EventData>"
       "<Data Name='Image'>C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Data>"
       "<Data Name='CommandLine'>powershell -enc Y2FsYy5leGU=</Data>"
       "</EventData></Event>")

c.execute("INSERT INTO sysmon_logs (ts, event_id, image, command_line, data) VALUES (datetime('now'), ?, ?, ?, ?)",
          (None, "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "powershell -enc Y2FsYy5leGU=", xml))

conn.commit()
print("Inserted test row, id =", c.lastrowid)
conn.close()
