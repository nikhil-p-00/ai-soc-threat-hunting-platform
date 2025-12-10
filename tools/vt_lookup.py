# tools/vt_lookup.py
import os
import requests

VT_API_KEY = os.environ.get("VT_API_KEY")  # read from environment
VT_BASE = "https://www.virustotal.com/api/v3"

HEADERS = {"x-apikey": VT_API_KEY} if VT_API_KEY else {}

def vt_lookup_ip(ip):
    """
    Lookup an IP address on VirusTotal.
    Returns a dict: {"success":bool, "malicious":int, "suspicious":int, "message":str, "permalink":str}
    """
    if not VT_API_KEY:
        return {"success": False, "error": "no_api_key"}
    url = f"{VT_BASE}/ip_addresses/{ip}"
    try:
        r = requests.get(url, headers=HEADERS, timeout=15)
    except Exception as e:
        return {"success": False, "error": str(e)}
    if r.status_code == 200:
        data = r.json()
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        permalink = f"https://www.virustotal.com/gui/ip-address/{ip}/detection"
        message = f"VT: malicious={malicious} suspicious={suspicious}"
        return {"success": True, "malicious": malicious, "suspicious": suspicious, "message": message, "permalink": permalink}
    elif r.status_code == 404:
        return {"success": False, "error": "not_found", "status_code": 404}
    else:
        return {"success": False, "error": f"status_{r.status_code}", "details": r.text}
