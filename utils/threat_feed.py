import requests
import sqlite3
import os
from dotenv import load_dotenv

load_dotenv()
API_KEY = os.getenv("ABUSEIPDB_API_KEY")
DB_PATH = "data/firewall.db"

def fetch_malicious_ips():
    print("[*] Fetching IPs from AbuseIPDB...")
    
    url = "https://api.abuseipdb.com/api/v2/blacklist"
    headers = {
        "Accept": "application/json",
        "Key": API_KEY
    }
    params = {
        "confidenceMinimum": "90"
    }

    response = requests.get(url, headers=headers, params=params)
    data = response.json()

    if "data" not in data:
        print("[!] API error:", data)
        return []

    ips = [entry["ipAddress"] for entry in data["data"]]
    print(f"[+] {len(ips)} malicious IPs fetched.")
    return ips

def insert_into_blocklist(ips):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    count = 0

    for ip in ips:
        # Avoid duplicates
        cursor.execute("SELECT * FROM rules WHERE ip=? AND action='block'", (ip,))
        if cursor.fetchone() is None:
            cursor.execute("INSERT INTO rules (action, ip) VALUES (?, ?)", ("block", ip))
            count += 1

    conn.commit()
    conn.close()
    print(f"[+] {count} new IPs added to blocklist.")

def run_threat_sync():
    ips = fetch_malicious_ips()
    if ips:
        insert_into_blocklist(ips)

if __name__ == "__main__":
    run_threat_sync()
