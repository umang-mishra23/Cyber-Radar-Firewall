import sqlite3
import os

DB_PATH = os.path.join("data", "firewall.db")

def match_rule(ip):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT action FROM rules WHERE ip = ?", (ip,))
    result = cursor.fetchone()
    conn.close()
    return result[0] if result else None

def add_rule_to_db(action, ip):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO rules (action, ip) VALUES (?, ?)", (action, ip))
    conn.commit()
    conn.close()

