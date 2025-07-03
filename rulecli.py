import sqlite3
import sys

DB_PATH = "data/firewall.db"

def add_rule(action, ip):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO rules (action, ip) VALUES (?, ?)", (action, ip))
    conn.commit()
    conn.close()
    print(f"[+] Rule added: {action.upper()} {ip}")

def remove_rule(ip):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM rules WHERE ip = ?", (ip,))
    conn.commit()
    conn.close()
    print(f"[-] Rule removed for IP: {ip}")

def list_rules():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT id, action, ip FROM rules")
    rules = cursor.fetchall()
    conn.close()

    print("Current Rules:")
    for rule in rules:
        print(f"ID: {rule[0]} | {rule[1].upper()} {rule[2]}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python3 rulecli.py add block 8.8.8.8")
        print("  python3 rulecli.py remove 8.8.8.8")
        print("  python3 rulecli.py list")
        sys.exit(1)

    command = sys.argv[1]

    if command == "add" and len(sys.argv) == 4:
        add_rule(sys.argv[2], sys.argv[3])
    elif command == "remove" and len(sys.argv) == 3:
        remove_rule(sys.argv[2])
    elif command == "list":
        list_rules()
    else:
        print("Invalid command or arguments.")
