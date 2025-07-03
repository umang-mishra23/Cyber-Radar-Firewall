import sqlite3
from werkzeug.security import generate_password_hash

conn = sqlite3.connect("data/firewall.db")
cursor = conn.cursor()

cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL
    )
''')

username = input("Enter admin username: ")
password = input("Enter password: ")

hashed = generate_password_hash(password)
cursor.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, hashed))
conn.commit()
conn.close()

print("[+] Admin user created.")
