from flask import Flask, render_template, request, redirect, url_for, session
from werkzeug.security import check_password_hash
import sqlite3
import os

app = Flask(__name__)
app.secret_key = 'sentinel_secret_key'  # Change this for production

BASE_DIR = os.path.dirname(os.path.abspath(__file__))  # path to 'web'
PARENT_DIR = os.path.dirname(BASE_DIR)  # path to project root
DB_PATH = os.path.join(PARENT_DIR, 'data', 'firewall.db')

# --- Database Functions ---
def get_rules():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT id, action, ip FROM rules")
    rules = cursor.fetchall()
    conn.close()
    return rules

def add_rule(action, ip):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO rules (action, ip) VALUES (?, ?)", (action, ip))
    conn.commit()
    conn.close()

def delete_rule(rule_id):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM rules WHERE id = ?", (rule_id,))
    conn.commit()
    conn.close()

def validate_user(username, password):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT password_hash FROM users WHERE username = ?", (username,))
    result = cursor.fetchone()
    conn.close()
    if result:
        return check_password_hash(result[0], password)
    return False

# --- Routes ---
@app.route('/')
def index():
    if not session.get("logged_in"):
        return redirect("/login")
    rules = get_rules()
    return render_template("index.html", rules=rules)

@app.route('/add', methods=['POST'])
def add():
    if not session.get("logged_in"):
        return redirect("/login")
    ip = request.form['ip']
    action = request.form['action']
    add_rule(action, ip)
    return redirect(url_for('index'))

@app.route('/delete/<int:rule_id>')
def delete(rule_id):
    if not session.get("logged_in"):
        return redirect("/login")
    delete_rule(rule_id)
    return redirect(url_for('index'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if session.get("logged_in"):
        return redirect('/')
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if validate_user(username, password):
            session["logged_in"] = True
            return redirect('/')
        else:
            return render_template("login.html", error="Invalid username or password.")
    return render_template("login.html")

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0')
