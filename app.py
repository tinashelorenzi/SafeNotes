from flask import Flask, render_template, redirect, request, session, url_for
import hashlib
import sqlite3
from datetime import datetime

app =Flask(__name__)
app.secret_key = "E95vfhvsKr4BIF0hIRNI4BIF0hIRNI4BIF0hIRNI4BIF0hIRNI"

def init_db():
    conn = sqlite3.connect('notes.db')
    cursor = conn.cursor()
    
    # Users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Notes table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    conn.commit()
    conn.close()

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


@app.route('/')
def index():
    return render_template("login.html")

@app.route("/submit-login", methods=['POST'])
def process_login():
    username = request.form["username"]
    password = request.form["password"]
    password_hash = hash_password(password)
    conn = sqlite3.connect('notes.db')
    cursor = conn.cursor()
    user = conn.execute(
            'SELECT * FROM users WHERE username = ? AND password_hash = ?',
            (username, password_hash)
        ).fetchone()
    print(f"Logging in with {username} | {hash_password}")
    print(user)
    conn.close()
    if user:
        session['is_logged_in'] = True
        #Let you into the platform
        return redirect("/dashboard")
    else:
        return redirect("/")



@app.route("/register")
def register_page():
    return render_template("register.html")

@app.route("/submit_register", methods=['POST'])
def register_process():
    username = request.form['username']
    password = request.form['password']
    conn = sqlite3.connect('notes.db')
    cursor = conn.cursor()
    cursor.execute("INSERT INTO users(username,password_hash) VALUES (?,?)",(username,hash_password(password)))
    conn.commit()
    conn.close()
    return redirect("/")

@app.route("/dashboard")
def dashboard():
    if session['is_logged_in'] == True:
        return "You are logged in!"
    else:
        return redirect("/")

init_db()
