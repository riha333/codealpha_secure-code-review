# app.py
from flask import Flask, request, render_template, redirect, url_for, session
import hashlib
import sqlite3
import os  # Imported for secure password storage

app = Flask(__name__)
app.secret_key = "insecure_secret_key" # TODO: Replace with a strong, random secret key

DATABASE = 'users.db'

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    with open('db/schema.sql') as f: 
        conn.executescript(f.read())

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Hash the password using SHA-256 with salt
        salt = os.urandom(16)  # Generate a random salt
        hashed_password = hashlib.sha256(salt + password.encode('utf-8')).hexdigest()
        salt_hex = salt.hex()  # Convert salt to hexadecimal for storage

        conn = get_db_connection()
        db = conn.cursor()
        try:
            db.execute("INSERT INTO users (username, password, salt) VALUES (?, ?, ?)", (username, hashed_password, salt_hex))
            conn.commit()
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            return render_template('register.html', error='Username already exists')
        finally:
            conn.close()
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = get_db_connection()
        db = conn.cursor()
        user = db.execute("SELECT password, salt FROM users WHERE username = ?", (username,)).fetchone()
        conn.close()

        if user:
            stored_password = user['password']
            stored_salt = bytes.fromhex(user['salt'])  # Convert salt back to bytes
            hashed_password = hashlib.sha256(stored_salt + password.encode('utf-8')).hexdigest()

            if hashed_password == stored_password:
                session['username'] = username
                return redirect(url_for('profile'))
            else:
                return render_template('login.html', error='Invalid credentials')
        else:
            return render_template('login.html', error='Invalid credentials')

    return render_template('login.html')


@app.route('/profile')
def profile():
    if 'username' in session:
        return render_template('profile.html', username=session['username'])
    else:
        return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('index'))

if __name__ == '__main__':
    init_db()
    app.run(debug=True)