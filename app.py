def is_logged_in():
    return 'username' in session
from flask import Flask, render_template, request, redirect, url_for
import sqlite3

app = Flask(__name__)
app.secret_key = 'your_super_secret_key_here'  # ← PASTE IT HERE
# Create the database
def init_db():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    
    # Create items table
    c.execute('''CREATE TABLE IF NOT EXISTS items (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        description TEXT,
        status TEXT,
        contact TEXT
    )''')

    # Create users table
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT
    )''')

    conn.commit()
    conn.close()

init_db()

@app.route('/')
def index():
    logged_in = 'username' in session
    username = session.get('username', None)
    return render_template('index.html', logged_in=logged_in, username=username)

@app.route('/post-lost', methods=['GET', 'POST'])
def post_lost():
    if not is_logged_in():
        flash("Please log in to post lost items.")
        return redirect(url_for('login'))

    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        contact = request.form['contact']
        conn = sqlite3.connect('database.db')
        conn.execute("INSERT INTO items (name, description, status, contact) VALUES (?, ?, ?, ?)",
                     (name, description, 'lost', contact))
        conn.commit()
        conn.close()
        return redirect('/')
    return render_template('post_lost.html')

@app.route('/post-found', methods=['GET', 'POST'])
def post_found():
    if not is_logged_in():
        flash("Please log in to post found items.")
        return redirect(url_for('login'))

    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        contact = request.form['contact']
        conn = sqlite3.connect('database.db')
        conn.execute("INSERT INTO items (name, description, status, contact) VALUES (?, ?, ?, ?)",
                     (name, description, 'found', contact))
        conn.commit()
        conn.close()
        return redirect('/')
    return render_template('post_found.html')

@app.route('/view-items')
def view_items():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("SELECT * FROM items")
    items = c.fetchall()
    conn.close()
    return render_template('view_items.html', items=items)
from flask import session, flash
import hashlib
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        hashed_password = hashlib.sha256(password.encode()).hexdigest()

        try:
            conn = sqlite3.connect('database.db')
            c = conn.cursor()
            c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
            conn.commit()
            flash("Registration successful! Please log in.")
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash("Username already taken!")
        finally:
            conn.close()
    return render_template('register.html')
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = hashlib.sha256(password.encode()).hexdigest()

        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, hashed_password))
        user = c.fetchone()
        conn.close()

        if user:
            session['username'] = username
            flash("Login successful!")
            return redirect(url_for('index'))
        else:
            flash("Invalid username or password!")
    return render_template('login.html')
@app.route('/logout')
def logout():
    session.pop('username', None)
    flash("You have been logged out.")
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
