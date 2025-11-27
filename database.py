import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash

DB_NAME = "logs.db"

def _conn():
    return sqlite3.connect(DB_NAME)

def init_db():
    conn = _conn()
    c = conn.cursor()

    # Logs table
    c.execute('''
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            action TEXT,
            filename TEXT,
            user TEXT,
            file_path TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Users table
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT
        )
    ''')

    # ✅ Migration: add missing columns
    c.execute("PRAGMA table_info(users)")
    columns = [col[1] for col in c.fetchall()]
    if "role" not in columns:
        c.execute("ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'user'")
    if "first_name" not in columns:
        c.execute("ALTER TABLE users ADD COLUMN first_name TEXT")
    if "second_name" not in columns:
        c.execute("ALTER TABLE users ADD COLUMN second_name TEXT")

    conn.commit()
    conn.close()

def add_log(action, filename, user, file_path):
    conn = _conn()
    c = conn.cursor()
    c.execute("INSERT INTO logs (action, filename, user, file_path) VALUES (?, ?, ?, ?)",
              (action, filename, user, file_path))
    conn.commit()
    conn.close()

def get_logs():
    conn = _conn()
    c = conn.cursor()
    c.execute("SELECT * FROM logs ORDER BY timestamp DESC")
    rows = c.fetchall()
    conn.close()
    return rows

def get_user_logs(username):
    conn = _conn()
    c = conn.cursor()
    c.execute("SELECT * FROM logs WHERE user = ? ORDER BY timestamp DESC", (username,))
    rows = c.fetchall()
    conn.close()
    return rows

def register_user(username, password, role="user", first_name=None, second_name=None):
    conn = _conn()
    c = conn.cursor()
    try:
        hashed = generate_password_hash(password)
        c.execute(
            "INSERT INTO users (username, password, role, first_name, second_name) VALUES (?, ?, ?, ?, ?)",
            (username, hashed, role, first_name, second_name)
        )
        conn.commit()
        conn.close()
        return True
    except sqlite3.IntegrityError:
        return False

def validate_user(username, password):
    conn = _conn()
    c = conn.cursor()
    c.execute("SELECT password, role, first_name, second_name FROM users WHERE username = ?", (username,))
    row = c.fetchone()
    conn.close()
    if row and check_password_hash(row[0], password):
        return {
            "username": username,
            "role": row[1] if row[1] else "user",
            "first_name": row[2] if row[2] else "",
            "second_name": row[3] if row[3] else ""
        }
    return None

def fix_roles():
    conn = _conn()
    c = conn.cursor()
    c.execute("UPDATE users SET role='user' WHERE role IS NULL OR role=''")
    conn.commit()
    conn.close()

def user_exists(username):
    conn = _conn()
    c = conn.cursor()
    c.execute("SELECT id FROM users WHERE username = ?", (username,))
    row = c.fetchone()
    conn.close()
    return bool(row)

def get_all_users():
    conn = _conn()
    c = conn.cursor()
    c.execute("SELECT id, username, role, first_name, second_name FROM users ORDER BY id ASC")
    rows = c.fetchall()
    conn.close()
    return rows

def update_user_role(user_id, new_role):
    conn = _conn()
    c = conn.cursor()
    c.execute("UPDATE users SET role=? WHERE id=?", (new_role, user_id))
    conn.commit()
    conn.close()

def delete_user(user_id):
    conn = _conn()
    c = conn.cursor()
    c.execute("DELETE FROM users WHERE id=?", (user_id,))
    conn.commit()
    conn.close()
