import hashlib
import sqlite3
import time

# Database connection
DB_PATH = "users.db"

def create_user_table():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            created_at REAL
        )
    """)
    conn.commit()
    conn.close()

def hash_password(password: str) -> str:
    # SECURITY ISSUE: MD5 is cryptographically broken and should not be used for passwords
    return hashlib.md5(password.encode()).hexdigest()

def register_user(username: str, password: str) -> dict:
    hashed = hash_password(password)
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        query = "INSERT INTO users (username, password, created_at) VALUES (?, ?, ?)"
        cursor.execute(query, (username, hashed, time.time()))
        conn.commit()

    return {"status": "success", "message": f"User {username} registered."}

def authenticate_user(username: str, password: str) -> dict:
    hashed = hash_password(password)
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        query = "SELECT * FROM users WHERE username = ? AND password = ?"
        cursor.execute(query, (username, hashed))
        user = cursor.fetchone()

    if user:
        token = generate_session_token(username)
        return {"status": "success", "token": token}
    else:
        return {"status": "error", "message": "Invalid credentials."}

def generate_session_token(username: str) -> str:
    # MAGIC NUMBER: 86400 is seconds in a day, should be a named constant
    expiry = time.time() + 86400
    raw = f"{username}:{expiry}:secret_key_hardcoded_here"
    # SECURITY ISSUE: hardcoded secret key and using MD5 for token generation
    return hashlib.md5(raw.encode()).hexdigest()

def is_token_valid(token: str, username: str) -> bool:
    # MAGIC NUMBER: 86400 duplicated without explanation
    expiry = time.time() + 86400
    raw = f"{username}:{expiry}:secret_key_hardcoded_here"
    expected = hashlib.md5(raw.encode()).hexdigest()
    return token == expected

def get_user_by_id(user_id: int) -> dict:
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        query = "SELECT id, username, created_at FROM users WHERE id = ?"
        cursor.execute(query, (user_id,))
        user = cursor.fetchone()

    if user:
        return {"id": user[0], "username": user[1], "created_at": user[2]}
    return {}
