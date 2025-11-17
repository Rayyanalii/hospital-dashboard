import sqlite3
from pathlib import Path

DB_PATH = Path("hospital.db")

def get_conn():
   
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
   
    conn = get_conn()
    cur = conn.cursor()

    cur.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        user_id       INTEGER PRIMARY KEY AUTOINCREMENT,
        username      TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role          TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS patients (
        patient_id          INTEGER PRIMARY KEY AUTOINCREMENT,
        name                TEXT,
        contact             TEXT,
        diagnosis           TEXT,
        anonymized_name     TEXT,
        anonymized_contact  TEXT,
        date_added          TEXT
        -- Bonus (optional) reversible encryption columns will be added later with ALTER TABLE
        -- enc_name BLOB,
        -- enc_contact BLOB
    );

    CREATE TABLE IF NOT EXISTS logs (
        log_id    INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id   INTEGER,
        role      TEXT,
        action    TEXT,
        timestamp TEXT,
        details   TEXT,
        FOREIGN KEY (user_id) REFERENCES users(user_id)
    );
    """)

    conn.commit()

    cur.execute("SELECT COUNT(*) AS cnt FROM users")
    count = cur.fetchone()["cnt"]
    if count == 0:
        from auth import hash_password

        seed_users = [
            ("admin",       "admin123", "admin"),
            ("doc",       "doc123",   "doctor"),
            ("rec", "rec123",   "receptionist"),
        ]

        for username, pwd, role in seed_users:
            pwd_hash = hash_password(pwd)
            cur.execute(
                "INSERT OR IGNORE INTO users (username, password_hash, role) VALUES (?,?,?)",
                (username, pwd_hash, role)
            )

        conn.commit()

    conn.close()

if __name__ == "__main__":
    init_db()
