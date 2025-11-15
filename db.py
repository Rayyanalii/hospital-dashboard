# db.py
import sqlite3
from pathlib import Path

DB_PATH = Path("hospital.db")

def get_conn():
    """
    Return a SQLite connection with Row factory, so you can access
    columns by name (row['col']) instead of indices.
    """
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """
    Initialize the database schema if it does not exist and seed default users.
    This function is safe to call multiple times.
    """
    conn = get_conn()
    cur = conn.cursor()

    # --- Core tables (users, patients, logs) ---
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

    # --- Seed default users if table is empty ---
    cur.execute("SELECT COUNT(*) AS cnt FROM users")
    count = cur.fetchone()["cnt"]
    if count == 0:
        # Import here to avoid circular import issues
        from auth import hash_password

        # Default demo users:
        #   admin / admin123  → admin
        #   drbob / doc123    → doctor
        #   alice_recep / rec123 → receptionist
        seed_users = [
            ("admin",       "admin123", "admin"),
            ("drbob",       "doc123",   "doctor"),
            ("alice_recep", "rec123",   "receptionist"),
        ]

        for username, pwd, role in seed_users:
            pwd_hash = hash_password(pwd)
            cur.execute(
                "INSERT OR IGNORE INTO users (username, password_hash, role) VALUES (?,?,?)",
                (username, pwd_hash, role)
            )

        conn.commit()

    # --- Optional: prepare columns for reversible encryption (bonus) ---
    # These are handled in the app's anonymize page with ALTER TABLE, but if you
    # want them always present from the start, uncomment this block.
    """
    try:
        cur.execute("ALTER TABLE patients ADD COLUMN enc_name BLOB")
    except sqlite3.OperationalError:
        # Column already exists
        pass

    try:
        cur.execute("ALTER TABLE patients ADD COLUMN enc_contact BLOB")
    except sqlite3.OperationalError:
        # Column already exists
        pass

    conn.commit()
    """

    conn.close()

if __name__ == "__main__":
    init_db()
