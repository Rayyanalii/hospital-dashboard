import os
import hashlib
import binascii
from datetime import datetime
from typing import Optional, Dict

_PBKDF2_ALGO = "sha256"
_PBKDF2_ITERATIONS = 100_000
_SALT_BYTES = 16

ROLE_PERMS = {
    "admin": {"view_raw": True, "view_anon": True, "edit": True, "view_logs": True},
    "doctor": {"view_raw": False, "view_anon": True, "edit": False, "view_logs": False},
    "receptionist": {"view_raw": False, "view_anon": False, "edit": True, "view_logs": False},
}

def hash_password(password: str, salt: Optional[bytes] = None) -> str:
    """
    Hash a password using PBKDF2-HMAC-SHA256 with a random salt.
    Returns a string in the format: salt_hex:hash_hex
    """
    if salt is None:
        salt = os.urandom(_SALT_BYTES)
    dk = hashlib.pbkdf2_hmac(_PBKDF2_ALGO, password.encode("utf-8"), salt, _PBKDF2_ITERATIONS)
    return binascii.hexlify(salt).decode() + ":" + binascii.hexlify(dk).decode()

def verify_password(password: str, stored: str) -> bool:
    try:
        salt_hex, dk_hex = stored.split(":")
    except Exception:
        return False
    salt = binascii.unhexlify(salt_hex)
    dk = hashlib.pbkdf2_hmac(_PBKDF2_ALGO, password.encode("utf-8"), salt, _PBKDF2_ITERATIONS)
    return binascii.hexlify(dk).decode() == dk_hex

def can(role: str, permission: str) -> bool:
 
    return ROLE_PERMS.get(role, {}).get(permission, False)

def authenticate(username: str, password: str) -> Optional[Dict]:
    from db import get_conn
    from logs import write_log

    try:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT user_id, password_hash, role FROM users WHERE username = ?", (username,))
        row = cur.fetchone()
        conn.close()
    except Exception as e:
        try:
            write_log(None, "unknown", "auth_db_error", f"auth DB error for {username}: {str(e)}")
        except Exception:
            pass
        return None

    if not row:
        try:
            write_log(None, "unknown", "login_failed", f"username={username} not found")
        except Exception:
            pass
        return None

    try:
        stored_hash = row["password_hash"]
        if verify_password(password, stored_hash):
            user = {"user_id": row["user_id"], "username": username, "role": row["role"]}
            try:
                write_log(user["user_id"], user["role"], "login_success", f"{username} logged in")
            except Exception:
                pass
            return user
        else:
            try:
                write_log(row["user_id"], row["role"], "login_failed", f"Incorrect password for {username}")
            except Exception:
                pass
            return None
    except Exception as e:
        try:
            write_log(row["user_id"], row["role"], "auth_error", f"Error during authentication: {str(e)}")
        except Exception:
            pass
        return None

def create_user(username: str, password: str, role: str) -> bool:
    from db import get_conn
    from logs import write_log

    if role not in ROLE_PERMS:
        raise ValueError(f"Unknown role '{role}'. Allowed roles: {list(ROLE_PERMS.keys())}")

    pwd_hash = hash_password(password)
    try:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("INSERT INTO users (username, password_hash, role) VALUES (?,?,?)",
                    (username, pwd_hash, role))
        conn.commit()
        new_id = cur.lastrowid
        conn.close()
        try:
            write_log(new_id, role, "create_user", f"User created: {username} (role={role})")
        except Exception:
            pass
        return True
    except Exception as e:
        try:
            write_log(None, "system", "create_user_failed", f"Failed to create {username}: {str(e)}")
        except Exception:
            pass
        return False

def change_password(user_id: int, new_password: str) -> bool:

    from db import get_conn
    from logs import write_log

    pwd_hash = hash_password(new_password)
    try:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("UPDATE users SET password_hash = ? WHERE user_id = ?", (pwd_hash, user_id))
        conn.commit()
        conn.close()
        try:
            write_log(user_id, None, "change_password", "Password changed")
        except Exception:
            pass
        return True
    except Exception as e:
        try:
            write_log(user_id, None, "change_password_failed", str(e))
        except Exception:
            pass
        return False

def get_user_by_id(user_id: int) -> Optional[Dict]:
 
    from db import get_conn
    try:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT user_id, username, role FROM users WHERE user_id = ?", (user_id,))
        row = cur.fetchone()
        conn.close()
        if not row:
            return None
        return {"user_id": row["user_id"], "username": row["username"], "role": row["role"]}
    except Exception:
        return None

def require_permission(permission: str):

    def decorator(func):
        def wrapper(user, *args, **kwargs):
            role = user.get("role") if isinstance(user, dict) else None
            if not role or not can(role, permission):
                try:
                    from logs import write_log
                    uid = user.get("user_id") if isinstance(user, dict) else None
                    write_log(uid, role or "unknown", "unauthorized_access", f"Attempted {permission}")
                except Exception:
                    pass
                return None
            return func(user, *args, **kwargs)
        return wrapper
    return decorator
