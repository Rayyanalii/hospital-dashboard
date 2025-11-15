# logs.py
"""
Logging / audit helpers for the Hospital Dashboard.

Responsibilities:
- write_log(...) to append an audit entry for any important action
- fetch_logs(...) to retrieve recent logs with optional filters
- fetch_logs_df(...) to get logs as a pandas.DataFrame (useful for charts / exports)
- fetch_action_counts(...) to get aggregated counts (useful for activity graphs)
- export_logs_csv(...) to produce a CSV bytes object suitable for Streamlit download_button

All timestamps are stored in UTC ISO format for consistent auditing.
"""

from typing import Optional, List, Tuple
from datetime import datetime
from db import get_conn
import sqlite3
import io

def write_log(user_id: Optional[int], role: Optional[str], action: str, details: str = "") -> None:
    """
    Insert an audit log entry.
    - user_id: may be None for unknown/system events
    - role: textual role (admin/doctor/receptionist/system/unknown)
    - action: short action code (login, login_failed, add_patient, anonymize, view_logs, etc.)
    - details: free-text details (should avoid sensitive plaintext in production)
    """
    conn = None
    try:
        conn = get_conn()
        cur = conn.cursor()
        ts = datetime.utcnow().isoformat()  # UTC timestamp
        cur.execute(
            "INSERT INTO logs (user_id, role, action, timestamp, details) VALUES (?,?,?,?,?)",
            (user_id, role, action, ts, details)
        )
        conn.commit()
    except Exception:
        # In a real system you'd send this to a remote logger; for assignment just attempt safe cleanup
        try:
            if conn:
                conn.rollback()
        except Exception:
            pass
    finally:
        try:
            if conn:
                conn.close()
        except Exception:
            pass

def fetch_logs(limit: int = 200,
               role: Optional[str] = None,
               action: Optional[str] = None,
               user_id: Optional[int] = None,
               since_iso: Optional[str] = None) -> List[sqlite3.Row]:
    """
    Retrieve logs with optional filters.
    - limit: max rows returned (ordered by timestamp DESC)
    - role: filter by role string
    - action: filter by action string
    - user_id: filter by user_id
    - since_iso: ISO datetime string to filter logs after that timestamp (inclusive)

    Returns list of sqlite3.Row objects (so callers can index by column name).
    """
    conn = get_conn()
    cur = conn.cursor()
    try:
        q = "SELECT * FROM logs WHERE 1=1"
        params: List = []
        if role:
            q += " AND role = ?"
            params.append(role)
        if action:
            q += " AND action = ?"
            params.append(action)
        if user_id is not None:
            q += " AND user_id = ?"
            params.append(user_id)
        if since_iso:
            q += " AND timestamp >= ?"
            params.append(since_iso)
        q += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        cur.execute(q, tuple(params))
        rows = cur.fetchall()
        return rows
    finally:
        try:
            conn.close()
        except Exception:
            pass

def fetch_logs_df(limit: int = 1000,
                  role: Optional[str] = None,
                  action: Optional[str] = None,
                  user_id: Optional[int] = None,
                  since_iso: Optional[str] = None):
    """
    Return logs as a pandas DataFrame. Useful for display, filtering, exporting, and charting.
    Requires pandas (imported inside function to avoid forcing dependency on callers that don't need it).
    """
    try:
        import pandas as pd
    except Exception as e:
        raise RuntimeError("pandas is required for fetch_logs_df") from e

    rows = fetch_logs(limit=limit, role=role, action=action, user_id=user_id, since_iso=since_iso)
    if not rows:
        return pd.DataFrame(columns=["log_id", "user_id", "role", "action", "timestamp", "details"])
    # convert sqlite Row objects into dicts
    data = [dict(r) for r in rows]
    df = pd.DataFrame(data)
    # parse timestamp to datetime
    try:
        df["timestamp_dt"] = pd.to_datetime(df["timestamp"], errors="coerce")
    except Exception:
        df["timestamp_dt"] = None
    return df

def fetch_action_counts(window_days: int = 7) -> List[Tuple[str, int]]:
    """
    Return aggregated action counts for the last `window_days` days.
    Useful to plot activity trends for the dashboard bonus feature.
    Returns list of tuples: (action, count) ordered by count desc.
    """
    conn = get_conn()
    cur = conn.cursor()
    try:
        since = (datetime.utcnow()).isoformat()
        # Simple aggregation: count actions in last window_days (we provide since_iso as naive; caller can refine)
        # To avoid complex datetime math in SQL for SQLite, compute earliest timestamp in Python:
        cutoff = (datetime.utcnow()).fromtimestamp((datetime.utcnow()).timestamp() - window_days * 86400).isoformat()
        cur.execute("""
            SELECT action, COUNT(*) as cnt
            FROM logs
            WHERE timestamp >= ?
            GROUP BY action
            ORDER BY cnt DESC
            LIMIT 50
        """, (cutoff,))
        rows = cur.fetchall()
        return [(r["action"], r["cnt"]) for r in rows]
    finally:
        try:
            conn.close()
        except Exception:
            pass

def export_logs_csv(limit: int = 1000,
                    role: Optional[str] = None,
                    action: Optional[str] = None,
                    user_id: Optional[int] = None,
                    since_iso: Optional[str] = None) -> bytes:
    """
    Export filtered logs to CSV and return bytes suitable for Streamlit download_button.
    """
    try:
        import pandas as pd
    except Exception as e:
        raise RuntimeError("pandas is required for export_logs_csv") from e

    df = fetch_logs_df(limit=limit, role=role, action=action, user_id=user_id, since_iso=since_iso)
    # drop the helper timestamp_dt column before export if present
    if "timestamp_dt" in df.columns:
        df = df.drop(columns=["timestamp_dt"])
    csv_bytes = df.to_csv(index=False).encode("utf-8")
    return csv_bytes

# simple test when run directly
if __name__ == "__main__":
    # quick smoke test (you may need a DB initialized first)
    write_log(None, "system", "test_log", "Testing log insertion")
    rows = fetch_logs(limit=5)
    for r in rows:
        print(dict(r))
