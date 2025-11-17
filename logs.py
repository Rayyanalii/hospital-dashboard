
from typing import Optional, List, Tuple
from datetime import datetime
from db import get_conn
import sqlite3
import io

def write_log(user_id: Optional[int], role: Optional[str], action: str, details: str = "") -> None:

    conn = None
    try:
        conn = get_conn()
        cur = conn.cursor()
        ts = datetime.utcnow().isoformat() 
        cur.execute(
            "INSERT INTO logs (user_id, role, action, timestamp, details) VALUES (?,?,?,?,?)",
            (user_id, role, action, ts, details)
        )
        conn.commit()
    except Exception:
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

    try:
        import pandas as pd
    except Exception as e:
        raise RuntimeError("pandas is required for fetch_logs_df") from e

    rows = fetch_logs(limit=limit, role=role, action=action, user_id=user_id, since_iso=since_iso)
    if not rows:
        return pd.DataFrame(columns=["log_id", "user_id", "role", "action", "timestamp", "details"])
    data = [dict(r) for r in rows]
    df = pd.DataFrame(data)
    try:
        df["timestamp_dt"] = pd.to_datetime(df["timestamp"], errors="coerce")
    except Exception:
        df["timestamp_dt"] = None
    return df

def fetch_action_counts(window_days: int = 7) -> List[Tuple[str, int]]:
 
    conn = get_conn()
    cur = conn.cursor()
    try:
        since = (datetime.utcnow()).isoformat()

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
 
    try:
        import pandas as pd
    except Exception as e:
        raise RuntimeError("pandas is required for export_logs_csv") from e

    df = fetch_logs_df(limit=limit, role=role, action=action, user_id=user_id, since_iso=since_iso)
    if "timestamp_dt" in df.columns:
        df = df.drop(columns=["timestamp_dt"])
    csv_bytes = df.to_csv(index=False).encode("utf-8")
    return csv_bytes

if __name__ == "__main__":
    write_log(None, "system", "test_log", "Testing log insertion")
    rows = fetch_logs(limit=5)
    for r in rows:
        print(dict(r))
