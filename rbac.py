# rbac.py
"""
Role-Based Access Control helpers for the Hospital Dashboard.

Provides:
- ROLE_PERMS: permission matrix for each role
- can(role, permission): check a permission
- get_permissions(role): return full permission dict for a role
- list_roles(): convenience to list defined roles
- require_permission(permission): decorator that blocks calls when role lacks permission
    and writes an unauthorized_access log entry (best used where you have a `user` dict).
"""

from typing import Dict, Any, Callable, Optional
import functools

# --- Permission matrix ---
ROLE_PERMS: Dict[str, Dict[str, bool]] = {
    "admin": {"view_raw": True,  "view_anon": True,  "edit": True,  "view_logs": True,  "delete": True},
    "doctor": {"view_raw": False, "view_anon": True,  "edit": False, "view_logs": False, "delete": False},
    "receptionist": {"view_raw": False, "view_anon": False, "edit": True,  "view_logs": False, "delete": False},
    # you may add more roles here if needed
}

# --- Basic helpers ---
def can(role: Optional[str], permission: str) -> bool:
    """
    Return True if the role has the given permission.
    role may be None or invalid -> returns False.
    Example permissions: 'view_raw', 'view_anon', 'edit', 'view_logs', 'delete'
    """
    if not role:
        return False
    return ROLE_PERMS.get(role, {}).get(permission, False)

def get_permissions(role: str) -> Dict[str, bool]:
    """
    Return the permissions dict for a given role (empty dict if role unknown).
    """
    return ROLE_PERMS.get(role, {}).copy()

def list_roles() -> list:
    """Return a list of all defined roles."""
    return list(ROLE_PERMS.keys())

# --- Decorator for protecting functions / view handlers ---
def require_permission(permission: str) -> Callable:
    """
    Decorator factory to protect a function that expects a `user` dict as the first argument.
    If the user role lacks the permission, the wrapper returns None and writes an 'unauthorized_access' log.

    Usage example in app.py:
        @require_permission('view_raw')
        def protected_view(user, ...):
            # safe to assume user has permission here
            ...

    If you prefer to use this in Streamlit callbacks where you don't pass user as first arg,
    wrap a small lambda that injects st.session_state['user'].
    """
    def decorator(fn: Callable) -> Callable:
        @functools.wraps(fn)
        def wrapper(user: Optional[Dict[str, Any]], *args, **kwargs):
            role = None
            uid = None
            try:
                if isinstance(user, dict):
                    role = user.get("role")
                    uid = user.get("user_id")
            except Exception:
                role = None
            allowed = can(role, permission)
            if not allowed:
                # import locally to avoid circular import at module load time
                try:
                    from logs import write_log
                    write_log(uid, role or "unknown", "unauthorized_access", f"Attempted '{permission}' on protected function {fn.__name__}")
                except Exception:
                    # swallow errors because logging failure should not break caller
                    pass
                return None
            return fn(user, *args, **kwargs)
        return wrapper
    return decorator

# --- Convenience check + log function (useful in Streamlit pages) ---
def require_or_warn(user: Optional[Dict[str, Any]], permission: str) -> bool:
    """
    Check permission and, if missing, write an unauthorized_access log entry.
    Returns True if allowed, False otherwise.

    Use in Streamlit pages:
        if not require_or_warn(user, 'view_raw'):
            st.info("You do not have permission to view this.")
            return
    """
    role = None
    uid = None
    try:
        if isinstance(user, dict):
            role = user.get("role")
            uid = user.get("user_id")
    except Exception:
        role = None
    if can(role, permission):
        return True
    try:
        from logs import write_log
        write_log(uid, role or "unknown", "unauthorized_access", f"Attempted permission '{permission}'")
    except Exception:
        pass
    return False

# --- Optional: runtime role management (simple, in-memory) ---
def add_role(role_name: str, permissions: Dict[str, bool]) -> None:
    """
    Add a new role at runtime (in-memory). Not persistent.
    Use only for demos/testing.
    """
    ROLE_PERMS[role_name] = permissions.copy()

def update_role(role_name: str, permissions: Dict[str, bool]) -> None:
    """Overwrite permissions for an existing role."""
    ROLE_PERMS[role_name] = permissions.copy()

# --- Example usage (not executed on import) ---
if __name__ == "__main__":
    print("Defined roles:", list_roles())
    print("Admin can view_raw?", can("admin", "view_raw"))
    print("Doctor can edit?", can("doctor", "edit"))
