from typing import Dict, Any, Callable, Optional
import functools

ROLE_PERMS: Dict[str, Dict[str, bool]] = {
    "admin": {"view_raw": True,  "view_anon": True,  "edit": True,  "view_logs": True,  "delete": True},
    "doctor": {"view_raw": False, "view_anon": True,  "edit": False, "view_logs": False, "delete": False},
    "receptionist": {"view_raw": False, "view_anon": False, "edit": True,  "view_logs": False, "delete": False},
}

def can(role: Optional[str], permission: str) -> bool:
    if not role:
        return False
    return ROLE_PERMS.get(role, {}).get(permission, False)

def get_permissions(role: str) -> Dict[str, bool]:
  
    return ROLE_PERMS.get(role, {}).copy()

def list_roles() -> list:
    return list(ROLE_PERMS.keys())

def require_permission(permission: str) -> Callable:
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
                try:
                    from logs import write_log
                    write_log(uid, role or "unknown", "unauthorized_access", f"Attempted '{permission}' on protected function {fn.__name__}")
                except Exception:
                    pass
                return None
            return fn(user, *args, **kwargs)
        return wrapper
    return decorator

def require_or_warn(user: Optional[Dict[str, Any]], permission: str) -> bool:
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

def add_role(role_name: str, permissions: Dict[str, bool]) -> None:
 
    ROLE_PERMS[role_name] = permissions.copy()

def update_role(role_name: str, permissions: Dict[str, bool]) -> None:
    ROLE_PERMS[role_name] = permissions.copy()

if __name__ == "__main__":
    print("Defined roles:", list_roles())
    print("Admin can view_raw?", can("admin", "view_raw"))
    print("Doctor can edit?", can("doctor", "edit"))
