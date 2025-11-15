# security.py
"""
Security helpers for the Hospital Dashboard.

Provides:
- Fernet-based reversible encryption (enc/dec) for optional reversible pseudonymization.
- Deterministic anonymized label generation (ANON_####) that is stable across runs.
- Masking helpers for contact numbers and diagnoses.
- Convenience functions that produce anonymized/encrypted values for a patient record.

Important:
- The Fernet key is stored in `.fernet.key` by default. **Do NOT** commit that file to a public repo.
- If you want to provide your own key, set environment variable FERNET_KEY (base64 urlsafe).
"""

from cryptography.fernet import Fernet, InvalidToken
from pathlib import Path
import os
import hashlib
import logging
from typing import Optional, Tuple

logger = logging.getLogger(__name__)

FERNET_KEY_PATH = Path(".fernet.key")
ENV_FERNET_KEY = "FERNET_KEY"  # optionally supply base64 key via env var

def get_or_create_key() -> bytes:
    """
    Return a Fernet key (bytes). Priority:
      1. ENV_FERNET_KEY environment variable (base64 urlsafe string)
      2. .fernet.key file in project root
      3. generate a new key, save to .fernet.key and return it

    NOTE: Keep the key secret. For demo/assignment it's convenient to keep
    a local key file but in production use a secret manager.
    """
    # env var
    env_key = os.getenv(ENV_FERNET_KEY)
    if env_key:
        try:
            return env_key.encode() if isinstance(env_key, str) else env_key
        except Exception:
            logger.exception("FERNET_KEY environment variable present but invalid; falling back to file/key generation")

    # file
    if not FERNET_KEY_PATH.exists():
        key = Fernet.generate_key()
        try:
            FERNET_KEY_PATH.write_bytes(key)
            # restrict permissions where possible (best-effort)
            try:
                os.chmod(FERNET_KEY_PATH, 0o600)
            except Exception:
                pass
        except Exception:
            # fallback: return in-memory key without saving
            logger.exception("Failed to write .fernet.key; using in-memory key")
            return key
        return key
    else:
        return FERNET_KEY_PATH.read_bytes()

# create Fernet instance (module-level)
try:
    _FERNET_KEY = get_or_create_key()
    FERNET = Fernet(_FERNET_KEY)
except Exception as e:
    logger.exception("Failed to initialize Fernet key - encryption functions will raise")
    FERNET = None  # encryption functions will check this

# -----------------------------
# Encryption helper functions
# -----------------------------
def encrypt_value(value: Optional[str]) -> Optional[bytes]:
    """
    Encrypt a string value with Fernet and return bytes suitable for storing as BLOB.
    Returns None if input is None/empty.

    Raises ValueError if Fernet is not initialized.
    """
    if value is None:
        return None
    if FERNET is None:
        raise ValueError("Fernet not initialized")
    if not isinstance(value, str):
        value = str(value)
    try:
        return FERNET.encrypt(value.encode("utf-8"))
    except Exception:
        logger.exception("Encryption failed")
        raise

def decrypt_value(token: Optional[bytes]) -> Optional[str]:
    """
    Decrypt bytes produced by encrypt_value and return the original string, or None if token is None.
    Accepts bytes or memoryview objects as returned by some DB drivers.
    """
    if token is None:
        return None
    if FERNET is None:
        raise ValueError("Fernet not initialized")
    try:
        # Some drivers return memoryview; ensure bytes
        if isinstance(token, memoryview):
            token = token.tobytes()
        if isinstance(token, str):
            # maybe stored as str; attempt encoding
            token = token.encode()
        return FERNET.decrypt(token).decode("utf-8")
    except InvalidToken:
        logger.warning("Failed to decrypt token (InvalidToken)")
        return None
    except Exception:
        logger.exception("Unexpected error during decrypt_value")
        return None

# -----------------------------
# Masking / Anonymization
# -----------------------------
def _stable_numeric_tag(seed: str, width: int = 4) -> str:
    """
    Produce a stable numeric tag string from an input string.
    Uses SHA256, returns last `width` digits (zero-padded).
    This is deterministic across runs and Python versions.
    """
    if seed is None:
        seed = ""
    h = hashlib.sha256(seed.encode("utf-8")).hexdigest()
    # take some hex, convert to int, mod by a power of 10
    val = int(h[-12:], 16)  # last 12 hex chars -> large number
    tag = str(val % (10 ** width)).zfill(width)
    return tag

def mask_name(name: Optional[str], id_for_tag: Optional[int] = None) -> str:
    """
    Return an anonymized label like 'ANON_1021'.
    If id_for_tag provided, tag is derived from the id (stable); otherwise derived from name.
    """
    seed = str(id_for_tag) if id_for_tag is not None else (name or "")
    tag = _stable_numeric_tag(seed, width=4)
    return f"ANON_{tag}"

def mask_contact(contact: Optional[str]) -> str:
    """
    Mask a contact number to format 'XXX-XXX-1234' showing only last 4 digits if available.
    Non-digit characters in the input are ignored.
    """
    if not contact:
        return "XXX-XXX-XXXX"
    digits = "".join(ch for ch in contact if ch.isdigit())
    if len(digits) >= 4:
        return f"XXX-XXX-{digits[-4:]}"
    elif len(digits) > 0:
        # preserve last available digits
        return f"XXX-XXX-{digits.zfill(4)[-4:]}"
    else:
        return "XXX-XXX-XXXX"

def mask_diagnosis(diagnosis: Optional[str], show_partial: bool = False, partial_chars: int = 15) -> str:
    """
    Mask diagnosis text. By default returns 'REDACTED'.
    If show_partial=True, returns the first `partial_chars` characters followed by '...'
    Useful when doctors need some context but full text should be protected.
    """
    if not diagnosis:
        return "REDACTED"
    if show_partial:
        txt = diagnosis.strip()
        if len(txt) <= partial_chars:
            return txt
        return txt[:partial_chars].rstrip() + "..."
    return "REDACTED"

# -----------------------------
# High-level helpers
# -----------------------------
def anonymize_record(name: Optional[str], contact: Optional[str], patient_id: Optional[int] = None,
                     encrypt_raw: bool = False) -> Tuple[str, str, Optional[bytes], Optional[bytes]]:
    """
    Given raw name and contact, return a tuple:
        (anonymized_name, anonymized_contact, enc_name_or_None, enc_contact_or_None)

    - anonymized_name: deterministic label 'ANON_xxxx'
    - anonymized_contact: masked contact 'XXX-XXX-1234'
    - enc_name_or_None, enc_contact_or_None: optional Fernet-encrypted bytes when encrypt_raw=True

    This helper is intended to be used by the Admin anonymize flow to update DB columns:
        anonymized_name, anonymized_contact, [enc_name, enc_contact]
    """
    anon_name = mask_name(name, id_for_tag=patient_id)
    anon_contact = mask_contact(contact)
    enc_name = None
    enc_contact = None
    if encrypt_raw:
        try:
            enc_name = encrypt_value(name) if name is not None else None
            enc_contact = encrypt_value(contact) if contact is not None else None
        except Exception:
            logger.exception("Failed to encrypt raw values during anonymize_record")
            # leave enc_* as None on failure
            enc_name = None
            enc_contact = None
    return anon_name, anon_contact, enc_name, enc_contact

def anonymize_bulk(rows: list, encrypt_raw: bool = False) -> list:
    """
    Given a list of rows (iterable of dict-like objects with keys 'patient_id','name','contact'),
    return a list of updates: each item is (patient_id, anon_name, anon_contact, enc_name, enc_contact)

    Example row input: [{'patient_id':1,'name':'Alice','contact':'03001234567'}, ...]
    """
    out = []
    for r in rows:
        pid = r.get("patient_id")
        name = r.get("name")
        contact = r.get("contact")
        anon_name, anon_contact, enc_name, enc_contact = anonymize_record(name, contact, patient_id=pid,
                                                                         encrypt_raw=encrypt_raw)
        out.append((pid, anon_name, anon_contact, enc_name, enc_contact))
    return out

# -----------------------------
# Small utility - safe string trimming
# -----------------------------
def safe_str(s: Optional[str]) -> str:
    return "" if s is None else str(s)

# -----------------------------
# Example usage (not executed at import)
# -----------------------------
if __name__ == "__main__":
    # quick self-test
    print("FERNET initialized:", FERNET is not None)
    print("Anon for 'Alice', id=1:", mask_name("Alice", 1))
    print("Mask contact:", mask_contact("+92-300-1234567"))
    enc = encrypt_value("secret")
    print("Encrypted (len):", len(enc) if enc else None)
    print("Decrypted:", decrypt_value(enc))
