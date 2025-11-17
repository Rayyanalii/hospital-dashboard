
from cryptography.fernet import Fernet, InvalidToken
from pathlib import Path
import os
import hashlib
import logging
from typing import Optional, Tuple

logger = logging.getLogger(__name__)

FERNET_KEY_PATH = Path(".fernet.key")
ENV_FERNET_KEY = "FERNET_KEY" 

def get_or_create_key() -> bytes:
 
    env_key = os.getenv(ENV_FERNET_KEY)
    if env_key:
        try:
            return env_key.encode() if isinstance(env_key, str) else env_key
        except Exception:
            logger.exception("FERNET_KEY environment variable present but invalid; falling back to file/key generation")

    if not FERNET_KEY_PATH.exists():
        key = Fernet.generate_key()
        try:
            FERNET_KEY_PATH.write_bytes(key)
            try:
                os.chmod(FERNET_KEY_PATH, 0o600)
            except Exception:
                pass
        except Exception:
            logger.exception("Failed to write .fernet.key; using in-memory key")
            return key
        return key
    else:
        return FERNET_KEY_PATH.read_bytes()

try:
    _FERNET_KEY = get_or_create_key()
    FERNET = Fernet(_FERNET_KEY)
except Exception as e:
    logger.exception("Failed to initialize Fernet key - encryption functions will raise")
    FERNET = None 


def encrypt_value(value: Optional[str]) -> Optional[bytes]:
 
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
  
    if token is None:
        return None
    if FERNET is None:
        raise ValueError("Fernet not initialized")
    try:
        if isinstance(token, memoryview):
            token = token.tobytes()
        if isinstance(token, str):
            token = token.encode()
        return FERNET.decrypt(token).decode("utf-8")
    except InvalidToken:
        logger.warning("Failed to decrypt token (InvalidToken)")
        return None
    except Exception:
        logger.exception("Unexpected error during decrypt_value")
        return None

def _stable_numeric_tag(seed: str, width: int = 4) -> str:
   
    if seed is None:
        seed = ""
    h = hashlib.sha256(seed.encode("utf-8")).hexdigest()
    val = int(h[-12:], 16)  
    tag = str(val % (10 ** width)).zfill(width)
    return tag

def mask_name(name: Optional[str], id_for_tag: Optional[int] = None) -> str:

    seed = str(id_for_tag) if id_for_tag is not None else (name or "")
    tag = _stable_numeric_tag(seed, width=4)
    return f"ANON_{tag}"

def mask_contact(contact: Optional[str]) -> str:
  
    if not contact:
        return "XXX-XXX-XXXX"
    digits = "".join(ch for ch in contact if ch.isdigit())
    if len(digits) >= 4:
        return f"XXX-XXX-{digits[-4:]}"
    elif len(digits) > 0:
        return f"XXX-XXX-{digits.zfill(4)[-4:]}"
    else:
        return "XXX-XXX-XXXX"

def mask_diagnosis(diagnosis: Optional[str], show_partial: bool = False, partial_chars: int = 15) -> str:
 
    if not diagnosis:
        return "REDACTED"
    if show_partial:
        txt = diagnosis.strip()
        if len(txt) <= partial_chars:
            return txt
        return txt[:partial_chars].rstrip() + "..."
    return "REDACTED"

def anonymize_record(name: Optional[str], contact: Optional[str], patient_id: Optional[int] = None,
                     encrypt_raw: bool = False) -> Tuple[str, str, Optional[bytes], Optional[bytes]]:

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
            enc_name = None
            enc_contact = None
    return anon_name, anon_contact, enc_name, enc_contact

def anonymize_bulk(rows: list, encrypt_raw: bool = False) -> list:

    out = []
    for r in rows:
        pid = r.get("patient_id")
        name = r.get("name")
        contact = r.get("contact")
        anon_name, anon_contact, enc_name, enc_contact = anonymize_record(name, contact, patient_id=pid,
                                                                         encrypt_raw=encrypt_raw)
        out.append((pid, anon_name, anon_contact, enc_name, enc_contact))
    return out


def safe_str(s: Optional[str]) -> str:
    return "" if s is None else str(s)


if __name__ == "__main__":
    print("FERNET initialized:", FERNET is not None)
    print("Anon for 'Alice', id=1:", mask_name("Alice", 1))
    print("Mask contact:", mask_contact("+92-300-1234567"))
    enc = encrypt_value("secret")
    print("Encrypted (len):", len(enc) if enc else None)
    print("Decrypted:", decrypt_value(enc))
