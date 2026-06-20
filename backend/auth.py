# backend/auth.py
from pathlib import Path
from fastapi import Header, HTTPException
import firebase_admin
from firebase_admin import auth, credentials

SERVICE_ACCOUNT = Path("backend/firebase_service_account.json")
_firebase_app = None

def init_firebase():
    global _firebase_app
    if _firebase_app is None:
        if not SERVICE_ACCOUNT.exists():
            raise RuntimeError("Missing backend/firebase_service_account.json")
        cred = credentials.Certificate(str(SERVICE_ACCOUNT))
        _firebase_app = firebase_admin.initialize_app(cred)
    return _firebase_app

def require_user(authorization: str | None = Header(default=None)):
    """
    Require: Authorization: Bearer <FirebaseIdToken>
    """
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing token")

    token = authorization.split(" ", 1)[1].strip()
    init_firebase()
    try:
        decoded = auth.verify_id_token(token)
        return decoded  # contains uid, email, etc.
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")

def optional_user(authorization: str | None = Header(default=None)):
    """
    Optional token. Returns decoded user or None.
    """
    if not authorization or not authorization.lower().startswith("bearer "):
        return None
    token = authorization.split(" ", 1)[1].strip()
    init_firebase()
    try:
        return auth.verify_id_token(token)
    except Exception:
        return None
