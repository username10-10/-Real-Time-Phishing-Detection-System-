import firebase_admin
from firebase_admin import credentials, auth, firestore

SERVICE_ACCOUNT_PATH = "backend/firebase_service_account.json"

_app = None
_db = None

def _init():
    global _app, _db
    if _app is None:
        cred = credentials.Certificate(SERVICE_ACCOUNT_PATH)
        _app = firebase_admin.initialize_app(cred)
        _db = firestore.client()

def get_db():
    _init()
    return _db

def verify_id_token(id_token: str):
    _init()
    return auth.verify_id_token(id_token)
