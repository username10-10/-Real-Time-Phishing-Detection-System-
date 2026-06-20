# backend/main.py
import json
import time
from pathlib import Path
from urllib.parse import urlparse

import joblib
import numpy as np
from fastapi import FastAPI, Header, HTTPException
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from ml.feature_extraction import extract_features
from backend.firebase import get_db, verify_id_token

# ----------------------------
# Cached SHAP explainer
# Created only once, then reused for faster XAI loading
# ----------------------------
shap_explainer = None

# -------------------------------------------------
# Stable absolute paths
# Project structure:
# PHISHING-DETECTION-XAI/
#   backend/main.py
#   dashboard/...
#   model/...
# -------------------------------------------------
BACKEND_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = BACKEND_DIR.parent
DASH_DIR = PROJECT_ROOT / "dashboard"
MODEL_DIR = PROJECT_ROOT / "model"

print("✅ PROJECT_ROOT =", PROJECT_ROOT)
print("✅ DASH_DIR     =", DASH_DIR)
print("✅ MODEL_DIR    =", MODEL_DIR)

# ----------------------------
# Model paths
# ----------------------------
RF_MODEL_PATH = MODEL_DIR / "rf_model.pkl"
RF_THRESH_PATH = MODEL_DIR / "rf_threshold.txt"
FEATURE_COLS_PATH = MODEL_DIR / "feature_columns.json"

CNN_MODEL_PATH = MODEL_DIR / "cnn_model.h5"
CNN_TOKEN_PATH = MODEL_DIR / "cnn_tokenizer.json"
CNN_MAXLEN_PATH = MODEL_DIR / "cnn_maxlen.txt"
CNN_THR_PATH = MODEL_DIR / "cnn_threshold.txt"

# ----------------------------
# Fusion policy
# ----------------------------
# Final score policy:
# score < 0.70       = safe
# 0.70 <= score < .90 = warn
# score >= 0.90      = block
POLICY_WARN = 0.70
POLICY_BLOCK = 0.90

# If RF and CNN differ by more than this value,
# system stores it as model disagreement.
# IMPORTANT: disagreement is now only an explanation reason,
# not an automatic warning trigger.
MODEL_DISAGREE_GAP = 0.40

# ----------------------------
# Load RF model + feature columns
# ----------------------------
rf_model = joblib.load(RF_MODEL_PATH) if RF_MODEL_PATH.exists() else None
rf_threshold = float(RF_THRESH_PATH.read_text().strip()) if RF_THRESH_PATH.exists() else 0.5
feature_cols = json.loads(FEATURE_COLS_PATH.read_text()) if FEATURE_COLS_PATH.exists() else None

# ----------------------------
# Load CNN model
# ----------------------------
cnn_model = None
cnn_tokenizer = None
cnn_maxlen = 200
cnn_threshold = 0.97

try:
    if CNN_MODEL_PATH.exists():
        from tensorflow.keras.models import load_model

        cnn_model = load_model(CNN_MODEL_PATH)

        if CNN_TOKEN_PATH.exists():
            cnn_tokenizer = json.loads(CNN_TOKEN_PATH.read_text())

        if CNN_MAXLEN_PATH.exists():
            cnn_maxlen = int(CNN_MAXLEN_PATH.read_text().strip())

        if CNN_THR_PATH.exists():
            cnn_threshold = float(CNN_THR_PATH.read_text().strip())

except Exception as e:
    print("⚠️ CNN load failed:", e)
    cnn_model = None
    cnn_tokenizer = None


# ----------------------------
# Helper functions
# ----------------------------
def normalize_url(u: str) -> str:
    u = str(u).strip()

    if not u:
        return ""

    if not u.startswith(("http://", "https://")):
        u = "http://" + u

    return u


def get_domain(url: str) -> str:
    try:
        parsed = urlparse(url)
        host = (parsed.netloc or "").lower()
        return host.split(":")[0]
    except Exception:
        return ""


def is_local_dev(url: str) -> bool:
    domain = get_domain(url)
    return domain in {"127.0.0.1", "localhost"} or domain.endswith(".local")


def auth_required(authorization: str | None):
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing Bearer token")

    token = authorization.split(" ", 1)[1].strip()

    try:
        decoded = verify_id_token(token)
        return decoded
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"Invalid token: {e}")


def ensure_feature_row(url: str):
    feats = extract_features(url)

    if feature_cols:
        row = {c: feats.get(c, 0) for c in feature_cols}
    else:
        row = feats

    X = np.array([list(row.values())], dtype=float)
    return X, row


def cnn_encode(url: str) -> np.ndarray:
    """
    Tokenizer JSON expected format:
    {
        "char2idx": {...},
        "unk": 1,
        "pad": 0
    }
    """
    if not cnn_tokenizer:
        return np.zeros((1, cnn_maxlen), dtype=np.int32)

    char2idx = cnn_tokenizer.get("char2idx", {})
    unk = int(cnn_tokenizer.get("unk", 1))
    pad = int(cnn_tokenizer.get("pad", 0))

    s = url[:cnn_maxlen]
    arr = [int(char2idx.get(ch, unk)) for ch in s]

    if len(arr) < cnn_maxlen:
        arr += [pad] * (cnn_maxlen - len(arr))

    return np.array([arr], dtype=np.int32)


def adaptive_weights(rf_prob, cnn_prob):
    """
    Adaptive weighting:
    The model that is further away from 0.5 is treated as more confident.
    """
    if rf_prob is None or cnn_prob is None:
        return 0.5, 0.5

    rf_conf = abs(rf_prob - 0.5)
    cnn_conf = abs(cnn_prob - 0.5)

    total = rf_conf + cnn_conf + 1e-6

    return rf_conf / total, cnn_conf / total


def predict_fusion(url: str) -> dict:
    url = normalize_url(url)
    domain = get_domain(url)

    # ----------------------------
    # Local development bypass
    # ----------------------------
    if is_local_dev(url):
        return {
            "url": url,
            "domain": domain,
            "rf_prob": 0.0,
            "cnn_prob": 0.0,
            "final_score": 0.0,
            "action": "safe",
            "type_pred": "benign",
            "reason": "local_dev_bypass",
            "fusion": "local_bypass",
            "uncertainty": False,
            "policy": {
                "warn": POLICY_WARN,
                "block": POLICY_BLOCK
            },
            "weights": {
                "rf": None,
                "cnn": None
            },
        }

    # ----------------------------
    # Random Forest prediction
    # ----------------------------
    rf_prob = None

    if rf_model is not None:
        X_rf, _ = ensure_feature_row(url)
        rf_prob = float(rf_model.predict_proba(X_rf)[0, 1])

    # ----------------------------
    # CNN prediction
    # ----------------------------
    cnn_prob = None

    if cnn_model is not None:
        X_cnn = cnn_encode(url)
        cnn_prob = float(cnn_model.predict(X_cnn, verbose=0)[0, 0])

    # ----------------------------
    # Fallback if no models loaded
    # ----------------------------
    if rf_prob is None and cnn_prob is None:
        return {
            "url": url,
            "domain": domain,
            "rf_prob": None,
            "cnn_prob": None,
            "final_score": 0.0,
            "action": "safe",
            "type_pred": "unknown",
            "reason": "no_models_loaded",
            "fusion": "none",
            "uncertainty": False,
            "policy": {
                "warn": POLICY_WARN,
                "block": POLICY_BLOCK
            },
            "weights": {
                "rf": None,
                "cnn": None
            },
        }

    # ----------------------------
    # Fusion score
    # ----------------------------
    if rf_prob is None:
        final_score = cnn_prob
        fusion = "cnn_only"
        w_rf, w_cnn = None, 1.0

    elif cnn_prob is None:
        final_score = rf_prob
        fusion = "rf_only"
        w_rf, w_cnn = 1.0, None

    else:
        w_rf, w_cnn = adaptive_weights(rf_prob, cnn_prob)
        final_score = (w_rf * rf_prob) + (w_cnn * cnn_prob)
        fusion = "adaptive_rf_cnn"

    final_score = float(final_score)

    # ----------------------------
    # Model disagreement / uncertainty
    # ----------------------------
    uncertainty = False

    if rf_prob is not None and cnn_prob is not None:
        if abs(rf_prob - cnn_prob) > MODEL_DISAGREE_GAP:
            uncertainty = True

    # ----------------------------
    # Decision logic
    # IMPORTANT:
    # Model disagreement does NOT automatically trigger warning anymore.
    # Warning/block decision is based on final_score policy.
    # ----------------------------
    if final_score >= POLICY_BLOCK:
        action = "block"
        type_pred = "phishing"

        if uncertainty:
            reason = "model_disagreement"
        else:
            reason = "high_confidence"

    elif final_score >= POLICY_WARN:
        action = "warn"
        type_pred = "suspicious"

        if uncertainty:
            reason = "model_disagreement"
        else:
            reason = "medium_confidence"

    else:
        action = "safe"
        type_pred = "benign"

        if uncertainty:
            reason = "model_disagreement_low_risk"
        else:
            reason = "low_risk"

    return {
        "url": url,
        "domain": domain,
        "rf_prob": rf_prob,
        "cnn_prob": cnn_prob,
        "final_score": final_score,
        "action": action,
        "type_pred": type_pred,
        "reason": reason,
        "fusion": fusion,
        "uncertainty": uncertainty,
        "policy": {
            "warn": POLICY_WARN,
            "block": POLICY_BLOCK
        },
        "weights": {
            "rf": float(w_rf) if w_rf is not None else None,
            "cnn": float(w_cnn) if w_cnn is not None else None,
        },
    }


# ----------------------------
# FastAPI setup
# ----------------------------
app = FastAPI(title="Phishing Detector (RF + Char-CNN)", version="0.1.0")

if DASH_DIR.exists():
    app.mount("/dashboard", StaticFiles(directory=str(DASH_DIR), html=True), name="dashboard")
else:
    print("❌ DASHBOARD folder not found at:", DASH_DIR)


# ----------------------------
# Request models
# ----------------------------
class PredictRequest(BaseModel):
    url: str


class FeedbackRequest(BaseModel):
    url: str
    verdict: str  # "safe" or "phishing"


class AuditLogRequest(BaseModel):
    action: str
    status: str
    email: str | None = None
    details: dict = {}
    userAgent: str | None = None
    source: str | None = None
    client_timestamp: str | None = None


# ----------------------------
# Audit log endpoint
# ----------------------------
@app.post("/audit-log")
def audit_log(req: AuditLogRequest, authorization: str | None = Header(default=None)):
    db = get_db()

    uid = "anonymous"
    email = req.email or "unknown"

    if authorization and authorization.lower().startswith("bearer "):
        try:
            user = auth_required(authorization)
            uid = user.get("uid", "unknown")
            email = user.get("email", email)
        except Exception:
            pass

    doc = {
        "uid": uid,
        "email": email,
        "action": req.action,
        "status": req.status,
        "details": req.details,
        "userAgent": req.userAgent,
        "source": req.source or "chrome_extension_popup",
        "client_timestamp": req.client_timestamp,
        "timestamp": int(time.time())
    }

    write_result = db.collection("audit_logs").add(doc)

    return {
        "ok": True,
        "log_id": write_result[1].id
    }


# ----------------------------
# Prediction endpoint
# ----------------------------
@app.post("/predict")
def predict(req: PredictRequest, authorization: str | None = Header(default=None)):
    result = predict_fusion(req.url)

    uid = None
    email = ""
    overridden_by_list = False

    # If token exists, identify user and apply user allow/block lists
    if authorization and authorization.lower().startswith("bearer "):
        user = auth_required(authorization)
        uid = user.get("uid")
        email = user.get("email", "")
        db = get_db()

        ref = db.collection("user_lists").document(uid)
        snap = ref.get()
        data = snap.to_dict() if snap.exists else {"safe": [], "phishing": []}

        safe_set = set(data.get("safe") or [])
        phish_set = set(data.get("phishing") or [])

        domain = result.get("domain") or get_domain(result.get("url") or req.url)

        # Priority: phishing list > safe list
        if domain in phish_set:
            result["action"] = "block"
            result["type_pred"] = "phishing"
            result["reason"] = "user_blocklist_override"
            result["final_score"] = max(float(result.get("final_score", 0.0)), POLICY_BLOCK)
            overridden_by_list = True

        elif domain in safe_set:
            result["action"] = "safe"
            result["type_pred"] = "benign"
            result["reason"] = "user_allowlist_override"
            result["final_score"] = 0.0
            overridden_by_list = True

        result["list_override"] = overridden_by_list

        # Store prediction log
        doc = {
            "uid": uid,
            "email": email,
            "timestamp": int(time.time()),
            "url": result.get("url"),
            "domain": domain,
            "action": result.get("action"),
            "final_score": result.get("final_score"),
            "type_pred": result.get("type_pred"),
            "reason": result.get("reason"),
            "rf_prob": result.get("rf_prob"),
            "cnn_prob": result.get("cnn_prob"),
            "fusion": result.get("fusion"),
            "list_override": overridden_by_list,
        }

        write_result = db.collection("predictions").add(doc)

        try:
            result["log_id"] = write_result[1].id
        except Exception:
            pass

    # Audit log only for warn/block events
    try:
        db = get_db()
        domain = result.get("domain") or get_domain(result.get("url") or req.url)

        if result.get("action") in {"warn", "block"}:
            db.collection("audit_logs").add({
                "uid": uid or "anonymous",
                "email": email or "unknown",
                "action": "phishing_detected",
                "status": result.get("action"),
                "details": {
                    "url": result.get("url"),
                    "domain": domain,
                    "final_score": result.get("final_score"),
                    "type_pred": result.get("type_pred"),
                    "reason": result.get("reason"),
                    "rf_prob": result.get("rf_prob"),
                    "cnn_prob": result.get("cnn_prob"),
                    "fusion": result.get("fusion"),
                    "uncertainty": result.get("uncertainty"),
                    "list_override": overridden_by_list
                },
                "source": "backend_predict",
                "timestamp": int(time.time())
            })

    except Exception as e:
        print("⚠️ Failed to write phishing audit log:", e)

    return result


# ----------------------------
# History endpoint
# ----------------------------
@app.get("/history")
def history(limit: int = 50, authorization: str | None = Header(default=None)):
    user = auth_required(authorization)
    uid = user.get("uid")
    db = get_db()

    q = (
        db.collection("predictions")
        .where("uid", "==", uid)
        .order_by("timestamp", direction="DESCENDING")
        .limit(limit)
    )

    rows = []

    for doc in q.stream():
        d = doc.to_dict()
        d["id"] = doc.id
        rows.append(d)

    return {"items": rows}


# ----------------------------
# User lists endpoint
# ----------------------------
@app.get("/lists")
def lists(authorization: str | None = Header(default=None)):
    user = auth_required(authorization)
    uid = user.get("uid")
    db = get_db()

    ref = db.collection("user_lists").document(uid)
    snap = ref.get()
    data = snap.to_dict() if snap.exists else {"safe": [], "phishing": []}

    return {
        "safe": data.get("safe", []),
        "phishing": data.get("phishing", [])
    }


# ----------------------------
# Feedback endpoint
# ----------------------------
@app.post("/feedback")
def feedback(req: FeedbackRequest, authorization: str | None = Header(default=None)):
    user = auth_required(authorization)
    uid = user.get("uid")
    db = get_db()

    url = normalize_url(req.url)
    domain = get_domain(url)

    if req.verdict not in {"safe", "phishing"}:
        raise HTTPException(status_code=400, detail="verdict must be 'safe' or 'phishing'")

    ref = db.collection("user_lists").document(uid)
    snap = ref.get()
    data = snap.to_dict() if snap.exists else {"safe": [], "phishing": []}

    safe_list = set(data.get("safe", []))
    phish_list = set(data.get("phishing", []))

    if req.verdict == "safe":
        safe_list.add(domain)
        phish_list.discard(domain)
    else:
        phish_list.add(domain)
        safe_list.discard(domain)

    ref.set({
        "safe": sorted(safe_list),
        "phishing": sorted(phish_list)
    }, merge=True)

    return {
        "ok": True,
        "domain": domain,
        "safe": sorted(safe_list),
        "phishing": sorted(phish_list)
    }


# ----------------------------
# XAI endpoint
# ----------------------------
@app.post("/xai")
def xai(req: PredictRequest, authorization: str | None = Header(default=None)):
    _user = auth_required(authorization)

    if rf_model is None:
        raise HTTPException(status_code=400, detail="RF model not loaded")

    import shap

    global shap_explainer

    url = normalize_url(req.url)
    X_rf, row = ensure_feature_row(url)

    # Create SHAP explainer once, reuse it after that
    if shap_explainer is None:
        shap_explainer = shap.TreeExplainer(rf_model)

    explainer = shap_explainer

    try:
        exp = explainer(X_rf)
        shap_values = exp.values
    except Exception:
        shap_values = explainer.shap_values(X_rf)

    if isinstance(shap_values, list):
        sv_arr = np.array(shap_values[1]) if len(shap_values) >= 2 else np.array(shap_values[0])
    else:
        sv_arr = np.array(shap_values)

    if sv_arr.ndim == 3:
        sv_vec = sv_arr[0, :, 1] if sv_arr.shape[-1] > 1 else sv_arr[0, :, 0]
    elif sv_arr.ndim == 2:
        sv_vec = sv_arr[0, :]
    elif sv_arr.ndim == 1:
        sv_vec = sv_arr
    else:
        raise HTTPException(status_code=500, detail=f"Unexpected SHAP shape: {sv_arr.shape}")

    sv_vec = np.asarray(sv_vec, dtype=float).flatten()

    cols = list(row.keys())
    vals = [float(row[c]) for c in cols]

    pairs = list(zip(cols, vals, sv_vec.tolist()))
    pairs.sort(key=lambda x: abs(float(x[2])), reverse=True)

    top = [
        {
            "feature": feature,
            "value": float(value),
            "shap": float(shap_score)
        }
        for feature, value, shap_score in pairs[:12]
    ]

    return {
        "url": url,
        "top": top
    }