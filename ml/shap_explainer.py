# ml/shap_explainer.py
from __future__ import annotations
import json
from pathlib import Path
import joblib
import numpy as np
import pandas as pd
import shap

from ml.feature_extraction import extract_features

RF_MODEL_PATH = "model/rf_model.pkl"
FEATCOL_PATH = "model/feature_columns.json"

rf_model = joblib.load(RF_MODEL_PATH)
FEATURE_COLUMNS = json.loads(Path(FEATCOL_PATH).read_text(encoding="utf-8"))

# TreeExplainer for RandomForest
explainer = shap.TreeExplainer(rf_model)

def explain_url_rf(url: str, top_k: int = 8):
    feats = extract_features(url)
    X = pd.DataFrame([[feats.get(c, 0) for c in FEATURE_COLUMNS]], columns=FEATURE_COLUMNS)

    # shap values for class 1
    shap_vals = explainer.shap_values(X)
    # Depending on shap version, shap_vals can be list [class0, class1]
    if isinstance(shap_vals, list) and len(shap_vals) > 1:
        sv = shap_vals[1][0]
    else:
        sv = np.array(shap_vals)[0]

    pairs = list(zip(FEATURE_COLUMNS, sv))
    pairs.sort(key=lambda x: abs(float(x[1])), reverse=True)
    top = [{"feature": f, "impact": float(v), "value": float(X.iloc[0][f])} for f, v in pairs[:top_k]]
    return top
