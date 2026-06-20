# ml/train_rf.py
from __future__ import annotations
import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt

from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    classification_report,
    precision_recall_curve,
    ConfusionMatrixDisplay,
)
from sklearn.model_selection import train_test_split

from ml.feature_extraction import extract_features
from ml.dataset_loader import load_all

MODEL_PATH = "model/rf_model.pkl"
THRESH_PATH = "model/rf_threshold.txt"
FEATCOL_PATH = "model/feature_columns.json"

def choose_threshold_for_recall(y_true, probs, target_recall=0.95):
    precisions, recalls, thresholds = precision_recall_curve(y_true, probs)
    precisions = precisions[1:]
    recalls = recalls[1:]
    valid = np.where(recalls >= target_recall)[0]
    if len(valid) == 0:
        return 0.5, float(precisions[-1]), float(recalls[-1])
    best_idx = valid[np.argmax(precisions[valid])]
    return float(thresholds[best_idx]), float(precisions[best_idx]), float(recalls[best_idx])

def main():
    df = load_all()
    print(f"Loaded total rows: {len(df)}")
    print("\nLabel counts:")
    print(df["label"].value_counts())

    X = df["url"].apply(extract_features)
    X = pd.DataFrame(list(X))
    y = df["label"].astype(int)

    feature_columns = X.columns.tolist()

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    model = RandomForestClassifier(
        n_estimators=400,
        random_state=42,
        n_jobs=-1,
        class_weight="balanced_subsample",
        min_samples_leaf=2,
    )
    model.fit(X_train, y_train)

    probs = model.predict_proba(X_test)[:, 1]
    thr, p_at, r_at = choose_threshold_for_recall(y_test, probs, target_recall=0.95)

    print(f"\nChosen RF threshold: {thr:.4f}")
    print(f"Precision@thr={p_at:.4f}, Recall@thr={r_at:.4f}\n")

    preds = (probs >= thr).astype(int)
    print(classification_report(y_test, preds, digits=4))

    # Save Random Forest Confusion Matrix
    Path("model").mkdir(parents=True, exist_ok=True)

    ConfusionMatrixDisplay.from_predictions(
        y_test,
        preds,
        display_labels=["Real", "Phishing"],
        cmap="viridis",
        values_format="d",
        colorbar=True
    )

    plt.title("Random Forest Confusion Matrix")
    plt.tight_layout()
    plt.savefig("model/rf_confusion_matrix.png", dpi=300, bbox_inches="tight")
    plt.close()

    # Save model files
    joblib.dump(model, MODEL_PATH)
    Path(THRESH_PATH).write_text(str(thr), encoding="utf-8")
    Path(FEATCOL_PATH).write_text(json.dumps(feature_columns, indent=2), encoding="utf-8")

    print("\nSaved:")
    print(" -", MODEL_PATH)
    print(" -", THRESH_PATH)
    print(" -", FEATCOL_PATH)
    print(" - model/rf_confusion_matrix.png")

if __name__ == "__main__":
    main()