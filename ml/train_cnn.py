# ml/train_cnn.py
from __future__ import annotations
import json
from pathlib import Path

import numpy as np
import matplotlib.pyplot as plt

from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, ConfusionMatrixDisplay

from ml.dataset_loader import load_all


# TensorFlow / Keras
import tensorflow as tf
from tensorflow.keras import layers, models

CNN_MODEL_PATH = "model/cnn_model.h5"
TOKEN_PATH = "model/cnn_tokenizer.json"
MAXLEN_PATH = "model/cnn_maxlen.txt"
CNN_THRESH_PATH = "model/cnn_threshold.txt"
CNN_CM_PATH = "model/cnn_confusion_matrix.png"

# Keep it small enough to train on CPU
MAX_LEN = 200
VOCAB_SIZE = 128  # ASCII-ish chars
EMB_DIM = 32


def url_to_ints(url: str) -> list[int]:
    """
    Character -> integer encoding:
    - 0 = padding / unknown
    - 1..127 = ASCII codes
    """
    url = (url or "")[:MAX_LEN]
    arr: list[int] = []

    for ch in url:
        code = ord(ch)
        if 0 < code < VOCAB_SIZE:
            arr.append(code)
        else:
            arr.append(0)

    return arr


def build_model():
    inp = layers.Input(shape=(MAX_LEN,), dtype="int32")
    x = layers.Embedding(
        input_dim=VOCAB_SIZE,
        output_dim=EMB_DIM,
        mask_zero=True
    )(inp)

    x = layers.Conv1D(64, 5, activation="relu")(x)
    x = layers.MaxPooling1D(2)(x)
    x = layers.Conv1D(64, 5, activation="relu")(x)
    x = layers.GlobalMaxPooling1D()(x)

    x = layers.Dense(64, activation="relu")(x)
    x = layers.Dropout(0.3)(x)
    out = layers.Dense(1, activation="sigmoid")(x)

    model = models.Model(inp, out)

    model.compile(
        optimizer=tf.keras.optimizers.Adam(1e-3),
        loss="binary_crossentropy",
        metrics=[tf.keras.metrics.AUC(name="auc"), "accuracy"],
    )

    return model


def choose_threshold_for_precision(
    y_true,
    probs,
    target_precision: float = 0.98
) -> float:
    """
    Choose a HIGH precision threshold to reduce false positives.
    We want BLOCK only when the model is very sure.
    """
    thresholds = np.linspace(0.10, 0.99, 90)
    best = 0.99

    for t in thresholds:
        pred = (probs >= t).astype(int)

        tp = np.sum((pred == 1) & (y_true == 1))
        fp = np.sum((pred == 1) & (y_true == 0))

        if tp + fp == 0:
            continue

        precision = tp / (tp + fp)

        if precision >= target_precision:
            best = t
            break

    return float(best)


def main():
    df = load_all()
    print(f"Loaded total rows: {len(df)}")
    print("\nLabel counts:")
    print(df["label"].value_counts())

    # For CPU speed, sample if dataset is huge
    MAX_SAMPLES = 250_000
    if len(df) > MAX_SAMPLES:
        df = df.sample(MAX_SAMPLES, random_state=42)
        print(f"\nSampled to {len(df)} rows for CNN training.")

    # Convert URL strings into character-level integer sequences
    seqs = [url_to_ints(u) for u in df["url"].tolist()]

    Xp = tf.keras.preprocessing.sequence.pad_sequences(
        seqs,
        maxlen=MAX_LEN,
        padding="post",
        truncating="post",
        value=0,
    ).astype("int32")

    y = df["label"].astype(int).to_numpy()

    X_train, X_test, y_train, y_test = train_test_split(
        Xp,
        y,
        test_size=0.2,
        random_state=42,
        stratify=y
    )

    model = build_model()
    model.summary()

    callbacks = [
        tf.keras.callbacks.EarlyStopping(
            monitor="val_auc",
            patience=2,
            mode="max",
            restore_best_weights=True
        )
    ]

    model.fit(
        X_train,
        y_train,
        validation_split=0.1,
        epochs=6,
        batch_size=512,
        callbacks=callbacks,
        verbose=1,
    )

    # Predict probability on test set
    probs = model.predict(
        X_test,
        batch_size=1024,
        verbose=0
    ).reshape(-1)

    # Select CNN threshold
    cnn_thr = choose_threshold_for_precision(
        y_test,
        probs,
        target_precision=0.98
    )

    print(f"\nChosen CNN high-precision threshold: {cnn_thr:.4f}")

    # Convert probabilities into final predictions
    cnn_preds = (probs >= cnn_thr).astype(int)

    # Print classification report
    print("\nCNN Classification Report:")
    print(classification_report(y_test, cnn_preds, digits=4))

    # Create model folder
    Path("model").mkdir(parents=True, exist_ok=True)

    # Generate and save CNN confusion matrix as PNG
    ConfusionMatrixDisplay.from_predictions(
        y_test,
        cnn_preds,
        display_labels=["Real", "Phishing"],
        cmap="viridis",
        values_format="d",
        colorbar=True
    )

    plt.title("CNN Confusion Matrix")
    plt.tight_layout()
    plt.savefig(
        CNN_CM_PATH,
        dpi=300,
        bbox_inches="tight"
    )
    plt.close()

    # Save trained CNN model
    model.save(CNN_MODEL_PATH)

    # Save tokenizer info
    tok = {
        "type": "ord",
        "vocab_size": VOCAB_SIZE
    }
    Path(TOKEN_PATH).write_text(
        json.dumps(tok, indent=2),
        encoding="utf-8"
    )

    Path(MAXLEN_PATH).write_text(
        str(MAX_LEN),
        encoding="utf-8"
    )

    Path(CNN_THRESH_PATH).write_text(
        str(cnn_thr),
        encoding="utf-8"
    )

    print("\nSaved:")
    print(" -", CNN_MODEL_PATH)
    print(" -", TOKEN_PATH)
    print(" -", MAXLEN_PATH)
    print(" -", CNN_THRESH_PATH)
    print(" -", CNN_CM_PATH)


if __name__ == "__main__":
    main()