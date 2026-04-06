#!/usr/bin/env python3
"""
ml/evaluate.py  —  RX-MORTEM v2 Standalone Model Evaluation

Loads the saved rf_model.pkl and evaluates it against any dataset (JSONL or CSV).

Run from project root:
  python ml/evaluate.py                              # uses JSONL or CSV test dataset
  python ml/evaluate.py --data ml/dataset/win64_test.csv
  python ml/evaluate.py --data ml/dataset/Win64_test
  python ml/evaluate.py --data any.csv --threshold 0.6
"""

import argparse, json, os, pickle, sys, glob
import numpy as np

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from config.settings import (
    MODEL_PATH, SCALER_PATH, MODEL_INFO_PATH,
    SAMPLE_CSV, WIN64_TEST, WIN64_TEST_DIR,
    FEATURE_COLUMNS, LABEL_COLUMN,
)
from ml.jsonl_loader import load_jsonl_files



def _load_csv(path: str):
    try:
        import pandas as pd
    except ImportError:
        print("[ERROR] pandas required: pip install pandas"); sys.exit(1)

    if not os.path.exists(path):
        print(f"[ERROR] File not found: {path}"); sys.exit(1)

    df = pd.read_csv(path)
    print(f"  [*] Rows={len(df)}  Cols={list(df.columns)}")

    # Map columns case-insensitively
    col_map = {}
    col_lower = {c.lower(): c for c in df.columns}
    for canonical in FEATURE_COLUMNS + [LABEL_COLUMN]:
        if canonical.lower() in col_lower:
            col_map[canonical] = col_lower[canonical.lower()]

    missing = [c for c in FEATURE_COLUMNS + [LABEL_COLUMN] if c not in col_map]
    if missing:
        print(f"[ERROR] Missing columns: {missing}")
        print(f"        Available: {list(df.columns)}")
        sys.exit(1)

    feat_cols = [col_map[f] for f in FEATURE_COLUMNS]
    lbl_col   = col_map[LABEL_COLUMN]
    df        = df[feat_cols + [lbl_col]].dropna()
    X = df[feat_cols].values.astype(float)
    y = df[lbl_col].values.astype(int)
    return X, y


def _load_data(path: str):
    """
    Load data from either JSONL directory or CSV file.
    Returns (X, y) numpy arrays.
    """
    if os.path.isdir(path):
        # JSONL directory
        print(f"  [*] Loading JSONL directory: {path}")
        X, y, _ = load_jsonl_files(path)
        if len(X) == 0:
            print(f"[ERROR] No valid data loaded from {path}")
            sys.exit(1)
        return X, y
    elif os.path.isfile(path):
        # CSV file
        print(f"  [*] Loading CSV file: {path}")
        return _load_csv(path)
    else:
        print(f"[ERROR] Path not found: {path}")
        sys.exit(1)


def evaluate(data_path: str, threshold: float = 0.50):
    from sklearn.metrics import (
        accuracy_score, precision_score, recall_score,
        f1_score, roc_auc_score, confusion_matrix, classification_report,
    )

    print(f"\n{'='*60}\n  RX-MORTEM v2 :: Model Evaluation\n{'='*60}")

    # Load model
    if not os.path.exists(MODEL_PATH):
        print(f"[ERROR] Model not found: {MODEL_PATH}")
        print("        Run: python ml/train.py")
        sys.exit(1)

    with open(MODEL_PATH, "rb") as fh:
        model = pickle.load(fh)
    print(f"[*] Model  : {MODEL_PATH}")

    scaler = None
    if os.path.exists(SCALER_PATH):
        with open(SCALER_PATH, "rb") as fh:
            scaler = pickle.load(fh)
        print(f"[*] Scaler : {SCALER_PATH}")

    if os.path.exists(MODEL_INFO_PATH):
        with open(MODEL_INFO_PATH) as fh:
            info = json.load(fh)
        print(f"[*] Trained: {info.get('trained_at', '?')}")
        print(f"[*] Train samples: {info.get('train_samples', '?')}")

    # Load evaluation data
    print(f"\n[*] Evaluating on: {data_path}")
    X, y = _load_data(data_path)
    print(f"[*] Samples: {len(X)}")
    classes, counts = np.unique(y, return_counts=True)
    for cls, cnt in zip(classes, counts):
        print(f"    Class {cls} ({'malware' if cls==1 else 'benign '}) : {cnt}")

    if scaler:
        X = scaler.transform(X)

    cls_list = list(model.classes_)
    mal_idx  = cls_list.index(1) if 1 in cls_list else 0
    y_proba  = model.predict_proba(X)[:, mal_idx]
    y_pred   = (y_proba >= threshold).astype(int)

    acc  = accuracy_score(y, y_pred)
    prec = precision_score(y, y_pred, zero_division=0)
    rec  = recall_score(y, y_pred, zero_division=0)
    f1   = f1_score(y, y_pred, zero_division=0)
    auc  = roc_auc_score(y, y_proba)
    cm   = confusion_matrix(y, y_pred)

    print(f"\n{'='*60}\n  RESULTS  (threshold={threshold})\n{'='*60}")
    print(f"  Accuracy  : {acc*100:.2f}%")
    print(f"  Precision : {prec*100:.2f}%")
    print(f"  Recall    : {rec*100:.2f}%")
    print(f"  F1-Score  : {f1*100:.2f}%")
    print(f"  ROC-AUC   : {auc:.4f}")
    print(f"\n  Confusion Matrix:")
    print(f"    TN={cm[0][0]}  FP={cm[0][1]}")
    print(f"    FN={cm[1][0]}  TP={cm[1][1]}")
    print(f"\n{classification_report(y, y_pred, target_names=['Benign','Malware'])}")

    print("  Feature Importances:")
    for feat, imp in zip(FEATURE_COLUMNS, model.feature_importances_):
        bar = "█" * int(imp * 50)
        print(f"    {feat:<34} {imp:.4f}  {bar}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="RX-MORTEM v2 — Evaluate saved model")
    ap.add_argument("--data",      metavar="PATH", help="Evaluation CSV path or JSONL directory")
    ap.add_argument("--threshold", type=float, default=0.50,
                    help="Classification threshold (default 0.5)")
    args = ap.parse_args()

    if args.data:
        path = args.data
    elif os.path.isdir(WIN64_TEST_DIR) and glob.glob(os.path.join(WIN64_TEST_DIR, "*.jsonl")):
        path = WIN64_TEST_DIR
        print(f"[*] Using JSONL test directory: {WIN64_TEST_DIR}")
    elif os.path.exists(WIN64_TEST) and os.path.getsize(WIN64_TEST) > 100:
        path = WIN64_TEST
    elif os.path.exists(SAMPLE_CSV):
        path = SAMPLE_CSV
    else:
        print("[ERROR] No evaluation dataset found."); sys.exit(1)

    evaluate(path, threshold=args.threshold)
