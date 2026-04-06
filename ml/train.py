#!/usr/bin/env python3
"""
ml/train.py  —  RX-MORTEM v2 Model Trainer

Dataset priority order:
  1. ml/dataset/Win64_train/ + ml/dataset/Win64_test/   (JSONL — your main dataset)
  2. ml/dataset/win64_train.csv + ml/dataset/win64_test.csv
  3. ml/dataset/sample_dataset.csv  (fallback — auto-split 80/20)

Column names accepted (case-insensitive, auto-mapped):
  file_size | entropy | num_sections | imports_count
  suspicious_strings_count | label

Run from project root:
  python ml/train.py                         # auto-detect
  python ml/train.py --sample                # force sample
  python ml/train.py --train path/train.csv  # custom CSV path
  python ml/train.py --train t.csv --test te.csv
"""

import argparse, json, os, pickle, sys
from datetime import datetime
import numpy as np
import joblib

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from config.settings import (
    WIN64_TRAIN_DIR, WIN64_TEST_DIR, WIN64_TRAIN, WIN64_TEST, SAMPLE_CSV,
    MODEL_PATH, SCALER_PATH, MODEL_INFO_PATH, MODEL_DIR,
    FEATURE_COLUMNS, LABEL_COLUMN,
    RF_N_ESTIMATORS, RF_MAX_DEPTH, RF_RANDOM_STATE,
    RF_N_JOBS, RF_CLASS_WEIGHT,
)
from ml.jsonl_loader import load_combined_jsonl_datasets

_SYNONYMS = {
    "file_size":                ["file_size","filesize","size","FileSize","SizeOfFile","file_size_bytes"],
    "entropy":                  ["entropy","Entropy","file_entropy","FileEntropy","shannon_entropy"],
    "num_sections":             ["num_sections","sections","NumSections","NumberOfSections","SectionCount","section_count"],
    "imports_count":            ["imports_count","imports","ImportsCount","NumberOfImports","num_imports","import_count"],
    "suspicious_strings_count": ["suspicious_strings_count","suspicious_strings","SuspiciousStrings","sus_count","suspicious_count"],
    "label":                    ["label","Label","class","Class","malware","Malware","target","Target","is_malware"],
}

def _banner(msg):
    print(f"\n{'='*62}\n  {msg}\n{'='*62}")

def _map_columns(available):
    avail_lower = {c.lower(): c for c in available}
    mapping = {}
    for canonical, synonyms in _SYNONYMS.items():
        found = None
        for syn in synonyms:
            if syn in available:
                found = syn; break
        if not found:
            for syn in synonyms:
                if syn.lower() in avail_lower:
                    found = avail_lower[syn.lower()]; break
        if not found:
            for syn in synonyms:
                for col in available:
                    if syn.lower() in col.lower():
                        found = col; break
                if found: break
        mapping[canonical] = found
    required = FEATURE_COLUMNS + [LABEL_COLUMN]
    unresolved = [k for k in required if not mapping.get(k)]
    if unresolved:
        print(f"\n[ERROR] Cannot map columns: {unresolved}")
        print(f"        CSV has: {available}")
        sys.exit(1)
    return mapping

def _load_csv(path):
    try:
        import pandas as pd
    except ImportError:
        print("[ERROR] pandas required: pip install pandas"); sys.exit(1)
    if not os.path.exists(path):
        print(f"[ERROR] Not found: {path}"); sys.exit(1)
    print(f"  [*] Reading : {path}")
    df = pd.read_csv(path)
    if df.empty or len(df.columns) < 2:
        print(f"[ERROR] CSV empty or malformed: {path}"); sys.exit(1)
    print(f"  [*] Rows={len(df)}  Cols={list(df.columns)}")
    mapping = _map_columns(list(df.columns))
    print(f"  [*] Mapping : {mapping}")
    feat_cols = [mapping[f] for f in FEATURE_COLUMNS]
    lbl_col   = mapping[LABEL_COLUMN]
    df_clean  = df[feat_cols + [lbl_col]].copy()
    dropped   = len(df_clean) - len(df_clean.dropna())
    df_clean.dropna(inplace=True)
    if dropped:
        print(f"  [!] Dropped {dropped} NaN rows")
    if len(df_clean) == 0:
        print(f"[ERROR] No rows left after cleaning: {path}"); sys.exit(1)
    X = df_clean[feat_cols].values.astype(float)
    y = df_clean[lbl_col].values.astype(int)
    classes, counts = np.unique(y, return_counts=True)
    for cls, cnt in zip(classes, counts):
        print(f"  [*] Class {cls} ({'malware' if cls==1 else 'benign '}) : {cnt}")
    return X, y, mapping

def _load_and_split(path, test_size=0.20):
    from sklearn.model_selection import train_test_split
    X, y, mapping = _load_csv(path)
    X_tr, X_te, y_tr, y_te = train_test_split(
        X, y, test_size=test_size, random_state=RF_RANDOM_STATE, stratify=y)
    return X_tr, X_te, y_tr, y_te, mapping

def train(train_path, test_path=None):
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.preprocessing import StandardScaler
    from sklearn.metrics import (accuracy_score, precision_score, recall_score,
        f1_score, roc_auc_score, confusion_matrix, classification_report)

    _banner("RX-MORTEM v2 :: ML Model Training")

    # Try to load JSONL datasets first
    if os.path.isdir(train_path):
        print(f"\n[*] Mode: JSONL dataset directories")
        print(f"[*] TRAIN directory: {train_path}")
        if test_path and os.path.isdir(test_path):
            print(f"[*] TEST directory : {test_path}")
            try:
                X_train, y_train, X_test, y_test = load_combined_jsonl_datasets(train_path, test_path)
                mapping = {col: col for col in FEATURE_COLUMNS + [LABEL_COLUMN]}
            except Exception as e:
                print(f"[ERROR] Failed to load JSONL datasets: {e}"); sys.exit(1)
        else:
            print(f"[ERROR] JSONL mode requires both train and test directories"); sys.exit(1)
    elif os.path.isfile(train_path):
        # CSV dataset mode
        if test_path and os.path.exists(test_path) and os.path.getsize(test_path) > 100:
            print(f"\n[*] Mode: separate train + test CSVs")
            print(f"\n[*] TRAIN dataset:")
            X_train, y_train, mapping = _load_csv(train_path)
            print(f"\n[*] TEST dataset:")
            X_test, y_test, _ = _load_csv(test_path)
        else:
            print(f"\n[*] Mode: single CSV — auto-splitting 80/20")
            X_train, X_test, y_train, y_test, mapping = _load_and_split(train_path)
    else:
        print(f"[ERROR] Invalid train path (not file or directory): {train_path}"); sys.exit(1)

    print(f"\n  Train samples : {len(X_train)}")
    print(f"  Test  samples : {len(X_test)}")

    print("\n[*] Fitting StandardScaler ...")
    scaler     = StandardScaler()
    X_train_sc = scaler.fit_transform(X_train)
    X_test_sc  = scaler.transform(X_test)

    print(f"[*] Training RandomForestClassifier (n_estimators={RF_N_ESTIMATORS}, max_depth={RF_MAX_DEPTH}) ...")
    model = RandomForestClassifier(
        n_estimators=RF_N_ESTIMATORS, max_depth=RF_MAX_DEPTH,
        min_samples_split=2, min_samples_leaf=1,
        max_features="sqrt", bootstrap=True,
        random_state=RF_RANDOM_STATE, n_jobs=RF_N_JOBS,
        class_weight=RF_CLASS_WEIGHT,
    )
    model.fit(X_train_sc, y_train)
    print("[*] Training complete.")

    classes  = list(model.classes_)
    mal_idx  = classes.index(1) if 1 in classes else 0
    y_pred   = model.predict(X_test_sc)
    y_proba  = model.predict_proba(X_test_sc)[:, mal_idx]

    acc  = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, zero_division=0)
    rec  = recall_score(y_test, y_pred, zero_division=0)
    f1   = f1_score(y_test, y_pred, zero_division=0)
    auc  = roc_auc_score(y_test, y_proba)
    cm   = confusion_matrix(y_test, y_pred)

    _banner("EVALUATION RESULTS")
    print(f"  Accuracy  : {acc*100:.2f}%")
    print(f"  Precision : {prec*100:.2f}%")
    print(f"  Recall    : {rec*100:.2f}%")
    print(f"  F1-Score  : {f1*100:.2f}%")
    print(f"  ROC-AUC   : {auc:.4f}")
    print(f"\n  Confusion Matrix:")
    print(f"    TN={cm[0][0]}  FP={cm[0][1]}")
    print(f"    FN={cm[1][0]}  TP={cm[1][1]}")
    print(f"\n{classification_report(y_test, y_pred, target_names=['Benign','Malware'])}")
    print("  Feature Importances:")
    for feat, imp in zip(FEATURE_COLUMNS, model.feature_importances_):
        bar = "█" * int(imp * 50)
        print(f"    {feat:<34} {imp:.4f}  {bar}")

    os.makedirs(MODEL_DIR, exist_ok=True)
    joblib.dump(model,  MODEL_PATH,  compress=3)
    joblib.dump(scaler, SCALER_PATH, compress=3)

    info = {
        "trained_at":      datetime.utcnow().isoformat() + "Z",
        "train":       train_path,
        "test":        test_path or "(auto-split)",
        "train_samples":   int(len(X_train)),
        "test_samples":    int(len(X_test)),
        "feature_columns": FEATURE_COLUMNS,
        "column_mapping":  {k: v for k, v in mapping.items() if v} if isinstance(mapping, dict) else {},
        "hyperparameters": {"n_estimators":RF_N_ESTIMATORS,"max_depth":RF_MAX_DEPTH,
                            "random_state":RF_RANDOM_STATE,"class_weight":RF_CLASS_WEIGHT},
        "metrics": {"accuracy":round(float(acc),4),"precision":round(float(prec),4),
                    "recall":round(float(rec),4),"f1_score":round(float(f1),4),"roc_auc":round(float(auc),4)},
        "confusion_matrix": cm.tolist(),
        "feature_importances": {f:round(float(v),6) for f,v in zip(FEATURE_COLUMNS,model.feature_importances_)},
    }
    with open(MODEL_INFO_PATH, "w") as fh: json.dump(info, fh, indent=2)

    _banner("TRAINING COMPLETE")
    print(f"  rf_model.pkl → {MODEL_PATH}")
    print(f"  scaler.pkl   → {SCALER_PATH}")
    print(f"  model_info   → {MODEL_INFO_PATH}")
    print(f"\n  Next: python run.py\n")
    print(f"\n  Next: python run.py\n")

def _resolve(args):
    if args.train:
        if not os.path.exists(args.train):
            print(f"[ERROR] --train not found: {args.train}"); sys.exit(1)
        te = args.test if (args.test and os.path.exists(args.test)) else None
        return args.train, te
    if args.sample:
        if not os.path.exists(SAMPLE_CSV):
            print(f"[ERROR] Sample not found: {SAMPLE_CSV}"); sys.exit(1)
        return SAMPLE_CSV, None
    
    # Priority 1: JSONL datasets (directories)
    if os.path.isdir(WIN64_TRAIN_DIR) and os.path.isdir(WIN64_TEST_DIR):
        # Check if directories contain JSONL files
        import glob
        train_jsonl = glob.glob(os.path.join(WIN64_TRAIN_DIR, "*.jsonl"))
        test_jsonl = glob.glob(os.path.join(WIN64_TEST_DIR, "*.jsonl"))
        if train_jsonl and test_jsonl:
            print(f"[*] JSONL datasets found")
            print(f"[*] Win64 train dir: {WIN64_TRAIN_DIR} ({len(train_jsonl)} files)")
            print(f"[*] Win64 test dir : {WIN64_TEST_DIR} ({len(test_jsonl)} files)")
            return WIN64_TRAIN_DIR, WIN64_TEST_DIR
    
    # Priority 2: CSV datasets
    if os.path.exists(WIN64_TRAIN) and os.path.getsize(WIN64_TRAIN) > 100:
        print(f"[*] Win64 train: {WIN64_TRAIN}")
        te = WIN64_TEST if (os.path.exists(WIN64_TEST) and os.path.getsize(WIN64_TEST) > 100) else None
        if te: print(f"[*] Win64 test : {te}")
        return WIN64_TRAIN, te
    
    # Fallback: Sample dataset
    if os.path.exists(SAMPLE_CSV):
        print(f"[*] Falling back to sample dataset: {SAMPLE_CSV}")
        return SAMPLE_CSV, None
    
    print(f"[ERROR] No dataset found"); sys.exit(1)

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="RX-MORTEM v2 — Model Trainer")
    ap.add_argument("--train",  metavar="PATH")
    ap.add_argument("--test",   metavar="PATH")
    ap.add_argument("--sample", action="store_true")
    args = ap.parse_args()
    tp, te = _resolve(args)
    train(tp, te)
