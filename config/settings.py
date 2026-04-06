"""
config/settings.py
RX-MORTEM v2 — Central configuration.
All paths, weights, thresholds, and hyperparameters live here.
Edit once — applied everywhere automatically.
"""

import os

# ── Project root ──────────────────────────────────────────────────────────────
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# ── ML paths ──────────────────────────────────────────────────────────────────
ML_DIR          = os.path.join(PROJECT_ROOT, "ml")
MODEL_DIR       = os.path.join(ML_DIR, "model")
DATASET_DIR     = os.path.join(ML_DIR, "dataset")

MODEL_PATH      = os.path.join(MODEL_DIR, "rf_model.pkl")
SCALER_PATH     = os.path.join(MODEL_DIR, "scaler.pkl")
MODEL_INFO_PATH = os.path.join(MODEL_DIR, "model_info.json")

# Win64 JSONL datasets (primary — multiple JSONL files per directory)
WIN64_TRAIN_DIR = os.path.join(DATASET_DIR, "Win64_train")
WIN64_TEST_DIR  = os.path.join(DATASET_DIR, "Win64_test")

# Legacy CSV paths (for backward compatibility)
WIN64_TRAIN = os.path.join(DATASET_DIR, "win64_train.csv")
WIN64_TEST  = os.path.join(DATASET_DIR, "win64_test.csv")
  
# Fallback demo dataset (always present)
SAMPLE_CSV      = os.path.join(DATASET_DIR, "sample_dataset.csv")

# ── YARA ──────────────────────────────────────────────────────────────────────
YARA_RULES_PATH = os.path.join(PROJECT_ROOT, "yara_rules", "malware_rules.yar")

# ── Feature columns (must match dataset CSV column names) ─────────────────────
FEATURE_COLUMNS = [
    "file_size",
    "entropy",
    "num_sections",
    "imports_count",
    "suspicious_strings_count",
]
LABEL_COLUMN = "label"   # 0 = benign, 1 = malware

# ── Threat score weights (must sum to 1.0) ────────────────────────────────────
WEIGHT_YARA    = 0.40
WEIGHT_ML      = 0.40
WEIGHT_ENTROPY = 0.20

# ── Verdict thresholds ────────────────────────────────────────────────────────
VERDICT_MALICIOUS_THRESHOLD  = 65   # score >= 65  → Malicious
VERDICT_SUSPICIOUS_THRESHOLD = 35   # score >= 35  → Suspicious
                                     # score <  35  → Benign

# ── Random Forest hyperparameters ─────────────────────────────────────────────
RF_N_ESTIMATORS = 300
RF_MAX_DEPTH    = 20
RF_RANDOM_STATE = 42
RF_N_JOBS       = -1           # use all CPU cores
RF_CLASS_WEIGHT = "balanced"

# ── Analysis limits ───────────────────────────────────────────────────────────
MAX_STRINGS_SAMPLE = 200       # max strings returned in API response
MAX_IMPORT_DISPLAY = 100       # max imports shown in frontend
MIN_STRING_LENGTH  = 4         # minimum printable-string length to extract

# ── Allowed upload extensions ─────────────────────────────────────────────────
ALLOWED_EXTENSIONS = {".exe", ".dll", ".elf", ".so", ".bin", ".sys", ".ocx"}
