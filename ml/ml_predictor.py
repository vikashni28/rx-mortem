"""
ml/ml_predictor.py  —  RX-MORTEM v2 inference engine
Loads rf_model.pkl + scaler.pkl once per process (module-level cache).
Falls back to heuristic scorer if model files are absent.
"""

import os, pickle, sys
from typing import Any, Dict

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from config.settings import MODEL_PATH, SCALER_PATH, FEATURE_COLUMNS
from ml.feature_extractor import extract_features_from_file, extract_features_from_static

# ── Module-level cache (loaded once) ─────────────────────────────────────────
_model  = None
_scaler = None
_loaded = False


def _load():
    global _model, _scaler, _loaded
    if _loaded:
        return
    if os.path.exists(MODEL_PATH):
        with open(MODEL_PATH, "rb") as fh:
            _model = pickle.load(fh)
    if os.path.exists(SCALER_PATH):
        with open(SCALER_PATH, "rb") as fh:
            _scaler = pickle.load(fh)
    _loaded = True


def model_is_loaded() -> bool:
    _load()
    return _model is not None


def predict_malware(filepath: str, static: Dict[str, Any] = None) -> Dict[str, Any]:
    _load()

    result: Dict[str, Any] = {
        "malware_probability": 0.0,
        "benign_probability":  1.0,
        "prediction":          "benign",
        "model_used":          "none",
        "features_used":       {},
        "error":               None,
    }

    try:
        features = (
            extract_features_from_static(static)
            if static
            else extract_features_from_file(filepath)
        )
        result["features_used"] = dict(zip(FEATURE_COLUMNS, features))

        if _model is not None:
            X = [features]
            if _scaler is not None:
                X = _scaler.transform(X)
                result["model_used"] = "RandomForest+Scaler"
            else:
                result["model_used"] = "RandomForest"

            classes  = list(_model.classes_)
            proba    = _model.predict_proba(X)[0]
            mal_idx  = classes.index(1) if 1 in classes else 0
            ben_idx  = classes.index(0) if 0 in classes else None
            mal_prob = float(proba[mal_idx])
            ben_prob = float(proba[ben_idx]) if ben_idx is not None else 1.0 - mal_prob

            result["malware_probability"] = round(mal_prob, 4)
            result["benign_probability"]  = round(ben_prob, 4)
            result["prediction"]          = "malware" if mal_prob >= 0.5 else "benign"

        else:
            result["model_used"] = "heuristic_fallback"
            result["error"]      = (
                "rf_model.pkl not found — using heuristic fallback. "
                "Run: python ml/train.py"
            )
            p = _heuristic(features)
            result["malware_probability"] = round(p, 4)
            result["benign_probability"]  = round(1.0 - p, 4)
            result["prediction"]          = "malware" if p >= 0.5 else "benign"

    except Exception as exc:
        result["error"]      = f"Prediction error: {exc}"
        result["model_used"] = "error"

    return result


def _heuristic(features: list) -> float:
    _, entropy, num_sections, imports_count, sus_count = features
    score = 0.0
    if   entropy >= 7.5: score += 0.40
    elif entropy >= 7.0: score += 0.30
    elif entropy >= 6.5: score += 0.18
    elif entropy >= 6.0: score += 0.08
    if   sus_count >= 10: score += 0.30
    elif sus_count >= 6:  score += 0.20
    elif sus_count >= 3:  score += 0.12
    elif sus_count >= 1:  score += 0.06
    if   imports_count == 0: score += 0.18
    elif imports_count <  5: score += 0.14
    elif imports_count < 15: score += 0.07
    if   num_sections < 2:  score += 0.12
    elif num_sections < 3:  score += 0.06
    elif num_sections > 20: score += 0.04
    return min(round(score, 4), 1.0)
