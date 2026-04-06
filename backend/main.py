"""
backend/main.py  —  RX-MORTEM v2 FastAPI entry point

Run from the PROJECT ROOT directory:
    uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000
  or:
    python run.py
"""

import os, sys, shutil, tempfile

# ── Ensure project root is on sys.path so all sibling packages resolve ───────
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from fastapi import FastAPI, File, UploadFile, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from config.settings import (
    ALLOWED_EXTENSIONS,
    WEIGHT_YARA, WEIGHT_ML, WEIGHT_ENTROPY,
    VERDICT_MALICIOUS_THRESHOLD, VERDICT_SUSPICIOUS_THRESHOLD,
)

# ── Sub-module imports (resolved via PROJECT_ROOT on sys.path) ────────────────
from backend.analyzer      import analyze_file
from backend.yara_scanner  import scan_with_yara
from ml.ml_predictor       import predict_malware, model_is_loaded

# ─────────────────────────────────────────────────────────────────────────────
app = FastAPI(
    title="RX-MORTEM",
    description="Hybrid Static Malware Analysis System — v2",
    version="2.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ─── Health ───────────────────────────────────────────────────────────────────
@app.get("/")
def root():
    return {"status": "RX-MORTEM v2 online", "version": "2.0.0"}


@app.get("/health")
def health():
    return {"api": "ok", "model_loaded": model_is_loaded()}


# ─── Analysis ─────────────────────────────────────────────────────────────────
@app.post("/analyze")
async def analyze(file: UploadFile = File(...)):
    filename = file.filename or "unknown"
    ext      = os.path.splitext(filename)[1].lower()

    if ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported extension '{ext}'. Allowed: {sorted(ALLOWED_EXTENSIONS)}",
        )

    tmp_dir  = tempfile.mkdtemp()
    tmp_path = os.path.join(tmp_dir, filename)

    try:
        content = await file.read()
        if not content:
            raise HTTPException(status_code=400, detail="File is empty.")

        with open(tmp_path, "wb") as fh:
            fh.write(content)

        static    = analyze_file(tmp_path)
        yara_hits = scan_with_yara(tmp_path)
        ml        = predict_malware(tmp_path, static)

        yara_score    = float(min(len([h for h in yara_hits if "error" not in h]) * 25, 100))
        ml_score      = round(ml.get("malware_probability", 0.0) * 100, 2)
        entropy_score = _entropy_score(static.get("entropy", 0.0))
        threat_score  = round(
            yara_score * WEIGHT_YARA + ml_score * WEIGHT_ML + entropy_score * WEIGHT_ENTROPY, 2
        )
        verdict = _verdict(threat_score)
        reasons = _build_reasons(yara_hits, ml, static)

        return JSONResponse(content={
            "filename":        filename,
            "file_size":       len(content),
            "file_type":       ext,
            "static_analysis": static,
            "yara_matches":    yara_hits,
            "ml_prediction":   ml,
            "threat_score":    threat_score,
            "yara_score":      round(yara_score, 2),
            "ml_score":        round(ml_score, 2),
            "entropy_score":   round(entropy_score, 2),
            "verdict":         verdict,
            "reasons":         reasons,
        })

    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Analysis error: {exc}")
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


def _entropy_score(e: float) -> float:
    if e >= 7.5: return 100.0
    if e >= 7.0: return 80.0
    if e >= 6.5: return 60.0
    if e >= 6.0: return 40.0
    if e >= 5.0: return 20.0
    return 0.0

def _verdict(score: float) -> str:
    if score >= VERDICT_MALICIOUS_THRESHOLD:  return "Malicious"
    if score >= VERDICT_SUSPICIOUS_THRESHOLD: return "Suspicious"
    return "Benign"

def _build_reasons(yara_hits, ml, static) -> list:
    reasons = []
    real = [h for h in yara_hits if "error" not in h]
    if real:
        names = ", ".join(h.get("rule","?") for h in real)
        reasons.append(f"YARA matched {len(real)} rule(s): {names}")

    prob = ml.get("malware_probability", 0.0)
    pct  = f"{prob*100:.1f}%"
    if prob >= 0.70:   reasons.append(f"ML model predicts high malware probability ({pct})")
    elif prob >= 0.40: reasons.append(f"ML model flags moderate risk ({pct})")
    else:              reasons.append(f"ML model indicates low risk ({pct})")

    e = static.get("entropy", 0.0)
    if   e >= 7.5: reasons.append(f"Critically high entropy ({e:.4f}) — likely packed/encrypted")
    elif e >= 7.0: reasons.append(f"High entropy ({e:.4f}) — possible obfuscation")
    elif e >= 6.5: reasons.append(f"Elevated entropy ({e:.4f})")

    susp = static.get("suspicious_strings", [])
    if susp:
        reasons.append(f"Found {len(susp)} suspicious string(s): {', '.join(susp[:5])}")

    for sec in static.get("sections", []):
        if sec.get("entropy", 0) >= 7.5:
            reasons.append(f"Section '{sec.get('name','?')}' entropy={sec['entropy']:.4f}")

    if not reasons:
        reasons.append("No significant threat indicators detected.")
    return reasons
