# RX-MORTEM
### Hybrid Static Malware Analysis System

Static binary analysis without execution. Combines YARA rules, ML (Random Forest), and entropy analysis to detect malware in `.exe` and `.elf` files.

---

## Architecture

```
rx-mortem/
├── backend/            FastAPI REST API
│   ├── main.py         Endpoint routing + threat scoring
│   ├── analyzer.py     PE/ELF static analysis + entropy + strings
│   ├── yara_scanner.py YARA rule matching + fallback scanner
│   ├── ml_predictor.py Feature extraction + RF model inference
│   └── requirements.txt
├── model/
│   └── train.py        Train RandomForest, save rf_model.pkl + scaler.pkl
├── yara_rules/
│   └── malware_rules.yar  12 YARA rules (shellcode, ransomware, injection, etc.)
├── frontend/
│   └── rx-mortem.html  Single-file React SPA
├── dataset/
│   └── sample_dataset.csv  1000-row training dataset
└── README.md
```

---

## Setup

### 1. Install Backend Dependencies

```bash
cd backend
pip install -r requirements.txt
```

> **Note:** `yara-python` requires YARA to be installed system-wide on some platforms.
> - Ubuntu/Debian: `sudo apt install yara`
> - macOS: `brew install yara`
> - Windows: Download from https://github.com/VirusTotal/yara/releases

### 2. Train the ML Model

Run from the **project root**:

```bash
python model/train.py
```

This will:
- Load `dataset/sample_dataset.csv`
- Train a `RandomForestClassifier` (200 estimators)
- Save `model/rf_model.pkl` and `model/scaler.pkl`
- Print accuracy, F1, ROC-AUC, confusion matrix

> **Required before first use.** Without the trained model, the ML predictor falls back to a heuristic scorer.

### 3. Start the Backend

From the **project root**:

```bash
uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000
```

Or from inside `backend/`:

```bash
cd backend
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

API docs available at: `http://localhost:8000/docs`

### 4. Open the Frontend

Open `frontend/rx-mortem.html` directly in any modern browser.

No build tools. No npm. No server required for the frontend.

---

## API Endpoints

### `POST /analyze`

Upload a binary file for analysis.

**Request:** `multipart/form-data` with field `file`

**Response:**
```json
{
  "filename": "malware.exe",
  "file_size": 204800,
  "file_type": ".exe",
  "static_analysis": {
    "format": "PE",
    "entropy": 7.821,
    "sections": [...],
    "imports": [...],
    "suspicious_strings": ["VirtualAlloc", "CreateRemoteThread"],
    "sections_count": 3,
    "imports_count": 12
  },
  "yara_matches": [
    {
      "rule": "Process_Injection_Indicators",
      "meta": { "severity": "high", "category": "injection" },
      "tags": []
    }
  ],
  "ml_prediction": {
    "malware_probability": 0.91,
    "benign_probability": 0.09,
    "prediction": "malware",
    "model_used": "RandomForest+Scaler",
    "features_used": { ... }
  },
  "threat_score": 78.4,
  "yara_score": 75.0,
  "ml_score": 91.0,
  "entropy_score": 100.0,
  "verdict": "Malicious",
  "reasons": [
    "YARA matched 3 rule(s): Process_Injection_Indicators, ...",
    "ML model predicts high malware probability (91.0%)",
    "Critically high entropy (7.821) — likely packed or encrypted"
  ]
}
```

---

## Threat Scoring Formula

| Component | Weight | Source |
|-----------|--------|--------|
| YARA      | 40%    | Number of rule matches (25pts each, max 100) |
| ML Model  | 40%    | Random Forest malware probability × 100 |
| Entropy   | 20%    | File entropy mapped to 0–100 scale |

**Verdict thresholds:**
- `0–34` → **Benign**
- `35–64` → **Suspicious**
- `65–100` → **Malicious**

---

## YARA Rules Included

| Rule | Category | Severity |
|------|----------|----------|
| `UPX_Packed_Binary` | packer | medium |
| `Metasploit_Shellcode_x86` | shellcode | critical |
| `Process_Injection_Indicators` | injection | high |
| `AntiDebugging_Techniques` | evasion | medium |
| `Ransomware_Indicators` | ransomware | critical |
| `Keylogger_Indicators` | keylogger | high |
| `Suspicious_Network_Activity` | network | medium |
| `Credential_Harvesting` | credential_theft | critical |
| `Suspicious_Registry_Persistence` | persistence | high |
| `ELF_Suspicious_Capabilities` | linux_malware | high |
| `PE_Suspicious_Section_Names` | packer | medium |
| `Spyware_DataExfiltration` | spyware | high |
| `Generic_Obfuscated_PE` | obfuscation | medium |

---

## ML Features

The classifier uses 5 features extracted directly from the binary:

1. `file_size` — Raw byte count
2. `entropy` — Shannon entropy of full file (0–8)
3. `num_sections` — PE section count or ELF section count
4. `imports_count` — Number of imported functions
5. `suspicious_strings_count` — Matched suspicious API/string indicators

---

## Dataset

`dataset/sample_dataset.csv` — 1000 rows (500 benign, 500 malware)

| Column | Type | Description |
|--------|------|-------------|
| `file_size` | int | File size in bytes |
| `entropy` | float | Shannon entropy |
| `num_sections` | int | Number of PE/ELF sections |
| `imports_count` | int | Number of imported functions |
| `suspicious_strings_count` | int | Suspicious indicator count |
| `label` | int | 0 = benign, 1 = malware |

**Distribution:**
- Malware: high entropy (6.8–8.0), few imports (0–20), many suspicious strings (5–30)
- Benign: moderate entropy (4.0–6.5), many imports (30–200), few suspicious strings (0–4)

---

## Supported File Types

- `.exe` — Windows PE executables
- `.dll` — Windows DLLs
- `.elf` — Linux ELF binaries
- `.so` — Linux shared objects
- `.bin` — Raw binaries (entropy + string analysis only)

---

## Fallback Behavior

| Component | Fallback When |
|-----------|--------------|
| YARA | `yara-python` not installed → byte-pattern scanner |
| PE Analysis | `pefile` not installed → raw struct parsing |
| ELF Analysis | `pyelftools` not installed → raw ELF header parsing |
| ML Model | `rf_model.pkl` missing → heuristic entropy/string scorer |

The system **always returns a result** regardless of which optional libraries are installed.

---

## Legal Notice

RX-MORTEM is intended for **defensive security research, malware analysis, and incident response** purposes only. Do not use against systems you do not own or have explicit authorization to analyze.
