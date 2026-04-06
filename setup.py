#!/usr/bin/env python3
"""
setup.py  —  RX-MORTEM v2 dependency installer
Run once before anything else:

    python setup.py
"""

import os
import subprocess
import sys

REQUIREMENTS = [
    "fastapi==0.111.0",
    "uvicorn[standard]==0.29.0",
    "python-multipart==0.0.9",
    "pefile==2023.2.7",
    "pyelftools==0.31",
    "scikit-learn==1.4.2",
    "numpy==1.26.4",
    "pandas==2.2.2",
    "joblib==1.4.2",
]

OPTIONAL = {
    "yara-python==4.5.0": (
        "YARA rule scanning. If this fails, install the YARA system library first:\n"
        "  Ubuntu/Debian : sudo apt install yara libyara-dev\n"
        "  macOS         : brew install yara\n"
        "  Windows       : download from https://github.com/VirusTotal/yara/releases"
    ),
}


def pip_install(packages: list, label: str = ""):
    cmd = [sys.executable, "-m", "pip", "install", "--upgrade"] + packages
    print(f"\n[*] Installing {label or ' '.join(packages)} ...")
    result = subprocess.run(cmd)
    return result.returncode == 0


def main():
    print("=" * 60)
    print("  RX-MORTEM v2  —  Dependency Setup")
    print("=" * 60)

    ok = pip_install(REQUIREMENTS, "core requirements")
    if not ok:
        print("[ERROR] Core install failed. Check your pip and Python version.")
        sys.exit(1)

    print("\n[*] Installing optional dependencies ...")
    for pkg, note in OPTIONAL.items():
        success = pip_install([pkg], pkg)
        if not success:
            print(f"\n[WARN] Optional package failed: {pkg}")
            print(f"       Note: {note}")
            print(f"       The system will still work using the built-in fallback scanner.")

    # Create required directories
    dirs = [
        "ml/model",
        "ml/dataset",
    ]
    for d in dirs:
        os.makedirs(d, exist_ok=True)

    print("\n" + "=" * 60)
    print("  Setup complete.")
    print("=" * 60)
    print("\nNext steps:")
    print("  1. python ml/train.py          — train the ML model")
    print("  2. python run.py               — start the API server")
    print("  3. open frontend/rx-mortem.html in your browser")
    print("\nOr do both steps 1+2 at once:")
    print("  python run.py --train")


if __name__ == "__main__":
    main()
