#!/usr/bin/env python3
"""
run.py  —  RX-MORTEM v2 launcher
Run from the project root:

    python run.py            # starts API on http://localhost:8000
    python run.py --train    # trains the model first, then starts API
    python run.py --train-only
    python run.py --port 9000
"""

import argparse
import os
import subprocess
import sys

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_ROOT)


def run_training():
    print("\n" + "=" * 60)
    print("  RX-MORTEM :: Training ML model")
    print("=" * 60)
    result = subprocess.run(
        [sys.executable, os.path.join(PROJECT_ROOT, "ml", "train.py")],
        cwd=PROJECT_ROOT,
    )
    if result.returncode != 0:
        print("\n[ERROR] Training failed. Fix errors above before starting API.")
        sys.exit(1)
    print("\n[OK] Training complete.\n")


def run_api(host: str = "0.0.0.0", port: int = 8000, reload: bool = True):
    print(f"\n[*] Starting RX-MORTEM API on http://{host}:{port}")
    print(f"[*] Frontend:  open frontend/rx-mortem.html in your browser")
    print(f"[*] API docs:  http://localhost:{port}/docs\n")
    cmd = [
        sys.executable, "-m", "uvicorn",
        "backend.main:app",
        "--host", host,
        "--port", str(port),
    ]
    if reload:
        cmd.append("--reload")
    subprocess.run(cmd, cwd=PROJECT_ROOT)


def main():
    parser = argparse.ArgumentParser(description="RX-MORTEM v2 launcher")
    parser.add_argument("--train",      action="store_true",
                        help="Train model before starting API")
    parser.add_argument("--train-only", action="store_true",
                        help="Only train; do not start API")
    parser.add_argument("--host",       default="0.0.0.0")
    parser.add_argument("--port",       type=int, default=8000)
    parser.add_argument("--no-reload",  action="store_true",
                        help="Disable uvicorn --reload")
    args = parser.parse_args()

    if args.train or args.train_only:
        run_training()

    if not args.train_only:
        run_api(host=args.host, port=args.port, reload=not args.no_reload)


if __name__ == "__main__":
    main()
