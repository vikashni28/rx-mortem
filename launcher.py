#!/usr/bin/env python3
"""
launcher.py  —  RX-MORTEM v2 Unified Launcher

Starts both backend API server and opens frontend in default browser.

Run:
    python launcher.py            # starts backend + opens frontend
    python launcher.py --port 9000
    python launcher.py --host 127.0.0.1
    python launcher.py --train    # train model, then start
"""

import argparse
import os
import subprocess
import sys
import time
import webbrowser

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_ROOT)


def run_training():
    """Train the ML model before starting the API."""
    print("\n" + "=" * 70)
    print("  RX-MORTEM :: Training ML Model")
    print("=" * 70)
    result = subprocess.run(
        [sys.executable, os.path.join(PROJECT_ROOT, "ml", "train.py")],
        cwd=PROJECT_ROOT,
    )
    if result.returncode != 0:
        print("\n[ERROR] Training failed. Fix errors above before starting.")
        sys.exit(1)
    print("\n[OK] Training complete.\n")


def start_backend(host: str = "0.0.0.0", port: int = 8000):
    """Start the backend API server in a subprocess."""
    print(f"\n[*] Starting Backend API Server...")
    cmd = [
        sys.executable, "-m", "uvicorn",
        "backend.main:app",
        "--host", host,
        "--port", str(port),
        "--reload",
    ]
    # Start backend in background
    process = subprocess.Popen(
        cmd,
        cwd=PROJECT_ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return process, port


def open_frontend(port: int = 8000):
    """Open the frontend in the default browser."""
    frontend_path = os.path.join(PROJECT_ROOT, "frontend", "rx-mortem.html")
    
    if not os.path.exists(frontend_path):
        print(f"[ERROR] Frontend not found: {frontend_path}")
        return False
    
    try:
        # Open in default browser
        webbrowser.open(f"file:///{frontend_path}")
        print(f"[*] Frontend opened in default browser")
        print(f"    File: {frontend_path}")
        return True
    except Exception as e:
        print(f"[!] Could not auto-open browser: {e}")
        print(f"    Open manually: {frontend_path}")
        return True


def main():
    parser = argparse.ArgumentParser(
        description="RX-MORTEM v2 Unified Launcher",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python launcher.py                    # starts both backend + frontend
  python launcher.py --train            # trains model, then starts both
  python launcher.py --port 9000        # custom port
  python launcher.py --host 127.0.0.1   # localhost only
        """
    )
    parser.add_argument("--train",      action="store_true",
                        help="Train model before starting")
    parser.add_argument("--host",       default="0.0.0.0",
                        help="API server host (default: 0.0.0.0)")
    parser.add_argument("--port",       type=int, default=8000,
                        help="API server port (default: 8000)")
    parser.add_argument("--no-browser", action="store_true",
                        help="Do not auto-open frontend in browser")
    args = parser.parse_args()

    if args.train:
        run_training()

    # Banner
    print("\n" + "=" * 70)
    print("  RX-MORTEM v2 — Unified Launcher")
    print("=" * 70)

    # Start backend
    print(f"\n[*] Backend will run on: http://{args.host}:{args.port}")
    backend_process, port = start_backend(host=args.host, port=args.port)
    
    # Wait for backend to be ready
    print("[*] Waiting for backend to initialize...")
    time.sleep(3)
    
    # Open frontend
    if not args.no_browser:
        print(f"\n[*] Opening frontend...")
        open_frontend(port=args.port)
    else:
        frontend_path = os.path.join(PROJECT_ROOT, "frontend", "rx-mortem.html")
        print(f"\n[*] To open frontend, open in browser:")
        print(f"    {frontend_path}")

    # Display access information
    print("\n" + "=" * 70)
    print("  RX-MORTEM is Running!")
    print("=" * 70)
    print(f"\n  API Server:     http://{args.host}:{args.port}")
    print(f"  API Docs:       http://localhost:{args.port}/docs")
    print(f"  Analyze:        http://localhost:{args.port}/analyze")
    print(f"\n  Frontend: frontend/rx-mortem.html")
    print(f"\n  Press CTRL+C to stop the server\n")

    # Keep the launcher running
    try:
        backend_process.wait()
    except KeyboardInterrupt:
        print("\n\n[*] Shutting down RX-MORTEM...")
        backend_process.terminate()
        backend_process.wait(timeout=5)
        print("[*] Server stopped.")
        sys.exit(0)


if __name__ == "__main__":
    main()
