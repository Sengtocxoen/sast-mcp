#!/usr/bin/env python3
"""
Launcher for SAST server. Run from project root so the "server" package is always found.

  python3 run_server.py --port 6000 --debug

This runs the app as a module (python -m server.sast_server), which correctly sets
sys.path so "import server.config" works on all platforms (including Kali).
"""
import os
import subprocess
import sys

def main():
    root = os.path.dirname(os.path.abspath(__file__))
    os.chdir(root)
    cmd = [sys.executable, "-m", "server.sast_server"] + sys.argv[1:]
    sys.exit(subprocess.call(cmd))

if __name__ == "__main__":
    main()
