#!/usr/bin/env python3
"""
MCP-SAST-Server - Security Analysis Server for Claude Code

Run from project root: python -m server.sast_server [--port 6000] [--debug]
Or: python server/sast_server.py  (from project root)
Config: server/config.py  |  Routes: server/routes/*.py  |  Core: server/core.py
"""
import argparse
import logging
import os
import sys

# Ensure "server" package is found whether run as "python3 server/sast_server.py" or "python3 sast_server.py" (from server/)
_file = os.path.realpath(os.path.abspath(__file__))
_script_dir = os.path.dirname(_file)
_PROJECT_ROOT = os.path.dirname(_script_dir)

def _norm(p):
    try:
        if not p:
            return None
        r = os.path.realpath(os.path.abspath(p))
        return r if os.path.isdir(r) else None
    except Exception:
        return None

# Resolve to absolute project root (handle run from server/ as "python3 sast_server.py")
_root_abs = _norm(_PROJECT_ROOT)
if not _root_abs:
    _cwd = _norm(os.getcwd())
    _root_abs = os.path.dirname(_cwd) if (_cwd and os.path.basename(_cwd) == "server") else (_cwd or os.getcwd())
if not _root_abs:
    _root_abs = os.path.realpath(os.getcwd())
_script_dir_norm = _norm(_script_dir)

# Remove script dir so it doesn't shadow the "server" package
sys.path = [p for p in sys.path if _norm(p) != _script_dir_norm]

# Always put absolute project root first so "import server.config" works reliably
sys.path.insert(0, _root_abs)
os.chdir(_root_abs)

from flask import Flask

from server.config import API_PORT, DEBUG_MODE, FORCE_SYNC_SCANS
from server.routes import register_all

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
register_all(app)


def parse_args():
    parser = argparse.ArgumentParser(description="Run the SAST Tools API Server")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")
    parser.add_argument("--port", type=int, default=API_PORT, help=f"Port (default: {API_PORT})")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    if args.debug:
        os.environ["DEBUG_MODE"] = "1"
        logger.setLevel(logging.DEBUG)
    port = args.port

    logger.info("Starting SAST Tools API Server on port %s", port)
    logger.info("SAST: Semgrep, Bearer, Graudit, Bandit, Gosec, Brakeman, NodeJSScan, ESLint")
    logger.info("Secrets: TruffleHog, Gitleaks | Deps: Safety, npm audit, Dependency-Check, Snyk")
    logger.info("IaC: Checkov, tfsec | Container: Trivy | Kali: Nikto, Nmap, SQLMap, WPScan, DIRB, Lynis, ClamAV")
    if FORCE_SYNC_SCANS:
        logger.info("Scan mode: SYNCHRONOUS (FORCE_SYNC_SCANS=1)")
    else:
        logger.warning("Scan mode: BACKGROUND (set FORCE_SYNC_SCANS=1 to avoid job queue hangs)")

    app.run(host="0.0.0.0", port=port, debug=DEBUG_MODE)
