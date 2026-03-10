#!/usr/bin/env python3
"""
MCP-SAST-Server - Security Analysis Server for Claude Code.

Run from project root:  python3 server/sast_server.py [--port 6000] [--debug]
Imports use the server folder as root (config, core, routes) so no 'server' package is required on path.
"""
import argparse
import logging
import os
import sys

# Server dir and project root from this file's location (no cwd/realpath so it works on any system).
_server_dir = os.path.dirname(os.path.abspath(__file__))
_project_root = os.path.dirname(_server_dir)
# [server_dir, project_root] so "config"/"core"/"routes" resolve and "tools" (at project root) resolve.
sys.path.insert(0, _project_root)
sys.path.insert(0, _server_dir)
os.chdir(_project_root)

from flask import Flask

from config import API_PORT, DEBUG_MODE, FORCE_SYNC_SCANS
from routes import register_all

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
