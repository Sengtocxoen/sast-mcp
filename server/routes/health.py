"""
Health check route: GET /health with tool availability and scan stats.
"""
import logging
from flask import Flask, jsonify

from core import execute_command, check_process_health, scan_stats_lock, scan_stats
from config import (
    DEPENDENCY_CHECK_PATH,
    FORCE_SYNC_SCANS,
    USE_MULTIPROCESSING,
    MAX_PARALLEL_SCANS,
    MAX_PROCESS_WORKERS,
)

logger = logging.getLogger(__name__)


def register(app: Flask) -> None:
    """Register health route on the Flask app."""

    @app.route("/health", methods=["GET"])
    def health_check():
        essential_tools = {
            "semgrep": "semgrep scan --version",
            "bandit": "bandit --version",
            "eslint": "eslint --version",
            "npm": "npm --version",
            "safety": "safety --version",
            "trufflehog": "trufflehog --version",
            "gitleaks": "gitleaks version",
        }

        additional_tools = {
            "bearer": "bearer version",
            "graudit": "which graudit",
            "gosec": "gosec -version",
            "brakeman": "brakeman --version",
            "checkov": "checkov --version",
            "tfsec": "tfsec --version",
            "trivy": "trivy --version",
            "nodejsscan": "nodejsscan --version",
            "dependency-check": f"{DEPENDENCY_CHECK_PATH} --version",
        }

        kali_tools = {
            "nikto": "nikto -Version",
            "nmap": "nmap --version",
            "sqlmap": "sqlmap --version",
            "wpscan": "wpscan --version",
            "dirb": "which dirb",
            "lynis": "lynis --version",
            "snyk": "snyk --version",
            "clamscan": "clamscan --version",
        }

        tools_status = {}

        for tool, check_cmd in essential_tools.items():
            try:
                result = execute_command(check_cmd, timeout=10)
                tools_status[tool] = result["success"]
            except Exception:
                tools_status[tool] = False

        for tool, check_cmd in additional_tools.items():
            try:
                result = execute_command(check_cmd, timeout=10)
                tools_status[tool] = result["success"]
            except Exception:
                tools_status[tool] = False

        for tool, check_cmd in kali_tools.items():
            try:
                result = execute_command(check_cmd, timeout=10)
                tools_status[tool] = result["success"]
            except Exception:
                tools_status[tool] = False

        all_essential_available = all(
            tools_status.get(tool, False) for tool in essential_tools.keys()
        )
        available_count = sum(1 for v in tools_status.values() if v)
        total_count = len(tools_status)
        kali_tools_available = sum(
            1 for tool in kali_tools.keys() if tools_status.get(tool, False)
        )

        process_health = check_process_health()

        with scan_stats_lock:
            scan_statistics = dict(scan_stats)

        return jsonify({
            "status": "healthy",
            "message": "SAST Tools API Server is running",
            "tools_status": tools_status,
            "all_essential_tools_available": all_essential_available,
            "total_tools_available": available_count,
            "total_tools_count": total_count,
            "kali_tools_available": kali_tools_available,
            "process_health": process_health,
            "scan_statistics": scan_statistics,
            "scan_mode": {
                "force_sync_scans": FORCE_SYNC_SCANS,
                "mode": "synchronous" if FORCE_SYNC_SCANS else "background",
                "description": (
                    "Scans run synchronously to avoid job queue hangs"
                    if FORCE_SYNC_SCANS
                    else "Scans run in background (may hang with semaphore issues)"
                ),
            },
            "multiprocessing_enabled": USE_MULTIPROCESSING,
            "max_parallel_scans": MAX_PARALLEL_SCANS,
            "max_process_workers": (
                MAX_PROCESS_WORKERS if USE_MULTIPROCESSING else "N/A"
            ),
            "version": "3.1.0",
        })
