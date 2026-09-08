"""
Health check route: GET /health with tool availability and scan stats.
"""
import logging
import shutil
from typing import Any, Dict

import pathmap
from flask import Flask, jsonify, request

from core import (
    execute_command, check_process_health, scan_stats_lock, scan_stats,
    ENHANCED_ENV,
)

# Detect tools against the SAME PATH the executor runs them with (includes the
# venv bin dir and the extra tool dirs). Bare shutil.which() would probe only
# the server process PATH and falsely report venv-installed tools (semgrep,
# bandit, safety, trufflehog, ...) as unavailable even though scans run them.
_ENHANCED_PATH = ENHANCED_ENV.get("PATH")

# Tools whose availability should also be satisfied by a compatible alternative
# binary. opengrep is a drop-in fork of semgrep (identical scan CLI), so having
# either one installed means the Semgrep-class scanner is available.
_TOOL_ALIASES = {
    "opengrep": ("semgrep",),
    "semgrep": ("opengrep",),
}


def _binary_of(check_cmd: str) -> str:
    """First real binary token of a version/`which` check command."""
    parts = check_cmd.split()
    if not parts:
        return ""
    if parts[0] == "which" and len(parts) > 1:
        return parts[1]
    return parts[0]


def _tool_available(tool: str, check_cmd: str) -> bool:
    """Detect a tool robustly.

    Presence on PATH is the source of truth: it is immune to flaky `--version`
    flags, tools that exit non-zero on version, and venv-installed binaries whose
    version subprocess env differs. Falls back to running the version command only
    when the binary name cannot be resolved on PATH.

    NOTE: this answers "is it installed", NOT "does it work". A binary that is
    present but crashes reports available here. See `_tool_functional()` and the
    `?verify=1` option on /health, added after a corrupt trufflehog reported
    healthy through an entire 136-repo sweep while contributing zero findings to
    every one of them.
    """
    candidates = (_binary_of(check_cmd),) + _TOOL_ALIASES.get(tool, ())
    for binary in candidates:
        if binary and shutil.which(binary, path=_ENHANCED_PATH):
            return True
    try:
        return bool(execute_command(check_cmd, timeout=10).get("success"))
    except Exception:
        return False


def _tool_functional(tool: str, check_cmd: str) -> Dict[str, Any]:
    """Actually run the tool and report whether it executed.

    Deliberately NOT part of the default /health response: this spawns one
    subprocess per tool, and /health is polled. Opt in with `?verify=1`.

    A crash is distinguished from a non-zero exit, because many scanners exit
    non-zero simply to report findings. Only a signal death (or the shell's
    128+N encoding of one) means the binary is broken.
    """
    if not _tool_available(tool, check_cmd):
        return {"status": "missing"}
    try:
        r = execute_command(check_cmd, timeout=20)
    except Exception as e:  # noqa: BLE001
        return {"status": "error", "detail": str(e)[:120]}

    rc = r.get("return_code")
    blob = f"{r.get('stdout', '')}{r.get('stderr', '')}".lower()

    # 128+N is a signal death. 135 == SIGBUS, which is what a truncated or
    # architecture-mismatched binary does.
    if isinstance(rc, int) and rc > 128:
        return {"status": "broken", "return_code": rc,
                "detail": f"killed by signal {rc - 128} (binary likely corrupt)"}
    if any(s in blob for s in ("bus error", "segmentation fault", "core dumped",
                               "cannot execute binary", "exec format error")):
        return {"status": "broken", "return_code": rc, "detail": blob.strip()[:120]}
    if r.get("timed_out"):
        return {"status": "slow", "return_code": rc, "detail": "no response within 20s"}
    return {"status": "ok", "return_code": rc}
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
            "opengrep": "opengrep --version",
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

        for group in (essential_tools, additional_tools, kali_tools):
            for tool, check_cmd in group.items():
                tools_status[tool] = _tool_available(tool, check_cmd)

        # Report the Semgrep-class engine under both names so clients can see which
        # binary is actually installed (opengrep fork vs semgrep upstream) rather
        # than one masking the other via the alias.
        tools_status["semgrep"] = shutil.which("semgrep", path=_ENHANCED_PATH) is not None
        tools_status["opengrep"] = shutil.which("opengrep", path=_ENHANCED_PATH) is not None

        # The Semgrep-class scanner counts as present if EITHER engine is installed.
        _grep_ok = tools_status["semgrep"] or tools_status["opengrep"]
        all_essential_available = _grep_ok and all(
            tools_status.get(tool, False)
            for tool in essential_tools.keys()
            if tool != "opengrep"
        )
        available_count = sum(1 for v in tools_status.values() if v)
        total_count = len(tools_status)
        kali_tools_available = sum(
            1 for tool in kali_tools.keys() if tools_status.get(tool, False)
        )

        # Opt-in functional verification. Off by default because it costs one
        # subprocess per tool; on when a caller actually wants to know that the
        # binaries run, not merely that they exist.
        tools_functional: Dict[str, Any] = {}
        if request.args.get("verify") in ("1", "true", "yes"):
            for group in (essential_tools, additional_tools, kali_tools):
                for tool, check_cmd in group.items():
                    tools_functional[tool] = _tool_functional(tool, check_cmd)

        process_health = check_process_health()
        _pm = pathmap.get().describe()

        with scan_stats_lock:
            scan_statistics = dict(scan_stats)

        return jsonify({
            "status": "healthy",
            "message": "SAST Tools API Server is running",
            "tools_status": tools_status,
            # Present only with ?verify=1. `tools_status` says installed;
            # this says it actually runs.
            **({"tools_functional": tools_functional,
                "tools_broken": sorted(t for t, v in tools_functional.items()
                                       if v.get("status") == "broken")}
               if tools_functional else {}),
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
            # Compact mount view: the most common scan failure is a path that
            # resolves outside the allowed roots, and this says at a glance which
            # shares are configured and which are actually mounted.
            "mounts": {
                "mappings": {m["client"]: m["server"] for m in _pm["mappings"]},
                "allowed_roots": [r["path"] for r in _pm["allowed_roots"]],
                "missing_roots": [r["path"] for r in _pm["allowed_roots"] if not r["exists"]],
                "auto_discovered": _pm["auto_discovered"],
                "detail_url": "/api/util/mounts",
            },
            "multiprocessing_enabled": USE_MULTIPROCESSING,
            "max_parallel_scans": MAX_PARALLEL_SCANS,
            "max_process_workers": (
                MAX_PROCESS_WORKERS if USE_MULTIPROCESSING else "N/A"
            ),
            "version": "3.1.0",
        })
