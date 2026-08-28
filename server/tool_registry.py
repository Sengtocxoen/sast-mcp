"""
tool_registry.py - one cached probe of which scanner binaries actually exist.

The repo-scan tool matrix wants to run EVERY tool that applies to a repo, but
firing a command for a tool that isn't installed costs a process spawn and
returns a useless "no report written" error that pollutes the results. Probing
`shutil.which` per tool is cheap; doing it 134 times across a fleet scan is not,
so the answer is cached process-wide with a TTL.

Availability is resolved against ENHANCED_ENV's PATH (not os.environ's), so
venv-installed tools are visible exactly as they are to execute_command.
"""
import logging
import os
import shutil
import threading
import time
from typing import Dict, List, Optional

from core import ENHANCED_ENV

logger = logging.getLogger(__name__)

# How long a probe result stays valid. Tools don't appear/disappear mid-fleet-scan,
# but a long-lived server should notice an install without a restart.
_TTL_SECS = int(os.environ.get("TOOL_PROBE_TTL", 900))

# Logical tool name -> the binaries that can satisfy it (first match wins).
# A tool is "available" if ANY of its candidate binaries is on the enhanced PATH.
_BINARIES: Dict[str, List[str]] = {
    "semgrep":          ["opengrep", "semgrep"],
    "bandit":           ["bandit"],
    "bearer":           ["bearer"],
    "graudit":          ["graudit"],
    "gosec":            ["gosec"],
    "brakeman":         ["brakeman"],
    "nodejsscan":       ["njsscan", "nodejsscan"],
    "eslint":           ["eslint"],
    "gitleaks":         ["gitleaks"],
    "trufflehog":       ["trufflehog"],
    "trivy":            ["trivy"],
    "safety":           ["safety"],
    "pip-audit":        ["pip-audit"],
    "npm":              ["npm"],
    "osv-scanner":      ["osv-scanner"],
    "dependency-check": ["dependency-check.sh", "dependency-check"],
    "snyk":             ["snyk"],
    "checkov":          ["checkov"],
    "tfsec":            ["tfsec", "trivy"],
    "hadolint":         ["hadolint"],
    "clamscan":         ["clamscan"],
}

_lock = threading.Lock()
_cache: Dict[str, Optional[str]] = {}
_cached_at: float = 0.0


def _probe_all() -> Dict[str, Optional[str]]:
    path = ENHANCED_ENV.get("PATH")
    resolved: Dict[str, Optional[str]] = {}
    for tool, candidates in _BINARIES.items():
        resolved[tool] = next(
            (c for c in candidates if shutil.which(c, path=path)), None
        )
    return resolved


def _ensure_fresh() -> Dict[str, Optional[str]]:
    global _cache, _cached_at
    with _lock:
        if not _cache or (time.time() - _cached_at) > _TTL_SECS:
            _cache = _probe_all()
            _cached_at = time.time()
            found = sorted(k for k, v in _cache.items() if v)
            logger.info(f"tool probe: {len(found)}/{len(_BINARIES)} available: {', '.join(found)}")
        return _cache


def binary_for(tool: str) -> Optional[str]:
    """The concrete binary name to invoke for a logical tool, or None if absent."""
    return _ensure_fresh().get(tool)


def have(tool: str) -> bool:
    return binary_for(tool) is not None


def availability() -> Dict[str, bool]:
    """Full {tool: installed?} map, for /health and scan-coverage reporting."""
    return {k: (v is not None) for k, v in _ensure_fresh().items()}


def missing() -> List[str]:
    return sorted(k for k, v in _ensure_fresh().items() if v is None)


def invalidate() -> None:
    """Force the next lookup to re-probe (used after a tool install)."""
    global _cache, _cached_at
    with _lock:
        _cache = {}
        _cached_at = 0.0
